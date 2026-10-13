# Copyright 2026 Aerleon Project Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Nokia EDA Filter and ControlPlaneFilter generator.

Generates native Nokia Event Driven Automation (EDA) resources from the
filters.eda.nokia.com/v1 API, as multi-document YAML: one resource per
filter header, ready to be applied to EDA with replace semantics.

Target syntax:
  target:: nokiaeda <name> [inet|inet6|mixed] [stats] namespace <ns>
  target:: nokiaeda <name> cpm [inet|inet6|mixed] [stats] namespace <ns>
           [node-selector <key> <value>]... [node <toponode>]...

Filter options:
  inet                       - IPv4 entries only (default)
  inet6                      - IPv6 entries only
  mixed                      - IPv4 and IPv6 entries in the same resource, in term order
  stats                      - enable per-entry statistics (statisticsPerEntry)
  namespace <ns>             - EDA namespace of the resource (required)
  cpm                        - render a ControlPlaneFilter instead of a Filter
  node-selector <key> <value> - TopoNode label selector, rendered as <key>=<value>
                               (ControlPlaneFilter only, repeatable). Key and
                               value are separate words as policy files do not
                               accept "=" in a target.
  node <toponode>            - TopoNode name (ControlPlaneFilter only, repeatable)

A ControlPlaneFilter needs at least one node-selector or node.

EDA numbers the entries itself from their order in the list, so entries carry
no sequence number. The entry description holds the term name; term comments
are written as YAML comments above the first entry of the term. Repository
tags go in the aerleon/revision annotation and header comments in the
aerleon/comment annotation.

Addresses, ports, protocols and ICMP types are expanded to one entry per
combination, as EDA entries match a single prefix, port and ICMP type.

Policers and counters are not rendered.
"""

import copy
import re
from typing import Any

import yaml
from absl import logging

from aerleon.lib import aclgenerator
from aerleon.lib.policy import Term as PolicyTerm

API_VERSION = 'filters.eda.nokia.com/v1'

# Kubernetes object name (DNS-1123 subdomain) and namespace (DNS-1123 label).
_NAME_RE = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$')
_NAMESPACE_RE = re.compile(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')


class Error(aclgenerator.Error):
    pass


class FilterOptionError(Error):
    pass


class InvalidResourceNameError(Error):
    pass


class UnknownProtocolError(Error):
    pass


class TcpEstablishedWithNonTcpError(Error):
    pass


class EstablishedWithNoProtocolError(Error):
    pass


class EstablishedWithNonTcpUdpError(Error):
    pass


class EDATerm(aclgenerator.Term):
    """Converts a policy term into EDA filter entries."""

    ACTION_MAP = {'accept': 'Accept', 'deny': 'Drop'}
    ENTRY_TYPE = {'inet': 'IPv4', 'inet6': 'IPv6'}

    def __init__(self, term: PolicyTerm, inet_version: str = 'inet', mixed: bool = False) -> None:
        super().__init__(term)
        self.inet_version = inet_version
        self.mixed = mixed
        self.term.FlattenAll()

    def ConvertToEntries(self) -> list[dict[str, Any]]:
        """Explode this term into a list of EDA filter entries."""
        term_af = self.AF_MAP[self.inet_version]

        protos_of_other_af = {'icmpv6', 'icmp6'} if self.inet_version == 'inet' else {'icmp'}
        if protos_of_other_af & set(self.term.protocol):
            if not self.mixed:
                logging.warning(
                    self.NO_AF_LOG_PROTO.substitute(
                        term=self.term.name,
                        proto=', '.join(self.term.protocol),
                        af=self.inet_version,
                    )
                )
            return []

        saddrs = self.term.GetAddressOfVersion('flattened_saddr', term_af)
        if self.term.flattened_saddr and not saddrs:
            self._LogNoAF('source')
            return []
        daddrs = self.term.GetAddressOfVersion('flattened_daddr', term_af)
        if self.term.flattened_daddr and not daddrs:
            self._LogNoAF('destination')
            return []
        saddrs = saddrs or ['any']
        daddrs = daddrs or ['any']
        sports = self.term.source_port or [(0, 0)]
        dports = self.term.destination_port or [(0, 0)]
        protos: list[Any] = self.term.protocol or [None]

        icmp_types: list[int | None] = [None]
        if self.term.icmp_type:
            icmp_map = self.ICMP_TYPE[term_af]
            resolved = [icmp_map[t] for t in self.term.icmp_type if t in icmp_map]
            if not resolved:
                return []
            icmp_types = resolved  # type: ignore[assignment]

        opts = [str(x) for x in self.term.option]
        tcp_flags = None
        if 'tcp-initial' in opts:
            tcp_flags = 'SYN'
        if 'not-syn-ack' in opts:
            tcp_flags = '!(SYN&ACK)'
        if 'tcp-established' in opts or ('established' in opts and self.term.protocol == ['tcp']):
            if self.term.protocol and self.term.protocol != ['tcp']:
                raise TcpEstablishedWithNonTcpError(
                    f'tcp-established can only be used with tcp protocol in term {self.term.name}'
                )
            tcp_flags = 'ACK|RST'
        elif 'established' in opts:
            if not self.term.protocol:
                raise EstablishedWithNoProtocolError(
                    f'must specify a protocol for "established" in term {self.term.name}'
                )
            if self.term.protocol != ['udp']:
                raise EstablishedWithNonTcpUdpError(
                    'established can only be used with tcp or udp protocol'
                    f' in term {self.term.name}'
                )
            # Replies to a UDP flow initiated from this side land on an ephemeral port.
            if not self.term.destination_port:
                dports = [(1024, 65535)]
        # TCP flags only make sense on TCP.
        if tcp_flags:
            protos = ['tcp']

        entries = []
        for saddr in saddrs:
            for daddr in daddrs:
                for sport in sports:
                    for dport in dports:
                        for proto in protos:
                            for icmp_type in icmp_types:
                                ip_entry = self._BuildIPEntry(
                                    saddr, daddr, sport, dport, proto, icmp_type, tcp_flags, opts
                                )
                                entries.append(
                                    {
                                        'description': self.term.name,
                                        'type': self.ENTRY_TYPE[self.inet_version],
                                        'ipEntry': ip_entry,
                                    }
                                )
        return entries

    def _LogNoAF(self, direction: str) -> None:
        if not self.mixed:
            logging.warning(
                self.NO_AF_LOG_ADDR.substitute(
                    term=self.term.name, direction=direction, af=self.inet_version
                )
            )

    def _BuildIPEntry(
        self,
        saddr: Any,
        daddr: Any,
        sport: tuple[int, int],
        dport: tuple[int, int],
        proto: int | str | None,
        icmp_type: int | None,
        tcp_flags: str | None,
        opts: list[str],
    ) -> dict[str, Any]:
        ip_entry: dict[str, Any] = {'action': self.ACTION_MAP[self.term.action[0]]}
        if self.term.logging and str(self.term.logging[0]).lower() not in ('disable', 'false'):
            ip_entry['log'] = True

        if saddr != 'any':
            ip_entry['sourcePrefix'] = str(saddr)
        if daddr != 'any':
            ip_entry['destinationPrefix'] = str(daddr)

        if proto is not None:
            if isinstance(proto, str):
                if proto not in self.PROTO_MAP:
                    raise UnknownProtocolError(
                        f'protocol {proto} unknown in term {self.term.name}, use an integer'
                    )
                proto = self.PROTO_MAP[proto]
            ip_entry['protocolNumber'] = int(proto)

        self._SetPort(ip_entry, 'source', sport)
        self._SetPort(ip_entry, 'destination', dport)

        if icmp_type is not None:
            ip_entry['icmpTypeNumber'] = icmp_type
            if self.term.icmp_code:
                ip_entry['icmpCodes'] = [int(c) for c in self.term.icmp_code]

        if tcp_flags:
            ip_entry['tcpFlags'] = tcp_flags

        if 'first-fragment' in opts:
            ip_entry['firstFragment'] = True
        elif 'is-fragment' in opts or 'fragments' in opts:
            ip_entry['fragment'] = True

        return ip_entry

    @staticmethod
    def _SetPort(ip_entry: dict[str, Any], direction: str, port: tuple[int, int]) -> None:
        start, end = port
        if start == end == 0:
            return
        if start == end:
            ip_entry[f'{direction}PortOperator'] = 'Equals'
            ip_entry[f'{direction}PortNumber'] = start
        else:
            ip_entry[f'{direction}PortRange'] = f'{start}-{end}'


class NokiaEDA(aclgenerator.ACLGenerator):
    """Nokia EDA Filter and ControlPlaneFilter generator."""

    _PLATFORM = 'nokiaeda'
    SUFFIX = '.eda.yaml'
    _SUPPORTED_AF = frozenset(('inet', 'inet6', 'mixed'))
    _REPEATABLE_OPTIONS = {'node-selector': 'nodeSelectors', 'node': 'nodes'}

    def _BuildTokens(self) -> tuple[set[str], dict[str, set[str]]]:
        supported_tokens, supported_sub_tokens = super()._BuildTokens()
        supported_tokens -= {'verbatim'}
        supported_tokens |= {'logging', 'icmp_code'}
        supported_sub_tokens['action'] = {'accept', 'deny'}
        supported_sub_tokens['option'] = {
            'established',
            'tcp-established',
            'tcp-initial',
            'not-syn-ack',
            'is-fragment',
            'fragments',
            'first-fragment',
        }
        return supported_tokens, supported_sub_tokens

    def _TranslatePolicy(self, pol: Any, exp_info: int) -> None:
        self.total_rule_count = 0
        # Each resource is (resource without entries, [(term comments, term entries)]).
        self.resources: list[tuple[dict[str, Any], list[tuple[list[str], list[dict]]]]] = []

        for header, terms in pol.filters:
            # Work on a copy: FilterOptions returns the header's own list.
            filter_options = list(header.FilterOptions(self._PLATFORM))
            filter_name = filter_options.pop(0) if filter_options else ''
            self.resources.append(
                self._TranslateFilter(filter_name, filter_options, terms, header.comment)
            )

    def _TranslateFilter(
        self,
        filter_name: str,
        filter_options: list[str],
        terms: list[PolicyTerm],
        hdr_comments: list[str],
    ) -> tuple[dict[str, Any], list[tuple[list[str], list[dict]]]]:
        if not _NAME_RE.match(filter_name) or len(filter_name) > 253:
            raise InvalidResourceNameError(
                f'filter name "{filter_name}" is not a valid EDA resource name: lowercase'
                ' alphanumerics, "-" and "." only'
            )

        address_family = 'inet'
        stats = False
        is_cpm = False
        namespace = None
        spec_lists: dict[str, list[str]] = {}
        options = iter(filter_options)
        for opt in options:
            if opt in self._SUPPORTED_AF:
                address_family = opt
            elif opt == 'stats':
                stats = True
            elif opt == 'cpm':
                is_cpm = True
            elif opt == 'namespace' or opt in self._REPEATABLE_OPTIONS:
                values = [next(options, None) for _ in range(2 if opt == 'node-selector' else 1)]
                if None in values:
                    raise FilterOptionError(
                        f'option "{opt}" needs {len(values)} value(s) in filter {filter_name}'
                    )
                if opt == 'namespace':
                    namespace = values[0]
                else:
                    spec_key = self._REPEATABLE_OPTIONS[opt]
                    spec_lists.setdefault(spec_key, []).append('='.join(values))
            else:
                raise FilterOptionError(f'unsupported option "{opt}" in filter {filter_name}')

        if namespace is None:
            raise FilterOptionError(f'filter {filter_name} needs a "namespace <ns>" option')
        if not _NAMESPACE_RE.match(namespace) or len(namespace) > 63:
            raise InvalidResourceNameError(
                f'namespace "{namespace}" of filter {filter_name} is not a valid EDA namespace'
            )
        if is_cpm and not spec_lists:
            raise FilterOptionError(
                f'cpm filter {filter_name} needs at least one "node-selector" or "node" option'
            )
        if spec_lists and not is_cpm:
            raise FilterOptionError(
                f'"node-selector" and "node" only apply to cpm filters, in filter {filter_name}'
            )

        afs = ['inet', 'inet6'] if address_family == 'mixed' else [address_family]
        term_blocks = []
        for term in terms:
            entries = []
            for af in afs:
                entries.extend(
                    EDATerm(term, af, mixed=address_family == 'mixed').ConvertToEntries()
                )
            if entries:
                term_blocks.append((list(term.comment), entries))
                self.total_rule_count += len(entries)

        annotations = {'aerleon/revision': ' '.join(aclgenerator.AddRepositoryTags())}
        if hdr_comments:
            annotations['aerleon/comment'] = ' '.join(hdr_comments)
        spec: dict[str, Any] = {}
        if is_cpm:
            for key in ('nodeSelectors', 'nodes'):
                if key in spec_lists:
                    spec[key] = spec_lists[key]
        if stats:
            spec['statisticsPerEntry'] = True
        resource = {
            'apiVersion': API_VERSION,
            'kind': 'ControlPlaneFilter' if is_cpm else 'Filter',
            'metadata': {
                'name': filter_name,
                'namespace': namespace,
                'annotations': annotations,
            },
            'spec': spec,
        }
        logging.info(
            'Total rule count of filter %s is: %d',
            filter_name,
            sum(len(e) for _, e in term_blocks),
        )
        return resource, term_blocks

    @staticmethod
    def _Dump(data: Any, indent: int = 0) -> str:
        text = yaml.safe_dump(data, sort_keys=False, default_flow_style=False, width=float('inf'))
        pad = ' ' * indent
        return ''.join(pad + line for line in text.splitlines(keepends=True))

    def _RenderResource(
        self, resource: dict[str, Any], term_blocks: list[tuple[list[str], list[dict]]]
    ) -> str:
        """Render one resource, with term comments as YAML comments above their entries."""
        resource = copy.deepcopy(resource)
        spec = resource.pop('spec')
        out = self._Dump(resource)
        out += 'spec:\n'
        if spec:
            out += self._Dump(spec, indent=2)
        if not term_blocks:
            return out + '  entries: []\n'
        out += '  entries:\n'
        for comments, entries in term_blocks:
            for comment in comments:
                for line in str(comment).splitlines():
                    out += f'  # {line}'.rstrip() + '\n'
            out += self._Dump(entries, indent=2)
        return out

    def __str__(self) -> str:
        return ''.join(
            '---\n' + self._RenderResource(resource, term_blocks)
            for resource, term_blocks in self.resources
        )
