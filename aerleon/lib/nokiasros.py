# Copyright 2024 Aerleon Project Authors.
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

"""Nokia SR OS JSON IP filter and CPM filter generator.

Generates ACL filters for Nokia SROS devices in the YANG JSON format
used by the nokia-conf model.

Target syntax:
  target:: nokiasros <filter-id-or-name> [inet|inet6|mixed] [accept|drop] [syslog-profile <N>]
  target:: nokiasros <any-name> cpm [inet|inet6] [syslog-profile <N>]

Filter options (ip-filter mode):
  inet             - generate IPv4 filter (default)
  inet6            - generate IPv6 filter
  mixed            - generate entries for both IPv4 and IPv6
  accept           - set default-action to accept (default: drop)
  drop             - set default-action to drop
  pktlenfilter     - set filter type to packet-length

  syslog-profile N - syslog profile ID for log entries (default: 102)
  (filter name may be numeric → nokia-conf:filter-id, or string →
   nokia-conf:filter-name)

Filter options (cpm mode):
  cpm              - render as a CPM filter (nokia-conf:admin-state wrapper)
  inet             - IPv4 CPM filter (default)
  inet6            - IPv6 CPM filter
  syslog-profile N - syslog profile ID for log entries (default: 102)

Both modes expand addresses to individual prefixes.  The only behavioural
difference in CPM mode is that tcp-established is rendered as
tcp-flags {ack: true} instead of the ip-filter tcp-established leaf.

CPM filter comments: the CPM YANG model has no top-level description leaf, so
a header comment is prepended to the first entry's description field as
"<comment> | <term-description>".
"""

import copy
import json
from typing import Any

from aerleon.lib import aclgenerator
from aerleon.lib import policy as policy_module
from aerleon.lib.policy import Term as PolicyTerm


class Error(aclgenerator.Error):
    pass


class TcpEstablishedWithNonTcpError(Error):
    pass


class SROSTerm(aclgenerator.Term):
    """Converts a policy term into SROS filter entry dicts."""

    ACTION_MAP = {'accept': 'accept', 'deny': 'drop', 'reject': 'drop'}
    # Protocols that SROS does not accept by name and must be expressed numerically.
    PROTO_NAME_TO_NUM = {'esp': 50}

    def __init__(
        self,
        term: PolicyTerm,
        inet_version: str = 'inet',
        syslog_profile: int = 102,
        cpm_mode: bool = False,
    ) -> None:
        super().__init__(term)
        self.inet_version = inet_version
        self.syslog_profile = syslog_profile
        self.cpm_mode = cpm_mode
        self.term.FlattenAll()

    def ConvertToEntries(self) -> list[dict[str, Any]]:
        """Explode this term into a list of SROS filter entry dicts."""
        action_key = self.ACTION_MAP[self.term.action[0]]
        term_af = self.AF_MAP[self.inet_version]

        saddrs = self.term.GetAddressOfVersion('flattened_saddr', term_af) or ['any']
        daddrs = self.term.GetAddressOfVersion('flattened_daddr', term_af) or ['any']
        sports = self.term.source_port or [(0, 0)]
        dports = self.term.destination_port or [(0, 0)]
        protos = self.term.protocol or [None]

        icmp_types: list[int | None] = [None]
        if self.term.icmp_type:
            icmp_map = self.ICMP_TYPE[term_af]
            resolved = [icmp_map[t] for t in self.term.icmp_type if t in icmp_map]
            if not resolved:
                return []
            icmp_types = resolved  # type: ignore[assignment]

        icmp_codes: list[int | None] = self.term.icmp_code or [None]

        opts = [str(x) for x in self.term.option]
        if 'tcp-established' in opts:
            if self.term.protocol and self.term.protocol != ['tcp']:
                raise TcpEstablishedWithNonTcpError(
                    f'tcp-established can only be used with tcp protocol in term {self.term.name}'
                )

        action: dict[str, Any] = {action_key: [None]}
        if self.term.policer:
            action['rate-limit'] = {'policer': str(self.term.policer)}

        entries = []
        for saddr in saddrs:
            for daddr in daddrs:
                for sport in sports:
                    for dport in dports:
                        for proto in protos:
                            for icmp_type in icmp_types:
                                for icmp_code in icmp_codes:
                                    match = self._BuildMatch(
                                        saddr,
                                        daddr,
                                        sport,
                                        dport,
                                        proto,
                                        icmp_type,
                                        icmp_code,
                                        opts,
                                    )
                                    desc = (
                                        ' '.join(self.term.comment)
                                        if self.term.comment
                                        else self.term.name
                                    )
                                    entry: dict[str, Any] = {
                                        'description': desc,
                                        'action': copy.deepcopy(action),
                                    }
                                    if match:
                                        entry['match'] = match
                                    if self.term.logging:
                                        entry['log'] = self.syslog_profile
                                    entries.append(entry)
        return entries

    def _BuildMatch(
        self,
        saddr: Any,
        daddr: Any,
        sport: tuple[int, int],
        dport: tuple[int, int],
        proto: int | str | None,
        icmp_type: int | None,
        icmp_code: int | None,
        opts: list[str],
    ) -> dict[str, Any]:
        match: dict[str, Any] = {}

        if saddr != 'any':
            match['src-ip'] = {'address': str(saddr)}
        if daddr != 'any':
            match['dst-ip'] = {'address': str(daddr)}

        s_start, s_end = sport
        if not (s_start == s_end == 0):
            match['src-port'] = (
                {'eq': s_start}
                if s_start == s_end
                else {'range':{'start': s_start, 'end': s_end}}
            )

        d_start, d_end = dport
        if not (d_start == d_end == 0):
            match['dst-port'] = (
                {'eq': d_start}
                if d_start == d_end
                else {'range': {'start': d_start, 'end': d_end}}
            )

        if proto is not None:
            if isinstance(proto, str):
                proto_name = proto
            else:
                proto_name = self.PROTO_MAP_BY_NUMBER.get(proto) or str(proto)
            proto_val: str | int = self.PROTO_NAME_TO_NUM.get(proto_name, proto_name)
            if self.inet_version == 'inet6':
                match['next-header'] = 'ipv6-icmp' if proto_name == 'icmpv6' else proto_val
            else:
                match['protocol'] = proto_val

        if icmp_type is not None:
            icmp: dict[str, int] = {'type': icmp_type}
            if icmp_code is not None:
                icmp['code'] = icmp_code
            match['icmp'] = icmp

        if self.term.hop_limit:
            match['hop-limit'] = {'lt': int(self.term.hop_limit)}

        if self.term.ttl:
            ttl_key = 'hop-limit' if self.inet_version == 'inet6' else 'ttl'
            match[ttl_key] = {'lt': self.term.ttl}

        if 'tcp-established' in opts:
            if self.cpm_mode:
                match['tcp-flags'] = {'ack': True}
            else:
                match['tcp-established'] = [None]

        if any(x in opts for x in ('is-fragment', 'fragments', 'first-fragment')):
            match['fragment'] = 'true'

        return match


class NokiaSROS(aclgenerator.ACLGenerator):
    """Nokia SR OS JSON IP-filter and CPM-filter generator."""

    _PLATFORM = 'nokiasros'
    SUFFIX = '.sros_acl'
    _SUPPORTED_AF = frozenset(('inet', 'inet6', 'mixed'))

    def _BuildTokens(self) -> tuple[set[str], dict[str, set[str]]]:
        supported_tokens, supported_sub_tokens = super()._BuildTokens()
        supported_tokens -= {'platform', 'platform_exclude', 'verbatim'}
        supported_tokens |= {'logging', 'hop_limit', 'icmp_code', 'policer', 'ttl'}
        supported_sub_tokens['action'] = {'accept', 'deny'}
        supported_sub_tokens['option'] |= {'fragments'}
        return supported_tokens, supported_sub_tokens

    def _TranslatePolicy(self, pol: Any, exp_info: int) -> None:
        self.total_rule_count = 0
        self.ip_filters: list[dict[str, Any]] = []

        for header, terms in pol.filters:
            filter_options = header.FilterOptions(self._PLATFORM)
            filter_name = header.FilterName(self._PLATFORM)

            comment = ' '.join(header.comment) if header.comment else None
            is_cpm = filter_name == 'cpm' or 'cpm' in filter_options
            if 'cpm' in filter_options:
                filter_options.remove('cpm')
            if is_cpm:
                self._TranslateCPMFilter(filter_options, terms, comment)
            else:
                self._TranslateIPFilter(filter_name, filter_options, terms, comment)

    def _TranslateIPFilter(
        self,
        filter_name: str,
        filter_options: list[str],
        terms: list[Any],
        comment: str | None = None,
    ) -> None:
        try:
            filter_key: str = 'nokia-conf:filter-id'
            filter_value: int | str = int(filter_name)
        except ValueError:
            filter_key = 'nokia-conf:filter-name'
            filter_value = filter_name

        address_family = 'inet'
        for af in self._SUPPORTED_AF:
            if af in filter_options:
                address_family = af
                filter_options.remove(af)

        default_action = 'drop'
        for opt in ('accept', 'drop'):
            if opt in filter_options:
                default_action = opt
                filter_options.remove(opt)

        packet_length = 'pktlenfilter' in filter_options
        if packet_length:
            filter_options.remove('pktlenfilter')

        syslog_profile = self._parse_common_options(filter_options)
        afs = ['inet', 'inet6'] if address_family == 'mixed' else [address_family]
        entries: list[dict[str, Any]] = []
        for term_idx, term in enumerate(terms, start=1):
            base_id = term_idx * 10000
            entry_offset = 0
            for af in afs:
                t = SROSTerm(term, af, syslog_profile)
                for entry in t.ConvertToEntries():
                    self.total_rule_count += 1
                    entry['entry-id'] = base_id + entry_offset
                    entry_offset += 1
                    entries.append(entry)

        filter_dict: dict[str, Any] = {'nokia-conf:scope': 'template'}
        if packet_length:
            filter_dict['nokia-conf:type'] = 'packet-length'
        if comment:
            filter_dict['nokia-conf:description'] = comment
        filter_dict['nokia-conf:default-action'] = default_action
        filter_dict[filter_key] = filter_value
        filter_dict['nokia-conf:entry'] = entries
        self.ip_filters.append(filter_dict)

    def _TranslateCPMFilter(
        self,
        filter_options: list[str],
        terms: list[Any],
        comment: str | None = None,
    ) -> None:
        address_family = 'inet'
        for af in ('inet', 'inet6'):
            if af in filter_options:
                address_family = af
                filter_options.remove(af)

        syslog_profile = self._parse_common_options(filter_options)
        entries: list[dict[str, Any]] = []
        for term_idx, term in enumerate(terms, start=1):
            base_id = term_idx * 10000
            entry_offset = 0
            t = SROSTerm(term, address_family, syslog_profile, cpm_mode=True)
            for entry in t.ConvertToEntries():
                self.total_rule_count += 1
                entry['entry-id'] = base_id + entry_offset
                entry_offset += 1
                entries.append(entry)

        if comment and entries:
            entries[0]['description'] = f"{comment} | {entries[0]['description']}"

        cpm_dict: dict[str, Any] = {'nokia-conf:admin-state': 'enable'}
        cpm_dict['nokia-conf:entry'] = entries
        self.ip_filters.append(cpm_dict)

    def _parse_common_options(self, filter_options: list[str]) -> int:
        """Extract syslog-profile from remaining options."""
        syslog_profile = 102
        if 'syslog-profile' in filter_options:
            idx = filter_options.index('syslog-profile')
            filter_options.pop(idx)
            if idx < len(filter_options):
                try:
                    syslog_profile = int(filter_options.pop(idx))
                except (ValueError, IndexError):
                    pass
        return syslog_profile

    def __str__(self) -> str:
        output = self.ip_filters[0] if len(self.ip_filters) == 1 else self.ip_filters
        return json.dumps(output, indent=4) + '\n'
