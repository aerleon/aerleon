# Copyright 2023 Nokia All Rights Reserved.
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
#

"""Nokia SR Linux yang ACL generator.

More information about the SR Linux ACL model schema: https://yang.srlinux.dev/

"""

import sys
from typing import Dict, List, Set, Tuple

from aerleon.lib import aclgenerator, openconfig
from aerleon.lib.policy import Term

if sys.version_info < (3, 8):
    from typing_extensions import TypedDict
else:
    from typing import TypedDict

R24_3_2 = "r24.3.2"  # Option flag to generate release >= 24.3.2 syntax

IPPrefix = TypedDict("IPPrefix", {"prefix": str})
PortRange = TypedDict("PortRange", {"start": int, "end": int})
Port = TypedDict("Port", {"value": int, "range": PortRange})

Match = TypedDict(
    "Match",
    {
        "fragment": bool,
        "first-fragment": bool,
        "protocol": int,
        "next-header": int,
        "source-ip": IPPrefix,
        "destination-ip": IPPrefix,
        "source-port": Port,
        "destination-port": Port,
    },
)
Action = TypedDict("Action", {"accept": None, "drop": None})
ACLEntry = TypedDict(
    "ACLEntry",
    {
        "sequence-id": int,
        "action": Action,
        "match": Match,
        "description": str,
        "_annotate_description": str,
    },
)
Entries = TypedDict(
    "Entries",
    {
        "entry": List[ACLEntry],
        "description": str,
        "name": str,
        "type": str,
        "_annotate": str,
        "statistics-per-entry": bool,
    },
)
IPFilters = TypedDict("IPFilters", {"acl-filter": Entries})


# generic error class
class Error(aclgenerator.Error):
    pass


class TcpEstablishedWithNonTcpError(Error):
    pass


class EstablishedWithNoProtocolError(Error):
    pass


class EstablishedWithNonTcpUdpError(Error):
    pass


class UnsupportedLogging(Error):
    pass


class SRLTerm(openconfig.Term):
    """Creates the term for the SR Linux ACL."""

    ACTION_MAP = {'accept': 'accept', 'deny': 'drop', 'reject': 'drop'}

    def SetName(self, name: str) -> None:
        # Put name in description field
        self.term_dict['description'] = name

    def SetAction(self) -> None:
        action = self.ACTION_MAP[self.term.action[0]]
        self.term_dict['action'] = {action: {}}
        if self.term.logging:
            self.term_dict['action']['log'] = True

    def SetComments(self, comments: List[str]) -> None:
        self.term_dict['_annotate_description'] = "_".join(comments)[:255]

    # Handles syntax changes in release 24.3.2 and beyond
    def _field(self, key, filter_options: List[str]):
        if R24_3_2 in filter_options:
            if key not in self.term_dict['match']:
                self.term_dict['match'][key] = {}
            return self.term_dict['match'][key]
        return self.term_dict['match']

    def SetOptions(self, family: str, filter_options: List[str]) -> None:
        # Handle various options
        opts = [str(x) for x in self.term.option]
        self.term_dict['match'] = {}
        if ('fragments' in opts) or ('is-fragment' in opts):
            self._field('ipv4', filter_options)['fragment'] = True
        if 'first-fragment' in opts:
            self._field('ipv4', filter_options)['first-fragment'] = True

        if 'initial' in opts or 'tcp-initial' in opts:
            self._field('transport', filter_options)['tcp-flags'] = "syn"
        if 'rst' in opts:
            _f = self._field('transport', filter_options)
            _f['tcp-flags'] = "syn&rst" if 'tcp-flags' in _f else "rst"
        if 'not-syn-ack' in opts:
            self._field('transport', filter_options)['tcp-flags'] = "!(syn&ack)"

        def _tcp_established():
            self._field('transport', filter_options)['tcp-flags'] = "ack|rst"

        if 'tcp-established' in opts:
            if not self.term.protocol or self.term.protocol == ['tcp']:
                _tcp_established()
            else:
                raise TcpEstablishedWithNonTcpError(
                    f'tcp-established can only be used with tcp protocol in term {self.term.name}'
                )
        elif 'established' in opts:
            if self.term.protocol:
                if self.term.protocol == ['tcp']:
                    _tcp_established()
                elif self.term.protocol == ['udp']:
                    self.SetProtocol(family=family, protocol="udp", filter_options=filter_options)
                    if not self.term.destination_port:
                        self.SetDestPorts(1024, 65535, filter_options)
                else:  # Could produce 2 rules if [tcp,udp]
                    raise EstablishedWithNonTcpUdpError(
                        f'established can only be used with tcp or udp protocol in term {self.term.name}'
                    )
            else:
                raise EstablishedWithNoProtocolError(
                    f'must specify a protocol for "established" in term {self.term.name}'
                )

        if 'tcp-flags' in self.term_dict['match'] or (
            R24_3_2 in filter_options
            and 'transport' in self.term_dict['match']
            and 'tcp-flags' in self.term_dict['match']['transport']
        ):
            self.SetProtocol(family=family, protocol="tcp", filter_options=filter_options)

    def SetSourceAddress(self, family: str, saddr: str, filter_options: List[str]) -> None:
        self._field(family, filter_options)['source-ip'] = {'prefix': saddr}

    def SetDestAddress(self, family: str, daddr: str, filter_options: List[str]) -> None:
        self._field(family, filter_options)['destination-ip'] = {'prefix': daddr}

    def SetSourcePorts(self, start: int, end: int, filter_options: List[str]) -> None:
        if start == end:
            val = {'value': start}
        else:
            val = {'range': {'start': start, 'end': end}}
        self._field('transport', filter_options)['source-port'] = val

    def SetDestPorts(self, start: int, end: int, filter_options: List[str]) -> None:
        if start == end:
            val = {'value': start}
        else:
            val = {'range': {'start': start, 'end': end}}
        self._field('transport', filter_options)['destination-port'] = val

    def SetProtocol(self, family: str, protocol: int, filter_options: List[str]) -> None:
        field_name = "protocol" if family == "ipv4" else "next-header"
        self._field(family, filter_options)[field_name] = protocol


class NokiaSRLinux(openconfig.OpenConfig):
    """A Nokia SR Linux ACL object, derived from OpenConfig."""

    _PLATFORM = 'nokiasrl'
    SUFFIX = '.srl_acl'

    def _BuildTokens(self) -> Tuple[Set[str], Dict[str, Set[str]]]:
        """Build supported tokens for platform.

        Returns:
          tuple containing both supported tokens and sub tokens
        """
        supported_tokens, supported_sub_tokens = super()._BuildTokens()

        supported_tokens -= {'platform', 'platform_exclude', 'verbatim', 'icmp-type'}

        supported_sub_tokens['action'] = {'accept', 'deny'}  # excludes 'reject'
        supported_sub_tokens['option'] = {
            'established',
            'first-fragment',
            'is-fragment',
            'fragments',
            #  'sample',
            'tcp-established',
            'tcp-initial',
            #  'inactive',
            'not-syn-ack',
        }
        return supported_tokens, supported_sub_tokens

    def _InitACLSet(self) -> None:
        """Initialize self.acl_sets with proper Typing"""
        self.acl_sets: List[IPFilters] = []

    def _TranslateTerms(
        self,
        terms: List[Term],
        address_family: str,
        filter_name: str,
        hdr_comments: List[str],
        filter_options: List[str],
    ) -> None:
        srl_acl_entries: Dict[str, List[ACLEntry]] = {'inet': [], 'inet6': []}
        afs = ['inet', 'inet6'] if address_family == 'mixed' else [address_family]
        for term in terms:
            for term_af in afs:
                t = SRLTerm(term, term_af)
                for rule in t.ConvertToDict(filter_options):
                    self.total_rule_count += 1
                    rule['sequence-id'] = (len(srl_acl_entries[term_af]) + 1) * 5
                    srl_acl_entries[term_af].append(rule)
        desc = "_".join(hdr_comments)[:255] if hdr_comments else ""

        for af in srl_acl_entries.keys():
            if srl_acl_entries[af]:
                # r24.3 changed the syntax for filters. For r24.3 or higher use the option `r24.3`.
                if 'r24.3' in filter_options or R24_3_2 in filter_options:
                    key = "acl-filter"
                else:
                    key = "ipv4-filter" if af == 'inet' else "ipv6-filter"

                ip_filter = {
                    key: {
                        '_annotate': " ".join(aclgenerator.AddRepositoryTags()),
                        'name': filter_name,
                        'description': desc,
                        'entry': srl_acl_entries[af],
                    }
                }
                if 'stats' in filter_options:
                    ip_filter[key]['statistics-per-entry'] = True
                if 'r24.3' in filter_options or R24_3_2 in filter_options:
                    ip_filter[key]['type'] = "ipv4" if af == 'inet' else "ipv6"
                self.acl_sets.append(ip_filter)
