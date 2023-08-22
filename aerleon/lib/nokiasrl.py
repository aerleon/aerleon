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
    {"sequence-id": int, "action": Action, "match": Match},
)
Entries = TypedDict("Entries", {"entry": List[ACLEntry], "description": str})
IPFilters = TypedDict("IPFilters", {"ipv4-filter": Entries, "ipv6-filter": Entries})


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

    def SetAction(self) -> None:
        action = self.ACTION_MAP[self.term.action[0]]
        log = {}
        if self.term.logging:
            if action == 'drop':
                log = {"log": True}
            else:
                raise UnsupportedLogging(
                    f'logging can only be used with deny in term {self.term.name}'
                )
        self.term_dict['action'] = {action: log}

    def SetComments(self, comments: List[str]) -> None:
        self.term_dict['description'] = "_".join(comments)[:255]

    def SetOptions(self, family: str) -> None:
        # Handle various options
        opts = [str(x) for x in self.term.option]
        self.term_dict['match'] = {}
        if ('fragments' in opts) or ('is-fragment' in opts):
            self.term_dict['match']['fragment'] = True
        if 'first-fragment' in opts:
            self.term_dict['match']['first-fragment'] = True

        if 'initial' in opts or 'tcp-initial' in opts:
            self.term_dict['match']['tcp-flags'] = "syn"
        if 'rst' in opts:
            self.term_dict['match']['tcp-flags'] = (
                "syn&rst" if 'tcp-flags' in self.term_dict['match'] else "rst"
            )
        if 'not-syn-ack' in opts:
            self.term_dict['match']['tcp-flags'] = "!(syn&ack)"

        def _tcp_established():
            self.term_dict['match']['tcp-flags'] = "ack|rst"

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
                    self.SetProtocol(family=family, protocol="udp")
                    if not self.term.destination_port:
                        self.SetDestPorts(1024, 65535)
                else:  # Could produce 2 rules if [tcp,udp]
                    raise EstablishedWithNonTcpUdpError(
                        f'established can only be used with tcp or udp protocol in term {self.term.name}'
                    )
            else:
                raise EstablishedWithNoProtocolError(
                    f'must specify a protocol for "established" in term {self.term.name}'
                )

        if 'tcp-flags' in self.term_dict['match']:
            self.SetProtocol(family=family, protocol="tcp")

    def SetSourceAddress(self, family: str, saddr: str) -> None:
        self.term_dict['match']['source-ip'] = {'prefix': saddr}

    def SetDestAddress(self, family: str, daddr: str) -> None:
        self.term_dict['match']['destination-ip'] = {'prefix': daddr}

    def SetSourcePorts(self, start: int, end: int) -> None:
        if start == end:
            self.term_dict['match']['source-port'] = {'value': start}
        else:
            self.term_dict['match']['source-port'] = {'range': {'start': start, 'end': end}}

    def SetDestPorts(self, start: int, end: int) -> None:
        if start == end:
            self.term_dict['match']['destination-port'] = {'value': start}
        else:
            self.term_dict['match']['destination-port'] = {'range': {'start': start, 'end': end}}

    def SetProtocol(self, family: str, protocol: int) -> None:
        field_name = "protocol" if family == "ipv4" else "next-header"
        self.term_dict['match'][field_name] = protocol


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
        self, terms: List[Term], address_family: str, filter_name: str, hdr_comments: List[str]
    ) -> None:
        srl_acl_entries: List[ACLEntry] = []
        for term in terms:
            # Handle mixed for each indvidual term as inet and inet6.
            # inet/inet6 are treated the same.
            term_address_families = []
            if address_family == 'mixed':
                term_address_families = ['inet', 'inet6']
            else:
                term_address_families = [address_family]
            for term_af in term_address_families:
                t = SRLTerm(term, term_af)
                for rule in t.ConvertToDict():
                    self.total_rule_count += 1
                    rule['sequence-id'] = (len(srl_acl_entries) + 1) * 5
                    srl_acl_entries.append(rule)
        desc = "_".join(hdr_comments)[:255] if hdr_comments else ""
        ip_filter = {
            'ipv4-filter'
            if address_family == 'inet'
            else 'ipv6-filter': {
                'description': desc,
                'entry': srl_acl_entries,
                'name': filter_name,
            }
        }
        self.acl_sets.append(ip_filter)
