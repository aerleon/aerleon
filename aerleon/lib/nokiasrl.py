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

import copy
import json
import sys
from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, Set, Tuple, Union

from absl import logging

from aerleon.lib import aclgenerator
from aerleon.lib import openconfig
from aerleon.lib.policy import Policy, Term

if sys.version_info < (3, 8):
    from typing_extensions import TypedDict
else:
    from typing import TypedDict


Match = TypedDict(
    "Match", {"fragment": bool, "first-fragment": bool, "protocol": int, "next-header": int}
)
Action = TypedDict("Action", {"accept": None, "drop": None})
ACLEntry = TypedDict(
    "ACLEntry",
    {"sequence-id": int, "action": Action, "match": Match},
)
aclEntries = TypedDict(
    "aclEntries", {"ipv4-filter": List[ACLEntry], "ipv6-filter": List[ACLEntry]}
)


class SRLTerm(openconfig.OCTerm):
    """Creates the term for the SR Linux ACL."""

    ACTION_MAP = {'accept': 'accept', 'deny': 'drop', 'reject': 'drop'}

    def SetAction(self, dict: dict) -> None:
        action = self.ACTION_MAP[self.term.action[0]]
        dict['action'] = {action: {}}

    def SetOptions(self, dict: dict) -> None:
        # Handle various options
        opts = [str(x) for x in self.term.option]
        _match = dict['match'] = {}
        if ('fragments' in opts) or ('is-fragment' in opts):
            _match['fragment'] = True
        if 'first-fragment' in opts:
            _match['first-fragment'] = True

        if 'initial' in opts or 'tcp-initial' in opts:
            _match['tcp-flags'] = "syn"
        if 'rst' in opts:
            _match['tcp-flags'] = "syn&rst" if 'tcp-flags' in _match else "rst"
        if 'not-syn-ack' in opts:
            _match['tcp-flags'] = "!(syn&ack)"
        # Note: not handling established | tcp-established, could throw error

    def SetSourceAddress(self, dict: dict, family: str, saddr: str) -> None:
        dict['match']['source-ip'] = {'prefix': saddr}

    def SetDestAddress(self, dict: dict, family: str, daddr: str) -> None:
        dict['match']['destination-ip'] = {'prefix': daddr}

    def SetSourcePorts(self, dict: dict, start: int, end: int) -> None:
        if start == end:
            dict['match']['source-port'] = {'value': start}
        else:
            dict['match']['source-port'] = {'range': {'start': start, 'end': end}}

    def SetDestPorts(self, dict: dict, start: int, end: int) -> None:
        if start == end:
            dict['match']['destination-port'] = {'value': start}
        else:
            dict['match']['destination-port'] = {'range': {'start': start, 'end': end}}

    def SetProtocol(self, dict: dict, family: str, protocol: int) -> None:
        field_name = "protocol" if family == "ipv4" else "next-header"
        dict['match'][field_name] = protocol


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

        # Remove unsupported things, note icmp-type could be supported
        supported_tokens -= {'platform', 'platform_exclude', 'verbatim', 'icmp-type'}

        # SR Linux ACL model only supports these 2 forwarding actions.
        supported_sub_tokens['action'] = {'accept', 'deny'}  # removed 'reject'
        supported_sub_tokens['option'] = {
            #  'established',
            'first-fragment',
            'is-fragment',
            'fragments',
            #  'sample',
            #  'tcp-established',
            'tcp-initial',
            #  'inactive',
            'not-syn-ack',
        }
        return supported_tokens, supported_sub_tokens

    def _TranslateTerms(self, terms: List[Term], address_family: str, filter_name: str) -> None:
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
                    rule['sequence-id'] = self.total_rule_count * 5
                    srl_acl_entries.append(rule)
        ip_filter = {
            'ipv4-filter'
            if address_family == 'inet'
            else 'ipv6-filter': {'entry': srl_acl_entries}
        }
        self.acl_sets.append(ip_filter)
