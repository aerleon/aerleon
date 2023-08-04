# Copyright 2021 Google Inc. All Rights Reserved.
# Modifications Copyright 2022-2023 Aerleon Project Authors.
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
from aerleon.lib.policy import Policy, Term

if sys.version_info < (3, 8):
    from typing_extensions import TypedDict
else:
    from typing import TypedDict


class Error(aclgenerator.Error):
    """Generic error class."""

class SRLinuxACLError(Error):
    """Raised with problems in formatting for OpenConfig firewall."""

class ExceededAttributeCountError(Error):
    """Raised when the total attribute count of a policy is above the maximum."""

# Graceful handling of dict hierarchy for SR Linux JSON.
def RecursiveDict() -> DefaultDict[Any, Any]:
    return defaultdict(RecursiveDict)


TransportConfig = TypedDict(
    "TransportConfig", {"source-port": Union[int, str], "destination-port": Union[int, str]}
)
Transport = TypedDict("Transport", {"transport": TransportConfig})
IPConfig = TypedDict(
    "IPConfig", {"source-address": str, "destination-address": str, "protocol": int}
)
IP = TypedDict("IP", {"config": IPConfig})
ActionConfig = TypedDict("ActionConfig", {"forwarding-action": str})
Action = TypedDict("Action", {"config": ActionConfig})
ACLEntry = TypedDict(
    "ACLEntry",
    {"sequence-id": int, "actions": Action, "ipv4": IP, "ipv6": IP, "transport": Transport},
)
aclEntries = TypedDict("aclEntries", {"acl-entry": List[ACLEntry]})
ACLSetConfig = TypedDict("ACLSetConfig", {"name": str, "type": str})
ACLSet = TypedDict(
    "ACLSet", {"acl-entries": aclEntries, "config": ACLSetConfig, "name": str, "type": str}
)


class Term(aclgenerator.Term):
    """Creates the term for the SR Linux ACL."""

    ACTION_MAP = {'accept': 'accept', 'deny': 'drop', 'reject': 'drop'}

    # ip-protocols always will resolve to an 8-bit int, but these
    # common names are more convenient in a policy file.
    _ALLOW_PROTO_NAME = frozenset(['tcp', 'udp', 'icmp', 'esp', 'ah', 'ipip', 'sctp'])

    AF_RENAME = {
        4: 'ipv4',
        6: 'ipv6',
    }

    def __init__(self, term: Term, inet_version: str = 'inet') -> None:
        super().__init__(term)
        self.term = term
        self.inet_version = inet_version

        # Combine (flatten) addresses with their exclusions into a resulting
        # flattened_saddr, flattened_daddr, flattened_addr.
        self.term.FlattenAll()

    def __str__(self) -> None:
        """Convert term to a string."""
        rules = self.ConvertToDict()
        json.dumps(rules, indent=2)

    def ConvertToDict(
        self,
    ) -> List[ACLEntry]:
        """Convert term to a dictionary.

        This is used to get a dictionary describing this term which can be
        output easily as an SR Linux JSON blob. It represents an "acl-entry"
        message from the OpenConfig ACL schema.

        Returns:
          A list of dictionaries that contains all fields necessary to create or
          update an SR Linux acl-entry.
        """
        term_dict = RecursiveDict()

        # Rules will hold all exploded acl-entry dictionaries.
        rules = []

        # Convert the integer to the proper openconfig schema name str, ipv4/ipv6.
        term_af = self.AF_MAP.get(self.inet_version)

        opts = [str(x) for x in self.term.option]

        # Action
        action = self.ACTION_MAP[self.term.action[0]]
        term_dict['action'] = { action: {} }

        # Ballot fatigue handling for 'any'.
        saddrs = self.term.GetAddressOfVersion('flattened_saddr', term_af)
        if not saddrs:
            saddrs = ['any']

        daddrs = self.term.GetAddressOfVersion('flattened_daddr', term_af)
        if not daddrs:
            daddrs = ['any']

        sports = self.term.source_port
        if not sports:
            sports = [(0, 0)]

        dports = self.term.destination_port
        if not dports:
            dports = [(0, 0)]

        protos = self.term.protocol
        if not protos:
            protos = ['none']

        ace_dict = copy.deepcopy(term_dict)
        _match = ace_dict['match'] = {}

        # Handle various options
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

        # Source Addresses
        for saddr in saddrs:
            if saddr != 'any':
                _match['source-ip'] = { 'prefix': str(saddr) }

            # Destination Addresses
            for daddr in daddrs:
                if daddr != 'any':
                    _match['destination-ip'] = { 'prefix': str(daddr) }

                # Source Port
                for start, end in sports:
                    # 'any' starts and ends with zero.
                    if not start == end == 0:
                        if start == end:
                            _match['source-port'] = { 'value': int(start) }
                        else:
                            _match['source-port'] = { 'range': { 'start': start, 
                                                                 'end': end } }

                    # Destination Port
                    for start, end in dports:
                        if not start == end == 0:
                            if start == end:
                              _match['destination-port'] = { 'value': int(start) }
                            else:
                              _match['destination-port'] = { 'range': { 'start': start,
                                                                        'end': end } }

                        # Protocol
                        for proto in protos:
                            if isinstance(proto, str):
                                if proto != 'none':
                                    try:
                                        proto_num = self.PROTO_MAP[proto]
                                    except KeyError:
                                        raise SRLinuxACLError(
                                            'Protocol %s unknown. Use an integer.', proto
                                        )
                                    _match['protocol'] = proto_num
                                rules.append(copy.deepcopy(ace_dict))
                            else:
                                proto_num = proto
                                _match['protocol'] = proto_num
                                # This is the business end of ace explosion.
                                # A dict is a reference type, so deepcopy is actually required.
                                rules.append(copy.deepcopy(ace_dict))

        return rules


class NokiaSRLinux(aclgenerator.ACLGenerator):
    """A Nokia SR Linux ACL object."""

    _PLATFORM = 'nokiasrl'
    SUFFIX = '.srl_acl'
    _SUPPORTED_AF = frozenset(('inet', 'inet6'))

    def _BuildTokens(self) -> Tuple[Set[str], Dict[str, Set[str]]]:
        """Build supported tokens for platform.

        Returns:
          tuple containing both supported tokens and sub tokens
        """
        supported_tokens, supported_sub_tokens = super()._BuildTokens()

        # Remove unsupported things, note icmp-type could be supported
        supported_tokens -= {'platform', 'platform_exclude', 'verbatim', 'icmp-type'}

        # SR Linux ACL model only supports these 2 forwarding actions.
        supported_sub_tokens['action'] = {'accept', 'deny' } # removed 'reject'
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

    def _TranslatePolicy(self, pol: Policy, exp_info: int) -> None:
        total_rule_count = 0
        self.acl_sets: List[ACLSet] = []

        for header, terms in pol.filters:
            filter_options = header.FilterOptions(self._PLATFORM)
            filter_name = header.FilterName(self._PLATFORM)

            # Options are anything after the platform name in the target message of
            # the policy header, [1:].

            # Get the address family if set.
            address_family = 'inet'
            for i in self._SUPPORTED_AF:
                if i in filter_options:
                    address_family = i
                    filter_options.remove(i)

            oc_acl_entries: List[ACLEntry] = []

            for term in terms:

                # Handle mixed for each indvidual term as inet and inet6.
                # inet/inet6 are treated the same.
                term_address_families = []
                if address_family == 'mixed':
                    term_address_families = ['inet', 'inet6']
                else:
                    term_address_families = [address_family]
                for term_af in term_address_families:
                    t = Term(term, term_af)

                    for rule in t.ConvertToDict():
                        total_rule_count += 1
                        rule['sequence-id'] = total_rule_count * 5
                        oc_acl_entries.append(rule)

            ip_filter = {
                'ipv4-filter' if address_family=='inet' else 'ipv6-filter': {
                   'entry': oc_acl_entries
                }
            }
            self.acl_sets.append(ip_filter)

        logging.info('Total rule count of policy %s is: %d', filter_name, total_rule_count)

    def __str__(self) -> str:
        out = '%s\n\n' % (
            json.dumps(self.acl_sets, indent=2, separators=(',', ': '), sort_keys=True)
        )

        return out
