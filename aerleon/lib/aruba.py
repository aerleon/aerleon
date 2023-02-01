# Copyright 2017 Google Inc. All Rights Reserved.
# Modifications Copyright 2022-2023 Aerleon Project Authors.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Aruba generator."""

from typing import List, Tuple

from absl import logging

from aerleon.lib import aclgenerator

_COMMENT_MARKER = '#'
_TERMINATOR_MARKER = '!'


class Error(aclgenerator.Error):
    """Base error class."""


class Term(aclgenerator.Term):
    """A single Aruba ACL term, mostly used for the __str__() method.

    Args:
      term: policy.Term object.
      filter_type: IP address version number.
    """

    _PLATFORM = 'aruba'

    _ANY_STR = 'any'
    _ALIAS_STR = 'alias'
    _IPV6_START_STR = 'ipv6'
    _NET_DEST_STR = 'netdestination'
    _NEGATOR = 'no'
    _SRC_NETDEST_SUF = '_src'
    _DST_NETDEST_SUF = '_dst'
    _NETWORK_STRING = 'network'
    _HOST_STRING = 'host'
    _USER_STR = 'user'
    _SOURCE_IS_USER_OPT_STR = 'source-is-user'
    _DESTINATION_IS_USER_OPT_STR = 'destination-is-user'
    _NEGATE_OPT_STR = 'negate'
    _IDENT = '  '

    _COMMENT_LINE_LENGTH = 70

    _ACTIONS = {
        'accept': 'permit',
        'deny': 'deny',
    }

    _PROTOCOL_MAP = {
        'icmp': 1,
        'gre': 47,
        'esp': 50,
    }

    def __init__(self, term, filter_type, verbose=True):
        super().__init__(term)
        self.term = term
        self.filter_type = filter_type
        self.netdestinations = []
        self.verbose = verbose

    def __str__(self):
        netdestinations = []
        ret_str = []
        term_af = self.AF_MAP.get(self.filter_type)

        if self.term.verbatim:
            for next_verbatim in self.term.verbatim:
                if next_verbatim[0] == self._PLATFORM and next_verbatim[1]:
                    ret_str.append('%s%s' % (self._IDENT, next_verbatim[1]))

            return '\n'.join(t for t in ret_str if t)
        if self.verbose:
            comments = self.term.comment[:]

            if self.term.owner:
                comments.append('Owner: %s' % self.term.owner)

            if comments:
                for line in aclgenerator.WrapWords(comments, self._COMMENT_LINE_LENGTH):
                    ret_str.append('%s%s %s' % (self._IDENT, _COMMENT_MARKER, line))

        src_addr_token = ''
        dst_addr_token = ''

        if self._SOURCE_IS_USER_OPT_STR in self.term.option:
            src_addr_token = self._USER_STR
        else:
            if self.term.source_address:
                src_addr = self.term.GetAddressOfVersion('source_address', term_af)
                if not src_addr:
                    return ''

                src_netdest_id = '%s%s' % (self.term.name.lower(), self._SRC_NETDEST_SUF)
                src_addr_token = '%s %s' % (self._ALIAS_STR, src_netdest_id)
                netdestinations.append(self._GenerateNetdest(src_netdest_id, src_addr, term_af))

            else:
                src_addr_token = self._ANY_STR

        if self._DESTINATION_IS_USER_OPT_STR in self.term.option:
            dst_addr_token = self._USER_STR
        else:
            if self.term.destination_address:
                dst_addr = self.term.GetAddressOfVersion('destination_address', term_af)
                if not dst_addr:
                    return ''

                dst_netdest_id = '%s%s' % (self.term.name.lower(), self._DST_NETDEST_SUF)
                dst_addr_token = '%s %s' % (self._ALIAS_STR, dst_netdest_id)
                netdestinations.append(self._GenerateNetdest(dst_netdest_id, dst_addr, term_af))
            else:
                dst_addr_token = self._ANY_STR

        dst_protocol_list = []
        if self.term.protocol:
            dst_protocol_list = self._GeneratePortTokens(
                self.term.protocol, self.term.destination_port
            )
        else:
            dst_protocol_list = [self._ANY_STR]

        for dst_port in dst_protocol_list:
            str_tok = [' ']

            if self._NEGATE_OPT_STR in self.term.option:
                str_tok.append(self._NEGATOR)

            if term_af == 6:
                str_tok.append(self._IPV6_START_STR)

            str_tok.append(src_addr_token)
            str_tok.append(dst_addr_token)

            str_tok.append(dst_port)
            str_tok.append(self._ACTIONS.get(self.term.action[0]))
            ret_str.append(' '.join(t for t in str_tok if t))

        self.netdestinations = netdestinations

        return '\n'.join(t for t in ret_str if t)

    def _GenerateNetdest(self, addr_netdestid, addresses, af):
        """Generates the netdestinations text block.

        Args:
          addr_netdestid: netdestinations identifier.
          addresses: IP addresses.
          af: address family.
        Returns:
          A text block suitable for netdestinations in Aruba ACLs.
        """
        ret_str = []

        # Aruba does not use IP version identifier for IPv4.
        addr_family = '6' if af == 6 else ''

        ret_str.append('%s %s' % (self._NET_DEST_STR + addr_family, addr_netdestid))

        for address in addresses:
            ret_str.append('%s%s' % (self._IDENT, self._GenerateNetworkOrHostTokens(address)))

        ret_str.append('%s\n' % _TERMINATOR_MARKER)

        return '\n'.join(t for t in ret_str if t)

    def _GenerateNetworkOrHostTokens(self, address):
        """Generates the text block host or network identifier for netdestinations.

        Args:
          address: IP address.
        Returns:
          A string line using either 'host' or 'network', properly formatted for
          Aruba ACLs.
        """
        if address.num_addresses == 1:
            return '%s %s' % (self._HOST_STRING, address.network_address)

        if address.version == 6:
            return '%s %s/%s' % (self._NETWORK_STRING, address.network_address, address.prefixlen)

        return '%s %s %s' % (self._NETWORK_STRING, address.network_address, address.netmask)

    def _GeneratePortTokens(self, protocols: List[str], ports: List[Tuple[int, int]]):
        """Generates string tokens for ports.

        Args:
          protocols: protocol to use (e.g. tcp, udp, etc.)
          ports: A list of tuples representing port ranges.
        Returns:
          A list of strings to be used as the port selector in Aruba ACLs.
        """
        ret_ports = []

        for protocol in protocols:
            if protocol in self._PROTOCOL_MAP:
                return [str(self._PROTOCOL_MAP[protocol])]
            for start_port, end_port in sorted(ports):
                ret_ports.append(
                    f'{protocol.lower()} {start_port}{" " + str(end_port) if start_port != end_port else ""}'
                )
        return ret_ports


class Aruba(aclgenerator.ACLGenerator):
    """An Aruba policy object.

    This class takes a policy object and renders the output (via __str__ method)
    into a syntax which is understood by Aruba devices.

    Args:
      pol: policy.Policy object.
    """

    SUFFIX = '.aacl'
    _PLATFORM = 'aruba'

    _ACL_LINE_HEADER = 'ip access-list session'

    def _BuildTokens(self):
        """Build supported tokens for platform.

        Returns:
          Tuple containing both supported tokens and sub tokens.
        """
        supported_tokens, supported_sub_tokens = super()._BuildTokens()

        supported_tokens -= {
            'destination_address_exclude',
            'icmp_type',
            'source_port',
            'source_address_exclude',
        }

        supported_sub_tokens.update(
            {
                'action': {
                    'accept',
                    'deny',
                },
                'option': {
                    'source-is-user',
                    'destination-is-user',
                    'negate',
                },
            }
        )

        del supported_sub_tokens['icmp_type']

        return supported_tokens, supported_sub_tokens

    def _TranslatePolicy(self, pol, exp_info):
        self.aruba_policies = []

        for header, terms in pol.filters:
            filter_name = header.FilterName(self._PLATFORM)
            filter_options = header.FilterOptions(self._PLATFORM)
            verbose = True
            if 'noverbose' in filter_options:
                filter_options.remove('noverbose')
                verbose = False

            filter_type = 'inet'
            if 'inet6' in filter_options:
                filter_type += '6'

            new_terms = []
            for term in terms:
                new_terms.append(Term(term, filter_type, verbose))

            self.aruba_policies.append((filter_name, new_terms, filter_type))

    def __str__(self):
        target = []

        target.extend(aclgenerator.AddRepositoryTags('%s ' % _COMMENT_MARKER))

        for filter_name, terms, _ in self.aruba_policies:
            netdestinations = []
            term_strings = []

            for term in terms:
                term_strings.append(str(term))
                netdestinations.extend(term.netdestinations)

            target.extend(netdestinations)
            target.append('%s %s' % (self._ACL_LINE_HEADER, filter_name))
            target.extend(term_strings)
            target.extend(_TERMINATOR_MARKER)

        if target:
            target.append('')

        return '\n'.join(target)
