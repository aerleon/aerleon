# Copyright 2008 Google Inc. All Rights Reserved.
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

"""Unittest for iptables rendering module."""

import datetime
import re
from unittest import mock

from absl.testing import absltest

from aerleon.lib import aclgenerator, iptables, nacaddr, naming, policy
from aerleon.lib import yaml as yaml_frontend
from tests.regression_utils import capture

GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: iptables INPUT ACCEPT
}
"""

GOOD_HEADER_2 = """
header {
  comment:: "this is a test acl"
  target:: iptables OUTPUT DROP
}
"""

GOOD_HEADER_3 = """
header {
  comment:: "this is a test acl with abbreviation"
  target:: iptables INPUT ACCEPT abbreviateterms
}
"""

GOOD_HEADER_4 = """
header {
  comment:: "this is a test acl with truncation"
  target:: iptables INPUT ACCEPT truncateterms
}
"""

GOOD_HEADER_5 = """
header {
  comment:: "this is a test acl with no default target"
  target:: iptables INPUT
}
"""

GOOD_HEADER_6 = """
header {
  comment:: "this is a test acl with a custom chain and no default target"
  target:: iptables foo
}
"""

GOOD_HEADER_7 = """
header {
  comment:: "this is a test acl with a custom chain and no default target"
  target:: iptables foo noverbose
}
"""

IPV6_HEADER_1 = """
header {
  comment:: "test header for inet6 terms"
  target:: iptables INPUT DROP inet6
}
"""

NON_STANDARD_CHAIN = """
header {
  comment:: "this is a test acl with non-standard chain"
  target:: iptables foo ACCEPT
}
"""

NOSTATE_HEADER = """
header {
  comment:: "iptables filter without stateful"
  target:: iptables INPUT ACCEPT nostate
}
"""

CHAIN_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: iptables foobar_chain nostate
}
"""

BAD_HEADER_2 = """
header {
  target:: juniper
}
"""

BAD_HEADER_3 = """
header {
  target:: iptables INPUT MAYBE
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_2 = """
term good-term-2 {
  source-address:: INTERNAL
  source-exclude:: OOB_NET
  protocol:: tcp
  source-port:: HTTP
  action:: accept
}
"""

GOOD_TERM_3 = """
term good-term-3 {
  source-port:: HTTP
  protocol:: tcp
  option:: rst fin tcp-established established
  action:: accept
}
"""

GOOD_TERM_4 = """
term good-term-4 {
  protocol:: tcp udp esp ah gre icmp 50
  action:: accept
}
"""

GOOD_TERM_5 = """
term good-term-5 {
  verbatim:: iptables "mary had a little lamb"
  verbatim:: cisco "mary had second lamb"
  verbatim:: juniper "mary had third lamb"
}
"""

GOOD_TERM_6 = """
term good-term-6 {
  comment:: "Some text describing what this block does,
             possibly including newines, blank lines,
             and extra-long comments (over 255 characters)
             %(long_line)s

             All these cause problems if passed verbatim to iptables.
             "
  comment:: ""
  protocol:: tcp
  action:: accept

}
""" % {
    'long_line': '-' * 260
}


GOOD_TERM_7 = """
term drop-short-initial-fragments {
  option:: first-fragment
  packet-length:: 1-119
  action:: deny
}

term drop-header-overwrite {
  fragment-offset:: 1-119
  action:: deny
}
"""

GOOD_TERM_8 = """
term block-some-icmp {
  protocol:: icmp
  icmp-type:: router-solicitation information-request unreachable echo-reply
  action:: deny
}
"""

GOOD_TERM_9 = """
term good-term-9 {
  source-address:: SOME_SOURCE
  destination-address:: SOME_DEST
  protocol:: tcp
  source-port:: HTTP
  action:: accept
}
"""

GOOD_TERM_10 = """
term good-term-10 {
  owner:: foo@google.com
  action:: accept
}
"""

GOOD_TERM_11 = """
term good_term_11 {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 3 4
  action:: accept
}
"""

GOOD_TERM_12 = """
term good_term_12 {
  comment:: "FOOO"
  action:: accept
}
"""

GOOD_TERM_13 = """
term good_term_13 {
  logging:: syslog
  log-limit:: 99/day
  action:: accept
}
"""

HOPOPT_TERM = """
term hopopt-term {
  protocol:: hopopt
  action:: accept
}
"""

BAD_LOGGING_TERM = """
term bad_logging_term {
  log-limit:: 99/day
  action:: accept
}
"""

BAD_QUOTE_TERM_1 = """
term bad-quote-term-1 {
  comment:: "Text describing without quotes"
  protocol:: tcp
  action:: accept
}
"""

IPV6_TERM_1 = """
term inet6-icmp {
  protocol:: icmpv6
  icmp-type:: destination-unreachable time-exceeded echo-reply
  action:: deny
}
"""

IPV6_HEADERS = """
term ipv6-header-1 {
  protocol:: hopopt
  action:: deny
}

term ipv6-header-2 {
  protocol:: fragment
  action:: deny
}
"""

ICMPV6_TERM_1 = """
term inet6-icmp {
  source-address:: IPV6_INTERNAL
  protocol:: icmpv6
  icmp-type:: destination-unreachable
  action:: deny
}
"""

LOGGING_TERM_1 = """
term foo {
  protocol:: tcp
  logging:: syslog
  action:: accept
}
"""

UDP_STATE_TERM = """
term test-conntrack-udp {
  protocol:: udp
  option:: established
  action:: accept
}
"""

TCP_STATE_TERM = """
term tcp-established-only {
  protocol:: tcp
  option:: established
  action:: accept
}
"""

STATEFUL_ONLY_TERM = """
term stateful-only {
  option:: established
  action:: accept
}
"""

BAD_LONG_TERM_NAME = """
term this-term-name-is-really-far-too-long {
  protocol:: tcp
  action:: accept
}
"""

GOOD_LONG_TERM_NAME = """
term google-experiment-abbreviations {
  protocol:: tcp
  action:: accept
}
"""

GOOD_MULTIPORT = """
term multiport {
  source-port:: FOURTEEN_PORTS
  protocol:: tcp
  action:: accept
}
"""

MULTIPORT_SWAP = """
term multiport {
  source-port:: HTTP HTTPS
  destination-port:: SSH
  protocol:: tcp
  action:: accept
}
"""

EXPIRED_TERM = """
term is_expired {
    expiration:: 2001-01-01
    action:: accept
}
"""

EXPIRING_TERM = """
term is_expiring {
  expiration:: %s
  action:: accept
}
"""

GOOD_MULTIPORT_RANGE = """
term bad-mport-ranges {
  destination-port:: FIFTEEN_PORTS_WITH_RANGES
  protocol:: tcp
  action:: accept
}
"""

LARGE_MULTIPORT = """
term bad-multiport {
  destination-port:: LOTS_OF_PORTS
  protocol:: tcp
  action:: accept
}
"""

DUAL_LARGE_MULTIPORT = """
term bad-multiport {
  source-port:: LOTS_OF_SPORTS
  destination-port:: LOTS_OF_DPORTS
  protocol:: tcp
  action:: accept
}
"""

UNSUPPORTED_TERM = """
term ether-type-filter {
  ether-type:: arp
  action:: accept
}
"""

UNKNOWN_TERM_KEYWORD = """
term unknown-keyword {
  comment:: "imaginary new keyword added to the policy library."
  comment:: "i.e. ip-options-count:: 2-255"
  comment:: "must be added in tests due to checking in policy library."
  action:: deny
}
"""

UNSUPPORTED_EXCEPT = """
term block-non-standard {
  protocol-except:: tcp udp icmp
  action:: deny
}
"""

REJECT_TERM1 = """
term reject-term1 {
  action:: reject-with-tcp-rst
}
"""

REJECT_TERM2 = """
term reject-term2 {
  action:: reject
}
"""

NEXT_TERM1 = """
term next-term1 {
  action:: next
}
"""

BAD_PROTOCOL_MATCHES = """
term proto-accept-and-reject {
  protocol:: tcp udp icmp
  protocol-except:: gre
  action:: accept
}
"""

SOURCE_INTERFACE_TERM = """
term src-interface {
  protocol:: tcp
  source-interface:: eth0
  action:: accept
}
"""

DESTINATION_INTERFACE_TERM = """
term dst-interface {
  protocol:: tcp
  destination-interface:: eth0
  action:: accept
}
"""

GOOD_WARNING_TERM = """
term good-warning-term {
  source-port:: HTTP
  protocol:: tcp
  option:: rst fin tcp-established established
  policer:: batman
  action:: accept
}
"""
BAD_ICMP_TERM = """
term permit-icmp {
	protocol:: icmp icmpv6
	action:: accept
}
"""

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'counter',
    'destination_address',
    'destination_address_exclude',
    'destination_interface',
    'destination_port',
    'destination_prefix',
    'expiration',
    'fragment_offset',
    'icmp_code',
    'icmp_type',
    'stateless_reply',
    'logging',
    'log_limit',
    'name',
    'option',
    'owner',
    'packet_length',
    'platform',
    'platform_exclude',
    'protocol',
    'routing_instance',
    'source_address',
    'source_address_exclude',
    'source_interface',
    'source_port',
    'source_prefix',
    'translated',
    'verbatim',
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'next', 'reject-with-tcp-rst'},
    'icmp_type': {
        'alternate-address',
        'certification-path-advertisement',
        'certification-path-solicitation',
        'conversion-error',
        'destination-unreachable',
        'echo-reply',
        'echo-request',
        'mobile-redirect',
        'home-agent-address-discovery-reply',
        'home-agent-address-discovery-request',
        'icmp-node-information-query',
        'icmp-node-information-response',
        'information-request',
        'inverse-neighbor-discovery-advertisement',
        'inverse-neighbor-discovery-solicitation',
        'mask-reply',
        'mask-request',
        'information-reply',
        'mobile-prefix-advertisement',
        'mobile-prefix-solicitation',
        'multicast-listener-done',
        'multicast-listener-query',
        'multicast-listener-report',
        'multicast-router-advertisement',
        'multicast-router-solicitation',
        'multicast-router-termination',
        'neighbor-advertisement',
        'neighbor-solicit',
        'packet-too-big',
        'parameter-problem',
        'redirect',
        'redirect-message',
        'router-advertisement',
        'router-renumbering',
        'router-solicit',
        'router-solicitation',
        'source-quench',
        'time-exceeded',
        'timestamp-reply',
        'timestamp-request',
        'unreachable',
        'version-2-multicast-listener-report',
    },
    'option': {
        'established',
        'first-fragment',
        'initial',
        'sample',
        'tcp-established',
        'tcp-initial',
        'syn',
        'ack',
        'fin',
        'rst',
        'urg',
        'psh',
        'all',
        'none',
    },
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class FakeTerm:
    name = ''
    protocol = ['tcp']


class AclCheckTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = mock.create_autospec(naming.Naming)

    @mock.patch.object(iptables.logging, 'warning')
    def testChainFilter(self, mock_warn):
        filter_name = 'foobar_chain'
        pol = policy.ParsePolicy(CHAIN_HEADER_1 + GOOD_TERM_1, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        # is the chain right?
        self.assertIn('-A foobar_chain -j f_good-term-1', result)
        # is the term named appropriately?
        self.assertIn('-N f_good-term-1', result)

        mock_warn.assert_called_once_with(
            'Filter is generating a non-standard chain that will '
            'not apply to traffic unless linked from INPUT, '
            'OUTPUT or FORWARD filters. New chain name is: %s',
            filter_name,
        )

    def testUnsupportedTargetOption(self):
        pol = policy.ParsePolicy(BAD_HEADER_3 + GOOD_TERM_1, self.naming)
        self.assertRaises(iptables.UnsupportedTargetOptionError, iptables.Iptables, pol, EXP_INFO)

    @capture.stdout
    def testGoodPolicy(self):
        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_1, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn('-P OUTPUT DROP', result, 'output default policy of drop not set.')
        self.assertIn('-N O_good-term-1', result, 'did not find new chain for good-term-1.')
        self.assertIn(
            '-A O_good-term-1 -p icmp -m state ' '--state NEW,ESTABLISHED,RELATED -j ACCEPT',
            result,
            'did not find append for good-term-1.',
        )
        print(result)

    @capture.stdout
    def testCustomChain(self):
        acl = iptables.Iptables(
            policy.ParsePolicy(NON_STANDARD_CHAIN + GOOD_TERM_1, self.naming), EXP_INFO
        )
        result = str(acl).split('\n')
        self.assertIn('-N foo', result, 'did not find new chain for foo.')
        self.assertNotIn('-P foo', result, 'chain foo may not have a policy set.')
        print(acl)

    @capture.stdout
    def testChainNoTarget(self):
        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_5 + GOOD_TERM_1, self.naming), EXP_INFO
        )
        result = str(acl).split('\n')
        for line in result:
            self.assertFalse(line.startswith(':INPUT'), 'chain may not have a policy set.')
            self.assertFalse(line.startswith('-P INPUT'), 'chain may not have a policy set.')
            self.assertFalse(line.startswith('-N INPUT'), 'attempting to create a built-in chain.')
        print(acl)

    @capture.stdout
    def testCustomChainNoTarget(self):
        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_6 + GOOD_TERM_1, self.naming), EXP_INFO
        )
        result = str(acl).split('\n')
        self.assertIn('-N foo', result, 'did not find a new chain for foo.')
        for line in result:
            self.assertFalse(line.startswith(':foo'), 'chain may not have a policy set.')
            self.assertFalse(line.startswith('-P foo'), 'chain may not have a policy set.')
        print(acl)

    @capture.stdout
    def testExcludeReturnsPolicy(self):
        #
        # In this test, we should get fewer lines of output by performing
        # early return jumps on excluded addresses.
        #
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IPv4('10.0.0.0/8')],
            [nacaddr.IPv4('10.0.0.0/24')],
        ]
        self.naming.GetServiceByProto.return_value = ['80']

        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn('-P INPUT ACCEPT', result, 'no default policy found.')
        self.assertIn('-p tcp', result, 'no protocol specification found.')
        self.assertIn('-s ', result, 'no source address found.')
        self.assertIn(
            '-s 10.0.0.0/24 -j RETURN',
            result,
            'expected address 10.0.0.0/24 not jumping to RETURN.',
        )
        self.assertIn(
            '--sport 80 -s 10.0.0.0/8', result, 'expected source address 10.0.0.0/8 not accepted.'
        )

        self.naming.GetNetAddr.assert_has_calls([mock.call('INTERNAL'), mock.call('OOB_NET')])
        self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')
        print(result)

    @capture.stdout
    def testExcludeAddressesPolicy(self):
        #
        # In this test, we should get fewer lines of output from excluding
        # addresses from the specified destination.
        #
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IPv4('10.0.0.0/8')],
            [nacaddr.IPv4('10.128.0.0/9'), nacaddr.IPv4('10.64.0.0/10')],
        ]
        self.naming.GetServiceByProto.return_value = ['80']

        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn(
            '--sport 80 -s 10.0.0.0/10',
            result,
            'expected source address 10.0.0.0/10 not accepted.',
        )

        self.naming.GetNetAddr.assert_has_calls([mock.call('INTERNAL'), mock.call('OOB_NET')])
        self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')
        print(result)

    @capture.stdout
    def testAddExcludeSourceForLengthPolicy(self):
        #
        # In this test, we should generate fewer lines of output by
        # excluding the inverted the source and performing early returns on
        # the excluded range.
        #
        source_range = []
        for i in range(18):
            address = nacaddr.IPv4(10 * 256 * 256 * 256 + i * 256 * 256)
            source_range.append(address.supernet(15))  # Grow to /17

        dest_range = []
        for i in range(40):
            address = nacaddr.IPv4(10 * 256 * 256 * 256 + i * 256)
            dest_range.append(address.supernet(7))  # Grow to /25

        self.naming.GetNetAddr.side_effect = [source_range, dest_range]
        self.naming.GetServiceByProto.return_value = ['80']

        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_9, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn('-P INPUT ACCEPT', result, 'no default policy found.')
        self.assertIn('-p tcp', result, 'no protocol specification found.')
        self.assertLess(
            result.count('\n'),
            len(source_range) * len(dest_range),
            'expected less than %d rows, got %d'
            % (len(source_range) * len(dest_range), result.count('\n')),
        )
        self.assertIn(
            '-s 0.0.0.0/5 -j RETURN', result, 'expected address 0.0.0.0/5 to RETURN:\n' + result
        )
        self.assertIn(
            '-s 10.0.128.0/17 -j RETURN',
            result,
            'expected address 10.0.128.0/17 not jumping to RETURN:\n' + result,
        )
        self.assertTrue(
            re.search('--sport 80 -d 10.0.1.0/25 [^\n]* -j ACCEPT', result),
            'expected destination addresss 10.0.1.0/25 accepted:\n' + result,
        )

        self.naming.GetNetAddr.assert_has_calls([mock.call('SOME_SOURCE'), mock.call('SOME_DEST')])
        self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')
        print(result)

    @capture.stdout
    def testAddExcludeDestForLengthPolicy(self):
        #
        # In this test, we should generate fewer lines of output by
        # excluding the inverted the source and performing early returns on
        # the excluded range.
        #
        source_range = []
        for i in range(40):
            address = nacaddr.IPv4(10 * 256 * 256 * 256 + i * 256)
            source_range.append(address.supernet(7))  # Grow to /25

        dest_range = []
        for i in range(18):
            address = nacaddr.IPv4(10 * 256 * 256 * 256 + i * 256 * 256)
            dest_range.append(address.supernet(15))  # Grow to /17

        self.naming.GetNetAddr.side_effect = [source_range, dest_range]
        self.naming.GetServiceByProto.return_value = ['80']

        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_9, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn('-P INPUT ACCEPT', result, 'no default policy found.')
        self.assertIn('-p tcp', result, 'no protocol specification found.')
        self.assertLess(
            result.count('\n'),
            len(source_range) * len(dest_range),
            'expected less than %d rows, got %d'
            % (len(source_range) * len(dest_range), result.count('\n')),
        )
        self.assertIn(
            '-d 0.0.0.0/5 -j RETURN', result, 'expected address 0.0.0.0/5 to RETURN:\n' + result
        )
        self.assertIn(
            '-d 10.0.128.0/17 -j RETURN',
            result,
            'expected address 10.0.128.0/17 not jumping to RETURN:\n' + result,
        )
        self.assertTrue(
            re.search('--sport 80 -s 10.0.1.0/25 [^\n]* -j ACCEPT', result),
            'expected destination addresss 10.0.1.0/25 accepted:\n' + result,
        )

        self.naming.GetNetAddr.assert_has_calls([mock.call('SOME_SOURCE'), mock.call('SOME_DEST')])
        self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')
        print(result)

    @capture.stdout
    def testOptions(self):
        self.naming.GetServiceByProto.return_value = ['80']

        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_3, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn('--tcp-flags FIN,RST FIN,RST', result, 'tcp flags missing or incorrect.')
        self.assertNotIn('-dport 1024:65535', result, 'destination port present.')
        self.assertIn(
            '-m state --state ESTABLISHED,RELATED',
            result,
            'missing or incorrect state information.',
        )

        self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')
        print(result)

    @capture.stdout
    def testRejectReset(self):
        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + REJECT_TERM1, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn(
            '-j REJECT --reject-with tcp-reset',
            result,
            'missing or incorrect reject specification.',
        )
        print(result)

    @capture.stdout
    def testReject(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + REJECT_TERM2, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn(
            '-j REJECT --reject-with icmp-host-prohibited',
            result,
            'missing or incorrect reject specification.',
        )
        print(result)

    @capture.stdout
    def testRejectIpv6(self):
        pol = policy.ParsePolicy(IPV6_HEADER_1 + REJECT_TERM2, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertNotIn('-p all', result, 'protocol spec present')
        self.assertIn(
            '-j REJECT --reject-with icmp6-adm-prohibited',
            result,
            'missing or incorrect reject specification.',
        )
        print(result)

    @capture.stdout
    def testIPv6Headers(self):
        pol = policy.ParsePolicy(IPV6_HEADER_1 + IPV6_HEADERS, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn(
            '-m u32 --u32 "0x3&0xff=0x0"', result, 'match for hop-by-hop header is missing'
        )
        self.assertIn(
            '-m u32 --u32 "0x3&0xff=0x2c"', result, 'match for fragment header is missing'
        )
        print(result)

    @capture.stdout
    def testNextTerm(self):
        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + NEXT_TERM1, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn('-j RETURN', result, 'jump to RETURN not found.')
        print(result)

    @capture.stdout
    def testProtocols(self):
        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_4, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn('-p tcp', result, 'protocol tcp not found.')
        self.assertIn('-p udp', result, 'protocol udp not found.')
        self.assertIn('-p esp', result, 'protocol esp not found.')
        self.assertIn('-p ah', result, 'protocol ah not found.')
        self.assertIn('-p gre', result, 'protocol gre not found.')
        self.assertIn('-p icmp', result, 'protocol icmp not found.')
        self.assertIn('-p 50', result, 'protocol 50 not found.')
        print(result)

    @capture.stdout
    def testVerbatimTerm(self):
        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_5, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn(
            'mary had a little lamb', result, 'first verbatim output is missing or incorrect.'
        )
        # check if another platforms verbatim shows up
        self.assertNotIn(
            'mary had a second lamb', result, 'second vebatim output is missing or incorrect.'
        )
        self.assertNotIn(
            'mary had a third lamb', result, 'third verbatim output is missing or incorrect.'
        )
        print(result)

    @capture.stdout
    def testCommentReflowing(self):
        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_6, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertNotIn('--comments ""', result, 'Iptables cannot handle empty comments')
        self.assertFalse(
            re.search('--comments "[^"]{256,}"', result),
            'Iptables comments must be under 255 characters.',
        )
        self.assertFalse(
            re.search('--comments "[^"]*\n', result),
            'Iptables comments may not contain newline characters.',
        )
        print(result)

    @capture.stdout
    def testCommentQuoteStripping(self):

        parsed_policy = policy.ParsePolicy(GOOD_HEADER_1 + BAD_QUOTE_TERM_1, self.naming)
        parsed_policy.filters[0][1][0].comment = ['Text "describing" "with" quotes']

        acl = iptables.Iptables(parsed_policy, EXP_INFO)
        result = str(acl)

        self.assertTrue(
            re.search('--comment "Text describing with quotes"', result),
            'Iptables did not strip out quotes',
        )
        print(result)

    def testLongTermName(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + BAD_LONG_TERM_NAME, self.naming)
        self.assertRaises(aclgenerator.TermNameTooLongError, iptables.Iptables, pol, EXP_INFO)

    @capture.stdout
    def testLongTermAbbreviation(self):
        pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_LONG_TERM_NAME, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn('-abbreviations', result, 'Our strings disappeared during abbreviation.')
        print(result)

    @capture.stdout
    def testLongTermTruncation(self):
        pol = policy.ParsePolicy(GOOD_HEADER_4 + GOOD_LONG_TERM_NAME, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn(
            'google-experiment-abbrev', result, 'Our strings disappeared during truncation.'
        )
        self.assertNotIn(
            'google-experiment-abbreviations', result, 'Term name was not truncated as expected.'
        )
        print(result)

    @capture.stdout
    def testFragmentOptions(self):
        pol = policy.ParsePolicy(GOOD_HEADER_3 + GOOD_TERM_7, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn('--u32 4&0x3FFF=0x2000', result, 'first-fragment rule is missing')
        self.assertIn('--length 1:119', result, 'length match is missing')
        self.assertIn('--u32 4&0x1FFF=1:119', result, 'fragment-offset rule is missing')
        print(result)

    @capture.stdout
    def testIcmpMatching(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_8, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn('--icmp-type 0', result, 'icmp-type 0 (echo-reply) is missing')
        self.assertIn('--icmp-type 3', result, 'icmp-type 3 (destination-unreachable) is missing')
        self.assertIn('--icmp-type 10', result, 'icmp-type 10 (router-solicit) is missing')
        self.assertIn('--icmp-type 15', result, 'icmp-type 15 (info-request) is missing')
        print(result)

    @capture.stdout
    def testIcmpCode(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_11, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn('--icmp-type 3/3', result, result)
        self.assertIn('--icmp-type 3/4', result, result)
        print(result)

    @capture.stdout
    def testConntrackUDP(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + UDP_STATE_TERM, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn(
            '-m state --state ESTABLISHED,RELATED',
            result,
            'udp connection tracking is missing state module',
        )
        self.assertNotIn(
            '-dport 1024:65535', result, 'udp connection tracking contains destination high-ports'
        )
        self.assertIn(
            '-p udp', result, 'udp connection tracking is missing protocol specification'
        )
        print(result)

    @capture.stdout
    def testConntrackAll(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + STATEFUL_ONLY_TERM, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn(
            '-m state --state ESTABLISHED,RELATED',
            result,
            'connection tracking is missing state module arguments',
        )
        self.assertNotIn(
            '-dport 1024:65535', result, 'High-ports should not appear for non-TCP/UDP protocols'
        )
        print(result)

    @capture.stdout
    def testTcpEstablishedNostate(self):
        pol = policy.ParsePolicy(NOSTATE_HEADER + TCP_STATE_TERM, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn(
            '%s %s' % ('--tcp-flags ACK,FIN,RST,SYN RST', '--dport 1024:65535 -j ACCEPT'),
            result,
            'No rule matching packets with RST bit only.\n' + result,
        )
        self.assertNotIn(
            '--state', result, 'Nostate header should not use nf_conntrack --state flag'
        )
        print(result)

    @capture.stdout
    def testUdpEstablishedNostate(self):
        pol = policy.ParsePolicy(NOSTATE_HEADER + UDP_STATE_TERM, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn(
            '-p udp --dport 1024:65535 -j ACCEPT',
            result,
            'No rule matching TCP packets with ACK bit.\n' + result,
        )
        self.assertNotIn(
            '--state', result, 'Nostate header should not use nf_conntrack --state flag'
        )
        print(result)

    def testEstablishedNostate(self):
        # when using "nostate" filter and a term with "option:: established"
        # have any protocol other than TCP and/or UDP should raise error.
        pol = policy.ParsePolicy(NOSTATE_HEADER + STATEFUL_ONLY_TERM, self.naming)
        self.assertRaises(aclgenerator.EstablishedError, iptables.Iptables, pol, EXP_INFO)

    def testUnsupportedFilter(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + UNSUPPORTED_TERM, self.naming)
        self.assertRaises(aclgenerator.UnsupportedFilterError, iptables.Iptables, pol, EXP_INFO)

    def testUnknownTermKeyword(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + UNKNOWN_TERM_KEYWORD, self.naming)
        # Adding a (fake) new property, e.g. if policy.py is updated.
        pol.filters[0][1][0].ip_options_count = '2-255'
        self.assertRaises(aclgenerator.UnsupportedFilterError, iptables.Iptables, pol, EXP_INFO)

    def testProtocolExceptUnsupported(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + UNSUPPORTED_EXCEPT, self.naming)
        self.assertRaises(aclgenerator.UnsupportedFilterError, iptables.Iptables, pol, EXP_INFO)

    def testTermNameConflict(self):
        pol = policy.ParsePolicy(
            GOOD_HEADER_2 + GOOD_TERM_1 + GOOD_TERM_1 + GOOD_TERM_1, self.naming
        )
        self.assertRaises(aclgenerator.DuplicateTermError, iptables.Iptables, pol, EXP_INFO)

    @capture.stdout
    def testMultiPort(self):
        ports = [str(x) for x in range(1, 29, 2)]
        self.naming.GetServiceByProto.return_value = ports

        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_MULTIPORT, self.naming), EXP_INFO
        )
        self.assertIn(
            '-m multiport --sports %s' % ','.join(ports),
            str(acl),
            'multiport module not used as expected.',
        )
        # b/10626420
        self.assertNotIn(
            '-m multiport --dports  -d', str(acl), 'invalid multiport syntax produced.'
        )

        self.naming.GetServiceByProto.assert_called_once_with('FOURTEEN_PORTS', 'tcp')
        print(acl)

    @capture.stdout
    def testMultiPortWithRanges(self):
        ports = [str(x) for x in (1, 3, 5, 7, 9, 11, 13, 15, 17, '19-21', '23-25', '27-29')]
        self.naming.GetServiceByProto.return_value = ports

        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_MULTIPORT_RANGE, self.naming), EXP_INFO
        )
        expected = '-m multiport --dports %s' % ','.join(ports).replace('-', ':')
        self.assertIn(expected, str(acl), 'multiport module not used as expected.')

        self.naming.GetServiceByProto.assert_called_once_with('FIFTEEN_PORTS_WITH_RANGES', 'tcp')
        print(acl)

    @capture.stdout
    def testMultiportSwap(self):
        self.naming.GetServiceByProto.side_effect = [['80'], ['443'], ['22']]

        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + MULTIPORT_SWAP, self.naming), EXP_INFO
        )
        expected = '--dport 22 -m multiport --sports 80,443'
        self.assertIn(expected, str(acl), 'failing to move single port before multiport values.')

        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('HTTP', 'tcp'), mock.call('HTTPS', 'tcp'), mock.call('SSH', 'tcp')]
        )
        print(acl)

    @capture.stdout
    def testMultiportLargePortCount(self):
        ports = [str(x) for x in range(1, 71, 2)]
        self.naming.GetServiceByProto.return_value = ports

        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + LARGE_MULTIPORT, self.naming), EXP_INFO
        )
        self.assertIn('-m multiport --dports 1,3,5,7,9', str(acl))
        self.assertIn('-m multiport --dports 29,31,33,35,37', str(acl))
        self.assertIn('-m multiport --dports 57,59,61,63,65,67,69', str(acl))

        self.naming.GetServiceByProto.assert_called_once_with('LOTS_OF_PORTS', 'tcp')
        print(acl)

    @capture.stdout
    def testMultiportDualLargePortCount(self):
        ports = [str(x) for x in range(1, 71, 2)]
        self.naming.GetServiceByProto.return_value = ports

        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + DUAL_LARGE_MULTIPORT, self.naming), EXP_INFO
        )
        self.assertIn('-m multiport --sports 1,3,5', str(acl))
        self.assertIn('-m multiport --sports 29,31,33', str(acl))
        self.assertIn('-m multiport --sports 57,59,61', str(acl))
        self.assertIn('23,25,27 -m multiport --dports 1,3,5', str(acl))
        self.assertIn('23,25,27 -m multiport --dports 29,31,33', str(acl))
        self.assertIn('23,25,27 -m multiport --dports 57,59,61', str(acl))
        self.assertIn('51,53,55 -m multiport --dports 1,3,5', str(acl))
        self.assertIn('51,53,55 -m multiport --dports 29,31,33', str(acl))
        self.assertIn('51,53,55 -m multiport --dports 57,59,61', str(acl))
        self.assertIn('65,67,69 -m multiport --dports 1,3,5', str(acl))
        self.assertIn('65,67,69 -m multiport --dports 29,31,33', str(acl))
        self.assertIn('65,67,69 -m multiport --dports 57,59,61', str(acl))

        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('LOTS_OF_SPORTS', 'tcp'), mock.call('LOTS_OF_DPORTS', 'tcp')]
        )
        print(acl)

    def testGeneratePortBadArguments(self):
        term = iptables.Term(FakeTerm(), 'test', True, 'test')
        # Both source and dest are true
        self.assertRaises(
            iptables.BadPortsError,
            term._GeneratePortStatement,
            [(1, 1), (2, 2)],
            source=True,
            dest=True,
        )

    def testGeneratePortNotImplemented(self):
        term = iptables.Term(FakeTerm(), 'test', True, 'test')
        # Both source and dest are false
        self.assertRaises(
            NotImplementedError,
            term._GeneratePortStatement,
            [(1, 1), (2, 2)],
            source=False,
            dest=False,
        )

    @capture.stdout
    def testLogging(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + LOGGING_TERM_1, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn('-j LOG --log-prefix foo', result, 'logging jump does not appear in output.')
        self.assertIn('-j ACCEPT', result, 'action jump does not appear in output.')
        print(result)

    @capture.stdout
    def testSourceInterface(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + SOURCE_INTERFACE_TERM, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn('-i eth0', result, 'source interface specification not in output.')
        print(result)

    @capture.stdout
    def testDestinationInterface(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + DESTINATION_INTERFACE_TERM, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn('-o eth0', result, 'destination interface specification not in output.')
        print(result)

    @mock.patch.object(iptables.logging, 'warning')
    def testExpired(self, mock_warn):
        _ = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + EXPIRED_TERM, self.naming), EXP_INFO
        )

        mock_warn.assert_called_once_with(
            'WARNING: Term %s in policy %s is expired' ' and will not be rendered.',
            'is_expired',
            'INPUT',
        )

    @mock.patch.object(iptables.logging, 'info')
    def testExpiringTerm(self, mock_info):
        exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
        _ = iptables.Iptables(
            policy.ParsePolicy(
                GOOD_HEADER_1 + EXPIRING_TERM % exp_date.strftime('%Y-%m-%d'), self.naming
            ),
            EXP_INFO,
        )

        mock_info.assert_called_once_with(
            'INFO: Term %s in policy %s expires in ' 'less than two weeks.', 'is_expiring', 'INPUT'
        )

    @capture.stdout
    def testIPv6Icmp(self):
        pol = policy.ParsePolicy(IPV6_HEADER_1 + IPV6_TERM_1, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn('--icmpv6-type 1', result, 'icmpv6-type 1 (echo-reply) is missing')
        self.assertIn(
            '--icmpv6-type 3', result, 'icmpv6-type 3 (destination-unreachable) is missing'
        )
        self.assertIn('--icmpv6-type 129', result, 'icmpv6-type 129 (router-solicit) is missing')
        print(result)

    @capture.stdout
    def testIPv6IcmpOrder(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IPv6('fd87:6044:ac54:3558::/64')]

        pol = policy.ParsePolicy(IPV6_HEADER_1 + ICMPV6_TERM_1, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)
        self.assertIn(
            '-s fd87:6044:ac54:3558::/64 -p ipv6-icmp -m icmp6' ' --icmpv6-type 1',
            result,
            'incorrect order of ICMPv6 match elements',
        )

        self.naming.GetNetAddr.assert_called_once_with('IPV6_INTERNAL')
        print(result)

    @mock.patch.object(iptables.logging, 'warning')
    def testIcmpv6InetMismatch(self, mock_warning):
        acl = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + IPV6_TERM_1, self.naming), EXP_INFO
        )
        # output happens in __str_
        str(acl)

        mock_warning.assert_called_once_with(
            'Term inet6-icmp will not be rendered,'
            ' as it has icmpv6 match specified but '
            'the ACL is of inet address family.'
        )

    @mock.patch.object(iptables.logging, 'warning')
    def testIcmpInet6Mismatch(self, mock_warning):
        acl = iptables.Iptables(
            policy.ParsePolicy(IPV6_HEADER_1 + GOOD_TERM_1, self.naming), EXP_INFO
        )
        # output happens in __str_
        str(acl)

        mock_warning.assert_called_once_with(
            'Term good-term-1 will not be rendered,'
            ' as it has icmp match specified but '
            'the ACL is of inet6 address family.'
        )

    @capture.stdout
    def testOwner(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_10, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl).split('\n')
        self.assertIn(
            '-A I_good-term-10 -m comment --comment "Owner: ' 'foo@google.com"',
            result,
            'missing or incorrect comment specification.',
        )
        print(acl)

    @capture.stdout
    def testSetTarget(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        acl.SetTarget('OUTPUT', 'DROP')
        result = str(acl).split('\n')
        self.assertIn('-P OUTPUT DROP', result, 'output default policy of drop not set.')
        print(acl)

    @capture.stdout
    def testSetCustomTarget(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        acl.SetTarget('foobar')
        result = str(acl).split('\n')
        self.assertIn('-N foobar', result, 'did not find a new chain for foobar.')
        print(acl)

    def testBuildTokens(self):
        pol1 = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_5, self.naming), EXP_INFO
        )
        st, sst = pol1._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    def testBuildWarningTokens(self):
        self.naming.GetServiceByProto.return_value = ['80']

        pol1 = iptables.Iptables(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_WARNING_TERM, self.naming), EXP_INFO
        )
        st, sst = pol1._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    @capture.stdout
    def testNoVerbose(self):
        pol = policy.ParsePolicy(GOOD_HEADER_7 + GOOD_TERM_12, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        self.assertNotIn('comment --comment "FOOO"', str(acl), acl)
        print(acl)

    @capture.stdout
    def testLogLimit(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_13, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        self.assertIn('-m --limit 99/day -j LOG --log-prefix good_term_13', str(acl), acl)
        print(acl)

    def testLogLimitFailsWithoutLogging(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + BAD_LOGGING_TERM, self.naming)
        self.assertRaises(iptables.LimitButNoLogError, iptables.Iptables, pol, EXP_INFO)

    @capture.stdout
    def testSkipHopByHopinV4(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + HOPOPT_TERM + GOOD_TERM_1, self.naming)
        acl = iptables.Iptables(pol, EXP_INFO)
        result = str(acl)

        self.assertNotIn(
            '-m u32 --u32 "0x3&0xff=0x0"', result, 'match for hop-by-hop header is missing'
        )
        print(acl)

    def testMixedICMPWarns(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + BAD_ICMP_TERM, self.naming)
        with self.assertLogs(level='WARNING') as log:
            acl = iptables.Iptables(pol, EXP_INFO)
            result = str(acl)
        self.assertIn(
            "permit-icmp will not be rendered, as it has icmp, icmpv6 match specified but the ACL is of inet address family.",
            ''.join(log.output),
        )


YAML_GOOD_HEADER_1 = """
filters:
- header:
    comment: this is a test acl
    targets:
      iptables: INPUT ACCEPT
  terms:
"""

YAML_GOOD_HEADER_2 = """
filters:
- header:
    comment: this is a test acl
    targets:
      iptables: OUTPUT DROP
  terms:
"""

YAML_GOOD_HEADER_3 = """
filters:
- header:
    comment: this is a test acl with abbreviation
    targets:
      iptables: INPUT ACCEPT abbreviateterms
  terms:
"""

YAML_GOOD_HEADER_4 = """
filters:
- header:
    comment: this is a test acl with truncation
    targets:
      iptables: INPUT ACCEPT truncateterms
  terms:
"""

YAML_GOOD_HEADER_5 = """
filters:
- header:
    comment: this is a test acl with no default target
    targets:
      iptables: INPUT
  terms:
"""

YAML_GOOD_HEADER_6 = """
filters:
- header:
    comment: this is a test acl with a custom chain and no default target
    targets:
      iptables: foo
  terms:
"""

YAML_GOOD_HEADER_7 = """
filters:
- header:
    comment: this is a test acl with a custom chain and no default target
    targets:
      iptables: foo noverbose
  terms:
"""

YAML_IPV6_HEADER_1 = """
filters:
- header:
    comment: test header for inet6 terms
    targets:
      iptables: INPUT DROP inet6
  terms:
"""

YAML_NON_STANDARD_CHAIN = """
filters:
- header:
    comment: this is a test acl with non-standard chain
    targets:
      iptables: foo ACCEPT
  terms:
"""

YAML_NOSTATE_HEADER = """
filters:
- header:
    comment: iptables filter without stateful
    targets:
      iptables: INPUT ACCEPT nostate
  terms:
"""

YAML_CHAIN_HEADER_1 = """
filters:
- header:
    comment: this is a test acl
    targets:
      iptables: foobar_chain nostate
  terms:
"""

YAML_BAD_HEADER_2 = """
filters:
- header:
    targets:
      juniper:
  terms:
"""

YAML_BAD_HEADER_3 = """
filters:
- header:
    targets:
      iptables: INPUT MAYBE
  terms:
"""

YAML_GOOD_TERM_1 = """
  - name: good-term-1
    protocol: icmp
    action: accept
"""

YAML_GOOD_TERM_2 = """
  - name: good-term-2
    source-address: INTERNAL
    source-exclude: OOB_NET
    protocol: tcp
    source-port: HTTP
    action: accept
"""

YAML_GOOD_TERM_3 = """
  - name: good-term-3
    source-port: HTTP
    protocol: tcp
    option: rst fin tcp-established established
    action: accept
"""

YAML_GOOD_TERM_4 = """
  - name: good-term-4
    protocol: tcp udp esp ah gre icmp 50
    action: accept
"""

YAML_GOOD_TERM_5 = """
  - name: good-term-5
    verbatim:
      iptables: mary had a little lamb
      cisco: mary had second lamb
      juniper: mary had third lamb
"""

YAML_GOOD_TERM_6 = """
  - name: good-term-6
    comment: |
        Some text describing what this block does,
        possibly including newines, blank lines,
        and extra-long comments (over 255 characters)
        %(long_line)s

        All these cause problems if passed verbatim to iptables.
               
    protocol: tcp
    action: accept

""" % {
    'long_line': '-' * 260
}


YAML_GOOD_TERM_7 = """
  - name: drop-short-initial-fragments
    option: first-fragment
    packet-length: 1-119
    action: deny

  - name: drop-header-overwrite
    fragment-offset: 1-119
    action: deny
"""

YAML_GOOD_TERM_8 = """
  - name: block-some-icmp
    protocol: icmp
    icmp-type: router-solicitation information-request unreachable echo-reply
    action: deny
"""

YAML_GOOD_TERM_9 = """
  - name: good-term-9
    source-address: SOME_SOURCE
    destination-address: SOME_DEST
    protocol: tcp
    source-port: HTTP
    action: accept
"""

YAML_GOOD_TERM_10 = """
  - name: good-term-10
    owner: foo@google.com
    action: accept
"""

YAML_GOOD_TERM_11 = """
  - name: good_term_11
    protocol: icmp
    icmp-type: unreachable
    icmp-code: 3 4
    action: accept
"""

YAML_GOOD_TERM_12 = """
  - name: good_term_12
    comment: FOOO
    action: accept
"""

YAML_GOOD_TERM_13 = """
  - name: good_term_13
    logging: syslog
    log-limit: 99/day
    action: accept
"""

YAML_HOPOPT_TERM = """
  - name: hopopt-term
    protocol: hopopt
    action: accept
"""

YAML_BAD_LOGGING_TERM = """
  - name: bad_logging_term
    log-limit: 99/day
    action: accept
"""

YAML_BAD_QUOTE_TERM_1 = """
  - name: bad-quote-term-1
    comment: Text describing without quotes
    protocol: tcp
    action: accept
"""

YAML_IPV6_TERM_1 = """
  - name: inet6-icmp
    protocol: icmpv6
    icmp-type: destination-unreachable time-exceeded echo-reply
    action: deny
"""

YAML_IPV6_HEADERS = """
  - name: ipv6-header-1
    protocol: hopopt
    action: deny

  - name: ipv6-header-2
    protocol: fragment
    action: deny
"""

YAML_ICMPV6_TERM_1 = """
  - name: inet6-icmp
    source-address: IPV6_INTERNAL
    protocol: icmpv6
    icmp-type: destination-unreachable
    action: deny
"""

YAML_LOGGING_TERM_1 = """
  - name: foo
    protocol: tcp
    logging: syslog
    action: accept
"""

YAML_UDP_STATE_TERM = """
  - name: test-conntrack-udp
    protocol: udp
    option: established
    action: accept
"""

YAML_TCP_STATE_TERM = """
  - name: tcp-established-only
    protocol: tcp
    option: established
    action: accept
"""

YAML_STATEFUL_ONLY_TERM = """
  - name: stateful-only
    option: established
    action: accept
"""

YAML_BAD_LONG_TERM_NAME = """
  - name: this-term-name-is-really-far-too-long
    protocol: tcp
    action: accept
"""

YAML_GOOD_LONG_TERM_NAME = """
  - name: google-experiment-abbreviations
    protocol: tcp
    action: accept
"""

YAML_GOOD_MULTIPORT = """
  - name: multiport
    source-port: FOURTEEN_PORTS
    protocol: tcp
    action: accept
"""

YAML_MULTIPORT_SWAP = """
  - name: multiport
    source-port: HTTP HTTPS
    destination-port: SSH
    protocol: tcp
    action: accept
"""

YAML_EXPIRED_TERM = """
  - name: is_expired
    expiration: 2001-01-01
    action: accept
"""

YAML_EXPIRING_TERM = """
  - name: is_expiring
    expiration: %s
    action: accept
"""

YAML_GOOD_MULTIPORT_RANGE = """
  - name: bad-mport-ranges
    destination-port: FIFTEEN_PORTS_WITH_RANGES
    protocol: tcp
    action: accept
"""

YAML_LARGE_MULTIPORT = """
  - name: bad-multiport
    destination-port: LOTS_OF_PORTS
    protocol: tcp
    action: accept
"""

YAML_DUAL_LARGE_MULTIPORT = """
  - name: bad-multiport
    source-port: LOTS_OF_SPORTS
    destination-port: LOTS_OF_DPORTS
    protocol: tcp
    action: accept
"""

YAML_UNSUPPORTED_TERM = """
  - name: ether-type-filter
    ether-type: arp
    action: accept
"""

YAML_UNKNOWN_TERM_KEYWORD = """
  - name: unknown-keyword
    comment: |
        imaginary new keyword added to the policy library.
        i.e. ip-options-count:: 2-255
        must be added in tests due to checking in policy library.
    action: deny
"""

YAML_UNSUPPORTED_EXCEPT = """
  - name: block-non-standard
    protocol-except: tcp udp icmp
    action: deny
"""

YAML_REJECT_TERM1 = """
  - name: reject-term1
    action: reject-with-tcp-rst
"""

YAML_REJECT_TERM2 = """
  - name: reject-term2
    action: reject
"""

YAML_NEXT_TERM1 = """
  - name: next-term1
    action: next
"""

YAML_BAD_PROTOCOL_MATCHES = """
  - name: proto-accept-and-reject
    protocol: tcp udp icmp
    protocol-except: gre
    action: accept
"""

YAML_SOURCE_INTERFACE_TERM = """
  - name: src-interface
    protocol: tcp
    source-interface: eth0
    action: accept
"""

YAML_DESTINATION_INTERFACE_TERM = """
  - name: dst-interface
    protocol: tcp
    destination-interface: eth0
    action: accept
"""

YAML_GOOD_WARNING_TERM = """
  - name: good-warning-term
    source-port: HTTP
    protocol: tcp
    option: rst fin tcp-established established
    policer: batman
    action: accept
"""
YAML_BAD_ICMP_TERM = """
  - name: permit-icmp
    protocol: icmp icmpv6
    action: accept
"""


def _YamlParsePolicy(
    data, definitions=None, optimize=True, base_dir='', shade_check=False, filename=''
):
    return yaml_frontend.ParsePolicy(
        data,
        filename=filename,
        base_dir=base_dir,
        definitions=definitions,
        optimize=optimize,
        shade_check=shade_check,
    )


class IPTablesYAMLTest(AclCheckTest):
    def setUp(self):
        super().setUp()
        # patch policy.ParsePolicy into a wrapper that calls YAML.load_str
        self.patchers = [mock.patch.object(policy, 'ParsePolicy', _YamlParsePolicy)]
        [patcher.start() for patcher in self.patchers]
        self.setUpFixtures()
        self.fixture_patcher.start()

    def tearDown(self):
        [patcher.stop() for patcher in self.patchers]
        self.tearDownFixtures()

    def tearDownFixtures(self):
        self.fixture_patcher.stop()

    def setUpFixtures(self):
        self.fixture_patcher = mock.patch.multiple(
            'iptables_test',
            GOOD_HEADER_1=YAML_GOOD_HEADER_1,
            GOOD_HEADER_2=YAML_GOOD_HEADER_2,
            GOOD_HEADER_3=YAML_GOOD_HEADER_3,
            GOOD_HEADER_4=YAML_GOOD_HEADER_4,
            GOOD_HEADER_5=YAML_GOOD_HEADER_5,
            GOOD_HEADER_6=YAML_GOOD_HEADER_6,
            GOOD_HEADER_7=YAML_GOOD_HEADER_7,
            IPV6_HEADER_1=YAML_IPV6_HEADER_1,
            NON_STANDARD_CHAIN=YAML_NON_STANDARD_CHAIN,
            NOSTATE_HEADER=YAML_NOSTATE_HEADER,
            CHAIN_HEADER_1=YAML_CHAIN_HEADER_1,
            BAD_HEADER_2=YAML_BAD_HEADER_2,
            BAD_HEADER_3=YAML_BAD_HEADER_3,
            GOOD_TERM_1=YAML_GOOD_TERM_1,
            GOOD_TERM_2=YAML_GOOD_TERM_2,
            GOOD_TERM_3=YAML_GOOD_TERM_3,
            GOOD_TERM_4=YAML_GOOD_TERM_4,
            GOOD_TERM_5=YAML_GOOD_TERM_5,
            GOOD_TERM_6=YAML_GOOD_TERM_6,
            GOOD_TERM_7=YAML_GOOD_TERM_7,
            GOOD_TERM_8=YAML_GOOD_TERM_8,
            GOOD_TERM_9=YAML_GOOD_TERM_9,
            GOOD_TERM_10=YAML_GOOD_TERM_10,
            GOOD_TERM_11=YAML_GOOD_TERM_11,
            GOOD_TERM_12=YAML_GOOD_TERM_12,
            GOOD_TERM_13=YAML_GOOD_TERM_13,
            HOPOPT_TERM=YAML_HOPOPT_TERM,
            BAD_LOGGING_TERM=YAML_BAD_LOGGING_TERM,
            BAD_QUOTE_TERM_1=YAML_BAD_QUOTE_TERM_1,
            IPV6_TERM_1=YAML_IPV6_TERM_1,
            IPV6_HEADERS=YAML_IPV6_HEADERS,
            ICMPV6_TERM_1=YAML_ICMPV6_TERM_1,
            LOGGING_TERM_1=YAML_LOGGING_TERM_1,
            UDP_STATE_TERM=YAML_UDP_STATE_TERM,
            TCP_STATE_TERM=YAML_TCP_STATE_TERM,
            STATEFUL_ONLY_TERM=YAML_STATEFUL_ONLY_TERM,
            BAD_LONG_TERM_NAME=YAML_BAD_LONG_TERM_NAME,
            GOOD_LONG_TERM_NAME=YAML_GOOD_LONG_TERM_NAME,
            GOOD_MULTIPORT=YAML_GOOD_MULTIPORT,
            MULTIPORT_SWAP=YAML_MULTIPORT_SWAP,
            EXPIRED_TERM=YAML_EXPIRED_TERM,
            EXPIRING_TERM=YAML_EXPIRING_TERM,
            GOOD_MULTIPORT_RANGE=YAML_GOOD_MULTIPORT_RANGE,
            LARGE_MULTIPORT=YAML_LARGE_MULTIPORT,
            DUAL_LARGE_MULTIPORT=YAML_DUAL_LARGE_MULTIPORT,
            UNSUPPORTED_TERM=YAML_UNSUPPORTED_TERM,
            UNKNOWN_TERM_KEYWORD=YAML_UNKNOWN_TERM_KEYWORD,
            UNSUPPORTED_EXCEPT=YAML_UNSUPPORTED_EXCEPT,
            REJECT_TERM1=YAML_REJECT_TERM1,
            REJECT_TERM2=YAML_REJECT_TERM2,
            NEXT_TERM1=YAML_NEXT_TERM1,
            BAD_PROTOCOL_MATCHES=YAML_BAD_PROTOCOL_MATCHES,
            SOURCE_INTERFACE_TERM=YAML_SOURCE_INTERFACE_TERM,
            DESTINATION_INTERFACE_TERM=YAML_DESTINATION_INTERFACE_TERM,
            GOOD_WARNING_TERM=YAML_GOOD_WARNING_TERM,
            BAD_ICMP_TERM=YAML_BAD_ICMP_TERM,
        )


if __name__ == '__main__':
    absltest.main()
