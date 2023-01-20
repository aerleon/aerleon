# Copyright 2007 Google Inc. All Rights Reserved.
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

"""Unittest for juniper acl rendering module."""

import datetime
import re
from unittest import mock

from absl import logging
from absl.testing import absltest, parameterized

from aerleon.lib import aclgenerator, juniper, nacaddr, naming, policy
from aerleon.lib import yaml as yaml_frontend
from tests.regression_utils import capture

GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: juniper test-filter
}
"""
GOOD_HEADER_2 = """
header {
  target:: juniper test-filter bridge
}
"""
GOOD_HEADER_V6 = """
header {
  target:: juniper test-filter inet6
}
"""
GOOD_HEADER_MIXED = """
header {
  target:: juniper test-filter mixed
}
"""
GOOD_HEADER_BRIDGE = """
header {
  target:: juniper test-filter bridge
}
"""
GOOD_DSMO_HEADER = """
header {
  target:: juniper test-filter enable_dsmo
}
"""
GOOD_FILTER_ENHANCED_MODE_HEADER = """
header {
  target:: juniper test-filter filter_enhanced_mode
}
"""
GOOD_NOVERBOSE_V4_HEADER = """
header {
  target:: juniper test-filter inet noverbose
}
"""
GOOD_NOVERBOSE_V6_HEADER = """
header {
  target:: juniper test-filter inet6 noverbose
}
"""
GOOD_HEADER_NOT_INTERFACE_SPECIFIC = """
header {
  target:: juniper test-filter bridge not-interface-specific
}
"""
BAD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: cisco test-filter
}
"""
BAD_HEADER_2 = """
header {
  target:: juniper test-filter inetpoop
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
GOOD_TERM_1 = """
term good-term-1 {
  protocol:: icmp
  action:: accept
}

term good-term-2 {
  protocol:: tcp
  destination-port:: SMTP
  destination-address:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_1_V6 = """
term good-term-1 {
  protocol:: icmpv6
  action:: accept
}

term good-term-2 {
  protocol:: tcp
  destination-port:: SMTP
  destination-address:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_2 = """
term good-term-3 {
  protocol:: tcp
  destination-address:: SOME_HOST
  source-port:: HTTP
  option:: established tcp-established
  action:: accept
}
"""
GOOD_TERM_3 = """
term good-term-3 {
  protocol:: icmp
  icmp-type:: echo-reply information-reply information-request
  icmp-type:: router-solicitation timestamp-request
  action:: accept
}
"""
GOOD_TERM_5 = """
term good-term-5 {
  protocol:: icmp
  protocol:: tcp
  action:: accept
}
"""
GOOD_TERM_7 = """
term good-term-7 {
  protocol-except:: tcp
  action:: accept
}
"""
GOOD_TERM_8 = """
term good-term-8 {
  source-prefix:: foo_prefix_list
  destination-prefix:: bar_prefix_list baz_prefix_list
  action:: accept
}
"""
GOOD_TERM_9 = """
term good-term-9 {
  ether-type:: arp
  action:: accept
}
"""
GOOD_TERM_10 = """
term good-term-10 {
  traffic-type:: unknown-unicast
  action:: accept
}
"""
GOOD_TERM_11 = """
term good-term-11 {
  verbatim:: juniper "mary had a little lamb"
  verbatim:: iptables "mary had a second lamb"
  verbatim:: cisco "mary had a third lamb"
}
"""
GOOD_TERM_12 = """
term good-term-12 {
  source-address:: LOCALHOST
  action:: accept
}
"""
GOOD_TERM_13 = """
term routing-instance-setting {
  protocol:: tcp
  routing-instance:: EXTERNAL-NAT
}
"""
GOOD_TERM_14 = """
term loss-priority-setting {
  protocol:: tcp
  loss-priority:: low
  action:: accept
}
"""
GOOD_TERM_15 = """
term precedence-setting {
  protocol:: tcp
  destination-port:: SSH
  precedence:: 7
  action:: accept
}
"""
GOOD_TERM_16 = """
term precedence-setting {
  protocol:: tcp
  destination-port:: SSH
  precedence:: 5 7
  action:: accept
}
"""
GOOD_TERM_17 = """
term owner-term {
  owner:: foo@google.com
  action:: accept
}
"""
GOOD_TERM_18_SRC = """
term address-exclusions {
  source-address:: INTERNAL
  source-exclude:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_18_DST = """
term address-exclusions {
  destination-address:: INTERNAL
  destination-exclude:: SOME_HOST
  action:: accept
}
"""
GOOD_TERM_19 = """
term minimize-prefix-list {
  source-address:: INCLUDES
  source-exclude:: EXCLUDES
  action:: accept
}
"""
GOOD_TERM_V6_HOP_LIMIT = """
term good-term-v6-hl {
  hop-limit:: 25
  action:: accept
}
"""
GOOD_TERM_20_V6 = """
term good-term-20-v6 {
  protocol-except:: icmpv6
  action:: accept
}
"""
GOOD_TERM_21 = """
term good_term_21 {
  ttl:: 10
  action:: accept
}
"""
GOOD_TERM_22 = """
term good_term_22 {
  protocol:: tcp
  source-port:: DNS
  dscp-set:: b111000
  action:: accept
}
"""
GOOD_TERM_23 = """
term good_term_23 {
  protocol:: tcp
  source-port:: DNS
  dscp-set:: af42
  dscp-match:: af41-af42 5
  dscp-except:: be
  action:: accept
}
"""
GOOD_TERM_24 = """
term good_term_24 {
  protocol:: tcp
  source-port:: DNS
  qos:: af1
  action:: accept
}
"""
GOOD_TERM_25 = """
term good_term_25 {
  protocol:: tcp
  source-port:: DNS
  action:: accept
}
"""
GOOD_TERM_26 = """
term good_term_26 {
  protocol:: tcp
  source-port:: DNS
  action:: deny
}
"""
GOOD_TERM_26_V6 = """
term good_term_26-v6 {
  protocol:: tcp
  source-port:: DNS
  action:: deny
}
"""
GOOD_TERM_26_V6_REJECT = """
term good_term_26-v6 {
  protocol:: tcp
  source-port:: DNS
  action:: reject
}
"""
GOOD_TERM_27 = """
term good_term_27 {
  forwarding-class:: Floop
  action:: deny
}
"""
GOOD_TERM_28 = """
term good_term_28 {
  next-ip:: TEST_NEXT
}
"""
GOOD_TERM_29 = """
term multiple-forwarding-class {
  forwarding-class:: floop fluup fleep
  action:: deny
}
"""
GOOD_TERM_30 = """
term good-term-30 {
  source-prefix-except:: foo_prefix_list
  destination-prefix-except:: bar_prefix_list
  action:: accept
}
"""
GOOD_TERM_31 = """
term good-term-31 {
  source-prefix:: foo_prefix
  source-prefix-except:: foo_except
  destination-prefix:: bar_prefix
  destination-prefix-except:: bar_except
  action:: accept
}
"""
GOOD_TERM_32 = """
term good_term_32 {
  forwarding-class-except:: floop
  action:: deny
}
"""
GOOD_TERM_33 = """
term multiple-forwarding-class-except {
  forwarding-class-except:: floop fluup fleep
  action:: deny
}
"""
GOOD_TERM_34 = """
term good_term_34 {
  traffic-class-count:: floop
  action:: deny
}
"""
GOOD_TERM_35 = """
term good_term_35 {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 3 4
  action:: accept
}
"""
GOOD_TERM_36 = """
term good-term-36 {
  protocol:: tcp
  destination-address:: SOME_HOST
  destination-address:: SOME_HOST
  option:: inactive
  action:: accept
}
"""
GOOD_TERM_37 = """
term good-term-37 {
  destination-address:: SOME_HOST
  restrict-address-family:: inet
  action:: accept
}
"""
GOOD_TERM_COMMENT = """
term good-term-comment {
  comment:: "This is a COMMENT"
  action:: accept
}
"""
GOOD_TERM_FILTER = """
term good-term-filter {
  comment:: "This is a COMMENT"
  filter-term:: my-filter
}
"""
BAD_TERM_1 = """
term bad-term-1 {
  protocol:: tcp udp
  source-port:: DNS
  option:: tcp-established
  action:: accept
}
"""
ESTABLISHED_TERM_1 = """
term established-term-1 {
  protocol:: tcp
  source-port:: DNS
  option:: established
  action:: accept
}
"""
OPTION_TERM_1 = """
term option-term {
  protocol:: tcp
  source-port:: SSH
  option:: is-fragment
  action:: accept
}
"""
BAD_ICMPTYPE_TERM_1 = """
term icmptype-mismatch {
  comment:: "error when icmpv6 paired with inet filter"
  protocol:: icmpv6
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""
BAD_ICMPTYPE_TERM_2 = """
term icmptype-mismatch {
  comment:: "error when icmp paired with inet6 filter"
  protocol:: icmp
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""
DEFAULT_TERM_1 = """
term default-term-1 {
  action:: deny
}
"""
ENCAPSULATE_GOOD_TERM_1 = """
term good-term-1 {
  protocol:: tcp
  encapsulate:: template-name
}
"""
ENCAPSULATE_GOOD_TERM_2 = """
term good-term-2 {
  protocol:: tcp
  encapsulate:: template-name
  counter:: count-name
}
"""
ENCAPSULATE_BAD_TERM_1 = """
term bad-term-1 {
  protocol:: tcp
  encapsulate:: template-name
  action:: accept
}
"""
ENCAPSULATE_BAD_TERM_2 = """
term bad-term-2 {
  protocol:: tcp
  encapsulate:: template-name
  routing-instance:: instance-name
}
"""
PORTMIRROR_GOOD_TERM_1 = """
term good-term-1 {
  protocol:: tcp
  port-mirror:: true
}
"""
PORTMIRROR_GOOD_TERM_2 = """
term good-term-2 {
  protocol:: tcp
  port-mirror:: true
  counter:: count-name
  action:: deny
}
"""
LONG_COMMENT_TERM_1 = """
term long-comment-term-1 {
  comment:: "this is very very very very very very very very very very very
  comment:: "very very very very very very very long."
  action:: deny
}
"""
LONG_POLICER_TERM_1 = """
term long-policer-term-1 {
  policer:: this-is-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-long
  action:: deny
}
"""
HOPOPT_TERM = """
term good-term-1 {
  protocol:: hopopt
  action:: accept
}
"""
HOPOPT_TERM_EXCEPT = """
term good-term-1 {
  protocol-except:: hopopt
  action:: accept
}
"""
FRAGOFFSET_TERM = """
term good-term-1 {
  fragment-offset:: 1-7
  action:: accept
}
"""
GOOD_FLEX_MATCH_TERM = """
term flex-match-term-1 {
  protocol:: tcp
  flexible-match-range:: bit-length 8
  flexible-match-range:: range 0x08
  flexible-match-range:: match-start payload
  flexible-match-range:: byte-offset 16
  flexible-match-range:: bit-offset 7
  action:: deny
}
"""
BAD_FLEX_MATCH_TERM_1 = """
term flex-match-term-1 {
  protocol:: tcp
  flexible-match-range:: bit-length 36
  flexible-match-range:: range 0x08
  flexible-match-range:: match-start payload
  flexible-match-range:: byte-offset 16
  flexible-match-range:: bit-offset 7
  action:: deny
}
"""
BAD_FLEX_MATCH_TERM_2 = """
term flex-match-term-1 {
  protocol:: tcp
  flexible-match-range:: bit-length 8
  flexible-match-range:: range 0x08
  flexible-match-range:: match-start wrong
  flexible-match-range:: byte-offset 16
  flexible-match-range:: bit-offset 7
  action:: deny
}
"""
BAD_FLEX_MATCH_TERM_3 = """
term flex-match-term-1 {
  protocol:: tcp
  flexible-match-range:: bit-length 8
  flexible-match-range:: range 0x08
  flexible-match-range:: match-start payload
  flexible-match-range:: byte-offset 260
  flexible-match-range:: bit-offset 7
  action:: deny
}
"""
BAD_FLEX_MATCH_TERM_4 = """
term flex-match-term-1 {
  protocol:: tcp
  flexible-match-range:: bit-length 8
  flexible-match-range:: range 0x08
  flexible-match-range:: match-start payload
  flexible-match-range:: byte-offset 16
  flexible-match-range:: bit-offset 8
  action:: deny
}
"""
BAD_TERM_FILTER = """
term bad_term_filter {
  filter-term:: my-filter
  action:: deny
}
"""

MIXED_TESTING_TERM = """
term good-term {
  protocol:: tcp
  source-address:: SOME_HOST
  destination-port:: SMTP
  destination-address:: SOME_OTHER_HOST
  action:: accept
}
"""

SUPPORTED_TOKENS = frozenset(
    [
        'action',
        'address',
        'comment',
        'counter',
        'destination_address',
        'destination_address_exclude',
        'destination_port',
        'destination_prefix',
        'destination_prefix_except',
        'dscp_except',
        'dscp_match',
        'dscp_set',
        'encapsulate',
        'ether_type',
        'expiration',
        'filter_term',
        'flexible_match_range',
        'forwarding_class',
        'forwarding_class_except',
        'fragment_offset',
        'hop_limit',
        'icmp_code',
        'icmp_type',
        'stateless_reply',
        'logging',
        'loss_priority',
        'name',
        'next_ip',
        'option',
        'owner',
        'packet_length',
        'platform',
        'platform_exclude',
        'policer',
        'port',
        'port_mirror',
        'precedence',
        'protocol',
        'protocol_except',
        'qos',
        'restrict_address_family',
        'routing_instance',
        'source_address',
        'source_address_exclude',
        'source_port',
        'source_prefix',
        'source_prefix_except',
        'traffic_class_count',
        'traffic_type',
        'translated',
        'ttl',
        'verbatim',
    ]
)

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
        'inactive',
        'is-fragment',
        '.*',  # not actually a lex token!
        'sample',
        'tcp-established',
        'tcp-initial',
    },
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class JuniperTest(parameterized.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = mock.create_autospec(naming.Naming)

    @capture.stdout
    def testOptions(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
        self.naming.GetServiceByProto.return_value = ['80']

        jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('destination-port 1024-65535;', output, output)
        # Verify that tcp-established; doesn't get duplicated if both 'established'
        # and 'tcp-established' options are included in term
        self.assertEqual(output.count('tcp-established;'), 1)

        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')
        print(output)

    @capture.stdout
    def testTermAndFilterName(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
        self.naming.GetServiceByProto.return_value = ['25']

        jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('term good-term-1 {', output, output)
        self.assertIn('replace: filter test-filter {', output, output)

        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')
        print(output)

    def testBadFilterType(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
        self.naming.GetServiceByProto.return_value = ['25']

        pol = policy.ParsePolicy(BAD_HEADER_2 + GOOD_TERM_1, self.naming)
        self.assertRaises(aclgenerator.UnsupportedAFError, juniper.Juniper, pol, EXP_INFO)

        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

    @capture.stdout
    def testBridgeFilterType(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
        self.naming.GetServiceByProto.return_value = ['25']

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_2 + GOOD_TERM_1, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('ip-protocol tcp;', output, output)
        self.assertNotIn(' destination-address {', output, output)

        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')
        print(output)

    @capture.stdout
    def testCommentShrinking(self):
        long_comment = ' this is a very descriptive comment ' * 10
        expected = (
            ' ' * 24
            + '/* this is a very descriptive comment  this is a\n'
            + ' ' * 25
            + '** very descriptive comment  this is a very\n'
            + ' ' * 25
            + '** descriptive comment  this is a very descript */'
        )
        self.naming.GetNetAddr.return_value = [nacaddr.IPv4('10.0.0.0/8', comment=long_comment)]
        self.naming.GetServiceByProto.return_value = ['25']

        jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn(expected, output, output)

        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')
        print(output)

    @capture.stdout
    def testDefaultDeny(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + DEFAULT_TERM_1, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertNotIn('from {', output, output)
        print(output)

    @capture.stdout
    def testEncapsulate(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + ENCAPSULATE_GOOD_TERM_1, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('encapsulate template-name;', output, output)
        print(output)
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + ENCAPSULATE_GOOD_TERM_2, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('encapsulate template-name;', output, output)
        self.assertIn('count count-name;', output, output)
        print(output)

    def testFailEncapsulate(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + ENCAPSULATE_BAD_TERM_1, self.naming), EXP_INFO
        )
        self.assertRaises(juniper.JuniperMultipleTerminatingActionError, str, jcl)
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + ENCAPSULATE_BAD_TERM_2, self.naming), EXP_INFO
        )
        self.assertRaises(juniper.JuniperMultipleTerminatingActionError, str, jcl)

    @capture.stdout
    def testPortMirror(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + PORTMIRROR_GOOD_TERM_1, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('port-mirror;', output, output)
        print(output)
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + PORTMIRROR_GOOD_TERM_2, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('port-mirror;', output, output)
        self.assertIn('count count-name;', output, output)
        self.assertIn('discard;', output, output)
        print(output)

    @capture.stdout
    def testIcmpType(self):
        jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_3, self.naming), EXP_INFO)
        output = str(jcl)
        # verify proper translation from policy icmp-type text to juniper-esque
        self.assertIn(' icmp-type [', output, output)
        self.assertIn(' 0 ', output, output)
        self.assertIn(' 15 ', output, output)
        self.assertIn(' 10 ', output, output)
        self.assertIn(' 13 ', output, output)
        self.assertIn(' 16 ', output, output)
        self.assertIn('];', output, output)
        print(output)

    @capture.stdout
    def testIcmpCode(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_35, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('icmp-code [ 3 4 ];', output, output)
        print(output)

    @capture.stdout
    def testInactiveTerm(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_36, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('inactive: term good-term-36 {', output)
        print(output)

    @capture.stdout
    def testInet6(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('2001::/33')]
        self.naming.GetServiceByProto.return_value = ['25']

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_V6 + GOOD_TERM_1_V6, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertTrue('next-header icmpv6;' in output and 'next-header tcp;' in output, output)

        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')
        print(output)

    @capture.stdout
    def testNotInterfaceSpecificHeader(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
        self.naming.GetServiceByProto.return_value = ['25']

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_NOT_INTERFACE_SPECIFIC + GOOD_TERM_1, self.naming),
            EXP_INFO,
        )
        output = str(jcl)
        self.assertNotIn('interface-specific;', output, output)

        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')
        print(output)

    @capture.stdout
    def testInterfaceSpecificHeader(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
        self.naming.GetServiceByProto.return_value = ['25']

        jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('interface-specific;', output, output)

        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')
        print(output)

    @capture.stdout
    def testFilterEnhancedModeHeader(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
        self.naming.GetServiceByProto.return_value = ['25']

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_FILTER_ENHANCED_MODE_HEADER + GOOD_TERM_1, self.naming),
            EXP_INFO,
        )
        output = str(jcl)
        self.assertIn('enhanced-mode;', output, output)

        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')
        print(output)

    @capture.stdout
    def testHopLimit(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_V6 + GOOD_TERM_V6_HOP_LIMIT, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('hop-limit 25;', output, output)
        print(output)

    @capture.stdout
    def testHopLimitInet(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_V6_HOP_LIMIT, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertNotIn('hop-limit 25;', output, output)
        print(output)

    @capture.stdout
    def testProtocolExcept(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_V6 + GOOD_TERM_7, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('next-header-except tcp;', output, output)
        print(output)

    @capture.stdout
    def testIcmpv6Except(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_V6 + GOOD_TERM_20_V6, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('next-header-except icmpv6;', output, output)
        print(output)

    @capture.stdout
    def testProtocolCase(self):
        jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_5, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('protocol [ icmp tcp ];', output, output)
        print(output)

    @capture.stdout
    def testPrefixList(self):
        jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_8, self.naming), EXP_INFO)
        spfx_re = re.compile(r'source-prefix-list {\W+foo_prefix_list;\W+}')
        dpfx_re = re.compile(
            r'destination-prefix-list {\W+bar_prefix_list;\W+baz_prefix_list;\W+}'
        )
        output = str(jcl)
        self.assertTrue(spfx_re.search(output), output)
        self.assertTrue(dpfx_re.search(output), output)
        print(output)

    @capture.stdout
    def testPrefixListExcept(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_30, self.naming), EXP_INFO
        )
        spfx_re = re.compile(r'source-prefix-list {\W+foo_prefix_list except;\W+}')
        dpfx_re = re.compile(r'destination-prefix-list {\W+bar_prefix_list except;\W+}')
        output = str(jcl)
        self.assertTrue(spfx_re.search(output), output)
        self.assertTrue(dpfx_re.search(output), output)
        print(output)

    @capture.stdout
    def testPrefixListMixed(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_31, self.naming), EXP_INFO
        )
        spfx_re = re.compile(r'source-prefix-list {\W+foo_prefix;\W+' r'foo_except except;\W+}')
        dpfx_re = re.compile(
            r'destination-prefix-list {\W+bar_prefix;\W+' r'bar_except except;\W+}'
        )
        output = str(jcl)
        self.assertTrue(spfx_re.search(output), output)
        self.assertTrue(dpfx_re.search(output), output)
        print(output)

    @capture.stdout
    def testEtherType(self):
        jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_9, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('ether-type arp;', output, output)
        print(output)

    @capture.stdout
    def testTrafficType(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_10, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('traffic-type unknown-unicast;', output, output)
        print(output)

    @capture.stdout
    def testVerbatimTerm(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_11, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('mary had a little lamb', output, output)
        # check if other platforms verbatim shows up in output
        self.assertNotIn('mary had a second lamb', output, output)
        self.assertNotIn('mary had a third lamb', output, output)
        print(output)

    @capture.stdout
    def testDscpByte(self):
        self.naming.GetServiceByProto.return_value = ['53']

        policy_text = GOOD_HEADER + GOOD_TERM_22
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('dscp b111000;', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')
        print(output)

    @capture.stdout
    def testDscpClass(self):
        self.naming.GetServiceByProto.return_value = ['53']

        policy_text = GOOD_HEADER + GOOD_TERM_23
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('dscp af42;', output, output)
        self.assertIn('dscp [ af41-af42 5 ];', output, output)
        self.assertIn('dscp-except [ be ];', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')
        print(output)

    @capture.stdout
    def testDscpIPv6(self):
        self.naming.GetServiceByProto.return_value = ['53']

        policy_text = GOOD_HEADER_V6 + GOOD_TERM_23
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('traffic-class af42;', output, output)
        self.assertIn('traffic-class [ af41-af42 5 ];', output, output)
        self.assertIn('traffic-class-except [ be ];', output, output)
        self.assertNotIn('dscp', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')
        print(output)

    @capture.stdout
    def testSimplifiedThenStatement(self):
        self.naming.GetServiceByProto.return_value = ['53']

        policy_text = GOOD_HEADER + GOOD_TERM_24
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('forwarding-class af1', output, output)
        self.assertIn('accept', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')
        print(output)

    @capture.stdout
    def testSimplifiedThenStatementWithSingleAction(self):
        self.naming.GetServiceByProto.return_value = ['53']

        policy_text = GOOD_HEADER + GOOD_TERM_25
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('then accept;', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')
        print(output)

    @capture.stdout
    def testSimplifiedThenStatementWithSingleActionDiscardIPv4(self):
        self.naming.GetServiceByProto.return_value = ['53']

        policy_text = GOOD_HEADER + GOOD_TERM_26
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('then {', output, output)
        self.assertIn('discard;', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')
        print(output)

    @capture.stdout
    def testSimplifiedThenStatementWithSingleActionDiscardIPv6(self):
        self.naming.GetServiceByProto.return_value = ['53']

        policy_text = GOOD_HEADER_V6 + GOOD_TERM_26_V6
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('then discard;', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')
        print(output)

    @capture.stdout
    def testSimplifiedThenStatementWithSingleActionRejectIPv6(self):
        self.naming.GetServiceByProto.return_value = ['53']

        policy_text = GOOD_HEADER_V6 + GOOD_TERM_26_V6_REJECT
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('then {', output, output)
        self.assertIn('reject;', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')
        print(output)

    @capture.stdout
    def testTcpEstablished(self):
        self.naming.GetServiceByProto.return_value = ['53']

        policy_text = GOOD_HEADER + ESTABLISHED_TERM_1
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('tcp-established', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')
        print(output)

    def testNonTcpWithTcpEstablished(self):
        self.naming.GetServiceByProto.return_value = ['53']

        policy_text = GOOD_HEADER + BAD_TERM_1
        pol_obj = policy.ParsePolicy(policy_text, self.naming)
        jcl = juniper.Juniper(pol_obj, EXP_INFO)
        self.assertRaises(juniper.TcpEstablishedWithNonTcpError, str, jcl)

        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'tcp'), mock.call('DNS', 'udp')]
        )

    @capture.stdout
    def testMixedFilterInetType(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IPv4('127.0.0.1'), nacaddr.IPv6('::1/128')]

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_12, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('test-filter4', output, output)
        self.assertIn('127.0.0.1', output, output)
        self.assertIn('test-filter6', output, output)
        self.assertIn('::1/128', output, output)

        self.naming.GetNetAddr.assert_called_once_with('LOCALHOST')
        print(output)

    @capture.stdout
    def testRestrictAddressFamilyType(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IPv4('127.0.0.1'), nacaddr.IPv6('::1/128')]

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_37, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('127.0.0.1', output, output)
        self.assertNotIn('::1/128', output, output)
        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        print(output)

    @capture.stdout
    def testBridgeFilterInetType(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IPv4('127.0.0.1'), nacaddr.IPv6('::1/128')]

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_BRIDGE + GOOD_TERM_12, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertNotIn('::1/128', output, output)

        self.naming.GetNetAddr.assert_called_once_with('LOCALHOST')
        print(output)

    @capture.stdout
    def testNoVerboseV4(self):
        addr_list = list()
        for octet in range(0, 256):
            net = nacaddr.IP('192.168.' + str(octet) + '.64/27')
            addr_list.append(net)
        self.naming.GetNetAddr.return_value = addr_list
        self.naming.GetServiceByProto.return_value = ['25']

        jcl = juniper.Juniper(
            policy.ParsePolicy(
                GOOD_NOVERBOSE_V4_HEADER + GOOD_TERM_1 + GOOD_TERM_COMMENT, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('192.168.0.64/27;', str(jcl))
        self.assertNotIn('COMMENT', str(jcl))
        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')
        print(jcl)

    @capture.stdout
    def testNoVerboseV6(self):
        addr_list = list()
        for octet in range(0, 256):
            net = nacaddr.IPv6('2001:db8:1010:' + str(octet) + '::64/64', strict=False)
            addr_list.append(net)
        self.naming.GetNetAddr.return_value = addr_list
        self.naming.GetServiceByProto.return_value = ['25']

        jcl = juniper.Juniper(
            policy.ParsePolicy(
                GOOD_NOVERBOSE_V6_HEADER + GOOD_TERM_1 + GOOD_TERM_COMMENT, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('2001:db8:1010:90::/61;', str(jcl))
        self.assertNotIn('COMMENT', str(jcl))
        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')
        print(jcl)

    @capture.stdout
    def testDsmo(self):
        addr_list = list()
        for octet in range(0, 256):
            net = nacaddr.IP('192.168.' + str(octet) + '.64/27')
            addr_list.append(net)
        self.naming.GetNetAddr.return_value = addr_list
        self.naming.GetServiceByProto.return_value = ['25']

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_DSMO_HEADER + GOOD_TERM_1, self.naming), EXP_INFO
        )
        self.assertIn('192.168.0.64/255.255.0.224;', str(jcl))

        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')
        print(jcl)

    @capture.stdout
    def testDsmoJuniperFriendly(self):
        addr_list = [nacaddr.IP('192.168.%d.0/24' % octet) for octet in range(256)]
        self.naming.GetNetAddr.return_value = addr_list
        self.naming.GetServiceByProto.return_value = ['25']

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_DSMO_HEADER + GOOD_TERM_1, self.naming), EXP_INFO
        )
        self.assertIn('192.168.0.0/16;', str(jcl))

        self.naming.GetNetAddr.assert_called_once_with('SOME_HOST')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')
        print(jcl)

    @capture.stdout
    def testDsmoExclude(self):
        big = nacaddr.IPv4('0.0.0.0/1')
        ip1 = nacaddr.IPv4('192.168.0.64/27')
        ip2 = nacaddr.IPv4('192.168.1.64/27')
        terms = (GOOD_TERM_18_SRC, GOOD_TERM_18_DST)
        self.naming.GetNetAddr.side_effect = [[big], [ip1, ip2]] * len(terms)

        mock_calls = []
        for term in terms:
            jcl = juniper.Juniper(
                policy.ParsePolicy(GOOD_DSMO_HEADER + term, self.naming), EXP_INFO
            )
            self.assertIn('192.168.0.64/255.255.254.224 except;', str(jcl))
            mock_calls.append(mock.call('INTERNAL'))
            mock_calls.append(mock.call('SOME_HOST'))
            print(jcl)

        self.naming.GetNetAddr.assert_has_calls(mock_calls)

    def testTermTypeIndexKeys(self):
        # ensure an _INET entry for each _TERM_TYPE entry
        self.assertEqual(
            sorted(juniper.Term._TERM_TYPE.keys()), sorted(juniper.Term.AF_MAP.keys())
        )

    @capture.stdout
    def testRoutingInstance(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_13, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('routing-instance EXTERNAL-NAT;', output, output)
        print(output)

    @capture.stdout
    def testLossPriority(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_14, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('loss-priority low;', output, output)
        print(output)

    @capture.stdout
    def testPrecedence(self):
        self.naming.GetServiceByProto.return_value = ['22']

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_15, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('precedence 7;', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')
        print(output)

    @capture.stdout
    def testMultiplePrecedence(self):
        self.naming.GetServiceByProto.return_value = ['22']

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_16, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('precedence [ 5 7 ];', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')
        print(output)

    @capture.stdout
    def testFilterTerm(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_FILTER, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('filter my-filter;', output, output)
        print(output)

    def testFilterActionTerm(self):
        with self.assertRaises(policy.InvalidTermActionError):
            policy.ParsePolicy(GOOD_HEADER + BAD_TERM_FILTER, self.naming)

    @capture.stdout
    def testArbitraryOptions(self):
        self.naming.GetServiceByProto.return_value = ['22']

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + OPTION_TERM_1, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('is-fragment;', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')
        print(output)

    @mock.patch.object(juniper.logging, 'warning')
    def testIcmpv6InetMismatch(self, mock_warning):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + BAD_ICMPTYPE_TERM_1, self.naming), EXP_INFO
        )
        # output happens in __str_
        str(jcl)

        mock_warning.assert_called_once_with(
            'Term icmptype-mismatch will not be rendered,'
            ' as it has icmpv6 match specified but '
            'the ACL is of inet address family.'
        )

    @mock.patch.object(juniper.logging, 'warning')
    def testIcmpInet6Mismatch(self, mock_warning):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_V6 + BAD_ICMPTYPE_TERM_2, self.naming), EXP_INFO
        )
        # output happens in __str_
        str(jcl)

        mock_warning.assert_called_once_with(
            'Term icmptype-mismatch will not be rendered,'
            ' as it has icmp match specified but '
            'the ACL is of inet6 address family.'
        )

    @mock.patch.object(juniper.logging, 'warning')
    def testExpiredTerm(self, mock_warn):
        _ = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + EXPIRED_TERM, self.naming), EXP_INFO)

        mock_warn.assert_called_once_with(
            'WARNING: Term %s in policy %s is expired and will ' 'not be rendered.',
            'is_expired',
            'test-filter',
        )

    @mock.patch.object(juniper.logging, 'info')
    def testExpiringTerm(self, mock_info):
        exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
        _ = juniper.Juniper(
            policy.ParsePolicy(
                GOOD_HEADER + EXPIRING_TERM % exp_date.strftime('%Y-%m-%d'), self.naming
            ),
            EXP_INFO,
        )

        mock_info.assert_called_once_with(
            'INFO: Term %s in policy %s expires in ' 'less than two weeks.',
            'is_expiring',
            'test-filter',
        )

    @capture.stdout
    def testOwnerTerm(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_17, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn(
            '            /*\n' '             ** Owner: foo@google.com\n' '             */',
            output,
            output,
        )
        print(output)

    @capture.stdout
    def testAddressExclude(self):
        big = nacaddr.IPv4('0.0.0.0/1')
        ip1 = nacaddr.IPv4('10.0.0.0/8')
        ip2 = nacaddr.IPv4('172.16.0.0/12')
        terms = (GOOD_TERM_18_SRC, GOOD_TERM_18_DST)
        self.naming.GetNetAddr.side_effect = [[big, ip1, ip2], [ip1]] * len(terms)

        mock_calls = []
        for term in terms:
            jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + term, self.naming), EXP_INFO)
            output = str(jcl)
            self.assertIn('10.0.0.0/8 except;', output, output)
            self.assertNotIn('10.0.0.0/8;', output, output)
            self.assertIn('172.16.0.0/12;', output, output)
            self.assertNotIn('172.16.0.0/12 except;', output, output)
            mock_calls.append(mock.call('INTERNAL'))
            mock_calls.append(mock.call('SOME_HOST'))
            print(output)

        self.naming.GetNetAddr.assert_has_calls(mock_calls)

    @capture.stdout
    def testMinimizePrefixes(self):
        includes = ['1.0.0.0/8', '2.0.0.0/8']
        excludes = ['1.1.1.1/32', '2.0.0.0/8', '3.3.3.3/32']

        expected = ['1.0.0.0/8;', '1.1.1.1/32 except;']
        unexpected = ['2.0.0.0/8;', '2.0.0.0/8 except;', '3.3.3.3/32']

        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IPv4(ip) for ip in includes],
            [nacaddr.IPv4(ip) for ip in excludes],
        ]

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_19, self.naming), EXP_INFO
        )
        output = str(jcl)
        for result in expected:
            self.assertIn(result, output, 'expected "%s" in %s' % (result, output))
        for result in unexpected:
            self.assertNotIn(result, output, 'unexpected "%s" in %s' % (result, output))

        self.naming.GetNetAddr.assert_has_calls([mock.call('INCLUDES'), mock.call('EXCLUDES')])
        print(output)

    @capture.stdout
    def testNoMatchReversal(self):
        includes = ['10.0.0.0/8', '10.0.0.0/10']
        excludes = ['10.0.0.0/9']

        expected = ['10.0.0.0/8;', '10.0.0.0/10;', '10.0.0.0/9 except;']

        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IPv4(ip) for ip in includes],
            [nacaddr.IPv4(ip) for ip in excludes],
        ]

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_19, self.naming), EXP_INFO
        )
        output = str(jcl)
        for result in expected:
            self.assertIn(result, output)
        print(output)

    def testConfigHelper(self):
        config = juniper.Config()
        config.Append('test {')
        config.Append('blah {')
        config.Append('foo;')
        config.Append('bar;')
        config.Append('}')  # close blah{}
        config.Append(' Mr. T Pities the fool!', verbatim=True)

        # haven't closed everything yet
        self.assertRaises(juniper.JuniperIndentationError, lambda: str(config))

        config.Append('}')  # close test{}
        self.assertMultiLineEqual(
            str(config),
            'test {\n'
            '    blah {\n'
            '        foo;\n'
            '        bar;\n'
            '    }\n'
            ' Mr. T Pities the fool!\n'
            '}',
        )

        # one too many '}'
        self.assertRaises(juniper.JuniperIndentationError, lambda: config.Append('}'))

    @capture.stdout
    def testForwardingClass(self):
        policy_text = GOOD_HEADER + GOOD_TERM_27
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('forwarding-class Floop;', output, output)
        print(output)

    @capture.stdout
    def testForwardingClassExcept(self):
        policy_text = GOOD_HEADER + GOOD_TERM_32
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('forwarding-class-except floop;', output, output)
        print(output)

    @capture.stdout
    def testTrafficClassCount(self):
        policy_text = GOOD_HEADER + GOOD_TERM_34
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('traffic-class-count floop;', output, output)
        print(output)

    @capture.stdout
    def testFragmentOffset(self):
        policy_text = GOOD_HEADER + FRAGOFFSET_TERM
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('fragment-offset 1-7;', output, output)
        print(output)

    @capture.stdout
    def testMultipleForwardingClass(self):
        policy_text = GOOD_HEADER + GOOD_TERM_29
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('forwarding-class [ floop fluup fleep ];', output, output)
        print(output)

    @capture.stdout
    def testMultipleForwardingClassExcept(self):
        policy_text = GOOD_HEADER + GOOD_TERM_33
        jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('forwarding-class-except [ floop fluup fleep ];', output, output)
        print(output)

    def testLongPolicer(self):
        with mock.patch.object(juniper.logging, 'warning', spec=logging.warn) as warn:
            policy_text = GOOD_HEADER + LONG_POLICER_TERM_1
            jcl = juniper.Juniper(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
            _ = str(jcl)
            warn.assert_called_with(
                'WARNING: %s is longer than %d bytes. Due to'
                ' limitation in JUNOS, OIDs longer than %dB'
                ' can cause SNMP timeout issues.',
                'this-is-very'
                '-very-very-very-very-very-very-very-very-very'
                '-very-very-very-very-very-very-very-very-very'
                '-very-very-very-very-very-very-very-very-very'
                '-very-very-long',
                128,
                128,
            )

    @capture.stdout
    def testNextIp(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn(('next-ip 10.1.1.1/32'), output)

        self.naming.GetNetAddr.assert_called_once_with('TEST_NEXT')
        print(output)

    @capture.stdout
    def testTTL(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_21, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('ttl 10;', output)
        print(output)

    @capture.stdout
    def testTTLInet6(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_V6 + GOOD_TERM_21, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertNotIn('ttl 10;', output)
        print(output)

    @capture.stdout
    def testNextIpFormat(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn(
            (
                '                then {\n'
                '                    next-ip 10.1.1.1/32;\n'
                '                }'
            ),
            output,
        )

        self.naming.GetNetAddr.assert_called_once_with('TEST_NEXT')
        print(output)

    @capture.stdout
    def testNextIpv6(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('2001::/128')]

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn(('next-ip6 2001::/128;'), output)

        self.naming.GetNetAddr.assert_called_once_with('TEST_NEXT')
        print(output)

    def testFailNextIpMultipleIP(self):
        self.naming.GetNetAddr.return_value = [
            nacaddr.IP('10.1.1.1/32'),
            nacaddr.IP('192.168.1.1/32'),
        ]
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28, self.naming), EXP_INFO
        )
        self.assertRaises(juniper.JuniperNextIpError, str, jcl)

        self.naming.GetNetAddr.assert_called_once_with('TEST_NEXT')

    def testFailNextIpNetworkIP(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/26', strict=False)]

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28, self.naming), EXP_INFO
        )
        self.assertRaises(juniper.JuniperNextIpError, str, jcl)

        self.naming.GetNetAddr.assert_called_once_with('TEST_NEXT')

    def testBuildTokens(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/26', strict=False)]

        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28, self.naming), EXP_INFO
        )
        st, sst = jcl._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    @capture.stdout
    def testBuildWarningTokens(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_28, self.naming), EXP_INFO
        )
        st, sst = jcl._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)
        print(jcl)

    @capture.stdout
    def testHopOptProtocol(self):
        jcl = juniper.Juniper(policy.ParsePolicy(GOOD_HEADER + HOPOPT_TERM, self.naming), EXP_INFO)
        output = str(jcl)
        self.assertIn('protocol hop-by-hop;', output, output)
        self.assertNotIn('protocol hopopt;', output, output)
        print(output)

    @capture.stdout
    def testHopOptProtocolExcept(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + HOPOPT_TERM_EXCEPT, self.naming), EXP_INFO
        )
        output = str(jcl)
        self.assertIn('protocol-except hop-by-hop;', output, output)
        self.assertNotIn('protocol-except hopopt;', output, output)
        print(output)

    @capture.stdout
    def testFlexibleMatch(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER + GOOD_FLEX_MATCH_TERM, self.naming), EXP_INFO
        )

        output = str(jcl)

        flexible_match_expected = [
            'flexible-match-range {',
            'bit-length 8;',
            'range 0x08;',
            'match-start payload;',
            'byte-offset 16;',
            'bit-offset 7;',
        ]

        self.assertEqual(all([x in output for x in flexible_match_expected]), True)
        print(output)

    @capture.stdout
    def testFlexibleMatchIPv6(self):
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_V6 + GOOD_FLEX_MATCH_TERM, self.naming), EXP_INFO
        )
        output = str(jcl)

        flexible_match_expected = [
            'flexible-match-range {',
            'bit-length 8;',
            'range 0x08;',
            'match-start payload;',
            'byte-offset 16;',
            'bit-offset 7;',
        ]

        self.assertEqual(all([x in output for x in flexible_match_expected]), True)
        print(output)

    def testFailIsFragmentInV6(self):
        self.naming.GetServiceByProto.return_value = ['22']
        pol = policy.ParsePolicy(GOOD_HEADER_V6 + OPTION_TERM_1, self.naming)

        self.assertRaises(juniper.JuniperFragmentInV6Error, juniper.Juniper, pol, EXP_INFO)

    def testFailFlexibleMatch(self):

        # bad bit-length
        self.assertRaises(
            policy.FlexibleMatchError,
            policy.ParsePolicy,
            GOOD_HEADER + BAD_FLEX_MATCH_TERM_1,
            self.naming,
        )
        self.assertRaises(
            policy.FlexibleMatchError,
            policy.ParsePolicy,
            GOOD_HEADER_V6 + BAD_FLEX_MATCH_TERM_1,
            self.naming,
        )

        # bad match-start
        self.assertRaises(
            policy.FlexibleMatchError,
            policy.ParsePolicy,
            GOOD_HEADER + BAD_FLEX_MATCH_TERM_2,
            self.naming,
        )
        self.assertRaises(
            policy.FlexibleMatchError,
            policy.ParsePolicy,
            GOOD_HEADER_V6 + BAD_FLEX_MATCH_TERM_2,
            self.naming,
        )

        # bad byte-offset
        self.assertRaises(
            policy.FlexibleMatchError,
            policy.ParsePolicy,
            GOOD_HEADER + BAD_FLEX_MATCH_TERM_3,
            self.naming,
        )
        self.assertRaises(
            policy.FlexibleMatchError,
            policy.ParsePolicy,
            GOOD_HEADER_V6 + BAD_FLEX_MATCH_TERM_3,
            self.naming,
        )

        # bad bit-offset
        self.assertRaises(
            policy.FlexibleMatchError,
            policy.ParsePolicy,
            GOOD_HEADER + BAD_FLEX_MATCH_TERM_4,
            self.naming,
        )
        self.assertRaises(
            policy.FlexibleMatchError,
            policy.ParsePolicy,
            GOOD_HEADER_V6 + BAD_FLEX_MATCH_TERM_4,
            self.naming,
        )

    @parameterized.named_parameters(
        (
            'MIXED_TO_V4',
            [
                [nacaddr.IPv4('0.0.0.0/1'), nacaddr.IPv6('2001::/33')],
                [nacaddr.IPv4('192.168.0.0/24')],
            ],
            [
                '            term good-term {\n'
                + '                from {\n'
                + '                    source-address {\n'
                + '                        0.0.0.0/1;\n'
                + '                    }\n'
                + '                    destination-address {\n'
                + '                        192.168.0.0/24;\n'
                + '                    }'
            ],
            ['2001::/33'],
        ),
        (
            'V4_TO_MIXED',
            [
                [nacaddr.IPv4('192.168.0.0/24')],
                [nacaddr.IPv4('0.0.0.0/1'), nacaddr.IPv6('2001::/33')],
            ],
            [
                '            term good-term {\n'
                + '                from {\n'
                + '                    source-address {\n'
                + '                        192.168.0.0/24;\n'
                + '                    }\n'
                + '                    destination-address {\n'
                + '                        0.0.0.0/1;\n'
                + '                    }'
            ],
            ['2001::/33'],
        ),
        (
            'MIXED_TO_V6',
            [[nacaddr.IPv4('0.0.0.0/1'), nacaddr.IPv6('2001::/33')], [nacaddr.IPv6('2201::/48')]],
            [
                '            term good-term {\n'
                + '                from {\n'
                + '                    source-address {\n'
                + '                        2001::/33;\n'
                + '                    }\n'
                + '                    destination-address {\n'
                + '                        2201::/48;\n'
                + '                    }'
            ],
            ['0.0.0.0/1'],
        ),
        (
            'V6_TO_MIXED',
            [[nacaddr.IPv6('2201::/48')], [nacaddr.IPv4('0.0.0.0/1'), nacaddr.IPv6('2001::/33')]],
            [
                '            term good-term {\n'
                + '                from {\n'
                + '                    source-address {\n'
                + '                        2201::/48;\n'
                + '                    }\n'
                + '                    destination-address {\n'
                + '                        2001::/33;\n'
                + '                    }'
            ],
            ['0.0.0.0/1'],
        ),
        (
            'MIXED_TO_MIXED',
            [
                [nacaddr.IPv4('0.0.0.0/1'), nacaddr.IPv6('2001::/33')],
                [nacaddr.IPv4('192.168.0.0/24'), nacaddr.IPv6('2201::/48')],
            ],
            [
                '            term good-term {\n'
                + '                from {\n'
                + '                    source-address {\n'
                + '                        0.0.0.0/1;\n'
                + '                    }\n'
                + '                    destination-address {\n'
                + '                        192.168.0.0/24;\n'
                + '                    }',
                '            term good-term {\n'
                + '                from {\n'
                + '                    source-address {\n'
                + '                        2001::/33;\n'
                + '                    }\n'
                + '                    destination-address {\n'
                + '                        2201::/48;\n'
                + '                    }',
            ],
            [],
        ),
        (
            'V4_TO_V4',
            [[nacaddr.IPv4('0.0.0.0/1')], [nacaddr.IPv4('192.168.0.0/24')]],
            [
                '            term good-term {\n'
                + '                from {\n'
                + '                    source-address {\n'
                + '                        0.0.0.0/1;\n'
                + '                    }\n'
                + '                    destination-address {\n'
                + '                        192.168.0.0/24;\n'
                + '                    }'
            ],
            [],
        ),
        (
            'V6_TO_V6',
            [[nacaddr.IPv6('2001::/33')], [nacaddr.IPv6('2201::/48')]],
            [
                '            term good-term {\n'
                + '                from {\n'
                + '                    source-address {\n'
                + '                        2001::/33;\n'
                + '                    }\n'
                + '                    destination-address {\n'
                + '                        2201::/48;\n'
                + '                    }'
            ],
            [],
        ),
        (
            'V4_TO_V6',
            [[nacaddr.IPv4('0.0.0.0/1')], [nacaddr.IPv6('2201::/48')]],
            [],
            ['0.0.0.0/1', '192.168.0.0/24', '2001::/33', '2201::/48'],
        ),
        (
            'V6_TO_V4',
            [[nacaddr.IPv6('2001::/33')], [nacaddr.IPv4('192.168.0.0/24')]],
            [],
            ['0.0.0.0/1', '192.168.0.0/24', '2001::/33', '2201::/48'],
        ),
        (
            'PARTLY_UNSPECIFIED',
            [[nacaddr.IPv6('2001::/33')], [nacaddr.IPv4('192.168.0.0/24')]],
            ['term good_term_25 '],
            [
                '0.0.0.0/1',
                '192.168.0.0/24',
                '2001::/33',
                '2201::/48',
                'term good-term-both-icmp-and-icmpv6-',
            ],
        ),
    )
    def testMixed(self, addresses, expected, notexpected):
        self.naming.GetNetAddr.side_effect = addresses
        self.naming.GetServiceByProto.return_value = ['25']
        jcl = juniper.Juniper(
            policy.ParsePolicy(GOOD_HEADER_MIXED + MIXED_TESTING_TERM + GOOD_TERM_25, self.naming),
            EXP_INFO,
        )
        output = str(jcl)
        for expect in expected:
            self.assertIn(expect, output, output)
        for notexpect in notexpected:
            self.assertNotIn(notexpect, output, output)


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


class JuniperYAMLTest(JuniperTest):
    def setUp(self):
        super().setUp()
        # patch policy.ParsePolicy into a wrapper that calls YAML.load_str
        self.patchers = [mock.patch.object(policy, 'ParsePolicy', _YamlParsePolicy)]
        [patcher.start() for patcher in self.patchers]
        self.setUpFixtures()

    def tearDown(self):
        [patcher.stop() for patcher in self.patchers]
        self.tearDownFixtures()

    def tearDownFixtures(self):
        self.fixture_patcher.stop()

    def setUpFixtures(self):
        self.fixture_patcher = mock.patch.multiple(
            'juniper_test',
            GOOD_HEADER=YAML_GOOD_HEADER,
            GOOD_HEADER_2=YAML_GOOD_HEADER_2,
            GOOD_HEADER_V6=YAML_GOOD_HEADER_V6,
            GOOD_HEADER_MIXED=YAML_GOOD_HEADER_MIXED,
            GOOD_HEADER_BRIDGE=YAML_GOOD_HEADER_BRIDGE,
            GOOD_DSMO_HEADER=YAML_GOOD_DSMO_HEADER,
            GOOD_FILTER_ENHANCED_MODE_HEADER=YAML_GOOD_FILTER_ENHANCED_MODE_HEADER,
            GOOD_NOVERBOSE_V4_HEADER=YAML_GOOD_NOVERBOSE_V4_HEADER,
            GOOD_NOVERBOSE_V6_HEADER=YAML_GOOD_NOVERBOSE_V6_HEADER,
            GOOD_HEADER_NOT_INTERFACE_SPECIFIC=YAML_GOOD_HEADER_NOT_INTERFACE_SPECIFIC,
            BAD_HEADER=YAML_BAD_HEADER,
            BAD_HEADER_2=YAML_BAD_HEADER_2,
            EXPIRED_TERM=YAML_EXPIRED_TERM,
            EXPIRING_TERM=YAML_EXPIRING_TERM,
            GOOD_TERM_1=YAML_GOOD_TERM_1,
            GOOD_TERM_1_V6=YAML_GOOD_TERM_1_V6,
            GOOD_TERM_2=YAML_GOOD_TERM_2,
            GOOD_TERM_3=YAML_GOOD_TERM_3,
            GOOD_TERM_5=YAML_GOOD_TERM_5,
            GOOD_TERM_7=YAML_GOOD_TERM_7,
            GOOD_TERM_8=YAML_GOOD_TERM_8,
            GOOD_TERM_9=YAML_GOOD_TERM_9,
            GOOD_TERM_10=YAML_GOOD_TERM_10,
            GOOD_TERM_11=YAML_GOOD_TERM_11,
            GOOD_TERM_12=YAML_GOOD_TERM_12,
            GOOD_TERM_13=YAML_GOOD_TERM_13,
            GOOD_TERM_14=YAML_GOOD_TERM_14,
            GOOD_TERM_15=YAML_GOOD_TERM_15,
            GOOD_TERM_16=YAML_GOOD_TERM_16,
            GOOD_TERM_17=YAML_GOOD_TERM_17,
            GOOD_TERM_18_SRC=YAML_GOOD_TERM_18_SRC,
            GOOD_TERM_18_DST=YAML_GOOD_TERM_18_DST,
            GOOD_TERM_19=YAML_GOOD_TERM_19,
            GOOD_TERM_V6_HOP_LIMIT=YAML_GOOD_TERM_V6_HOP_LIMIT,
            GOOD_TERM_20_V6=YAML_GOOD_TERM_20_V6,
            GOOD_TERM_21=YAML_GOOD_TERM_21,
            GOOD_TERM_22=YAML_GOOD_TERM_22,
            GOOD_TERM_23=YAML_GOOD_TERM_23,
            GOOD_TERM_24=YAML_GOOD_TERM_24,
            GOOD_TERM_25=YAML_GOOD_TERM_25,
            GOOD_TERM_26=YAML_GOOD_TERM_26,
            GOOD_TERM_26_V6=YAML_GOOD_TERM_26_V6,
            GOOD_TERM_26_V6_REJECT=YAML_GOOD_TERM_26_V6_REJECT,
            GOOD_TERM_27=YAML_GOOD_TERM_27,
            GOOD_TERM_28=YAML_GOOD_TERM_28,
            GOOD_TERM_29=YAML_GOOD_TERM_29,
            GOOD_TERM_30=YAML_GOOD_TERM_30,
            GOOD_TERM_31=YAML_GOOD_TERM_31,
            GOOD_TERM_32=YAML_GOOD_TERM_32,
            GOOD_TERM_33=YAML_GOOD_TERM_33,
            GOOD_TERM_34=YAML_GOOD_TERM_34,
            GOOD_TERM_35=YAML_GOOD_TERM_35,
            GOOD_TERM_36=YAML_GOOD_TERM_36,
            GOOD_TERM_37=YAML_GOOD_TERM_37,
            GOOD_TERM_COMMENT=YAML_GOOD_TERM_COMMENT,
            GOOD_TERM_FILTER=YAML_GOOD_TERM_FILTER,
            BAD_TERM_1=YAML_BAD_TERM_1,
            ESTABLISHED_TERM_1=YAML_ESTABLISHED_TERM_1,
            OPTION_TERM_1=YAML_OPTION_TERM_1,
            BAD_ICMPTYPE_TERM_1=YAML_BAD_ICMPTYPE_TERM_1,
            BAD_ICMPTYPE_TERM_2=YAML_BAD_ICMPTYPE_TERM_2,
            DEFAULT_TERM_1=YAML_DEFAULT_TERM_1,
            ENCAPSULATE_GOOD_TERM_1=YAML_ENCAPSULATE_GOOD_TERM_1,
            ENCAPSULATE_GOOD_TERM_2=YAML_ENCAPSULATE_GOOD_TERM_2,
            ENCAPSULATE_BAD_TERM_1=YAML_ENCAPSULATE_BAD_TERM_1,
            ENCAPSULATE_BAD_TERM_2=YAML_ENCAPSULATE_BAD_TERM_2,
            PORTMIRROR_GOOD_TERM_1=YAML_PORTMIRROR_GOOD_TERM_1,
            PORTMIRROR_GOOD_TERM_2=YAML_PORTMIRROR_GOOD_TERM_2,
            LONG_COMMENT_TERM_1=YAML_LONG_COMMENT_TERM_1,
            LONG_POLICER_TERM_1=YAML_LONG_POLICER_TERM_1,
            HOPOPT_TERM=YAML_HOPOPT_TERM,
            HOPOPT_TERM_EXCEPT=YAML_HOPOPT_TERM_EXCEPT,
            FRAGOFFSET_TERM=YAML_FRAGOFFSET_TERM,
            GOOD_FLEX_MATCH_TERM=YAML_GOOD_FLEX_MATCH_TERM,
            BAD_FLEX_MATCH_TERM_1=YAML_BAD_FLEX_MATCH_TERM_1,
            BAD_FLEX_MATCH_TERM_2=YAML_BAD_FLEX_MATCH_TERM_2,
            BAD_FLEX_MATCH_TERM_3=YAML_BAD_FLEX_MATCH_TERM_3,
            BAD_FLEX_MATCH_TERM_4=YAML_BAD_FLEX_MATCH_TERM_4,
            BAD_TERM_FILTER=YAML_BAD_TERM_FILTER,
            MIXED_TESTING_TERM=YAML_MIXED_TESTING_TERM,
        )

        self.fixture_patcher.start()

    def testFailFlexibleMatch(self):
        # The parent test asserts that invalid flexmatch configuration crashes the run
        # The YAML parser will reject the flexmatch rule with a warning.
        self.assertTrue(True)


YAML_GOOD_HEADER = """
filters:
- header:
    comment: this is a test acl
    targets:
      juniper: test-filter
  terms:
"""
YAML_GOOD_HEADER_2 = """
filters:
- header:
    targets:
      juniper: test-filter bridge
  terms:
"""
YAML_GOOD_HEADER_V6 = """
filters:
- header:
    targets:
      juniper: test-filter inet6
  terms:
"""
YAML_GOOD_HEADER_MIXED = """
filters:
- header:
    targets:
      juniper: test-filter mixed
  terms:
"""
YAML_GOOD_HEADER_BRIDGE = """
filters:
- header:
    targets:
      juniper: test-filter bridge
  terms:
"""
YAML_GOOD_DSMO_HEADER = """
filters:
- header:
    targets:
      juniper: test-filter enable_dsmo
  terms:
"""
YAML_GOOD_FILTER_ENHANCED_MODE_HEADER = """
filters:
- header:
    targets:
      juniper: test-filter filter_enhanced_mode
  terms:
"""
YAML_GOOD_NOVERBOSE_V4_HEADER = """
filters:
- header:
    targets:
      juniper: test-filter inet noverbose
  terms:
"""
YAML_GOOD_NOVERBOSE_V6_HEADER = """
filters:
- header:
    targets:
      juniper: test-filter inet6 noverbose
  terms:
"""
YAML_GOOD_HEADER_NOT_INTERFACE_SPECIFIC = """
filters:
- header:
    targets:
      juniper: test-filter bridge not-interface-specific
  terms:
"""
YAML_BAD_HEADER = """
filters:
- header:
    comment: this is a test acl
    targets:
      cisco: test-filter
  terms:
"""
YAML_BAD_HEADER_2 = """
filters:
- header:
    targets:
      juniper: test-filter inetpoop
  terms:
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
YAML_GOOD_TERM_1 = """
  - name: good-term-1
    protocol: icmp
    action: accept

  - name: good-term-2
    protocol: tcp
    destination-port: SMTP
    destination-address: SOME_HOST
    action: accept
"""
YAML_GOOD_TERM_1_V6 = """
  - name: good-term-1
    protocol: icmpv6
    action: accept

  - name: good-term-2
    protocol: tcp
    destination-port: SMTP
    destination-address: SOME_HOST
    action: accept
"""
YAML_GOOD_TERM_2 = """
  - name: good-term-3
    protocol: tcp
    destination-address: SOME_HOST
    source-port: HTTP
    option: established tcp-established
    action: accept
"""
YAML_GOOD_TERM_3 = """
  - name: good-term-3
    protocol: icmp
    icmp-type: echo-reply information-reply information-request router-solicitation timestamp-request
    action: accept
"""
YAML_GOOD_TERM_5 = """
  - name: good-term-5
    protocol: icmp tcp
    action: accept
"""
YAML_GOOD_TERM_7 = """
  - name: good-term-7
    protocol-except: tcp
    action: accept
"""
YAML_GOOD_TERM_8 = """
  - name: good-term-8
    source-prefix: foo_prefix_list
    destination-prefix: bar_prefix_list baz_prefix_list
    action: accept
"""
YAML_GOOD_TERM_9 = """
  - name: good-term-9
    ether-type: arp
    action: accept
"""
YAML_GOOD_TERM_10 = """
  - name: good-term-10
    traffic-type: unknown-unicast
    action: accept
"""
YAML_GOOD_TERM_11 = """
  - name: good-term-11
    verbatim:
      juniper: mary had a little lamb
      iptables: mary had a second lamb
      cisco: mary had a third lamb
"""
YAML_GOOD_TERM_12 = """
  - name: good-term-12
    source-address: LOCALHOST
    action: accept
"""
YAML_GOOD_TERM_13 = """
  - name: routing-instance-setting
    protocol: tcp
    routing-instance: EXTERNAL-NAT
"""
YAML_GOOD_TERM_14 = """
  - name: loss-priority-setting
    protocol: tcp
    loss-priority: low
    action: accept
"""
YAML_GOOD_TERM_15 = """
  - name: precedence-setting
    protocol: tcp
    destination-port: SSH
    precedence: 7
    action: accept
"""
YAML_GOOD_TERM_16 = """
  - name: precedence-setting
    protocol: tcp
    destination-port: SSH
    precedence: 5 7
    action: accept
"""
YAML_GOOD_TERM_17 = """
  - name: owner-term
    owner: foo@google.com
    action: accept
"""
YAML_GOOD_TERM_18_SRC = """
  - name: address-exclusions
    source-address: INTERNAL
    source-exclude: SOME_HOST
    action: accept
"""
YAML_GOOD_TERM_18_DST = """
  - name: address-exclusions
    destination-address: INTERNAL
    destination-exclude: SOME_HOST
    action: accept
"""
YAML_GOOD_TERM_19 = """
  - name: minimize-prefix-list
    source-address: INCLUDES
    source-exclude: EXCLUDES
    action: accept
"""
YAML_GOOD_TERM_V6_HOP_LIMIT = """
  - name: good-term-v6-hl
    hop-limit: 25
    action: accept
"""
YAML_GOOD_TERM_20_V6 = """
  - name: good-term-20-v6
    protocol-except: icmpv6
    action: accept
"""
YAML_GOOD_TERM_21 = """
  - name: good_term_21
    ttl: 10
    action: accept
"""
YAML_GOOD_TERM_22 = """
  - name: good_term_22
    protocol: tcp
    source-port: DNS
    dscp-set: b111000
    action: accept
"""
YAML_GOOD_TERM_23 = """
  - name: good_term_23
    protocol: tcp
    source-port: DNS
    dscp-set: af42
    dscp-match: af41-af42 5
    dscp-except: be
    action: accept
"""
YAML_GOOD_TERM_24 = """
  - name: good_term_24
    protocol: tcp
    source-port: DNS
    qos: af1
    action: accept
"""
YAML_GOOD_TERM_25 = """
  - name: good_term_25
    protocol: tcp
    source-port: DNS
    action: accept
"""
YAML_GOOD_TERM_26 = """
  - name: good_term_26
    protocol: tcp
    source-port: DNS
    action: deny
"""
YAML_GOOD_TERM_26_V6 = """
  - name: good_term_26-v6
    protocol: tcp
    source-port: DNS
    action: deny
"""
YAML_GOOD_TERM_26_V6_REJECT = """
  - name: good_term_26-v6
    protocol: tcp
    source-port: DNS
    action: reject
"""
YAML_GOOD_TERM_27 = """
  - name: good_term_27
    forwarding-class: Floop
    action: deny
"""
YAML_GOOD_TERM_28 = """
  - name: good_term_28
    next-ip: TEST_NEXT
"""
YAML_GOOD_TERM_29 = """
  - name: multiple-forwarding-class
    forwarding-class: floop fluup fleep
    action: deny
"""
YAML_GOOD_TERM_30 = """
  - name: good-term-30
    source-prefix-except: foo_prefix_list
    destination-prefix-except: bar_prefix_list
    action: accept
"""
YAML_GOOD_TERM_31 = """
  - name: good-term-31
    source-prefix: foo_prefix
    source-prefix-except: foo_except
    destination-prefix: bar_prefix
    destination-prefix-except: bar_except
    action: accept
"""
YAML_GOOD_TERM_32 = """
  - name: good_term_32
    forwarding-class-except: floop
    action: deny
"""
YAML_GOOD_TERM_33 = """
  - name: multiple-forwarding-class-except
    forwarding-class-except: floop fluup fleep
    action: deny
"""
YAML_GOOD_TERM_34 = """
  - name: good_term_34
    traffic-class-count: floop
    action: deny
"""
YAML_GOOD_TERM_35 = """
  - name: good_term_35
    protocol: icmp
    icmp-type: unreachable
    icmp-code: 3 4
    action: accept
"""
YAML_GOOD_TERM_36 = """
  - name: good-term-36
    protocol: tcp
    destination-address: SOME_HOST SOME_HOST
    option: inactive
    action: accept
"""
YAML_GOOD_TERM_37 = """
  - name: good-term-37
    destination-address: SOME_HOST
    restrict-address-family: inet
    action: accept
"""
YAML_GOOD_TERM_COMMENT = """
  - name: good-term-comment
    comment: This is a COMMENT
    action: accept
"""
YAML_GOOD_TERM_FILTER = """
  - name: good-term-filter
    comment: This is a COMMENT
    filter-term: my-filter
"""
YAML_BAD_TERM_1 = """
  - name: bad-term-1
    protocol: tcp udp
    source-port: DNS
    option: tcp-established
    action: accept
"""
YAML_ESTABLISHED_TERM_1 = """
  - name: established-term-1
    protocol: tcp
    source-port: DNS
    option: established
    action: accept
"""
YAML_OPTION_TERM_1 = """
  - name: option-term
    protocol: tcp
    source-port: SSH
    option: is-fragment
    action: accept
"""
YAML_BAD_ICMPTYPE_TERM_1 = """
  - name: icmptype-mismatch
    comment: error when icmpv6 paired with inet filter
    protocol: icmpv6
    icmp-type: echo-request echo-reply
    action: accept
"""
YAML_BAD_ICMPTYPE_TERM_2 = """
  - name: icmptype-mismatch
    comment: error when icmp paired with inet6 filter
    protocol: icmp
    icmp-type: echo-request echo-reply
    action: accept
"""
YAML_DEFAULT_TERM_1 = """
  - name: default-term-1
    action: deny
"""
YAML_ENCAPSULATE_GOOD_TERM_1 = """
  - name: good-term-1
    protocol: tcp
    encapsulate: template-name
"""
YAML_ENCAPSULATE_GOOD_TERM_2 = """
  - name: good-term-2
    protocol: tcp
    encapsulate: template-name
    counter: count-name
"""
YAML_ENCAPSULATE_BAD_TERM_1 = """
  - name: bad-term-1
    protocol: tcp
    encapsulate: template-name
    action: accept
"""
YAML_ENCAPSULATE_BAD_TERM_2 = """
  - name: bad-term-2
    protocol: tcp
    encapsulate: template-name
    routing-instance: instance-name
"""
YAML_PORTMIRROR_GOOD_TERM_1 = """
  - name: good-term-1
    protocol: tcp
    port-mirror: true
"""
YAML_PORTMIRROR_GOOD_TERM_2 = """
  - name: good-term-2
    protocol: tcp
    port-mirror: true
    counter: count-name
    action: deny
"""
YAML_LONG_COMMENT_TERM_1 = """
  - name: long-comment-term-1
    comment: |
        this is very very very very very very very very very very very
        very very very very very very very long.
    action: deny
"""
YAML_LONG_POLICER_TERM_1 = """
  - name: long-policer-term-1
    policer: this-is-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-very-long
    action: deny
"""
YAML_HOPOPT_TERM = """
  - name: good-term-1
    protocol: hopopt
    action: accept
"""
YAML_HOPOPT_TERM_EXCEPT = """
  - name: good-term-1
    protocol-except: hopopt
    action: accept
"""
YAML_FRAGOFFSET_TERM = """
  - name: good-term-1
    fragment-offset: 1-7
    action: accept
"""
YAML_GOOD_FLEX_MATCH_TERM = """
  - name: flex-match-term-1
    protocol: tcp
    flexible-match-range:
      bit-length: 8
      range: "0x08"
      match-start: payload
      byte-offset: 16
      bit-offset: 7
    action: deny
"""
YAML_BAD_FLEX_MATCH_TERM_1 = """
  - name: flex-match-term-1
    protocol: tcp
    flexible-match-range:
      bit-length: 36
      range: "0x08"
      match-start: payload
      byte-offset: 16
      bit-offset: 7
    action: deny
"""
YAML_BAD_FLEX_MATCH_TERM_2 = """
  - name: flex-match-term-1
    protocol: tcp
    flexible-match-range:
      bit-length: 8
      range: "0x08"
      match-start: wrong
      byte-offset: 16
      bit-offset: 7
    action: deny
"""
YAML_BAD_FLEX_MATCH_TERM_3 = """
  - name: flex-match-term-1
    protocol: tcp
    flexible-match-range:
      bit-length: 8
      range: "0x08"
      match-start: payload
      byte-offset: 260
      bit-offset: 7
    action: deny
"""
YAML_BAD_FLEX_MATCH_TERM_4 = """
  - name: flex-match-term-1
    protocol: tcp
    flexible-match-range:
      bit-length: 8
      range: "0x08"
      match-start: payload
      byte-offset: 16
      bit-offset: 8
    action: deny
"""
YAML_BAD_TERM_FILTER = """
  - name: bad_term_filter
    filter-term: my-filter
    action: deny
"""

YAML_MIXED_TESTING_TERM = """
  - name: good-term
    protocol: tcp
    source-address: SOME_HOST
    destination-port: SMTP
    destination-address: SOME_OTHER_HOST
    action: accept
"""

if __name__ == '__main__':
    absltest.main()
