# Copyright 2016 Google Inc. All Rights Reserved.
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
"""Unittest for pcap rendering module."""

import datetime
from unittest import mock

from absl.testing import absltest

from aerleon.lib import aclgenerator, nacaddr, naming, pcap, policy
from tests.regression_utils import capture

GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: pcap test-filter
}
"""

GOOD_HEADER_IN = """
header {
  comment:: "this is a test acl"
  target:: pcap test-filter in
}
"""

GOOD_HEADER_OUT = """
header {
  comment:: "this is a test acl"
  target:: pcap test-filter out
}
"""

GOOD_TERM_ICMP = """
term good-term-icmp {
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_ICMP_TYPES = """
term good-term-icmp-types {
  protocol:: icmp
  icmp-type:: echo-reply unreachable time-exceeded
  action:: deny
}
"""

GOOD_TERM_ICMPV6 = """
term good-term-icmpv6 {
  protocol:: icmpv6
  action:: accept
}
"""

BAD_TERM_ICMP = """
term test-icmp {
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

BAD_TERM_ACTION = """
term bad-term-action {
  protocol:: icmp
  action:: undefined
}
"""

GOOD_TERM_TCP = """
term good-term-tcp {
  comment:: "Test term 1"
  destination-address:: PROD_NETWRK
  destination-port:: SMTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_WARNING_TERM = """
term good-warning-term {
  comment:: "Test term 1"
  destination-address:: PROD_NETWRK
  destination-port:: SMTP
  protocol:: tcp
  policer:: batman
  action:: accept
}
"""

GOOD_TERM_LOG = """
term good-term-log {
  protocol:: tcp
  logging:: true
  action:: accept
}
"""
GOOD_ICMP_CODE = """
term good_term {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 3 4
  action:: accept
}
"""
EXPIRED_TERM = """
term expired_test {
  expiration:: 2000-1-1
  action:: deny
}
"""

EXPIRING_TERM = """
term is_expiring {
  expiration:: %s
  action:: accept
}
"""

MULTIPLE_PROTOCOLS_TERM = """
term multi-proto {
  protocol:: tcp udp icmp
  action:: accept
}
"""

NEXT_TERM = """
term next {
  action:: next
}
"""

NEXT_LOG_TERM = """
term next-log {
  logging:: true
  action:: next
}
"""

ESTABLISHED_TERM = """
term accept-established {
  protocol:: tcp
  option:: tcp-established
  action:: accept
}
"""

VRRP_TERM = """
term vrrp-term {
  protocol:: vrrp
  action:: accept
}
"""

UNICAST_TERM = """
term unicast-term {
  destination-address:: ANY
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_HBH = """
term good-term-hbh {
  protocol:: hopopt
  action:: accept
}
"""

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'expiration',
    'icmp_code',
    'icmp_type',
    'stateless_reply',
    'logging',
    'name',
    'option',
    'platform',
    'platform_exclude',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
    'translated',
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'next'},
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
        'syn',
        'ack',
        'fin',
        'rst',
        'urg',
        'psh',
        'all',
        'none',
        'established',
        'tcp-established',
    },
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class PcapFilter(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = mock.create_autospec(naming.Naming)

    @capture.stdout
    def testTcp(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
        self.naming.GetServiceByProto.return_value = ['25']

        acl = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_TCP, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn(
            '(dst net 10.0.0.0/8) and (proto \\tcp) and (dst port 25)',
            result,
            'did not find actual term for good-term-tcp',
        )

        self.naming.GetNetAddr.assert_called_once_with('PROD_NETWRK')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')
        print(result)

    @capture.stdout
    def testLog(self):
        acl = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_LOG, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn('proto \\tcp', result, 'did not find actual term for good-term-log')
        print(result)

    @capture.stdout
    def testIcmp(self):
        acl = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_ICMP, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn('proto \\icmp', result, 'did not find actual term for good-term-icmp')
        print(result)

    @capture.stdout
    def testIcmpCode(self):
        acl = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER + GOOD_ICMP_CODE, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn('and icmp[icmpcode] == 3', result, result)
        self.assertIn('and icmp[icmpcode] == 4', result, result)
        print(result)

    @capture.stdout
    def testIcmpTypes(self):
        acl = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_ICMP_TYPES, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn(
            '(proto \\icmp) and (icmp[icmptype] == 0 or icmp[icmptype] == 3'
            ' or icmp[icmptype] == 11)',
            result,
            'did not find actual term for good-term-icmp-types',
        )
        print(result)

    @capture.stdout
    def testIcmpv6(self):
        acl = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_ICMPV6, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn('icmp6', result, 'did not find actual term for good-term-icmpv6')
        print(result)

    def testBadIcmp(self):
        acl = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER + BAD_TERM_ICMP, self.naming), EXP_INFO
        )
        self.assertRaises(aclgenerator.UnsupportedFilterError, str, acl)

    @mock.patch.object(pcap.logging, 'warning')
    def testExpiredTerm(self, mock_warn):
        pcap.PcapFilter(policy.ParsePolicy(GOOD_HEADER + EXPIRED_TERM, self.naming), EXP_INFO)

        mock_warn.assert_called_once_with(
            'WARNING: Term %s in policy %s is expired and ' 'will not be rendered.',
            'expired_test',
            'test-filter',
        )

    @mock.patch.object(pcap.logging, 'info')
    def testExpiringTerm(self, mock_info):
        exp_date = datetime.date.today() + datetime.timedelta(weeks=EXP_INFO)
        pcap.PcapFilter(
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
    def testMultiprotocol(self):
        acl = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER + MULTIPLE_PROTOCOLS_TERM, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn(
            '(proto \\tcp or proto \\udp or proto \\icmp)',
            result,
            'did not find actual term for multi-proto',
        )
        print(result)

    def testNextTerm(self):
        acl = pcap.PcapFilter(policy.ParsePolicy(GOOD_HEADER + NEXT_TERM, self.naming), EXP_INFO)
        result = str(acl)
        self.assertIn('', result, 'did not find actual term for good-term-icmpv6')

    @capture.stdout
    def testTcpOptions(self):
        acl = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER + ESTABLISHED_TERM, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn(
            '(tcp[tcpflags] & (tcp-ack) == (tcp-ack)',
            result,
            'did not find actual term for established',
        )
        print(result)

    @capture.stdout
    def testVrrpTerm(self):
        acl = pcap.PcapFilter(policy.ParsePolicy(GOOD_HEADER + VRRP_TERM, self.naming), EXP_INFO)
        result = str(acl)
        self.assertIn('(proto 112)', result, 'did not find actual term for vrrp')
        print(result)

    @capture.stdout
    def testMultiHeader(self):
        acl = pcap.PcapFilter(
            policy.ParsePolicy(
                GOOD_HEADER + GOOD_TERM_LOG + GOOD_HEADER + GOOD_TERM_ICMP, self.naming
            ),
            EXP_INFO,
        )
        result = str(acl)
        self.assertIn(
            '((((proto \\tcp))\n))\nor\n((((proto \\icmp))\n))',
            result,
            'did not find actual terms for multi-header',
        )
        print(result)

    @capture.stdout
    def testDirectional(self):
        acl = pcap.PcapFilter(
            policy.ParsePolicy(
                GOOD_HEADER_IN + GOOD_TERM_LOG + GOOD_HEADER_OUT + GOOD_TERM_ICMP, self.naming
            ),
            EXP_INFO,
        )
        result = str(acl)
        self.assertIn(
            '(((dst net localhost and ((proto \\tcp)))\n))\nor\n'
            '(((src net localhost and ((proto \\icmp)))\n))',
            result,
            'did not find actual terms for directional',
        )
        print(result)

    @capture.stdout
    def testUnicastIPv6(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('::/0')]

        acl = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER_IN + UNICAST_TERM, self.naming), EXP_INFO
        )
        result = str(acl)
        self.assertIn(
            '(dst net localhost and ((proto \\tcp)))',
            result,
            'did not find actual terms for unicast-term',
        )

        self.naming.GetNetAddr.assert_called_once_with('ANY')
        print(result)

    @capture.stdout
    def testHbh(self):
        acl = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_HBH, self.naming), EXP_INFO
        )
        result = str(acl)

        self.assertIn('(ip6 protochain 0)', result, 'did not find actual terms for unicast-term')
        print(result)

    def testBuildTokens(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
        self.naming.GetServiceByProto.return_value = ['25']
        pol1 = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_TCP, self.naming), EXP_INFO
        )
        st, sst = pol1._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    def testBuildWarningTokens(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.0.0.0/8')]
        self.naming.GetServiceByProto.return_value = ['25']

        pol1 = pcap.PcapFilter(
            policy.ParsePolicy(GOOD_HEADER + GOOD_WARNING_TERM, self.naming), EXP_INFO
        )
        st, sst = pol1._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)


if __name__ == '__main__':
    absltest.main()
