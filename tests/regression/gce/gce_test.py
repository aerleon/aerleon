# Copyright 2015 Google Inc. All Rights Reserved.
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

"""Unittest for GCE firewall rendering module."""

import json
from unittest import mock

from absl.testing import absltest, parameterized

from aerleon.lib import aclgenerator, gce, gcp, nacaddr, naming, policy
from aerleon.lib import yaml as yaml_frontend
from tests.regression_utils import capture

GOOD_HEADER = """
header {
  comment:: "The general policy comment."
  target:: gce global/networks/default
}
"""

GOOD_HEADER_INGRESS = """
header {
  comment:: "The general policy comment."
  target:: gce INGRESS
}
"""

GOOD_HEADER_EGRESS = """
header {
  comment:: "The general policy comment."
  target:: gce EGRESS
}
"""

GOOD_HEADER_NO_NETWORK = """
header {
  comment:: "The general policy comment."
  target:: gce
}
"""

GOOD_HEADER_MAX_ATTRIBUTE_COUNT = """
header {
  comment:: "The general policy comment."
  target:: gce INGRESS global/networks/default 2
}
"""

GOOD_HEADER_INET = """
header {
  comment:: "The general policy comment."
  target:: gce INGRESS inet
}
"""

GOOD_HEADER_EGRESS_INET = """
header {
  comment:: "The general policy comment."
  target:: gce INGRESS inet
}
"""

GOOD_HEADER_INET6 = """
header {
  comment:: "The general policy comment."
  target:: gce INGRESS inet6
}
"""

GOOD_HEADER_EGRESS_INET6 = """
header {
  comment:: "The general policy comment."
  target:: gce EGRESS inet6
}
"""

GOOD_HEADER_MIXED = """
header {
  comment:: "The general policy comment."
  target:: gce INGRESS mixed
}
"""

GOOD_HEADER_EGRESS_MIXED = """
header {
  comment:: "The general policy comment."
  target:: gce EGRESS mixed
}
"""

GOOD_TERM = """
term good-term-1 {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_TERM_2 = """
term good-term-2 {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  policer:: batman
  action:: accept
}
"""

GOOD_TERM_3 = """
term good-term-1 {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  priority:: 1
  action:: accept
}
"""

GOOD_TERM_EXCLUDE = """
term good-term-1 {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  source-exclude:: GUEST_WIRELESS_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_TERM_4 = """
term good-term-1 {
  comment:: "DNS access from corp."
  destination-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""
GOOD_TERM_5 = """
term good-term-5 {
  comment:: "ICMP from IP."
  source-address:: CORP_EXTERNAL
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_EGRESS = """
term good-term-1 {
  comment:: "DNS access from corp."
  destination-address:: CORP_EXTERNAL
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_TERM_EGRESS_SOURCETAG = """
term good-term-1 {
  comment:: "DNS access from corp."
  destination-address:: CORP_EXTERNAL
  source-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_TERM_INGRESS_SOURCETAG = """
term good-term-1 {
  comment:: "Allow all GCE network internal traffic."
  source-tag:: internal-servers
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_TERM_INGRESS_ADDRESS_SOURCETAG = """
term good-term-1 {
  comment:: "Allow all GCE network internal traffic."
  source-tag:: internal-servers
  source-address:: CORP_EXTERNAL
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_PLATFORM_EXCLUDE_TERM = """
term good-platform-exclude-term {
  comment:: "DNS access from corp."
  destination-tag:: dns-servers
  protocol:: udp tcp
  action:: accept
  platform-exclude:: gce
}
"""

GOOD_PLATFORM_TERM = """
term good-platform-term {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
  platform:: gce
}
"""


GOOD_TERM_JSON = """
[
  {
    "name": "default-good-term-1",
    "sourceRanges": [
      "10.2.3.4/32"
    ],
    "allowed": [
      {
        "ports": [
          "53"
        ],
        "IPProtocol": "udp"
      },
      {
        "ports": [
          "53"
        ],
        "IPProtocol": "tcp"
      }
    ],
    "description": "DNS access from corp.",
    "targetTags": [
      "dns-servers"
    ],
    "direction": "INGRESS",
    "network": "global/networks/default"
  }
]
"""

GOOD_TERM_NO_NETWORK_JSON = """
[
  {
    "name": "good-term-1",
    "sourceRanges": [
      "10.2.3.4/32"
    ],
    "allowed": [
      {
        "ports": [
          "53"
        ],
        "IPProtocol": "udp"
      },
      {
        "ports": [
          "53"
        ],
        "IPProtocol": "tcp"
      }
    ],
    "description": "DNS access from corp.",
    "direction": "INGRESS",
    "targetTags": [
      "dns-servers"
    ]
  }
]
"""


GOOD_TERM_EXPIRED = """
term good-term-expired {
  comment:: "Management access from corp."
  expiration:: 2001-01-01
  source-address:: CORP_EXTERNAL
  destination-tag:: ssh-servers
  destination-port:: SSH
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_LOGGING = """
term good-term-logging {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
  logging:: true
}
"""

GOOD_TERM_CUSTOM_NAME = """
term %s {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_TERM_OWNERS = """
term good-term-owners {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  owner:: test-owner
  action:: accept
}
"""

GOOD_TERM_ICMP = """
term good-term-ping {
  comment:: "Good term."
  source-address:: CORP_EXTERNAL
  protocol:: icmp
  action:: accept
}
"""

GOOD_TERM_ICMPV6 = """
term good-term-pingv6 {
  comment:: "Good term."
  source-address:: CORP_EXTERNAL
  protocol:: icmpv6
  action:: accept
}
"""

GOOD_TERM_IGMP = """
term good-term-igmp {
  comment:: "Good term."
  source-address:: CORP_EXTERNAL
  protocol:: igmp
  action:: accept
}
"""

GOOD_TERM_NO_PROTOCOL = """
term good-term-no-protocol {
  comment:: "Good term."
  source-address:: CORP_EXTERNAL
  action:: accept
}
"""

BAD_TERM_NO_SOURCE = """
term bad-term-no-source {
  comment:: "Management access from corp."
  destination-tag:: ssh-servers
  destination-port:: SSH
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_SOURCE_EXCLUDE_ONLY = """
term bad-term-source-ex-only {
  comment:: "Management access from corp."
  destination-port:: SSH
  source-tag:: ssh-bastion
  source-exclude:: GUEST_WIRELESS_EXTERNAL
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_SOURCE_PORT = """
term bad-term-source-port {
  comment:: "Management access from corp."
  source-address:: CORP_EXTERNAL
  source-port:: SSH
  destination-tag:: ssh-servers
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_NAME_TOO_LONG = """
term good-term-whith-a-name-which-is-way-way-too-long-for-gce-to-accept {
  comment:: "Management access from corp."
  source-address:: CORP_EXTERNAL
  destination-port:: SSH
  protocol:: tcp
  action:: accept
}
"""

BAD_TERM_UNSUPPORTED_PORT = """
term good-term-unsupported-port {
  comment:: "Management access from corp."
  source-address:: CORP_EXTERNAL
  destination-port:: SSH
  protocol:: tcp icmp
  action:: accept
}
"""

BAD_TERM_UNSUPPORTED_OPTION = """
term bad-term-unsupported-option {
  comment:: "Management access from corp."
  source-address:: CORP_EXTERNAL
  destination-port:: SSH
  protocol:: tcp
  action:: accept
  option:: tcp-initial
}
"""

BAD_TERM_EGRESS = """
term bad-term-dest-tag {
  comment:: "DNS access from corp."
  destination-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

BAD_TERM_EGRESS_SOURCE_ADDRESS = """
term bad-term-source-address {
  comment:: "DNS access from corp."
  destination-address:: CORP_EXTERNAL
  source-address:: CORP_EXTERNAL
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

BAD_TERM_EGRESS_SOURCE_DEST_TAG = """
term bad-term-source-dest-tag {
  comment:: "DNS access from corp."
  destination-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  source-tag:: ssh-bastion
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

BAD_TERM_PORTS_COUNT = """
term bad-term-ports-count {
  comment:: "This term has way too many ports."
  source-address:: CORP_EXTERNAL
  source-tag:: ssh-bastion
  destination-port:: SSH
  protocol:: tcp
  action:: accept
}
"""

SAMPLE_TAG = 'ssh-bastions '

BAD_TERM_SOURCE_TAGS_COUNT = """
term bad-term-source-tags-count {{
  comment:: "This term has way too many source tags."
  protocol:: tcp
  action:: accept
  source-tag:: {many_source_tags}
}}""".format(
    many_source_tags=SAMPLE_TAG * (gce.Term._TERM_SOURCE_TAGS_LIMIT + 1)
)

BAD_TERM_TARGET_TAGS_COUNT = """
term bad-term-target-tags-count {{
  comment:: "This term has way too many target tags."
  source-address:: CORP_EXTERNAL
  protocol:: tcp
  action:: accept
  destination-tag:: {many_target_tags}
}}""".format(
    many_target_tags=SAMPLE_TAG * (gce.Term._TERM_TARGET_TAGS_LIMIT + 1)
)

GOOD_TERM_EXCLUDE_RANGE = """
[
  {
    "name": "default-good-term-1",
    "sourceRanges": [
      "10.128.0.0/10",
      "10.192.0.0/11",
      "10.224.0.0/12",
      "10.241.0.0/16",
      "10.242.0.0/15",
      "10.244.0.0/14",
      "10.248.0.0/13"
    ],
    "allowed": [
      {
        "ports": [
          "53"
        ],
        "IPProtocol": "udp"
      },
      {
        "ports": [
          "53"
        ],
        "IPProtocol": "tcp"
      }
    ],
    "description": "DNS access from corp.",
    "direction": "INGRESS",
    "targetTags": [
      "dns-servers"
    ],
    "network": "global/networks/default"
  }
]
"""

DEFAULT_DENY = """
term default-deny {
  comment:: "default_deny."
  action:: deny
}
"""

GOOD_TERM_DENY = """
term good-term-1 {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-tag:: dns-servers
  protocol:: udp tcp
  action:: deny
}
"""

GOOD_TERM_DENY_EXPECTED = """[
  {
    "denied": [
      {
        "IPProtocol": "udp"
      },
      {
        "IPProtocol": "tcp"
      }
    ],
    "description": "DNS access from corp.",
    "name": "default-good-term-1",
    "network": "global/networks/default",
    "sourceRanges": [
      "10.2.3.4/32"
    ],
    "direction": "INGRESS",
    "targetTags": [
      "dns-servers"
    ]
  }
]
"""

VALID_TERM_NAMES = [
    'icmp',
    'gcp-to-gcp',
    'accept-ssh-from-google',
    'ndc-rampart',
    'lab-syslog',
    'windows-windows',
    'shell-wmn-inbound',
    'shell-internal-smtp',
    'accept-internal-traffic',
    'deepfield-lab-management',
    'deepfield-lab-reverse-proxy',
    'cr-proxy-replication',
    'ciena-one-control-tcp',
    'fms-prod-to-fms-prod',
    'ast',
    'default-deny',
    'google-web',
    'zo6hmxkfibardh6tgbiy7ua6',
]

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'destination_tag',
    'expiration',
    'stateless_reply',
    'name',
    'option',
    'owner',
    'priority',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
    'source_tag',
    'translated',
    'platform',
    'platform_exclude',
}

SUPPORTED_SUB_TOKENS = {'action': {'accept', 'deny'}}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2

TEST_IPS = [nacaddr.IP('10.2.3.4/32'), nacaddr.IP('2001:4860:8000::5/128')]

TEST_INCLUDE_IPS = [nacaddr.IP('10.2.3.4/32'), nacaddr.IP('10.4.3.2/32')]

TEST_EXCLUDE_IPS = [nacaddr.IP('10.4.3.2/32')]

TEST_INCLUDE_RANGE = [nacaddr.IP('10.128.0.0/9')]

TEST_EXCLUDE_RANGE = [nacaddr.IP('10.240.0.0/16')]

ANY_IPS = [nacaddr.IP('0.0.0.0/0'), nacaddr.IP('::/0')]

TEST_IPV4_ONLY = [nacaddr.IP('10.2.3.4/32')]

TEST_IPV6_ONLY = [nacaddr.IP('2001:4860:8000::5/128')]

_TERM_SOURCE_TAGS_LIMIT = 30
_TERM_TARGET_TAGS_LIMIT = 70
_TERM_PORTS_LIMIT = 256


class GCETest(parameterized.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = mock.create_autospec(naming.Naming)

    def _StripAclHeaders(self, acl):
        return '\n'.join(
            [line for line in str(acl).split('\n') if not line.lstrip().startswith('#')]
        )

    @capture.stdout
    def testGenericTerm(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, self.naming), EXP_INFO)
        expected = json.loads(GOOD_TERM_JSON)
        self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'udp'), mock.call('DNS', 'tcp')]
        )
        print(acl)

    @capture.stdout
    def testTermWithPriority(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_3, self.naming), EXP_INFO)
        self.assertIn('"priority": "1",', str(acl), str(acl))
        print(acl)

    @capture.stdout
    def testTermWithLogging(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_LOGGING, self.naming), EXP_INFO)
        rendered_acl = json.loads(str(acl))[0]
        self.assertIn('logConfig', rendered_acl)
        self.assertEqual(rendered_acl['logConfig'], {'enable': True})
        print(acl)

    @capture.stdout
    def testGenericTermWithoutNetwork(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_NO_NETWORK + GOOD_TERM, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_TERM_NO_NETWORK_JSON)
        self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'udp'), mock.call('DNS', 'tcp')]
        )
        print(acl)

    @capture.stdout
    def testGenericTermWithExclude(self):
        self.naming.GetNetAddr.side_effect = [TEST_INCLUDE_IPS, TEST_EXCLUDE_IPS]
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_EXCLUDE, self.naming), EXP_INFO)
        expected = json.loads(GOOD_TERM_JSON)
        self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

        self.naming.GetNetAddr.assert_has_calls(
            [mock.call('CORP_EXTERNAL'), mock.call('GUEST_WIRELESS_EXTERNAL')]
        )
        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'udp'), mock.call('DNS', 'tcp')]
        )
        print(acl)

    @capture.stdout
    def testGenericTermWithExcludeRange(self):
        self.naming.GetNetAddr.side_effect = [TEST_INCLUDE_RANGE, TEST_EXCLUDE_RANGE]
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_EXCLUDE, self.naming), EXP_INFO)
        expected = json.loads(GOOD_TERM_EXCLUDE_RANGE)
        self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))

        self.naming.GetNetAddr.assert_has_calls(
            [mock.call('CORP_EXTERNAL'), mock.call('GUEST_WIRELESS_EXTERNAL')]
        )
        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'udp'), mock.call('DNS', 'tcp')]
        )
        print(acl)

    def testSkipExpiredTerm(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.return_value = ['22']

        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_EXPIRED, self.naming), EXP_INFO)
        self.assertEqual(self._StripAclHeaders(str(acl)), '[]\n\n')

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

    def testSkipStatelessReply(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.return_value = ['22']

        # Add stateless_reply to terms, there is no current way to include it in the
        # term definition.
        ret = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, self.naming)
        _, terms = ret.filters[0]
        for term in terms:
            term.stateless_reply = True

        acl = gce.GCE(ret, EXP_INFO)
        self.assertEqual(self._StripAclHeaders(str(acl)), '[]\n\n')

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'udp'), mock.call('DNS', 'tcp')]
        )

    @capture.stdout
    def testSourceNetworkSplit(self):
        lots_of_ips = []
        for i in range(20):
            for j in range(20):
                lots_of_ips.append(nacaddr.IP('10.%d.%d.1/32' % (i, j)))
        self.naming.GetNetAddr.return_value = lots_of_ips
        self.naming.GetServiceByProto.return_value = ['53']

        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, self.naming), EXP_INFO)
        self.assertIn('default-good-term-1-1', str(acl))
        self.assertIn('default-good-term-1-2', str(acl))

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'udp'), mock.call('DNS', 'tcp')]
        )
        print(acl)

    def testRaisesWithoutSource(self):
        self.naming.GetServiceByProto.return_value = ['22']

        self.assertRaisesRegex(
            gce.GceFirewallError,
            'Ingress rule missing required field oneof "sourceRanges" or "sourceTags.',
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER + BAD_TERM_NO_SOURCE, self.naming),
            EXP_INFO,
        )

        self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

    def testRaisesWithOnlySourceExclusion(self):
        self.naming.GetNetAddr.return_value = TEST_EXCLUDE_IPS
        self.naming.GetServiceByProto.return_value = ['22']

        self.assertRaisesRegex(
            gce.GceFirewallError,
            ('GCE firewall does not support address exclusions without a source ' 'address list.'),
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER + BAD_TERM_SOURCE_EXCLUDE_ONLY, self.naming),
            EXP_INFO,
        )

        self.naming.GetNetAddr.assert_called_once_with('GUEST_WIRELESS_EXTERNAL')
        self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

    def testRaisesNoSourceAfterExclude(self):
        self.naming.GetNetAddr.side_effect = [TEST_INCLUDE_IPS, TEST_INCLUDE_IPS]
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

        self.assertRaisesRegex(
            gce.GceFirewallError,
            (
                'GCE firewall rule no longer contains any source addresses after '
                'the prefixes in source_address_exclude were removed.'
            ),
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_EXCLUDE, self.naming),
            EXP_INFO,
        )

        self.naming.GetNetAddr.assert_has_calls(
            [mock.call('CORP_EXTERNAL'), mock.call('GUEST_WIRELESS_EXTERNAL')]
        )
        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'udp'), mock.call('DNS', 'tcp')]
        )

    def testRaisesWithSourcePort(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.return_value = ['22']

        self.assertRaisesRegex(
            gce.GceFirewallError,
            'GCE firewall does not support source port restrictions.',
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER + BAD_TERM_SOURCE_PORT, self.naming),
            EXP_INFO,
        )

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

    def testRaisesWithLongTermName(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.return_value = ['22']

        self.assertRaises(
            aclgenerator.TermNameTooLongError,
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER + BAD_TERM_NAME_TOO_LONG, self.naming),
            EXP_INFO,
        )

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

    def testRaisesWithUnsupportedOption(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.return_value = ['22']

        self.assertRaisesRegex(
            gce.GceFirewallError,
            'GCE firewall does not support term options.',
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER + BAD_TERM_UNSUPPORTED_OPTION, self.naming),
            EXP_INFO,
        )

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

    def testBuildTokens(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        pol1 = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, self.naming), EXP_INFO)
        st, sst = pol1._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    def testBuildWarningTokens(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

        pol1 = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2, self.naming), EXP_INFO)
        st, sst = pol1._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    @capture.stdout
    def testDenyAction(self):
        self.naming.GetNetAddr.return_value = TEST_IPS

        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_DENY, self.naming), EXP_INFO)
        expected = json.loads(GOOD_TERM_DENY_EXPECTED)
        self.assertEqual(expected, json.loads(self._StripAclHeaders(str(acl))))
        print(acl)

    @capture.stdout
    def testIngress(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER_INGRESS + GOOD_TERM, self.naming), EXP_INFO)
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        print(acl)

    @capture.stdout
    def testEgress(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_EGRESS + GOOD_TERM_EGRESS, self.naming), EXP_INFO
        )
        self.assertIn('EGRESS', str(acl))
        self.assertIn('good-term-1-e', str(acl))
        self.assertNotIn('INGRESS', str(acl))
        print(acl)

    def testRaisesWithEgressDestinationTag(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        self.assertRaisesRegex(
            gce.GceFirewallError,
            'GCE Egress rule cannot have destination tag.',
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER_EGRESS + BAD_TERM_EGRESS, self.naming),
            EXP_INFO,
        )

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'udp'), mock.call('DNS', 'tcp')]
        )

    def testRaisesWithEgressSourceAddress(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        self.assertRaisesRegex(
            gce.GceFirewallError,
            'Egress rules cannot include "sourceRanges".',
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER_EGRESS + BAD_TERM_EGRESS_SOURCE_ADDRESS, self.naming),
            EXP_INFO,
        )

        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'udp'), mock.call('DNS', 'tcp')]
        )

    def testRaisesWithEgressSourceAndDestTag(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        self.assertRaisesRegex(
            gce.GceFirewallError,
            'GCE Egress rule cannot have destination tag.',
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER_EGRESS + BAD_TERM_EGRESS_SOURCE_DEST_TAG, self.naming),
            EXP_INFO,
        )

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'udp'), mock.call('DNS', 'tcp')]
        )

    @capture.stdout
    def testEgressTags(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_EGRESS + GOOD_TERM_EGRESS_SOURCETAG, self.naming),
            EXP_INFO,
        )

        self.assertIn('targetTags', str(acl))
        self.assertNotIn('sourceTags', str(acl))
        print(acl)

    @capture.stdout
    def testIngressTags(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_INGRESS + GOOD_TERM_INGRESS_SOURCETAG, self.naming),
            EXP_INFO,
        )

        self.assertIn('sourceTags', str(acl))
        self.assertNotIn('targetTags', str(acl))
        print(acl)

    @capture.stdout
    def testDestinationRanges(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_EGRESS + GOOD_TERM_EGRESS, self.naming), EXP_INFO
        )
        self.assertIn('destinationRanges', str(acl), str(acl))
        self.assertNotIn('sourceRanges', str(acl), str(acl))
        self.assertIn('10.2.3.4/32', str(acl), str(acl))
        print(acl)

    @capture.stdout
    def testP4TagsNotPresent(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, self.naming), EXP_INFO)
        self.assertNotIn('$Id:', str(acl))
        print(acl)

    def testRaisesConflictingDirectionAddress(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.return_value = ['22']

        self.assertRaisesRegex(
            gce.GceFirewallError,
            'Ingress rule missing required field oneof "sourceRanges" or "sourceTags"',
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER_INGRESS + GOOD_TERM_4, self.naming),
            EXP_INFO,
        )
        self.assertRaisesRegex(
            gce.GceFirewallError,
            'Egress rules cannot include "sourceRanges".',
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER_EGRESS + GOOD_TERM, self.naming),
            EXP_INFO,
        )

    @capture.stdout
    def testDefaultDenyEgressCreation(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_EGRESS + GOOD_TERM_EGRESS + DEFAULT_DENY, self.naming),
            EXP_INFO,
        )
        self.assertIn('"priority": 65534', str(acl))
        print(acl)

    @capture.stdout
    def testDefaultDenyIngressCreation(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_INGRESS + GOOD_TERM_INGRESS_SOURCETAG + DEFAULT_DENY, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('"priority": 65534', str(acl))
        print(acl)

    def testValidTermNames(self):
        for name in VALID_TERM_NAMES:
            self.naming.GetNetAddr.return_value = TEST_IPS
            self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
            pol = policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_CUSTOM_NAME % name, self.naming)
            acl = gce.GCE(pol, EXP_INFO)
            self.assertIsNotNone(str(acl))

    @capture.stdout
    def testInet(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER_INET + GOOD_TERM, self.naming), EXP_INFO)
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        print(acl)

    @capture.stdout
    def testInet6(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_TERM, self.naming), EXP_INFO)
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertIn('2001:4860:8000::5/128', str(acl))
        self.assertNotIn('10.2.3.4/32', str(acl))
        print(acl)

    @capture.stdout
    def testInetWithV6AddressesOnly(self):
        self.naming.GetNetAddr.return_value = TEST_IPV6_ONLY
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_INET + GOOD_TERM + DEFAULT_DENY, self.naming), EXP_INFO
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertNotIn('10.2.3.4/32', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        print(acl)

    @capture.stdout
    def testInet6WithV4AddressesOnly(self):
        self.naming.GetNetAddr.return_value = TEST_IPV4_ONLY
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_TERM + DEFAULT_DENY, self.naming), EXP_INFO
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        self.assertNotIn('10.2.3.4/32', str(acl))
        print(acl)

    @capture.stdout
    def testInetWithSourceTag(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_INET + GOOD_TERM_INGRESS_ADDRESS_SOURCETAG, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        self.assertIn('internal-servers', str(acl))
        print(acl)

    @capture.stdout
    def testInet6WithSourceTag(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_INET6 + GOOD_TERM_INGRESS_ADDRESS_SOURCETAG, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertIn('2001:4860:8000::5/128', str(acl))
        self.assertNotIn('10.2.3.4/32', str(acl))
        self.assertIn('internal-servers', str(acl))
        print(acl)

    @capture.stdout
    def testInetWithSourceTagAndV6Addresses(self):
        self.naming.GetNetAddr.return_value = TEST_IPV6_ONLY
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_INET + GOOD_TERM_INGRESS_ADDRESS_SOURCETAG + DEFAULT_DENY, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertNotIn('10.2.3.4/32', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        self.assertNotIn('internal-servers', str(acl))
        print(acl)

    @capture.stdout
    def testInet6WithSourceTagAndV4Addresses(self):
        self.naming.GetNetAddr.return_value = TEST_IPV4_ONLY
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_INET6 + GOOD_TERM_INGRESS_ADDRESS_SOURCETAG + DEFAULT_DENY, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        self.assertNotIn('10.2.3.4/32', str(acl))
        self.assertNotIn('internal-servers', str(acl))
        print(acl)

    @capture.stdout
    def testInet6DefaultDenyEgressCreation(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_EGRESS_INET6 + GOOD_TERM_EGRESS + DEFAULT_DENY, self.naming
            ),
            EXP_INFO,
        )
        self.assertNotIn('INGRESS', str(acl))
        self.assertIn('EGRESS', str(acl))
        self.assertIn('"priority": 65534', str(acl))
        self.assertIn('::/0', str(acl))
        self.assertNotIn('0.0.0.0/0', str(acl))
        print(acl)

    @capture.stdout
    def testInet6DefaultDenyIngressCreation(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_INET6 + GOOD_TERM_INGRESS_SOURCETAG + DEFAULT_DENY, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertIn('"priority": 65534', str(acl))
        self.assertIn('::/0', str(acl))
        self.assertNotIn('0.0.0.0/0', str(acl))
        print(acl)

    @capture.stdout
    def testIcmpInet(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER_INET + GOOD_TERM_ICMP, self.naming), EXP_INFO)
        self.assertIn('icmp', str(acl))
        self.assertNotIn('58', str(acl))
        print(acl)

    @capture.stdout
    def testIcmpv6Inet6(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_TERM_ICMPV6, self.naming), EXP_INFO
        )
        self.assertIn('58', str(acl))
        self.assertNotIn('icmp', str(acl))
        print(acl)

    @capture.stdout
    def testIcmpInet6(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_TERM_ICMP, self.naming), EXP_INFO
        )
        self.assertNotIn('icmp', str(acl))
        print(acl)

    def testIcmpv6Inet(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_INET + GOOD_TERM_ICMPV6, self.naming), EXP_INFO
        )
        self.assertNotIn('58', str(acl))

    @capture.stdout
    def testIgmpInet(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER_INET + GOOD_TERM_IGMP, self.naming), EXP_INFO)
        self.assertIn('2', str(acl))
        print(acl)

    def testIgmpInet6(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_TERM_IGMP, self.naming), EXP_INFO
        )
        self.assertNotIn('2', str(acl))

    def testPortsCountExceededError(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.return_value = list(
            str(i) for i in range(1024, 1024 + (gce.Term._TERM_PORTS_LIMIT) * 3, 2)
        )
        self.assertRaisesRegex(
            gce.GceFirewallError,
            'GCE firewall rule exceeded number of ports per rule: ' + 'bad-term-ports-count',
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER_INET + BAD_TERM_PORTS_COUNT, self.naming),
            EXP_INFO,
        )
        self.naming.GetServiceByProto.assert_called_once_with('SSH', 'tcp')

    def testSourceTagCountExceededError(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.assertRaisesRegex(
            gce.GceFirewallError,
            'GCE firewall rule exceeded number of source tags per rule: '
            + 'bad-term-source-tags-count',
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER_INET + BAD_TERM_SOURCE_TAGS_COUNT, self.naming),
            EXP_INFO,
        )

    def testTargetTagCountExceededError(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.assertRaisesRegex(
            gce.GceFirewallError,
            'GCE firewall rule exceeded number of target tags per rule: '
            + 'bad-term-target-tags-count',
            gce.GCE,
            policy.ParsePolicy(GOOD_HEADER_INET + BAD_TERM_TARGET_TAGS_COUNT, self.naming),
            EXP_INFO,
        )

    @capture.stdout
    def testMixed(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM, self.naming), EXP_INFO)
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertIn('2001:4860:8000::5/128', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        print(acl)

    @capture.stdout
    def testInetIsDefault(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM, self.naming), EXP_INFO)
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        print(acl)

    @capture.stdout
    def testMixedWithV6AddressesOnly(self):
        self.naming.GetNetAddr.return_value = TEST_IPV6_ONLY
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM + DEFAULT_DENY, self.naming), EXP_INFO
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertNotIn('10.2.3.4/32', str(acl))
        self.assertIn('2001:4860:8000::5/128', str(acl))
        print(acl)

    @capture.stdout
    def testMixedWithV4AddressesOnly(self):
        self.naming.GetNetAddr.return_value = TEST_IPV4_ONLY
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM + DEFAULT_DENY, self.naming), EXP_INFO
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        print(acl)

    @capture.stdout
    def testMixedIsSeparateRules(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM + DEFAULT_DENY, self.naming), EXP_INFO
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertIn('2001:4860:8000::5/128', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        self.assertIn('good-term-1', str(acl))
        self.assertIn(gcp.GetIpv6TermName('good-term-1'), str(acl))
        print(acl)

    @capture.stdout
    def testMixedWithSourceTag(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_MIXED + GOOD_TERM_INGRESS_ADDRESS_SOURCETAG, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        self.assertIn('2001:4860:8000::5/128', str(acl))
        self.assertIn('internal-servers', str(acl))
        self.assertIn(gcp.GetIpv6TermName('good-term-1'), str(acl))
        print(acl)

    @capture.stdout
    def testMixedWithSourceTagOnly(self):
        self.naming.GetNetAddr.return_value = []
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_MIXED + GOOD_TERM_INGRESS_ADDRESS_SOURCETAG, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertNotIn('10.2.3.4/32', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        self.assertIn('internal-servers', str(acl))
        self.assertNotIn(gcp.GetIpv6TermName('good-term-1'), str(acl))
        print(acl)

    @capture.stdout
    def testMixedWithSourceTagAndV6Addresses(self):
        self.naming.GetNetAddr.return_value = TEST_IPV6_ONLY
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_MIXED + GOOD_TERM_INGRESS_ADDRESS_SOURCETAG + DEFAULT_DENY, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertNotIn('10.2.3.4/32', str(acl))
        self.assertIn('2001:4860:8000::5/128', str(acl))
        self.assertIn('internal-servers', str(acl))
        self.assertIn(gcp.GetIpv6TermName('good-term-1'), str(acl))
        print(acl)

    @capture.stdout
    def testMixedWithSourceTagAndV4Addresses(self):
        self.naming.GetNetAddr.return_value = TEST_IPV4_ONLY
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_MIXED + GOOD_TERM_INGRESS_ADDRESS_SOURCETAG + DEFAULT_DENY, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        self.assertIn('internal-servers', str(acl))
        self.assertNotIn(gcp.GetIpv6TermName('good-term-1'), str(acl))
        print(acl)

    @capture.stdout
    def testMixedWithEgressSourceTag(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_EGRESS_MIXED + GOOD_TERM_EGRESS_SOURCETAG, self.naming),
            EXP_INFO,
        )
        self.assertNotIn('INGRESS', str(acl))
        self.assertIn('EGRESS', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        self.assertIn('2001:4860:8000::5/128', str(acl))
        self.assertIn('dns-servers', str(acl))
        self.assertIn(gcp.GetIpv6TermName('good-term-1-e'), str(acl))
        print(acl)

    @capture.stdout
    def testMixedDefaultDenyEgressCreation(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_EGRESS_MIXED + GOOD_TERM_EGRESS + DEFAULT_DENY, self.naming
            ),
            EXP_INFO,
        )
        self.assertNotIn('INGRESS', str(acl))
        self.assertIn('EGRESS', str(acl))
        self.assertIn('"priority": 65534', str(acl))
        self.assertIn('default-deny-e', str(acl))
        self.assertIn(gcp.GetIpv6TermName('default-deny-e'), str(acl))
        self.assertIn('::/0', str(acl))
        self.assertIn('0.0.0.0/0', str(acl))
        print(acl)

    @capture.stdout
    def testMixedDefaultDenyIngressCreation(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_MIXED + GOOD_TERM_INGRESS_SOURCETAG + DEFAULT_DENY, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertIn('"priority": 65534', str(acl))
        self.assertIn('default-deny', str(acl))
        self.assertIn(gcp.GetIpv6TermName('default-deny'), str(acl))
        self.assertIn('::/0', str(acl))
        self.assertIn('0.0.0.0/0', str(acl))
        print(acl)

    @capture.stdout
    def testIcmpMixed(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_ICMP, self.naming), EXP_INFO
        )
        self.assertIn('icmp', str(acl))
        self.assertNotIn('58', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        self.assertNotIn(gcp.GetIpv6TermName('good-term-1'), str(acl))
        print(acl)

    @capture.stdout
    def testIcmpv6Mixed(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_ICMPV6, self.naming), EXP_INFO
        )
        self.assertIn('58', str(acl))
        self.assertNotIn('icmp', str(acl))
        self.assertNotIn('10.2.3.4/32', str(acl))
        self.assertIn('2001:4860:8000::5/128', str(acl))
        self.assertIn(gcp.GetIpv6TermName('good-term-pingv6'), str(acl))
        print(acl)

    @capture.stdout
    def testIgmpMixed(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_IGMP, self.naming), EXP_INFO
        )
        self.assertIn('2', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        self.assertNotIn(gcp.GetIpv6TermName('good-term-pingv6'), str(acl))
        print(acl)

    @capture.stdout
    def testNoProtocol(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_NO_PROTOCOL, self.naming), EXP_INFO
        )
        self.assertIn('all', str(acl))
        print(acl)

    @capture.stdout
    def testPlatformExclude(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(
                GOOD_HEADER_INET + GOOD_PLATFORM_EXCLUDE_TERM + GOOD_TERM, self.naming
            ),
            EXP_INFO,
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        self.assertIn('good-term-1', str(acl))
        self.assertNotIn('good-platform-exclude-term', str(acl))
        print(acl)

    @capture.stdout
    def testPlatform(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        acl = gce.GCE(
            policy.ParsePolicy(GOOD_HEADER_INET + GOOD_PLATFORM_TERM, self.naming), EXP_INFO
        )
        self.assertIn('INGRESS', str(acl))
        self.assertNotIn('EGRESS', str(acl))
        self.assertIn('10.2.3.4/32', str(acl))
        self.assertNotIn('2001:4860:8000::5/128', str(acl))
        self.assertIn('good-platform-term', str(acl))
        print(acl)

    @capture.stdout
    def testTermOwners(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

        acl = gce.GCE(policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_OWNERS, self.naming), EXP_INFO)
        rendered_acl = json.loads(str(acl))[0]
        self.assertEqual(rendered_acl['description'], 'DNS access from corp. Owner: test-owner')
        print(acl)

    def testMaxAttributeExceeded(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        self.assertRaises(
            gce.ExceededAttributeCountError,
            gce.GCE,
            policy.ParsePolicy(
                GOOD_HEADER_MAX_ATTRIBUTE_COUNT + GOOD_TERM + DEFAULT_DENY, self.naming
            ),
            EXP_INFO,
        )

    @capture.stdout
    def testMaxAttribute(self):
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.2.3.4/32')]
        pol = policy.ParsePolicy(GOOD_HEADER_MAX_ATTRIBUTE_COUNT + GOOD_TERM_5, self.naming)
        acl = gce.GCE(pol, EXP_INFO)
        self.assertIsNotNone(str(acl))
        print(acl)

    @parameterized.named_parameters(
        (
            '1 ip, 2 ports',
            {
                'sourceRanges': ['10.128.0.0/10'],
                'allowed': [
                    {'ports': ['22'], 'IPProtocol': 'tcp'},
                    {'ports': ['53'], 'IPProtocol': 'udp'},
                ],
            },
            5,
        ),
        (
            '1 ip, 2 ports, 1 target tag',
            {
                'sourceRanges': ['10.128.0.0/10'],
                'allowed': [
                    {'ports': ['22'], 'IPProtocol': 'tcp'},
                    {'ports': ['53'], 'IPProtocol': 'udp'},
                ],
                'targetTags': ['dns-servers'],
            },
            6,
        ),
        (
            '2 ips, 2 ports, 1 target tag',
            {
                'sourceRanges': ['10.128.0.0/10', '192.168.1.1/24'],
                'allowed': [
                    {'ports': ['22'], 'IPProtocol': 'tcp'},
                    {'ports': ['53'], 'IPProtocol': 'udp'},
                ],
                'targetTags': ['dns-servers'],
            },
            7,
        ),
        (
            '2 ips, 2 ports',
            {
                'sourceRanges': ['10.128.0.0/10', '192.168.1.1/24'],
                'allowed': [
                    {'ports': ['22'], 'IPProtocol': 'tcp'},
                    {'ports': ['53'], 'IPProtocol': 'udp'},
                ],
            },
            6,
        ),
        (
            '2 ips, 2 protocols',
            {
                'sourceRanges': ['10.128.0.0/10', '192.168.1.1/24'],
                'allowed': [{'IPProtocol': 'tcp'}, {'IPProtocol': 'udp'}],
            },
            4,
        ),
        (
            '1 ip, 2 protocols, 1 source tag',
            {
                'sourceRanges': ['10.128.0.0/10'],
                'allowed': [{'IPProtocol': 'tcp'}, {'IPProtocol': 'udp'}],
                'sourceTags': ['dns-servers'],
            },
            4,
        ),
        (
            '2 ips, 1 protocol',
            {
                'sourceRanges': ['10.128.0.0/10', '192.168.1.1/24'],
                'allowed': [{'IPProtocol': 'icmp'}],
            },
            3,
        ),
        (
            '1 ip, 2 protocols, 1 service account',
            {
                'sourceRanges': ['10.128.0.0/10'],
                'allowed': [{'IPProtocol': 'tcp'}, {'IPProtocol': 'udp'}],
                'targetServiceAccount': ['test@system.gserviceaccount.com'],
            },
            4,
        ),
    )
    def testGetAttributeCount(self, dict_term, expected):
        self.assertEqual(gce.GetAttributeCount(dict_term), expected)


YAML_GOOD_HEADER = """
filters:
- header:
    comment: The general policy comment.
    targets:
      gce: global/networks/default
  terms:
"""

YAML_GOOD_HEADER_INGRESS = """
filters:
- header:
    comment: The general policy comment.
    targets:
      gce: INGRESS
  terms:
"""

YAML_GOOD_HEADER_EGRESS = """
filters:
- header:
    comment: The general policy comment.
    targets:
      gce: EGRESS
  terms:
"""

YAML_GOOD_HEADER_NO_NETWORK = """
filters:
- header:
    comment: The general policy comment.
    targets:
      gce:
  terms:
"""

YAML_GOOD_HEADER_MAX_ATTRIBUTE_COUNT = """
filters:
- header:
    comment: The general policy comment.
    targets:
      gce: INGRESS global/networks/default 2
  terms:
"""

YAML_GOOD_HEADER_INET = """
filters:
- header:
    comment: The general policy comment.
    targets:
      gce: INGRESS inet
  terms:
"""

YAML_GOOD_HEADER_EGRESS_INET = """
filters:
- header:
    comment: The general policy comment.
    targets:
      gce: INGRESS inet
  terms:
"""

YAML_GOOD_HEADER_INET6 = """
filters:
- header:
    comment: The general policy comment.
    targets:
      gce: INGRESS inet6
  terms:
"""

YAML_GOOD_HEADER_EGRESS_INET6 = """
filters:
- header:
    comment: The general policy comment.
    targets:
      gce: EGRESS inet6
  terms:
"""

YAML_GOOD_HEADER_MIXED = """
filters:
- header:
    comment: The general policy comment.
    targets:
      gce: INGRESS mixed
  terms:
"""

YAML_GOOD_HEADER_EGRESS_MIXED = """
filters:
- header:
    comment: The general policy comment.
    targets:
      gce: EGRESS mixed
  terms:
"""

YAML_GOOD_TERM = """
  - name: good-term-1
    comment: DNS access from corp.
    source-address: CORP_EXTERNAL
    destination-tag: dns-servers
    destination-port: DNS
    protocol: udp tcp
    action: accept
"""

YAML_GOOD_TERM_2 = """
  - name: good-term-2
    comment: DNS access from corp.
    source-address: CORP_EXTERNAL
    destination-tag: dns-servers
    destination-port: DNS
    protocol: udp tcp
    policer: batman
    action: accept
"""

YAML_GOOD_TERM_3 = """
  - name: good-term-1
    comment: DNS access from corp.
    source-address: CORP_EXTERNAL
    destination-tag: dns-servers
    destination-port: DNS
    protocol: udp tcp
    priority: 1
    action: accept
"""

YAML_GOOD_TERM_EXCLUDE = """
  - name: good-term-1
    comment: DNS access from corp.
    source-address: CORP_EXTERNAL
    source-exclude: GUEST_WIRELESS_EXTERNAL
    destination-tag: dns-servers
    destination-port: DNS
    protocol: udp tcp
    action: accept
"""

YAML_GOOD_TERM_4 = """
  - name: good-term-1
    comment: DNS access from corp.
    destination-address: CORP_EXTERNAL
    destination-tag: dns-servers
    destination-port: DNS
    protocol: udp tcp
    action: accept
"""
YAML_GOOD_TERM_5 = """
  - name: good-term-5
    comment: ICMP from IP.
    source-address: CORP_EXTERNAL
    protocol: icmp
    action: accept
"""

YAML_GOOD_TERM_EGRESS = """
  - name: good-term-1
    comment: DNS access from corp.
    destination-address: CORP_EXTERNAL
    destination-port: DNS
    protocol: udp tcp
    action: accept
"""

YAML_GOOD_TERM_EGRESS_SOURCETAG = """
  - name: good-term-1
    comment: DNS access from corp.
    destination-address: CORP_EXTERNAL
    source-tag: dns-servers
    destination-port: DNS
    protocol: udp tcp
    action: accept
"""

YAML_GOOD_TERM_INGRESS_SOURCETAG = """
  - name: good-term-1
    comment: Allow all GCE network internal traffic.
    source-tag: internal-servers
    protocol: udp tcp
    action: accept
"""

YAML_GOOD_TERM_INGRESS_ADDRESS_SOURCETAG = """
  - name: good-term-1
    comment: Allow all GCE network internal traffic.
    source-tag: internal-servers
    source-address: CORP_EXTERNAL
    protocol: udp tcp
    action: accept
"""

YAML_GOOD_PLATFORM_EXCLUDE_TERM = """
  - name: good-platform-exclude-term
    comment: DNS access from corp.
    destination-tag: dns-servers
    protocol: udp tcp
    action: accept
    platform-exclude: gce
"""

YAML_GOOD_PLATFORM_TERM = """
  - name: good-platform-term
    comment: DNS access from corp.
    source-address: CORP_EXTERNAL
    destination-tag: dns-servers
    destination-port: DNS
    protocol: udp tcp
    action: accept
    platform: gce
"""


YAML_GOOD_TERM_EXPIRED = """
  - name: good-term-expired
    comment: Management access from corp.
    expiration: 2001-01-01
    source-address: CORP_EXTERNAL
    destination-tag: ssh-servers
    destination-port: SSH
    protocol: tcp
    action: accept
"""

YAML_GOOD_TERM_LOGGING = """
  - name: good-term-logging
    comment: DNS access from corp.
    source-address: CORP_EXTERNAL
    destination-tag: dns-servers
    destination-port: DNS
    protocol: udp tcp
    action: accept
    logging: true
"""

YAML_GOOD_TERM_CUSTOM_NAME = """
  - name: %s
    comment: DNS access from corp.
    source-address: CORP_EXTERNAL
    destination-tag: dns-servers
    destination-port: DNS
    protocol: udp tcp
    action: accept
"""

YAML_GOOD_TERM_OWNERS = """
  - name: good-term-owners
    comment: DNS access from corp.
    source-address: CORP_EXTERNAL
    destination-tag: dns-servers
    destination-port: DNS
    protocol: udp tcp
    owner: test-owner
    action: accept
"""

YAML_GOOD_TERM_ICMP = """
  - name: good-term-ping
    comment: Good term.
    source-address: CORP_EXTERNAL
    protocol: icmp
    action: accept
"""

YAML_GOOD_TERM_ICMPV6 = """
  - name: good-term-pingv6
    comment: Good term.
    source-address: CORP_EXTERNAL
    protocol: icmpv6
    action: accept
"""

YAML_GOOD_TERM_IGMP = """
  - name: good-term-igmp
    comment: Good term.
    source-address: CORP_EXTERNAL
    protocol: igmp
    action: accept
"""

YAML_GOOD_TERM_NO_PROTOCOL = """
  - name: good-term-no-protocol
    comment: Good term.
    source-address: CORP_EXTERNAL
    action: accept
"""

YAML_BAD_TERM_NO_SOURCE = """
  - name: bad-term-no-source
    comment: Management access from corp.
    destination-tag: ssh-servers
    destination-port: SSH
    protocol: tcp
    action: accept
"""

YAML_BAD_TERM_SOURCE_EXCLUDE_ONLY = """
  - name: bad-term-source-ex-only
    comment: Management access from corp.
    destination-port: SSH
    source-tag: ssh-bastion
    source-exclude: GUEST_WIRELESS_EXTERNAL
    protocol: tcp
    action: accept
"""

YAML_BAD_TERM_SOURCE_PORT = """
  - name: bad-term-source-port
    comment: Management access from corp.
    source-address: CORP_EXTERNAL
    source-port: SSH
    destination-tag: ssh-servers
    protocol: tcp
    action: accept
"""

YAML_BAD_TERM_NAME_TOO_LONG = """
  - name: good-term-whith-a-name-which-is-way-way-too-long-for-gce-to-accept
    comment: Management access from corp.
    source-address: CORP_EXTERNAL
    destination-port: SSH
    protocol: tcp
    action: accept
"""

YAML_BAD_TERM_UNSUPPORTED_PORT = """
  - name: good-term-unsupported-port
    comment: Management access from corp.
    source-address: CORP_EXTERNAL
    destination-port: SSH
    protocol: tcp icmp
    action: accept
"""

YAML_BAD_TERM_UNSUPPORTED_OPTION = """
  - name: bad-term-unsupported-option
    comment: Management access from corp.
    source-address: CORP_EXTERNAL
    destination-port: SSH
    protocol: tcp
    action: accept
    option: tcp-initial
"""

YAML_BAD_TERM_EGRESS = """
  - name: bad-term-dest-tag
    comment: DNS access from corp.
    destination-address: CORP_EXTERNAL
    destination-tag: dns-servers
    destination-port: DNS
    protocol: udp tcp
    action: accept
"""

YAML_BAD_TERM_EGRESS_SOURCE_ADDRESS = """
  - name: bad-term-source-address
    comment: DNS access from corp.
    destination-address: CORP_EXTERNAL
    source-address: CORP_EXTERNAL
    destination-port: DNS
    protocol: udp tcp
    action: accept
"""

YAML_BAD_TERM_EGRESS_SOURCE_DEST_TAG = """
  - name: bad-term-source-dest-tag
    comment: DNS access from corp.
    destination-address: CORP_EXTERNAL
    destination-tag: dns-servers
    source-tag: ssh-bastion
    destination-port: DNS
    protocol: udp tcp
    action: accept
"""
YAML_BAD_TERM_PORTS_COUNT = """
  - name: bad-term-ports-count
    comment: This term has way too many ports.
    source-address: CORP_EXTERNAL
    source-tag: ssh-bastion
    destination-port: SSH
    protocol: tcp
    action: accept
"""

YAML_BAD_TERM_SOURCE_TAGS_COUNT = """
  - name: bad-term-source-tags-count
    comment: This term has way too many source tags.
    protocol: tcp
    action: accept
    source-tag: {many_source_tags}
""".format(
    many_source_tags=SAMPLE_TAG * (gce.Term._TERM_SOURCE_TAGS_LIMIT + 1)
)

YAML_BAD_TERM_TARGET_TAGS_COUNT = """
  - name: bad-term-target-tags-count
    comment: This term has way too many target tags.
    source-address: CORP_EXTERNAL
    protocol: tcp
    action: accept
    destination-tag: {many_target_tags}
""".format(
    many_target_tags=SAMPLE_TAG * (gce.Term._TERM_TARGET_TAGS_LIMIT + 1)
)

YAML_DEFAULT_DENY = """
  - name: default-deny
    comment: default_deny.
    action: deny
"""

YAML_GOOD_TERM_DENY = """
  - name: good-term-1
    comment: DNS access from corp.
    source-address: CORP_EXTERNAL
    destination-tag: dns-servers
    protocol: udp tcp
    action: deny
"""


def _YamlParsePolicy(
    data, definitions=None, optimize=True, base_dir='', shade_check=False, filename=''
):
    """Test shim for patching policy.ParsePolicy with yaml.ParsePolicy."""

    # Erase any subsequent copies of "filters:". Multi-filter tests must not
    # contain copies of the "filters:" key
    data = "filters:" + ''.join(data.split("filters:\n"))

    return yaml_frontend.ParsePolicy(
        data,
        filename=filename,
        base_dir=base_dir,
        definitions=definitions,
        optimize=optimize,
        shade_check=shade_check,
    )


class GCETestYAMLTest(GCETest):
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
            'gce_test',
            GOOD_HEADER=YAML_GOOD_HEADER,
            GOOD_HEADER_INGRESS=YAML_GOOD_HEADER_INGRESS,
            GOOD_HEADER_EGRESS=YAML_GOOD_HEADER_EGRESS,
            GOOD_HEADER_NO_NETWORK=YAML_GOOD_HEADER_NO_NETWORK,
            GOOD_HEADER_MAX_ATTRIBUTE_COUNT=YAML_GOOD_HEADER_MAX_ATTRIBUTE_COUNT,
            GOOD_HEADER_INET=YAML_GOOD_HEADER_INET,
            GOOD_HEADER_EGRESS_INET=YAML_GOOD_HEADER_EGRESS_INET,
            GOOD_HEADER_INET6=YAML_GOOD_HEADER_INET6,
            GOOD_HEADER_EGRESS_INET6=YAML_GOOD_HEADER_EGRESS_INET6,
            GOOD_HEADER_MIXED=YAML_GOOD_HEADER_MIXED,
            GOOD_HEADER_EGRESS_MIXED=YAML_GOOD_HEADER_EGRESS_MIXED,
            GOOD_TERM=YAML_GOOD_TERM,
            GOOD_TERM_2=YAML_GOOD_TERM_2,
            GOOD_TERM_3=YAML_GOOD_TERM_3,
            GOOD_TERM_EXCLUDE=YAML_GOOD_TERM_EXCLUDE,
            GOOD_TERM_4=YAML_GOOD_TERM_4,
            GOOD_TERM_5=YAML_GOOD_TERM_5,
            GOOD_TERM_EGRESS=YAML_GOOD_TERM_EGRESS,
            GOOD_TERM_EGRESS_SOURCETAG=YAML_GOOD_TERM_EGRESS_SOURCETAG,
            GOOD_TERM_INGRESS_SOURCETAG=YAML_GOOD_TERM_INGRESS_SOURCETAG,
            GOOD_TERM_INGRESS_ADDRESS_SOURCETAG=YAML_GOOD_TERM_INGRESS_ADDRESS_SOURCETAG,
            GOOD_PLATFORM_EXCLUDE_TERM=YAML_GOOD_PLATFORM_EXCLUDE_TERM,
            GOOD_PLATFORM_TERM=YAML_GOOD_PLATFORM_TERM,
            GOOD_TERM_EXPIRED=YAML_GOOD_TERM_EXPIRED,
            GOOD_TERM_LOGGING=YAML_GOOD_TERM_LOGGING,
            GOOD_TERM_CUSTOM_NAME=YAML_GOOD_TERM_CUSTOM_NAME,
            GOOD_TERM_OWNERS=YAML_GOOD_TERM_OWNERS,
            GOOD_TERM_ICMP=YAML_GOOD_TERM_ICMP,
            GOOD_TERM_ICMPV6=YAML_GOOD_TERM_ICMPV6,
            GOOD_TERM_IGMP=YAML_GOOD_TERM_IGMP,
            GOOD_TERM_NO_PROTOCOL=YAML_GOOD_TERM_NO_PROTOCOL,
            BAD_TERM_NO_SOURCE=YAML_BAD_TERM_NO_SOURCE,
            BAD_TERM_SOURCE_EXCLUDE_ONLY=YAML_BAD_TERM_SOURCE_EXCLUDE_ONLY,
            BAD_TERM_SOURCE_PORT=YAML_BAD_TERM_SOURCE_PORT,
            BAD_TERM_NAME_TOO_LONG=YAML_BAD_TERM_NAME_TOO_LONG,
            BAD_TERM_UNSUPPORTED_PORT=YAML_BAD_TERM_UNSUPPORTED_PORT,
            BAD_TERM_UNSUPPORTED_OPTION=YAML_BAD_TERM_UNSUPPORTED_OPTION,
            BAD_TERM_EGRESS=YAML_BAD_TERM_EGRESS,
            BAD_TERM_EGRESS_SOURCE_ADDRESS=YAML_BAD_TERM_EGRESS_SOURCE_ADDRESS,
            BAD_TERM_EGRESS_SOURCE_DEST_TAG=YAML_BAD_TERM_EGRESS_SOURCE_DEST_TAG,
            BAD_TERM_PORTS_COUNT=YAML_BAD_TERM_PORTS_COUNT,
            BAD_TERM_SOURCE_TAGS_COUNT=YAML_BAD_TERM_SOURCE_TAGS_COUNT,
            BAD_TERM_TARGET_TAGS_COUNT=YAML_BAD_TERM_TARGET_TAGS_COUNT,
            DEFAULT_DENY=YAML_DEFAULT_DENY,
            GOOD_TERM_DENY=YAML_GOOD_TERM_DENY,
        )


if __name__ == '__main__':
    absltest.main()
