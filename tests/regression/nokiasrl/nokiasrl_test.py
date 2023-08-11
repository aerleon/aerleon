# Copyright 2023 Nokia All Rights Reserved.
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

"""Unittest for SR Linux rendering module."""

import json
from unittest import mock

from absl.testing import absltest

from aerleon.lib import nacaddr, naming, nokiasrl, policy
from tests.regression_utils import capture

GOOD_HEADER = """
header {
  comment:: "The general policy comment."
  target:: nokiasrl good-name-v4 inet
}
"""

GOOD_SADDR = """
term good-term-1 {
  comment:: "Allow source address."
  source-address:: CORP_EXTERNAL
  action:: accept
}
"""

GOOD_DADDR = """
term good-term-1 {
  comment:: "Allow destination address."
  destination-address:: CORP_EXTERNAL
  action:: accept
}
"""

GOOD_SPORT = """
term good-term-1 {
  comment:: "Allow TCP 53 source."
  source-port:: DNS
  protocol:: tcp
  action:: accept
}
"""

GOOD_DPORT = """
term good-term-1 {
  comment:: "Allow TCP 53 dest."
  destination-port:: DNS
  protocol:: tcp
  action:: accept
}
"""

GOOD_MULTI_PROTO_DPORT = """
term good-term-1 {
  comment:: "Allow TCP & UDP high."
  source-port:: HIGH_PORTS
  destination-port:: HIGH_PORTS
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_EVERYTHING = """
term good-term-1 {
  comment:: "Deny TCP & UDP 53 with saddr/daddr and logging."
  destination-address:: CORP_EXTERNAL
  source-address:: CORP_EXTERNAL
  destination-port:: DNS
  protocol:: udp tcp
  action:: deny
  logging:: True
}
"""

GOOD_JSON_SADDR = """
[
{
    "ipv4-filter": {
      "description": "The general policy comment.",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "Allow source address.",
          "match": {
            "source-ip": {
              "prefix": "10.2.3.4/32"
            }
          },
          "sequence-id": 5
        }
      ]
    }
}
]
"""

GOOD_JSON_V6_SADDR = """
[
{
    "ipv6-filter": {
      "description": "The general policy comment.",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "Allow source address.",
          "match": {
            "source-ip": {
              "prefix": "2001:4860:8000::5/128"
            }
          },
          "sequence-id": 5
        }
      ]
    }
}
]
"""

GOOD_JSON_DADDR = """
[
{
    "ipv4-filter": {
      "description": "The general policy comment.",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "Allow destination address.",
          "match": {
            "destination-ip": {
              "prefix": "10.2.3.4/32"
            }
          },
          "sequence-id": 5
        }
      ]
    }
}
]
"""

GOOD_JSON_V6_DADDR = """
[
{
    "ipv6-filter": {
      "description": "The general policy comment.",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "Allow destination address.",
          "match": {
            "destination-ip": {
              "prefix": "2001:4860:8000::5/128"
            }
          },
          "sequence-id": 5
        }
      ]
    }
}
]
"""

GOOD_JSON_SPORT = """
[
{
    "ipv4-filter": {
      "description": "The general policy comment.",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "Allow TCP 53 source.",
          "match": {
            "protocol": 6,
            "source-port": { "value": 53 }
          },
          "sequence-id": 5
        }
      ]
    }
}
]
"""

GOOD_JSON_DPORT = """
[
{
    "ipv4-filter": {
      "description": "The general policy comment.",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "Allow TCP 53 dest.",
          "match": {
            "protocol": 6,
            "destination-port": { "value": 53 }
          },
          "sequence-id": 5
        }
      ]
    }
}
]
"""

GOOD_JSON_MULTI_PROTO_DPORT = """
[
{
    "ipv4-filter": {
      "description": "The general policy comment.",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "Allow TCP & UDP high.",
          "match": {
            "protocol": 17,
            "source-port": { "range": { "start": 1024, "end": 65535 } },
            "destination-port": { "range": { "start": 1024, "end": 65535 } }
          },
          "sequence-id": 5
        },
        {
          "action": {
            "accept": {}
          },
          "description": "Allow TCP & UDP high.",
          "match": {
            "protocol": 6,
            "source-port": { "range": { "start": 1024, "end": 65535 } },
            "destination-port": { "range": { "start": 1024, "end": 65535 } }
          },
          "sequence-id": 10
        }
      ]
    }
}
]
"""

GOOD_JSON_EVERYTHING = """
[
{
    "ipv4-filter": {
      "description": "The general policy comment.",
      "entry": [
        {
          "action": {
            "drop": {
             "log": true
            }
          },
          "description": "Deny TCP & UDP 53 with saddr/daddr and logging.",
          "match": {
            "protocol": 17,
            "destination-ip": { "prefix": "10.2.3.4/32" },
            "destination-port": { "value": 53 },
            "source-ip": { "prefix": "10.2.3.4/32" }
          },
          "sequence-id": 5
        },
        {
          "action": {
            "drop": {
             "log": true
            }
          },
          "description": "Deny TCP & UDP 53 with saddr/daddr and logging.",
          "match": {
            "protocol": 6,
            "destination-ip": { "prefix": "10.2.3.4/32" },
            "destination-port": { "value": 53 },
            "source-ip": { "prefix": "10.2.3.4/32" }
          },
          "sequence-id": 10
        }
      ]
    }
}
]
"""

BAD_TERM_1 = """
term bad-term-1 {
  protocol:: tcp udp
  source-port:: DNS
  option:: tcp-established
  action:: accept
}
"""
BAD_TERM_2 = """
term bad-term-2 {
  protocol:: icmp
  option:: tcp-established
  action:: accept
}
"""
GOOD_ESTABLISHED_TERM_1 = """
term established-term-1 {
  protocol:: tcp
  source-port:: DNS
  option:: established
  action:: accept
}
"""
GOOD_TCP_ESTABLISHED_TERM_1 = """
term tcp-established-term-1 {
  protocol:: tcp
  source-port:: DNS
  option:: tcp-established
  action:: accept
}
"""
GOOD_UDP_ESTABLISHED_TERM_1 = """
term udp-established-term-1 {
  protocol:: udp
  source-port:: DNS
  option:: established
  action:: accept
}
"""

GOOD_HEADER_INET6 = """
header {
  comment:: "The general policy comment."
  target:: nokiasrl good-name-v6 inet6
}
"""

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2

TEST_IPS = [nacaddr.IP('10.2.3.4/32'), nacaddr.IP('2001:4860:8000::5/128')]


_TERM_SOURCE_TAGS_LIMIT = 30
_TERM_TARGET_TAGS_LIMIT = 70
_TERM_PORTS_LIMIT = 256


class NokiaSRLTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = mock.create_autospec(naming.Naming)

    @capture.stdout
    def testSaddr(self):
        self.naming.GetNetAddr.return_value = TEST_IPS

        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_SADDR, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_SADDR)
        self.assertEqual(expected, json.loads(str(acl)))

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        print(acl)

    @capture.stdout
    def testDaddr(self):
        self.naming.GetNetAddr.return_value = TEST_IPS

        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_DADDR, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_DADDR)
        self.assertEqual(expected, json.loads(str(acl)))

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        print(acl)

    @capture.stdout
    def testSport(self):
        self.naming.GetNetAddr.return_value = TEST_IPS
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_SPORT, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_SPORT)
        self.assertEqual(expected, json.loads(str(acl)))

        self.naming.GetServiceByProto.assert_has_calls([mock.call('DNS', 'tcp')])
        print(acl)

    # TODO v6 s/dport
    @capture.stdout
    def testDport(self):
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]

        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_DPORT, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_DPORT)
        self.assertEqual(expected, json.loads(str(acl)))

        self.naming.GetServiceByProto.assert_has_calls([mock.call('DNS', 'tcp')])
        print(acl)

    @capture.stdout
    def testMultiDport(self):
        self.naming.GetServiceByProto.return_value = ['1024-65535']

        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_MULTI_PROTO_DPORT, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_MULTI_PROTO_DPORT)
        self.assertEqual(expected, json.loads(str(acl)))

        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('HIGH_PORTS', 'tcp'), mock.call('HIGH_PORTS', 'udp')], any_order=True
        )
        print(acl)

    @capture.stdout
    def testEverything(self):
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        self.naming.GetNetAddr.return_value = TEST_IPS

        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_EVERYTHING, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_EVERYTHING)
        self.assertEqual(expected, json.loads(str(acl)))

        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'udp'), mock.call('DNS', 'tcp')]
        )
        print(acl)

    @capture.stdout
    def testV6Saddr(self):
        self.naming.GetNetAddr.return_value = TEST_IPS

        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_SADDR, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_V6_SADDR)
        self.assertEqual(expected, json.loads(str(acl)))

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        print(acl)

    @capture.stdout
    def testV6Daddr(self):
        self.naming.GetNetAddr.return_value = TEST_IPS

        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_DADDR, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_V6_DADDR)
        self.assertEqual(expected, json.loads(str(acl)))

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        print(acl)

    @capture.stdout
    def testEstablished(self):
        self.naming.GetServiceByProto.return_value = ['53']

        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_ESTABLISHED_TERM_1, self.naming), EXP_INFO
        )
        output = str(acl)
        self.assertIn('"ack|rst"', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')
        print(output)

    @capture.stdout
    def testTcpEstablished(self):
        self.naming.GetServiceByProto.return_value = ['53']

        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TCP_ESTABLISHED_TERM_1, self.naming), EXP_INFO
        )
        output = str(acl)
        self.assertIn('"ack|rst"', output, output)

        self.naming.GetServiceByProto.assert_called_once_with('DNS', 'tcp')
        print(output)

    @capture.stdout
    def testUdpEstablishedv6(self):
        self.naming.GetServiceByProto.return_value = ['53']

        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_UDP_ESTABLISHED_TERM_1, self.naming),
            EXP_INFO,
        )
        output = str(acl)
        self.naming.GetServiceByProto.assert_called_once_with('DNS', 'udp')
        print(output)

    def testNonTcpWithTcpEstablished(self):
        self.naming.GetServiceByProto.return_value = ['53']

        acl = policy.ParsePolicy(GOOD_HEADER + BAD_TERM_1, self.naming)
        with self.assertRaises(nokiasrl.TcpEstablishedWithNonTcpError):
            _ = nokiasrl.NokiaSRLinux(acl, EXP_INFO)

        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'tcp'), mock.call('DNS', 'udp')]
        )

    def testEstablishedNonTcpUdp(self):
        self.naming.GetServiceByProto.return_value = ['53']

        acl = policy.ParsePolicy(GOOD_HEADER + BAD_TERM_2, self.naming)
        with self.assertRaises(nokiasrl.TcpEstablishedWithNonTcpError):
            _ = nokiasrl.NokiaSRLinux(acl, EXP_INFO)


#
# TODO:
# - Fragments
# - TCP flags
# - ICMP type codes
#

if __name__ == '__main__':
    absltest.main()
