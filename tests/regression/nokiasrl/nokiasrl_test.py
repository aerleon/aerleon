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

from absl.testing import absltest

from aerleon.lib import naming, nokiasrl, policy
from tests.regression_utils import capture

GOOD_HEADER = """
header {
  comment:: "The general policy comment."
  target:: nokiasrl good-name-v4 inet r24.3
}
"""

GOOD_HEADER_MIXED = """
header {
  comment:: "GOOD_HEADER_MIXED comment."
  target:: nokiasrl good-name-mixed mixed r24.3
}
"""


GOOD_HEADER_STATS = """
header {
  comment:: "The general policy comment."
  target:: nokiasrl good-name-v4 inet stats r24.3
}
"""

GOOD_HEADER_PRE2024 = """
header {
  comment:: "The general policy comment."
  target:: nokiasrl good-name-mixed mixed
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
    "acl-filter": {
      "_annotate": "$Id:$ $Date:$ $Revision:$",
      "name": "good-name-v4",
      "description": "The general policy comment.",
      "type": "ipv4",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "good-term-1",
          "_annotate_description": "Allow source address.",
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
    "acl-filter": {
      "_annotate": "$Id:$ $Date:$ $Revision:$",
      "name": "good-name-v6",
      "description": "The general policy comment.",
      "type": "ipv6",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "good-term-1",
          "_annotate_description": "Allow source address.",
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
    "acl-filter": {
      "_annotate": "$Id:$ $Date:$ $Revision:$",
      "name": "good-name-v4",
      "description": "The general policy comment.",
      "type": "ipv4",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "good-term-1",
          "_annotate_description": "Allow destination address.",
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
    "acl-filter": {
      "_annotate": "$Id:$ $Date:$ $Revision:$",
      "name": "good-name-v6",
      "description": "The general policy comment.",
      "type": "ipv6",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "good-term-1",
          "_annotate_description": "Allow destination address.",
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
    "acl-filter": {
      "_annotate": "$Id:$ $Date:$ $Revision:$",
      "name": "good-name-v4",
      "description": "The general policy comment.",
      "type": "ipv4",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "good-term-1",
          "_annotate_description": "Allow TCP 53 source.",
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
    "acl-filter": {
      "_annotate": "$Id:$ $Date:$ $Revision:$",
      "name": "good-name-v4",
      "description": "The general policy comment.",
      "type": "ipv4",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "good-term-1",
          "_annotate_description": "Allow TCP 53 dest.",
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
    "acl-filter": {
      "_annotate": "$Id:$ $Date:$ $Revision:$",
      "name": "good-name-v4",
      "description": "The general policy comment.",
      "type": "ipv4",
      "entry": [
        {
          "action": {
            "accept": {}
          },
          "description": "good-term-1",
          "_annotate_description": "Allow TCP & UDP high.",
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
          "description": "good-term-1",
          "_annotate_description": "Allow TCP & UDP high.",
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
BAD_TERM_3 = """
term bad-term-3 {
  protocol:: icmp
  option:: established
  action:: accept
}
"""
BAD_TERM_4 = """
term bad-term-4 {
  option:: established
  action:: accept
}
"""

BAD_LOGGING = """
term bad-term-5 {
  comment:: "Allow TCP & UDP 53 with saddr/daddr and logging."
  destination-address:: CORP_EXTERNAL
  source-address:: CORP_EXTERNAL
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
  logging:: True
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
  target:: nokiasrl good-name-v6 inet6 r24.3
}
"""

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class NokiaSRLTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = naming.Naming()
        self.naming._ParseLine('CORP_EXTERNAL = 10.2.3.4/32 2001:4860:8000::5/128', 'networks')
        self.naming._ParseLine('DNS = 53/tcp 53/udp', 'services')
        self.naming._ParseLine('HIGH_PORTS = 1024-65535/tcp 1024-65535/udp', 'services')

    @capture.stdout
    def testSaddr(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_SADDR, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_SADDR)
        self.assertEqual(expected, json.loads(str(acl)))

        print(acl)

    @capture.stdout
    def testDaddr(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_DADDR, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_DADDR)
        self.assertEqual(expected, json.loads(str(acl)))

        print(acl)

    @capture.stdout
    def testSport(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_SPORT, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_SPORT)
        self.assertEqual(expected, json.loads(str(acl)))

        print(acl)

    # TODO v6 s/dport
    @capture.stdout
    def testDport(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_DPORT, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_DPORT)
        self.assertEqual(expected, json.loads(str(acl)))

        print(acl)

    @capture.stdout
    def testMultiDport(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_MULTI_PROTO_DPORT, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_MULTI_PROTO_DPORT)
        self.assertEqual(expected, json.loads(str(acl)))

        print(acl)

    @capture.stdout
    def testEverything(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_EVERYTHING, self.naming), EXP_INFO
        )
        print(acl)

    @capture.stdout
    def testV6Saddr(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_SADDR, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_V6_SADDR)
        self.assertEqual(expected, json.loads(str(acl)))

        print(acl)

    @capture.stdout
    def testV6Daddr(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_DADDR, self.naming), EXP_INFO
        )
        expected = json.loads(GOOD_JSON_V6_DADDR)
        self.assertEqual(expected, json.loads(str(acl)))

        print(acl)

    @capture.stdout
    def testEstablished(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_ESTABLISHED_TERM_1, self.naming), EXP_INFO
        )
        output = str(acl)
        self.assertIn('"ack|rst"', output, output)

        print(output)

    @capture.stdout
    def testTcpEstablished(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TCP_ESTABLISHED_TERM_1, self.naming), EXP_INFO
        )
        output = str(acl)
        self.assertIn('"ack|rst"', output, output)

        print(output)

    @capture.stdout
    def testUdpEstablishedv6(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER_INET6 + GOOD_UDP_ESTABLISHED_TERM_1, self.naming),
            EXP_INFO,
        )
        output = str(acl)
        print(output)

    @capture.stdout
    def testStats(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER_STATS + GOOD_UDP_ESTABLISHED_TERM_1, self.naming),
            EXP_INFO,
        )
        output = str(acl)
        print(output)

    @capture.stdout
    def testPre2024(self):
        acl = nokiasrl.NokiaSRLinux(
            policy.ParsePolicy(GOOD_HEADER_PRE2024 + GOOD_EVERYTHING, self.naming),
            EXP_INFO,
        )
        output = str(acl)
        print(output)

    def testTcpEstablishedWithNonTcpError1(self):
        acl = policy.ParsePolicy(GOOD_HEADER + BAD_TERM_1, self.naming)
        with self.assertRaises(nokiasrl.TcpEstablishedWithNonTcpError):
            _ = nokiasrl.NokiaSRLinux(acl, EXP_INFO)

    def testTcpEstablishedWithNonTcpError2(self):
        acl = policy.ParsePolicy(GOOD_HEADER + BAD_TERM_2, self.naming)
        with self.assertRaises(nokiasrl.TcpEstablishedWithNonTcpError):
            _ = nokiasrl.NokiaSRLinux(acl, EXP_INFO)

    def testUnsupportedLogging(self):
        acl = policy.ParsePolicy(GOOD_HEADER + BAD_LOGGING, self.naming)
        with self.assertRaises(nokiasrl.UnsupportedLogging):
            _ = nokiasrl.NokiaSRLinux(acl, EXP_INFO)

    def testEstablishedWithNonTcpUdpError(self):
        acl = policy.ParsePolicy(GOOD_HEADER + BAD_TERM_3, self.naming)
        with self.assertRaises(nokiasrl.EstablishedWithNonTcpUdpError):
            _ = nokiasrl.NokiaSRLinux(acl, EXP_INFO)

    def testEstablishedWithNoProtocolError(self):
        acl = policy.ParsePolicy(GOOD_HEADER + BAD_TERM_4, self.naming)
        with self.assertRaises(nokiasrl.EstablishedWithNoProtocolError):
            _ = nokiasrl.NokiaSRLinux(acl, EXP_INFO)


#
# TODO:
# - Fragments
# - TCP flags
# - ICMP type codes
#

if __name__ == '__main__':
    absltest.main()
