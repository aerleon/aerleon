# Copyright 2008 Google Inc. All Rights Reserved.
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

"""Unit tests for AclCheck."""

from typing import Literal
import pytest
from absl.testing import absltest

from aerleon.lib import aclcheck, naming, policy, port
from tests.regression_utils import capture

POLICYTEXT = """
header {
  comment:: "this is a test acl"
  target:: juniper test-filter
}
term term-1 {
  protocol:: tcp
  action:: next
}
term term-2 {
  source-address:: NET172
  destination-address:: NET10
  protocol:: tcp
  destination-port:: SSH
  option:: first-fragment tcp-established
  fragment-offset:: 1-6
  packet-length:: 1-119
  action:: accept
}
term term-3 {
  source-address:: NET172
  destination-address:: NET10
  protocol:: tcp
  destination-port:: SSH
  action:: accept
}
term term-4 {
  protocol:: udp
  action:: accept
}
term term-5 {
  action:: reject
}
"""

ZONE_POLICY_TEST = """
header {
  comment:: "zone test acl"
  target:: srx from-zone any to-zone any
}
term zone-term {
  source-address:: NET172
  source-zone:: TRUST

  destination-address:: NET10
  destination-zone:: UNTRUST
  protocol:: tcp
  action:: accept
}
term default-term {
  action:: reject
}
"""


class AclCheckTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.defs = naming.Naming(None)
        servicedata = []
        servicedata.append('SSH = 22/tcp')
        networkdata = []
        networkdata.append('NET172 = 172.16.0.0/12')
        networkdata.append('NET10 = 10.0.0.0/8')

        self.defs.ParseServiceList(servicedata)
        self.defs.ParseNetworkList(networkdata)
        self.pol = policy.ParsePolicy(POLICYTEXT, self.defs)

    def testExactMatches(self):
        check = aclcheck.AclCheck(self.pol, '172.16.1.1', '10.1.1.1', '1025', '22', 'tcp')
        matches = check.ExactMatches()
        self.assertEqual(len(matches), 1)

    def testAclCheck(self):
        srcip = '172.16.1.1'
        dstip = '10.2.2.10'
        sport = '10000'
        dport = '22'
        proto = 'tcp'
        check = aclcheck.AclCheck(
            self.pol, src=srcip, dst=dstip, sport=sport, dport=dport, proto=proto
        )
        matches = check.Matches()
        # Check correct number of matches
        self.assertEqual(len(matches), 3)

        # Check correct actions
        self.assertEqual(matches[0].action, 'next')  # term-1
        self.assertEqual(matches[1].action, 'accept')  # term-2
        self.assertEqual(matches[2].action, 'accept')  # term-3

        # Check for correct 'possibles'
        self.assertEqual(matches[0].possibles, [])  # term-1
        self.assertEqual(
            matches[1].possibles, ['first-frag', 'frag-offset', 'packet-length', 'tcp-est']
        )  # term-2
        self.assertEqual(matches[2].possibles, [])  # term-3

        # Check which term names match
        self.assertEqual(matches[0].term, 'term-1')
        self.assertEqual(matches[1].term, 'term-2')
        self.assertEqual(matches[2].term, 'term-3')
        # term-4 should never match
        self.assertNotIn('term-4', str(matches))
        self.assertNotIn('term-5', str(matches))

    @capture.stdout
    def testSummarize(self):
        srcip = '172.16.1.1'
        dstip = '10.2.2.10'
        sport = '10000'
        dport = '22'
        proto = 'tcp'
        check = aclcheck.AclCheck(
            self.pol, src=srcip, dst=dstip, sport=sport, dport=dport, proto=proto
        )

        summary = check.Summarize()

        self.assertIn('term-1', summary['test-filter'].keys())
        self.assertIn('term-2', summary['test-filter'].keys())
        self.assertIn('term-3', summary['test-filter'].keys())
        self.assertNotIn('term-4', summary['test-filter'].keys())
        self.assertNotIn('term-5', summary['test-filter'].keys())

        print(str(check))

    def testExceptions(self):
        srcip = '172.16.1.1'
        dstip = '10.2.2.10'
        sport = '10000'
        dport = '22'
        proto = 'tcp'
        bad_portrange = '99999'
        bad_portvalue = 'port_99'
        self.assertRaises(
            port.BadPortValue,
            aclcheck.AclCheck,
            self.pol,
            srcip,
            dstip,
            bad_portvalue,
            dport,
            proto,
        )
        self.assertRaises(
            port.BadPortRange,
            aclcheck.AclCheck,
            self.pol,
            srcip,
            dstip,
            sport,
            bad_portrange,
            proto,
        )
        self.assertRaises(
            aclcheck.AddressError,
            aclcheck.AclCheck,
            self.pol,
            '300.400.500.600',
            dstip,
            sport,
            dport,
            proto,
        )


@pytest.mark.parametrize(
    "mode,source_zone,destination_zone,expected",
    [
        ("contains", None, None, ["zone-term"]),
        ("equals", "TRUST", "UNTRUST", ["zone-term"]),
        ("equals", "WRONG", "UNTRUST", ["default-term"]),
    ],
)
def test_zone_matches_parametrized(mode: Literal["contains", "equals"], source_zone: str | None, destination_zone: str | None, expected: list[str]) -> None:
    defs = naming.Naming(None)
    servicedata = ["SSH = 22/tcp"]
    networkdata = ["NET172 = 172.16.0.0/12", "NET10 = 10.0.0.0/8"]
    defs.ParseServiceList(servicedata)
    defs.ParseNetworkList(networkdata)

    pol = policy.ParsePolicy(ZONE_POLICY_TEST, defs)

    kwargs = {}
    if source_zone is not None:
        kwargs["source_zone"] = source_zone
    if destination_zone is not None:
        kwargs["destination_zone"] = destination_zone

    check = aclcheck.AclCheck(
        pol,
        src="172.16.1.1",
        dst="10.2.2.10",
        sport="10000",
        dport="22",
        proto="tcp",
        **kwargs,
    )

    matches = [m.term for m in check.Matches()]

    if mode == "contains":
        assert expected[0] in matches
    else:
        assert matches == expected


if __name__ == '__main__':
    absltest.main()
