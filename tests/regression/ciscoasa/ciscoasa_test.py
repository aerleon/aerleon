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

"""Unittest for ciscoasa acl rendering module."""

from unittest import mock

from absl.testing import absltest, parameterized

from aerleon.lib import ciscoasa, nacaddr, naming, policy
from aerleon.lib import yaml as yaml_frontend
from tests.regression_utils import capture

GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: ciscoasa test-filter
}
"""

DSMO_HEADER = """
header {
  target:: ciscoasa foo enable_dsmo
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  verbatim:: ciscoasa "mary had a little lamb"
  verbatim:: iptables "mary had second lamb"
  verbatim:: juniper "mary had third lamb"
}
"""

GOOD_TERM_2 = """
term good-term-2 {
  verbatim:: ciscoasa "mary had a little lamb"
  policer:: batman
}
"""

GOOD_TERM_3 = """
term good-src-term-3 {
    source-address:: CORP
    action:: accept
}
"""
GOOD_TERM_4 = """
term good-dst-term-3 {
    destination-address:: CORP
    action:: accept
}
"""
VERBATIM_TERM = """
term verbatim-term {
    verbatim:: ciscoasa "foo bar"
    verbatim:: ciscoasa "biz baz"
}
"""

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'expiration',
    'icmp_type',
    'stateless_reply',
    'logging',
    'name',
    'option',
    'owner',
    'platform',
    'platform_exclude',
    'protocol',
    'source_address',
    'source_address_exclude',
    'source_port',
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
    'option': {'established', 'tcp-established'},
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class CiscoASATest(parameterized.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = mock.create_autospec(naming.Naming)

    def testBuildTokens(self):
        pol1 = ciscoasa.CiscoASA(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_1, self.naming), EXP_INFO
        )
        st, sst = pol1._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    def testBuildWarningTokens(self):
        pol1 = ciscoasa.CiscoASA(
            policy.ParsePolicy(GOOD_HEADER + GOOD_TERM_2, self.naming), EXP_INFO
        )
        st, sst = pol1._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    @capture.stdout
    def testVerbatim(self):
        pol = ciscoasa.CiscoASA(
            policy.ParsePolicy(GOOD_HEADER + VERBATIM_TERM, self.naming), EXP_INFO
        )
        print(pol)
        expect = 'access-list test-filter remark verbatim-term\nfoo bar\nbiz baz'
        self.assertIn(expect, str(pol))

    @parameterized.named_parameters(
        ('source', GOOD_TERM_3, 'permit ip 128.168.0.0 191.255.255.128 any'),
        ('destination', GOOD_TERM_4, 'permit ip any 128.168.0.0 191.255.255.128'),
    )
    @capture.stdout
    def testDSMO(self, term, expected):
        self.naming.GetNetAddr.return_value = [
            nacaddr.IPv4('192.168.0.0/25'),
            nacaddr.IPv4('128.168.0.0/25'),
        ]
        pol = ciscoasa.CiscoASA(policy.ParsePolicy(DSMO_HEADER + term, self.naming), EXP_INFO)
        print(pol)
        self.assertIn(expected, str(pol))

    @capture.stdout
    def testHostAddressFormat(self):
        defs = naming.Naming()
        defs._ParseLine('FOO = 10.0.0.1/32', 'networks')
        pol_yaml = """
        filters:
          - header:
              targets:
                ciscoasa: allowtointernet
            terms:
              - name: accept-foo
                source-address: FOO
                destination-address: FOO
                action: accept
        """
        pol = ciscoasa.CiscoASA(_YamlParsePolicy(pol_yaml, definitions=defs), EXP_INFO)
        print(pol)
        self.assertIn(
            'access-list allowtointernet extended permit ip host 10.0.0.1 host 10.0.0.1', str(pol)
        )


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


if __name__ == '__main__':
    absltest.main()
