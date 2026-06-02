# Copyright 2022 Google Inc. All Rights Reserved.
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
"""Regression tests for the Aerleon nftables fork extensions.

These cover the router-oriented features this fork adds on top of the upstream
nftables generator:

  * forward / prerouting / postrouting hooks
  * named (and negative) netfilter priorities
  * the reject and masquerade actions
  * NAT 'type nat' base-chain rendering
  * the tcp-mss MSS-clamp token

Policies are authored through the YAML PolicyBuilder path (the way the fork is
actually consumed) rather than the legacy .pol DSL. The snapshot tests print a
complete ruleset whose .ref file doubles as an `nft -c -f` validation fixture.
"""

from absl.testing import absltest, parameterized

from aerleon.lib import nftables, policy, policy_builder
from aerleon.lib.naming import Naming
from tests.regression_utils import capture

# Print an info message when a term is set to expire in that many weeks.
EXP_INFO = 2

NETWORKS = {
    'networks': {
        'LAN': {'values': [{'address': '192.168.1.0/24'}]},
        'GUEST': {'values': [{'address': '10.0.9.0/24'}]},
        'DMZ': {'values': [{'address': '172.16.0.0/24'}]},
        # Dual-stack group to exercise 'mixed' (table inet) rendering.
        'WEBHOST': {'values': [{'address': '192.0.2.10/32'}, {'address': '2001:db8::10/128'}]},
    }
}

SERVICES = {
    'services': {
        'SSH': [{'protocol': 'tcp', 'port': 22}],
        'HTTP': [{'protocol': 'tcp', 'port': 80}],
        'HTTPS': [{'protocol': 'tcp', 'port': 443}],
        'DNS': [{'protocol': 'udp', 'port': 53}],
    }
}


class NftablesForkTest(parameterized.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = Naming()
        self.naming.ParseDefinitionsObject(NETWORKS, '')
        self.naming.ParseDefinitionsObject(SERVICES, '')

    def _render(self, filters):
        """Render a list of (target, terms) tuples into a single nftables config."""
        pol_dict = {
            'filters': [
                {
                    'header': {'comment': comment, 'targets': {'nftables': target}},
                    'terms': terms,
                }
                for comment, target, terms in filters
            ]
        }
        pol = policy.FromBuilder(policy_builder.PolicyBuilder(pol_dict, self.naming))
        return str(nftables.Nftables(pol, EXP_INFO))

    def _render_one(self, target, terms, comment='fork test'):
        return self._render([(comment, target, terms)])

    # --- Hooks ---------------------------------------------------------------

    @parameterized.parameters('prerouting', 'input', 'forward', 'output', 'postrouting')
    def testSupportedHooks(self, hook):
        out = self._render_one(
            f'inet {hook}',
            [{'name': 'allow-ssh', 'protocol': 'tcp', 'destination-port': 'SSH', 'action': 'accept'}],
        )
        self.assertIn(f'type filter hook {hook} priority', out)

    # --- Named / negative priorities -----------------------------------------

    @parameterized.parameters(
        ('raw', '-300'),
        ('mangle', '-150'),
        ('dstnat', '-100'),
        ('filter', '0'),
        ('security', '50'),
        ('srcnat', '100'),
    )
    def testNamedPriority(self, alias, expected):
        out = self._render_one(
            f'inet forward {alias}',
            [{'name': 'allow-web', 'protocol': 'tcp', 'destination-port': 'HTTP', 'action': 'accept'}],
        )
        self.assertIn(f'priority {expected};', out)

    def testNamedPriorityIsCaseInsensitive(self):
        out = self._render_one(
            'inet forward MANGLE',
            [{'name': 'allow-web', 'protocol': 'tcp', 'destination-port': 'HTTP', 'action': 'accept'}],
        )
        self.assertIn('priority -150;', out)

    def testIntegerPriorityPreserved(self):
        out = self._render_one(
            'inet input 300',
            [{'name': 'allow-ssh', 'protocol': 'tcp', 'destination-port': 'SSH', 'action': 'accept'}],
        )
        self.assertIn('priority 300;', out)

    # --- reject --------------------------------------------------------------

    def testRejectAction(self):
        out = self._render_one(
            'inet input',
            [{'name': 'block-and-tell', 'source-address': 'GUEST', 'action': 'reject'}],
        )
        self.assertIn('reject', out)
        # reject lives in an ordinary filter chain.
        self.assertIn('type filter hook input', out)
        self.assertNotIn('type nat', out)

    # --- masquerade / NAT ----------------------------------------------------

    def testMasqueradeRendersNatChain(self):
        out = self._render_one(
            'inet postrouting srcnat',
            [{'name': 'masq-lan', 'source-address': 'LAN', 'action': 'masquerade'}],
        )
        self.assertIn('type nat hook postrouting priority 100; policy accept;', out)
        self.assertIn('masquerade', out)
        # NAT base chains must not carry the stateful conntrack preamble.
        self.assertNotIn('ct state established,related accept', out)

    def testNonNatChainKeepsStatefulPreamble(self):
        out = self._render_one(
            'inet input',
            [{'name': 'allow-ssh', 'protocol': 'tcp', 'destination-port': 'SSH', 'action': 'accept'}],
        )
        self.assertIn('type filter hook input', out)
        self.assertIn('ct state established,related accept', out)

    # --- MSS clamp -----------------------------------------------------------

    @parameterized.parameters(
        ('pmtu', 'rt mtu'),
        ('rt-mtu', 'rt mtu'),
        ('rt_mtu', 'rt mtu'),
        ('1460', '1460'),
        ('1400', '1400'),
    )
    def testMssClamp(self, value, expected):
        out = self._render_one(
            'inet forward mangle',
            [{'name': 'clamp-mss', 'protocol': 'tcp', 'tcp-mss': value, 'action': 'accept'}],
        )
        self.assertIn(f'tcp flags syn tcp option maxseg size set {expected}', out)

    # --- Interface matching --------------------------------------------------

    def testSourceInterface(self):
        out = self._render_one(
            'inet forward',
            [{'name': 'from-lan', 'source-interface': 'eth1', 'action': 'accept'}],
        )
        self.assertIn('iifname "eth1"', out)

    def testDestinationInterface(self):
        out = self._render_one(
            'inet forward',
            [{'name': 'to-wan', 'destination-interface': 'eth0', 'action': 'accept'}],
        )
        self.assertIn('oifname "eth0"', out)

    def testBothInterfacesPrefixMatch(self):
        out = self._render_one(
            'inet forward',
            [
                {
                    'name': 'lan-to-wan',
                    'source-interface': 'eth1',
                    'destination-interface': 'eth0',
                    'protocol': 'tcp',
                    'destination-port': 'HTTP',
                    'action': 'accept',
                }
            ],
        )
        # Interface match is the prefix, ahead of the address/port match.
        self.assertIn('iifname "eth1" oifname "eth0" tcp dport 80', out)

    def testMasqueradeScopedByInterface(self):
        """The §7 use case: masquerade only out the WAN interface, not unconditional."""
        out = self._render_one(
            'inet postrouting srcnat',
            [{'name': 'masq-wan', 'destination-interface': 'wan0', 'action': 'masquerade'}],
        )
        self.assertIn('oifname "wan0"', out)
        self.assertIn('masquerade', out)
        self.assertIn('type nat hook postrouting', out)

    # --- Full-ruleset snapshots (also serve as `nft -c -f` fixtures) ---------

    @capture.stdout
    def testRouterComboRuleset(self):
        """A realistic single-host router: forward + input + postrouting NAT."""
        out = self._render(
            [
                (
                    'router1 forward',
                    'inet forward',
                    [
                        {
                            'name': 'fwd-lan-web',
                            'source-address': 'LAN',
                            'protocol': 'tcp',
                            'destination-port': 'HTTP',
                            'action': 'accept',
                        },
                    ],
                ),
                (
                    'router1 input',
                    'inet input',
                    [
                        {
                            'name': 'allow-ssh',
                            'protocol': 'tcp',
                            'destination-port': 'SSH',
                            'action': 'accept',
                        },
                        {'name': 'allow-icmp', 'protocol': 'icmp', 'action': 'accept'},
                        {'name': 'drop-guest', 'source-address': 'GUEST', 'action': 'reject'},
                    ],
                ),
                (
                    'router1 nat',
                    'inet postrouting srcnat',
                    [{'name': 'masq-lan', 'source-address': 'LAN', 'action': 'masquerade'}],
                ),
            ]
        )
        print(out)

    @capture.stdout
    def testMangleMssClampRuleset(self):
        out = self._render_one(
            'inet forward mangle',
            [{'name': 'clamp-mss', 'protocol': 'tcp', 'tcp-mss': 'pmtu', 'action': 'accept'}],
            comment='clamp mss on forward',
        )
        print(out)

    @capture.stdout
    def testMasqueradeRuleset(self):
        out = self._render_one(
            'inet postrouting srcnat',
            [{'name': 'masq-lan', 'source-address': 'LAN', 'action': 'masquerade'}],
            comment='masquerade out',
        )
        print(out)

    @capture.stdout
    def testInterfaceScopedRouterRuleset(self):
        """Real router shape: forward LAN(eth1)->WAN(eth0), masquerade out eth0."""
        out = self._render(
            [
                (
                    'forward lan to wan',
                    'inet forward',
                    [
                        {
                            'name': 'lan-out',
                            'source-interface': 'eth1',
                            'destination-interface': 'eth0',
                            'source-address': 'LAN',
                            'action': 'accept',
                        },
                    ],
                ),
                (
                    'masquerade out wan',
                    'inet postrouting srcnat',
                    [
                        {
                            'name': 'masq-wan',
                            'destination-interface': 'eth0',
                            'source-address': 'LAN',
                            'action': 'masquerade',
                        }
                    ],
                ),
            ]
        )
        print(out)

    @capture.stdout
    def testMixedFamilyForwardRuleset(self):
        """'mixed' renders a dual-stack `table inet` with v4 and v6 rules."""
        out = self._render_one(
            'mixed forward',
            [
                {
                    'name': 'fwd-to-webhost',
                    'destination-address': 'WEBHOST',
                    'protocol': 'tcp',
                    'destination-port': 'HTTPS',
                    'action': 'accept',
                },
            ],
            comment='dual-stack forward',
        )
        print(out)


if __name__ == '__main__':
    absltest.main()
