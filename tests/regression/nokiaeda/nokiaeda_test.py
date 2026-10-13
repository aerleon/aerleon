# Copyright 2026 Aerleon Project Authors.
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

"""Regression tests for the Nokia EDA Filter generator."""

import yaml
from absl.testing import absltest

from aerleon.lib import aclgenerator, naming, nokiaeda, policy
from tests.regression_utils import capture

# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

HEADER_INET = """
header {
  target:: nokiaeda my-filter inet namespace my-ns
}
"""

HEADER_INET6 = """
header {
  target:: nokiaeda my-filter inet6 namespace my-ns
}
"""

HEADER_MIXED = """
header {
  target:: nokiaeda my-filter mixed namespace my-ns
}
"""

HEADER_STATS = """
header {
  target:: nokiaeda my-filter inet stats namespace my-ns
}
"""

HEADER_COMMENT = """
header {
  comment:: "my filter description"
  target:: nokiaeda my-filter inet namespace my-ns
}
"""

HEADER_CPM = """
header {
  target:: nokiaeda my-cpm cpm inet namespace my-ns node-selector eda.nokia.com/role leaf node leaf1 node leaf2
}
"""

HEADER_NO_NAMESPACE = """
header {
  target:: nokiaeda my-filter inet
}
"""

HEADER_NAMESPACE_NO_VALUE = """
header {
  target:: nokiaeda my-filter inet namespace
}
"""

HEADER_SELECTOR_NO_VALUE = """
header {
  target:: nokiaeda my-cpm cpm namespace my-ns node-selector eda.nokia.com/role
}
"""

HEADER_UNKNOWN_OPTION = """
header {
  target:: nokiaeda my-filter inet r24.3.2 namespace my-ns
}
"""

HEADER_UPPERCASE_NAME = """
header {
  target:: nokiaeda My_Filter inet namespace my-ns
}
"""

HEADER_BAD_NAMESPACE = """
header {
  target:: nokiaeda my-filter inet namespace my.ns
}
"""

HEADER_CPM_NO_NODE = """
header {
  target:: nokiaeda my-cpm cpm inet namespace my-ns
}
"""

HEADER_NODE_NOT_CPM = """
header {
  target:: nokiaeda my-filter inet namespace my-ns node leaf1
}
"""

# ---------------------------------------------------------------------------
# Terms
# ---------------------------------------------------------------------------

TERM_ACCEPT = """
term term-accept {
  action:: accept
}
"""

TERM_DENY = """
term term-deny {
  action:: deny
}
"""

TERM_REJECT = """
term term-reject {
  action:: reject
}
"""

TERM_SADDR = """
term term-saddr {
  source-address:: CORP_EXTERNAL
  action:: accept
}
"""

TERM_SADDR_V4_ONLY = """
term term-saddr-v4 {
  source-address:: V4_ONLY
  action:: accept
}
"""

TERM_DADDR_V6_ONLY = """
term term-daddr-v6 {
  destination-address:: V6_ONLY
  action:: accept
}
"""

TERM_SPORT = """
term term-sport {
  protocol:: tcp
  source-port:: BGP
  action:: accept
}
"""

TERM_DPORT_MULTI_PROTO = """
term term-dport {
  protocol:: tcp udp
  destination-port:: DNS
  action:: accept
}
"""

TERM_PORT_RANGE = """
term term-port-range {
  protocol:: tcp
  destination-port:: HIGH_PORTS
  action:: accept
}
"""

TERM_ICMP = """
term term-icmp {
  protocol:: icmp
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

TERM_ICMPV6 = """
term term-icmpv6 {
  protocol:: icmpv6
  icmp-type:: echo-request
  action:: accept
}
"""

TERM_ICMP_CODE = """
term term-icmp-code {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 3 4
  action:: accept
}
"""

TERM_LOGGING = """
term term-logging {
  logging:: syslog
  action:: deny
}
"""

TERM_LOGGING_DISABLE = """
term term-logging-disable {
  logging:: disable
  action:: deny
}
"""

TERM_TCP_EST = """
term term-tcp-est {
  protocol:: tcp
  option:: tcp-established
  action:: accept
}
"""

TERM_TCP_EST_NO_PROTO = """
term term-tcp-est-no-proto {
  option:: tcp-established
  action:: accept
}
"""

TERM_TCP_EST_UDP = """
term term-tcp-est-udp {
  protocol:: udp
  option:: tcp-established
  action:: accept
}
"""

TERM_EST_TCP = """
term term-est-tcp {
  protocol:: tcp
  option:: established
  action:: accept
}
"""

TERM_EST_UDP = """
term term-est-udp {
  protocol:: udp
  option:: established
  action:: accept
}
"""

TERM_EST_UDP_DPORT = """
term term-est-udp-dport {
  protocol:: udp
  destination-port:: DNS
  option:: established
  action:: accept
}
"""

TERM_EST_NO_PROTO = """
term term-est-no-proto {
  option:: established
  action:: accept
}
"""

TERM_EST_ICMP = """
term term-est-icmp {
  protocol:: icmp
  option:: established
  action:: accept
}
"""

TERM_TCP_INITIAL = """
term term-tcp-initial {
  protocol:: tcp
  option:: tcp-initial
  action:: accept
}
"""

TERM_FRAGMENTS = """
term term-fragments {
  option:: fragments
  action:: deny
}
"""

TERM_FIRST_FRAGMENT = """
term term-first-fragment {
  option:: first-fragment
  action:: deny
}
"""

TERM_POLICER_COUNTER = """
term term-policer {
  policer:: limit-100k
  counter:: my-counter
  action:: accept
}
"""

TERM_COMMENTS = """
term term-comments {
  comment:: "first comment - NET-1"
  comment:: "second comment"
  source-address:: CORP_EXTERNAL
  action:: accept
}
"""

TERM_HOP_LIMIT = """
term term-hop-limit {
  hop-limit:: 10
  action:: deny
}
"""

EXP_INFO = 2


class NokiaEDATest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = naming.Naming()
        self.naming._ParseLine('CORP_EXTERNAL = 10.2.3.4/32 2001:4860:8000::5/128', 'networks')
        self.naming._ParseLine('V4_ONLY = 10.2.3.4/32', 'networks')
        self.naming._ParseLine('V6_ONLY = 2001:4860:8000::5/128', 'networks')
        self.naming._ParseLine('DNS = 53/tcp 53/udp', 'services')
        self.naming._ParseLine('BGP = 179/tcp', 'services')
        self.naming._ParseLine('HIGH_PORTS = 1024-65535/tcp 1024-65535/udp', 'services')

    def _make_acl(self, header, terms):
        return nokiaeda.NokiaEDA(policy.ParsePolicy(header + terms, self.naming), EXP_INFO)

    def _resources(self, acl):
        return list(yaml.safe_load_all(str(acl)))

    def _resource(self, acl):
        """Return the single resource in the output."""
        resources = self._resources(acl)
        self.assertEqual(len(resources), 1)
        return resources[0]

    def _entries(self, header, terms):
        return self._resource(self._make_acl(header, terms))['spec']['entries']

    def _ip_entries(self, header, terms):
        return [e['ipEntry'] for e in self._entries(header, terms)]

    # -----------------------------------------------------------------------
    # Resource structure
    # -----------------------------------------------------------------------

    @capture.stdout
    def testFilter(self):
        acl = self._make_acl(HEADER_INET, TERM_DENY)
        resource = self._resource(acl)
        self.assertEqual(resource['apiVersion'], 'filters.eda.nokia.com/v1')
        self.assertEqual(resource['kind'], 'Filter')
        self.assertEqual(resource['metadata']['name'], 'my-filter')
        self.assertEqual(resource['metadata']['namespace'], 'my-ns')
        self.assertEqual(
            resource['metadata']['annotations'],
            {'aerleon/revision': '$Id:$ $Date:$ $Revision:$'},
        )
        self.assertEqual(
            resource['spec']['entries'],
            [{'description': 'term-deny', 'type': 'IPv4', 'ipEntry': {'action': 'Drop'}}],
        )
        self.assertNotIn('statisticsPerEntry', resource['spec'])
        print(acl)

    def testStats(self):
        resource = self._resource(self._make_acl(HEADER_STATS, TERM_DENY))
        self.assertIs(resource['spec']['statisticsPerEntry'], True)

    def testHeaderComment(self):
        resource = self._resource(self._make_acl(HEADER_COMMENT, TERM_DENY))
        self.assertEqual(
            resource['metadata']['annotations']['aerleon/comment'], 'my filter description'
        )

    @capture.stdout
    def testControlPlaneFilter(self):
        acl = self._make_acl(HEADER_CPM, TERM_DENY)
        resource = self._resource(acl)
        self.assertEqual(resource['kind'], 'ControlPlaneFilter')
        self.assertEqual(resource['spec']['nodeSelectors'], ['eda.nokia.com/role=leaf'])
        self.assertEqual(resource['spec']['nodes'], ['leaf1', 'leaf2'])
        print(acl)

    def testMultipleHeaders(self):
        acl = self._make_acl(HEADER_INET + TERM_DENY + HEADER_CPM, TERM_ACCEPT)
        self.assertEqual(
            [r['kind'] for r in self._resources(acl)], ['Filter', 'ControlPlaneFilter']
        )

    def testNoEntries(self):
        """A filter whose terms all render to nothing still has an entries list."""
        acl = self._make_acl(HEADER_INET6, TERM_SADDR_V4_ONLY)
        self.assertIn('  entries: []\n', str(acl))
        self.assertEqual(self._resource(acl)['spec']['entries'], [])

    def testHeaderOptionsNotModified(self):
        """Parsing the options must not consume the header's own option list."""
        pol = policy.ParsePolicy(HEADER_INET + TERM_DENY, self.naming)
        nokiaeda.NokiaEDA(pol, EXP_INFO)
        options = pol.filters[0][0].FilterOptions('nokiaeda')
        self.assertEqual(options, ['my-filter', 'inet', 'namespace', 'my-ns'])

    # -----------------------------------------------------------------------
    # Header option errors
    # -----------------------------------------------------------------------

    def testHeaderErrors(self):
        cases = {
            'no namespace': (HEADER_NO_NAMESPACE, nokiaeda.FilterOptionError),
            'namespace without value': (HEADER_NAMESPACE_NO_VALUE, nokiaeda.FilterOptionError),
            'selector without value': (HEADER_SELECTOR_NO_VALUE, nokiaeda.FilterOptionError),
            'unknown option': (HEADER_UNKNOWN_OPTION, nokiaeda.FilterOptionError),
            'cpm without node': (HEADER_CPM_NO_NODE, nokiaeda.FilterOptionError),
            'node without cpm': (HEADER_NODE_NOT_CPM, nokiaeda.FilterOptionError),
            'uppercase name': (HEADER_UPPERCASE_NAME, nokiaeda.InvalidResourceNameError),
            'bad namespace': (HEADER_BAD_NAMESPACE, nokiaeda.InvalidResourceNameError),
        }
        for case, (header, error) in cases.items():
            with self.subTest(case):
                with self.assertRaises(error):
                    self._make_acl(header, TERM_DENY)

    def testUnsupportedTokens(self):
        for term in (TERM_REJECT, TERM_HOP_LIMIT):
            with self.subTest(term):
                with self.assertRaises(aclgenerator.UnsupportedFilterError):
                    self._make_acl(HEADER_INET, term)

    # -----------------------------------------------------------------------
    # Addresses and address families
    # -----------------------------------------------------------------------

    def testAddressFamilies(self):
        """Entries per filter AF for dual-stack, v4-only, v6-only and ICMP terms."""
        v4 = ('IPv4', {'action': 'Accept', 'sourcePrefix': '10.2.3.4/32'})
        v6 = ('IPv6', {'action': 'Accept', 'sourcePrefix': '2001:4860:8000::5/128'})
        v6_dst = ('IPv6', {'action': 'Accept', 'destinationPrefix': '2001:4860:8000::5/128'})
        icmp = ('IPv4', {'action': 'Accept', 'protocolNumber': 1, 'icmpTypeNumber': 8})
        icmpv6 = ('IPv6', {'action': 'Accept', 'protocolNumber': 58, 'icmpTypeNumber': 128})
        expected = {
            'inet': {
                TERM_SADDR: [v4],
                TERM_SADDR_V4_ONLY: [v4],
                TERM_DADDR_V6_ONLY: [],
                TERM_ICMPV6: [],
            },
            'inet6': {
                TERM_SADDR: [v6],
                TERM_SADDR_V4_ONLY: [],
                TERM_DADDR_V6_ONLY: [v6_dst],
                TERM_ICMP: [],
                TERM_ICMPV6: [icmpv6],
            },
            'mixed': {
                TERM_SADDR: [v4, v6],
                TERM_SADDR_V4_ONLY: [v4],
                TERM_DADDR_V6_ONLY: [v6_dst],
                TERM_ICMP: [icmp, icmp[:1] + ({**icmp[1], 'icmpTypeNumber': 0},)],
                TERM_ICMPV6: [icmpv6],
            },
        }
        headers = {'inet': HEADER_INET, 'inet6': HEADER_INET6, 'mixed': HEADER_MIXED}
        for af, cases in expected.items():
            for term, want in cases.items():
                with self.subTest(af=af, term=term.split()[1]):
                    entries = self._entries(headers[af], term)
                    self.assertEqual([(e['type'], e['ipEntry']) for e in entries], want)

    def testMixedKeepsTermOrder(self):
        """mixed renders each term for both AFs before the next term."""
        entries = self._entries(HEADER_MIXED, TERM_SADDR + TERM_DENY)
        self.assertEqual(
            [(e['description'], e['type']) for e in entries],
            [
                ('term-saddr', 'IPv4'),
                ('term-saddr', 'IPv6'),
                ('term-deny', 'IPv4'),
                ('term-deny', 'IPv6'),
            ],
        )

    # -----------------------------------------------------------------------
    # Protocols and ports
    # -----------------------------------------------------------------------

    def testSourcePort(self):
        self.assertEqual(
            self._ip_entries(HEADER_INET, TERM_SPORT),
            [
                {
                    'action': 'Accept',
                    'protocolNumber': 6,
                    'sourcePortOperator': 'Equals',
                    'sourcePortNumber': 179,
                }
            ],
        )

    @capture.stdout
    def testDestinationPortMultiProtocol(self):
        acl = self._make_acl(HEADER_INET, TERM_DPORT_MULTI_PROTO)
        entries = [e['ipEntry'] for e in self._resource(acl)['spec']['entries']]
        self.assertEqual([e['protocolNumber'] for e in entries], [6, 17])
        for entry in entries:
            self.assertEqual(entry['destinationPortOperator'], 'Equals')
            self.assertEqual(entry['destinationPortNumber'], 53)
        print(acl)

    def testPortRange(self):
        entries = self._ip_entries(HEADER_INET, TERM_PORT_RANGE)
        self.assertEqual(entries[0]['destinationPortRange'], '1024-65535')
        self.assertNotIn('destinationPortOperator', entries[0])

    # -----------------------------------------------------------------------
    # ICMP
    # -----------------------------------------------------------------------

    @capture.stdout
    def testIcmp(self):
        acl = self._make_acl(HEADER_INET, TERM_ICMP)
        entries = [e['ipEntry'] for e in self._resource(acl)['spec']['entries']]
        self.assertEqual([e['icmpTypeNumber'] for e in entries], [8, 0])
        print(acl)

    def testIcmpCode(self):
        self.assertEqual(
            self._ip_entries(HEADER_INET, TERM_ICMP_CODE),
            [{'action': 'Accept', 'protocolNumber': 1, 'icmpTypeNumber': 3, 'icmpCodes': [3, 4]}],
        )

    # -----------------------------------------------------------------------
    # Options
    # -----------------------------------------------------------------------

    def testTcpFlags(self):
        tcp_est = {'action': 'Accept', 'protocolNumber': 6, 'tcpFlags': 'ACK|RST'}
        cases = {
            TERM_TCP_EST: [tcp_est],
            TERM_TCP_EST_NO_PROTO: [tcp_est],
            TERM_EST_TCP: [tcp_est],
            TERM_TCP_INITIAL: [{'action': 'Accept', 'protocolNumber': 6, 'tcpFlags': 'SYN'}],
        }
        for term, want in cases.items():
            with self.subTest(term.split()[1]):
                self.assertEqual(self._ip_entries(HEADER_INET, term), want)

    def testEstablishedUdp(self):
        """established on UDP matches replies on ephemeral ports, unless ports are set."""
        self.assertEqual(
            self._ip_entries(HEADER_INET, TERM_EST_UDP),
            [{'action': 'Accept', 'protocolNumber': 17, 'destinationPortRange': '1024-65535'}],
        )
        entry = self._ip_entries(HEADER_INET, TERM_EST_UDP_DPORT)[0]
        self.assertEqual(entry['destinationPortNumber'], 53)
        self.assertNotIn('tcpFlags', entry)

    def testEstablishedErrors(self):
        cases = {
            TERM_TCP_EST_UDP: nokiaeda.TcpEstablishedWithNonTcpError,
            TERM_EST_NO_PROTO: nokiaeda.EstablishedWithNoProtocolError,
            TERM_EST_ICMP: nokiaeda.EstablishedWithNonTcpUdpError,
        }
        for term, error in cases.items():
            with self.subTest(term.split()[1]):
                with self.assertRaises(error):
                    self._make_acl(HEADER_INET, term)

    def testFragments(self):
        self.assertEqual(
            self._ip_entries(HEADER_INET, TERM_FRAGMENTS), [{'action': 'Drop', 'fragment': True}]
        )
        self.assertEqual(
            self._ip_entries(HEADER_INET, TERM_FIRST_FRAGMENT),
            [{'action': 'Drop', 'firstFragment': True}],
        )

    def testLogging(self):
        self.assertEqual(
            self._ip_entries(HEADER_INET, TERM_LOGGING), [{'action': 'Drop', 'log': True}]
        )
        self.assertEqual(
            self._ip_entries(HEADER_INET, TERM_LOGGING_DISABLE), [{'action': 'Drop'}]
        )

    def testPolicerAndCounterIgnored(self):
        self.assertEqual(
            self._ip_entries(HEADER_INET, TERM_POLICER_COUNTER), [{'action': 'Accept'}]
        )

    # -----------------------------------------------------------------------
    # Comments
    # -----------------------------------------------------------------------

    @capture.stdout
    def testTermComments(self):
        """Term comments are YAML comments above the first entry of the term only."""
        acl = self._make_acl(HEADER_MIXED, TERM_COMMENTS + TERM_DENY)
        output = str(acl)
        self.assertEqual(output.count('# first comment - NET-1'), 1)
        self.assertEqual(output.count('# second comment'), 1)
        self.assertLess(output.index('# second comment'), output.index('term-comments'))
        # Comments are not part of the data.
        self.assertNotIn('NET-1', str(self._resource(acl)))
        print(acl)


if __name__ == '__main__':
    absltest.main()
