# Copyright 2024 Aerleon Project Authors.
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

"""Regression tests for the Nokia SR OS JSON filter generator."""

import json

from absl.testing import absltest

from aerleon.lib import naming, nokiasros, policy
from tests.regression_utils import capture

# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

HEADER_INET = """
header {
  target:: nokiasros my-filter inet
}
"""

HEADER_INET_ID = """
header {
  target:: nokiasros 100 inet
}
"""

HEADER_INET6 = """
header {
  target:: nokiasros my-filter inet6
}
"""

HEADER_MIXED = """
header {
  target:: nokiasros my-filter mixed
}
"""

HEADER_ACCEPT = """
header {
  target:: nokiasros my-filter inet accept
}
"""

HEADER_PKTLEN = """
header {
  target:: nokiasros my-filter inet pktlenfilter
}
"""

HEADER_SYSLOG = """
header {
  target:: nokiasros my-filter inet syslog-profile 200
}
"""

HEADER_CPM = """
header {
  target:: nokiasros my-cpm cpm inet
}
"""

HEADER_CPM_INET6 = """
header {
  target:: nokiasros my-cpm cpm inet6
}
"""

HEADER_INET_COMMENT = """
header {
  comment:: "my filter description"
  target:: nokiasros my-filter inet
}
"""

HEADER_CPM_COMMENT = """
header {
  comment:: "my cpm description"
  target:: nokiasros my-cpm cpm inet
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

TERM_SADDR = """
term term-saddr {
  source-address:: CORP_EXTERNAL
  action:: accept
}
"""

TERM_DADDR = """
term term-daddr {
  destination-address:: CORP_EXTERNAL
  action:: accept
}
"""

TERM_SPORT = """
term term-sport {
  protocol:: tcp
  source-port:: DNS
  action:: accept
}
"""

TERM_DPORT = """
term term-dport {
  protocol:: tcp
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

TERM_MULTI_PROTO = """
term term-multi-proto {
  protocol:: tcp udp
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
  icmp-type:: neighbor-solicit neighbor-advertisement
  action:: accept
}
"""

TERM_ICMP_CODE = """
term term-icmp-code {
  protocol:: icmp
  icmp-type:: unreachable
  icmp-code:: 3
  action:: accept
}
"""

TERM_TTL = """
term term-ttl {
  ttl:: 5
  action:: deny
}
"""

TERM_HOP_LIMIT = """
term term-hop-limit {
  hop-limit:: 10
  action:: deny
}
"""

TERM_LOGGING = """
term term-logging {
  logging:: syslog
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

TERM_FRAGMENT = """
term term-fragment {
  option:: fragments
  action:: deny
}
"""

TERM_COMMENT = """
term term-comment {
  comment:: "my comment text"
  action:: deny
}
"""

TERM_ESP = """
term term-esp {
  protocol:: esp
  action:: accept
}
"""

BAD_TERM_TCP_EST = """
term bad-term-tcp-est {
  protocol:: udp
  option:: tcp-established
  action:: accept
}
"""

EXP_INFO = 2


class NokiaSROSTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = naming.Naming()
        self.naming._ParseLine('CORP_EXTERNAL = 10.2.3.4/32 2001:4860:8000::5/128', 'networks')
        self.naming._ParseLine('DNS = 53/tcp 53/udp', 'services')
        self.naming._ParseLine('BGP = 179/tcp', 'services')
        self.naming._ParseLine('HIGH_PORTS = 1024-65535/tcp 1024-65535/udp', 'services')

    def _make_acl(self, header, term):
        return nokiasros.NokiaSROS(policy.ParsePolicy(header + term, self.naming), EXP_INFO)

    def _entries(self, header, term):
        return json.loads(str(self._make_acl(header, term)))['nokia-conf:entry']

    # -----------------------------------------------------------------------
    # Filter-level structure
    # -----------------------------------------------------------------------

    @capture.stdout
    def testInetFilter(self):
        acl = self._make_acl(HEADER_INET, TERM_DENY)
        output = json.loads(str(acl))
        self.assertEqual(output['nokia-conf:scope'], 'template')
        self.assertEqual(output['nokia-conf:default-action'], 'drop')
        self.assertEqual(output['nokia-conf:filter-name'], 'my-filter')
        self.assertNotIn('nokia-conf:filter-id', output)
        self.assertNotIn('nokia-conf:type', output)
        print(acl)

    @capture.stdout
    def testInetFilterNumericId(self):
        acl = self._make_acl(HEADER_INET_ID, TERM_DENY)
        output = json.loads(str(acl))
        self.assertEqual(output['nokia-conf:filter-id'], 100)
        self.assertNotIn('nokia-conf:filter-name', output)
        print(acl)

    @capture.stdout
    def testDefaultActionAccept(self):
        acl = self._make_acl(HEADER_ACCEPT, TERM_DENY)
        output = json.loads(str(acl))
        self.assertEqual(output['nokia-conf:default-action'], 'accept')
        print(acl)

    @capture.stdout
    def testPktlenfilter(self):
        acl = self._make_acl(HEADER_PKTLEN, TERM_DENY)
        output = json.loads(str(acl))
        self.assertEqual(output['nokia-conf:scope'], 'template')
        self.assertEqual(output['nokia-conf:type'], 'packet-length')
        print(acl)

    @capture.stdout
    def testCpmFilter(self):
        acl = self._make_acl(HEADER_CPM, TERM_DENY)
        output = json.loads(str(acl))
        self.assertEqual(output['nokia-conf:admin-state'], 'enable')
        self.assertNotIn('nokia-conf:scope', output)
        self.assertNotIn('nokia-conf:default-action', output)
        print(acl)

    def testFilterDescriptionFromComment(self):
        acl = self._make_acl(HEADER_INET_COMMENT, TERM_DENY)
        output = json.loads(str(acl))
        self.assertEqual(output['nokia-conf:description'], 'my filter description')

    def testFilterNoDescriptionWithoutComment(self):
        acl = self._make_acl(HEADER_INET, TERM_DENY)
        output = json.loads(str(acl))
        self.assertNotIn('nokia-conf:description', output)

    def testCpmFilterDescriptionFromComment(self):
        acl = self._make_acl(HEADER_CPM_COMMENT, TERM_DENY)
        output = json.loads(str(acl))
        self.assertNotIn('nokia-conf:description', output)
        entries = output['nokia-conf:entry']
        self.assertEqual(entries[0]['description'], 'my cpm description | term-deny')

    # -----------------------------------------------------------------------
    # Entry-id numbering
    # -----------------------------------------------------------------------

    def testEntryIdFirstTerm(self):
        entries = self._entries(HEADER_INET, TERM_DENY)
        self.assertEqual(entries[0]['entry-id'], 10000)

    def testEntryIdSecondTerm(self):
        entries = self._entries(HEADER_INET, TERM_DENY + TERM_LOGGING)
        self.assertEqual(entries[0]['entry-id'], 10000)
        self.assertEqual(entries[1]['entry-id'], 20000)

    def testEntryIdMultipleEntriesPerTerm(self):
        # ICMP with two types → two entries, both within term 1's block.
        entries = self._entries(HEADER_INET, TERM_ICMP)
        self.assertEqual(entries[0]['entry-id'], 10000)
        self.assertEqual(entries[1]['entry-id'], 10001)

    # -----------------------------------------------------------------------
    # Match: addresses
    # -----------------------------------------------------------------------

    @capture.stdout
    def testInetSaddr(self):
        acl = self._make_acl(HEADER_INET, TERM_SADDR)
        entries = json.loads(str(acl))['nokia-conf:entry']
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['match']['src-ip'], {'address': '10.2.3.4/32'})
        print(acl)

    @capture.stdout
    def testInetDaddr(self):
        acl = self._make_acl(HEADER_INET, TERM_DADDR)
        entries = json.loads(str(acl))['nokia-conf:entry']
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['match']['dst-ip'], {'address': '10.2.3.4/32'})
        print(acl)

    @capture.stdout
    def testInet6Saddr(self):
        """inet6 filter selects only IPv6 addresses."""
        acl = self._make_acl(HEADER_INET6, TERM_SADDR)
        entries = json.loads(str(acl))['nokia-conf:entry']
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['match']['src-ip'], {'address': '2001:4860:8000::5/128'})
        print(acl)

    @capture.stdout
    def testMixedFilter(self):
        """Mixed filter produces one entry for each address family."""
        acl = self._make_acl(HEADER_MIXED, TERM_SADDR)
        entries = json.loads(str(acl))['nokia-conf:entry']
        self.assertEqual(len(entries), 2)
        addrs = {e['match']['src-ip']['address'] for e in entries}
        self.assertIn('10.2.3.4/32', addrs)
        self.assertIn('2001:4860:8000::5/128', addrs)
        print(acl)

    # -----------------------------------------------------------------------
    # Match: ports
    # -----------------------------------------------------------------------

    @capture.stdout
    def testSport(self):
        acl = self._make_acl(HEADER_INET, TERM_SPORT)
        entries = json.loads(str(acl))['nokia-conf:entry']
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['match']['src-port'], {'eq': 53})
        print(acl)

    @capture.stdout
    def testDport(self):
        acl = self._make_acl(HEADER_INET, TERM_DPORT)
        entries = json.loads(str(acl))['nokia-conf:entry']
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['match']['dst-port'], {'eq': 53})
        print(acl)

    def testPortRange(self):
        entries = self._entries(HEADER_INET, TERM_PORT_RANGE)
        self.assertEqual(entries[0]['match']['dst-port'], {'range': {'start': 1024, 'end': 65535}})

    # -----------------------------------------------------------------------
    # Match: protocol
    # -----------------------------------------------------------------------

    def testInetUsesProtocolKey(self):
        entries = self._entries(HEADER_INET, TERM_SPORT)
        self.assertIn('protocol', entries[0]['match'])
        self.assertNotIn('next-header', entries[0]['match'])

    def testInet6UsesNextHeaderKey(self):
        entries = self._entries(HEADER_INET6, TERM_ICMPV6)
        self.assertIn('next-header', entries[0]['match'])
        self.assertNotIn('protocol', entries[0]['match'])

    def testIcmpv6MappedToIpv6Icmp(self):
        entries = self._entries(HEADER_INET6, TERM_ICMPV6)
        self.assertEqual(entries[0]['match']['next-header'], 'ipv6-icmp')

    def testMultipleProtocolsGenerateMultipleEntries(self):
        entries = self._entries(HEADER_INET, TERM_MULTI_PROTO)
        protos = {e['match']['protocol'] for e in entries}
        self.assertEqual(protos, {'tcp', 'udp'})

    def testEspInetUsesNumericProtocol(self):
        entries = self._entries(HEADER_INET, TERM_ESP)
        self.assertEqual(entries[0]['match']['protocol'], 50)

    def testEspInet6UsesNumericNextHeader(self):
        entries = self._entries(HEADER_INET6, TERM_ESP)
        self.assertEqual(entries[0]['match']['next-header'], 50)

    # -----------------------------------------------------------------------
    # Match: ICMP types and codes
    # -----------------------------------------------------------------------

    @capture.stdout
    def testIcmp(self):
        """ICMPv4 type names resolve to correct numeric codes."""
        acl = self._make_acl(HEADER_INET, TERM_ICMP)
        entries = json.loads(str(acl))['nokia-conf:entry']
        types = {e['match']['icmp']['type'] for e in entries}
        self.assertEqual(types, {8, 0})  # echo-request=8, echo-reply=0
        print(acl)

    @capture.stdout
    def testIcmpV6(self):
        """ICMPv6 type names resolve to correct numeric codes."""
        acl = self._make_acl(HEADER_INET6, TERM_ICMPV6)
        entries = json.loads(str(acl))['nokia-conf:entry']
        types = {e['match']['icmp']['type'] for e in entries}
        self.assertEqual(types, {135, 136})  # neighbor-solicit=135, neighbor-advertisement=136
        print(acl)

    def testIcmpCode(self):
        entries = self._entries(HEADER_INET, TERM_ICMP_CODE)
        self.assertEqual(entries[0]['match']['icmp']['code'], 3)

    # -----------------------------------------------------------------------
    # Match: TTL / hop-limit
    # -----------------------------------------------------------------------

    @capture.stdout
    def testTtlInet(self):
        """ttl renders as 'ttl' key for IPv4."""
        acl = self._make_acl(HEADER_INET, TERM_TTL)
        entries = json.loads(str(acl))['nokia-conf:entry']
        self.assertEqual(entries[0]['match']['ttl'], {'lt': 5})
        self.assertNotIn('hop-limit', entries[0]['match'])
        print(acl)

    @capture.stdout
    def testTtlInet6(self):
        """ttl renders as 'hop-limit' key for IPv6."""
        acl = self._make_acl(HEADER_INET6, TERM_TTL)
        entries = json.loads(str(acl))['nokia-conf:entry']
        self.assertEqual(entries[0]['match']['hop-limit'], {'lt': 5})
        self.assertNotIn('ttl', entries[0]['match'])
        print(acl)

    def testHopLimit(self):
        entries = self._entries(HEADER_INET6, TERM_HOP_LIMIT)
        self.assertEqual(entries[0]['match']['hop-limit'], {'lt': 10})

    # -----------------------------------------------------------------------
    # Match: options
    # -----------------------------------------------------------------------

    def testTcpEstablishedIpFilter(self):
        """tcp-established renders as leaf in ip-filter mode."""
        entries = self._entries(HEADER_INET, TERM_TCP_EST)
        self.assertIn('tcp-established', entries[0]['match'])
        self.assertNotIn('tcp-flags', entries[0]['match'])

    def testTcpEstablishedCpmMode(self):
        """tcp-established renders as tcp-flags {ack: true} in CPM mode."""
        entries = self._entries(HEADER_CPM, TERM_TCP_EST)
        self.assertTrue(entries[0]['match']['tcp-flags']['ack'])
        self.assertNotIn('tcp-established', entries[0]['match'])

    def testFragment(self):
        entries = self._entries(HEADER_INET, TERM_FRAGMENT)
        self.assertEqual(entries[0]['match']['fragment'], 'true')

    # -----------------------------------------------------------------------
    # Action
    # -----------------------------------------------------------------------

    def testActionAccept(self):
        entries = self._entries(HEADER_INET, TERM_ACCEPT)
        self.assertIn('accept', entries[0]['action'])
        self.assertNotIn('drop', entries[0]['action'])

    def testActionDeny(self):
        entries = self._entries(HEADER_INET, TERM_DENY)
        self.assertIn('drop', entries[0]['action'])
        self.assertNotIn('accept', entries[0]['action'])

    # -----------------------------------------------------------------------
    # Logging
    # -----------------------------------------------------------------------

    def testLoggingDefaultProfile(self):
        entries = self._entries(HEADER_INET, TERM_LOGGING)
        self.assertEqual(entries[0]['log'], 102)

    def testLoggingCustomProfile(self):
        entries = self._entries(HEADER_SYSLOG, TERM_LOGGING)
        self.assertEqual(entries[0]['log'], 200)

    def testNoLogFieldWithoutLogging(self):
        entries = self._entries(HEADER_INET, TERM_DENY)
        self.assertNotIn('log', entries[0])

    # -----------------------------------------------------------------------
    # Description
    # -----------------------------------------------------------------------

    def testDescriptionFromTermName(self):
        entries = self._entries(HEADER_INET, TERM_DENY)
        self.assertEqual(entries[0]['description'], 'term-deny')

    def testDescriptionFromComment(self):
        entries = self._entries(HEADER_INET, TERM_COMMENT)
        self.assertEqual(entries[0]['description'], 'my comment text')

    # -----------------------------------------------------------------------
    # No-match entry (no match block when term has no match conditions)
    # -----------------------------------------------------------------------

    def testNoMatchBlock(self):
        entries = self._entries(HEADER_INET, TERM_DENY)
        self.assertNotIn('match', entries[0])

    # -----------------------------------------------------------------------
    # Multiple filters → JSON list
    # -----------------------------------------------------------------------

    def testMultipleFiltersProduceList(self):
        pol_str = HEADER_INET + TERM_DENY + HEADER_INET6 + TERM_DENY
        acl = nokiasros.NokiaSROS(policy.ParsePolicy(pol_str, self.naming), EXP_INFO)
        output = json.loads(str(acl))
        self.assertIsInstance(output, list)
        self.assertEqual(len(output), 2)

    # -----------------------------------------------------------------------
    # Error cases
    # -----------------------------------------------------------------------

    def testTcpEstablishedWithNonTcpError(self):
        acl = policy.ParsePolicy(HEADER_INET + BAD_TERM_TCP_EST, self.naming)
        with self.assertRaises(nokiasros.TcpEstablishedWithNonTcpError):
            _ = nokiasros.NokiaSROS(acl, EXP_INFO)


if __name__ == '__main__':
    absltest.main()
