# Copyright 2025 Aerleon Project Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unittest for NVUE API ACL rendering module."""

import json

from absl.testing import absltest

from aerleon.lib import nacaddr, naming, nvueapi, policy
from tests.regression_utils import capture

GOOD_HEADER_IPV4 = """
header {
  comment:: "this is a test nvue acl"
  target:: nvueapi test-filter ipv4
}
"""

GOOD_HEADER_IPV6 = """
header {
  comment:: "this is a test nvue ipv6 acl"  
  target:: nvueapi test-filter-v6 ipv6
}
"""

GOOD_HEADER_MIXED = """
header {
  comment:: "this is a test nvue mixed acl"
  target:: nvueapi test-filter-mixed mixed
}
"""

GOOD_HEADER_MAC = """
header {
  comment:: "this is a test nvue mac acl"
  target:: nvueapi test-filter-mac mac
}
"""

GOOD_TERM_1 = """
term good-term-1 {
  comment:: "DNS access from corp."
  source-address:: CORP_EXTERNAL
  destination-port:: DNS
  protocol:: udp tcp
  action:: accept
}
"""

GOOD_TERM_2 = """
term good-term-2 {
  comment:: "HTTP access from corp."
  source-address:: CORP_EXTERNAL  
  destination-port:: HTTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_DENY = """
term deny-all {
  comment:: "Default deny rule."
  action:: deny
}
"""

GOOD_TERM_IPV6 = """
term good-term-ipv6 {
  comment:: "Allow IPv6 traffic."
  source-address:: IPV6_INTERNAL
  destination-port:: HTTP
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_ICMP = """
term test-icmp {
  comment:: "ICMP echo-request"
  protocol:: icmp
  icmp-type:: echo-request
  action:: accept
}
"""

GOOD_TERM_ICMPV6 = """
term test-icmpv6 {
  comment:: "ICMPv6 echo-request"
  protocol:: icmpv6
  icmp-type:: echo-request
  action:: accept
}
"""

GOOD_TERM_LOG = """
term test-log {
  comment:: "Log all traffic"
  logging:: True
  action:: accept
}
"""

GOOD_TERM_TCP_ESTABLISHED = """
term test-tcp-established {
  comment:: "Allow established TCP connections"
  destination-port:: HTTP
  protocol:: tcp
  option:: tcp-established
  action:: accept
}
"""

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_port',
    'expiration',
    'icmp_type',
    'logging',
    'name',
    'option',
    'platform',
    'platform_exclude',
    'protocol',
    'source_address',
    'source_port',
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'next'},
}

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2

TEST_IPS = [nacaddr.IP('10.2.3.4/32'), nacaddr.IP('2001:4860:8000::5/128')]

TEST_IPV4_IPS = [nacaddr.IP('10.2.3.4/32')]

TEST_IPV6_IPS = [nacaddr.IP('2001:4860:8000::5/128')]


class NvueApiTest(absltest.TestCase):

    def setUp(self):
        super().setUp()
        self.naming = naming.Naming()

    @capture.stdout
    def testGenericTerm(self):
        """Test a basic term."""
        self.naming._ParseLine('CORP_EXTERNAL = 10.2.3.4/32 2001:4860:8000::5/128', 'networks')
        self.naming._ParseLine('DNS = 53/tcp 53/udp', 'services')

        pol = policy.ParsePolicy(GOOD_HEADER_IPV4 + GOOD_TERM_1, self.naming)
        output = str(nvueapi.NvueApi(pol, EXP_INFO))
        
        # Verify it's valid JSON
        config = json.loads(output)
        
        # Check basic structure
        self.assertIn('acl', config)
        self.assertIn('test-filter', config['acl'])
        
        acl_config = config['acl']['test-filter']
        self.assertEqual(acl_config['type'], 'ipv4')
        self.assertIn('rule', acl_config)
        
        # Check rule content
        rules = acl_config['rule']
        self.assertTrue(len(rules) > 0)
        
        # First rule should be our DNS rule (action is now an object)
        first_rule = rules['10']
        self.assertIn('permit', first_rule['action'])
        self.assertIn('match', first_rule)
        self.assertIn('ip', first_rule['match'])
        
        ip_match = first_rule['match']['ip']
        self.assertIn('source-ip', ip_match)
        self.assertIn('dest-port', ip_match)
        
        print(output)

    @capture.stdout
    def testMultipleTerms(self):
        """Test multiple terms in one ACL."""
        self.naming._ParseLine('CORP_EXTERNAL = 10.2.3.4/32', 'networks')
        self.naming._ParseLine('DNS = 53/tcp 53/udp', 'services')
        self.naming._ParseLine('HTTP = 80/tcp', 'services')

        pol = policy.ParsePolicy(
            GOOD_HEADER_IPV4 + GOOD_TERM_1 + GOOD_TERM_2 + GOOD_TERM_DENY, 
            self.naming
        )
        output = str(nvueapi.NvueApi(pol, EXP_INFO))
        
        config = json.loads(output)
        rules = config['acl']['test-filter']['rule']
        
        # Should have 4 rules now (DNS TCP+UDP, HTTP, DENY = 4 total)
        self.assertEqual(len(rules), 4)
        self.assertIn('10', rules)  # DNS UDP
        self.assertIn('20', rules)  # DNS TCP
        self.assertIn('30', rules)  # HTTP
        self.assertIn('40', rules)  # DENY
        
        # Check the deny rule (now at position 40)
        deny_rule = rules['40']
        self.assertIn('deny', deny_rule['action'])
        
        print(output)

    @capture.stdout
    def testIPv6Term(self):
        """Test IPv6 ACL generation."""
        self.naming._ParseLine('IPV6_INTERNAL = 2001:4860:8000::5/128', 'networks')
        self.naming._ParseLine('HTTP = 80/tcp', 'services')

        pol = policy.ParsePolicy(GOOD_HEADER_IPV6 + GOOD_TERM_IPV6, self.naming)
        output = str(nvueapi.NvueApi(pol, EXP_INFO))
        
        config = json.loads(output)
        acl_config = config['acl']['test-filter-v6']
        
        self.assertEqual(acl_config['type'], 'ipv6')
        
        print(output)

    def testMixedAddressFamilyError(self):
        """Test that mixed IPv4/IPv6 ACL raises an error."""
        self.naming._ParseLine('CORP_EXTERNAL = 10.2.3.4/32 2001:4860:8000::5/128', 'networks')
        self.naming._ParseLine('DNS = 53/tcp 53/udp', 'services')

        pol = policy.ParsePolicy(GOOD_HEADER_MIXED + GOOD_TERM_1, self.naming)
        
        # NVUE doesn't support mixed address family ACLs
        with self.assertRaises(nvueapi.UnsupportedNvueFilterError) as context:
            nvueapi.NvueApi(pol, EXP_INFO)
        
        self.assertIn('mixed address family', str(context.exception))

    def testMacAddressFamilyError(self):
        """Test that MAC ACL raises an error since Aerleon doesn't support MAC ACLs."""
        pol = policy.ParsePolicy(GOOD_HEADER_MAC + """
term allow-mac {
  comment:: "Allow specific MAC addresses"
  action:: accept
}
""", self.naming)
        
        # Aerleon doesn't support MAC ACLs
        with self.assertRaises(nvueapi.UnsupportedNvueFilterError) as context:
            nvueapi.NvueApi(pol, EXP_INFO)
        
        self.assertIn('MAC ACLs are not supported', str(context.exception))

    def testBuildTokens(self):
        """Test that we can build tokens correctly."""
        self.naming._ParseLine('CORP_EXTERNAL = 10.2.3.4/32', 'networks')
        self.naming._ParseLine('DNS = 53/tcp', 'services')
        pol1 = nvueapi.NvueApi(policy.ParsePolicy(GOOD_HEADER_IPV4 + GOOD_TERM_1,
                                                  self.naming), EXP_INFO)
        st, sst = pol1._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    @capture.stdout
    def testIcmpTerm(self):
        """Test ICMP rule generation."""
        pol = policy.ParsePolicy(GOOD_HEADER_IPV4 + GOOD_TERM_ICMP, self.naming)
        output = str(nvueapi.NvueApi(pol, EXP_INFO))
        
        config = json.loads(output)
        acl_config = config['acl']['test-filter']
        
        self.assertEqual(acl_config['type'], 'ipv4')
        
        # Check ICMP rule content
        rules = acl_config['rule']
        icmp_rule = rules['10']
        self.assertIn('permit', icmp_rule['action'])
        self.assertIn('match', icmp_rule)
        self.assertIn('ip', icmp_rule['match'])
        
        ip_match = icmp_rule['match']['ip']
        self.assertEqual(ip_match['protocol'], 'icmp')
        self.assertEqual(ip_match['icmp-type'], 'echo-request')
        
        print(output)

    @capture.stdout  
    def testIcmpv6Term(self):
        """Test ICMPv6 rule generation."""
        pol = policy.ParsePolicy(GOOD_HEADER_IPV6 + GOOD_TERM_ICMPV6, self.naming)
        output = str(nvueapi.NvueApi(pol, EXP_INFO))
        
        config = json.loads(output)
        acl_config = config['acl']['test-filter-v6']
        
        self.assertEqual(acl_config['type'], 'ipv6')
        
        # Check ICMPv6 rule content  
        rules = acl_config['rule']
        icmpv6_rule = rules['10']
        self.assertIn('permit', icmpv6_rule['action'])
        self.assertIn('match', icmpv6_rule)
        self.assertIn('ip', icmpv6_rule['match'])
        
        ip_match = icmpv6_rule['match']['ip']
        self.assertEqual(ip_match['protocol'], 'icmpv6')
        self.assertEqual(ip_match['icmpv6-type'], 'echo-request')
        
        print(output)

    @capture.stdout
    def testMultipleAddresses(self):
        """Test multiple address expansion into separate rules."""
        self.naming._ParseLine('SERVERS = 192.168.1.10/32 192.168.1.20/32', 'networks')
        self.naming._ParseLine('CLIENTS = 10.0.1.0/24 10.0.2.0/24', 'networks')
        self.naming._ParseLine('HTTP = 80/tcp', 'services')

        pol = policy.ParsePolicy(GOOD_HEADER_IPV4 + """
term allow-web-multi {
  comment:: "Allow HTTP from multiple clients to multiple servers"
  source-address:: CLIENTS
  destination-address:: SERVERS
  destination-port:: HTTP
  protocol:: tcp
  action:: accept
}
""", self.naming)
        output = str(nvueapi.NvueApi(pol, EXP_INFO))
        
        config = json.loads(output)
        rules = config['acl']['test-filter']['rule']
        
        # Should have 4 rules (2 clients × 2 servers = 4 combinations)
        self.assertEqual(len(rules), 4)
        
        # Check that each rule has single addresses
        for rule_num, rule in rules.items():
            self.assertIn('match', rule)
            self.assertIn('ip', rule['match'])
            ip_match = rule['match']['ip']
            
            # Each rule should have exactly one source and dest IP
            self.assertIn('source-ip', ip_match)
            self.assertIn('dest-ip', ip_match)
            
            # Should not contain commas (indicating single address)
            self.assertNotIn(',', ip_match['source-ip'])
            self.assertNotIn(',', ip_match['dest-ip'])
        
        print(output)

    @capture.stdout
    def testLogAction(self):
        """Test logging attribute maps to log action."""
        pol = policy.ParsePolicy(GOOD_HEADER_IPV4 + GOOD_TERM_LOG, self.naming)
        output = str(nvueapi.NvueApi(pol, EXP_INFO))
        
        config = json.loads(output)
        acl_config = config['acl']['test-filter']
        
        self.assertEqual(acl_config['type'], 'ipv4')
        
        # Check log rule content - logging:: True should map to action: log
        rules = acl_config['rule']
        log_rule = rules['10']
        self.assertIn('log', log_rule['action'])
        self.assertEqual(log_rule['remark'], 'Log all traffic')
        
        print(output)

    @capture.stdout
    def testTcpEstablished(self):
        """Test TCP established state matching."""
        self.naming._ParseLine('HTTP = 80/tcp', 'services')
        
        pol = policy.ParsePolicy(GOOD_HEADER_IPV4 + GOOD_TERM_TCP_ESTABLISHED, self.naming)
        output = str(nvueapi.NvueApi(pol, EXP_INFO))
        
        config = json.loads(output)
        acl_config = config['acl']['test-filter']
        
        self.assertEqual(acl_config['type'], 'ipv4')
        
        # Check TCP established rule content
        rules = acl_config['rule']
        tcp_rule = rules['10']
        self.assertIn('permit', tcp_rule['action'])
        self.assertIn('match', tcp_rule)
        
        # Check that both ip and tcp sections exist
        match = tcp_rule['match']
        self.assertIn('ip', match)
        self.assertIn('tcp', match)
        
        # Verify IP match conditions
        ip_match = match['ip']
        self.assertEqual(ip_match['protocol'], 'tcp')
        self.assertEqual(ip_match['dest-port'], '80')
        
        # Verify TCP state match
        tcp_match = match['tcp']
        self.assertEqual(tcp_match['state'], 'established')
        
        print(output)

if __name__ == '__main__':
    absltest.main()