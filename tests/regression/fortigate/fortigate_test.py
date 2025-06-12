"""Regressopn test for Fortigate module."""
import textwrap
from unittest import mock

from absl.testing import absltest, parameterized

from aerleon.lib import fortigate, naming, policy
from aerleon.lib import yaml as yaml_frontend
from tests.regression_utils import capture

GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: fortigate from-zone port1 to-zone port2
}
"""
YAML_GOOD_HEADER_1 = """
filters:
- header:
    comment: this is a test acl
    targets:
      fortigate: from-zone port1 to-zone port2
  terms:
"""

INET_HEADER = """
header {
  comment:: "this is a test acl"
  target:: fortigate from-zone port1 to-zone port2 inet
  }
"""
YAML_INET_HEADER = """
filters:
- header:
    comment: this is a test acl
    targets:
      fortigate: from-zone port1 to-zone port2 inet
  terms:
"""
INET6_HEADER = """
header {
  comment:: "this is a test acl"
  target:: fortigate from-zone port1 to-zone port2 inet6
  }
"""
YAML_INET6_HEADER = """
filters:
- header:
    comment: this is a test acl
    targets:
      fortigate: from-zone port1 to-zone port2 inet6
  terms:
"""
MIXED_HEADER = """
header {
  comment:: "this is a test acl"
  target:: fortigate from-zone port1 to-zone port2 mixed
  }
"""
YAML_MIXED_HEADER = """
filters:
- header:
    comment: this is a test acl
    targets:
      fortigate: from-zone port1 to-zone port2 mixed
  terms:
"""
HEADER_BAD_NUMBER_OF_INTERFACES = """
header {
  comment:: "this is a test acl"
  target:: fortigate from-zone port1
  }
"""
YAML_HEADER_BAD_NUMBER_OF_INTERFACES = """
filters:
- header:
    comment: this is a test acl
    targets:
      fortigate: from-zone port1
  terms:
"""
LOCAL_POLICY = """
header {
  comment:: "this is a test acl"
  target:: fortigate from-zone port1 to-zone local-in-policy inet
}
"""
YAML_LOCAL_POLICY = """
filters:
- header:
    comment: this is a test acl
    targets:
      fortigate: from-zone port1 to-zone local-in-policy inet
  terms:
"""
LOCAL_POLICY_V6 = """
header {
  comment:: "this is a test acl"
  target:: fortigate from-zone port1 to-zone local-in-policy inet6
}
"""
YAML_LOCAL_POLICY_V6 = """
filters:
- header:
    comment: this is a test acl
    targets:
      fortigate: from-zone port1 to-zone local-in-policy inet6
  terms:
"""
GOOD_TERM_1 = """
term good-term-1 {
  source-address:: FOO GOO
  destination-address:: BAR
  source-port:: HTTP
  destination-port:: DNS
  protocol:: tcp udp
  action:: accept
}
"""
YAML_GOOD_TERM_1 = """
  - name: good-term-1
    source-address: FOO GOO
    destination-address: BAR
    source-port: HTTP
    destination-port: DNS
    protocol: tcp udp
    action: accept
"""
ALL_IPS = """
term good-term-1 {
  source-port:: HTTP
  destination-port:: DNS
  protocol:: tcp
  action:: accept
}
"""
YAML_ALL_IPS = """
  - name: good-term-1
    source-port: HTTP
    destination-port: DNS
    protocol: tcp
    action: accept
"""
GOOD_TERM_2 = """
term good-term-2 {
  source-address:: FOO GOO
  destination-address:: BAR
  source-port:: HTTP
  destination-port:: DNS
  protocol:: tcp udp
  action:: accept
}
"""
YAML_GOOD_TERM_2 = """
  - name: good-term-2
    source-address: FOO GOO
    destination-address: BAR
    source-port: HTTP
    destination-port: DNS
    protocol: tcp udp
    action: accept
"""
V6_TERM = """
term good-v6-term {
  source-address:: FOO6
  destination-address:: BAR6
  source-port:: HTTP
  destination-port:: DNS
  protocol:: tcp udp
  action:: accept
}
"""
YAML_V6_TERM = """
  - name: good-v6-term
    source-address: FOO6
    destination-address: BAR6
    source-port: HTTP
    destination-port: DNS
    protocol: tcp udp
    action: accept
"""
MIXED_AF_TERM = """
term good-mixed-term {
  source-address:: MIXED_IP
  destination-address:: BAR
  source-port:: HTTP
  destination-port:: DNS
  protocol:: tcp udp
  action:: accept
}
"""
YAML_MIXED_AF_TERM = """
  - name: good-mixed-term
    source-address: MIXED_IP
    destination-address: BAR
    source-port: HTTP
    destination-port: DNS
    protocol: tcp udp
    action: accept
"""
NO_SERVICES_TERM = """
term no-services {
  source-address:: FOO
  destination-address:: BAR
  action:: accept
}
"""
YAML_NO_SERVICES_TERM = """
  - name: no-services
    source-address: FOO
    destination-address: BAR
    action: accept
"""
EXPIRED_TERM = """
term expired-term {
  source-address:: FOO
  destination-address:: BAR
  expiration:: 2010-01-01
  action:: accept
}
"""
YAML_EXPIRED_TERM = """
  - name: expired_term
    source-address: FOO
    destination-address: BAR
    expiration: 2010-01-01
    action: accept
"""
DENY_RULE = """
term deny-foo {
  source-address:: FOO
  destination-address:: FOO
  action:: deny
}
"""
YAML_DENY_RULE = """
  - name: deny-foo
    source-address: FOO
    destination-address: FOO
    action: deny
"""
COMMENT_TERM_1 = """
term good-term-1 {
  comment:: "This term tests a basic comment."
  action:: accept
}
"""
YAML_COMMENT_TERM_1 = """
  - name: good-term-1
    comment: This term tests a basic comment.
    action: accept
"""
SOURCE_EXCLUDE_TERM = """
term exclude-test-1 {
  source-address:: FOO
  source-exclude:: BAR
  action:: accept
}
"""
YAML_SOURCE_EXCLUDE_TERM = """
  - name: exclude-test-1
    source-address: FOO
    source-exclude: BAR
    action: accept
"""
DESTINATION_EXCLUDE_TERM = """
term exclude-test-2 {
  destination-address:: FOO
  destination-exclude:: BAR
  action:: accept
}
"""
YAML_DESTINATION_EXCLUDE_TERM = """
  - name: exclude-test-2
    destination-address: FOO
    destination-exclude: BAR
    action: accept
"""
OWNER_TERM = """
term good-term-1 {
  owner:: foo@invariant.tech
  action:: accept
}
"""
YAML_OWNER_TERM = """
  - name: good-term-1
    owner: "foo@invariant.tech"
    action: accept
"""
LONG_COMMENT_TERM = """
term good-term-1 {
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "This comment is over 1023 characters in length."
  comment:: "We should not see this"
  action:: accept
}
"""
YAML_LONG_COMMENT_TERM = """
  - name: good-term-1
    comment: This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. This comment is over 1023 characters in length. We should not see this
    action: accept
"""
OWNER_COMMENT_TERM = """
term good-term-1 {
  comment:: "The owner is foo at invariant."
  owner:: foo@invariant.tech
  action:: accept
}
"""
YAML_OWNER_COMMENT_TERM = """
  - name: good-term-1
    comment: The owner is foo at invariant.
    owner: "foo@invariant.tech"
    action: accept
"""
EXP_INFO = 2


class FortigateObjectGroupTest(parameterized.TestCase):
    def setUp(self):
        pass

    def testICMPService(self):
        expect = """\
    edit FOO-icmp
        set protocol ICMP
        set icmptype 10
    next"""
        self.assertMultiLineEqual(expect, str(fortigate.FortigateIcmpService('FOO', [10])))

    def testICMPServiceMultipleTypes(self):
        expect = """\
    edit FOO-icmp
        set protocol ICMP
        set icmptype 10 20 30
    next"""
        self.assertMultiLineEqual(expect, str(fortigate.FortigateIcmpService('FOO', [10, 20, 30])))

    def testTCPService(self):
        expect = """\
    edit FOO
        set tcp-portrange 80:80
    next"""
        self.assertMultiLineEqual(
            expect, str(fortigate.FortigateIPService('FOO', [(80, 80)], [(80, 80)], ['tcp']))
        )

    def testUDPService(self):
        expect = """\
    edit BAR
        set udp-portrange 80:80
    next"""
        self.assertMultiLineEqual(
            expect, str(fortigate.FortigateIPService('BAR', [(80, 80)], [(80, 80)], ['udp']))
        )

    def testBothService(self):
        expect = """\
    edit BAR
        set tcp-portrange 80:80
        set udp-portrange 80:80
    next"""
        self.assertMultiLineEqual(
            expect,
            str(fortigate.FortigateIPService('BAR', [(80, 80)], [(80, 80)], ['tcp', 'udp'])),
        )

    @parameterized.parameters(
        ([(80, 80)], [(80, 80)], "80:80"),
        ([(80, 80)], [(90, 100)], "90-100:80"),
        ([], [(90, 100)], "90-100"),
        ([], [(100, 100)], "100"),
    )
    def testGenerateServiceString(self, src, dst, expected):
        self.assertEqual(expected, fortigate.GenerateFortinetServiceString(src, dst))


class FortigateTest(parameterized.TestCase):
    """Test Fortigate module."""

    def setUp(self):
        super().setUp()
        self.naming = naming.Naming()
        self.naming._ParseLine('FOO = 10.1.1.1/32 10.1.1.2/32', 'networks')
        self.naming._ParseLine('BAR = 10.1.1.3/32 10.1.1.4/32', 'networks')
        self.naming._ParseLine('GOO = 10.1.1.9/32', 'networks')
        self.naming._ParseLine('FOO6 = 2001:db8::1/128', 'networks')
        self.naming._ParseLine('BAR6 = 2001:db8::2/128', 'networks')
        self.naming._ParseLine('MIXED_IP = 10.1.1.1/32 2001:db8::2/128', 'networks')
        self.naming._ParseLine('HTTP = 80/tcp', 'services')
        self.naming._ParseLine('DNS = 53/tcp 53/udp', 'services')
        self.naming._ParseLine('V4_A = 1.1.1.1/32 1.1.1.2/32', 'networks')
        self.naming._ParseLine('V4_B = 1.1.1.2/32 1.1.1.3/32', 'networks')
        # Superset of V4_A
        self.naming._ParseLine('V4_C = 1.1.1.1/32 1.1.1.2/32 1.1.1.3/32 1.1.1.4/32', 'networks')

        self.naming._ParseLine('V6_X = 2001:db8::1/128 2001:db8::2/128', 'networks')
        self.naming._ParseLine('V6_Y = 2001:db8::2/128 2001:db8::3/128', 'networks')
        # Superset of V6_X
        self.naming._ParseLine(
            'V6_Z = 2001:db8::1/128 2001:db8::2/128 2001:db8::3/128 2001:db8::4/128', 'networks'
        )

        # Mixed Definitions for general source/destination testing
        # Contains V4_A's first IP and V6_X's first IP
        self.naming._ParseLine('MIXED_P = 1.1.1.1/32 2001:db8::1/128', 'networks')
        # Different IPs from MIXED_P for exclusion testing
        self.naming._ParseLine('MIXED_Q = 1.1.1.3/32 2001:db8::3/128', 'networks')

    @capture.stdout
    def testNoAddressesInet6OutputsAll(self):
        pol = policy.ParsePolicy(INET6_HEADER + ALL_IPS, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)
        self.assertNotIn('srcaddr ', str(acl))
        self.assertNotIn('dstaddr ', str(acl))
        self.assertIn('set srcaddr6 "all"', str(acl))
        self.assertIn('set dstaddr6 "all"', str(acl))

    @capture.stdout
    def testNoAddressesInetOutputsAll(self):
        pol = policy.ParsePolicy(INET_HEADER + ALL_IPS, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        self.assertNotIn('srcaddr6', str(acl))
        self.assertNotIn('dstaddr6', str(acl))
        self.assertIn('set srcaddr "all"', str(acl))
        self.assertIn('set dstaddr "all"', str(acl))
        print(acl)

    @capture.stdout
    def testNoAddressesMixedOutputAll(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + ALL_IPS, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        self.assertIn('set srcaddr6 "all"', str(acl))
        self.assertIn('set dstaddr6 "all"', str(acl))
        self.assertIn('set srcaddr "all"', str(acl))
        self.assertIn('set dstaddr "all"', str(acl))
        print(acl)

    # @capture.stdout
    def testInet(self):
        pol = policy.ParsePolicy(INET_HEADER + GOOD_TERM_1, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        self.assertNotIn('srcaddr6 ', str(acl))
        self.assertNotIn('dstaddr6 ', str(acl))
        print(acl)

    @capture.stdout
    def testInet6(self):
        pol = policy.ParsePolicy(INET6_HEADER + V6_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)

    @capture.stdout
    def testInetFiltersV6(self):
        pol = policy.ParsePolicy(INET_HEADER + MIXED_AF_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        self.assertNotIn('MIXED_IP_1', str(acl))
        print(acl)

    @capture.stdout
    def testInet6FiltersV4(self):
        pol = policy.ParsePolicy(INET6_HEADER + MIXED_AF_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        self.assertNotIn('MIXED_IP_1', str(acl))
        print(acl)

    logging_test_parameters = [
        ("Disable", False, "", "set logtraffic disable"),
        ("UTM", True, "", ""),
        ("All", True, "log_traffic_mode_all", "set logtraffic all"),
        ("Start", True, "log_traffic_start_session", "set logtraffic-start enable"),
        (
            "All_Start",
            True,
            "log_traffic_mode_all log_traffic_start_session",
            "set logtraffic all\n        set logtraffic-start enable",
        ),
        ("UTM_Start", True, "log_traffic_start_session", "set logtraffic-start enable"),
        ("Disable_Start", True, "log_traffic_mode_disable log_traffic_start_session", ""),
    ]

    @parameterized.named_parameters(logging_test_parameters)
    @capture.stdout
    def testLogging(self, logging_enabled: bool, logging_options: str, expected: str):
        options = ""
        if logging_options:
            options = f"option:: {logging_options}"
        logging = ""
        if logging_enabled:
            logging = f"logging:: {logging_enabled}"
        LOGGING_TERM = f"""
        term good-term-1 {{
            action:: accept
            {logging}
            {options}
        }}
        """
        pol = policy.ParsePolicy(GOOD_HEADER_1 + LOGGING_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)
        self.assertIn(expected, str(acl))

    @capture.stdout
    def testMixedAddresses(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + MIXED_AF_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)

    @capture.stdout
    def testMultipleTerms(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1 + GOOD_TERM_2, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)

    @capture.stdout
    def testV6(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + V6_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        self.assertNotIn('srcaddr ', str(acl))
        self.assertNotIn('dstaddr ', str(acl))
        print(acl)

    def testErrorDuplicateTerm(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1 + GOOD_TERM_1, self.naming)
        with self.assertRaises(ValueError):
            fortigate.Fortigate(pol, EXP_INFO)

    @capture.stdout
    def testNoPortsOrProto(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + NO_SERVICES_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)

    @capture.stdout
    def testExpiredNotPrinted(self):
        pol = policy.ParsePolicy(
            GOOD_HEADER_1 + GOOD_TERM_1 + EXPIRED_TERM + GOOD_TERM_2, self.naming
        )
        acl = fortigate.Fortigate(pol, EXP_INFO)
        self.assertNotIn('expired-term', str(acl))
        print(acl)

    @capture.stdout
    def testDenyRule(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + DENY_RULE, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)

    bad_headers_test_parameters = [
        ("inet", "inet6"),
        ("inet6", "mixed"),
        ("mixed", "inet"),
    ]

    @parameterized.parameters(bad_headers_test_parameters)
    def testBadAddressFamilyCombos(self, address_family_one: str, address_family_two: str):
        HEADER = f"""\
        header {{
            target:: fortigate from-zone port1 to-zone port2 {address_family_one} {address_family_two}
        }}
        """
        pol = policy.ParsePolicy(HEADER + GOOD_TERM_1, self.naming)
        with self.assertRaises(ValueError):
            fortigate.Fortigate(pol, EXP_INFO)

    def testBadNumberOfInterfaces(self):
        pol = policy.ParsePolicy(HEADER_BAD_NUMBER_OF_INTERFACES + GOOD_TERM_1, self.naming)
        with self.assertRaises(ValueError):
            fortigate.Fortigate(pol, EXP_INFO)

    @capture.stdout
    def testComment(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + COMMENT_TERM_1, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)

    @capture.stdout
    def testOwner(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + OWNER_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)

    @capture.stdout
    def testLongCommentTruncated(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + LONG_COMMENT_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)
        self.assertNotIn("We should not see this", str(acl))

    @capture.stdout
    def testOwnerAndComment(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + OWNER_COMMENT_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)

    exclude_test_parameters = [
        # V4 tests
        ("V4_No_Exclude", "V4_A", ""),
        ("V4_Exclude", "V4_A", "V4_B"),
        ("V4_Exclude_V6", "V4_A", "V6_X"),
        ("V4_Exclude_Mixed", "V4_A", "MIXED_P"),
        ("V4_Exclude_Superset", "V4_A", "V4_C"),
        # #V6 tests
        ("V6_No_Exclude", "V6_X", ""),
        ("V6_Exclude", "V6_X", "V6_Y"),
        ("V6_Exclude_V4", "V6_X", "V4_A"),
        ("V6_Exclude_Mixed", "V6_X", "MIXED_P"),
        ("V6_Exclude_Superset", "V6_X", "V6_Z"),
        # #Mixed tests
        ("Mixed_No_Exclude", "MIXED_P", ""),
        ("Mixed_Exclude_V4", "MIXED_P", "V4_A"),
        ("Mixed_Exclude_V6", "MIXED_P", "V6_X"),
        ("Mixed_Exclude_Mixed", "MIXED_P", "MIXED_Q"),
    ]

    @parameterized.named_parameters(exclude_test_parameters)
    @capture.stdout
    def testSourceExcludes(self, source, source_exclude):
        source_text = ""
        if source:
            source_text = f"source-address:: {source}"
        source_exclude_text = ""
        if source_exclude:
            source_exclude_text = f"source-exclude:: {source_exclude}"
        TERM = f"""
        term good-term-1 {{
            {source_text}
            {source_exclude_text}
            action:: accept
        }}
        """
        pol = policy.ParsePolicy(GOOD_HEADER_1 + TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)

    @parameterized.named_parameters(exclude_test_parameters)
    @capture.stdout
    def testDestinationExcludes(self, destination, destination_exclude):
        destination_text = ""
        if destination:
            destination_text = f"destination-address:: {destination}"
        destination_exclude_text = ""
        if destination_exclude:
            destination_exclude_text = f"destination-exclude:: {destination_exclude}"
        TERM = f"""
        term good-term-1 {{
            {destination_text}
            {destination_exclude_text}
            action:: accept
        }}
        """
        pol = policy.ParsePolicy(GOOD_HEADER_1 + TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)

    @capture.stdout
    def testLocalInPolicy(self):
        pol = policy.ParsePolicy(LOCAL_POLICY + MIXED_AF_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)

    @capture.stdout
    def testLocalInPolicyV6(self):
        pol = policy.ParsePolicy(LOCAL_POLICY_V6 + MIXED_AF_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)


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


class FortigateYAMLTest(FortigateTest):
    def setUp(self):
        super().setUp()
        # patch policy.ParsePolicy into a wrapper that calls YAML.load_str
        self.patchers = [mock.patch.object(policy, 'ParsePolicy', _YamlParsePolicy)]
        [patcher.start() for patcher in self.patchers]
        self.setUpFixtures()

    def tearDown(self):
        [patcher.stop() for patcher in self.patchers]
        self.tearDownFixtures()

    def tearDownFixtures(self):
        self.fixture_patcher.stop()

    def setUpFixtures(self):
        self.fixture_patcher = mock.patch.multiple(
            'fortigate_test',
            GOOD_HEADER_1=YAML_GOOD_HEADER_1,
            INET_HEADER=YAML_INET_HEADER,
            INET6_HEADER=YAML_INET6_HEADER,
            MIXED_HEADER=YAML_MIXED_HEADER,
            GOOD_TERM_1=YAML_GOOD_TERM_1,
            ALL_IPS=YAML_ALL_IPS,
            GOOD_TERM_2=YAML_GOOD_TERM_2,
            V6_TERM=YAML_V6_TERM,
            MIXED_AF_TERM=YAML_MIXED_AF_TERM,
            NO_SERVICES_TERM=YAML_NO_SERVICES_TERM,
            EXPIRED_TERM=YAML_EXPIRED_TERM,
            DENY_RULE=YAML_DENY_RULE,
            HEADER_BAD_NUMBER_OF_INTERFACES=YAML_HEADER_BAD_NUMBER_OF_INTERFACES,
            COMMENT_TERM_1=YAML_COMMENT_TERM_1,
            OWNER_TERM=YAML_OWNER_TERM,
            LONG_COMMENT_TERM=YAML_LONG_COMMENT_TERM,
            OWNER_COMMENT_TERM=YAML_OWNER_COMMENT_TERM,
            SOURCE_EXCLUDE_TERM=YAML_SOURCE_EXCLUDE_TERM,
            DESTINATION_EXCLUDE_TERM=YAML_DESTINATION_EXCLUDE_TERM,
            LOCAL_POLICY=YAML_LOCAL_POLICY,
            LOCAL_POLICY_V6=YAML_LOCAL_POLICY_V6,
        )
        self.fixture_patcher.start()

    @parameterized.named_parameters(FortigateTest.logging_test_parameters)
    def testLogging(self, logging_enabled: bool, logging_options: str, expected: str):
        options = ""
        if logging_options:
            options = f"option: {logging_options}"
        logging = ""
        if logging_enabled:
            logging = f"logging: {logging_enabled}"
        LOGGING_TERM = f"""
        - name: good-term-1
          action: accept
          {logging}
          {options}
        """
        pol = policy.ParsePolicy(GOOD_HEADER_1 + LOGGING_TERM, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)
        self.assertIn(expected, str(acl))

    @parameterized.parameters(FortigateTest.bad_headers_test_parameters)
    def testBadAddressFamilyCombos(self, address_family_one: str, address_family_two: str):
        input_pol = f"""\
                filters:
                  - header:
                      comment: sample arista traffic policy
                      targets:
                        fortigate: from-zone port1 to-zone port2 {address_family_one} {address_family_two}
                    terms:
                      - name: accept-all
                        action: accept
        """
        input_pol = textwrap.dedent(input_pol)
        pol = policy.ParsePolicy(input_pol, self.naming)
        with self.assertRaises(ValueError):
            fortigate.Fortigate(pol, EXP_INFO)

    @parameterized.named_parameters(FortigateTest.exclude_test_parameters)
    @capture.stdout
    def testSourceExcludes(self, source, source_exclude):
        source_text = ""
        if source:
            source_text = f"source-address: {source}"
        source_exclude_text = ""
        if source_exclude:
            source_exclude_text = f"source-exclude: {source_exclude}"
        input_pol = f"""\
                filters:
                  - header:
                      comment: this is a test acl
                      targets:
                        fortigate: from-zone port1 to-zone port2
                    terms:
                      - name: good-term-1
                        {source_text}
                        {source_exclude_text}
                        action: accept
        """
        input_pol = textwrap.dedent(input_pol)
        pol = policy.ParsePolicy(input_pol, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)

    @parameterized.named_parameters(FortigateTest.exclude_test_parameters)
    @capture.stdout
    def testDestinationExcludes(self, destination, destination_exclude):
        destination_text = ""
        if destination:
            destination_text = f"destination-address: {destination}"
        destination_exclude_text = ""
        if destination_exclude:
            destination_exclude_text = f"destination-exclude: {destination_exclude}"
        input_pol = f"""\
                filters:
                  - header:
                      comment: this is a test acl
                      targets:
                        fortigate: from-zone port1 to-zone port2
                    terms:
                      - name: good-term-1
                        {destination_text}
                        {destination_exclude_text}
                        action: accept
        """
        input_pol = textwrap.dedent(input_pol)

        pol = policy.ParsePolicy(input_pol, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)
