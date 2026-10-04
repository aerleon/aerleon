"""Unittest for proxmox rendering module."""

from absl.testing import absltest

from aerleon.lib import naming, policy, proxmox
from aerleon.lib import yaml as yaml_frontend
from aerleon.lib.proxmox import UnsupportedFilterOptionError, ZoneMismatchError
from tests.regression_utils import capture

GOOD_HEADER_1 = """
header {
  comment:: "test acl with comment"
  target:: proxmox vm IN
}
"""

GOOD_HEADER_2 = """
header {
  comment:: "test acl for host zone IN"
  target:: proxmox host IN
}
"""

GOOD_HEADER_3 = """
header {
  comment:: "test acl for host zone OUT"
  target:: proxmox host OUT
}
"""

GOOD_HEADER_4 = """
header {
  comment:: "test value option"
  target:: proxmox host OUT log_level_in err
}
"""

GOOD_HEADER_5 = """
header {
  comment:: "test boolean option"
  target:: proxmox host IN ndp
}
"""

GOOD_HEADER_6 = """
header {
  comment:: "test number value option"
  target:: proxmox host IN nf_conntrack_max 32768
}
"""

GOOD_HEADER_7 = """
header {
  comment:: "test multivalue option"
  target:: proxmox host OUT nf_conntrack_helpers tftp irc sip
}
"""

BAD_HEADER_1 = """
header {
  target:: proxmox badzone IN
}
"""

BAD_HEADER_2 = """
header {
  target:: proxmox vm OUI
}
"""

BAD_HEADER_3 = """
header {
  target:: proxmox vm
}
"""

BAD_HEADER_4 = """
header {
  target:: proxmox
}
"""

GOOD_TERM_1 = """
term good-term-1 {
   destination-address:: SOME_HOST
   protocol:: tcp
   action:: accept
   comment:: "some comment"
}
"""

GOOD_TERM_2 = """
term good-term-2 {
  source-address:: V4ANY
  protocol:: tcp udp
  action:: deny
}
"""

GOOD_TERM_3 = """
term good-term-3 {
  source-address:: SOME_HOST
  comment:: "log activity from SOME_HOST with default loglevel"
  logging:: true
  action:: deny
}
"""

GOOD_TERM_4 = """
term good-term-4 {
  source-address:: SOME_HOST
  comment:: "log activity from SOME_HOST with info loglevel"
  logging:: true
  option:: log_info
  action:: deny
}
"""

GOOD_TERM_5 = """
term good-term-5 {
  comment:: "term with no source/destination addr"
  protocol:: l2tp ipip gre esp
  action:: deny
}
"""

GOOD_TERM_6 = """
term good-term-6 {
  source-port:: GAMES
  protocol:: tcp udp
  action:: deny
  logging:: true
}
"""

GOOD_TERM_7 = """
term good-term-7 {
  destination-port:: WEB_ALT
  protocol:: tcp
  action:: deny
  logging:: true
}
"""

SOURCE_INTERFACE_TERM = """
term source-interface-term {
  source-address:: V4ANY
  source-interface:: b2b0
  action:: accept
}
"""

MULTI_ICMP_TERM = """
term multi-icmp-term {
  source-address:: V4ANY
  protocol:: icmp
  icmp-type:: redirect router-advertisement mask-request mask-reply
  action:: deny
}
"""

MIXED_AF_TERM = """
term mixed-af-term {
  source-address:: SOME_HOST SOME_HOST6
  protocol:: icmp
  icmp-type:: echo-request
  action:: accept
}
"""

EXPIRED_TERM_1 = """
term expired-term-1 {
  expiration:: 2000-1-1
  protocol:: tcp
  destination-port:: NTP
  action:: deny
}
"""


EXP_INFO = 2


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


class ProxmoxFWTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = naming.Naming()
        self.naming._ParseLine('SOME_HOST = 10.0.0.1/32', 'networks')
        self.naming._ParseLine('SOME_HOST6 = 2001:db8::2af/128', 'networks')
        self.naming._ParseLine('V4ANY = 0.0.0.0/0', 'networks')
        self.naming._ParseLine('NTP = 123/tcp 123/udp', 'services')
        self.naming._ParseLine(
            'GAMES = 1926/tcp 1926/udp 26000/tcp 26000/udp 666/tcp 666/udp', 'services'
        )
        self.naming._ParseLine('WEB_ALT = 8000-8800/tcp', 'services')

    def testBadZoneName(self):
        pol = policy.ParsePolicy(BAD_HEADER_1 + GOOD_TERM_1, self.naming)
        with self.assertRaises(UnsupportedFilterOptionError):
            proxmox.Proxmox(pol, EXP_INFO)

    def testMultipleZonesBadMixup(self):
        pol = policy.ParsePolicy(
            GOOD_HEADER_1 + GOOD_TERM_1 + GOOD_HEADER_2 + GOOD_TERM_1, self.naming
        )
        with self.assertRaises(ZoneMismatchError):
            proxmox.Proxmox(pol, EXP_INFO)

    def testBadDirection(self):
        pol = policy.ParsePolicy(BAD_HEADER_2 + GOOD_TERM_1, self.naming)
        with self.assertRaises(UnsupportedFilterOptionError):
            proxmox.Proxmox(pol, EXP_INFO)

    def testMissingArguments(self):
        pol = policy.ParsePolicy(BAD_HEADER_3 + GOOD_TERM_1, self.naming)
        with self.assertRaises(UnsupportedFilterOptionError):
            proxmox.Proxmox(pol, EXP_INFO)
        pol = policy.ParsePolicy(BAD_HEADER_4 + GOOD_TERM_1, self.naming)
        with self.assertRaises(UnsupportedFilterOptionError):
            proxmox.Proxmox(pol, EXP_INFO)

    @capture.stdout
    def testValueOption(self):
        pol = policy.ParsePolicy(GOOD_HEADER_4 + GOOD_TERM_1, self.naming)
        acl = proxmox.Proxmox(pol, EXP_INFO)
        out = str(acl)
        self.assertIn('log_level_in: err', out, "value option not present in final output")
        print(out)

    @capture.stdout
    def testBooleanOption(self):
        pol = policy.ParsePolicy(GOOD_HEADER_5 + GOOD_TERM_1, self.naming)
        acl = proxmox.Proxmox(pol, EXP_INFO)
        out = str(acl)
        self.assertIn('ndp: 1', out, "boolean option not present in final output")
        print(out)

    @capture.stdout
    def testNumberValueOption(self):
        pol = policy.ParsePolicy(GOOD_HEADER_6 + GOOD_TERM_1, self.naming)
        acl = proxmox.Proxmox(pol, EXP_INFO)
        out = str(acl)
        self.assertIn(
            'nf_conntrack_max: 32768', out, "number value option not present in final output"
        )
        print(out)

    @capture.stdout
    def testMultiValueOption(self):
        pol = policy.ParsePolicy(GOOD_HEADER_7 + GOOD_TERM_1, self.naming)
        acl = proxmox.Proxmox(pol, EXP_INFO)
        out = str(acl)
        self.assertIn(
            f"nf_conntrack_helpers: {','.join(sorted(['tftp','irc','sip']))}",
            out,
            "multivalue option not present in final output",
        )
        print(out)

    @capture.stdout
    def testOptionMerge(self):
        pol = policy.ParsePolicy(
            GOOD_HEADER_4
            + GOOD_TERM_1
            + GOOD_HEADER_5
            + GOOD_TERM_1
            + GOOD_HEADER_7
            + GOOD_TERM_2,
            self.naming,
        )
        acl = proxmox.Proxmox(pol, EXP_INFO)
        out = str(acl)
        default_msg = "missing option in final output, option merge failed?"
        self.assertIn("log_level_in: err", out, default_msg)
        self.assertIn("ndp: 1", out, default_msg)
        self.assertIn(
            f"nf_conntrack_helpers: {','.join(sorted(['tftp','irc','sip']))}", out, default_msg
        )
        print(out)

    @capture.stdout
    def testComment(self):
        output = proxmox.Proxmox(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1, self.naming), EXP_INFO
        )
        self.assertRegex(str(output), "# some comment", "did not output comment")
        print(output)

    @capture.stdout
    def testExpiredNotPrinted(self):
        output = proxmox.Proxmox(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1 + EXPIRED_TERM_1, self.naming), EXP_INFO
        )
        self.assertNotIn('expired-term', str(output))
        print(output)

    @capture.stdout
    def testMultipleTerms(self):
        output = proxmox.Proxmox(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1 + GOOD_TERM_2, self.naming), EXP_INFO
        )
        print(output)

    @capture.stdout
    def testLogging(self):
        output = proxmox.Proxmox(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_3, self.naming), EXP_INFO
        )
        print(output)

    @capture.stdout
    def testLoggingOptions(self):
        output = proxmox.Proxmox(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_4, self.naming), EXP_INFO
        )
        print(output)

    @capture.stdout
    def testExcludeRegeneratesSource(self):
        self.naming._ParseLine('RFC1918_10 = 10.0.0.0/8', 'networks')
        self.naming._ParseLine('OURNET = 10.10.0.0/16', 'networks')
        exclude_term_1 = """
        term exclude-term-1 {
          source-address:: RFC1918_10
          source-exclude:: OURNET
          destination-address:: V4ANY
          action:: deny
        }
        """
        output = proxmox.Proxmox(
            policy.ParsePolicy(GOOD_HEADER_1 + exclude_term_1, self.naming), EXP_INFO
        )
        output_str = str(output)
        self.assertNotIn(
            '10.0.0.0/8', output_str, 'original network with exclude should not be in output'
        )
        print(output_str)

    @capture.stdout
    def testSourceInterface(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + SOURCE_INTERFACE_TERM, self.naming)
        acl = proxmox.Proxmox(pol, EXP_INFO)
        output = str(acl)
        self.assertIn('-iface b2b0', output, 'source interface not in output')
        print(output)

    @capture.stdout
    def testMultipleICMPTypes(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + MULTI_ICMP_TERM, self.naming)
        acl = proxmox.Proxmox(pol, EXP_INFO)
        output = str(acl)
        for t in ['redirect', 'router-advertisement', 'mask-request', 'mask-reply']:
            self.assertIn(f'-icmp-type {proxmox.ProxmoxIcmp.ICMPv4_MAP[t][None]}', output)
        print(output)

    @capture.stdout
    def testMixedAddressFamilies(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + MIXED_AF_TERM, self.naming)
        acl = proxmox.Proxmox(pol, EXP_INFO)
        output = str(acl)
        self.assertIn('-source 10.0.0.1/32', output)
        self.assertIn('-source 2001:db8::2af/128', output)
        print(output)

    @capture.stdout
    def testPortAndPortRanges(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_6, self.naming)
        acl = proxmox.Proxmox(pol, EXP_INFO)
        output = str(acl)
        self.assertIn('-proto tcp -sport 666,1926,26000', output, 'ports not found')
        self.assertIn('-proto udp -sport 666,1926,26000', output, 'ports not found')
        print(output)
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_7, self.naming)
        acl = proxmox.Proxmox(pol, EXP_INFO)
        output = str(acl)
        self.assertIn('-proto tcp -dport 8000-8800', output, 'port range not found')
        print(output)

    @capture.stdout
    def testNoSourceNoDestinationTerm(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_5, self.naming)
        acl = proxmox.Proxmox(pol, EXP_INFO)
        output = str(acl)
        self.assertIn('IN DROP -proto', output)
        print(output)

    @capture.stdout
    def testMixedDirectionPolicy(self):
        pol = policy.ParsePolicy(
            GOOD_HEADER_2 + GOOD_TERM_1 + GOOD_HEADER_3 + GOOD_TERM_1, self.naming
        )
        acl = proxmox.Proxmox(pol, EXP_INFO)
        output = str(acl)
        self.assertIn('IN ACCEPT', output)
        self.assertIn('OUT ACCEPT', output)
        print(output)


if __name__ == '__main__':
    absltest.main()
