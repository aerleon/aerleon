""" Unittest for proxmox rendering module. """

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
  comment:: "test acl for host zone"
  target:: proxmox host IN
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
            self.assertIn('-icmp-type %s' % proxmox.ProxmoxIcmp.ICMPv4_MAP[t][None], output)
        print(output)

    @capture.stdout
    def testMixedAddressFamilies(self):
        pol = policy.ParsePolicy(GOOD_HEADER_1 + MIXED_AF_TERM, self.naming)
        acl = proxmox.Proxmox(pol, EXP_INFO)
        output = str(acl)
        self.assertIn('-source 10.0.0.1/32', output)
        self.assertIn('-source 2001:db8::2af/128', output)
        print(output)


if __name__ == '__main__':
    absltest.main()
