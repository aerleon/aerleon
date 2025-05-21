
""" Unittest for proxmox rendering module. """

from absl.testing import absltest
from aerleon.lib import proxmox, policy, naming
from aerleon.lib.proxmox import UnsupportedFilterOptionError
from tests.regression_utils import capture
from aerleon.lib import yaml as yaml_frontend

GOOD_HEADER_1 = """
header {
  comment:: "test acl with comment"
  target:: proxmox vm IN
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

    def testBadZoneName(self):
        pol = policy.ParsePolicy(BAD_HEADER_1 + GOOD_TERM_1, self.naming)
        with self.assertRaises(UnsupportedFilterOptionError):
            proxmox.Proxmox(pol, EXP_INFO)

    def testBadDirection(self):
        pol = policy.ParsePolicy(BAD_HEADER_2 + GOOD_TERM_1, self.naming)
        with self.assertRaises(UnsupportedFilterOptionError):
            proxmox.Proxmox(pol, EXP_INFO)

    @capture.stdout
    def testComment(self):
        output = proxmox.Proxmox(
            policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1, self.naming),
            EXP_INFO
        )
        print(output)



if __name__ == '__main__':
    absltest.main()
