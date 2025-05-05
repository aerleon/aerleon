"""Regressopn test for Fortigate module."""
from absl.testing import absltest

from aerleon.lib import fortigate, naming, policy
from tests.regression_utils import capture

GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: fortigate test-filter port1 port1
}
"""
GOOD_TERM_2 = """
term good-term-1 {
  protocol:: tcp
  source-address:: SOME_HOST SOME_HOST3
  destination-address:: SOME_HOST2
  action:: accept
}
"""

EXP_INFO = 2
"""
config firewall address
    edit "Internal_Subnet_10"
        set subnet 10.10.10.0 255.255.255.0
        set uuid <auto_or_your_uuid_1> // Optional: Set UUID if needed for automation
    next
    edit "Internal_Subnet_20"
        set subnet 10.10.20.0 255.255.255.0
        set uuid <auto_or_your_uuid_2> // Optional: Set UUID
    next
    # Add more address objects for other subnets if needed
end
config firewall addrgrp
    edit "All_Internal_User_Subnets"
        set member "Internal_Subnet_10" "Internal_Subnet_20"
    next
end
"""

class FortigateTest(absltest.TestCase):
    """Test Fortigate module."""
    def setUp(self):
        super().setUp()
        self.naming = naming.Naming()

    # @capture.stdout
    def testOne(self):
        self.naming._ParseLine('SOME_HOST = 10.1.1.1/32 10.1.1.2/32', 'networks')
        self.naming._ParseLine('SOME_HOST3 = 10.1.1.3/32 10.1.1.4/32', 'networks')
        self.naming._ParseLine('SOME_HOST2 = 10.1.1.9/32', 'networks')
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_2, self.naming)
        acl = fortigate.Fortigate(pol, EXP_INFO)
        print(acl)
        print("done")
