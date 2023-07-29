from absl.testing import absltest

from aerleon.lib.addressbook import Addressbook
from aerleon.lib.fqdn import FQDN
from aerleon.lib.nacaddr import IPv4


class ACLGeneratorTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.ab = Addressbook()

    def testFQDNs(self):
        foo = FQDN('foo.com', 'FOO')
        self.ab.AddFQDNs('zone', [foo])
        self.assertEqual(
            self.ab.GetFQDN('zone', 'FOO'), [FQDN(fqdn='foo.com', comment='', token='FOO')]
        )

    def testAddresses(self):
        foo = IPv4('1.1.1.1/32', '', 'FOO')
        self.ab.AddAddresses('zone', [foo])
        self.assertEqual(self.ab.GetAddress('zone', 'FOO'), [IPv4('1.1.1.1/32', '', 'FOO')])
