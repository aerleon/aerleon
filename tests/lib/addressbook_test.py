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

    def testMultipleZones(self):
        foo = FQDN('foo.com', 'FOO')
        self.ab.AddFQDNs('zone', [foo])
        self.ab.AddFQDNs('zone2', [foo])
        self.assertEqual(['zone', 'zone2'], self.ab.GetZoneNames())

    def testGetTokens(self):
        foo = FQDN('foo.com', 'FOO')
        bar = IPv4('1.1.1.1/32', '', 'BAR')
        self.ab.AddFQDNs('zone', [foo])
        self.ab.AddAddresses('zone2', [bar])
        self.assertEqual(['FOO'], self.ab.GetFQDNTokensInZone('zone'))
        self.assertEqual(['BAR'], self.ab.GetAddressTokensInZone('zone2'))

    def testAddresses(self):
        foo = IPv4('1.1.1.1/32', '', 'FOO')
        self.ab.AddAddresses('zone', [foo])
        self.assertEqual(self.ab.GetAddress('zone', 'FOO'), [IPv4('1.1.1.1/32', '', 'FOO')])

    def testWalkAddressbook(self):
        self.ab.AddAddresses(
            'trust', [IPv4('1.1.1.1/32', '', 'FOO'), IPv4('1.1.1.2/32', '', 'BAR')]
        )
        self.ab.AddFQDNs(
            'trust',
            [
                FQDN(fqdn='foo.com', comment='', token='FOO'),
                FQDN(fqdn='biz.com', comment='', token='BIZ'),
            ],
        )
        self.ab.AddAddresses(
            'untrust', [IPv4('2.2.2.1/32', '', 'LOL'), IPv4('2.2.2.2/32', '', 'LOL')]
        )
        expected = [
            ['trust', 'BAR', [IPv4('1.1.1.2/32', '', 'BAR')], []],
            ['trust', 'BIZ', [], [FQDN(fqdn='biz.com', comment='', token='BIZ')]],
            [
                'trust',
                'FOO',
                [IPv4('1.1.1.1/32', '', 'FOO')],
                [FQDN(fqdn='foo.com', comment='', token='FOO')],
            ],
            ['untrust', 'LOL', [IPv4('2.2.2.1/32', '', 'LOL'), IPv4('2.2.2.2/32', '', 'LOL')], []],
        ]
        count = 0
        for zone, group, ips, fqdns in self.ab.Walk():
            self.assertEqual([zone, group, ips, fqdns], expected[count])
            count += 1
