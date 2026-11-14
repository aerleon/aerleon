import ipaddress
import random

from absl.testing import absltest

from aerleon.lib.addressbook import Addressbook
from aerleon.lib.fqdn import FQDN
from aerleon.lib.nacaddr import IPv4, IPv6


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

    def testAddressIdentityAndContainmentAcrossBatches(self):
        first = IPv4('10.0.0.0/25', 'first', 'FOO')
        adjacent = IPv4('10.0.0.128/25', 'adjacent', 'FOO')
        wider = IPv4('10.0.0.0/24', 'wider', 'FOO')
        duplicate = IPv4('10.0.0.0/24', 'duplicate', 'FOO')
        self.ab.AddAddresses('zone', [adjacent, first])
        self.assertEqual(self.ab.GetAddress('zone', 'FOO'), [first, adjacent])
        self.ab.AddAddresses('zone', [wider, duplicate, first])
        self.assertEqual(self.ab.GetAddress('zone', 'FOO'), [wider])
        self.assertIs(self.ab.GetAddress('zone', 'FOO')[0], wider)
        self.ab.AddAddresses('zone', [duplicate])
        self.assertIs(self.ab.GetAddress('zone', 'FOO')[0], wider)
        self.assertEqual(wider.text, 'wider')

    def testAddressFamiliesAndBounds(self):
        v4 = IPv4('0.0.0.0/0', token='FOO')
        v6 = IPv6('::/0', token='FOO')
        addresses = [
            IPv6('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128', token='FOO'),
            IPv4('255.255.255.255/32', token='FOO'),
            IPv6('::/128', token='FOO'),
            IPv4('0.0.0.0/32', token='FOO'),
        ]
        self.ab.AddAddresses('zone', addresses)
        self.assertLen(self.ab.GetAddress('zone', 'FOO'), 4)
        self.ab.AddAddresses('zone', [v6, v4])
        self.assertEqual(self.ab.GetAddress('zone', 'FOO'), [v4, v6])

    def testSingleAddressInsertionOrder(self):
        addresses = [IPv4(f'10.0.{index}.0/24', token='FOO') for index in range(5)]
        self.ab.AddAddresses('zone', [addresses[1], addresses[3]])
        for index in (4, 0, 2):
            self.ab.AddAddresses('zone', [addresses[index]])
        self.ab.AddAddresses('zone', [IPv4('10.0.2.0/24', 'duplicate', 'FOO')])
        self.assertEqual(
            [id(address) for address in self.ab.GetAddress('zone', 'FOO')],
            [id(address) for address in addresses],
        )

    def testAddressGroupOrderAndFQDNRetention(self):
        fqdn = FQDN('example.test', 'DNS')
        self.ab.AddFQDNs('zone', [fqdn])
        self.ab.AddAddresses('zone', [IPv4('10.0.0.0/24', token='Z')])
        incoming: list[IPv4 | IPv6] = [
            IPv4('10.0.0.0/24', token='B'),
            IPv4('10.0.0.0/24', token='A'),
        ]
        self.ab.AddAddresses('zone', incoming)
        self.ab.AddAddresses('empty', [])
        self.assertEqual(self.ab.GetAddressTokensInZone('zone'), ['Z', 'A', 'B'])
        self.assertEqual(self.ab.GetZoneNames(), ['zone', 'empty'])
        self.assertIs(self.ab.GetFQDN('zone', 'DNS')[0], fqdn)
        self.assertEqual([address.parent_token for address in incoming], ['B', 'A'])

    def testAddressSubclassSortKey(self):
        class ReversePrefixIPv4(IPv4):
            def _get_networks_key(self):
                return self.version, self.network_address, self.hostmask

        narrow = ReversePrefixIPv4('10.0.0.0/25', token='FOO')
        broad = ReversePrefixIPv4('10.0.0.0/24', token='FOO')
        self.ab.AddAddresses('zone', [broad, narrow])
        self.assertEqual(self.ab.GetAddress('zone', 'FOO'), [narrow, broad])

    def testScopedAddresses(self):
        addresses: list[IPv4 | IPv6] = [
            IPv6('fe80::%eth0/128', token='FOO'),
            IPv6('fe80::1%eth0/128', token='FOO'),
        ]
        self.ab.AddAddresses('zone', list(reversed(addresses)))
        self.ab.AddAddresses('zone', addresses)
        self.assertEqual(self.ab.GetAddress('zone', 'FOO'), addresses)
        for actual, expected in zip(self.ab.GetAddress('zone', 'FOO'), addresses):
            self.assertIs(actual, expected)

    def testAddressSelectionAgainstPairwiseContainment(self):
        rng = random.Random(37421)
        for case in range(100):
            book = Addressbook()
            expected = []
            for batch in range(6):
                incoming = []
                for item in range(20):
                    cls, bits = rng.choice([(IPv4, 32), (IPv6, 128)])
                    prefix = rng.choice([0, 1, bits // 2, bits - 1, bits])
                    start = rng.getrandbits(bits) >> (bits - prefix) << (bits - prefix)
                    incoming.append(cls((start, prefix), f'{case}/{batch}/{item}', 'FOO'))
                candidates = expected + incoming
                expected = []
                for address in candidates:
                    if address not in expected and not any(
                        address != other and address.subnet_of(other) for other in candidates
                    ):
                        expected.append(address)
                expected.sort(key=ipaddress.get_mixed_type_key)
                book.AddAddresses('zone', incoming)
                self.assertEqual(
                    [id(address) for address in book.GetAddress('zone', 'FOO')],
                    [id(address) for address in expected],
                    (case, batch),
                )

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
