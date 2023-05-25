from absl.testing import absltest, parameterized
from aerleon.lib import addressbook, nacaddr, fqdn


class AddressbookTest(parameterized.TestCase):
    @parameterized.named_parameters(
        (
            "SimpleIPv4NoCollapse",
            [nacaddr.IP('192.168.1.1/32', '', 'FOO'), nacaddr.IP('192.168.1.2/32', '', 'FOO')],
            [nacaddr.IP('192.168.1.1/32', '', 'FOO'), nacaddr.IP('192.168.1.2/32', '', 'FOO')],
        ),
        (
            "SimpleIPv4Collapse",
            [nacaddr.IP('192.168.1.0/24', '', 'FOO'), nacaddr.IP('192.168.1.2/32', '', 'FOO')],
            [nacaddr.IP('192.168.1.0/24', '', 'FOO')],
        ),
    )
    def testAddressBookAddrs(self, ips, expected):

        book = addressbook.Addressbook()
        book.AddAddresses('', ips)
        self.assertEqual(book.addressbook['']['FOO'].addresses, expected)

    @parameterized.named_parameters(
        (
            "SingleAdd",
            [fqdn.FQDN('dns.google.com', 'FOO')],
            [fqdn.FQDN('dns.google.com', 'FOO')]
        ),
    )
    def testAddressBookHostnames(self, hosts, expected):
        book = addressbook.Addressbook()
        book.AddFQDN('', hosts)
        self.assertEqual(book.addressbook['']['FOO'].fqdn, expected)
        