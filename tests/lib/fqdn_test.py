from absl.testing import parameterized

from aerleon.lib.fqdn import FQDN


class FQDNTest(parameterized.TestCase):
    @parameterized.named_parameters(
        ('Simple', 'foo.bar', 'FOOBAR', 'This is the foo domain', False),
        ('Not a Domain', 'lolol', '', '', True),
        # The following tests are pulled from https://regexr.com/3g5j0
        ('Test', 'ec2-35-160-210-253.us-west-2-.compute.amazonaws.com', '', '', False),
        ('Test2', '-ec2_35$160%210-253.us-west-2-.compute.amazonaws.com', '', '', False),
        (
            'Test trailing dot',
            'ec2-35-160-210-253.us-west-2-.compute.amazonaws.com.mx.gmail.com.',
            '',
            '',
            False,
        ),
        ('Numeric domain', '1.2.3.4.com', '', '', False),
        # Punycode is used to convert Unicode to ascii and is used by DNS.
        # THe following tests FQDN would translate to мойподъезд.рф and ουτοπία.δπθ.gr
        ('Unicode1', 'xn--d1aacihrobi6i.xn--p1ai', '', '', False),
        ('Unicode2', 'xn--kxae4bafwg.xn--pxaix.gr', '', '', False),
        ('TLD cannot be numeric 1', 'label.name.321', '', '', True),
        ('TLD cannot be numeric 2', 'so-me.na-me.567', '', '', True),
        (
            'Label cannot Exceed 63 characters',
            '1234567890-1234567890-1234567890-1234567890-12345678901234567890.123.com',
            '',
            '',
            True,
        ),
        (
            'FQDN cannot exceed 255 characters',
            '1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.1234567890.com',
            '',
            '',
            True,
        ),
        ('URL scheme must not be included', 'https://foo.bar', '', '', True),
    )
    def testFQDNCreation(self, possible_fqdn: str, token: str, comment: str, error: Exception):

        if error:
            with self.assertRaises(ValueError):
                FQDN(possible_fqdn, token, comment)
        else:
            fqdn = FQDN(possible_fqdn, token, comment)
            self.assertEqual(fqdn.fqdn, possible_fqdn)
            self.assertEqual(fqdn.token, token)
            self.assertEqual(fqdn.parent_token, token)
            self.assertEqual(fqdn.text, comment)
