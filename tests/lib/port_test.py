from absl.testing import absltest, parameterized
from aerleon.lib import port

import pytest


class PortTest(parameterized.TestCase):
    @parameterized.named_parameters(
        ("ValidIntPort_1", 1, 1),
        ('InvalidStrPort', 'a', port.BadPortValue),
        ('ValidStrPort', '1', 1),
        ('InvalidPort_Negative', -2, port.BadPortRange),
        ('InvalidPort_TooLarge', 99999, port.BadPortRange)
    )
    def testPort(self, p, expected):
        if type(expected) == type and issubclass(expected, Exception):

            with pytest.raises(expected):
                port.Port(p)
        else:
            self.assertEqual(port.Port(p), expected)

class PPPTest(parameterized.TestCase):
    @parameterized.parameters(
            ('22/tcp', '22', 'tcp', False),
            ('22-23/tcp', '22-23', 'tcp', False),
            ('22-23/tcp # foo', '22-23', 'tcp', False),
            ("SSH", None, None, True),
    )
    def testPPPInit(self, input, port_num, protocol, nested):
      result = port.PPP(input)
      self.assertEqual(result.port, port_num)
      self.assertEqual(result.protocol, protocol)
      self.assertEqual(result.nested, nested)

    @parameterized.parameters(
        ('22/tcp',False),
        ('SSH', False),
        ('22-23/tcp', True)
    )
    def testPPPRange(self, input, expected):
        result = port.PPP(input)
        self.assertEqual(result.is_range, expected)

    @parameterized.parameters(
        ('22/tcp',True),
        ('SSH', False),
        ('22-23/tcp', False)
    )
    def testPPPSinglePort(self, input, expected):
        result = port.PPP(input)
        self.assertEqual(result.is_single_port, expected)

    @parameterized.parameters(
        ('22/tcp',port.InvalidRange),
        ('SSH', port.InvalidRange),
        ('22-23/tcp', 22)
    )
    def testPPPStart(self, input, expected):
        result = port.PPP(input)
        if type(expected) == type and issubclass(expected, Exception):
            with pytest.raises(expected):
                _ = result.start
        else:
            self.assertEqual(result.start, expected)

    @parameterized.parameters(
        ('22/tcp',port.InvalidRange),
        ('SSH', port.InvalidRange),
        ('22-23/tcp', 23)
    )
    def testPPPEnd(self, input, expected):
        result = port.PPP(input)
        if type(expected) == type and issubclass(expected, Exception):
            with pytest.raises(expected):
                _ = result.start
        else:
            self.assertEqual(result.end, expected)