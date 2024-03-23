import operator as op
from typing import Tuple

from absl.testing import parameterized

from aerleon.lib import port


class PortTest(parameterized.TestCase):
    @parameterized.named_parameters(
        ('SimpleTCP', '80/tcp', '80', 'tcp', False),
        ('SimpleUDP', '80/udp', '80', 'udp', False),
        ('SimpleService', 'FOO', None, None, True),
        ('RangeInput', '80-90/tcp', '80-90', 'tcp', False)
    )
    def testPortCreation(
        self, possible_ports: str, expected_port: str, expected_protocol: str, nested: bool
    ):
        result = port.PPP(possible_ports)
        self.assertEqual(result.service, possible_ports)
        self.assertEqual(result.port, expected_port)
        self.assertEqual(result.protocol, expected_protocol)
        self.assertEqual(result.nested, nested)

    @parameterized.named_parameters(
        ('SimpleRange', '80-81/tcp', True),
        ('SimpleSingle', '80/tcp', False),
        ('SimpleToken', 'FOO', False),
        ('RangeButSingle', '80-80/tcp', False)
    )
    def testIsRangeOrSingle(self, possible_range: str, range: bool):
        result = port.PPP(possible_range)
        self.assertEqual(result.is_range, range)
        self.assertEqual(result.is_single_port, not range)

    @parameterized.named_parameters(
        ('SimpleRange', port.PPP('80/tcp'), port.PPP('80-81/tcp'), True),
        ('NotContained', port.PPP('89/tcp'), port.PPP('80-81/tcp'), False),
        ('NotRanged', port.PPP('80/tcp'), port.PPP('80/tcp'), True),
    )
    def testContains(self, single: port.PPP, range: port.PPP, contained: bool):
        result = single in range
        self.assertEqual(result, contained)

    @parameterized.named_parameters(
        ('SimpleRange', port.PPP('80-100/tcp'), (80, 100)),
        ('NotARange', port.PPP('100/tcp'), (100, 100)),
    )
    def testRangeValues(self, range: port.PPP, expected: Tuple[str, str]):
        self.assertEqual(range.start, expected[0])
        self.assertEqual(range.end, expected[1])

    @parameterized.parameters(
        (port.PPP('80/tcp'), port.PPP('80/tcp'), op.lt, False),
        (port.PPP('81/tcp'), port.PPP('80/tcp'), op.lt, False),
        (port.PPP('80/tcp'), port.PPP('81/tcp'), op.lt, True),
        (port.PPP('85/tcp'), port.PPP('80/tcp'), op.gt, True),
        (port.PPP('80/tcp'), port.PPP('85/tcp'), op.gt, False),
        (port.PPP('80/tcp'), port.PPP('80/tcp'), op.gt, False),
        (port.PPP('80/tcp'), port.PPP('80/tcp'), op.le, True),
        (port.PPP('81/tcp'), port.PPP('80/tcp'), op.le, False),
        (port.PPP('80/tcp'), port.PPP('81/tcp'), op.le, True),
        (port.PPP('80/tcp'), port.PPP('80/tcp'), op.ge, True),
        (port.PPP('81/tcp'), port.PPP('80/tcp'), op.ge, True),
        (port.PPP('80/tcp'), port.PPP('81/tcp'), op.ge, False),
        (port.PPP('80/tcp'), port.PPP('80/tcp'), op.eq, True),
        (port.PPP('81/tcp'), port.PPP('80/tcp'), op.eq, False),
        (port.PPP('80/tcp'), port.PPP('81/tcp'), op.eq, False),
    )
    def testComparistons(self, operand_one: port.PPP, operand_two: port.PPP, operator, result):
        self.assertEqual(operator(operand_one, operand_two), result)