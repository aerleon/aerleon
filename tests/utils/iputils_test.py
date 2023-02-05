# Copyright 2018-2021 Google Inc. All Rights Reserved.
# Modifications Copyright 2022-2023 Aerleon Project Authors.
import pathlib

import pytest

from absl.testing import parameterized
from aerleon.lib import nacaddr
from aerleon.utils import iputils

file_directory = pathlib.Path(__file__).parent.absolute()
exclude_address_testcases = [
    ('invalid', 'invalid', TypeError),
    (nacaddr.IP('10.0.0.1'), 'invalid', TypeError),
    (nacaddr.IP('10.0.0.1'), nacaddr.IP('0000::/8'), TypeError),
    (nacaddr.IP('10.0.0.1'), nacaddr.IP('10.0.0.1'), []),
    (nacaddr.IP('10.0.0.1'), nacaddr.IP('192.168.1.1'), ValueError)
    
]
with open(str(file_directory) + "/address_exclude_test_cases.txt", 'r') as f:
    for line in f:
        ipstr, exstrs, restrs = line.strip().split(' ')
        ip = nacaddr.IP(ipstr)
        exclude_ips = list(map(nacaddr.IP, exstrs.split(',')))
        expected_results = []
        for i in restrs.split(';'):
            result_strings = i.split(',')
            ip_map = map(nacaddr.IP, result_strings)
            ip_list = list(ip_map)
            expected_results.append(ip_list)
        for ex, res in zip(exclude_ips, expected_results):
            exclude_address_testcases.append((ip, ex, res))


class TestIPUtils(parameterized.TestCase):
    @parameterized.parameters(exclude_address_testcases)
    def test_exclude_address(self, ip, exclude, expected):
        if type(expected) == type and issubclass(expected, Exception):
            with pytest.raises(expected):
                _ = list(iputils.exclude_address(ip, exclude))
        else:
            result = iputils.exclude_address(ip, exclude)
            self.assertEqual(list(result), expected)
