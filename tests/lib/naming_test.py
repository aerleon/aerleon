# Copyright 2007 Google Inc. All Rights Reserved.
# Modifications Copyright 2022-2023 Aerleon Project Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unittest for naming.py module."""

from absl.testing import absltest

from aerleon.lib import nacaddr, naming


class NamingUnitTest(absltest.TestCase):
    """Unit Test for naming.py.

    The Naming class allows us to specify if we want to use arrays of text
    instead of files.  Most of the tests below create an empty Naming class.
    To populate the class with data, we simply pass our test data in arrays
    to the ParseList method, or in some cases, pass an io.BytesIO stream.
    """

    def setUp(self):
        super().setUp()
        self.defs = naming.Naming(None)
        servicedata = []
        servicedata.append('SVC1 = 80/tcp 81/udp 82/tcp')
        servicedata.append('SVC2 = 80/tcp 81/udp 82/tcp SVC2')
        servicedata.append('SVC3 = 80/tcp 81/udp')
        servicedata.append('SVC4 = 80/tcp # some service')
        servicedata.append('TCP_90 = 90/tcp')
        servicedata.append('SVC5 = TCP_90')
        servicedata.append('SVC6 = SVC1 SVC5')
        networkdata = []
        networkdata.append('NET1 = 10.1.0.0/8 # network1')
        networkdata.append('NET2 = 10.2.0.0/16 # network2.0')
        networkdata.append('       NET1')
        networkdata.append('9OCLOCK = 1.2.3.4/32 # 9 is the time')
        networkdata.append('FOOBAR = 9OCLOCK')
        networkdata.append('FOO_V6 = ::FFFF:FFFF:FFFF:FFFF')
        networkdata.append('BAR_V6 = ::1/128')
        networkdata.append('BAZ = FOO_V6')
        networkdata.append('      BAR_V6')
        networkdata.append('BING = NET1 # foo')
        networkdata.append('       FOO_V6')

        self.defs.ParseServiceList(servicedata)
        self.defs.ParseNetworkList(networkdata)

    def testCommentedServices(self):
        self.assertEqual(self.defs.GetService('SVC4'), ['80/tcp'])
        self.assertListEqual(self.defs.GetServiceByProto('SVC4', 'tcp'), ['80'])

    def testBadGetRequest(self):
        """Test proper handling of a non-existant service request."""
        self.assertRaises(naming.UndefinedServiceError, self.defs.GetService, 'FOO')
        self.assertRaises(naming.UndefinedServiceError, self.defs.GetServiceByProto, 'FOO', 'tcp')

    def testGetServiceRecursion(self):
        """Ensure we don't slip into recursion hell when object contains itself."""
        self.assertListEqual(self.defs.GetService('SVC2'), ['80/tcp', '81/udp', '82/tcp'])

    def testGetService(self):
        """Verify proper results from a service lookup request."""
        self.assertListEqual(self.defs.GetService('SVC1'), ['80/tcp', '81/udp', '82/tcp'])

    def testBadProtocol(self):
        """Test proper handling of a non-existant service request."""
        self.assertListEqual(self.defs.GetServiceByProto('SVC1', 'fud'), [])

    def testGetServiceByProto(self):
        self.assertListEqual(self.defs.GetServiceByProto('SVC1', 'tcp'), ['80', '82'])

    def testGetServiceByProtoWithoutProtocols(self):
        """Ensure services with protocol are not returned when type is specified."""
        self.assertListEqual(self.defs.GetServiceByProto('SVC3', 'tcp'), ['80'])

    def testNetworkComment(self):
        self.assertEqual(self.defs.GetNetAddr('NET1')[0].text, 'network1')

    def testNestedNetworkComment(self):
        self.assertEqual(self.defs.GetNetAddr('NET2')[1].text, 'network1')

    def testUndefinedAddress(self):
        self.assertRaises(naming.UndefinedAddressError, self.defs.GetNetAddr, 'FOO')

    def testNamespaceCollisionError(self):
        badservicedata = []
        badservicedata.append('SVC1 = 80/tcp')
        badservicedata.append('SVC1 = 81/udp')
        testdefs = naming.Naming(None)
        self.assertRaises(
            naming.NamespaceCollisionError, testdefs.ParseServiceList, badservicedata
        )

    def testNetworkAddress(self):
        self.assertListEqual(self.defs.GetNetAddr('NET1'), [nacaddr.IPv4('10.0.0.0/8')])

    def testInet6Address(self):
        self.assertListEqual(
            self.defs.GetNetAddr('BAZ'),
            [nacaddr.IPv6('::FFFF:FFFF:FFFF:FFFF'), nacaddr.IPv6('::1/128')],
        )

    def testMixedAddresses(self):
        self.assertListEqual(
            self.defs.GetNetAddr('BING'),
            [nacaddr.IPv4('10.0.0.0/8'), nacaddr.IPv6('::FFFF:FFFF:FFFF:FFFF')],
        )
        # same thing but letting nacaddr decide which v4 or v6.
        self.assertListEqual(
            self.defs.GetNetAddr('BING'),
            [nacaddr.IP('10.0.0.0/8'), nacaddr.IP('::FFFF:FFFF:FFFF:FFFF')],
        )

    def testNestedServices(self):
        self.assertListEqual(self.defs.GetServiceByProto('SVC6', 'tcp'), ['80', '82', '90'])

    def testServiceParents(self):
        """SVC6 contains SVC5 which contains TCP_90 which contains 90/tcp."""
        self.assertListEqual(self.defs.GetServiceParents('90/tcp'), ['TCP_90', 'SVC5', 'SVC6'])

    def testNetParents(self):
        """BIN & NET2 contain NET1, BING & BAZ contain FOO_V6."""
        self.assertListEqual(sorted(self.defs.GetNetParents('NET1')), ['BING', 'NET2'])
        self.assertListEqual(sorted(self.defs.GetNetParents('FOO_V6')), ['BAZ', 'BING'])

    def testGetIpParents(self):
        """Ensure GetIpParents returns proper results."""
        self.assertListEqual(self.defs.GetIpParents('10.11.12.13/32'), ['BING', 'NET1', 'NET2'])

    def testUndefinedTokenNesting(self):
        bad_servicedata = ['FOO = 7/tcp BAR']
        bad_networkdata = ['NETGROUP = 10.0.0.0/8 FOOBAR']
        baddefs = naming.Naming(None)
        baddefs.ParseServiceList(bad_servicedata)
        baddefs.ParseNetworkList(bad_networkdata)
        self.assertRaises(naming.UndefinedServiceError, baddefs._CheckUnseen, 'services')
        self.assertRaises(naming.UndefinedAddressError, baddefs._CheckUnseen, 'networks')

    def testParseNetFile(self):
        filedefs = naming.Naming(None)
        data = ['FOO = 127.0.0.1 # some network\n']
        filedefs._ParseFile(data, 'networks')
        self.assertEqual(filedefs.GetNetAddr('FOO'), [nacaddr.IPv4('127.0.0.1')])

    def testParseServiceFile(self):
        filedefs = naming.Naming(None)
        data = ['HTTP = 80/tcp\n']
        filedefs._ParseFile(data, 'services')
        self.assertEqual(filedefs.GetService('HTTP'), ['80/tcp'])

    def testServiceIncorrectSyntax(self):
        badservicedata = []
        badservicedata.append('SVC1 = 80//tcp 80/udp')
        badservicedata.append('SVC2 = 81/tcp')
        testdefs = naming.Naming(None)
        self.assertRaises(naming.NamingSyntaxError, testdefs.ParseServiceList, badservicedata)

    def testGetNetChildrenSingle(self):
        expected = ['NET1']
        self.assertEqual(expected, self.defs.GetNetChildren('NET2'))

    def testGetNetChildrenMulti(self):
        expected = ['FOO_V6', 'BAR_V6']
        self.assertEqual(expected, self.defs.GetNetChildren('BAZ'))

    def testGetNetChildrenQueryNotExist(self):
        self.assertEqual([], self.defs.GetNetChildren('IDONOTEXIST'))

    def testGetNetChildrenNoChild(self):
        self.assertEqual([], self.defs.GetNetChildren('NET1'))


class DefinitionYAMLUnitTest(NamingUnitTest):
    """Runs the NamingUnitTest suite against YAML input.

    Behavior should be identical."""

    def setUp(self):
        super().setUp()
        defs_yaml = """
services:
  SVC1:
    - protocol: tcp
      port: 80
    - protocol: udp
      port: 81
    - protocol: tcp
      port: 82
  SVC2:
    - protocol: tcp
      port: 80
    - protocol: udp
      port: 81
    - protocol: tcp
      port: 82
    - SVC2
  SVC3:
    - protocol: tcp
      port: 80
    - protocol: udp
      port: 81
  SVC4:
    - protocol: tcp
      port: 80
      comment: "some service"
  TCP_90:
    - protocol: tcp
      port: 90
  SVC5:
    - TCP_90
  SVC6:
    - SVC1
    - SVC5
networks:
  NET1:
    values:
      - address: 10.1.0.0/8
        comment: "network1"
  NET2:
    values:
      - address: 10.2.0.0/16
        comment: "network2.0"
      - NET1
  9OCLOCK:
    values:
      - address: 1.2.3.4/32
        comment: "9 is the time"
  FOOBAR:
    values:
      - 9OCLOCK
  FOO_V6:
    values:
      - address: ::FFFF:FFFF:FFFF:FFFF
  BAR_V6:
    values:
      - address: ::1/128
  BAZ:
    values:
      - FOO_V6
      - BAR_V6
  BING:
    values:
      - name: NET1
        comment: "foo"
      - FOO_V6

"""
        self.defs = naming.Naming(None)
        self.defs.ParseYaml(defs_yaml, "example_defs.yaml")


class DefinitionObjectUnitTest(NamingUnitTest):
    """Runs the NamingUnitTest suite against object input.

    This is the object representation used by YAML definition files and API calls.

    Behavior should be identical."""

    def setUp(self):
        super().setUp()
        defs_obj = {
            'networks': {
                '9OCLOCK': {'values': [{'comment': '9 is the time', 'address': '1.2.3.4/32'}]},
                'BAR_V6': {'values': [{'address': '::1/128'}]},
                'BAZ': {'values': ['FOO_V6', 'BAR_V6']},
                'BING': {'values': [{'comment': 'foo', 'name': 'NET1'}, 'FOO_V6']},
                'FOOBAR': {'values': ['9OCLOCK']},
                'FOO_V6': {'values': [{'address': '::FFFF:FFFF:FFFF:FFFF'}]},
                'NET1': {'values': [{'comment': 'network1', 'address': '10.1.0.0/8'}]},
                'NET2': {'values': [{'comment': 'network2.0', 'address': '10.2.0.0/16'}, 'NET1']},
            },
            'services': {
                'SVC1': [
                    {'port': 80, 'protocol': 'tcp'},
                    {'port': 81, 'protocol': 'udp'},
                    {'port': 82, 'protocol': 'tcp'},
                ],
                'SVC2': [
                    {'port': 80, 'protocol': 'tcp'},
                    {'port': 81, 'protocol': 'udp'},
                    {'port': 82, 'protocol': 'tcp'},
                    'SVC2',
                ],
                'SVC3': [{'port': 80, 'protocol': 'tcp'}, {'port': 81, 'protocol': 'udp'}],
                'SVC4': [{'comment': 'some service', 'port': 80, 'protocol': 'tcp'}],
                'SVC5': ['TCP_90'],
                'SVC6': ['SVC1', 'SVC5'],
                'TCP_90': [{'port': 90, 'protocol': 'tcp'}],
            },
        }
        self.defs = naming.Naming(None)
        self.defs.ParseDefinitionsObject(defs_obj, "example_defs.yaml")


if __name__ == '__main__':
    absltest.main()
