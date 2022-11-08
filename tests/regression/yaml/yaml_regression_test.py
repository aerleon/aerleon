"""Regression tests for YAML front-end."""
import multiprocessing
import os
import pathlib
import shutil
import tempfile

from unittest import mock

from absl.testing import absltest

from aerleon import aclgen
from aerleon.lib import nacaddr, naming, policy, yaml as yaml_frontend
from tests.regression_utils import capture

EXP_INFO = 2


class YAMLPolAATest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.test_subdirectory = tempfile.mkdtemp()
        self.def_dir = pathlib.Path(self.test_subdirectory).joinpath('def')
        self.pol_dir = pathlib.Path(self.test_subdirectory).joinpath('policies')
        shutil.rmtree(self.test_subdirectory, ignore_errors=True)
        os.mkdir(self.test_subdirectory)
        shutil.copytree('def', self.def_dir)
        shutil.copytree('policies', self.pol_dir)
        self.context = multiprocessing.get_context()
        self.max_renderers = 10
        self.exp_info = 2
        self.ignore_directories = ['DEPRECATED', 'def']

    @mock.patch("aerleon.aclgen.WriteFiles")
    def testCompareEquivalentYamlPol(self, mockWriteFiles):
        test_files = (
            'sample_cisco_lab',
            'sample_ipset',
            'sample_arista_tp',
            'sample_paloalto',
            'sample_srx',
            'sample_k8s',
        )
        for file_name in test_files:
            pol_filename = f"{file_name}.pol"

            policy_file = (
                pathlib.Path(self.test_subdirectory)
                .joinpath('policies/pol/')
                .joinpath(pol_filename)
            )
            aclgen.Run(
                str(self.pol_dir),
                str(self.def_dir),
                str(policy_file),
                str(self.test_subdirectory),
                self.exp_info,
                self.max_renderers,
                self.ignore_directories,
                None,
                None,
                self.context,
            )

            yaml_filename = f"{file_name}_yaml.pol.yaml"
            policy_file = (
                pathlib.Path(self.test_subdirectory)
                .joinpath('policies/pol/')
                .joinpath(yaml_filename)
            )
            aclgen.Run(
                str(self.pol_dir),
                str(self.def_dir),
                str(policy_file),
                str(self.test_subdirectory),
                self.exp_info,
                self.max_renderers,
                self.ignore_directories,
                None,
                None,
                self.context,
            )
            output_from_pol = mockWriteFiles.call_args_list[0][0][0][0][1]
            output_from_yaml = mockWriteFiles.call_args_list[1][0][0][0][1]
            self.assertEqual(output_from_pol, output_from_yaml)
            mockWriteFiles.reset_mock()


YAML_POLICY_WITH_INCLUDE = """
filters:
- header:
    targets:
      ipset: OUTPUT DROP
  terms:
  - include: include_test_terms.pol-include.yaml
"""
YAML_POLICY_BASE_1 = """
filters:
- header:
    comment: |
        this is a test acl
        this is another comment
    targets:
      juniper: test-filter
  terms:
  - include: include_test_terms.pol-include.yaml
"""
YAML_POLICY_BASE_2 = """
filters:
- header:
    comment: this goes in the other direction
    targets:
      juniper: test-filter-outbound
  terms:
  - include: include_test_terms.pol-include.yaml
"""
YAML_POLICY_BASE_3 = """
filters:
- header:
    comment: test header 3
    targets:
      cisco: 50 standard
  terms:
  - include: include_test_terms.pol-include.yaml
"""
YAML_POLICY_BASE_4 = """
filters:
- header:
    comment: test header 4
    targets:
      iptables:
  terms:
  - include: include_test_terms.pol-include.yaml
"""
YAML_POLICY_BASE_5 = """
filters:
- header:
    comment: test header 5
    targets:
      gce: global/networks/default
  terms:
  - include: include_test_terms.pol-include.yaml
"""
YAML_POLICY_BASE_6 = """
filters:
- header:
    comment: this is a test nftable acl
    targets:
      nftables: chain_name input 0 inet
  terms:
  - include: include_test_terms.pol-include.yaml
"""
YAML_POLICY_BASE_V6 = """
filters:
- header:
    comment: |
      this is a test inet6 acl
      this is another comment
    targets:
      juniper: test-filter inet6
  terms:
  - include: include_test_terms.pol-include.yaml
"""
YAML_POLICY_BASE_SRX = """
filters:
- header:
    targets:
      srx: from-zone foo to-zone bar
  terms:
  - include: include_test_terms.pol-include.yaml
"""


@mock.patch.object(yaml_frontend.logging, "warning")
@mock.patch.object(yaml_frontend, "_load_include_file")
class YAMLPolicyTermTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = mock.create_autospec(naming.Naming)
        self.base_dir = ""

    @capture.stdout
    def testGoodPol(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-1
          protocol: icmp
          action: accept
        - name: good-term-2
          protocol: tcp
          source-address: PROD_NETWORK
          action: accept
        """
        self.naming.GetNetAddr.return_value = [nacaddr.IPv4('10.0.0.0/8')]
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        # we should only have one filter from that
        self.assertEqual(len(pol.filters), 1)
        header, terms = pol.filters[0]
        self.assertEqual(type(pol), policy.Policy)
        self.assertEqual(str(terms[0].protocol[0]), 'icmp')
        self.assertEqual(len(terms), 2)
        # the comment is stored as a double quoted string, complete with double
        # quotes.
        self.assertEqual(str(header.comment[0]), 'this is a test acl')
        self.assertEqual(str(header.comment[1]), 'this is another comment')
        self.assertEqual(str(header.target[0]), 'juniper')

        self.naming.GetNetAddr.assert_called_once_with('PROD_NETWORK')

    @capture.stdout
    def testService(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-1
          protocol: icmp
          action: accept
        - name: good-term-3
          protocol: tcp
          source-address: PROD_NETWORK
          destination-port: SMTP
          action: accept
        """
        self.naming.GetNetAddr.return_value = [nacaddr.IPv4('10.0.0.0/8')]
        self.naming.GetServiceByProto.return_value = ['25']

        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)

        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(len(terms), 2)
        self.assertEqual(str(terms[1].protocol[0]), 'tcp')
        self.assertEqual(terms[1].destination_port[0], (25, 25))

        self.naming.GetNetAddr.assert_called_once_with('PROD_NETWORK')
        self.naming.GetServiceByProto.assert_called_once_with('SMTP', 'tcp')

    @capture.stdout
    def testNumericProtocol(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-4
          protocol: 1
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(str(terms[0].protocol[0]), '1')

    @capture.stdout
    def testHopLimitSingle(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-v6-1
          hop-limit: 5
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(str(terms[0].hop_limit[0]), '5')

    @capture.stdout
    def testHopLimitRange(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-v6-2
          hop-limit: 5-7
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)

        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(str(terms[0].hop_limit[2]), '7')

    @capture.stdout
    def testMinimumTerm(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-5
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)

        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(len(terms), 1)
        self.assertEqual(str(terms[0].action[0]), 'accept')

    @capture.stdout
    def testMinimumTerm2(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-9
          comment: |
            first comment
            second comment
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(str(terms[0].comment[0]), 'first comment')
        self.assertEqual(str(terms[0].comment[1]), 'second comment')

    @capture.stdout
    def testLogNameTerm(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-37
          protocol: icmp
          log-name: my special prefix
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_6,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(str(terms[0].log_name), 'my special prefix')

    @capture.stdout
    def testPortCollapsing(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-6
          protocol: tcp
          destination-port: MYSQL HIGH_PORTS
          action: accept
        """
        self.naming.GetServiceByProto.return_value = ['3306']
        self.naming.GetServiceByProto.return_value = ['1024-65535']
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertSequenceEqual(terms[0].destination_port, [(1024, 65535)])

        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('MYSQL', 'tcp'), mock.call('HIGH_PORTS', 'tcp')], any_order=True
        )

    @capture.stdout
    def testPortCollapsing2(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-8
          protocol: tcp udp
          destination-port: DNS
          action: accept
        """
        self.naming.GetServiceByProto.side_effect = [['53'], ['53']]
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertSequenceEqual(terms[0].destination_port, [(53, 53)])

        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('DNS', 'tcp'), mock.call('DNS', 'udp')], any_order=True
        )

    @capture.stdout
    def testTermEquality(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-19
          source-port: HTTP MYSQL
          destination-address: PROD_EXTERNAL_SUPER PROD_NETWORK
          protocol: tcp
          action: accept
        - name: good-term-20
          source-port: MYSQL HTTP
          destination-address: PROD_NETWORK PROD_EXTERNAL_SUPER
          protocol: tcp
          action: accept
        - name: good-term-21
          source-port: MYSQL HTTPS
          destination-address: PROD_NETWORK PROD_EXTERNAL_SUPER
          protocol: tcp
          action: accept
        """
        self.naming.GetNetAddr.side_effect = [
            [
                nacaddr.IPv4('64.233.160.0/19'),
                nacaddr.IPv4('66.102.0.0/20'),
                nacaddr.IPv4('66.249.80.0/20'),
                nacaddr.IPv4('72.14.192.0/18'),
                nacaddr.IPv4('72.14.224.0/20'),
                nacaddr.IPv4('216.239.32.0/19'),
            ],
            [nacaddr.IPv4('10.0.0.0/8')],
            [nacaddr.IPv4('10.0.0.0/8')],
            [
                nacaddr.IPv4('64.233.160.0/19'),
                nacaddr.IPv4('66.102.0.0/20'),
                nacaddr.IPv4('66.249.80.0/20'),
                nacaddr.IPv4('72.14.192.0/18'),
                nacaddr.IPv4('72.14.224.0/20'),
                nacaddr.IPv4('216.239.32.0/19'),
            ],
            [nacaddr.IPv4('10.0.0.0/8')],
            [
                nacaddr.IPv4('64.233.160.0/19'),
                nacaddr.IPv4('66.102.0.0/20'),
                nacaddr.IPv4('66.249.80.0/20'),
                nacaddr.IPv4('72.14.192.0/18'),
                nacaddr.IPv4('72.14.224.0/20'),
                nacaddr.IPv4('216.239.32.0/19'),
            ],
        ]
        self.naming.GetServiceByProto.side_effect = [
            ['80'],
            ['3306'],
            ['3306'],
            ['80'],
            ['3306'],
            ['443'],
        ]
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(len(terms), 3)
        self.assertEqual(terms[0], terms[1])
        self.assertNotEqual(terms[0], terms[2])

        self.naming.GetNetAddr.assert_has_calls(
            [
                mock.call('PROD_EXTERNAL_SUPER'),
                mock.call('PROD_NETWORK'),
                mock.call('PROD_NETWORK'),
                mock.call('PROD_EXTERNAL_SUPER'),
                mock.call('PROD_NETWORK'),
                mock.call('PROD_EXTERNAL_SUPER'),
            ],
            any_order=True,
        )
        self.naming.GetServiceByProto.assert_has_calls(
            [
                mock.call('HTTP', 'tcp'),
                mock.call('MYSQL', 'tcp'),
                mock.call('MYSQL', 'tcp'),
                mock.call('HTTP', 'tcp'),
                mock.call('MYSQL', 'tcp'),
                mock.call('HTTPS', 'tcp'),
            ],
            any_order=True,
        )

    @capture.stdout
    def testGoodDestAddrExcludes(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-7
          protocol: tcp
          destination-address: PROD_NETWORK
          destination-exclude: PROD_EH
          action: accept
        """
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IPv4('10.0.0.0/8')],
            [nacaddr.IPv4('10.62.0.0/15')],
        ]
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        _, terms = pol.filters[0]
        self.assertEqual(terms[0].destination_address_exclude[0], nacaddr.IPv4('10.62.0.0/15'))

        self.naming.GetNetAddr.assert_has_calls(
            [mock.call('PROD_NETWORK'), mock.call('PROD_EH')], any_order=True
        )

    @capture.stdout
    def testGoodSrcAddrExcludes(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-26
          protocol: tcp
          source-address: PROD_NETWORK
          source-exclude: PROD_EH
          action: accept
        """
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IPv4('10.0.0.0/8')],
            [nacaddr.IPv4('10.62.0.0/15')],
        ]
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        _, terms = pol.filters[0]
        self.assertEqual(terms[0].source_address_exclude[0], nacaddr.IPv4('10.62.0.0/15'))

        self.naming.GetNetAddr.assert_has_calls(
            [mock.call('PROD_NETWORK'), mock.call('PROD_EH')], any_order=True
        )

    @capture.stdout
    def testGoodAddrExcludes(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-27
          protocol: tcp
          address: PROD_NETWORK
          address-exclude: PROD_EH
          action: accept
        """
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IPv4('10.0.0.0/8')],
            [nacaddr.IPv4('10.62.0.0/15')],
        ]
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        _, terms = pol.filters[0]
        self.assertEqual(terms[0].address_exclude[0], nacaddr.IPv4('10.62.0.0/15'))

        self.naming.GetNetAddr.assert_has_calls(
            [mock.call('PROD_NETWORK'), mock.call('PROD_EH')], any_order=True
        )

    @capture.stdout
    def testGoodAddrExcludesFlatten(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-27
          protocol: tcp
          address: PROD_NETWORK
          address-exclude: PROD_EH
          action: accept
        """
        self.naming.GetNetAddr.side_effect = [
            [nacaddr.IPv4('10.0.0.0/8')],
            [nacaddr.IPv4('10.62.0.0/15'), nacaddr.IPv4('10.129.0.0/15', strict=False)],
        ]
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        _, terms = pol.filters[0]
        terms[0].FlattenAll()

        expected = sorted(
            [
                nacaddr.IPv4(u'10.0.0.0/11'),
                nacaddr.IPv4(u'10.32.0.0/12'),
                nacaddr.IPv4(u'10.48.0.0/13'),
                nacaddr.IPv4(u'10.56.0.0/14'),
                nacaddr.IPv4(u'10.60.0.0/15'),
                nacaddr.IPv4(u'10.64.0.0/10'),
                nacaddr.IPv4(u'10.130.0.0/15'),
                nacaddr.IPv4(u'10.132.0.0/14'),
                nacaddr.IPv4(u'10.136.0.0/13'),
                nacaddr.IPv4(u'10.144.0.0/12'),
                nacaddr.IPv4(u'10.160.0.0/11'),
                nacaddr.IPv4(u'10.192.0.0/10'),
            ]
        )
        self.assertEqual(sorted(terms[0].address), expected)

        self.naming.GetNetAddr.assert_has_calls(
            [mock.call('PROD_NETWORK'), mock.call('PROD_EH')], any_order=True
        )

    @capture.stdout
    def testGoodAddrExcludesFlattenMultiple(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-27
          protocol: tcp
          address: PROD_NETWORK
          address-exclude: PROD_EH
          action: accept
        """
        self.naming.GetNetAddr.side_effect = [
            [
                nacaddr.IPv4('10.1.0.0/16'),
                nacaddr.IPv4('10.2.0.0/16'),
                nacaddr.IPv4('10.3.0.0/16'),
                nacaddr.IPv4('192.168.0.0/16'),
            ],
            [nacaddr.IPv4('10.2.0.0/15')],
        ]
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        _, terms = pol.filters[0]
        terms[0].FlattenAll()
        self.assertEqual(
            terms[0].address, [nacaddr.IPv4('10.1.0.0/16'), nacaddr.IPv4('192.168.0.0/16')]
        )

        self.naming.GetNetAddr.assert_has_calls(
            [mock.call('PROD_NETWORK'), mock.call('PROD_EH')], any_order=True
        )

    @capture.stdout
    def testGoodAddrExcludesFlattenAll(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-27
          protocol: tcp
          address: PROD_NETWORK
          address-exclude: PROD_EH
          action: accept
        """
        self.naming.GetNetAddr.side_effect = [
            [
                nacaddr.IPv4('10.1.0.0/16'),
                nacaddr.IPv4('10.2.0.0/16'),
                nacaddr.IPv4('10.3.0.0/16'),
            ],
            [nacaddr.IPv4('10.0.0.0/8')],
        ]
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        _, terms = pol.filters[0]
        terms[0].FlattenAll()
        self.assertEqual(terms[0].address, [])

        self.naming.GetNetAddr.assert_has_calls(
            [mock.call('PROD_NETWORK'), mock.call('PROD_EH')], any_order=True
        )

    @capture.stdout
    def testLogging(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-10
          logging: true
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(str(terms[0].logging[0]), 'true')

    @capture.stdout
    def testICMPTypes(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-10
          protocol: icmp
          icmp-type: echo-reply echo-request unreachable
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(terms[0].icmp_type[0], 'echo-reply')

    @capture.stdout
    def testICMPTypesSorting(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-11
          protocol: icmp
          icmp-type: unreachable echo-request echo-reply
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        icmp_types = ['echo-reply', 'echo-request', 'unreachable']
        expected = 'icmp_type: %s' % icmp_types
        self.assertIn(expected, str(pol))

    @capture.stdout
    def testICMPCodesSorting(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-11
          icmp-type: unreachable
          icmp-code: 15 4 9 1
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertIn('icmp_code: [1, 4, 9, 15]', str(pol))

    @capture.stdout
    def testReservedWordTermName(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: qos-good-term-12
          action: accept
          qos: af4
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(terms[0].qos, 'af4')
        self.assertEqual(terms[0].name, 'qos-good-term-12')

    @capture.stdout
    def testMultiPortLines(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-13
          source-port: GOOGLE_PUBLIC SNMP
          protocol: udp
          action: accept
        """
        self.naming.GetServiceByProto.side_effect = [['22', '160-162'], ['161']]
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertSequenceEqual(terms[0].source_port, [(22, 22), (160, 162)])

        self.naming.GetServiceByProto.assert_has_calls(
            [mock.call('GOOGLE_PUBLIC', 'udp'), mock.call('SNMP', 'udp')], any_order=True
        )

    @capture.stdout
    def testSourcePrefixList(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-14
          source-prefix: foo_prefix_list
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(terms[0].source_prefix, ['foo_prefix_list'])

    @capture.stdout
    def testDestinationPrefixList(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-15
          destination-prefix: bar_prefix_list baz_prefix_list
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(terms[0].destination_prefix, ['bar_prefix_list', 'baz_prefix_list'])

    @capture.stdout
    def testSourcePrefixListExcept(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-38
          source-prefix-except: foo_prefix_list
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(terms[0].source_prefix_except, ['foo_prefix_list'])

    @capture.stdout
    def testDestinationPrefixListExcept(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-39
          destination-prefix-except: bar_prefix_list baz_prefix_list
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(
            terms[0].destination_prefix_except, ['bar_prefix_list', 'baz_prefix_list']
        )

    @capture.stdout
    def testSourcePrefixListMixed(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-38
          source-prefix: foo_prefix_list
          source-prefix-except: foo_prefix_list_except
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(terms[0].source_prefix, ['foo_prefix_list'])
        self.assertEqual(terms[0].source_prefix_except, ['foo_prefix_list_except'])

    @capture.stdout
    def testDestinationPrefixListMixed(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: good-term-39
          destination-prefix: bar_prefix_list
          destination-prefix-except: bar_prefix_list_except
          action: accept
        """
        pol = yaml_frontend.load_str(
            YAML_POLICY_BASE_1,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        print(pol)
        self.assertEqual(len(pol.filters), 1)
        _, terms = pol.filters[0]
        self.assertEqual(terms[0].destination_prefix, ['bar_prefix_list'])
        self.assertEqual(terms[0].destination_prefix_except, ['bar_prefix_list_except'])

    def testBadTermName(self, mock_open_include, _mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term -name
          action: deny
        """
        self.assertTermRaises(TypeError)

    def testBadKeyName(self, mock_open_include, mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term-2
          prootocol: tcp
          action: accept
        """
        self.assertTermWarns(mock_warn, regex="Unexpected term keyword")

    def testBadPortProtocol(self, mock_open_include, mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term-3
          protocol: tcp
          source-port: SNMP
          action: accept
        """
        self.naming.GetServiceByProto('SNMP', 'tcp').AndReturn([])
        self.assertTermRaises(policy.TermPortProtocolError)

    def testBadPortProtocol2(self, mock_open_include, mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term-4
          source-port: SNMP
          action: accept
        """
        self.assertTermRaises(policy.TermPortProtocolError)

    def testBadLogging(self, mock_open_include, mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term-6
          logging: unvalidloggingoption
          action: accept
        """
        self.assertTermRaises(policy.InvalidTermLoggingError)

    def testBadAction(self, mock_open_include, mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term-7
          action: discard
        """
        self.assertTermRaises(policy.InvalidTermActionError)

    def testBadProtocolEtherTypes(self, mock_open_include, mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term-9
          ether-type: arp
          protocol: udp
          action: accept
        """
        self.assertTermRaises(policy.TermProtocolEtherTypeError)

    def testVerbatimMixed(self, mock_open_include, mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term-10
          verbatim:
            cisco: mary had a little lamb
          action: accept
        """
        self.assertTermRaises(policy.ParseError)

    def testBadICMPTypes(self, mock_open_include, mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term-12
          protocol: icmp
          icmp-type: echo-foo packet-too-beaucoups
          action: accept
        """
        self.assertTermRaises(policy.TermInvalidIcmpType)

    def testBadICMPCodes(self, mock_open_include, mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term-13
          protocol: icmp
          icmp-type: unreachable
          icmp-code: 99
          action: accept
        """
        self.assertTermRaises(policy.ICMPCodeError)

    def testBadICMPCodes2(self, mock_open_include, mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term-14
          protocol: icmp
          icmp-type: unreachable redirect
          icmp-code: 3
          action: accept
        """
        self.assertTermRaises(policy.ICMPCodeError)

    def testInvalidTTL(self, mock_open_include, mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term-15
          ttl: 300
          action: accept
        """
        self.assertTermRaises(policy.InvalidTermTTLValue)

    def testGREandTCPUDPError(self, mock_open_include, mock_warn):
        mock_open_include.return_value = """terms:
        - name: bad-term-16
          destination-port: FOO
          protocol: tcp udp gre
          action: accept
        """
        self.naming.GetServiceByProto.return_value = ['25']
        self.assertTermRaises(policy.MixedPortandNonPortProtos)

    def assertTermRaises(self, error_type):
        with self.assertRaises(error_type):
            yaml_frontend.load_str(
                YAML_POLICY_WITH_INCLUDE,
                filename="policy_test.pol.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )

    def assertTermWarns(self, mock_warn, *, regex):
        yaml_frontend.load_str(
            YAML_POLICY_WITH_INCLUDE,
            filename="policy_test.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        self.assertRegex(mock_warn.call_args[0][0], regex)


if __name__ == '__main__':
    absltest.main()
