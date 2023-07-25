"""Unittest for YAML front-end."""

from unittest import mock

from absl.testing import absltest

from aerleon.lib import nacaddr, naming
from aerleon.lib import yaml as yaml_frontend

GOOD_YAML_POLICY_BASIC = """
filters:
- header:
    targets:
      ipset: OUTPUT DROP
  terms:
    - name: deny-to-reserved
      destination-address: RESERVED
      action: deny
    - name: deny-to-bogons
      destination-address: RESERVED
      action: deny
    - name: allow-web-to-mail
      source-address: WEB_SERVERS
      destination-address: MAIL_SERVERS
      action: accept
"""
GOOD_YAML_POLICY_INCLUDE = """
filters:
- header:
    targets:
      ipset: OUTPUT DROP
  terms:
  - name: deny-to-reserved
    destination-address: RESERVED
    action: deny
  - include: include_1.yaml
  - name: allow-web-to-mail
    source-address: WEB_SERVERS
    destination-address: MAIL_SERVERS
    action: accept
"""
GOOD_POLICY_INCLUDE_FILTERS = """
filters:
- include: filters_include1.yaml
- include: filters_include2.yaml
"""
GOOD_INCLUDE_YAML = """
terms:
- name: deny-to-bogons
  destination-address: RESERVED
  action: deny
"""
GOOD_INCLUDE_FILTERS_YAML = """
filters:
- header:
    targets:
      ipset: OUTPUT DROP
  terms:
  - name: deny-to-reserved
    destination-address: RESERVED
    action: deny
  - name: allow-web-to-mail
    source-address: WEB_SERVERS
    destination-address: MAIL_SERVERS
    action: accept
"""
GOOD_INCLUDE_FILTERS_YAML_ONLY = """
filters_include_only:
- header:
    targets:
      ipset: OUTPUT DROP
  terms:
  - name: deny-to-reserved
    destination-address: RESERVED
    action: deny
  - name: allow-web-to-mail
    source-address: WEB_SERVERS
    destination-address: MAIL_SERVERS
    action: accept
"""
BAD_INCLUDE_YAML_EMPTY = """
terms:
"""
BAD_INCLUDE_YAML_INFINITE_RECURSION = """
terms:
- include: include_1.yaml
"""
BAD_INCLUDE_YAML_INVALID_FILENAME = """
terms:
- include: include_1.pol
"""
BAD_INCLUDE_YAML_INVALID_PATH = """
terms:
- include: /tmp/include_2.yaml
"""
BAD_INCLUDE_YAML_INVALID_YAML = """
%INVALID YAML% &unknown
"""
BAD_INCLUDE_FILTERS_YAML_EMPTY = """
filters:
"""
BAD_INCLUDE_FILTERS_YAML_INFINITE_RECURSION = """
filters:
- include: filters_include1.yaml
"""
BAD_INCLUDE_FILTERS_YAML_INVALID_STRUCTURE = """
terms:
- include: include_1.pol
"""
BAD_INCLUDE_FILTERS_YAML_INVALID_PATH = """
filters:
- include: /tmp/include_2.yaml
"""
BAD_INCLUDE_FILTERS_YAML_INVALID_YAML = """
%INVALID YAML% &unknown
"""
BAD_YAML_POLICY_NO_HEADER = """
filters:
- terms: scalar-value
"""
BAD_YAML_POLICY_SCALAR_HEADER = """
filters:
- header: scalar-value
"""
BAD_YAML_POLICY_NO_TARGET = """
filters:
- header:
    comment: This filter has no target
"""
BAD_YAML_POLICY_NO_TERMS = """
filters:
- header:
    targets:
      ipset: OUTPUT DROP
"""
BAD_YAML_POLICY_SCALAR_TERMS = """
filters:
- terms: scalar-value
"""
BAD_YAML_POLICY_EMPTY_TERMS = """
filters:
- header:
    targets:
      ipset: OUTPUT DROP
  terms:
"""
BAD_YAML_POLICY_TERM_NO_NAME = """
filters:
- header:
    targets:
      ipset: OUTPUT DROP
  terms:
  - action: deny
  - name: valid-term-name
    action: deny
"""
IGNORED_YAML_POLICY_NO_TARGET = """
filters:
- header:
    targets:
    comment: This filter has no target
  terms:
  - name: deny-to-reserved
    destination-address: RESERVED
    action: deny
"""
IGNORED_YAML_POLICY_NO_TERMS = """
filters:
- header:
    targets:
      ipset: OUTPUT DROP
  terms:
"""
MULTI_DOC_POLICY = """
filters:
- header:
    targets:
      ipset: OUTPUT DROP
  terms:
  - name: deny-to-reserved
    destination-address: RESERVED
    action: deny
  - name: deny-to-bogons
    destination-address: RESERVED
    action: deny
  - name: allow-web-to-mail
    source-address: WEB_SERVERS
    destination-address: MAIL_SERVERS
    action: accept
---
filters2:
- header:
    targets:
      ipset: OUTPUT DROP
  terms:
  - name: deny-to-reserved
    destination-address: RESERVED
    action: deny
  - name: deny-to-bogons
    destination-address: RESERVED
    action: deny
  - name: allow-web-to-mail
    source-address: WEB_SERVERS
    destination-address: MAIL_SERVERS
    action: accept
"""


class YAMLParsePolicyTest(absltest.TestCase):
    def setUp(self):
        self.naming = mock.create_autospec(naming.Naming)
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]
        self.base_dir = ""

    def testTypeErrors(self):
        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                "other_key:",
                filename="policy_empty.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Policy file must contain one or more filter sections. File=policy_empty.yaml.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                "filters: scalar-value",
                filename="policy_scalar_filter.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Policy file must contain one or more filter sections. File=policy_scalar_filter.yaml.",  # noqa: E501
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                BAD_YAML_POLICY_NO_HEADER,
                filename="policy_no_header.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a header section. File=policy_no_header.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                BAD_YAML_POLICY_SCALAR_HEADER,
                filename="policy_scalar_header.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a header section. File=policy_scalar_header.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                BAD_YAML_POLICY_NO_TARGET,
                filename="policy_no_target.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a terms section. File=policy_no_target.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                BAD_YAML_POLICY_NO_TERMS,
                filename="policy_no_terms.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a terms section. File=policy_no_terms.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                IGNORED_YAML_POLICY_NO_TERMS,
                filename="policy_no_targets.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        self.assertEqual(
            str(user_message),
            "Filter must contain a terms section. File=policy_no_terms.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                BAD_YAML_POLICY_SCALAR_TERMS,
                filename="policy_scalar_terms.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a header section. File=policy_scalar_terms.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                BAD_YAML_POLICY_TERM_NO_NAME,
                filename="policy_term_no_name.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message), "Term must have a name. File=policy_term_no_name.yaml, Line=7."
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                IGNORED_YAML_POLICY_NO_TARGET,
                filename="policy_no_targets.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter header cannot be empty. File=policy_no_targets.yaml, Line=3.",
        )

    @mock.patch.object(yaml_frontend.policy, "FromBuilder")
    @mock.patch.object(yaml_frontend.logging, "warning")
    def testWarnings(self, mock_warning, _mock_raw_to_policy):
        yaml_frontend.ParsePolicy(
            "",
            filename="policy_empty.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        self.assertEqual(mock_warning.call_args[0][0].message, "Ignoring empty policy file.")
        mock_warning.reset_mock()

    @mock.patch.object(yaml_frontend.policy, "FromBuilder")
    @mock.patch.object(yaml_frontend.logging, "warning")
    def testIncludeEmptySource(self, mock_warning, _mock_raw_to_policy):
        with mock.patch("builtins.open", mock.mock_open(read_data="")):
            yaml_frontend.ParsePolicy(
                GOOD_YAML_POLICY_INCLUDE,
                filename="policy_with_empty_include.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        self.assertEqual(
            mock_warning.call_args[0][0].message, "Ignoring empty policy include source."
        )
        self.assertEqual(mock_warning.call_args[0][0].filename, "include_1.yaml")

    @mock.patch.object(yaml_frontend.policy, "FromBuilder")
    @mock.patch.object(yaml_frontend.logging, "warning")
    def testFiltersIncludeEmptySource(self, mock_warning, _mock_raw_to_policy):
        with mock.patch("builtins.open", mock.mock_open(read_data="")):
            yaml_frontend.ParsePolicy(
                GOOD_POLICY_INCLUDE_FILTERS,
                filename="policy_with_empty_include.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        self.assertEqual(mock_warning.call_args[0][0].message, "Ignoring empty policy file.")
        self.assertEqual(mock_warning.call_args[0][0].filename, "filters_include2.yaml")

    def testIncludeInfiniteRecursion(self):
        with self.assertRaises(yaml_frontend.ExcessiveRecursionError) as arcm:
            with mock.patch(
                "builtins.open", mock.mock_open(read_data=BAD_INCLUDE_YAML_INFINITE_RECURSION)
            ):
                yaml_frontend.ParsePolicy(
                    GOOD_YAML_POLICY_INCLUDE,
                    filename="policy_with_include.yaml",
                    base_dir=self.base_dir,
                    definitions=self.naming,
                )
        user_message = arcm.exception.args[0]
        self.assertEqual(user_message.filename, "include_1.yaml")
        self.assertEqual(user_message.line, 3)
        self.assertEqual(
            user_message.include_chain,
            [
                ('policy_with_include.yaml', 10),
                ('include_1.yaml', 3),
                ('include_1.yaml', 3),
                ('include_1.yaml', 3),
                ('include_1.yaml', 3),
                ('include_1.yaml', 3),
            ],
        )
        self.assertEqual(
            str(user_message),
            """Excessive recursion: include depth limit of 5 reached. File=include_1.yaml, Line=3.
Include stack:
> File='policy_with_include.yaml', Line=10 (Top Level)
> File='include_1.yaml', Line=3
> File='include_1.yaml', Line=3
> File='include_1.yaml', Line=3
> File='include_1.yaml', Line=3
> File='include_1.yaml', Line=3""",  # noqa: E501
        )

    def testIncludeInvalidFilename(self):
        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            with mock.patch(
                "builtins.open", mock.mock_open(read_data=BAD_INCLUDE_YAML_INVALID_FILENAME)
            ):
                yaml_frontend.ParsePolicy(
                    GOOD_YAML_POLICY_INCLUDE,
                    filename="policy_with_include.yaml",
                    base_dir=self.base_dir,
                    definitions=self.naming,
                )
        user_message = arcm.exception.args[0]
        self.assertEqual(user_message.filename, "include_1.yaml")
        self.assertEqual(user_message.line, 3)
        self.assertEqual(
            user_message.include_chain,
            [('policy_with_include.yaml', 10), ('include_1.yaml', 3)],
        )
        self.assertEqual(
            str(user_message),
            """Policy include source include_1.pol must end in ".yaml". File=include_1.yaml, Line=3.
Include stack:
> File='policy_with_include.yaml', Line=10 (Top Level)
> File='include_1.yaml', Line=3""",  # noqa: E501
        )

    def testIncludeInvalidPath(self):
        with self.assertRaises(yaml_frontend.BadIncludePath):
            with mock.patch(
                "builtins.open", mock.mock_open(read_data=BAD_INCLUDE_YAML_INVALID_PATH)
            ):
                yaml_frontend.ParsePolicy(
                    GOOD_YAML_POLICY_INCLUDE,
                    filename="policy_with_include.yaml",
                    base_dir=self.base_dir,
                    definitions=self.naming,
                )

    def testIncludeInvalidYAML(self):
        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            with mock.patch(
                "builtins.open", mock.mock_open(read_data=BAD_INCLUDE_YAML_INVALID_YAML)
            ):
                yaml_frontend.ParsePolicy(
                    GOOD_YAML_POLICY_INCLUDE,
                    filename="policy_with_include.yaml",
                    base_dir=self.base_dir,
                    definitions=self.naming,
                )
        user_message = arcm.exception.args[0]
        self.assertEqual(user_message.filename, "include_1.yaml")
        self.assertEqual(
            user_message.include_chain,
            [('policy_with_include.yaml', 10)],
        )
        self.assertEqual(
            str(user_message),
            """Unable to read file as YAML. File=include_1.yaml.""",
        )

    def testSkipIncludeFile(self):
        pol = yaml_frontend.ParsePolicy(
            GOOD_INCLUDE_YAML,
            filename="terms_include.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        self.assertEqual(pol, None)

    def testSkipIncludeFileFilter(self):
        pol = yaml_frontend.ParsePolicy(
            GOOD_INCLUDE_FILTERS_YAML_ONLY,
            filename="filters_include.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        self.assertEqual(pol, None)

    def testParsePolicy(self):
        pol = yaml_frontend.ParsePolicy(
            GOOD_YAML_POLICY_BASIC,
            filename="policy_basic.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        expected_pol = """Policy: {Target[ipset], Comments [], Apply groups: [], except: []:[ name: deny-to-reserved
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['deny'],  name: deny-to-bogons
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['deny'],  name: allow-web-to-mail
  source_address: [IPv4('10.1.1.1/32')]
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['accept']]}"""
        self.assertEqual(str(pol), expected_pol)

    def testParsePolicyInclude(self):
        with mock.patch("builtins.open", mock.mock_open(read_data=GOOD_INCLUDE_YAML)):
            pol = yaml_frontend.ParsePolicy(
                GOOD_YAML_POLICY_INCLUDE,
                filename="policy_include.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        expected_pol = """Policy: {Target[ipset], Comments [], Apply groups: [], except: []:[ name: deny-to-reserved
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['deny'],  name: deny-to-bogons
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['deny'],  name: allow-web-to-mail
  source_address: [IPv4('10.1.1.1/32')]
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['accept']]}"""
        self.assertEqual(str(pol), expected_pol)

    def testParsePolicyIncludeFilter(self):
        with mock.patch("builtins.open", mock.mock_open(read_data=GOOD_INCLUDE_FILTERS_YAML)):
            pol = yaml_frontend.ParsePolicy(
                GOOD_POLICY_INCLUDE_FILTERS,
                filename="policy_include_filters.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        expected_pol = """Policy: {Target[ipset], Comments [], Apply groups: [], except: []:[ name: deny-to-reserved
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['deny'],  name: allow-web-to-mail
  source_address: [IPv4('10.1.1.1/32')]
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['accept']], Target[ipset], Comments [], Apply groups: [], except: []:[ name: deny-to-reserved
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['deny'],  name: allow-web-to-mail
  source_address: [IPv4('10.1.1.1/32')]
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['accept']]}"""
        self.assertEqual(str(pol), expected_pol)

    def testParsePolicyIncludeOnlyFilter(self):
        with mock.patch("builtins.open", mock.mock_open(read_data=GOOD_INCLUDE_FILTERS_YAML_ONLY)):
            pol = yaml_frontend.ParsePolicy(
                GOOD_POLICY_INCLUDE_FILTERS,
                filename="policy_include_filters.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        expected_pol = """Policy: {Target[ipset], Comments [], Apply groups: [], except: []:[ name: deny-to-reserved
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['deny'],  name: allow-web-to-mail
  source_address: [IPv4('10.1.1.1/32')]
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['accept']], Target[ipset], Comments [], Apply groups: [], except: []:[ name: deny-to-reserved
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['deny'],  name: allow-web-to-mail
  source_address: [IPv4('10.1.1.1/32')]
  destination_address: [IPv4('10.1.1.1/32')]
  action: ['accept']]}"""
        self.assertEqual(str(pol), expected_pol)


if __name__ == '__main__':
    absltest.main()
