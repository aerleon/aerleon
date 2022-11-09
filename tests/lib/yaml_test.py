"""Unittest for YAML front-end."""

from absl.testing import absltest
from unittest import mock
from aerleon.lib import nacaddr, naming, yaml as yaml_frontend

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
  - include: include_1.pol-include.yaml
  - name: allow-web-to-mail
    source-address: WEB_SERVERS
    destination-address: MAIL_SERVERS
    action: accept
"""
GOOD_INCLUDE_YAML = """
terms:
- name: deny-to-bogons
  destination-address: RESERVED
  action: deny
"""
BAD_INCLUDE_YAML_EMPTY = """
terms:
"""
BAD_INCLUDE_YAML_INFINITE_RECURSION = """
terms:
- include: include_1.pol-include.yaml
"""
BAD_INCLUDE_YAML_INVALID_FILENAME = """
terms:
- include: include_1.pol.yaml
"""
BAD_INCLUDE_YAML_INVALID_YAML = """
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


def open_good_includes():
    pass


def open_bad_include_infinite_recursion():
    pass


def open_bad_include_empty():
    pass


class YAMLFrontEndTest(absltest.TestCase):
    def setUp(self):
        self.naming = mock.create_autospec(naming.Naming)
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]
        self.base_dir = ""

    def testTypeErrors(self):
        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                "other_key:",
                filename="policy_empty.pol.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Policy file must contain one or more filter sections. File=policy_empty.pol.yaml.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                "filters: scalar-value",
                filename="policy_scalar_filter.pol.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Policy file must contain one or more filter sections. File=policy_scalar_filter.pol.yaml.",  # noqa: E501
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                BAD_YAML_POLICY_NO_HEADER,
                filename="policy_no_header.pol.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a header section. File=policy_no_header.pol.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                BAD_YAML_POLICY_SCALAR_HEADER,
                filename="policy_scalar_header.pol.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a header section. File=policy_scalar_header.pol.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                BAD_YAML_POLICY_NO_TARGET,
                filename="policy_no_target.pol.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a terms section. File=policy_no_target.pol.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                BAD_YAML_POLICY_NO_TERMS,
                filename="policy_no_terms.pol.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a terms section. File=policy_no_terms.pol.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                BAD_YAML_POLICY_SCALAR_TERMS,
                filename="policy_scalar_terms.pol.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a header section. File=policy_scalar_terms.pol.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                BAD_YAML_POLICY_TERM_NO_NAME,
                filename="policy_term_no_name.pol.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message), "Term must have a name. File=policy_term_no_name.pol.yaml, Line=7."
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.ParsePolicy(
                IGNORED_YAML_POLICY_NO_TARGET,
                filename="policy_no_targets.pol.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter header cannot be empty. File=policy_no_targets.pol.yaml, Line=3.",
        )

    @mock.patch.object(yaml_frontend, "_raw_policy_to_policy")
    @mock.patch.object(yaml_frontend.logging, "warning")
    def testWarnings(self, mock_warning, _mock_raw_to_policy):
        yaml_frontend.ParsePolicy(
            "",
            filename="policy_empty.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        self.assertEqual(mock_warning.call_args[0][0].message, "Ignoring empty policy file.")
        mock_warning.reset_mock()

        yaml_frontend.ParsePolicy(
            IGNORED_YAML_POLICY_NO_TERMS,
            filename="policy_no_targets.pol.yaml",
            base_dir=self.base_dir,
            definitions=self.naming,
        )
        self.assertEqual(mock_warning.call_args[0][0].message, "Ignoring filter with zero terms.")
        mock_warning.reset_mock()

    @mock.patch.object(yaml_frontend, "_raw_policy_to_policy")
    @mock.patch.object(yaml_frontend.logging, "warning")
    def testIncludeEmptySource(self, mock_warning, _mock_raw_to_policy):
        with mock.patch("builtins.open", mock.mock_open(read_data="")):
            yaml_frontend.ParsePolicy(
                GOOD_YAML_POLICY_INCLUDE,
                filename="policy_with_empty_include.pol.yaml",
                base_dir=self.base_dir,
                definitions=self.naming,
            )
        self.assertEqual(
            mock_warning.call_args[0][0].message, "Ignoring empty policy include source."
        )
        self.assertEqual(mock_warning.call_args[0][0].filename, "include_1.pol-include.yaml")

    def testIncludeInfiniteRecursion(self):
        with mock.patch(
            "builtins.open", mock.mock_open(read_data=BAD_INCLUDE_YAML_INFINITE_RECURSION)
        ):
            with self.assertRaises(yaml_frontend.ExcessiveRecursionError) as arcm:
                yaml_frontend.ParsePolicy(
                    GOOD_YAML_POLICY_INCLUDE,
                    filename="policy_with_include.pol.yaml",
                    base_dir=self.base_dir,
                    definitions=self.naming,
                )
            user_message = arcm.exception.args[0]
            self.assertEqual(user_message.filename, "include_1.pol-include.yaml")
            self.assertEqual(user_message.line, 3)
            self.assertEqual(
                user_message.include_chain,
                [
                    ('policy_with_include.pol.yaml', 10),
                    ('include_1.pol-include.yaml', 3),
                    ('include_1.pol-include.yaml', 3),
                    ('include_1.pol-include.yaml', 3),
                    ('include_1.pol-include.yaml', 3),
                    ('include_1.pol-include.yaml', 3),
                ],
            )
            self.assertEqual(
                str(user_message),
                """Excessive recursion: include depth limit of 5 reached. File=include_1.pol-include.yaml, Line=3.
Include stack:
> File='policy_with_include.pol.yaml', Line=10 (Top Level)
> File='include_1.pol-include.yaml', Line=3
> File='include_1.pol-include.yaml', Line=3
> File='include_1.pol-include.yaml', Line=3
> File='include_1.pol-include.yaml', Line=3
> File='include_1.pol-include.yaml', Line=3""",  # noqa: E501
            )

    def testIncludeInvalidFilename(self):
        with mock.patch(
            "builtins.open", mock.mock_open(read_data=BAD_INCLUDE_YAML_INVALID_FILENAME)
        ):
            with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
                yaml_frontend.ParsePolicy(
                    GOOD_YAML_POLICY_INCLUDE,
                    filename="policy_with_include.pol.yaml",
                    base_dir=self.base_dir,
                    definitions=self.naming,
                )
            user_message = arcm.exception.args[0]
            self.assertEqual(user_message.filename, "include_1.pol-include.yaml")
            self.assertEqual(user_message.line, 3)
            self.assertEqual(
                user_message.include_chain,
                [('policy_with_include.pol.yaml', 10), ('include_1.pol-include.yaml', 3)],
            )
            self.assertEqual(
                str(user_message),
                """Policy include source include_1.pol.yaml must end in ".pol-include.yaml". File=include_1.pol-include.yaml, Line=3.
Include stack:
> File='policy_with_include.pol.yaml', Line=10 (Top Level)
> File='include_1.pol-include.yaml', Line=3""",  # noqa: E501
            )

    def testIncludeInvalidYAML(self):
        with mock.patch("builtins.open", mock.mock_open(read_data=BAD_INCLUDE_YAML_INVALID_YAML)):
            with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
                yaml_frontend.ParsePolicy(
                    GOOD_YAML_POLICY_INCLUDE,
                    filename="policy_with_include.pol.yaml",
                    base_dir=self.base_dir,
                    definitions=self.naming,
                )
            user_message = arcm.exception.args[0]
            self.assertEqual(user_message.filename, "include_1.pol-include.yaml")
            self.assertEqual(
                user_message.include_chain,
                [('policy_with_include.pol.yaml', 10)],
            )
            self.assertEqual(
                str(user_message),
                """Unable to read file as YAML. File=include_1.pol-include.yaml.""",
            )

    def testBasicPolicyModel(self):
        pol = yaml_frontend.ParsePolicy(
            GOOD_YAML_POLICY_BASIC,
            filename="policy_basic.pol.yaml",
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


if __name__ == '__main__':
    absltest.main()

# TODO(jb) try MULTI_DOC example
# TODO(jb) seems like buildPolicy crashes when targets is not recognized, should raise
