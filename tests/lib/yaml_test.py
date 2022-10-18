"""Unittest for YAML front-end."""

from absl.testing import absltest
from unittest import mock
import aerleon.lib.yaml as yaml_frontend

GOOD_YAML_POLICY_BASIC = """
filters:
- header:
    targets:
    - target: ipset
      options: OUTPUT DROP
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
    - target: ipset
      options: OUTPUT DROP
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
    - target: ipset
      options: OUTPUT DROP
"""
BAD_YAML_POLICY_SCALAR_TERMS = """
filters:
- terms: scalar-value
"""
BAD_YAML_POLICY_EMPTY_TERMS = """
filters:
- header:
    targets:
    - target: ipset
      options: OUTPUT DROP
  terms:
"""
BAD_YAML_POLICY_TERM_NO_NAME = """
filters:
- header:
    targets:
    - target: ipset
      options: OUTPUT DROP
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
    - target: ipset
      options: OUTPUT DROP
  terms:
"""
MULTI_DOC_POLICY = """
filters:
- header:
    targets:
    - target: ipset
      options: OUTPUT DROP
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
    - target: ipset
      options: OUTPUT DROP
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
    def testTypeErrors(self):
        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.load_str("other_key:", filename="policy_empty.pol.yaml")
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Policy file must contain one or more filter sections. File=policy_empty.pol.yaml.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.load_str(
                "filters: scalar-value", filename="policy_scalar_filter.pol.yaml"
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Policy file must contain one or more filter sections. File=policy_scalar_filter.pol.yaml.",  # noqa: E501
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.load_str(BAD_YAML_POLICY_NO_HEADER, filename="policy_no_header.pol.yaml")
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a header section. File=policy_no_header.pol.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.load_str(
                BAD_YAML_POLICY_SCALAR_HEADER, filename="policy_scalar_header.pol.yaml"
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a header section. File=policy_scalar_header.pol.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.load_str(BAD_YAML_POLICY_NO_TARGET, filename="policy_no_target.pol.yaml")
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a terms section. File=policy_no_target.pol.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.load_str(BAD_YAML_POLICY_NO_TERMS, filename="policy_no_terms.pol.yaml")
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a terms section. File=policy_no_terms.pol.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.load_str(
                BAD_YAML_POLICY_SCALAR_TERMS, filename="policy_scalar_terms.pol.yaml"
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message),
            "Filter must contain a header section. File=policy_scalar_terms.pol.yaml, Line=3.",
        )

        with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
            yaml_frontend.load_str(
                BAD_YAML_POLICY_TERM_NO_NAME, filename="policy_term_no_name.pol.yaml"
            )
        user_message = arcm.exception.args[0]
        self.assertEqual(
            str(user_message), "Term must have a name. File=policy_term_no_name.pol.yaml, Line=8."
        )

    @mock.patch.object(yaml_frontend.logging, "warning")
    def testWarnings(self, mock_warning):
        yaml_frontend.load_str("", filename="policy_empty.pol.yaml")
        self.assertEqual(mock_warning.call_args[0][0].message, "Ignoring empty policy file.")
        mock_warning.reset_mock()

        yaml_frontend.load_str(
            IGNORED_YAML_POLICY_NO_TARGET, filename="policy_no_targets.pol.yaml"
        )
        self.assertEqual(
            mock_warning.call_args[0][0].message, "Ignoring filter with zero targets."
        )
        mock_warning.reset_mock()

        yaml_frontend.load_str(IGNORED_YAML_POLICY_NO_TERMS, filename="policy_no_targets.pol.yaml")
        self.assertEqual(mock_warning.call_args[0][0].message, "Ignoring filter with zero terms.")
        mock_warning.reset_mock()

    @mock.patch.object(yaml_frontend.logging, "warning")
    def testIncludeEmptySource(self, mock_warning):
        with mock.patch("builtins.open", mock.mock_open(read_data="")):
            yaml_frontend.load_str(
                GOOD_YAML_POLICY_INCLUDE, filename="policy_with_empty_include.pol.yaml"
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
                yaml_frontend.load_str(
                    GOOD_YAML_POLICY_INCLUDE, filename="policy_with_include.pol.yaml"
                )
            user_message = arcm.exception.args[0]
            self.assertEqual(user_message.filename, "include_1.pol-include.yaml")
            self.assertEqual(user_message.line, 3)
            self.assertEqual(
                user_message.include_chain,
                [
                    ('policy_with_include.pol.yaml', 11),
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
> File='policy_with_include.pol.yaml', Line=11 (Top Level)
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
                yaml_frontend.load_str(
                    GOOD_YAML_POLICY_INCLUDE, filename="policy_with_include.pol.yaml"
                )
            user_message = arcm.exception.args[0]
            self.assertEqual(user_message.filename, "include_1.pol-include.yaml")
            self.assertEqual(user_message.line, 3)
            self.assertEqual(
                user_message.include_chain,
                [('policy_with_include.pol.yaml', 11), ('include_1.pol-include.yaml', 3)],
            )
            self.assertEqual(
                str(user_message),
                """Policy include source include_1.pol.yaml must end in ".pol-include.yaml". File=include_1.pol-include.yaml, Line=3.
Include stack:
> File='policy_with_include.pol.yaml', Line=11 (Top Level)
> File='include_1.pol-include.yaml', Line=3""",  # noqa: E501
            )

    def testIncludeInvalidYAML(self):
        with mock.patch("builtins.open", mock.mock_open(read_data=BAD_INCLUDE_YAML_INVALID_YAML)):
            with self.assertRaises(yaml_frontend.PolicyTypeError) as arcm:
                yaml_frontend.load_str(
                    GOOD_YAML_POLICY_INCLUDE, filename="policy_with_include.pol.yaml"
                )
            user_message = arcm.exception.args[0]
            self.assertEqual(user_message.filename, "include_1.pol-include.yaml")
            self.assertEqual(
                user_message.include_chain,
                [('policy_with_include.pol.yaml', 11)],
            )
            self.assertEqual(
                str(user_message),
                """Unable to read file as YAML. File=include_1.pol-include.yaml.""",
            )


if __name__ == '__main__':
    absltest.main()
