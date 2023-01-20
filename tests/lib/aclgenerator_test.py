# Copyright 2010 Google Inc. All Rights Reserved.
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

"""Unittest for ACL rendering module."""

from unittest import mock

from absl.testing import absltest

from aerleon.lib import aclgenerator, naming, policy

GOOD_HEADER_1 = """
header {
  comment:: "this is a test acl"
  target:: mock
}
"""


GOOD_TERM_1 = """
term good-term-1 {
  protocol:: icmp
  action:: accept
}
"""


STATEFUL_ONLY_TERM = """
term stateful-only {
  option:: established
  action:: accept
}
"""


ICMPV6_TERM = """
term icmpv6-term {
  protocol:: icmpv6
  action:: accept
}
"""

SHORT_TERM_NAME = """
term short-term-name {
  protocol:: tcp
  action:: accept
}
"""

GOOD_LONG_TERM_NAME = """
term google-experiment-abbreviations {
  protocol:: tcp
  action:: accept
}
"""

BAD_LONG_TERM_NAME = """
term this-term-name-is-really-far-too-long {
  protocol:: tcp
  action:: accept
}
"""

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2


class ACLMock(aclgenerator.ACLGenerator):
    _PLATFORM = 'mock'
    _TERM_MAX_LENGTH = 24

    def _TranslatePolicy(self, pol, exp_info):
        pass


class ACLGeneratorTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = mock.create_autospec(naming.Naming)

    def testEstablishedNostate(self):
        # When using "nostate" filter and a term with "option:: established"
        # have any protocol other than TCP and/or UDP should raise error.
        pol = policy.ParsePolicy(GOOD_HEADER_1 + STATEFUL_ONLY_TERM, self.naming)
        acl = ACLMock(pol, EXP_INFO)
        for _, terms in pol.filters:
            for term in terms:
                self.assertRaises(
                    aclgenerator.EstablishedError, acl.FixHighPorts, term, 'inet', False
                )

    def testSupportedAF(self):
        # Unsupported address families should raise an error.
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_TERM_1, self.naming)
        acl = ACLMock(pol, EXP_INFO)
        for _, terms in pol.filters:
            for term in terms:
                self.assertRaises(
                    aclgenerator.UnsupportedAFError, acl.FixHighPorts, term, 'unsupported', False
                )

    def testTermNameBelowLimit(self):
        # Term name that is below specified limit should come out unchanged,
        # regardless of abbreviation and truncation settings.
        pol = policy.ParsePolicy(GOOD_HEADER_1 + SHORT_TERM_NAME, self.naming)
        acl = ACLMock(pol, EXP_INFO)
        for _, terms in pol.filters:
            for term in terms:
                result = acl.FixTermLength(term.name, True, True)
                self.assertEqual(term.name, result)
                result = acl.FixTermLength(term.name, True, False)
                self.assertEqual(term.name, result)
                result = acl.FixTermLength(term.name, False, True)
                self.assertEqual(term.name, result)
                result = acl.FixTermLength(term.name, False, False)
                self.assertEqual(term.name, result)
                result = acl.FixTermLength(term.name, False, False, 30)
                self.assertEqual(term.name, result)

    def testLongTermAbbreviation(self):
        # Term name that is above specified limit should come out abbreviated
        # when abbreviation is enabled.
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_LONG_TERM_NAME, self.naming)
        acl = ACLMock(pol, EXP_INFO)
        for _, terms in pol.filters:
            for term in terms:
                result = acl.FixTermLength(term.name, True, False)
                self.assertIn(
                    '-abbreviations', result, 'Our strings disappeared during abbreviation.'
                )
                # override the term max length and ensure there are no abbreviations.
                result = acl.FixTermLength(term.name, True, False, 4 * acl._TERM_MAX_LENGTH)
                self.assertNotIn(
                    'GOOG', result, 'Strings incorrect in abbreviation and length overriding.'
                )

    def testTermNameTruncation(self):
        # Term name that is above specified limit should come out truncated
        # when truncation is enabled.
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_LONG_TERM_NAME, self.naming)
        acl = ACLMock(pol, EXP_INFO)
        for _, terms in pol.filters:
            for term in terms:
                result = acl.FixTermLength(term.name, False, True)
                self.assertEqual('google-experiment-abbrev', result)
                result = acl.FixTermLength(term.name, True, False, 4 * acl._TERM_MAX_LENGTH)
                self.assertIn(
                    'google-experiment-abbreviations',
                    result,
                    'Strings incorrectly disappeared during abbreviation '
                    'and length overriding.',
                )

    def testHexDigest(self):
        # Term name that is above specified limit should come out truncated
        # when truncation is enabled.
        pol = policy.ParsePolicy(GOOD_HEADER_1 + GOOD_LONG_TERM_NAME, self.naming)
        acl = ACLMock(pol, EXP_INFO)
        for _, terms in pol.filters:
            for term in terms:
                result = acl.HexDigest(term.name)
                self.assertEqual(
                    '070582f8b50d3cb01aa432c26a55b5f378d281c98647f59dd7f3b0d8b1c9d0d5', result
                )
                result = acl.HexDigest(term.name, 32)
                self.assertEqual('070582f8b50d3cb01aa432c26a55b5f3', result)

    def testLongTermName(self):
        # Term name that is above specified limit and is impossible to abbreviate
        # should raise an exception.
        pol = policy.ParsePolicy(GOOD_HEADER_1 + BAD_LONG_TERM_NAME, self.naming)
        acl = ACLMock(pol, EXP_INFO)
        for _, terms in pol.filters:
            for term in terms:
                self.assertRaises(
                    aclgenerator.TermNameTooLongError, acl.FixTermLength, term.name, True, False
                )

    def testProtocolNameToNumber(self):
        proto_map = {
            'icmp': 1,
            'ipip': 4,
            'tcp': 6,
            'gre': 47,
        }
        proto_convert = ['gre', 'tcp']

        protocol_list = ['icmp', 'gre', 'tcp', 'ipip']
        expected_protocol_list = ['icmp', 47, 6, 'ipip']

        retprotocol_list = aclgenerator.ProtocolNameToNumber(
            protocol_list, proto_convert, proto_map
        )

        self.assertListEqual(expected_protocol_list, retprotocol_list)

    def testAddRepositoryTags(self):
        # Format print the '$' into the RCS tags in order prevent the tags from
        # being interpolated here.

        # Include all tags.
        self.assertListEqual(
            ['%sId:%s' % ('$', '$'), '%sDate:%s' % ('$', '$'), '%sRevision:%s' % ('$', '$')],
            aclgenerator.AddRepositoryTags(),
        )
        # Remove the revision tag.
        self.assertListEqual(
            ['%sId:%s' % ('$', '$'), '%sDate:%s' % ('$', '$')],
            aclgenerator.AddRepositoryTags(revision=False),
        )
        # Only include the Id: tag.
        self.assertListEqual(
            ['%sId:%s' % ('$', '$')], aclgenerator.AddRepositoryTags(date=False, revision=False)
        )
        # Wrap the Date: tag.
        self.assertListEqual(
            ['"%sDate:%s"' % ('$', '$')],
            aclgenerator.AddRepositoryTags(revision=False, rid=False, wrap=True),
        )


if __name__ == '__main__':
    absltest.main()
