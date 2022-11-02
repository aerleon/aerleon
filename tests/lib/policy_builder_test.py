from unittest import mock

from absl.testing import absltest

from aerleon.lib import nacaddr, naming, policy
from aerleon.lib.policy_builder import (
    PolicyBuilder,
    RawFilter,
    RawFilterHeader,
    RawPolicy,
    RawTerm,
)


RAW_POLICY_ALL_BUILTIN = RawPolicy(
    filename="raw_policy_all_builtin",
    filters=[
        RawFilter(
            header=RawFilterHeader(
                targets={"cisco": "test-filter"},
                kvs={"comment": "Sample comment"},
            ),
            terms=[
                RawTerm(
                    name="deny-to-reserved",
                    kvs={"destination-address": "RESERVED", "action": "deny"},
                ),
                RawTerm(
                    name="deny-to-bogons",
                    kvs={"destination-address": "RESERVED", "action": "deny"},
                ),
                RawTerm(
                    name="allow-web-to-mail",
                    kvs={
                        "source-address": "WEB_SERVERS",
                        "destination-address": "MAIL_SERVERS",
                        "action": "accept",
                    },
                ),
            ],
        )
    ],
)

RAW_POLICY_UNRECOGNIZED_MIX = RawPolicy(
    filename="raw_policy_all_builtin",
    filters=[
        RawFilter(
            header=RawFilterHeader(
                targets={"cisco": "test-filter"},
                kvs={
                    "comment": "Sample comment",
                    "extension-kw": "",
                },
            ),
            terms=[
                RawTerm(
                    name="deny-to-reserved",
                    kvs={"destination-address": "RESERVED", "action": "deny"},
                ),
                RawTerm(
                    name="deny-to-bogons",
                    kvs={"destination-address": "RESERVED", "action": "deny"},
                ),
                RawTerm(
                    name="allow-web-to-mail",
                    kvs={
                        "source-address": "WEB_SERVERS",
                        "destination-address": "MAIL_SERVERS",
                        "action": "accept",
                    },
                ),
            ],
        )
    ],
)

GOOD_POLICY = """
header {
    target:: cisco test-filter
    comment:: "Sample comment"
}

term deny-to-reserved {
  destination-address:: RESERVED
  action:: deny
}

term deny-to-bogons {
  destination-address:: RESERVED
  action:: deny
}

term allow-web-to-mail {
  source-address:: WEB_SERVERS
  destination-address:: MAIL_SERVERS
  action:: accept
}
"""


class PolicyBuilderTest(absltest.TestCase):
    """Test PolicyBuilder class."""

    def setUp(self):
        super().setUp()
        self.naming = mock.create_autospec(naming.Naming)
        self.naming.GetNetAddr.return_value = [nacaddr.IP('10.1.1.1/32')]

    def testPolicyBuilderBuiltins(self):
        builder = PolicyBuilder(RAW_POLICY_ALL_BUILTIN, self.naming)
        pol = policy.FromBuilder(builder)

        pol2 = policy.ParsePolicy(GOOD_POLICY, self.naming)

        self.assertEqual(str(pol), str(pol2))
        self.assertEqual(pol, pol2)

    def testPolicyBuilderUnexpected(self):
        builder = PolicyBuilder(RAW_POLICY_UNRECOGNIZED_MIX, self.naming)
        pol = policy.FromBuilder(builder)

        pol2 = policy.ParsePolicy(GOOD_POLICY, self.naming)

        self.assertEqual(str(pol), str(pol2))
        self.assertEqual(pol, pol2)


if __name__ == '__main__':
    absltest.main()
