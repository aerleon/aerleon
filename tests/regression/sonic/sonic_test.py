# Copyright 2021 Google Inc. All Rights Reserved.
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

"""Unittest for OpenConfig rendering module."""

import json
from unittest import mock

from absl.testing import absltest, parameterized

from aerleon.lib import aclgenerator, nacaddr, naming, policy, sonic
from tests.regression_utils import capture

GOOD_HEADER = """
header {
  comment:: "The general policy comment."
  target:: sonic good-name-v4 inet
}
"""
GOOD_TCP_EST = """
term good-tcp-est {
  protocol:: tcp
  destination-address:: CORP_EXTERNAL
  source-port:: HTTP
  option:: tcp-established
  action:: accept
}
"""

# Print a info message when a term is set to expire in that many weeks.
# This is normally passed from command line.
EXP_INFO = 2

TEST_IPS = [nacaddr.IP('10.2.3.4/32'), nacaddr.IP('2001:4860:8000::5/128')]


_TERM_SOURCE_TAGS_LIMIT = 30
_TERM_TARGET_TAGS_LIMIT = 70
_TERM_PORTS_LIMIT = 256


class SONiCTest(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = mock.create_autospec(naming.Naming)

    def _StripAclHeaders(self, acl):
        return '\n'.join(
            [line for line in str(acl).split('\n') if not line.lstrip().startswith('#')]
        )

    @capture.stdout
    def testTcpEstablished(self):
        self.naming.GetServiceByProto.return_value = [port.PPP('80/tcp')]
        self.naming.GetNetAddr.return_value = TEST_IPS

        policy_text = GOOD_HEADER + GOOD_TCP_EST
        acl = sonic.SONiC(policy.ParsePolicy(policy_text, self.naming), EXP_INFO)
        output = str(acl)
        self.assertIn('tcp-session-established', output, output)

        self.naming.GetNetAddr.assert_called_once_with('CORP_EXTERNAL')
        self.naming.GetServiceByProto.assert_called_once_with('HTTP', 'tcp')
        print(acl)


if __name__ == '__main__':
    absltest.main()
