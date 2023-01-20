# Copyright 2015 The Capirca Project Authors All Rights Reserved.
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

import multiprocessing
import os
import shutil
import tempfile
from unittest import mock

from absl import app
from absl.testing import absltest

from aerleon import aclgen
from tests.regression_utils import capture


class TestRegressionDemo(absltest.TestCase):
    """Ensure Aerleon demo runs successfully out-of-the-box."""

    def setUp(self):
        super().setUp()
        self.test_subdirectory = tempfile.mkdtemp()
        self.def_dir = os.path.join(self.test_subdirectory, 'def')
        self.pol_dir = os.path.join(self.test_subdirectory, 'policies')
        shutil.rmtree(self.test_subdirectory, ignore_errors=True)
        os.mkdir(self.test_subdirectory)
        shutil.copytree('def', self.def_dir)
        shutil.copytree('policies', self.pol_dir)
        self.context = multiprocessing.get_context()
        self.max_renderers = 10
        self.exp_info = 2
        self.ignore_directories = ['DEPRECATED', 'def']

    @capture.files(
        (
            'sample_cisco_lab.acl',
            'sample_cloudarmor.gca',
            'sample_gce.gce',
            'sample_ipset.ips',
            'sample_juniper_loopback.jcl',
            'sample_juniperevo_loopback.evojcl',
            'sample_multitarget.acl',
            'sample_multitarget.asa',
            'sample_multitarget.bacl',
            'sample_multitarget.eacl',
            'sample_multitarget.ipt',
            'sample_multitarget.jcl',
            'sample_multitarget.evojcl',
            'sample_multitarget.msmpc',
            'sample_multitarget.xacl',
            'sample_multitarget.nxacl',
            'sample_nsxv.nsx',
            'sample_packetfilter.pf',
            'sample_speedway.ipt',
            'sample_srx.srx',
            'sample_paloalto.xml',
            'sample_nftables-mixed-icmp.nft',
            'sample_nftables-mixed-multiple-headers-combo.nft',
            'sample_nftables.nft',
            'sample_nftables-dev.nft',
            'sample_stateful_multitarget_simple.xml',
            'sample_stateful_multitarget_simple.srx',
            'sample_stateful_multitarget_complex.xml',
            'sample_stateful_multitarget_complex.srx',
            'sample_k8s.yml',
        )
    )
    def testSmokeTest(self):
        aclgen.Run(
            self.pol_dir,
            self.def_dir,
            None,
            self.test_subdirectory,
            self.exp_info,
            self.max_renderers,
            self.ignore_directories,
            None,
            None,
            self.context,
        )

    @capture.files(('sample_cisco_lab.acl',))
    def testSinglePolicy(self):
        policy_file = os.path.join(self.test_subdirectory, 'policies/pol/sample_cisco_lab.pol')
        aclgen.Run(
            self.pol_dir,
            self.def_dir,
            policy_file,
            self.test_subdirectory,
            self.exp_info,
            self.max_renderers,
            self.ignore_directories,
            None,
            None,
            self.context,
        )

    # Test to ensure existence of the entry point function for installed script.
    @mock.patch.object(aclgen, 'SetupFlags', autospec=True)
    @mock.patch.object(app, 'run', autospec=True)
    def test_entry_point(self, mock_run, mock_flags):
        aclgen.EntryPoint()
        mock_flags.assert_called_with()
        mock_run.assert_called_with(aclgen.main)


def main(unused_argv):
    absltest.main()


if __name__ == '__main__':
    app.run(main)
