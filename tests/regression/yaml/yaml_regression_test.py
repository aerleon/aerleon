"""Regression tests for YAML front-end."""
import multiprocessing
import os
import pathlib
import shutil
import tempfile

from unittest import mock

from absl.testing import absltest

from aerleon import aclgen

EXP_INFO = 2


# TODO(jb) add YAML files to demo test
class YAMLRegressionTest(absltest.TestCase):
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
    def testCompareYamlPolEquivalents(self, mockWriteFiles):
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


if __name__ == '__main__':
    absltest.main()
