"""Benchmark SampleSuiteV1: Render to string from policy samples."""

import multiprocessing
import os
import shutil
import tempfile
from unittest import mock

from aerleon import aclgen


class SampleSuiteV1:
    """This benchmark will load all policy files found in ./policies and generate configs.
    It will not try to write() any configs.

    If any of the following are changed, please bump the version in the class name of this suite:

    * The contents of this test.
    * The contents of the ./policies folder.
    * The contents of the ./def folder.

    DO NOT run this benchmark if you have uncomitted files in the ./policies or ./def folders.

    """

    def __init__(self, argv):
        skip_samples = []
        only_samples = argv[1:]

        def ignore_policy_files(src, names):
            if src == 'policies/pol':
                if len(only_samples) != 0:
                    return [name for name in names if name not in only_samples]
                if len(skip_samples) != 0:
                    return [name for name in names if name in skip_samples]
            return []

        self.test_subdirectory = tempfile.mkdtemp()
        self.def_dir = os.path.join(self.test_subdirectory, 'def')
        self.pol_dir = os.path.join(self.test_subdirectory, 'policies')
        shutil.rmtree(self.test_subdirectory, ignore_errors=True)
        os.mkdir(self.test_subdirectory)
        shutil.copytree('def', self.def_dir)
        shutil.copytree('policies', self.pol_dir, ignore=ignore_policy_files)
        self.context = multiprocessing.get_context()
        self.max_renderers = 1
        self.exp_info = 2
        self.ignore_directories = ['DEPRECATED', 'def']

    def run(self):
        with mock.patch.object(aclgen, '_WriteFile', autospec=True):
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


if __name__ == '__main__':
    import sys

    suite = SampleSuiteV1(sys.argv)
    suite.run()
