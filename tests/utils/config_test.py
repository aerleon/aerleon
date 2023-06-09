"""Unit tests for config.py"""

from unittest import mock

from absl.testing import absltest

from aerleon.utils import config

EXAMPLE_CONFIG_FILE1 = """
base_directory: ./example_base_directory1
"""

EXAMPLE_CONFIG_FILE2 = """
base_directory: ./example_base_directory2
definitions_directory: ./example_defs_directory2
"""


class ConfigTestSute(absltest.TestCase):
    def setUp(self):
        super().setUp()

    def testDefaultFile(self):
        """Zero args, aerleon.yml present."""
        mock_open_conf = mock.mock_open(read_data=EXAMPLE_CONFIG_FILE1)
        with mock.patch("builtins.open", mock_open_conf):
            config_data = config.load_config()
            expected = {}
            expected.update(config.defaults)
            expected['base_directory'] = './example_base_directory1'
            self.assertEqual(str(mock_open_conf.call_args[0][0]), 'aerleon.yml')
            self.assertDictEqual(expected, config_data)

    def testDefaultFileNotFound(self):
        """Zero args, aerleon.yml not found."""
        mock_error = mock.MagicMock()
        mock_error.return_value.__enter__.side_effect = FileNotFoundError()
        with mock.patch("builtins.open", mock_error):
            config_data = config.load_config()
            self.assertEqual(str(mock_error.call_args[0][0]), 'aerleon.yml')
            self.assertDictEqual(config.defaults, config_data)

    def testInvalidDefaultFile(self):
        """Zero args, aerleon.yml present but invalid."""
        # YAML case
        with mock.patch("builtins.open", mock.mock_open(read_data="\"")):
            with self.assertRaisesRegex(config.ConfigFileError, r'not a valid YAML file'):
                config.load_config()

        # Invalid case
        with mock.patch("builtins.open", mock.mock_open(read_data="")):
            with self.assertRaisesRegex(config.ConfigFileError, r'contents not valid'):
                config.load_config()

        # Permissions case
        mock_error = mock.MagicMock()
        mock_error.return_value.__enter__.side_effect = PermissionError()
        with mock.patch("builtins.open", mock_error):
            with self.assertRaisesRegex(config.ConfigFileError, r'Insufficient permissions'):
                config.load_config()

    def testGivenFile(self):
        """Config file given."""
        mock_open_conf = mock.mock_open(read_data=EXAMPLE_CONFIG_FILE1)
        with mock.patch("builtins.open", mock_open_conf):
            config_data = config.load_config(config_file='config.yaml')
            expected = {}
            expected.update(config.defaults)
            expected['base_directory'] = './example_base_directory1'
            self.assertEqual(str(mock_open_conf.call_args[0][0]), 'config.yaml')
            self.assertDictEqual(expected, config_data)

    def testGivenFileNotFound(self):
        """Config file given but not found."""
        mock_error = mock.MagicMock()
        mock_error.return_value.__enter__.side_effect = FileNotFoundError()
        with mock.patch("builtins.open", mock_error):
            with self.assertRaisesRegex(config.ConfigFileError, r'Config file not found'):
                config.load_config(config_file='config.yaml')

    def testInvalidGivenFile(self):
        """Config file given but invalid."""
        # YAML case
        with mock.patch("builtins.open", mock.mock_open(read_data="\"")):
            with self.assertRaisesRegex(config.ConfigFileError, r'not a valid YAML file'):
                config.load_config(config_file='config.yaml')

        # Invalid case
        with mock.patch("builtins.open", mock.mock_open(read_data="")):
            with self.assertRaisesRegex(config.ConfigFileError, r'contents not valid'):
                config.load_config(config_file='config.yaml')

        # Permissions case
        mock_error = mock.MagicMock()
        mock_error.return_value.__enter__.side_effect = PermissionError()
        with mock.patch("builtins.open", mock_error):
            with self.assertRaisesRegex(config.ConfigFileError, r'Insufficient permissions'):
                config.load_config(config_file='config.yaml')

    def testGivenFileList(self):
        """List of config files given."""

        config_files = (data for data in [EXAMPLE_CONFIG_FILE2, EXAMPLE_CONFIG_FILE1])

        mock_open_conf = mock.MagicMock()
        mock_open_conf.return_value.__enter__.side_effect = lambda: next(config_files)
        with mock.patch("builtins.open", mock_open_conf):
            config_data = config.load_config(config_file=['config2.yaml', 'config1.yaml'])
            expected = {}
            expected.update(config.defaults)
            expected['base_directory'] = './example_base_directory1'
            expected['definitions_directory'] = './example_defs_directory2'

            self.assertEqual(str(mock_open_conf.call_args_list[0][0][0]), 'config2.yaml')
            self.assertEqual(str(mock_open_conf.call_args_list[1][0][0]), 'config1.yaml')
            self.assertDictEqual(expected, config_data)
