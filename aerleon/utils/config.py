# Copyright 2020-2021 Google Inc. All Rights Reserved.
# Modifications Copyright 2022-2023 Aerleon Project Authors.
"""A module to handle merging file configurations with CLI configs for Aerleon."""

import pathlib

import yaml

defaults = {
    'base_directory': './policies',
    'definitions_directory': './def',
    'policy_file': None,
    'output_directory': './',
    'optimize': False,
    'recursive': True,
    'debug': False,
    'verbose': False,
    'ignore_directories': ['DEPRECATED', 'def'],
    'max_renderers': 10,
    'shade_check': False,
    'exp_info': 2,
}

DEFAULT_FILE = './aerleon.yml'


class ConfigFileError(Exception):
    """Raised if there is some problem reading a config file."""


def load_config(
    config_file: "str | pathlib.Path | list[str | pathlib.Path]" = None,
    apply_defaults: bool = True,
) -> dict:
    """Load Aerleon configuration file(s).

    Args:
        config_file: An optional string or pathlib.Path with the location of the config file
            to open. A list of config files can be given. Default is './aerleon.yml'.
        apply_defaults: Whether to set missing config fields to their default values. Default
            is True.

    Raises:
        ConfigFileError: If the config file could not be opened and loaded. It is not an error
            if config_file is not given and the default config file is not found.

    Returns: A dictionary containing the contents of the config file. If no config file is found
        all default values will be returned (unless apply_defaults is False). If a list of config
        files is given their contents will be merged by their order in the list."""

    using_default = False
    if not config_file:
        config_file = [pathlib.Path(DEFAULT_FILE)]
        using_default = True
    elif not isinstance(config_file, list):
        config_file = [config_file]

    local_defaults = {}
    if apply_defaults:
        local_defaults.update(defaults)

    for config in config_file:
        if isinstance(config, str):
            config = pathlib.Path(config)

        try:
            with open(config, 'r') as f:
                data = yaml.safe_load(f)

                if not data or not isinstance(data, dict):
                    raise ConfigFileError(f"Config file contents not valid: {config}")

                local_defaults.update(data)  # NOTE: Safe as long as the config file is flat

        # If a user-specified config file is not found, re-raise
        # It is not an error if there is no default config file
        except FileNotFoundError as e:
            if not using_default:
                raise ConfigFileError(f"Config file not found: {config}") from e

        except PermissionError as e:
            raise ConfigFileError(f"Insufficient permissions to open config file: {config}") from e

        except IsADirectoryError as e:
            raise ConfigFileError(f"Expected a config file, found a directory: {config}") from e

        except OSError as e:
            raise ConfigFileError(f"Unable to open config file: {config}") from e

        except yaml.YAMLError as e:
            raise ConfigFileError(f"Config file is not a valid YAML file: {config}") from e

    return local_defaults
