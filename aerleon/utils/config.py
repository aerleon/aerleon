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

default_file = './aerleon.yml'


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
        IOError: If open(config_file) raises an IOError. Note that it is not an error for the
            config file to not exist.
        yaml.YAMLError: If the config file is not valid YAML.

    Returns: a dictionary containing the contents of the config file. If no config file is found
        all default values will be returned (unless apply_defaults is False). If a list of config
        files is given their contents will be merged by their order in the list."""

    if not config_file:
        config_file = [pathlib.Path(default_file)]
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
                local_defaults.update(data)  # NOTE: Safe as long as the config file is flat

        except FileNotFoundError:
            pass

    return local_defaults
