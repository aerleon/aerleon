import argparse
import enum
import logging
import pathlib
from typing import Any

from tabulate import tabulate  # TODO(jb) just write a func as needed
import yaml

VERSION = '1.0'


cli_defaults = {
    'base_directory': './policies',
    'config_file': './aerleon.yml',
    'definitions_directory': './def',
    'dry_run': False,
    'file': [],
    'force': False,
    'output_directory': None,
    'reformat_yaml': False,
    'verbose': False,
}


class _InputMode(enum.Enum):
    """Describes the input mode for this run."""

    RECURSIVE = enum.auto()  # Visit all input files in base_directory and definitions_directory
    FILES = enum.auto()  # Visit specific input.net files


class _Operation(enum.Enum):
    """Distinguishes between convert and reformat modes."""

    CONVERT = enum.auto()  # Convert .pol/.inc/.net/.svc files
    REFORMAT = enum.auto()  # Reformat YAML files


class _ConverterOutputMode(enum.Enum):
    """Describes the output mode for this run."""

    NORMAL = enum.auto()  # In "P2Y" mode, stop if we would overwrite an output YAML file
    FORCE = enum.auto()  # In "P2Y" mode, overwrite any output YAML file as needed


class _FilePlan(enum.Enum):
    """Describes what will happen with an input or output file."""

    INPUT = enum.auto()  # Read only
    OUTPUT = enum.auto()  # Write only
    OUTPUT_MKDIR = enum.auto()  # Write only, parent directory or directories will be created
    OUTPUT_CONFLICT = enum.auto()  # Cannot write due to collision, use --force
    OUTPUT_FORCE = enum.auto()  # Write only, name collision, overwriting with --force
    REFORMAT = enum.auto()  # Read and replace with reformatted text

    def __str__(self):
        return str(self.name)


# TODO(jb) consider what this would look like as import aerleon.tools.pol2yaml or aerleon.lib.pol2yaml?? (Do we care?)
def pol2yaml(options, style_options):
    """Convert Capirca files to YAML. Supports .pol, .inc, .net, and .svc . Can also reformat YAML files.

    pol2yaml has three phases of operation:

    * Collect target file(s).
    * Create a normalized YAML file for each target file.
    * Write each file to the target location.

    """

    # Determine operation and input mode
    if options['reformat_yaml']:
        operation = _Operation.REFORMAT
    else:
        operation = _Operation.CONVERT

    if options['file']:
        input_mode = _InputMode.FILES
    else:
        input_mode = _InputMode.RECURSIVE

    if options['force']:
        if operation == _Operation.REFORMAT:
            logging.warning(
                "Option '--force' has no effect and is ignored when used with flag '--yaml'."
            )
        output_mode = _ConverterOutputMode.FORCE
    else:
        output_mode = _ConverterOutputMode.NORMAL

    # If we are in file mode, and --output_directory is set, then the current directory will serve as the root for determining placement within the output directory.
    file_targets = {}
    if input_mode == _InputMode.FILES:
        file_targets.update(
            _get_file_plan(pathlib.Path().cwd(), input_mode, operation, output_mode, options)
        )
    else:
        file_targets.update(
            _get_file_plan(
                pathlib.Path(options['base_directory']),
                input_mode,
                operation,
                output_mode,
                options,
            )
        )
        file_targets.update(
            _get_file_plan(
                pathlib.Path(options['definitions_directory']),
                input_mode,
                operation,
                output_mode,
                options,
            )
        )

    if options['dry_run'] or options['verbose']:
        print(tabulate(file_targets.items(), headers=['File', 'Action']))


def _get_file_plan(
    directory: pathlib.Path,
    input_mode: _InputMode,
    operation: _Operation,
    output_mode: _ConverterOutputMode,
    options: 'dict[str, Any]',
):
    """Identify input and output files. Designate each file with the following statuses.

    INPUT               Read only
    OUTPUT              Write only
    OUTPUT_MKDIR        Write only, parent directory or directories will be created
    OUTPUT_CONFLICT     Cannot write due to collision, use --force
    OUTPUT_FORCE        Write only, name collision, overwriting with --force
    REFORMAT            Read and replace with reformatted text
    """

    files = {}
    import pdb

    # pdb.set_trace()
    # Identify all input files. If --file is used confirm file exists.
    if input_mode == _InputMode.FILES:
        for file in options['file']:
            file = pathlib.Path(file)

            if not file.exists():
                logging.warning(f"File not found: {file}.")
                continue

            file = file.resolve()

            files[file] = _FilePlan.INPUT

    else:
        if operation == _Operation.CONVERT:
            target_suffixes = ['.pol', '.inc', '.svc', '.net']
        else:
            target_suffixes = ['.yaml', '.yml']

        for file in pathlib.Path(directory).rglob('*'):
            if file.suffix not in target_suffixes:
                continue

            files[file] = _FilePlan.INPUT

    # Determine outputs depending on scenario
    output_files = {}

    # Case: separate output directory
    if options['output_directory']:
        for file in files.keys():
            # Possible conflict scenario
            if operation == _Operation.CONVERT:
                file = file.with_suffix('.yaml')

            # Find path relative to 'directory'
            # In 'FILES' mode we look relative to the directory, in 'RECURSIVE' mode we look relative to the parent of the directory
            if input_mode == _InputMode.FILES:
                file = file.relative_to(directory)
            else:
                file = file.relative_to(directory.parent)

            # Join that to 'output'
            file = pathlib.Path(options['output_directory']).joinpath(file).resolve()

            # Now we can check for MKDIR
            if not file.parent.exists():
                output_files[file] = _FilePlan.OUTPUT_MKDIR
                continue

            # Now check for conflict (if CONVERT mode)
            if operation == _Operation.CONVERT and file.exists():
                if output_mode == _ConverterOutputMode.FORCE:
                    output_files[file] = _FilePlan.OUTPUT_FORCE
                else:
                    output_files[file] = _FilePlan.OUTPUT_CONFLICT
            else:
                output_files[file] = _FilePlan.OUTPUT

    # Case: reformat in place
    elif operation == _Operation.REFORMAT:
        for file in files.keys():
            output_files[file] = _FilePlan.REFORMAT

    # Case: convert in place
    else:
        for file in files.keys():

            # Replace suffix
            file = file.with_suffix('.yaml')

            # Check for conflict
            if file.exists():
                if output_mode == _ConverterOutputMode.FORCE:
                    output_files[file] = _FilePlan.OUTPUT_FORCE
                else:
                    output_files[file] = _FilePlan.OUTPUT_CONFLICT
            else:
                output_files[file] = _FilePlan.OUTPUT

    files.update(output_files)
    return files


def cli_options():

    parser = argparse.ArgumentParser(
        prog="pol2yaml",
        description='Convert Capirca files to YAML. Can also reformat YAML files.\n'
        '\n'
        'Usage Examples\n'
        '\n'
        'Recursively convert all files to YAML\n'
        '\n'
        '        pol2yaml --base_directory=./policies --definitions_directory=./def\n'
        '\n'
        '    This will create a YAML file for every input file found in base_directory and definitions_directory.\n'
        '    Each output file will be placed in the same folder as its source Capirca file.\n'
        '\n'
        'Convert specific files to YAML\n'
        '\n'
        '        pol2yaml -file ./policies/example.pol -file ./def/example_networks.net \n'
        '\n'
        '    This will create a YAML file for each input file.\n'
        '\n'
        'Place output files in a separate location\n'
        '\n'
        '        pol2yaml --base_directory=./policies --definitions_directory=./def --output_directory=./output \n'
        '\n'
        '    This will place all output files in the output folder. %(prog)s will create folders to mirror the structure of the input directories.\n'
        '\n'
        'Reformat YAML files \n'
        '\n'
        '        pol2yaml --yaml --base_directory=./policies --definitions_directory=./def \n'
        '\n'
        '    This will reformat all Aeleon YAML files with the same style used by the converter.\n'
        '\n'
        'Using pol2yaml.yml\n'
        '\n'
        '    The program will look for a configuration file named pol2yaml.yml in the current directory or at the location given by --config.\n'
        '    The config file can configure how the YAML output will be formatted and set default values for command line arguments.\n',
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        '--base_directory',
        dest='base_directory',
        help=f'The base directory to look for policy and policy include files. Default value is {cli_defaults["base_directory"]}\n',
    )

    parser.add_argument(
        '-c',
        '--config_file',
        dest='config_file',
        help=f'Change the location searched for the configuration YAML file.  Default value is {cli_defaults["config_file"]}\n',
    )

    parser.add_argument(
        '--definitions_directory',
        dest='definitions_directory',
        help=f'The directory where network and service definition files can be found. Default value is {cli_defaults["definitions_directory"]}\n',
    )
    parser.add_argument(
        '--file',
        action="append",
        nargs="*",
        dest='file',
        help='Convert a specific file or files. Can be given more than once. Only the file(s) specified will be converted.\n',
    )

    parser.add_argument(
        '--force',
        action='store_true',
        dest='force',
        help='Overwrite YAML files with the same name as an output file. %(prog)s will not overwrite existing output files without this flag set.\n',
    )

    parser.add_argument(
        '-n',
        '--dry_run',
        action='store_true',
        dest='dry_run',
        help='Run the program but do not write any files.\n',
    )

    parser.add_argument(
        '--output_directory',
        dest='output_directory',
        help='The directory to output the rendered configs.\n',
    )

    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        dest='verbose',
        help='Display additional information.\n',
    )

    parser.add_argument('--version', action='version', version=f'{VERSION}')

    parser.add_argument(
        '-y',
        '--yaml',
        action='store_true',
        dest='reformat_yaml',
        help='Enable reformatting YAML files. This will reformat all input files unless --ouput_directory is set.\n',
    )

    return parser


def load_config(config_file):
    if not config_file:
        config_file = cli_defaults['config_file']

    try:
        with open(config_file, 'r') as config_fstream:
            return yaml.safe_load(config_fstream)
    except FileNotFoundError:
        return


def main(parser):
    import pdb

    # pdb.set_trace()
    cli_options = {}
    cli_options.update(cli_defaults)

    style_options = {
        'list_style': 'string',
        'multiline_style': 'pipe',
        'tuple_stlye': 'list',
        'value_style': 'string_always',
    }

    logging.basicConfig(level=logging.INFO)
    options = parser.parse_args()

    # collapse possible list of lists
    if options.file:
        options.file = [file for sublist in options.file for file in sublist]

    # apply options found in the config file
    config = load_config(options.config_file)
    if config:
        style_options.update(config)
        cli_options.update(config)

    # apply command line options
    for option, value in vars(options).items():

        # NOTE: this is kosher as long as we never use argparse's "store_false" flags.
        if value:
            cli_options[option] = value

    pol2yaml(cli_options, style_options)


if __name__ == '__main__':
    main(cli_options())
