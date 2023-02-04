import argparse
from collections import defaultdict
import enum
import logging
import pathlib
import sys
from typing import Any

from tabulate import tabulate  # TODO(jb) just write a func as needed
import yaml
from aerleon.aclgen import ACLParserError

from aerleon.lib import aclgenerator, naming, policy


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
    base_directory = options['base_directory']
    definitions_directory = options['definitions_directory']

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
                pathlib.Path(base_directory),
                input_mode,
                operation,
                output_mode,
                options,
            )
        )
        file_targets.update(
            _get_file_plan(
                pathlib.Path(definitions_directory),
                input_mode,
                operation,
                output_mode,
                options,
            )
        )

    # Construct a reverse table also
    targets = defaultdict(list)
    for input_file, file_plan in file_targets.items():
        targets[file_plan].append(input_file)

    # Print table
    if options['dry_run'] or options['verbose']:
        print(tabulate(file_targets.items(), headers=['File', 'Action']))

    # If we know there will be conflicts we will bail out early.
    # If --force or --yaml are set we don't need to check.
    if output_mode != _ConverterOutputMode.FORCE and operation != _Operation.REFORMAT:

        if targets[_FilePlan.OUTPUT_CONFLICT]:
            conflicts = [f'    {file}' for file in targets[_FilePlan.OUTPUT_CONFLICT]]
            message = (
                'Command would overwrite the following files. Use option --force to override.\n\n'
            )
            message += "\n".join(conflicts)

            if options['dry_run']:
                logging.warning(message)
            else:
                logging.error(f'COMMAND FAILED\n\n{message}')
                return

    # Now we have our plan, time to EXECUTE.
    # The idea is to produce a Policy object, then run it through the policy_to_yaml() function
    #

    # Create output directories now (if not --dry_run)
    if not options['dry_run'] and options['output_directory']:
        # Get list of unique parents
        mkdir_targets = list(set([file.parent for file in targets[_FilePlan.OUTPUT_MKDIR]]))
        for directory in mkdir_targets:
            pathlib.Path(directory).mkdir(parents=True, exists_ok=True)

    # Start visiting input files

    # TODO(jb) The next step might need to be broken up into sub classes by case
    # or at least functions
    #
    # TODO(jb) The following content is pretty good docstring material

    # POLICY / INCLUDE
    # Our goal in this step is to directly translate (or reformat) policy and include files.
    # This is a challenge because parsing is a _destructive_ process:
    # 1. Preprocessing eliminates include statements
    # 2. Error checking may reject or clean up parts of terms/policies
    # Includes are a special chanllenge because there is no parser for .inc files - they can only be parsed in the context
    # of the policy file they were injected into.
    #
    # The strategies for various pol / include cases are as follows:
    #
    # .pol :
    # 1. pre-preprocess #include, replacing the include with a placeholder term, e.g.
    # term ZZZZZ_INCLUDE_PLACEHOLDER_PATH_TO_FILE_INC {
    #   comment:: /path/to/file.inc
    # }
    # 2. Watch for any other destructive processing step and see if we can preserve it with placeholders.
    # 3. Take the Policy / Term models and replace ZZZZZ_INCLUDE_PLACEHOLDER terms with YAML include during the generation step.
    #
    # .inc :
    # 1. Wrap the whole include file in a dummy filter
    # 2. pre-preprocess #include as above
    # 3. Parse it as if it were a .pol file
    # 4. Discard the dummy filter and only render the terms during the generation step. (Different generator subclass).
    #
    # .yaml :
    # Note: the "Y2Y" flow could be done very directly without any parsing at all.
    # In a direct reformat we are not creating a Policy model at all.
    # The downside here is we are now on a different rendering code path as the generator, unless
    # we get the generator to sit on top of the "export" code. Still might require lots of new code.
    # The advantage is it is much faster and stands alone from the .pol conversion after that becomes less relevant.
    #
    # If we try to go the Policy model route we do have to determine what kind of file it is
    # and then process it using similar tricks for includes.
    #
    # DEFINITIONS
    #
    # Definition files get loaded into a pretty low level IR that looks very similar to the original files.
    # So the strategy would be to parse into Naming and then export from Naming.
    # Probably no tricks needed at all.
    #
    #
    # INCLUDE SPECIAL NOTES
    #
    # Includes in .pol/.inc cannot be translated with the original file path since it will reference a .inc file.
    # YAML policy/include files cannot include from .inc.
    # So the translated policy must rename the suffix to .yaml, but we don't know for certain whether that file exists.
    # Ideally the user is in RECURSIVE | CONVERT mode and the include target in question is getting translated at this time.
    # But the corner cases are so vast that we have to accept that we don't know about the target at all, or else we have
    # to consider:
    # * Dead/dead - neither .inc target nor .yaml target exist
    # * Live/dead - the .inc target exists but it is not going to be translated at this time
    # * Dead/live - the .inc target does not exist but the .yaml target does exist, it was already translated and the original was removed.
    # So the simplest answer is we do not examine the target at all.
    # We COULD message the user if the .yaml target (1) does not exist, and (2) is not planned as an output as part of this run.
    # This might help users catch dead links.
    # We COULD do link checking on any emitted .yaml includes (including reformatting) following the rules above.
    #
    #
    # DETERMINING FILE TYPE
    #
    # For DSL inputs the extension tells us how to treat the file, so in the CONVERT branch
    # we can branch by extension (suffix).
    #
    # For YAML inputs we have to inspect the file. Arguably in RECURSIVE | REFORMAT mode we can assume that
    # files in definitions_directory are not policy / include files. But for policy / include files we have
    # to inspect the file, and when in FILE | REFORMAT mode we have to inspect every file anyway.
    #
    # This will entail opening the file and performing an initial YAML load to classify it.
    # The current code structure forces us to discard the initial YAML load after classification.
    # Arguably interface changes could allow us to re-use the YAML load (possibly tying in with the API use case).
    # For now we can keep it simple.
    mod_count = 0
    input_files = targets[_FilePlan.INPUT]
    if operation == _Operation.REFORMAT:
        for input_file in input_files:
            pol = get_policy_for_file(
                input_file, base_directory=base_directory, definitions=definitions_directory
            )
            pol_yaml = YAMLExportGenerator(pol)
            print(str(pol_yaml))
    else:
        for input_file in input_files:
            pol = get_policy_for_file(
                input_file, base_directory=base_directory, definitions=definitions_directory
            )
            pol_yaml = YAMLExportGenerator(pol)
            print(str(pol_yaml))

    if operation == _Operation.REFORMAT:
        report = f'{len(input_files)} files checked, {mod_count} files reformatted'
    else:
        report = f'{len(input_files)} files converted'

    if options['dry_run']:
        print(f'{report} (dry run)')
    else:
        print(report)


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


def get_policy_for_file(input_file: pathlib.Path, base_directory, definitions):
    """Construct a policy object from input file path.

    Args:
        input_file: A pathlib.Path pointing to the file.
    """

    try:
        with open(input_file) as f:
            conf = f.read()
            logging.debug('opened and read %s', input_file)
    except IOError as e:
        logging.warning('bad file: \n%s', e)
        raise

    try:
        if pathlib.Path(input_file).suffix == '.yaml' or pathlib.Path(input_file).suffix == '.yml':
            pol = yaml.ParsePolicy(
                conf,
                filename=input_file,
                base_dir=base_directory,
                definitions=definitions,
                optimize=False,
                shade_check=False,
            )
        else:
            pol = policy.ParsePolicy(
                conf,
                definitions,
                optimize=False,
                base_dir=base_directory,
                shade_check=False,
            )
    except policy.ShadingError as e:
        logging.warning('shading errors for %s:\n%s', input_file, e)
        return
    except (policy.Error, naming.Error) as e:
        raise ACLParserError(
            'Error parsing policy file %s:\n%s%s'
            % (input_file, sys.exc_info()[0], sys.exc_info()[1])
        ) from e
    return pol


class YAMLExportGenerator(aclgenerator.ACLGenerator):
    """A fake generator that exists purely for pol2yaml. This generator just spits the policy object back out as YAML."""

    def __str__(self):
        import pprint

        return pprint.pformat(self)


class YAMLExportTerm(aclgenerator.Term):
    """A fake generator term that exists purely for pol2yaml. See YAMLExportGenerator."""

    def __str__(self):
        import pprint

        return pprint.pformat(self)


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
