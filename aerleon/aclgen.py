# Copyright 2011 Google Inc. All Rights Reserved.
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
#
"""Renders policy source files into actual Access Control Lists."""

import copy
import pathlib
import sys
from concurrent.futures import Future, ProcessPoolExecutor
from typing import Any, Callable, Iterator, List, Optional, Tuple

from absl import app, flags, logging

from aerleon.lib import aclgenerator, naming, plugin_supervisor, policy, yaml
from aerleon.utils import config

FLAGS = flags.FLAGS

OutputFile = Tuple[pathlib.Path, str]


def SetupFlags():
    """Read in configuration from CLI flags."""
    flags.DEFINE_string(
        'base_directory',
        None,
        'The base directory to look for acls; '
        'typically where you\'d find ./corp and ./prod\n(default: \'%s\')'
        % config.defaults['base_directory'],
    )
    flags.DEFINE_string(
        'definitions_directory',
        None,
        'Directory where the definitions can be found.\n(default: \'%s\')'
        % config.defaults['definitions_directory'],
    )
    flags.DEFINE_string('policy_file', None, 'Individual policy file to generate.')
    flags.DEFINE_string(
        'output_directory',
        None,
        'Directory to output the rendered acls.\n(default: \'%s\')'
        % config.defaults['output_directory'],
    )
    flags.DEFINE_boolean(
        'optimize',
        None,
        'Turn on optimization.\n(default: \'%s\')' % config.defaults['optimize'],
        short_name='o',
    )
    flags.DEFINE_boolean(
        'recursive',
        None,
        'Descend recursively from the base directory rendering acls\n(default: \'%s\')'
        % str(config.defaults['recursive']).lower(),
    )
    flags.DEFINE_boolean(
        'debug', None, 'Debug messages\n(default: \'%s\')' % str(config.defaults['debug']).lower()
    )
    flags.DEFINE_boolean(
        'verbose',
        None,
        'Verbose messages\n(default: \'%s\')' % str(config.defaults['verbose']).lower(),
    )
    flags.DEFINE_list(
        'ignore_directories',
        None,
        'Don\'t descend into directories that look like this string\n(default: \'%s\')'
        % ','.join(config.defaults['ignore_directories']),
    )
    flags.DEFINE_integer(
        'max_renderers',
        None,
        'Max number of rendering processes to use.\n(default: \'%s\')'
        % config.defaults['max_renderers'],
    )
    flags.DEFINE_boolean(
        'shade_check',
        None,
        'Raise an error when a term is completely shaded by a prior term.\n(default: \'%s\')'
        % str(config.defaults['shade_check']).lower(),
    )
    flags.DEFINE_integer(
        'exp_info',
        None,
        'Print a info message when a term is set to expire in that many weeks.\n(default: \'%s\')'
        % str(config.defaults['exp_info']),
    )
    flags.DEFINE_multi_string(
        'config_file', None, 'A yaml file with the configuration options for aerleon'
    )


class Error(Exception):
    """Base Error class."""


class P4WriteFileError(Error):
    """Error when there are issues p4 editing the destination."""


class ACLGeneratorError(Error):
    """Raised when an ACL generator has errors."""


class ACLParserError(Error):
    """Raised when the ACL parser fails."""


def SkipLines(text, skip_line_func=False):
    """Apply skip_line_func to the given text.

    Args:
      text: list of the first text to scan
      skip_line_func: function to use to check if we should skip a line

    Returns:
      ret_text: text(list) minus the skipped lines
    """
    if not skip_line_func:
        return text
    return [x for x in text if not skip_line_func(x)]


def RenderFile(
    base_directory: str,
    input_file: pathlib.Path,
    output_directory: pathlib.Path,
    definitions: naming.Naming,
    exp_info: int,
    optimize: bool,
    shade_check: bool,
) -> List[OutputFile]:
    """Render a single file.

    Args:
      base_directory: The base directory to look for acls.
      input_file: the name of the input policy file.
      output_directory: the directory in which we place the rendered file.
      definitions: the definitions from naming.Naming().
      exp_info: print a info message when a term is set to expire in that many
        weeks.
      optimize: a boolean indicating if we should turn on optimization or not.
      shade_check: should we raise an error if a term is completely shaded
      write_files: a list of file tuples, (output_file, acl_text), to write
    """
    output_relative = input_file.relative_to(base_directory).parent.parent
    output_directory = output_directory / output_relative

    logging.debug('rendering file: %s into %s', input_file, output_directory)

    try:
        with open(input_file) as f:
            conf = f.read()
            logging.debug('opened and read %s', input_file)
    except IOError as e:
        logging.warning('bad file: \n%s', e)
        raise

    try:
        # PolicySource[extension].ParsePolicy(conf)
        if pathlib.Path(input_file).suffix == '.yaml' or pathlib.Path(input_file).suffix == '.yml':
            pol = yaml.ParsePolicy(
                conf,
                filename=input_file,
                base_dir=base_directory,
                definitions=definitions,
                optimize=optimize,
                shade_check=shade_check,
            )
        else:
            pol = policy.ParsePolicy(
                conf,
                definitions,
                optimize=optimize,
                base_dir=base_directory,
                shade_check=shade_check,
            )
    except policy.ShadingError as e:
        logging.warning('shading errors for %s:\n%s', input_file, e)
        return
    except (policy.Error, naming.Error) as e:
        raise ACLParserError(
            'Error parsing policy file %s:\n%s%s'
            % (input_file, sys.exc_info()[0], sys.exc_info()[1])
        ) from e

    platforms = set()
    for header in pol.headers:
        platforms.update(header.platforms)

    acl_obj: aclgenerator.ACLGenerator
    plugin_supervisor.PluginSupervisor.Start()

    output_files: List[OutputFile] = []

    for target in platforms:
        generator = plugin_supervisor.PluginSupervisor.generators.get(target)
        if not generator:
            logging.warning(f"No generator found for target \"{target}\", skipping target.")
            continue

        try:
            # special handling for pcap
            if target == 'pcap':
                acl_obj = generator(copy.deepcopy(pol), exp_info)
                output_file = RenderACL(
                    str(acl_obj),
                    '-accept' + acl_obj.SUFFIX,
                    output_directory,
                    input_file,
                )
                if output_file:
                    output_files.append(output_file)

                acl_obj = generator(copy.deepcopy(pol), exp_info, invert=True)
                output_file = RenderACL(
                    str(acl_obj),
                    '-deny' + acl_obj.SUFFIX,
                    output_directory,
                    input_file,
                )
                if output_file:
                    output_files.append(output_file)
            else:
                acl_obj = generator(copy.deepcopy(pol), exp_info)
                output_file = RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory, input_file)
                if output_file:
                    output_files.append(output_file)

        except aclgenerator.Error as e:
            raise ACLGeneratorError(
                'Error generating target ACL for %s:\n%s' % (input_file, e)
            ) from e

    return output_files


def RenderACL(
    acl_text: str,
    acl_suffix: str,
    output_directory: pathlib.Path,
    input_file: pathlib.Path,
    binary: bool = False,
) -> Optional[OutputFile]:
    """Write the ACL string out to file if appropriate.

    Args:
      acl_text: Rendered output of an ACL Generator.
      acl_suffix: File suffix to append to output filename.
      output_directory: The directory to write the output file.
      input_file: The name of the policy file that was used to render ACL.
      write_files: A list of file tuples, (output_file, acl_text), to write.
      binary: Boolean if the rendered ACL is in binary format.
    """
    input_filename = input_file.with_suffix(acl_suffix).name
    output_file = output_directory / input_filename

    if FilesUpdated(output_file, acl_text, binary):
        logging.info('file changed: %s', output_file)
        return (output_file, acl_text)
    else:
        logging.debug('file not changed: %s', output_file)
        return None


def FilesUpdated(file_name: pathlib.Path, new_text: str, binary: bool) -> bool:
    """Diff the rendered acl with what's already on disk.

    Args:
      file_name: Name of file on disk to check against.
      new_text: Text of newly generated ACL.
      binary: True if file is a binary format.

    Returns:
      Boolean if config does not equal new text.
    """
    if binary:
        readmode = 'rb'
    else:
        readmode = 'r'
    try:
        with open(file_name, readmode) as f:
            conf: str = str(f.read())
    except IOError:
        return True
    if not binary:
        p4_id = '$' + 'Id:'
        p4_date = '$' + 'Date:'
        p4_revision = '$' + 'Revision:'

        def P4Tags(text: str) -> bool:
            return not (p4_id in text or p4_date in text or p4_revision in text)

        filtered_conf = filter(P4Tags, conf.split('\n'))
        filtered_text = filter(P4Tags, new_text.split('\n'))
        return list(filtered_conf) != list(filtered_text)
    return conf != new_text


def DescendDirectory(input_dirname: str, ignore_directories: List[str]) -> List[pathlib.Path]:
    """Descend from input_dirname looking for policy files to render.

    Args:
      input_dirname: the base directory.
      ignore_directories: directories to ignore while traversing.

    Returns:
      a list of input file paths
    """
    input_dir = pathlib.Path(input_dirname)

    policy_files: List[pathlib.Path] = []
    policy_directories: Iterator[pathlib.Path] = filter(
        lambda path: path.is_dir(), input_dir.glob('**/pol')
    )
    for ignored_directory in ignore_directories:

        def Filtering(path, ignored=ignored_directory):
            return not path.match('%s/**/pol' % ignored) and not path.match('%s/pol' % ignored)

        policy_directories = filter(Filtering, policy_directories)

    for directory in policy_directories:
        # Build glob strings from PolicySources.keys()
        # Or just match by extension
        directory_policies = (
            list(directory.glob('*.pol'))
            + list(directory.glob('*.yaml'))
            + list(directory.glob('*.yml'))
        )
        depth = len(directory.parents) - 1
        logging.warning(
            '-' * (2 * depth) + '> %s (%d pol files found)' % (directory, len(directory_policies))
        )
        policy_files.extend(filter(lambda path: path.is_file(), directory_policies))

    return policy_files


def WriteFiles(write_files: List[OutputFile]):
    """Writes files to disk.

    Args:
      write_files: List of file names and strings.
    """
    if write_files:
        logging.info('writing %d files to disk...', len(write_files))
    else:
        logging.info('no files changed, not writing to disk')
    for output_file, file_contents in write_files:
        _WriteFile(output_file, file_contents)


def _WriteFile(output_file: pathlib.Path, file_contents: str):
    """Inner file writing function.

    Args:
      output_file: Path to write to
      file_contents: Data to write
    """
    try:
        parent_path = pathlib.Path(output_file).parent
        if not parent_path.is_dir():
            parent_path.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as output:
            logging.info('writing file: %s', output_file)
            output.write(file_contents)
    except IOError:
        logging.warning('error while writing file: %s', output_file)
        raise


def _run_with_logging(logging_level, /, *args: Any, **kwargs: Any) -> List[OutputFile]:
    """
    runs RenderFile but sets up logging first.  This is needed for
    multiprocessing where the logging in main isn't applied
    """
    setup_logging(logging_level)

    return RenderFile(*args, **kwargs)


def Run(
    base_directory: str,
    definitions_directory: str,
    policy_file: str,
    output_directory: str,
    exp_info: int,
    max_renderers: int,
    ignore_directories: List[str],
    optimize: bool,
    shade_check: bool,
):
    """Generate ACLs.

    Args:
      base_directory: directory containing policy files.
      definitions_directory: directory containing NETWORK and SERVICES definition
        files.
      policy_file: path to a single policy file to render.
      output_directory: directory in which rendered files are placed.
      exp_info: print a info message when a term is set to expire in that many
        weeks.
      max_renderers: the number of renderers to run in parallel.
      ignore_directories: directories to ignore when searching for policy files.
      optimize: a boolean indicating if we should turn on optimization or not.
      shade_check: should we raise an error if a term is completely shaded.
    """
    definitions = None
    try:
        definitions = naming.Naming(definitions_directory)
    except naming.NoDefinitionsError:
        err_msg = 'bad definitions directory: %s' % definitions_directory
        logging.fatal(err_msg)
        return  # static type analyzer can't detect that logging.fatal exits program

    with_errors = False
    logging.info('finding policies...')
    if policy_file:
        # render just one file
        logging.info('rendering one file')
        write_files = RenderFile(
            base_directory,
            pathlib.Path(policy_file),
            pathlib.Path(output_directory),
            definitions,
            exp_info,
            optimize,
            shade_check,
        )
    elif max_renderers == 1:
        # If only one process, run it sequentially
        policies = DescendDirectory(base_directory, ignore_directories)
        write_files: List[OutputFile] = []
        for pol in policies:
            write_files.extend(
                RenderFile(
                    base_directory,
                    pol,
                    pathlib.Path(output_directory),
                    definitions,
                    exp_info,
                    optimize,
                    shade_check,
                )
            )
    else:
        # render all files in parallel
        policies = DescendDirectory(base_directory, ignore_directories)

        logging_level = logging.get_verbosity()
        with ProcessPoolExecutor(max_workers=max_renderers) as e:
            futures = [
                e.submit(
                    _run_with_logging,
                    logging_level,
                    base_directory,
                    policy,
                    output_directory,
                    definitions,
                    exp_info,
                    optimize,
                    shade_check,
                )
                for policy in policies
            ]

        write_files: List[OutputFile] = []
        for fut in futures:
            try:
                write_files.extend(fut.result())
            except (ACLParserError, ACLGeneratorError) as e:
                with_errors = True
                logging.warning('\n\nerror encountered in rendering process:\n%s\n\n', e)

    # actually write files to disk
    WriteFiles(write_files)

    if with_errors:
        logging.warning('done, with errors.')
        sys.exit(1)
    else:
        logging.info('done.')


def setup_logging(level: Any) -> None:
    logging.use_absl_handler()
    if level:
        logging.set_verbosity(level)


def main(argv):
    del argv  # Unused.

    configs = config.generate_configs(FLAGS)

    logging_level = None
    if configs['verbose']:
        logging_level = logging.INFO
    elif configs['debug']:
        logging_level = logging.DEBUG
    setup_logging(logging_level)

    logging.debug(
        'binary: %s\noptimize: %d\nbase_directory: %s\n'
        'policy_file: %s\nrendered_acl_directory: %s',
        str(sys.argv[0]),
        int(configs['optimize']),
        str(configs['base_directory']),
        str(configs['policy_file']),
        str(configs['output_directory']),
    )
    logging.debug('aerleon configurations: %s', configs)

    Run(
        configs['base_directory'],
        configs['definitions_directory'],
        configs['policy_file'],
        configs['output_directory'],
        configs['exp_info'],
        configs['max_renderers'],
        configs['ignore_directories'],
        configs['optimize'],
        configs['shade_check'],
    )


def EntryPoint():
    """Read in flags and call main()."""
    SetupFlags()
    app.run(main)


if __name__ == '__main__':
    EntryPoint()
