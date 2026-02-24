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
import multiprocessing.context
import multiprocessing.managers
import multiprocessing.pool
import pathlib
import sys
import typing
from collections.abc import Iterator

from absl import app, flags, logging

from aerleon.lib import aclgenerator, naming, pcap, plugin_supervisor, policy, yaml
from aerleon.utils import config

FLAGS = flags.FLAGS
WriteList = typing.MutableSequence[tuple[pathlib.Path, str]]


def SetupFlags():
    """Read in configuration from CLI flags."""
    flags.DEFINE_string(
        'base_directory',
        None,
        'The base directory to search recursively for policy files.\n'
        'Relative policy imports are resolved against this directory.\n'
        'If --policy_file is used, aclgen will not search this directory.\n'
        'Default: \'%s\'' % config.defaults['base_directory'],
    )
    flags.DEFINE_string(
        'definitions_directory',
        None,
        'Directory containing network and service definition files.\n'
        'Default: \'%s\'' % config.defaults['definitions_directory'],
    )
    flags.DEFINE_string('policy_file', None, 'Individual policy file to generate.')
    flags.DEFINE_string(
        'output_directory',
        None,
        'Directory to output the rendered acls.\nDefault: \'%s\''
        % config.defaults['output_directory'],
    )
    flags.DEFINE_boolean(
        'optimize',
        None,
        f"Turn on optimization.\nDefault: '{config.defaults['optimize']}'",
        short_name='o',
    )
    flags.DEFINE_boolean(
        'recursive',
        None,
        'UNUSED. '
        'Recursive policy file search is always enabled except when using the --policy_file flag.',
    )
    flags.DEFINE_boolean(
        'debug',
        None,
        f"Display detailed messages.\nDefault: '{str(config.defaults['debug']).lower()}'",
    )
    flags.DEFINE_boolean('verbose', None, 'UNUSED. Use --debug instead.')
    flags.DEFINE_list(
        'ignore_directories',
        None,
        'Don\'t descend into directories that look like this string.\nDefault: \'%s\''
        % ','.join(config.defaults['ignore_directories']),
    )
    flags.DEFINE_integer(
        'max_renderers',
        None,
        'Max number of rendering processes to use.\nDefault: \'%s\''
        % config.defaults['max_renderers'],
    )
    flags.DEFINE_boolean(
        'shade_check',
        None,
        'Raise an error when a term is completely shaded by a prior term.\nDefault: \'%s\''
        % str(config.defaults['shade_check']).lower(),
    )
    flags.DEFINE_integer(
        'exp_info',
        None,
        'Print a message when a term is set to expire in that many weeks.\nDefault: \'%s\''
        % str(config.defaults['exp_info']),
    )
    flags.DEFINE_multi_string('config_file', None, 'A YAML file with configuration options')


class Error(Exception):
    """Base Error class."""


class P4WriteFileError(Error):
    """Error when there are issues p4 editing the destination."""


class ACLGeneratorError(Error):
    """Raised when an ACL generator has errors."""


class ACLParserError(Error):
    """Raised when the ACL parser fails."""


def RenderFile(
    base_directory: str,
    input_file: pathlib.Path,
    output_directory: pathlib.Path,
    definitions: naming.Naming,
    exp_info: int,
    optimize: bool,
    shade_check: bool,
    write_files: WriteList,
):
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

    pol = None

    try:
        with open(input_file) as f:
            conf = f.read()
            logging.debug('opened and read %s', input_file)
    except OSError as e:
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

    platforms = {platform for header in pol.headers for platform in header.platforms}

    acl_obj: aclgenerator.ACLGenerator
    plugin_supervisor.PluginSupervisor.Start()

    for target in platforms:
        generator = plugin_supervisor.PluginSupervisor.generators.get(target)
        if not generator:
            logging.warning(f"No generator found for target \"{target}\", skipping target.")
            continue

        try:
            # special handling for pcap
            if target == 'pcap':
                assert issubclass(generator, pcap.PcapFilter)
                acl_obj = generator(copy.deepcopy(pol), exp_info)
                RenderACL(
                    str(acl_obj),
                    f"-accept{acl_obj.SUFFIX}",
                    output_directory,
                    input_file,
                    write_files,
                )
                acl_obj = generator(copy.deepcopy(pol), exp_info, invert=True)
                RenderACL(
                    str(acl_obj),
                    f"-deny{acl_obj.SUFFIX}",
                    output_directory,
                    input_file,
                    write_files,
                )
            else:
                acl_obj = generator(copy.deepcopy(pol), exp_info)
                RenderACL(str(acl_obj), acl_obj.SUFFIX, output_directory, input_file, write_files)

        except aclgenerator.Error as e:
            raise ACLGeneratorError(f'Error generating target ACL for {input_file}:\n{e}') from e


def RenderACL(
    acl_text: str,
    acl_suffix: str,
    output_directory: pathlib.Path,
    input_file: pathlib.Path,
    write_files: typing.MutableSequence[tuple[pathlib.Path, str]],
    binary: bool = False,
):
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
        write_files.append((output_file, acl_text))
    else:
        logging.debug('file not changed: %s', output_file)


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
    except OSError:
        return True
    if not binary:
        p4_id = '$I d:'.replace(' ', '')
        p4_date = '$Da te:'.replace(' ', '')
        p4_revision = '$Rev ision:'.replace(' ', '')

        def P4Tags(text: str) -> bool:
            return not (p4_id in text or p4_date in text or p4_revision in text)

        filtered_conf = filter(P4Tags, conf.split('\n'))
        filtered_text = filter(P4Tags, new_text.split('\n'))
        return list(filtered_conf) != list(filtered_text)
    return conf != new_text


def DescendDirectory(input_dirname: str, ignore_directories: list[str]) -> list[pathlib.Path]:
    """Descend from input_dirname looking for policy files to render.

    Args:
      input_dirname: the base directory.
      ignore_directories: directories to ignore while traversing.

    Returns:
      a list of input file paths
    """
    input_dir = pathlib.Path(input_dirname)

    policy_files: list[pathlib.Path] = []
    policy_directories: Iterator[pathlib.Path] = filter(
        lambda path: path.is_dir(), input_dir.glob('**/pol')
    )
    for ignored_directory in ignore_directories:

        def Filtering(path, ignored=ignored_directory):
            return not path.match(f'{ignored}/**/pol') and not path.match(f'{ignored}/pol')

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
            f"{'-' * (2 * depth)}> {directory} ({len(directory_policies)} pol files found)"
        )
        policy_files.extend(filter(lambda path: path.is_file(), directory_policies))

    return policy_files


def WriteFiles(write_files: WriteList):
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
    except OSError:
        logging.warning('error while writing file: %s', output_file)
        raise


def Run(
    base_directory: str,
    definitions_directory: str,
    policy_file: str,
    output_directory: str,
    exp_info: int,
    max_renderers: int,
    ignore_directories: list[str],
    optimize: bool,
    shade_check: bool,
    context: multiprocessing.context.BaseContext,
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
      context: multiprocessing context
    """
    definitions = None
    try:
        definitions = naming.Naming(definitions_directory)
    except naming.NoDefinitionsError:
        err_msg = f'bad definitions directory: {definitions_directory}'
        logging.fatal(err_msg)
        return  # static type analyzer can't detect that logging.fatal exits program

    # thead-safe list for storing files to write
    manager: multiprocessing.managers.SyncManager = context.Manager()
    write_files: WriteList = manager.list()

    with_errors = False
    logging.info('finding policies...')
    if max_renderers == 1 or policy_file:
        if policy_file:
            policies = [pathlib.Path(policy_file)]
        else:
            policies = DescendDirectory(base_directory, ignore_directories)
        try:
            for pol in policies:
                RenderFile(
                    base_directory,
                    pol,
                    pathlib.Path(output_directory),
                    definitions,
                    exp_info,
                    optimize,
                    shade_check,
                    write_files,
                )
        except (ACLParserError, ACLGeneratorError) as e:
            with_errors = True
            logging.warning('\n\nerror encountered in rendering process:\n%s\n\n', e)
    else:
        # render all files in parallel
        policies = DescendDirectory(base_directory, ignore_directories)
        pool = context.Pool(processes=max_renderers)
        results: list[multiprocessing.pool.AsyncResult] = []
        for pol in policies:
            results.append(
                pool.apply_async(
                    RenderFile,
                    args=(
                        base_directory,
                        pol,
                        output_directory,
                        definitions,
                        exp_info,
                        optimize,
                        shade_check,
                        write_files,
                    ),
                )
            )
        pool.close()
        pool.join()

        for result in results:
            try:
                result.get()
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


def main(argv):
    del argv  # Unused.

    absl_flags = {
        flag: getattr(FLAGS, flag) for flag in config.defaults.keys() if getattr(FLAGS, flag, None)
    }
    try:
        configs = config.load_config(config_file=FLAGS.config_file)
        configs.update(absl_flags)
    except config.ConfigFileError as e:
        exit(f"Error: {e}")

    if configs['verbose']:
        logging.set_verbosity(logging.INFO)
    if configs['debug']:
        logging.set_verbosity(logging.DEBUG)
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

    context = multiprocessing.get_context()
    try:
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
            context,
        )
    except Exception as e:
        logging.error(f"Unhandled exception: {e}", exc_info=True)
        sys.exit(1)


def EntryPoint():
    """Read in flags and call main()."""
    SetupFlags()
    app.run(main)


if __name__ == '__main__':
    EntryPoint()
