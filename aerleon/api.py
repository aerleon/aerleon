"""Aerleon Python API

"""
import copy
import multiprocessing
import pathlib
import sys
import typing

from absl import logging

from aerleon.aclgen import ACLParserError, ACLGeneratorError, RenderACL, WriteFiles, WriteList

from aerleon.lib import aclgenerator
from aerleon.lib import naming
from aerleon.lib import plugin_supervisor
from aerleon.lib import policy
from aerleon.lib import policy_builder


def Generate(
    policies,
    definitions,
    output_directory: pathlib.Path = None,
    optimize=False,
    shade_check=False,
    exp_info=2,
) -> "dict[str, str]":

    context = multiprocessing.get_context()
    return _Generate(
        policies,
        definitions,
        context,
        output_directory,
        optimize,
        shade_check,
        exp_info,
    )


def _Generate(
    policies,
    definitions: naming.Naming,
    context: multiprocessing.context.BaseContext,
    output_directory=None,
    optimize=False,
    shade_check=False,
    exp_info=2,
    max_renderers=1,
) -> "dict[str, str]":

    # thead-safe list for storing files to write
    manager: multiprocessing.managers.SyncManager = context.Manager()
    write_files: WriteList = manager.list()
    errors: list = manager.list()
    generated_configs: dict = manager.dict()

    if max_renderers == 1:
        for input_policy in policies:
            _GenerateACL(
                input_policy,
                definitions,
                write_files,
                generated_configs,
                output_directory,
                optimize,
                shade_check,
                exp_info,
            )
    else:
        pool = context.Pool(processes=max_renderers)
        async_results: list[multiprocessing.pool.AsyncResult] = []
        for input_policy in policies:
            async_result = pool.apply_async(
                _GenerateACL,
                args=(
                    input_policy,
                    definitions,
                    write_files,
                    generated_configs,
                    output_directory,
                    optimize,
                    shade_check,
                    exp_info,
                ),
            )
            async_results.append(async_result)
        pool.close()
        pool.join()
        for result in async_results:
            try:
                result.get()
            except (ACLParserError, ACLGeneratorError) as e:
                logging.warning('\n\nerror encountered in rendering process:\n%s\n\n', e)
                errors.append(e)

    if output_directory:
        WriteFiles(write_files)
        return None
    else:
        return generated_configs


def _GenerateACL(
    input_policy: policy.Policy,
    definitions: naming.Naming,
    write_files: WriteList,
    generated_configs: dict,
    output_directory: pathlib.Path = None,
    optimize=False,
    shade_check=False,
    exp_info=2,
):
    raw_filters = []
    input_filters = input_policy["filters"]
    filename = input_policy.get("filename")
    for filter in input_filters:

        filter_header = filter["header"]
        header_targets = filter_header["targets"]
        raw_filter_header = policy_builder.RawFilterHeader(
            targets=header_targets, kvs=filter_header
        )

        raw_terms = []
        filter_terms = filter["terms"]
        for term in filter_terms:
            raw_term = policy_builder.RawTerm(name=term["name"], kvs=term)
            raw_terms.append(raw_term)

        raw_filters.append(policy_builder.RawFilter(header=raw_filter_header, terms=raw_terms))

    raw_policy = policy_builder.RawPolicy(filename=filename, filters=raw_filters)
    try:
        policy_obj = policy.FromBuilder(
            policy_builder.PolicyBuilder(raw_policy, definitions, optimize, shade_check)
        )
    except policy.ShadingError as e:
        logging.warning('shading errors for %s:\n%s', filename, e)
        return
    except (policy.Error, naming.Error) as e:
        raise ACLParserError(
            'Error parsing policy %s:\n%s%s' % (filename, sys.exc_info()[0], sys.exc_info()[1])
        ) from e

    platforms = set()
    for header in policy_obj.headers:
        platforms.update(header.platforms)

    acl_obj: aclgenerator.ACLGenerator
    plugin_supervisor.PluginSupervisor.Start()

    def EmitACL(
        acl_text: str,
        acl_suffix: str,
        write_files: typing.List[typing.Tuple[pathlib.Path, str]],
        binary: bool = False,
    ):
        if output_directory:
            RenderACL(acl_text, acl_suffix, output_directory, filename, write_files, binary)
        else:
            output_file = pathlib.Path(filename).with_suffix(acl_suffix).name
            generated_configs[output_file] = acl_text

    for target in platforms:
        generator = plugin_supervisor.PluginSupervisor.generators.get(target)
        if not generator:
            logging.warning(f"No generator found for target \"{target}\", skipping target.")
            continue

        try:
            # special handling for pcap
            if target == 'pcap':
                acl_obj = generator(copy.deepcopy(policy_obj), exp_info)
                EmitACL(
                    str(acl_obj),
                    '-accept' + acl_obj.SUFFIX,
                    write_files,
                )
                acl_obj = generator(copy.deepcopy(policy_obj), exp_info, invert=True)
                EmitACL(
                    str(acl_obj),
                    '-deny' + acl_obj.SUFFIX,
                    write_files,
                )
            else:
                acl_obj = generator(copy.deepcopy(policy_obj), exp_info)
                EmitACL(str(acl_obj), acl_obj.SUFFIX, write_files)

        except aclgenerator.Error as e:
            raise ACLGeneratorError(
                'Error generating target ACL for %s:\n%s' % (filename, e)
            ) from e
