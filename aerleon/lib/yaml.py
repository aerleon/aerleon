"""YAML front-end. Loads a Policy model from a .yaml file."""

import pathlib
from typing import Tuple
import yaml
from yaml.error import YAMLError

from absl import logging

from aerleon.lib import policy
from aerleon.lib.policy_builder import (
    PolicyBuilder,
    RawFilter,
    RawFilterHeader,
    RawPolicy,
    RawTerm,
)
from aerleon.lib.yaml_loader import SpanSafeYamlLoader


class PolicyTypeError(Exception):
    """Invalid policy."""


class ExcessiveRecursionError(Exception):
    """Include depth limit exceeded."""


# Consider making this span-oriented
# (file > line > (start_ch, end_ch))
class UserMessage:
    """A user-facing error message encountered during file processing.

    Users can be shown:
    * An error message only (user_message.message).
    * An error message with file / line / include stack (user_message.__repr__()).

    Attributes:
        message: The error message.
        filename: The name of the file in which this error or message originated.
        line: The line where this error or message originated.
        include_chain: If the error or message originated while processing an included
            file, include_chain will list the include file chain as a list of file/line tuples.
            The top-level file should be the first item in the list.
    """

    message: str
    filename: str
    line: int
    include_chain: "list[Tuple[str, int]]"

    def __init__(self, message, *, filename, line=None, include_chain=None):
        self.message = message
        self.filename = filename
        self.line = line
        self.include_chain = include_chain

    def __str__(self):
        """Display user-facing error message with include chain (if present).

        e.g.
        Excessive recursion: include depth limit of 5 reached. File=include_1.yaml, Line=3.
        Include stack:
        > File='policy_with_include.yaml', Line=11 (Top Level)
        > File='include_1.yaml', Line=3
        > File='include_1.yaml', Line=3
        > File='include_1.yaml', Line=3
        > File='include_1.yaml', Line=3
        > File='include_1.yaml', Line=3
        """  # noqa: E501
        error_context = f"{self.message} File={self.filename}"
        if self.line is not None:
            error_context += f", Line={self.line}"
        error_context += "."
        if self.include_chain is not None and len(self.include_chain) > 1:
            error_context += "\nInclude stack:"
            for i, (File, Line) in enumerate(self.include_chain):
                error_context += f"\n> File='{File}', Line={Line}"
                if i == 0:
                    error_context += " (Top Level)"
        return error_context

    def __repr__(self):
        return f"UserMessage(\"{str(self)}\")"


def ParseFile(filename, base_dir, definitions, optimize=False, shade_check=False):
    """Load a policy yaml file and return a Policy data model.

    Args:
        filename: Policy file path. Any output configs will share
            the same file name (except the file extension).
        naming: Naming database (see Naming class). Resolves network
            names to networks or lists of networks.
        optimize: bool - Whether to summarize networks and services.
        shade_check: bool - Whether to raise an exception when a term is shaded.

    Raises:
        PolicyTypeError: The policy file provided is not valid.
    """
    with open(pathlib.Path(base_dir).joinpath(filename), 'r') as file:
        try:
            file_data = yaml.load(file, Loader=SpanSafeYamlLoader(filename=filename))
        except YAMLError as yaml_error:
            raise PolicyTypeError(
                UserMessage("Unable to read file as YAML.", filename=filename)
            ) from yaml_error
    raw_policy = _RawPolicyFromFile(filename, base_dir, file_data)
    return _PolicyFromRawPolicy(raw_policy, definitions, optimize, shade_check)


def ParsePolicy(file, *, filename, base_dir, definitions, optimize=False, shade_check=False):
    """Load a policy yaml file (provided as a string) and return a Policy data model.

    Note that "filename" must still be provided. The input filename is used to
    determine the output filename.

    Args:
        file: The contents of the policy file.
        filename: Any output configs base their file name on this value (except the file extension).
        naming: Naming database (see Naming class). Resolves network
            names to networks or lists of networks.
        optimize: bool - Whether to summarize networks and services.
        shade_check: bool - Whether to raise an exception when a term is shaded.

    Raises:
        PolicyTypeError: The policy file provided is not valid.
    """
    try:
        file_data = yaml.load(file, Loader=SpanSafeYamlLoader(filename=filename))
    except YAMLError as yaml_error:
        raise PolicyTypeError(
            UserMessage("Unable to read file as YAML.", filename=filename)
        ) from yaml_error
    raw_policy = _RawPolicyFromFile(filename, base_dir, file_data)
    return _PolicyFromRawPolicy(raw_policy, definitions, optimize, shade_check)


def _RawPolicyFromFile(filename, base_dir, file_data):
    """Construct and return a RawPolicy from file data."""

    filters_model = []

    # Empty files are ignored with a warning
    if file_data is None or not file_data:
        logging.warning(UserMessage("Ignoring empty policy file.", filename=filename))
        return

    # Malformed policy files should generate a PolicyTypeError (unless this is an include file)
    if 'filters' not in file_data or not isinstance(file_data['filters'], list):

        if 'terms' in file_data:
            # In this case we are looking at an include file and need to quietly ignore it.
            return

        raise PolicyTypeError(
            UserMessage("Policy file must contain one or more filter sections.", filename=filename)
        )

    for filter in file_data['filters']:
        # Malformed filters should generate a PolicyTypeError
        if not isinstance(filter, dict):
            raise PolicyTypeError(UserMessage("Filter must be a mapping.", filename=filename))
        if 'header' not in filter or not isinstance(filter['header'], dict):
            raise PolicyTypeError(
                UserMessage(
                    "Filter must contain a header section.",
                    filename=filename,
                    line=filter['__line__'],
                )
            )
        if 'terms' not in filter or (
            filter['terms'] is not None and not isinstance(filter['terms'], list)
        ):
            raise PolicyTypeError(
                UserMessage(
                    "Filter must contain a terms section.",
                    filename=filename,
                    line=filter['__line__'],
                )
            )
        # Filters with an empty term list can be ignored with a warning
        elif filter['terms'] is None:
            logging.warning(
                UserMessage(
                    "Ignoring filter with zero terms.",
                    filename=filename,
                    line=filter['__line__'],
                )
            )
            continue

        header = filter['header']
        if 'targets' not in header or (
            header['targets'] is not None and not isinstance(header['targets'], dict)
        ):
            raise PolicyTypeError(
                UserMessage(
                    "Filter header must contain a targets section.",
                    filename=filename,
                    line=header['__line__'],
                )
            )
        # Filters with an empty target list can be ignored with a warning
        elif not header['targets']:
            raise PolicyTypeError(
                UserMessage(
                    "Filter header cannot be empty.",
                    filename=filename,
                    line=filter['__line__'],
                )
            )
            continue

        targets_model = {
            target: options
            for target, options in header['targets'].items()
            if target not in ('__line__', '__filename__')
        }

        header_kvs_model = {
            key: value
            for key, value in header.items()
            if key not in ('targets', '__line__', '__filename__')
        }
        header_model = RawFilterHeader(targets=targets_model, kvs=header_kvs_model)

        found_terms = []
        max_include_depth = 5

        def process_include(depth, stack, inc_filename):
            try:
                include_file = _LoadIncludeFile(base_dir, inc_filename)
                include_data = yaml.load(
                    include_file, Loader=SpanSafeYamlLoader(filename=inc_filename)
                )
            except YAMLError as yaml_error:
                raise PolicyTypeError(
                    UserMessage(
                        "Unable to read file as YAML.",
                        filename=inc_filename,
                        include_chain=stack,
                    )
                ) from yaml_error
            if not include_data or 'terms' not in include_data or not include_data['terms']:
                logging.warning(
                    UserMessage(
                        "Ignoring empty policy include source.",
                        filename=inc_filename,
                        include_chain=stack,
                    )
                )
                return
            process_terms(depth, stack, include_data['terms'])

        def process_terms(depth, stack, term_items):
            for term_item in term_items:
                if 'include' in term_item:
                    new_stack = stack.copy()
                    new_stack.append((term_item['__filename__'], term_item['__line__']))
                    if depth <= 0:
                        raise ExcessiveRecursionError(
                            UserMessage(
                                f"Excessive recursion: include depth limit of {max_include_depth} reached.",  # noqa: E501
                                filename=term_item['__filename__'],
                                line=term_item['__line__'],
                                include_chain=new_stack,
                            )
                        )
                    if (
                        term_item['include'][-5:] != '.yaml'
                        and term_item['include'][-4:] != '.yml'
                    ):
                        raise PolicyTypeError(
                            UserMessage(
                                f"Policy include source {term_item['include']} must end in \".yaml\".",  # noqa: E501
                                filename=term_item['__filename__'],
                                line=term_item['__line__'],
                                include_chain=new_stack,
                            )
                        )
                    process_include(depth - 1, new_stack, term_item['include'])
                else:
                    found_terms.append(term_item)

        process_terms(max_include_depth, [], filter['terms'])

        if not found_terms:
            logging.warning(
                UserMessage(
                    "Ignoring filter with zero terms.",
                    filename=filename,
                    line=filter['__line__'],
                )
            )
            continue

        terms_model = []
        for term_item in found_terms:
            if 'name' not in term_item or len(term_item['name'].strip()) == 0:
                raise PolicyTypeError(
                    UserMessage(
                        "Term must have a name.",
                        filename=term_item['__filename__'],
                        line=term_item['__line__'],
                    )
                )
            name = term_item['name']
            term_kvs_model = {
                key: value
                for key, value in term_item.items()
                if key not in ('name', '__filename__', '__line__')
            }

            # strip any nested debugging data
            for value in term_kvs_model.values():
                if isinstance(value, dict):
                    value.pop('__line__')
                    value.pop('__filename__')

            terms_model.append(RawTerm(name=name, kvs=term_kvs_model))
        filters_model.append(RawFilter(header=header_model, terms=terms_model))

    return RawPolicy(filename=filename, filters=filters_model)


def _LoadIncludeFile(base_dir, inc_filename):
    """Open an include file."""

    with open(pathlib.Path(base_dir).joinpath(inc_filename), 'r') as include_file:
        return include_file


def _PolicyFromRawPolicy(raw_policy, definitions, optimize=False, shade_check=False):
    """Construct and return a policy.Policy model from a RawPolicy."""

    policy_builder = PolicyBuilder(raw_policy, definitions, optimize, shade_check)
    return policy.FromBuilder(policy_builder)
