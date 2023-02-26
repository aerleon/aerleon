"""YAML front-end. Loads a Policy model from a .yaml file."""

import pathlib
from typing import Dict, List, Optional, Tuple, Union
from unittest.mock import MagicMock

import yaml
from absl import logging
from yaml.error import YAMLError

from aerleon.lib import policy
from aerleon.lib.policy import BadIncludePath, Policy, _SubpathOf
from aerleon.lib.policy_builder import (
    PolicyBuilder,
    PolicyDict,
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

    def __init__(self, message: str, *, filename, line=None, include_chain=None) -> None:
        self.message = message
        self.filename = filename
        self.line = line
        self.include_chain = include_chain

    def __str__(self) -> str:
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


def ParseFile(filename, base_dir='', definitions=None, optimize=False, shade_check=False):
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
            policy_dict = yaml.load(file, Loader=SpanSafeYamlLoader(filename=filename))
        except YAMLError as yaml_error:
            raise PolicyTypeError(
                UserMessage("Unable to read file as YAML.", filename=filename)
            ) from yaml_error
    policy_dict = PreprocessYAMLPolicy(filename, base_dir, policy_dict)
    if not policy_dict:
        return
    return policy.FromBuilder(PolicyBuilder(policy_dict, definitions, optimize, shade_check))


def ParsePolicy(
    file: str, *, filename, base_dir='', definitions=None, optimize=False, shade_check=False
) -> Optional[Union[MagicMock, Policy]]:
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
        policy_dict = yaml.load(file, Loader=SpanSafeYamlLoader(filename=filename))
    except YAMLError as yaml_error:
        raise PolicyTypeError(
            UserMessage("Unable to read file as YAML.", filename=filename)
        ) from yaml_error

    policy_dict = PreprocessYAMLPolicy(filename, base_dir, policy_dict)
    if not policy_dict:
        return
    return policy.FromBuilder(PolicyBuilder(policy_dict, definitions, optimize, shade_check))


def PreprocessYAMLPolicy(
    filename: str, base_dir: str, policy_dict: Optional[PolicyDict]
) -> Optional[Dict[str, List[Dict[str, Union[Dict[str, Dict[str, str]], List[Dict[str, str]]]]]]]:
    """Process includes and validate the file data as a PolicyDict."""

    # Empty files are ignored with a warning
    if policy_dict is None or not policy_dict:
        logging.warning(UserMessage("Ignoring empty policy file.", filename=filename))
        return

    # Malformed policy files should generate a PolicyTypeError (unless this is an include file)
    if 'filters' not in policy_dict or not isinstance(policy_dict['filters'], list):

        if 'terms' in policy_dict:
            # In this case we are looking at an include file and need to quietly ignore it.
            return

        raise PolicyTypeError(
            UserMessage("Policy file must contain one or more filter sections.", filename=filename)
        )

    for filter in policy_dict['filters']:
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
        if 'terms' not in filter or not filter['terms'] or not isinstance(filter['terms'], list):
            raise PolicyTypeError(
                UserMessage(
                    "Filter must contain a terms section.",
                    filename=filename,
                    line=filter['__line__'],
                )
            )

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

        found_terms = []
        max_include_depth = 5

        def process_include(depth, stack, include_filename):
            include_path = pathlib.Path(base_dir).joinpath(include_filename)
            if not _SubpathOf(base_dir, include_path):
                raise BadIncludePath(
                    f"Include file cannot be loaded from outside the base directory. File={include_path} base_directory={base_dir}"
                )

            try:
                include_file = _LoadIncludeFile(include_path)
                include_data = yaml.load(
                    include_file, Loader=SpanSafeYamlLoader(filename=str(include_path))
                )
            except YAMLError as yaml_error:
                raise PolicyTypeError(
                    UserMessage(
                        "Unable to read file as YAML.",
                        filename=str(include_path),
                        include_chain=stack,
                    )
                ) from yaml_error
            if not include_data or 'terms' not in include_data or not include_data['terms']:
                logging.warning(
                    UserMessage(
                        "Ignoring empty policy include source.",
                        filename=str(include_path),
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

        for term_item in found_terms:
            if 'name' not in term_item or len(term_item['name'].strip()) == 0:
                raise PolicyTypeError(
                    UserMessage(
                        "Term must have a name.",
                        filename=term_item['__filename__'],
                        line=term_item['__line__'],
                    )
                )

        filter['terms'] = found_terms

    def StripDebuggingData(data):
        if isinstance(data, list):
            for item in data:
                if isinstance(item, list) or isinstance(item, dict):
                    StripDebuggingData(item)
        elif isinstance(data, dict):
            data.pop('__line__', None)
            data.pop('__filename__', None)
            for item in data.values():
                if isinstance(item, list) or isinstance(item, dict):
                    StripDebuggingData(item)

    StripDebuggingData(policy_dict)

    return policy_dict


def _LoadIncludeFile(include_path: pathlib.PosixPath) -> str:
    """Open an include file."""

    with open(include_path, 'r') as include_file:
        return include_file.read()
