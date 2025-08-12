"""YAML front-end. Loads a Policy model from a .yaml file."""

import pathlib
from typing import Dict, List, Optional, Tuple, Union
from unittest.mock import MagicMock

import yaml
from absl import logging
from yaml.error import YAMLError

from aerleon.lib import policy
from aerleon.lib.policy import BadIncludePath, Policy, _SubpathOf
from aerleon.lib.policy_builder import PolicyBuilder, PolicyDict
from aerleon.lib.yaml_loader import SpanSafeYamlLoader

MAX_INCLUDE_DEPTH = 5


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

    @classmethod
    def fromValueError(cls, error: ValueError, *, filename, line=None, include_chain=None):
        """Create a UserMessage from a ValueError."""
        return cls(str(error), filename=filename, line=line, include_chain=include_chain)


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
    processor = YAMLPolicyPreprocessor(base_dir)
    policy_dict = processor(filename, policy_dict)
    if not policy_dict:
        return
    if not policy_dict['filters']:
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

    processor = YAMLPolicyPreprocessor(base_dir)
    policy_dict = processor(filename, policy_dict)
    if not policy_dict:
        return
    if not policy_dict['filters']:
        return
    return policy.FromBuilder(PolicyBuilder(policy_dict, definitions, optimize, shade_check))


def suffix_is_yaml(filename):
    return filename[-5:] == '.yaml' or filename[-4:] == '.yml'


class YAMLPolicyPreprocessor:
    """Processes a policy dictionary, handling includes and performing validation."""

    def __init__(self, base_dir: str):
        """
        Args:
            base_dir: The base directory for resolving include paths.
        """
        self.base_dir = base_dir

    def __call__(
        self, filename: str, policy_dict: Optional[PolicyDict]
    ) -> Optional[Dict[str, List[Dict[str, Union[Dict[str, Dict[str, str]], List[Dict[str, str]]]]]]]:
        """Process includes and validate the file data as a PolicyDict.

        Args:
            filename: The name of the policy file.
            policy_dict: The parsed YAML policy data.

        Returns:
            The processed policy dictionary with includes expanded.
        """
        debug_stack = []
        return self._preprocess_inner(
            MAX_INCLUDE_DEPTH,
            debug_stack,
            filename=filename,
            policy_dict=policy_dict,
        )

    def _preprocess_inner(
        self, depth: int, debug_stack: list, filename: str, policy_dict: Optional[PolicyDict]
    ) -> Optional[Dict[str, List[Dict[str, Union[Dict[str, Dict[str, str]], List[Dict[str, str]]]]]]]:
        # Empty files are ignored with a warning
        if policy_dict is None or not policy_dict:
            logging.warning(UserMessage("Ignoring empty policy file.", filename=filename))
            return

        # Malformed policy files should generate a PolicyTypeError (unless this is an include file)
        if 'filters' in policy_dict and isinstance(policy_dict['filters'], list):
            pass  # Normal case.
        elif (
            depth < MAX_INCLUDE_DEPTH
            and 'filters_include_only' in policy_dict
            and isinstance(policy_dict['filters_include_only'], list)
        ):
            # Policy files with filters_include_only: are ignored by ParsePolicy but can be included.
            policy_dict['filters'] = policy_dict['filters_include_only']
            del policy_dict['filters_include_only']
        elif 'terms' in policy_dict or 'filters_include_only' in policy_dict:
            # We are looking at an include file outside of an include and should quietly ignore it.
            return
        else:
            raise PolicyTypeError(
                UserMessage(
                    "Policy file must contain one or more filter sections.", filename=filename
                )
            )

        found_filters = []

        for filter_item in policy_dict['filters']:
            # Malformed filters should generate a PolicyTypeError
            if not isinstance(filter_item, dict):
                raise PolicyTypeError(UserMessage("Filter must be a mapping.", filename=filename))

            def expand_filter(filter_to_expand):
                stack = debug_stack.copy()
                stack.append((filter_to_expand['__filename__'], filter_to_expand['__line__']))

                if depth <= 0:
                    raise ExcessiveRecursionError(
                        UserMessage(
                            f"Excessive recursion: include depth limit of {MAX_INCLUDE_DEPTH} reached.",  # noqa: E501
                            filename=filter_to_expand['__filename__'],
                            line=filter_to_expand['__line__'],
                            include_chain=stack,
                        )
                    )
                try:
                    include_data, include_path = self._load_include_file(
                        filter_to_expand['include'], stack
                    )
                except ValueError as value_error:
                    raise PolicyTypeError(
                        UserMessage.fromValueError(
                            value_error,
                            filename=filter_to_expand['__filename__'],
                            line=filter_to_expand['__line__'],
                            include_chain=stack,
                        )
                    ) from value_error
                except YAMLError as yaml_error:
                    raise PolicyTypeError(
                        UserMessage(
                            "Unable to read file as YAML.",
                            filename=str(
                                pathlib.Path(self.base_dir).joinpath(filter_to_expand['include'])
                            ),
                            include_chain=stack,
                        )
                    ) from yaml_error

                data = self._preprocess_inner(
                    depth - 1,
                    stack,
                    filename=include_path.name,
                    policy_dict=include_data,
                )
                if not (data and data['filters']):
                    logging.warning(
                        UserMessage(
                            "Ignoring empty policy include source.",
                            filename=str(include_path),
                            include_chain=stack,
                        )
                    )
                    return
                found_filters.extend(data['filters'])

            if 'include' in filter_item:
                # This is an include directive
                expand_filter(filter_item)
                continue

            if 'header' not in filter_item or not isinstance(filter_item['header'], dict):
                raise PolicyTypeError(
                    UserMessage(
                        "Filter must contain a header section.",
                        filename=filename,
                        line=filter_item['__line__'],
                    )
                )

            if 'terms' not in filter_item or not filter_item['terms'] or not isinstance(filter_item['terms'], list):
                raise PolicyTypeError(
                    UserMessage(
                        "Filter must contain a terms section.",
                        filename=filename,
                        line=filter_item['__line__'],
                    )
                )

            header = filter_item['header']
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
                        line=filter_item['__line__'],
                    )
                )

            found_terms = []

            def process_terms(term_depth, stack, term_items):
                for term_item in term_items:
                    if 'include' not in term_item:
                        found_terms.append(term_item)
                        continue
                    new_stack = stack.copy()
                    new_stack.append((term_item['__filename__'], term_item['__line__']))
                    if term_depth <= 0:
                        raise ExcessiveRecursionError(
                            UserMessage(
                                f"Excessive recursion: include depth limit of {MAX_INCLUDE_DEPTH} reached.",  # noqa: E501
                                filename=term_item['__filename__'],
                                line=term_item['__line__'],
                                include_chain=new_stack,
                            )
                        )
                    try:
                        include_data, include_path = self._load_include_file(
                            term_item['include'], new_stack
                        )
                    except ValueError as value_error:
                        raise PolicyTypeError(
                            UserMessage.fromValueError(
                                value_error,
                                filename=term_item['__filename__'],
                                line=term_item['__line__'],
                                include_chain=new_stack,
                            )
                        ) from value_error
                    except YAMLError as yaml_error:
                        raise PolicyTypeError(
                            UserMessage(
                                "Unable to read file as YAML.",
                                filename=str(pathlib.Path(self.base_dir).joinpath(term_item['include'])),
                                include_chain=new_stack,
                            )
                        ) from yaml_error
                    if not include_data or 'terms' not in include_data or not include_data['terms']:
                        logging.warning(
                            UserMessage(
                                "Ignoring empty policy include source.",
                                filename=str(include_path),
                                include_chain=new_stack,
                            )
                        )
                        continue
                    process_terms(term_depth - 1, new_stack, include_data['terms'])

            process_terms(MAX_INCLUDE_DEPTH, [], filter_item['terms'])

            if not found_terms:
                logging.warning(
                    UserMessage(
                        "Ignoring filter with zero terms.",
                        filename=filename,
                        line=filter_item['__line__'],
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

            filter_item['terms'] = found_terms
            found_filters.append(filter_item)

        policy_dict['filters'] = found_filters

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

    def _load_include_file(
        self, relative_path: str, stack: list
    ) -> Tuple[Optional[PolicyDict], Union[str, pathlib.Path]]:
        """Load, parse, and validate an include file path."""
        if not suffix_is_yaml(relative_path):
            raise ValueError(
                f'Policy include source {relative_path} must end in ".yaml" or ".yml".'
            )
        include_path = pathlib.Path(self.base_dir).joinpath(relative_path)
        if not _SubpathOf(self.base_dir, include_path):
            raise BadIncludePath(
                f"Include file cannot be loaded from outside the base directory. File={include_path} base_directory={self.base_dir}"
            )

        with open(include_path, 'r') as include_file:
            include_data = yaml.load(
                include_file.read(), Loader=SpanSafeYamlLoader(filename=str(include_path))
            )
        return include_data, include_path


class GenerateAPIPolicyPreprocessor(YAMLPolicyPreprocessor):
    """A YAMLPolicyPreprocessor that sources includes from a dictionary."""

    def __init__(self, includes: Dict[str, PolicyDict]):
        """
        Args:
            includes: A read-only mapping from include name to file_dict.
        """
        super().__init__('')
        self.includes = includes

    def _load_include_file(
        self, relative_path: str, stack: list
    ) -> Tuple[Optional[PolicyDict], Union[str, pathlib.Path]]:
        """Override to load includes from the self.includes dictionary."""
        return self.includes.get(relative_path), relative_path
