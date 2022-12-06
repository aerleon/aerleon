"""Intermediate data models and classes for the front-end parsing phase.

Classes:

## RawPolicy, RawFilter, RawTerm, RawKV

These classes act as an intermediate representation between a raw file representation
and the main Policy data model.

## TValue, TComposite

These are recognizers (they have a method .Recognize(value)). They will parse value expressions
and extract normalized data from within.

## BuiltinRecognizer

This class uses recognizers to parse, validate and normalize all built-in fields in the Policy.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime
import enum
import re
import typing

if typing.TYPE_CHECKING:
    from aerleon.lib.policy_builder import (
        RawFilter,
        RawFilterHeader,
        RawPolicy,
        RawTarget,
        RawTerm,
    )


@dataclass
class RecognizerContext:
    policy: RawPolicy
    filter: RawFilter = None
    header: RawFilterHeader = None
    target: RawTarget = None
    term: RawTerm = None
    keyword: str = None
    value: str = None


@dataclass
class RecognizerKeywordResult:
    recognized: bool
    securityCritical: bool = False


@dataclass
class RecognizerValueResult:
    recognized: bool
    securityCritical: bool = False
    valueKV: dict = None


@dataclass
class RecognizerOptionResult:
    securityCritical: bool
    valueKV: dict = None


class TValue(enum.Enum):
    """Common recognizer types.

    These names are based loosely on the token names in Capirca's policy file
    parser. "WordString" is based on "STRING" and "AnyString" is based on "ANY".

    Generators that recognize extra keywords are encouraged
    but not required to use these types when implementing
    recognizeKeywordValue(). For the sake of consistency Generator
    authors should try to map their input to one of these value
    types, or a composition of value types (see TComposite).
    """

    AnyString = enum.auto()  # any value expression
    WordString = enum.auto()  # \w+
    Integer = enum.auto()  # \d+ string or YAML integer
    Hex = enum.auto()  # hex
    IntegerRange = enum.auto()  # Integer '-' Integer
    YearMonthDay = enum.auto()  # YYYY '-' MM '-' DD
    DSCP = enum.auto()  # DSCP traffic class
    DSCPRange = enum.auto()  # Range of DSCP traffic classes
    LogLimit = enum.auto()  # Integer '/' Str
    TargetResourceTuple = enum.auto()  # '(' Str ',' Str ')'

    def Recognize(self, value: typing.Any):
        """Match and parse the input value.

        Arguments:
            value: The input value.

        Returns: The input value after some parsing and normalization. For example,
            TValue.YearMonthDay would accept both a date object and a string of
            the form YYYY-MM-DD and return a date object in both cases.

        Raises:
            TypeError: If the input value does not match.
        """
        # .pol files allow strings with value "true" "True" "false" "False" and have no concept of a boolean type.
        if isinstance(value, bool):
            value = str(value).lower()

        if value is None:
            value = ""

        if self == TValue.AnyString:
            if not isinstance(value, str):
                raise TypeError("Expected string.")
            return value

        elif self == TValue.WordString:
            if not isinstance(value, str):
                raise TypeError("Expected string.")
            match = re.fullmatch(r'\w+([-_+.@/]\w*)*', value.strip())
            if match is None:
                raise TypeError("Expected value class 'String'.")
            return match[0]

        elif self == TValue.Integer:
            if isinstance(value, int):
                return value
            if not isinstance(value, str):
                raise TypeError("Expected integer or string.")
            match = re.fullmatch(r'\d+', value.strip())
            if match is None:
                raise TypeError("Expected value class 'Integer'.")
            return int(match[0])

        elif self == TValue.Hex:
            if not isinstance(value, str):
                raise TypeError("Expected string.")
            match = re.fullmatch(r'0x[a-fA-F0-9]+', value.strip())
            if match is None:
                raise TypeError("Expected value class 'Hex'.")
            return match[0]

        elif self == TValue.IntegerRange:
            if not isinstance(value, str):
                raise TypeError("Expected string.")
            match = re.fullmatch(r'(?P<start>\d+)\s*-\s*(?P<end>\d+)', value.strip())
            if match is None:
                raise TypeError("Expected value class 'IntegerRange'.")
            return f"{match['start']}-{match['end']}"

        elif self == TValue.YearMonthDay:
            if isinstance(value, datetime.date):
                return value
            if not isinstance(value, str):
                raise TypeError("Expected string or date.")
            match = re.fullmatch(
                r'(?P<year>\d+)\s*-\s*(?P<month>\d+)\s*-\s*(?P<day>\d+)', value.strip()
            )
            if match is None:
                raise TypeError("Expected value class 'YearMonthDay'.")
            return datetime.date(int(match['year']), int(match['month']), int(match['day']))

        elif self == TValue.DSCP:
            if isinstance(value, int):
                return str(value)
            if not isinstance(value, str):
                raise TypeError("Expected string or integer.")
            match = re.fullmatch(r'\d+', value.strip())
            if match:
                return match[0]
            match = re.fullmatch(
                r'\b((b[0-1]{6})|(af[1-4]{1}[1-3]{1})|(be)|(ef)|(cs[0-7]{1}))(?![\w-])\b',
                value.strip(),
            )
            if match:
                return match[0]
            raise TypeError("Expected value class 'DSCP'.")

        elif self == TValue.DSCPRange:
            try:
                return TValue.DSCP.Recognize(value)
            except TypeError:
                return '-'.join(
                    [TValue.DSCP.Recognize(subvalue) for subvalue in value.strip().split('-')]
                )

        elif self == TValue.LogLimit:
            if not isinstance(value, str):
                raise TypeError("Expected string.")
            match = re.fullmatch(r'(?P<frequency>\d+)\s*/\s*(?P<period>\w+)', value.strip())
            if match is None:
                raise TypeError("Expected value class 'LogLimit'.")
            return (match['frequency'], match['period'])

        elif self == TValue.TargetResourceTuple:
            if isinstance(value, list):
                if len(value) != 2:
                    raise TypeError("Expected list of length=2 or string.")
                first, second = value
            else:
                if not isinstance(value, str):
                    raise TypeError("Expected list or string.")
                match = re.fullmatch(r'\(\s*(.*)\s*,\s*(.*)\s*\)|(.*)\s*,\s*(.*)', value.strip())
                if match is None:
                    raise TypeError("Expected list or tuple expression.")
                first, second = (
                    (match[1], match[2]) if match[1] is not None else (match[3], match[4])
                )
            return (TValue.WordString.Recognize(first), TValue.WordString.Recognize(second))


class TComposition:
    of: typing.Any

    def Recognize(self, value: typing.Any) -> typing.Any:
        """Match and parse the input value."""
        pass


@dataclass
class TUnion(TComposition):
    """Recognizer that multiplexes a list of sub-recognizers.

    Attributes:
        of: A list of allowed types. The input must match one of these types.
    """

    of: "list[TValue | TComposition]"

    def Recognize(self, value):
        """Match and parse the input value using the list of sub-recognizers given in the 'of'
        class attribute.

        Arguments:
            value: The input value.

        Returns: The value processed by the first recognizer that matches it.

        Raises:
            TypeError: If none of the sub-recognizers match the input.
        """
        # Try each tokenizer on input
        for tokenizer in self.of:
            try:
                return tokenizer.Recognize(value)
            except TypeError:
                continue
        raise TypeError('Not recognized by this union type.')


@dataclass
class TList(TComposition):
    """Recognizer for list inputs.

    Attributes:
        of: The allowed type for members of this list.
        collapsible: Whether a list with a single item can be given directly.
    """

    of: "TValue | TComposition"
    collapsible: bool = False

    def Recognize(self, value):
        """Match and parse the input value using the recognizer given in the 'of' class attribute.

        Arguments:
            value: The input value. Can be a list of values, a string (if space-separated list
            criteria are met), or a value that directly matches the 'of' recognizer.

        Returns: A list with each value processed by the recognizer given in attribute 'of'.

            If the 'collapsible' attribute is true, the input can be a value that matches the 'of'
            recognizer directly. For example, if 'of' is TValue.Integer, value=list(100) and
            value=100 are both acceptable inputs.

            If the 'of' attribute is a space-free TValue or a union of space-free TValues, a string
            input may be passed to this function. That string will be split by whitespace and the
            resulting list will be used as the input.

        Raises:
            TypeError: If any value in the list is not recognized by the 'of' attribute or
                if a non-list was provided when the collapsible list or space-separated list
                criteria are not met.
        """

        # TList accepts three modes of input:
        # (1) A list where each value is recognized by self.of
        # (2) A single value, dist or list recognized by self.of if collapsible=True.
        # (3) A string containing a space separated list of values (not supported for all value types).

        def _isSpaceFreeValue(value_type: TValue):
            return isinstance(value_type, TValue) and value_type not in (
                TValue.AnyString,
                TValue.TargetResourceTuple,
            )

        if value is None:
            value = []

        if isinstance(value, str) and _isSpaceFreeValue(self.of):
            return list(map(self.of.Recognize, value.split()))

        if (
            isinstance(value, str)
            and isinstance(self.of, TUnion)
            and all((_isSpaceFreeValue(value_type) for value_type in self.of.of))
        ):
            return list(map(self.of.Recognize, value.split()))

        if self.collapsible:
            try:
                return [self.of.Recognize(value)]
            except TypeError:
                pass

        if isinstance(value, list):
            return list(map(self.of.Recognize, value))
        else:
            if self.collapsible:
                raise TypeError("Expected a list or collapsed list.")
            else:
                raise TypeError("Expected a list.")


@dataclass
class TSection(TComposition):
    """Recognizer for dict inputs.

    Attributes:
        of: A list of rules for this section. Each rule is a 2-tuple with the first
            part containing the 'key rule' and the second part the 'value rule'.

            A 'key rule' can be:
                * A string literal.
                * A TValue recognizer.
                * A TUnion recognizer.

            A 'value rule' can be:
                * A TValue reconizer.
                * Any TComposition recognizer.

            A string literal key rule matches a key exactly. A TValue or TUnion key rule matches
            any key recognized by the given recognizer. A TValue or TComposition value rule matches
            any value recognized by the given recognizer.
    """

    of: "list[typing.Tuple[str | TValue | TUnion, TValue | TComposition]]"

    def Recognize(self, value: dict):
        """Match and parse the input value using the list of rules given in the 'of' class attribute.
        See class docstring for more details on how to specify the rules list.

        Arguments:
            value: The input dict.

        Returns: A dict with the same keys as the input and with each value processed by the first
            matching value rule.

            Rules are processed in the order the appear in the 'of' list. In the event that a key
            rule matches but the value rule does not match, processing will continue through the
            list of rules.

        Raises:
            TypeError: If any key/value pair present in the input did not match any of the rules.
        """
        if value is None:
            value = {}
        if not isinstance(value, dict):
            raise TypeError("Expected a dictionary.")

        rules = self.of
        result = {}
        for keyword, keyword_value in value.items():
            last_error = None
            for key_rule, value_rule in rules:
                if isinstance(key_rule, str):
                    if keyword != key_rule:
                        continue
                else:
                    try:
                        keyword = key_rule.Recognize(keyword)
                    except TypeError:
                        continue
                try:
                    keyword_value = value_rule.Recognize(keyword_value)
                    result[keyword] = keyword_value
                    break
                except TypeError as e:
                    # Collect any TypeError but continue to search for another matching key_rule.
                    # If a subsequent key_rule / value_rule pair matches we can ignore the stored error.
                    # If no subsequent match is found we will raise the last value rule TypeError.
                    last_error = e
                    continue
            else:
                if last_error:
                    # A value rule TypeError was collected and no subsequent key rules matched.
                    raise last_error
                # None of the key rules matched `keyword`
                raise TypeError(f"Unexpected key {keyword} in section.")
        return result


# Pre-instantiate frequently used composite structures
TListStr = TList(of=TValue.WordString)
TListStrCollapsible = TList(of=TValue.WordString, collapsible=True)
