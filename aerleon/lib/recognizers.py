"""Intermediate data models and classes for the front-end parsing phase.

Classes:

## RawPolicy, RawFilter, RawTerm, RawKV

These classes act as an intermediate representation between a raw file representation
and the main Policy data model.

## TValue, TComposite

These are recognizers (they have a method .recognize(value)). They will parse value expressions
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
    """Recognizer types.

    Note these names are based loosely on Capirca's policy file
    YACC tokenizer token names. Conventions like "string" meaning
    essentially /\w+/ come from that vocabulary.

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

    def recognize(self, value):
        # .pol files allow strings with value "true" "True" "false" "False" and have no concept of a boolean type.
        if isinstance(value, bool):
            value = str(value).lower()

        if value is None:
            value = ""

        if self == TValue.AnyString:
            if not isinstance(value, str):
                # TODO(jb) some kind of debug context is needed here
                raise TypeError("Expected string.")
            return value

        elif self == TValue.WordString:
            if not isinstance(value, str):
                # TODO(jb) some kind of debug context is needed here
                raise TypeError("Expected string.")
            match = re.fullmatch(r'\w+([-_+.@/]\w*)*', value.strip())
            if match is None:
                raise TypeError("Expected value class 'String'.")
            return match[0]

        elif self == TValue.Integer:
            if isinstance(value, int):
                return value
            if not isinstance(value, str):
                # TODO(jb) some kind of debug context is needed here
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
                return TValue.DSCP.recognize(value)
            except TypeError:
                return '-'.join(
                    [TValue.DSCP.recognize(subvalue) for subvalue in value.strip().split('-')]
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
            return (TValue.WordString.recognize(first), TValue.WordString.recognize(second))


# TODO(jb) need good reprs for telling users what composite failed.
class TComposition:
    pass


@dataclass
class TUnion(TComposition):
    of: list[TValue | TComposition]

    def recognize(self, value):
        # Try each tokenizer on input
        for tokenizer in self.of:
            try:
                return tokenizer.recognize(value)
            except TypeError:
                continue
        # TODO(jb) need error context spans and repr for this union type:
        raise TypeError('Not recognized by this union type.')


@dataclass
class TList(TComposition):
    """
    Attributes:
        of: The allowed value or composition type for members of this list.
        collapsible: Whether a list with a single item can be given directly.
    """

    of: TValue | TComposition
    collapsible: bool = False

    def recognize(self, value):
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
            return list(map(self.of.recognize, value.split()))

        if (
            isinstance(value, str)
            and isinstance(self.of, TUnion)
            and all((_isSpaceFreeValue(value_type) for value_type in self.of.of))
        ):
            return list(map(self.of.recognize, value.split()))

        if self.collapsible:
            try:
                return [self.of.recognize(value)]
            except TypeError:
                pass

        if isinstance(value, list):
            return list(map(self.of.recognize, value))
        else:
            # TODO(jb) more error context please
            if self.collapsible:
                raise TypeError("Expected a list or collapsed list.")
            else:
                raise TypeError("Expected a list.")


@dataclass
class TSection(TComposition):
    of: list[typing.Tuple[str | TValue | TUnion, TValue | TComposition]]

    def recognize(self, value):
        if value is None:
            value = {}
        if not isinstance(value, dict):
            raise TypeError("Expected a dictionary.")
        # Rules:
        # (1) All keys must match one of the key rules. Key rules are checked in the order given.
        # (2) All values must match the value rule for that key
        # TODO(jb) move the above into docstring

        rules = self.of
        result = {}
        for keyword, keyword_value in value.items():
            for key_rule, value_rule in rules:
                if isinstance(key_rule, str):
                    if keyword != key_rule:
                        continue
                else:
                    try:
                        keyword = key_rule.recognize(keyword)
                    except TypeError:
                        continue
                # Let any TypeError propagate
                keyword_value = value_rule.recognize(keyword_value)
                result[keyword] = keyword_value
                break
        return result


# Pre-instantiate frequently used composite structures
TListStr = TList(of=TValue.WordString)
TListStrCollapsible = TList(of=TValue.WordString, collapsible=True)
