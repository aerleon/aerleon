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


BUILTIN_FLEXIBLE_MATCH_RANGE_ATTRIBUTES = {
    'byte-offset',
    'bit-offset',
    'bit-length',
    'match-start',
    'range',
    'range-except',
    'flexible-range-name',
}
BUILTIN_FLEXIBLE_MATCH_START_OPTIONS = {'layer-3', 'layer-4', 'payload'}


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
            return {key: match[key] for key in ('frequency', 'period')}

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

BUILTIN_HEADER_SPEC: dict[str, TValue | TComposition] = {
    'apply-groups': TListStrCollapsible,
    'apply-groups-except': TListStrCollapsible,
    'comment': TValue.AnyString,
    'targets': TSection(of=[(TValue.WordString, TListStrCollapsible)]),
}
BUILTIN_TERM_SPEC: dict[str, TValue | TComposition] = {
    'name': TValue.WordString,
    'action': TListStrCollapsible,
    'address': TListStrCollapsible,
    'address-exclude': TListStrCollapsible,
    'restrict-address-family': TValue.WordString,
    'comment': TValue.AnyString,
    'counter': TValue.WordString,
    'expiration': TValue.YearMonthDay,
    'destination-address': TListStrCollapsible,
    'destination-exclude': TListStrCollapsible,
    'destination-port': TListStrCollapsible,
    'destination-prefix': TListStrCollapsible,
    'filter-term': TValue.WordString,
    'forwarding-class': TList(of=TValue.WordString),
    'forwarding-class-except': TList(of=TValue.WordString),
    'logging': TListStrCollapsible,
    'log-limit': TValue.LogLimit,
    'log-name': TValue.AnyString,
    'loss-priority': TValue.WordString,
    'option': TListStr,
    'owner': TValue.WordString,
    'policer': TValue.WordString,
    'port': TListStrCollapsible,
    'precedence': TList(of=TValue.Integer, collapsible=True),
    'protocol': TList(of=TUnion(of=[TValue.Integer, TValue.WordString]), collapsible=True),
    'protocol-except': TList(of=TUnion(of=[TValue.Integer, TValue.WordString]), collapsible=True),
    'qos': TValue.WordString,
    'pan-application': TListStrCollapsible,
    'routing-instance': TValue.WordString,
    'source-address': TListStrCollapsible,
    'source-exclude': TListStrCollapsible,
    'source-port': TListStrCollapsible,
    'source-prefix': TListStrCollapsible,
    'ttl': TValue.Integer,
    'verbatim': TSection(of=[(TValue.WordString, TValue.AnyString)]),
    # juniper specific.
    # TODO(jb) these ranges (and DSCP ranges) might also be expressed as a mapping
    # with start: , end: keys - raise in design meet
    'packet-length': TUnion(of=[TValue.Integer, TValue.IntegerRange]),
    'fragment-offset': TUnion(of=[TValue.Integer, TValue.IntegerRange]),
    'hop-limit': TUnion(of=[TValue.Integer, TValue.IntegerRange]),
    'icmp-type': TListStrCollapsible,
    'icmp-code': TList(of=TValue.Integer, collapsible=True),
    'ether-type': TListStrCollapsible,
    'traffic-class-count': TValue.WordString,
    'traffic-type': TListStrCollapsible,
    'dscp-set': TValue.DSCP,
    'dscp-match': TList(of=TUnion(of=[TValue.DSCP, TValue.DSCPRange]), collapsible=True),
    'dscp-except': TList(of=TUnion(of=[TValue.DSCP, TValue.DSCPRange]), collapsible=True),
    'next-ip': TValue.WordString,
    'flexible-match-range': TSection(
        of=[(TValue.WordString, TUnion(of=[TValue.Hex, TValue.Integer, TValue.WordString]))]
    ),
    'source-prefix-except': TListStrCollapsible,
    'destination-prefix-except': TListStrCollapsible,
    'encapsulate': TValue.WordString,
    'port-mirror': TValue.WordString,
    # srx specific
    'destination-zone': TListStrCollapsible,
    'source-zone': TListStrCollapsible,
    'vpn': TSection(of=[('name', TValue.WordString), ('policy', TValue.WordString)]),
    # gce specific
    'source-tag': TListStrCollapsible,
    'destination-tag': TListStrCollapsible,
    'priority': TValue.Integer,
    # iptables specific
    'source-interface': TValue.WordString,
    'destination-interface': TValue.WordString,
    'platform': TListStrCollapsible,
    'platform-exclude': TListStrCollapsible,
    'target-resources': TList(of=TValue.TargetResourceTuple),
    'target-service-accounts': TListStrCollapsible,
    'timeout': TValue.Integer,
    # 'stateless-reply': TValue.Str, <-- stateless-reply is not implemented in the open source parser
}


class BuiltinRecognizer:
    """BuiltinRecognizer recognizes built-in keywords, values, and options. It
    flags these as SecurityCritical where required."""

    @staticmethod
    def recognizeKeyword(context: RecognizerContext) -> RecognizerKeywordResult:
        securityCritical = False
        if context.term is not None:
            recognized = context.keyword in BUILTIN_TERM_SPEC
        elif context.header is not None:
            recognized = context.keyword in BUILTIN_HEADER_SPEC
        return RecognizerKeywordResult(recognized=recognized, securityCritical=securityCritical)

    @classmethod
    def recognizeKeywordValue(cls, context: RecognizerContext) -> RecognizerValueResult:
        if context.term is not None:
            return cls.recognizeTermKeywordValue(context)
        elif context.header is not None:
            return cls.recognizeHeaderKeywordValue(context)

    @staticmethod
    def recognizeTermKeywordValue(context: RecognizerContext) -> RecognizerValueResult:
        # The idea here is to do a full parse of every possible input and convert it to some KV
        # representation. Look out for invalid options, syntax, etc.
        #
        # Note that some of these representations are still up in the air. The Capirca representations
        # are pretty well defined (by code) but YAML/JSON provides an opportunity to use more structured
        # representations, e.g. a YAML list of strings instead of a space-separated list. YAML users
        # can even use ['a', 'b'] repr for single-line or &ref references for common blocks.
        #
        # Goal:
        # For each possible keyname, (1) assert the YAML structure, (2) extract values out of sub-representations into KV,
        # (3) assemble the model value, (4) make a determination about Security Critical.
        # Unrecognized values will be flagged with recognized=false

        try:
            tokenizer = BUILTIN_TERM_SPEC[context.keyword]
        except KeyError:
            return RecognizerValueResult(recognized=False)

        try:
            repr = tokenizer.recognize(context.value)
        except TypeError:
            return RecognizerValueResult(recognized=False)

        # Last-minute validations and normalization
        try:
            # Plain term objects should specify a comment as a single string,
            # potentially a multi-line string. The Policy model will represent
            # the comment as a list of lines, so we perform the transformation here.
            if context.keyword == "comment" and isinstance(repr, str):
                repr = repr.splitlines()

            elif context.keyword == "flexible-match-range":
                new_repr = {}
                for key, value in repr.items():
                    if key not in BUILTIN_FLEXIBLE_MATCH_RANGE_ATTRIBUTES:
                        raise TypeError(f"Flexible match range: {key} is not a valid attribute")
                    if key == "match-start":
                        if value not in BUILTIN_FLEXIBLE_MATCH_START_OPTIONS:
                            raise TypeError(f"Flexible match range: {key} value is not valid")
                    # per Juniper, max bit length is 32
                    elif key == "bit-length":
                        if int(value) not in list(range(33)):
                            raise TypeError(f"Flexible match range: {key} value is not valid")
                    # per Juniper, max bit offset is 7
                    elif key == "bit-offset":
                        if int(value) not in list(range(8)):
                            raise TypeError(f"Flexible match range: {key} value is not valid")
                    # per Juniper, offset can be up to 256 bytes
                    elif key == "byte-offset":
                        if int(value) not in list(range(256)):
                            raise TypeError(f"Flexible match range: {key} value is not valid")
                    # Policy model expects "range" in hex format, the rest as strings
                    new_repr[key] = str(value)
                repr = new_repr

            # Protocol lists, numeric ranges expect numeric protocols as strings
            # TODO(jb) possibly another enum driven normalization
            elif context.keyword in ("protocol", "protocol-except"):
                repr = [str(value) for value in repr]

            elif context.keyword in ("hop-limit", "packet-length", "fragment-offset"):
                repr = str(repr)

            elif context.keyword == "vpn":
                if 'name' not in repr:
                    raise TypeError("VPN: keyword 'name' is mising.")
        except TypeError:
            return RecognizerValueResult(recognized=False)

        # We have recognized the keyword, asserted the representation matches the tokenizer
        # and assembed a native object representation.
        return RecognizerValueResult(recognized=True, valueKV={context.keyword: repr})

    @staticmethod
    def recognizeHeaderKeywordValue(context: RecognizerContext) -> RecognizerValueResult:
        try:
            tokenizer = BUILTIN_HEADER_SPEC[context.keyword]
        except KeyError:
            return RecognizerValueResult(recognized=False)

        try:
            repr = tokenizer.recognize(context.value)
        except TypeError:
            return RecognizerValueResult(recognized=False)

        # Plain term objects should specify a comment as a single string,
        # potentially a multi-line string. The Policy model will represent
        # the comment as a list of lines, so we perform the transformation here.
        if context.keyword == "comment" and isinstance(repr, str):
            repr = repr.splitlines()

        return RecognizerValueResult(recognized=True, valueKV={context.keyword: repr})
