"""Intermediate data models and classes for the front-end parsing phase.

Classes:

## RawPolicy, RawFilter, RawTerm, RawKV

These classes act as an intermediate representation between a raw file representation
and the main data models (Policy, Naming). They exist mainly to support the consultative
extension system (consulting the generators during the parse process through the hooks
RecognizeKeyword(), RecognizeKeywordValue()).

## ConsultativePolicyBuilder

This class executes the consultative parse process. It transforms RawPolicy into Policy
by consulting all loaded generators (through the hooks RecognizeKeyword(),
RecognizeKeywordValue()) to understand what keywords are considered valid and what options
are valid.
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

    Any = enum.auto()  # any value expression
    Str = enum.auto()  # \w+
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
            value = str(value)

        if value is None:
            value = ""

        if self == TValue.Any:
            if not isinstance(value, str):
                # TODO(jb) some kind of debug context is needed here
                raise TypeError("Expected string.")
            return value

        elif self == TValue.Str:
            if not isinstance(value, str):
                # TODO(jb) some kind of debug context is needed here
                raise TypeError("Expected string.")
            match = re.fullmatch(r'\w+([-_+.@/]\w*)*', value.strip())
            if match is None:
                raise TypeError("Expected value class 'String'.")
            return match[0]

        elif self == TValue.Integer:
            if isinstance(value, int):
                return str(value)
            if not isinstance(value, str):
                # TODO(jb) some kind of debug context is needed here
                raise TypeError("Expected integer or string.")
            match = re.fullmatch(r'\d+', value.strip())
            if match is None:
                raise TypeError("Expected value class 'Integer'.")
            return match[0]

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
            return {key: match[key] for key in ('start', 'end')}

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
            if not isinstance(value, str):
                raise TypeError("Expected string.")
            match = re.fullmatch(
                r'\b((b[0-1]{6})|(af[1-4]{1}[1-3]{1})|(be)|(ef)|(cs[0-7]{1}))(?![\w-])\b',
                value.strip(),
            )
            if match is None:
                raise TypeError("Expected value class 'DSCP'.")
            return match[0]

        elif self == TValue.DSCPRange:
            if not isinstance(value, str):
                raise TypeError("Expected string.")
            match = re.fullmatch(
                r'\b(?P<start>(b[0-1]{6})|(af[1-4]{1}[1-3]{1})|(be)|(ef)|(cs[0-7]{1}))([-]{1})(?P<end>(b[0-1]{6})|(af[1-4]{1}[1-3]{1})|(be)|(ef)|(cs[0-7]{1}))\b',
                value.strip(),
            )
            if match is None:
                raise TypeError("Expected value class 'DSCPRange'.")
            return match[0]
            # return {key: match[key] for key in ('start', 'end')}

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
            return (TValue.Str.recognize(first), TValue.Str.recognize(second))


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
                TValue.Any,
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
TListStr = TList(of=TValue.Str)
TListStrCollapsible = TList(of=TValue.Str, collapsible=True)

BUILTIN_HEADER_SPEC: dict[str, TValue | TComposition] = {
    'apply-groups': TListStrCollapsible,
    'apply-groups-except': TListStrCollapsible,
    'comment': TValue.Any,
    'targets': TSection(of=[(TValue.Str, TListStrCollapsible)]),
}
BUILTIN_TERM_SPEC: dict[str, TValue | TComposition] = {
    'name': TValue.Str,
    'action': TListStrCollapsible,
    'address': TListStrCollapsible,
    'address-exclude': TListStrCollapsible,
    'restrict-address-family': TValue.Str,
    'comment': TValue.Any,
    'counter': TValue.Str,
    'expiration': TValue.YearMonthDay,
    'destination-address': TListStrCollapsible,
    'destination-exclude': TListStrCollapsible,
    'destination-port': TListStrCollapsible,
    'destination-prefix': TListStrCollapsible,
    'filter-term': TValue.Str,
    'forwarding-class': TList(of=TValue.Str),
    'forwarding-class-except': TList(of=TValue.Str),
    'logging': TListStrCollapsible,
    'log-limit': TValue.LogLimit,
    'log-name': TValue.Any,
    'loss-priority': TValue.Str,
    'option': TListStr,
    'owner': TValue.Str,
    'policer': TValue.Str,
    'port': TListStrCollapsible,
    'precedence': TList(of=TValue.Integer),
    'protocol': TList(of=TUnion(of=[TValue.Integer, TValue.Str]), collapsible=True),
    'protocol-except': TList(of=TUnion(of=[TValue.Integer, TValue.Str]), collapsible=True),
    'qos': TValue.Str,
    'pan-application': TListStrCollapsible,
    'routing-instance': TValue.Str,
    'source-address': TListStrCollapsible,
    'source-exclude': TListStrCollapsible,
    'source-port': TListStrCollapsible,
    'source-prefix': TListStrCollapsible,
    'ttl': TValue.Integer,
    'verbatim': TSection(of=[(TValue.Str, TValue.Any)]),
    # juniper specific.
    # TODO(jb) these ranges (and DSCP ranges) might also be expressed as a mapping
    # with start: , end: keys - raise in design meet
    'packet-length': TUnion(of=[TValue.Integer, TValue.IntegerRange]),
    'fragment-offset': TUnion(of=[TValue.Integer, TValue.IntegerRange]),
    'hop-limit': TUnion(of=[TValue.Integer, TValue.IntegerRange]),
    'icmp-type': TListStrCollapsible,
    'icmp-code': TList(of=TValue.Integer, collapsible=True),
    'ether-type': TListStrCollapsible,
    'traffic-class-count': TValue.Str,
    'traffic-type': TListStrCollapsible,
    'dscp-set': TValue.DSCP,
    'dscp-match': TList(of=TUnion(of=[TValue.DSCP, TValue.DSCPRange]), collapsible=True),
    'dscp-except': TList(of=TUnion(of=[TValue.DSCP, TValue.DSCPRange]), collapsible=True),
    'next-ip': TValue.Str,
    'flexible-match-range': TSection(
        of=[(TValue.Str, TUnion(of=[TValue.Integer, TValue.Hex, TValue.Str]))]
    ),
    'source-prefix-except': TListStrCollapsible,
    'destination-prefix-except': TListStrCollapsible,
    'encapsulate': TValue.Str,
    'port-mirror': TValue.Str,
    # srx specific
    'destination-zone': TListStrCollapsible,
    'source-zone': TListStrCollapsible,
    'vpn': TSection(of=[('name', TValue.Str), ('policy', TValue.Str)]),
    # gce specific
    'source-tag': TListStrCollapsible,
    'destination-tag': TListStrCollapsible,
    'priority': TValue.Integer,
    # iptables specific
    'source-interface': TValue.Str,
    'destination-interface': TValue.Str,
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

        # Last-minute validations
        try:
            if context.keyword == "flexible-match-range":
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

            elif context.keyword == "vpn":
                # TODO(jb) this implies term.vpn.vpn ...
                if 'vpn' not in repr:
                    raise TypeError("VPN: key 'vpn' is mising.")
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
            return RecognizerValueResult(recognized=True, valueKV={context.keyword: repr})
        except TypeError:
            return RecognizerValueResult(recognized=False)
