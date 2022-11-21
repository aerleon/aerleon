from dataclasses import dataclass, field
import enum
import typing
from typing import Annotated

from absl import logging

from aerleon.lib.policy import (
    Policy,
    Header,
    Target,
    Term,
    VarType,
    BUILTIN_FLEXIBLE_MATCH_RANGE_ATTRIBUTES,
    BUILTIN_FLEXIBLE_MATCH_START_OPTIONS,
)
from aerleon.lib.recognizers import (
    RecognizerContext,
    RecognizerKeywordResult,
    RecognizerValueResult,
    TValue,
    TComposition,
    TList,
    TSection,
    TUnion,
    TListStr,
    TListStrCollapsible,
)

if typing.TYPE_CHECKING:
    from aerleon.lib import naming


RawTarget = Annotated[
    str,
    """
    RawTarget contains an partially evaluated representation of platform-specific target options.
    At the time of writing only a string can be provided for target options but that may change
    in the future.
    """,
]


@dataclass
class RawFilterHeader:
    """
    RawFilterHeader contains an partially evaluated representation
    of the "header" section within a Filter.

    Fields:
    - targets: table mapping targets to target options.
    - kvs: table containing any other key/value pairs in the header.
    """

    targets: dict[str, RawTarget]
    kvs: dict[str, typing.Any] = field(default_factory=dict)


@dataclass
class RawTerm:
    """
    RawTerm contains an partially evaluated representation
    of a Term item within a Filter.

    Fields:
    - name: name for this term.
    - kvs: table containing all other key/value pairs in the term.
    """

    name: str
    kvs: dict[str, typing.Any] = field(default_factory=dict)


@dataclass
class RawFilter:
    """
    RawFilter contains an partially evaluated representation
    of a Filter.

    Fields:
    - header: header for this filter.
    - terms: term list for this filter.
    """

    header: RawFilterHeader
    terms: list[RawTerm]


@dataclass
class RawPolicy:
    """
    RawPolicy contains an partially evaluated representation
    of a Policy.

    Fields:
    - filename: filename for this policy.
    - filters: list of filters in this policy.
    """

    filename: str
    filters: list[RawFilter]


class PolicyBuilder:
    """
    PolicyBuilder produces a Policy model from a RawPolicy. This allows a Policy
    model to be constructed without having or creating a .pol file.

    PolicyBuilder works by constructing Term, Header, Target, and Policy models
    directly. These models expect to be constructed incrementally by ply during
    ply's parsing procedure using methods like Term.AddObject(), Header.AddObject()
    and Policy.AddFilter(). PolicyBuilder walks through the given RawPolicy
    and incrementally constructs the models using the same API.

    PolicyBuilder is responsible for recognizing the keys and values in the
    given RawPolicy. Unexpected keywords or unexpected value formats are ignored
    with a warning. The recognizer process also parses information from values.

    PolicyBuilder is responsible for normalizing values across equivalent inputs.
    A .pol file is essentially composed of strings, but RawPolicy is a
    structure of Python native objects, where date values might be represented
    as a Python date and numeric values might be represented as numbers.

    PolicyBuilder also carries configuration forward to the Policy model. The
    Policy model may optionally perform optimization or shade checking during
    model construction. This behavior is configured through module-global
    variables within policy.py. policy.FromBuilder() will read this configuration
    off the PolicyBuilder and pass it through the module-global channel.

    Usage:

    policy_builder = PolicyBuilder(raw_policy, definitions, optimize, shade_check)
    return policy.FromBuilder(policy_builder)
    """

    raw_policy: RawPolicy
    definitions: "naming.Naming"
    optimize: bool
    shade_check: bool

    def __init__(self, raw_policy, definitions, optimize=False, shade_check=False):
        self.raw_policy = raw_policy
        self.definitions = definitions
        self.optimize = optimize
        self.shade_check = shade_check

    def buildPolicy(self):
        """Build a Policy model from a RawPolicy.

        Do not call this method directly. See "Usage" in the class docstring.
        """

        # Process each raw filter into a filter model instance and attach to the policy
        # return models.Policy(filename=policy.filename, filters=filter_models)
        policy_model = None
        obj_calls = [self._buildFilter(policy_filter) for policy_filter in self.raw_policy.filters]
        for obj in obj_calls:
            if policy_model is None:
                policy_model = Policy(*obj)
            else:
                policy_model.AddFilter(*obj)
        policy_model.filename = self.raw_policy.filename
        return policy_model

    def _buildFilter(self, policy_filter: RawFilter):

        kvs_parsed = {}
        header_kvs = policy_filter.header.kvs
        header_kvs["targets"] = policy_filter.header.targets

        for keyword, value in header_kvs.items():
            recognizer_context = RecognizerContext(
                policy=None,
                filter=policy_filter,
                header=policy_filter.header,
                target=None,
                term=None,
                keyword=keyword,
                value=value,
            )
            kw_recognizer_result = HeaderBuiltinRecognizer.recognizeKeyword(recognizer_context)
            if not kw_recognizer_result.recognized:
                logging.warning(f"Unexpected term keyword {keyword}")
                continue
            val_recognizer_result = HeaderBuiltinRecognizer.recognizeKeywordValue(
                recognizer_context
            )
            if not val_recognizer_result.recognized:
                logging.warning(f"Unrecognized value format for {keyword}: {value}")
                continue
            for repr_key, repr_value in val_recognizer_result.valueKV.items():
                kvs_parsed[repr_key] = repr_value

        header = Header()
        for target, target_options in kvs_parsed["targets"].items():
            target_args = [target]
            target_args.extend(target_options)
            target = Target(target_args)
            header.AddObject(target)

        for keyword, value in kvs_parsed.items():
            if keyword == 'targets':
                continue

            obj_calls = _Builtin.fromKeyword(keyword).addObjectCallSequence(value)
            for obj in obj_calls:
                header.AddObject(obj)

        return (header, [self._buildTerm(term) for term in policy_filter.terms])

    def _buildTerm(self, term: RawTerm):

        # It is an error for a term to be empty or
        # to only contain a name.
        if term.name is None:
            raise TypeError("Term must have a name.")

        if not len(term.kvs):
            raise TypeError("Term must have at least one keyword.")

        # Validate name
        term_name_recognizer_result = TermBuiltinRecognizer.recognizeKeywordValue(
            RecognizerContext(
                policy=None,
                filter=None,
                header=None,
                target=None,
                term=term,
                keyword='name',
                value=term.name,
            )
        )
        if not term_name_recognizer_result.recognized:
            raise TypeError("Invalid term name.")

        # Run recognizers over all term items.
        kvs_parsed = {}
        for keyword, value in term.kvs.items():
            recognizer_context = RecognizerContext(
                policy=None,
                filter=None,
                header=None,
                target=None,
                term=term,
                keyword=keyword,
                value=value,
            )
            kw_recognizer_result = TermBuiltinRecognizer.recognizeKeyword(recognizer_context)
            if not kw_recognizer_result.recognized:
                logging.warning(f"Unexpected term keyword {keyword}")
                continue
            val_recognizer_result = TermBuiltinRecognizer.recognizeKeywordValue(recognizer_context)
            if not val_recognizer_result.recognized:
                logging.warning(f"Unrecognized value format for {keyword}: {value}")
                continue
            for repr_key, repr_value in val_recognizer_result.valueKV.items():
                kvs_parsed[repr_key] = repr_value

        term.kvs = kvs_parsed

        # _buildTermModel() constructs a Term model. This is not especially
        # straightforward.
        #
        # This method expects its input RawTerm to already have been normalized
        # and parsed by recognizers.
        #
        # policy.Term() will crash if initialized without a VarType object.
        # This method will initialize the Term on the first iteration cycle over
        # the kvs and call AddObject on subsequent passes.
        #
        # Constructing VarType objects: AddObject has unique expectations
        # of structure per keyword. Common patterns dominate the list of keywords
        # but a handful of special cases exist. The common representations are:
        # 1. Single value: can only be set once per Term.
        # 2. List of values: a whole list can be given and can be set
        #    more than once per Term.
        # 3. Single value given multiple times: only a single value can be
        #    given but can be set more than once per Term.
        #
        # The special cases are:
        # * LOG_LIMIT is expected as a 2-tuple.
        # * EXPIRATION is expected as a date.
        # * FLEXIBLE_MATCH_RANGE is expected as list of length 2.
        # * VERBATIM is expected as a list of length 2.
        # * VPN is expected as a list of length 2.
        #   An empty string must be in the second slot if only one
        #   VPN value is given.
        # * Integer ranges are expected as a string like "2 - 100".
        # * DSCP ranges are expected as a string like "b000001-b001000"

        # TODO(jb) the comments above would be better in the Builtin enum docstring

        term_model = None  # Will initialize on first cycle

        for keyword, value in term.kvs.items():
            if keyword == 'name':
                continue

            obj_calls = _Builtin.fromKeyword(keyword).addObjectCallSequence(value)

            for obj in obj_calls:
                if term_model is None:
                    term_model = Term(obj)
                else:
                    term_model.AddObject(obj)
        term_model.name = term.name
        return term_model


# ### BUILTINS ###
# The following section deals with the recognition of built-in keywords and values

BUILTIN_SPEC: dict[str, TValue | TComposition] = {
# fmt: off
    'apply-groups':               TListStrCollapsible,
    'apply-groups-except':        TListStrCollapsible,
    'comment':                    TValue.AnyString,
    'targets':                    TSection(of=[(TValue.WordString, TListStrCollapsible)]),
    'name':                       TValue.WordString,
    'action':                     TListStrCollapsible,
    'address':                    TListStrCollapsible,
    'address-exclude':            TListStrCollapsible,
    'restrict-address-family':    TValue.WordString,
    'counter':                    TValue.WordString,
    'expiration':                 TValue.YearMonthDay,
    'destination-address':        TListStrCollapsible,
    'destination-exclude':        TListStrCollapsible,
    'destination-port':           TListStrCollapsible,
    'destination-prefix':         TListStrCollapsible,
    'filter-term':                TValue.WordString,
    'forwarding-class':           TList(of=TValue.WordString),
    'forwarding-class-except':    TList(of=TValue.WordString),
    'logging':                    TListStrCollapsible,
    'log-limit':                  TValue.LogLimit,
    'log-name':                   TValue.AnyString,
    'loss-priority':              TValue.WordString,
    'option':                     TListStr,
    'owner':                      TValue.WordString,
    'policer':                    TValue.WordString,
    'port':                       TListStrCollapsible,
    'precedence':                 TList(of=TValue.Integer, collapsible=True),
    'protocol':                   TList(of=TUnion(of=[TValue.Integer, TValue.WordString]), collapsible=True),
    'protocol-except':            TList(of=TUnion(of=[TValue.Integer, TValue.WordString]), collapsible=True),
    'qos':                        TValue.WordString,
    'pan-application':            TListStrCollapsible,
    'routing-instance':           TValue.WordString,
    'source-address':             TListStrCollapsible,
    'source-exclude':             TListStrCollapsible,
    'source-port':                TListStrCollapsible,
    'source-prefix':              TListStrCollapsible,
    'ttl':                        TValue.Integer,
    'verbatim':                   TSection(of=[(TValue.WordString, TValue.AnyString)]),
    # juniper specific.           
    'packet-length':              TUnion(of=[TValue.Integer, TValue.IntegerRange]),
    'fragment-offset':            TUnion(of=[TValue.Integer, TValue.IntegerRange]),
    'hop-limit':                  TUnion(of=[TValue.Integer, TValue.IntegerRange]),
    'icmp-type':                  TListStrCollapsible,
    'icmp-code':                  TList(of=TValue.Integer, collapsible=True),
    'ether-type':                 TListStrCollapsible,
    'traffic-class-count':        TValue.WordString,
    'traffic-type':               TListStrCollapsible,
    'dscp-set':                   TValue.DSCP,
    'dscp-match':                 TList(of=TUnion(of=[TValue.DSCP, TValue.DSCPRange]), collapsible=True),
    'dscp-except':                TList(of=TUnion(of=[TValue.DSCP, TValue.DSCPRange]), collapsible=True),
    'next-ip':                    TValue.WordString,
    'flexible-match-range':       TSection(of=[(TValue.WordString, TUnion(of=[TValue.Hex, TValue.Integer, TValue.WordString]))]),
    'source-prefix-except':       TListStrCollapsible,
    'destination-prefix-except':  TListStrCollapsible,
    'encapsulate':                TValue.WordString,
    'port-mirror':                TValue.WordString,
    # srx specific                
    'destination-zone':           TListStrCollapsible,
    'source-zone':                TListStrCollapsible,
    'vpn':                        TSection(of=[('name', TValue.WordString), ('policy', TValue.WordString)]),
    # gce specific                
    'source-tag':                 TListStrCollapsible,
    'destination-tag':            TListStrCollapsible,
    'priority':                   TValue.Integer,
    # iptables specific           
    'source-interface':           TValue.WordString,
    'destination-interface':      TValue.WordString,
    'platform':                   TListStrCollapsible,
    'platform-exclude':           TListStrCollapsible,
    'target-resources':           TList(of=TValue.TargetResourceTuple),
    'target-service-accounts':    TListStrCollapsible,
    'timeout':                    TValue.Integer,
# fmt: on
}


class _CallType(enum.Enum):
    """_CallType enumerates the calling conventions used by Term.AddObject()
    and Header.AddObject() in policy.py.

    Term.AddObject() is an unusual and complex function that adapts the ply
    parser to the Policy data model. It is the only method of attaching data
    to a Term model instance. Specifically it mirrors the numerous grammar rule
    function implementations (roughly one grammar rule is defined for each
    VarType type).

    Term.AddObject() accepts a single parameter, obj, containing either a single
    VarType object or a list of VarType objects. The semantics of how values
    are represented within 'obj' vary by the type of the VarType object. These
    semantics broadly fall into three cases, enumerated by this class.

    Attributes:
      SingleValue: AddObject should only be called zero or one times for this
        VarType type. 'obj' should contain a single VarType instance.
      SingleList: AddObject should only be called zero or one times for this
        VarType type. 'obj' should contain a list of VarType instances.
      MultiCall: AddObject should be called once per value. 'obj' should contain
        a single VarType instance.

    N.b. A few VarType types expect the VarType object value to be a list.
    This pattern is used to represent tuple-like values. It does not affect the
    AddObject call convention.
    """

    SingleValue = enum.auto()
    SingleList = enum.auto()
    MultiCall = enum.auto()


class _Builtin:
    """_Builtin represents all possible built-in key-value pairs found
    in Policy Term and Header sections.

    These mirror the attributes of the Term and Header models.
    """

    # fmt: off
    BUILTINS = {
        # KEYNAME:                    (CALL_CONVENTION,        VAR_TYPE)
        'name':                       (None,                   None),
        'targets':                    (None,                   None),
        'next-ip':                    (_CallType.SingleValue,  VarType.NEXT_IP),
        'restrict-address-family':    (_CallType.SingleValue,  VarType.RESTRICT_ADDRESS_FAMILY),
        'owner':                      (_CallType.SingleValue,  VarType.OWNER),
        'expiration':                 (_CallType.SingleValue,  VarType.EXPIRATION),
        'loss-priority':              (_CallType.SingleValue,  VarType.LOSS_PRIORITY),
        'routing-instance':           (_CallType.SingleValue,  VarType.ROUTING_INSTANCE),
        'precedence':                 (_CallType.SingleValue,  VarType.PRECEDENCE),
        'counter':                    (_CallType.SingleValue,  VarType.COUNTER),
        'encapsulate':                (_CallType.SingleValue,  VarType.ENCAPSULATE),
        'port-mirror':                (_CallType.SingleValue,  VarType.PORT_MIRROR),
        'traffic-class-count':        (_CallType.SingleValue,  VarType.TRAFFIC_CLASS_COUNT),
        'icmp-type':                  (_CallType.SingleValue,  VarType.ICMP_TYPE),
        'icmp-code':                  (_CallType.SingleValue,  VarType.ICMP_CODE),
        'log-name':                   (_CallType.SingleValue,  VarType.LOG_NAME),
        'log-limit':                  (_CallType.SingleValue,  VarType.LOG_LIMIT),
        'policer':                    (_CallType.SingleValue,  VarType.POLICER),
        'priority':                   (_CallType.SingleValue,  VarType.PRIORITY),
        'qos':                        (_CallType.SingleValue,  VarType.QOS),
        'packet-length':              (_CallType.SingleValue,  VarType.PACKET_LEN),
        'fragment-offset':            (_CallType.SingleValue,  VarType.FRAGMENT_OFFSET),
        'hop-limit':                  (_CallType.SingleValue,  VarType.HOP_LIMIT),
        'source-interface':           (_CallType.SingleValue,  VarType.SINTERFACE),
        'destination-interface':      (_CallType.SingleValue,  VarType.DINTERFACE),
        'timeout':                    (_CallType.SingleValue,  VarType.TIMEOUT),
        'dscp-set':                   (_CallType.SingleValue,  VarType.DSCP_SET),
        'ttl':                        (_CallType.SingleValue,  VarType.TTL),
        'filter-term':                (_CallType.SingleValue,  VarType.FILTER_TERM),
        'vpn':                        (_CallType.SingleValue,  VarType.VPN),
        'source-address':             (_CallType.SingleList,   VarType.SADDRESS),
        'destination-address':        (_CallType.SingleList,   VarType.DADDRESS),
        'address':                    (_CallType.SingleList,   VarType.ADDRESS),
        'source-exclude':             (_CallType.SingleList,   VarType.SADDREXCLUDE),
        'destination-exclude':        (_CallType.SingleList,   VarType.DADDREXCLUDE),
        'address-exclude':            (_CallType.SingleList,   VarType.ADDREXCLUDE),
        'port':                       (_CallType.SingleList,   VarType.PORT),
        'source-port':                (_CallType.SingleList,   VarType.SPORT),
        'destination-port':           (_CallType.SingleList,   VarType.DPORT),
        'protocol':                   (_CallType.SingleList,   VarType.PROTOCOL),
        'protocol-except':            (_CallType.SingleList,   VarType.PROTOCOL_EXCEPT),
        'option':                     (_CallType.SingleList,   VarType.OPTION),
        'source-prefix':              (_CallType.SingleList,   VarType.SPFX),
        'source-prefix-except':       (_CallType.SingleList,   VarType.ESPFX),
        'destination-prefix':         (_CallType.SingleList,   VarType.DPFX),
        'destination-prefix-except':  (_CallType.SingleList,   VarType.EDPFX),
        'ether-type':                 (_CallType.SingleList,   VarType.ETHER_TYPE),
        'traffic-type':               (_CallType.SingleList,   VarType.TRAFFIC_TYPE),
        'forwarding-class':           (_CallType.SingleList,   VarType.FORWARDING_CLASS),
        'forwarding-class-except':    (_CallType.SingleList,   VarType.FORWARDING_CLASS_EXCEPT),
        'pan-application':            (_CallType.SingleList,   VarType.PAN_APPLICATION),
        'platform':                   (_CallType.SingleList,   VarType.PLATFORM),
        'platform-exclude':           (_CallType.SingleList,   VarType.PLATFORMEXCLUDE),
        'source-tag':                 (_CallType.SingleList,   VarType.STAG),
        'destination-tag':            (_CallType.SingleList,   VarType.DTAG),
        'target-resources':           (_CallType.SingleList,   VarType.TARGET_RESOURCES),
        'target-service-accounts':    (_CallType.SingleList,   VarType.TARGET_SERVICE_ACCOUNTS),
        'source-zone':                (_CallType.SingleList,   VarType.SZONE),
        'destination-zone':           (_CallType.SingleList,   VarType.DZONE),
        'apply-groups':               (_CallType.SingleList,   VarType.APPLY_GROUPS),
        'apply-groups-except':        (_CallType.SingleList,   VarType.APPLY_GROUPS_EXCEPT),
        'dscp-match':                 (_CallType.SingleList,   VarType.DSCP_MATCH),
        'dscp-except':                (_CallType.SingleList,   VarType.DSCP_EXCEPT),
        'flexible-match-range':       (_CallType.SingleList,   VarType.FLEXIBLE_MATCH_RANGE),
        'action':                     (_CallType.MultiCall,    VarType.ACTION),
        'comment':                    (_CallType.MultiCall,    VarType.COMMENT),
        'logging':                    (_CallType.MultiCall,    VarType.LOGGING),
        'verbatim':                   (_CallType.MultiCall,    VarType.VERBATIM),
    }
    # fmt: on

    def __init__(self, keyname, call_convention, var_type):
        self.keyname = keyname
        self.call_convention = call_convention
        self.var_type = var_type

    @classmethod
    def fromKeyword(cls, keyname):
        """Construct a Builtin instance from keyname.

        Args:
            keyname (string): Builtin keyname.

        Returns:
            A Builtin instance.

        Raises:
            KeyError if no builtin data is registered for argument keyname.
        """
        return cls(keyname, *cls.BUILTINS[keyname])

    @property
    def recognizer(self):
        return BUILTIN_SPEC[self.keyname]

    def addObjectCallSequence(self, value: typing.Any):
        """Construct a calling sequence for Term.AddObject or Header.AddObject for
        this builtin type.

        Args:
            value (Any): Variable value.

        Returns:
            A list where each item contains the args list for a single call
            to AddObject.
        """
        if self.call_convention == _CallType.SingleValue:
            return [VarType(self.var_type, value)]  # One call
        elif self.call_convention == _CallType.SingleList:
            return [[VarType(self.var_type, item) for item in value]]  # One call
        elif self.call_convention == _CallType.MultiCall:
            return [VarType(self.var_type, item) for item in value]  # One call per item


class BuiltinRecognizer:
    """BuiltinRecognizer recognizes built-in keywords, values, and options. It
    flags these as SecurityCritical where required."""

    ALLOWED_BUILTIN_KEYS = ()

    @classmethod
    def recognizeKeyword(cls, context: RecognizerContext) -> RecognizerKeywordResult:
        securityCritical = False
        recognized = context.keyword in cls.ALLOWED_BUILTIN_KEYS
        return RecognizerKeywordResult(recognized=recognized, securityCritical=securityCritical)

    @classmethod
    def recognizeKeywordValue(cls, context: RecognizerContext) -> RecognizerValueResult:
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
            recognizer = _Builtin.fromKeyword(context.keyword).recognizer
            repr = recognizer.recognize(context.value)
        except KeyError:
            return RecognizerValueResult(recognized=False)
        except TypeError:
            return RecognizerValueResult(recognized=False)

        # Last-minute validations and normalization
        try:
            if context.keyword == "comment" and isinstance(repr, str):
                # Plain term objects should specify a comment as a single string,
                # potentially a multi-line string. The Policy model will represent
                # the comment as a list of lines, so we perform the transformation here.
                repr = repr.splitlines()
            elif context.keyword == 'verbatim':
                # Verbatim tables must be presented as a list of 2-tuples.
                repr = repr.items()
            elif recognizer == TValue.Integer:
                # All builtins that accept a single integer must pass that integer as a string
                # into the model.
                repr = str(repr)
            elif recognizer == TUnion(of=[TValue.Integer, TValue.IntegerRange]):
                # All builtins that accept an integer/integer range must pass a string
                # into the model.
                repr = str(repr)
            elif context.keyword in ("protocol", "protocol-except"):
                # Builtins that accept a list of words or integers must represent any integers
                # as strings in the mode.
                repr = [str(value) for value in repr]

            # Allow for additional section-specific normalizations
            repr = cls.normalizeValues(context, repr)
        except TypeError:
            return RecognizerValueResult(recognized=False)

        # We have recognized the keyword, asserted the representation matches the tokenizer
        # and assembed a native object representation.
        return RecognizerValueResult(recognized=True, valueKV={context.keyword: repr})

    @classmethod
    def normalizeValues(cls, _context: RecognizerContext, repr: typing.Any) -> typing.Any:
        return repr


class HeaderBuiltinRecognizer(BuiltinRecognizer):
    ALLOWED_BUILTIN_KEYS = frozenset(
        {
            'apply-groups',
            'apply-groups-except',
            'comment',
            'targets',
        }
    )


class TermBuiltinRecognizer(BuiltinRecognizer):
    ALLOWED_BUILTIN_KEYS = frozenset(
        {
            'name',
            'action',
            'address',
            'address-exclude',
            'restrict-address-family',
            'comment',
            'counter',
            'expiration',
            'destination-address',
            'destination-exclude',
            'destination-port',
            'destination-prefix',
            'filter-term',
            'forwarding-class',
            'forwarding-class-except',
            'logging',
            'log-limit',
            'log-name',
            'loss-priority',
            'option',
            'owner',
            'policer',
            'port',
            'precedence',
            'protocol',
            'protocol-except',
            'qos',
            'pan-application',
            'routing-instance',
            'source-address',
            'source-exclude',
            'source-port',
            'source-prefix',
            'ttl',
            'verbatim',
            'packet-length',
            'fragment-offset',
            'hop-limit',
            'icmp-type',
            'icmp-code',
            'ether-type',
            'traffic-class-count',
            'traffic-type',
            'dscp-set',
            'dscp-match',
            'dscp-except',
            'next-ip',
            'flexible-match-range',
            'source-prefix-except',
            'destination-prefix-except',
            'encapsulate',
            'port-mirror',
            'destination-zone',
            'source-zone',
            'vpn',
            'source-tag',
            'destination-tag',
            'priority',
            'source-interface',
            'destination-interface',
            'platform',
            'platform-exclude',
            'target-resources',
            'target-service-accounts',
            'timeout',
        }
    )

    @classmethod
    def normalizeValues(cls, context: RecognizerContext, repr):
        if context.keyword == "flexible-match-range":
            # Flexible match range values are validated during the lex/yacc parsing phase.
            # TODO(jb) This validation step can be performed once within the Term model in the
            # SanityCheck step and removed from both the lex/yacc code and this builder code.
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
                # Policy model expects all values as strings
                new_repr[key] = str(value)
            # Policy model expects each kv represented as a length-2 tuple
            repr = new_repr.items()

        elif context.keyword == "vpn":
            if 'name' not in repr:
                raise TypeError("VPN: keyword 'name' is mising.")
            # Policy model expects each kv represented as a length-2 tuple.
            # The policy name field should be given as an empty string if not provided
            # by the user.
            repr = (repr['name'], repr.get('policy', ''))

        return repr