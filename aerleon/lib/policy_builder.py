from dataclasses import dataclass, field
import typing
from typing import Annotated

from absl import logging

from aerleon.lib.policy import Policy, Header, Target, Term, VarType
from aerleon.lib.recognizers import (
    BuiltinRecognizer,
    RecognizerContext,
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
            kw_recognizer_result = BuiltinRecognizer.recognizeKeyword(recognizer_context)
            if not kw_recognizer_result.recognized:
                logging.warning(f"Unexpected term keyword {keyword}")
                continue
            val_recognizer_result = BuiltinRecognizer.recognizeKeywordValue(recognizer_context)
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
            if keyword == 'comment':
                obj_calls = [VarType(VarType.COMMENT, line) for line in value]
            elif keyword == 'apply-groups':
                obj_calls = [[VarType(VarType.APPLY_GROUPS, group) for group in value]]
            elif keyword == 'apply-groups-except':
                obj_calls = [[VarType(VarType.APPLY_GROUPS_EXCEPT, group) for group in value]]
            else:
                continue
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
        term_name_recognizer_result = BuiltinRecognizer.recognizeKeywordValue(
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
            kw_recognizer_result = BuiltinRecognizer.recognizeKeyword(recognizer_context)
            if not kw_recognizer_result.recognized:
                logging.warning(f"Unexpected term keyword {keyword}")
                continue
            val_recognizer_result = BuiltinRecognizer.recognizeKeywordValue(recognizer_context)
            if not val_recognizer_result.recognized:
                logging.warning(f"Unrecognized value format for {keyword}: {value}")
                continue
            for repr_key, repr_value in val_recognizer_result.valueKV.items():
                kvs_parsed[repr_key] = repr_value

        term.kvs = kvs_parsed

        return self._buildTermModel(term)

    # TODO(jb) Migrate this into policy.py as Term.fromPlainObject(term)
    # TODO(jb) Also re-write to be enum-driven where each keyword links to a vartype and a calling convention

    def _buildTermModel(self, term: RawTerm):
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

        # List of common patterns.
        TERM_SINGLE_VALUES_VAR_TYPES = {
            'next-ip': VarType.NEXT_IP,
            'restrict-address-family': VarType.RESTRICT_ADDRESS_FAMILY,
            'owner': VarType.OWNER,
            'expiration': VarType.EXPIRATION,
            'loss-priority': VarType.LOSS_PRIORITY,
            'routing-instance': VarType.ROUTING_INSTANCE,
            'precedence': VarType.PRECEDENCE,
            'counter': VarType.COUNTER,
            'encapsulate': VarType.ENCAPSULATE,
            'port-mirror': VarType.PORT_MIRROR,
            'traffic-class-count': VarType.TRAFFIC_CLASS_COUNT,
            'icmp-type': VarType.ICMP_TYPE,
            'icmp-code': VarType.ICMP_CODE,
            'log-name': VarType.LOG_NAME,
            'policer': VarType.POLICER,
            'priority': VarType.PRIORITY,
            'qos': VarType.QOS,
            'source-interface': VarType.SINTERFACE,
            'destination-interface': VarType.DINTERFACE,
            'timeout': VarType.TIMEOUT,
            'dscp-set': VarType.DSCP_SET,
            'ttl': VarType.TTL,
            'filter-term': VarType.FILTER_TERM,
        }
        TERM_LIST_VALUES_VAR_TYPES = {
            'source-address': VarType.SADDRESS,
            'destination-address': VarType.DADDRESS,
            'address': VarType.ADDRESS,
            'source-exclude': VarType.SADDREXCLUDE,
            'destination-exclude': VarType.DADDREXCLUDE,
            'address-exclude': VarType.ADDREXCLUDE,
            'port': VarType.PORT,
            'source-port': VarType.SPORT,
            'destination-port': VarType.DPORT,
            'protocol': VarType.PROTOCOL,
            'protocol-except': VarType.PROTOCOL_EXCEPT,
            'option': VarType.OPTION,
            'source-prefix': VarType.SPFX,
            'source-prefix-except': VarType.ESPFX,
            'destination-prefix': VarType.DPFX,
            'destination-prefix-except': VarType.EDPFX,
            'ether-type': VarType.ETHER_TYPE,
            'traffic-type': VarType.TRAFFIC_TYPE,
            'precedence': VarType.PRECEDENCE,
            'forwarding-class': VarType.FORWARDING_CLASS,
            'forwarding-class-except': VarType.FORWARDING_CLASS_EXCEPT,
            'pan-application': VarType.PAN_APPLICATION,
            'platform': VarType.PLATFORM,
            'platform-exclude': VarType.PLATFORMEXCLUDE,
            'source-tag': VarType.STAG,
            'destination-tag': VarType.DTAG,
            'flexible-match-range': VarType.FLEXIBLE_MATCH_RANGE,
            'target-resources': VarType.TARGET_RESOURCES,
            'target-service-accounts': VarType.TARGET_SERVICE_ACCOUNTS,
            'source-zone': VarType.SZONE,
            'destination-zone': VarType.DZONE,
        }
        TERM_MULTI_VALUE_VAR_TYPES = {
            'action': VarType.ACTION,
            'comment': VarType.COMMENT,
            'logging': VarType.LOGGING,
            'target-resources': VarType.TARGET_RESOURCES,
            'target-service-accounts': VarType.TARGET_SERVICE_ACCOUNTS,
        }
        TERM_SINGLE_VALUE_INT_RANGE_VAR_TYPES = {
            'packet-length': VarType.PACKET_LEN,
            'fragment-offset': VarType.FRAGMENT_OFFSET,
            'hop-limit': VarType.HOP_LIMIT,
        }
        TERM_LIST_VALUES_DSCP_RANGE_VAR_TYPES = {
            'dscp-match': VarType.DSCP_MATCH,
            'dscp-except': VarType.DSCP_EXCEPT,
        }

        term_model = None  # Will initialize on first cycle

        for keyword, value in term.kvs.items():
            # Handle each common calling convention for AddObject.
            if keyword in TERM_SINGLE_VALUES_VAR_TYPES:
                # AddObject must be called exactly once.
                # The argument must be an instance of VarType.
                var_type = TERM_SINGLE_VALUES_VAR_TYPES[keyword]
                obj_calls = [VarType(var_type, value)]  # One call

            elif keyword in TERM_LIST_VALUES_VAR_TYPES:
                # AddObject may be called with a list of VarType objects.
                # It would be acceptible to call multiple times but
                # a single call is most efficent.
                var_type = TERM_LIST_VALUES_VAR_TYPES[keyword]
                obj_calls = [[VarType(var_type, item) for item in value]]  # One call

            elif keyword in TERM_MULTI_VALUE_VAR_TYPES:
                # AddObject must be called once per item.
                # The argument must be an instance of VarType.
                var_type = TERM_MULTI_VALUE_VAR_TYPES[keyword]
                obj_calls = [VarType(var_type, item) for item in value]  # One call per item

            elif keyword in TERM_SINGLE_VALUE_INT_RANGE_VAR_TYPES:
                # AddObject must be called exactly once.
                # The argument must be an instance of VarType.
                # The VarType value must be a string containing a single number
                # or a range expression like "1-40".
                var_type = TERM_SINGLE_VALUE_INT_RANGE_VAR_TYPES[keyword]
                if isinstance(value, dict):
                    value = f"{value['start']}-{value['end']}"
                obj_calls = [VarType(var_type, value)]  # One call

            elif keyword in TERM_LIST_VALUES_DSCP_RANGE_VAR_TYPES:
                # AddObject may be called with a list of VarType objects.
                # The VarType value, if it contains a DSCP range,
                var_type = TERM_LIST_VALUES_DSCP_RANGE_VAR_TYPES[keyword]
                obj_calls = [[VarType(var_type, item) for item in value]]  # One call

            elif keyword == 'log-limit':
                # AddObject must be called exactly once.
                # The VarType value must be a 2-tuple.
                value = (value['frequency'], value['period'])
                obj_calls = [VarType(VarType.LOG_LIMIT, value)]  # One call

            elif keyword == 'flexible-match-range':
                # AddObject may be called with a list of VarType objects.
                # The VarType value is expected as list of lists with
                # each inner list having length 2.
                value = value.items()
                obj_calls = [
                    [VarType(VarType.FLEXIBLE_MATCH_RANGE, item) for item in value]
                ]  # One call

            elif keyword == 'verbatim':
                # AddObject must be called once per item.
                # The VarType value is expected as list of lists with
                # each inner list having length 2.
                value = value.items()
                obj_calls = [
                    VarType(VarType.VERBATIM, item) for item in value
                ]  # One call per item

            elif keyword == 'vpn':
                # AddObject must be called exactly once.
                # The VarType value must be a list of length 2 or a 2-tuple
                # where the second slot is the empty string if a policy name is not given.
                value = (value['name'], value.get('policy', ''))
                obj_calls = [VarType(VarType.VPN, value)]  # One call

            for obj in obj_calls:
                if term_model is None:
                    term_model = Term(obj)
                else:
                    term_model.AddObject(obj)
        term_model.name = term.name
        return term_model
