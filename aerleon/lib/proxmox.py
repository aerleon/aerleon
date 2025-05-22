import math
from abc import ABCMeta, abstractmethod
from typing import Dict, List, MutableMapping, Self, Set, Tuple, Type, Union

from aerleon.lib import aclgenerator, policy
from aerleon.lib.nacaddr import ExcludeAddrs, IPv4, IPv6
from aerleon.lib.policy import PROTOS_WITH_PORTS, Policy


### error classes ###
class Error(aclgenerator.Error):
    pass


class UnsupportedFilterOptionError(Error):
    pass


class ZoneMismatchError(Error):
    pass


### helper classes ###
class ProxmoxConfigDataClass:
    def __init__(self, *args, **kwargs):
        self._store: Dict[str, Union[str, List[str]]] = dict()
        self._store.update(*args)
        self._store.update(**kwargs)
        self._store['enable'] = '1'

    def __getitem__(self, item):
        return self._store[item]

    def __setitem__(self, key, value):
        self._store[key] = value

    def __delitem__(self, key):
        del self._store[key]

    def __add__(self, other):
        return self.merge(other)

    def keys(self):
        return self._store.keys()

    def flatten(self, item):
        if isinstance(item, dict):
            return {k: self.flatten(v) for k, v in item.items()}
        elif isinstance(item, list) or isinstance(item, set):
            return ",".join([self.flatten(i) for i in item])
        elif not isinstance(item, str):
            return str(item)
        else:
            return item

    @staticmethod
    def _merge_list(list_a: list, list_b: list) -> list:
        return list(set(list_a + list_b))

    def merge(self, other: Self) -> Self:
        self_keys = list(self.keys())
        other_keys = list(other.keys())
        ret = dict()
        for k in self_keys + other_keys:
            if k in self_keys and k in other_keys:
                if isinstance(self[k], list) and isinstance(other[k], list):
                    ret[k] = self._merge_list(self[k], other[k])
                else:
                    ret[k] = other[k]
            elif k in self_keys:
                ret[k] = self[k]
            elif k in other_keys:
                ret[k] = other[k]
        self._store = ret
        return self

    def __str__(self):
        flattened_store = self.flatten(self._store)
        lines = []
        for k, v in flattened_store.items():
            lines.append(f'{k}: {v}')
        return "\n".join(lines)


class AbstractOption(metaclass=ABCMeta):
    def __init__(self, config: MutableMapping, *args, **kwargs):
        self.config_ref = config

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, self.getKey())

    @abstractmethod
    def ingest(self, token: str) -> bool:
        # should return true if token is ingested
        pass

    @abstractmethod
    def complete(self) -> bool:
        pass

    @abstractmethod
    def getKey(self) -> str:
        pass


class BooleanKeywordOption(AbstractOption):
    def __init__(self, key: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = key

    def getKey(self) -> str:
        return self.key

    def ingest(self, token: str) -> bool:
        got_token = False
        if token == self.key:
            self.config_ref[self.key] = "1"  # perl
            got_token = True
        return got_token

    def complete(self) -> bool:
        return True


class AbstractValueOption(AbstractOption, metaclass=ABCMeta):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key_ingested = False
        self.any_value_ingested = False

    @abstractmethod
    def tokenValidationTemplateMethod(self, token: str) -> bool:
        pass

    def configInsertTemplateMethod(self, token: str):
        self.config_ref[self.getKey()] = token

    def ingest(self, token: str) -> bool:
        got_token = False
        if token == self.getKey():
            self.key_ingested, got_token = True, True
        elif self.tokenValidationTemplateMethod(token) and self.key_ingested:
            self.any_value_ingested, got_token = True, True
            self.configInsertTemplateMethod(token)
        else:
            # reset so that we don't accept values after other tokens
            self.key_ingested, self.any_value_ingested = False, False
        return got_token

    def complete(self) -> bool:
        return (
            (self.key_ingested, self.any_value_ingested) == (False, False)
            or self.key_ingested
            and self.any_value_ingested
        )


class ValueOption(AbstractValueOption):
    def __init__(self, *args, **kwargs: List[str]):
        super().__init__(*args, **kwargs)
        self.key = list(kwargs.keys())[0]
        self.values = kwargs[self.key]

    def getKey(self) -> str:
        return self.key

    def tokenValidationTemplateMethod(self, token: str) -> bool:
        return token in self.values


class MultiValueOption(ValueOption):
    def configInsertTemplateMethod(self, token: str):
        if self.getKey() not in self.config_ref.keys():
            self.config_ref[self.getKey()] = []
        self.config_ref[self.getKey()].append(token)


class NumberValueOption(AbstractValueOption):
    def __init__(self, key: str, lower: float, upper: float, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = key
        self.lower = lower
        self.upper = upper

    def getKey(self) -> str:
        return self.key

    def tokenValidationTemplateMethod(self, token: str) -> bool:
        return token.isdecimal() and self.lower <= float(token) <= self.upper


class ProxmoxPort:
    @staticmethod
    def _singlePortFmt(port: int) -> str:
        return str(port)

    @staticmethod
    def _portTupleFmt(port: tuple) -> str:
        if port[0] == port[1]:
            return str(port[0])
        else:
            return '%d-%d' % port

    def __init__(self, port: Union[Tuple[int, int], int]):
        self.str_representation = ''
        if isinstance(port, int):
            self.str_representation = self._singlePortFmt(port)
        elif isinstance(port, tuple):
            self.str_representation = self._portTupleFmt(port)

    def __str__(self):
        return self.str_representation


class ProxmoxIcmp:
    # proxmox firewall only supports a subset of ICMP code/types
    ICMPv4_MAP = {
        None: {None: 'any'},
        'echo-reply': {None: 'echo-reply'},
        'unreachable': {
            None: 'destination-unreachable',
            0: 'network-unreachable',
            1: 'host-unreachable',
            2: 'protocol-unreachable',
            3: 'port-unreachable',
            4: 'fragmentation-needed',
            5: 'source-route-failed',
            6: 'network-unknown',
            7: 'host-unknown',
            9: 'network-prohibited',
            10: 'host-prohibited',
            11: 'TOS-network-unreachable',
            12: 'TOS-host-unreachable',
            13: 'communication-prohibited',
            14: 'host-precedence-violation',
            15: 'precedence-cutoff',
        },
        'source-quench': {None: 'source-quench'},
        'redirect': {
            None: 'redirect',
            0: 'network-redirect',
            1: 'host-redirect',
            2: 'TOS-network-redirect',
            3: 'TOS-host-redirect',
        },
        'echo-request': {None: 'echo-request'},
        'router-advertisement': {None: 'router-advertisement'},
        'router-solicitation': {None: 'router-solicitation'},
        'time-exceeded': {
            None: 'time-exceeded',
            0: 'ttl-zero-during-transit',
            1: 'ttl-zero-during-reassembly',
        },
        'parameter-problem': {
            None: 'parameter-problem',
            0: 'ip-header-bad',
            1: 'required-option-missing',
        },
        'timestamp-request': {None: 'timestamp-request'},
        'timestamp-reply': {None: 'timestamp-reply'},
        'mask-request': {None: 'address-mask-request'},
        'mask-reply': {None: 'address-mask-reply'},
    }
    ICMPv6_MAP = {
        None: {None: 'any'},
        'destination-unreachable': {
            None: 'destination-unreachable',
            0: 'no-route',
            1: 'communication-prohibited',
            2: 'beyond-scope',
            3: 'address-unreachable',
            4: 'port-unreachable',
            5: 'failed-policy',
            6: 'reject-route',
        },
        'packet-too-big': {None: 'packet-too-big'},
        'time-exceeded': {
            None: 'time-exceeded',
            0: 'ttl-zero-during-transit',
            1: 'ttl-zero-during-reassembly',
        },
        'parameter-problem': {
            None: 'parameter-problem',
            0: 'bad-header',
            1: 'unknown-header-type',
            2: 'unknown-option',
        },
        'echo-request': {None: 'echo-request'},
        'echo-reply': {None: 'echo-reply'},
        'router-solicit': {None: 'router-solicitation'},
        'router-advertisement': {None: 'router-advertisement'},
        'neighbor-solicit': {None: 'neighbour-solicitation'},
        'neighbor-advertisement': {None: 'neighbour-advertisement'},
        'redirect-message': {None: 'redirect'},
    }
    ICMP_MAP = {
        'icmp': ICMPv4_MAP,
        'icmpv6': ICMPv6_MAP,
        'icmp6': ICMPv6_MAP,
    }
    ICMP_PROTOS = ['icmp', 'icmp6', 'icmpv6']

    def __init__(
        self,
        icmp_proto: str,
        icmp_type: Union[str, None] = None,
        icmp_code: Union[int, None] = None,
    ):
        self.icmp_proto = icmp_proto
        self.type = icmp_type
        self.code = icmp_code

    def __str__(self):
        return self.ICMP_MAP[self.icmp_proto][self.type][self.code]


### implementation ###
class Term(aclgenerator.Term):
    """
    (internal) representation of an individual proxmox-firewall term
    takes generic Term for conversion to internal type as an argument
    direction is IN, OUT, FORWARD (regardless of zone type, zone
    constraints should be handled by the client class)
    """

    GOOD_DIRECTIONS = ['IN', 'OUT', 'FORWARD']
    ACTIONS_MAP = {
        'accept': 'ACCEPT',
        'deny': 'DROP',
        'reject': 'REJECT',
    }
    LOG_LEVELS_MAP_OPTIONS = {
        'log_nolog': 'nolog',
        'log_emergency': 'emerg',
        'log_alert': 'alert',
        'log_critical': 'crit',
        'log_error': 'err',
        'log_warning': 'warning',
        'log_notice': 'notice',
        'log_info': 'info',
        'log_debug': 'debug',
    }
    _LOG_LEVELS_MAP = LOG_LEVELS_MAP_OPTIONS | {
        'true': 'warning',
        'disable': 'nolog',
    }
    # Proxmox uses slightly different names for certain IP protocols
    # since it depends on Debian's netbase package for /etc/protocols
    # (other distributions use different /etc/protocols files)
    PROXMOX_PROTO_MAP = {
        'icmpv6': 'ipv6-icmp',
        'icmp6': 'ipv6-icmp',
        'ipip': 'ipencap',
        'fragment': 'ipv6-frag',
    }

    def __init__(self, term: policy.Term, direction: str):
        self.term = term
        self.direction = direction

    @staticmethod
    def has_mixed_af(addresses: List[Union[IPv4, IPv6]]):
        has_v4 = any(map(lambda a: isinstance(a, IPv4), addresses))
        has_v6 = any(map(lambda a: isinstance(a, IPv6), addresses))
        return has_v4 and has_v6

    @staticmethod
    def filter_for_af(af: Union[Type[IPv4], Type[IPv6]], addresses: List[Union[IPv4, IPv6]]):
        return list(filter(lambda a: isinstance(a, af), addresses))

    @staticmethod
    def _ComputeAddresses(addresses, exclude_addresses):
        addresses_with_exclude = addresses
        if exclude_addresses:
            addresses_with_exclude = ExcludeAddrs(addresses, exclude_addresses)
        return addresses_with_exclude

    def __str__(self) -> str:
        """returns the proxmox-firewall string representation of the term"""
        ret_str = []
        address_families = [IPv4, IPv6]
        all_addresses = self.term.source_address + self.term.destination_address
        if not self.has_mixed_af(all_addresses) and all_addresses:  # single-AF term
            address_families = [type(all_addresses[0])]
        elif not all_addresses:  # no source and no destination
            address_families = [IPv6]  # doesn't matter which one but there should be only one

        icmp_types = self.term.icmp_type if self.term.icmp_type else [None]
        icmp_codes = self.term.icmp_code if self.term.icmp_code else [None]
        term_protocol = self.term.protocol if self.term.protocol else [None]

        # proxmox firewall only supports one protocol per rule
        for protocol in term_protocol:
            # proxmox firewall does not support mixed AFs in filters
            for af in address_families:
                for icmp_type in icmp_types:
                    for icmp_code in icmp_codes:
                        source = self._ComputeAddresses(
                            self.filter_for_af(af, self.term.source_address),
                            self.term.source_address_exclude,
                        )
                        dest = self._ComputeAddresses(
                            self.filter_for_af(af, self.term.destination_address),
                            self.term.destination_address_exclude,
                        )
                        ret_str.append(
                            self._Format(
                                protocol,
                                self.direction,
                                self.ACTIONS_MAP[self.term.action[0]],
                                source,
                                dest,
                                icmp_code,
                                icmp_type,
                                self.term.source_interface,
                                self.term.source_port,
                                self.term.destination_port,
                                self.term.comment,
                                self.term.logging,
                                self.term.option,
                            )
                        )

        return '\n'.join(ret_str)

    def _Format(
        self,
        protocol: Union[str, None],
        direction: str,
        action: str,
        source_addresses: List[Union[IPv4, IPv6]],
        destination_addresses: List[Union[IPv4, IPv6]],
        icmp_code: Union[str, None],
        icmp_type: Union[str, None],
        source_interface: str,
        source_ports: List[Union[Tuple[int, int], int]],
        destination_ports: List[Union[Tuple[int, int], int]],
        comment: List[str],
        logging: List[str],
        term_options: List[str],
    ):
        def to_network_addr(i: Union[IPv6, IPv4]):
            return str(i.with_prefixlen)

        options = [direction, action]

        if protocol:
            options.append("-proto %s" % self.PROXMOX_PROTO_MAP.get(protocol, protocol))

        # proxmox firewall supports multiple sources/destinations per rule
        if source_interface:
            options.append("-iface %s" % source_interface)

        # we cannot use address tokens since IPsets are defined in separate files (at cluster
        # or at host level) and we're only outputting one file at a time, which may not be
        # cluster/host firewall configuration.
        if destination_addresses:
            options.append("-dest %s" % ','.join(map(to_network_addr, destination_addresses)))

        if source_addresses:
            options.append("-source %s" % ','.join(map(to_network_addr, source_addresses)))

        if source_ports and protocol in PROTOS_WITH_PORTS:
            options.append(
                "-sport %s" % ','.join(map(lambda p: str(ProxmoxPort(p)), source_ports))
            )

        if destination_ports and protocol in PROTOS_WITH_PORTS:
            options.append(
                "-dport %s" % ','.join(map(lambda p: str(ProxmoxPort(p)), destination_ports))
            )

        if protocol in ProxmoxIcmp.ICMP_PROTOS:
            options.append('-icmp-type %s' % str(ProxmoxIcmp(protocol, icmp_type, icmp_code)))

        if logging:
            logging_key = 'true'
            log_option = next(
                map(
                    lambda o: o if o in self._LOG_LEVELS_MAP.keys() else None,
                    term_options or [None],
                )
            )
            log = log_option or logging_key
            options.append('-log %s' % self._LOG_LEVELS_MAP[log])

        if comment:
            options.append("# %s" % ' '.join(comment))

        return ' '.join(options)


class Proxmox(aclgenerator.ACLGenerator):
    """Proxmox firewall policy object"""

    # aerleon class props
    _PLATFORM = 'proxmox'
    SUFFIX = '.prxmxfw'
    _TERM = Term
    _LOG_LEVELS = list(_TERM.LOG_LEVELS_MAP_OPTIONS.values())
    # own class props
    _NF_CONNTRACK_HELPERS = [
        "amanda",
        "ftp",
        "irc",
        "netbios-ns",
        "pptp",
        "sane",
        "sip",
        "snmp",
        "tftp",
    ]
    _BY_ZONE = {
        "cluster": {
            "supported_directions": _TERM.GOOD_DIRECTIONS,
            "supported_options": lambda config: [
                BooleanKeywordOption('enable', config),
                BooleanKeywordOption('ebtables', config),
                ValueOption(config, policy_forward=list(Proxmox._TERM.ACTIONS_MAP.values())),
                ValueOption(config, policy_in=list(Proxmox._TERM.ACTIONS_MAP.values())),
                ValueOption(config, policy_out=list(Proxmox._TERM.ACTIONS_MAP.values())),
            ],
        },
        "host": {
            "supported_directions": _TERM.GOOD_DIRECTIONS,
            "supported_options": lambda config: [
                BooleanKeywordOption('enable', config),
                ValueOption(config, log_level_forward=Proxmox._LOG_LEVELS),
                ValueOption(config, log_level_in=Proxmox._LOG_LEVELS),
                ValueOption(config, log_level_out=Proxmox._LOG_LEVELS),
                BooleanKeywordOption('log_nf_conntrack', config),
                BooleanKeywordOption('ndp', config),
                BooleanKeywordOption('nf_conntrack_allow_invalid', config),
                MultiValueOption(config, nf_conntrack_helpers=Proxmox._NF_CONNTRACK_HELPERS),
                NumberValueOption('nf_conntrack_max', 32768, math.inf, config),
                NumberValueOption('nf_conntrack_tcp_timeout_established', 7875, math.inf, config),
                NumberValueOption('nf_conntrack_tcp_timeout_syn_recv', 30, 60, config),
                BooleanKeywordOption('nftables', config),
                BooleanKeywordOption('nosmurfs', config),
                BooleanKeywordOption('protection_synflood', config),
                NumberValueOption('protection_synflood_burst', 0, math.inf, config),
                NumberValueOption('protection_synflood_rate', 0, math.inf, config),
                ValueOption(config, smurf_log_level=Proxmox._LOG_LEVELS),
                ValueOption(config, tcp_flags_log_level=Proxmox._LOG_LEVELS),
                BooleanKeywordOption('tcp_flags', config),
            ],
        },
        "vm": {
            "supported_directions": ["IN", "OUT"],
            "supported_options": lambda config: [
                BooleanKeywordOption('dhcp', config),
                BooleanKeywordOption('enable', config),
                BooleanKeywordOption('ipfilter', config),
                ValueOption(config, log_level_in=Proxmox._LOG_LEVELS),
                ValueOption(config, log_level_out=Proxmox._LOG_LEVELS),
                BooleanKeywordOption('macfilter', config),
                BooleanKeywordOption('ndp', config),
                ValueOption(config, policy_in=list(Proxmox._TERM.ACTIONS_MAP.values())),
                ValueOption(config, policy_out=list(Proxmox._TERM.ACTIONS_MAP.values())),
                BooleanKeywordOption('radv', config),
            ],
        },
        "vnet": {
            "supported_directions": ["FORWARD"],
            "supported_options": lambda config: [
                BooleanKeywordOption('enable', config),
                ValueOption(config, log_level_forward=Proxmox._LOG_LEVELS),
                ValueOption(config, policy_forward=list(Proxmox._TERM.ACTIONS_MAP.values())),
            ],
        },
    }

    def __init__(self, pol: Policy, exp_info: int):
        self.proxmox_policies = []
        super().__init__(pol, exp_info)

    def _BuildTokens(self) -> Tuple[Set[str], Dict[str, Set[str]]]:
        """returns the list of DSL + YAML supplementary tokens supported (proxmox-firewall specific)"""
        supported_tokens, supported_sub_tokens = super()._BuildTokens()
        supported_tokens |= {
            # proxmox firewall only supports setting the source interface
            'source_interface',
            # proxmox firewall supports icmp type + icmp code
            'icmp_code',
        }
        supported_sub_tokens.update({'option': set(self._TERM.LOG_LEVELS_MAP_OPTIONS.keys())})
        return supported_tokens, supported_sub_tokens

    def _TranslatePolicy(self, pol: policy.Policy, exp_info: int) -> None:
        filter_zones = []
        global_policy_config = ProxmoxConfigDataClass()
        for header, terms in pol.filters:
            self.filter_options = header.FilterOptions(self._PLATFORM)

            if len(self.filter_options) < 2:
                raise UnsupportedFilterOptionError(
                    "missing options, zone and direction are mandatory"
                )

            filter_zone = self.filter_options[0]
            filter_direction = self.filter_options[1]

            if filter_zone not in self._BY_ZONE.keys():
                raise UnsupportedFilterOptionError("unknown zone")

            if filter_zones and filter_zone not in filter_zones:
                raise ZoneMismatchError("cannot mix zone types in one policy")
            filter_zones.append(filter_zone)

            if filter_direction not in self._BY_ZONE[filter_zone]["supported_directions"]:
                raise UnsupportedFilterOptionError(
                    "direction "
                    + filter_direction
                    + " not supported for zone type "
                    + filter_zone,
                )

            filter_config = ProxmoxConfigDataClass()
            available_zone_options = self._BY_ZONE[filter_zone]['supported_options'](filter_config)
            for t in self.filter_options[2:]:
                ingested_options = []
                for o in available_zone_options:
                    ingested_options.append(o.ingest(t))
                if not any(ingested_options):
                    raise UnsupportedFilterOptionError("incorrect filter option directive %s" % t)
            incomplete_options = list(filter(lambda o: not o.complete(), available_zone_options))
            if incomplete_options:
                raise UnsupportedFilterOptionError(
                    "missing or incorrect value for filter option(s) %s", incomplete_options
                )
            global_policy_config += filter_config  # merge, will stay set to the same ref
            new_terms = []
            for term in terms:
                new_terms.append(
                    Term(
                        term,
                        filter_direction,
                    )
                )
            self.proxmox_policies.append(
                (header, filter_zone, filter_direction, global_policy_config, new_terms)
            )

    def __str__(self):
        target: List[str] = []
        terms_str: List[str] = []
        global_policy_config = ''
        for header, zone, direction, filter_config, terms in self.proxmox_policies:
            global_policy_config = filter_config  # only one (merged) config for the whole zone
            for term in terms:
                term_str = str(term)
                if term_str:
                    terms_str.append(term_str)
        target.append('[OPTIONS]')
        target.append(str(global_policy_config))
        target.append('[RULES]')
        target.append('\n'.join(terms_str))
        return '\n'.join(target) + '\n'
