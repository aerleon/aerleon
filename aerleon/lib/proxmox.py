import math
from abc import abstractmethod, ABCMeta
from typing import Tuple, Set, Dict, Union, List

from aerleon.lib import aclgenerator, policy
from aerleon.lib.nacaddr import IPv6, IPv4
from aerleon.lib.policy import Policy


### error classes ###
class Error(aclgenerator.Error):
    pass


class UnsupportedFilterOptionError(Error):
    pass

### helper classes ###
class AbstractOption(metaclass=ABCMeta):
    def __init__(self, config: dict, *args, **kwargs):
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
            self.config_ref[self.key] = "1" # perl
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
        return got_token

    def complete(self) -> bool:
        return (
                (self.key_ingested, self.any_value_ingested) == (False, False)
                or self.key_ingested and self.any_value_ingested
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


### implementation ###
class Term(aclgenerator.Term):
    """
    (internal) representation of an individual proxmox-firewall term
    takes generic Term for conversion to internal type as an argument
    direction is IN, OUT, FORWARD (regardless of zone type, zone
    constraints should be handled by the client class)
    """
    GOOD_DIRECTIONS = [ 'IN', 'OUT', 'FORWARD' ]
    ACTIONS_MAP = {
        'accept': 'ACCEPT',
        'deny': 'DROP',
        'reject': 'REJECT',
    }

    def __init__(self, term: policy.Term, direction: str):
        self.term = term
        self.direction = direction

    def __str__(self) -> str:
        """ returns the proxmox-firewall string representation of the term """
        ret_str = []

        def to_network_addr(i: Union[IPv6, IPv4]):
            return str(i.with_prefixlen)

        # proxmox firewall only supports one protocol per rule
        for protocol in self.term.protocol:
            options = [self.direction, self.ACTIONS_MAP[self.term.action[0]], "-proto %s" % protocol]
            # proxmox firewall supports multiple sources/destinations per rule
            if self.term.source_interface:
                options.append("-iface %s" % self.term.source_interface)
            if self.term.destination_address:
                options.append("-dest %s" % ','.join(map(to_network_addr, self.term.destination_address)))
            if self.term.source_address:
                options.append("-source %s" % ','.join(map(to_network_addr, self.term.source_address)))
            if self.term.source_port:
                options.append("-sport %s" % ','.join(map(lambda p: str(ProxmoxPort(p)), self.term.source_port)))
            if self.term.destination_port:
                options.append("-dport %s" % ','.join(map(lambda p: str(ProxmoxPort(p)), self.term.destination_port)))
            if self.term.comment:
                options.append("# %s" % ' '.join(self.term.comment))
            ret_str.append(' '.join(options))

        return '\n'.join(ret_str)


class Proxmox(aclgenerator.ACLGenerator):
    """Proxmox firewall policy object"""

    # aerleon class props
    _PLATFORM = 'proxmox'
    SUFFIX = '.fw'
    _TERM = Term
    # own class props
    _LOG_LEVELS = [
        "alert", "crit", "debug", "emerg", "error", "info", "nolog", "notice", "warning"
    ]
    _NF_CONNTRACK_HELPERS = [ "amanda", "ftp", "irc", "netbios-ns", "pptp", "sane", "sip", "snmp", "tftp" ]
    _BY_ZONE = {
        "cluster": {
            "supported_directions": _TERM.GOOD_DIRECTIONS,
            "supported_options": lambda config : [
                BooleanKeywordOption('enable', config),
                BooleanKeywordOption('ebtables', config),
                ValueOption(config, policy_forward=list(Proxmox._TERM.ACTIONS_MAP.values())),
                ValueOption(config, policy_in=list(Proxmox._TERM.ACTIONS_MAP.values())),
                ValueOption(config, policy_out=list(Proxmox._TERM.ACTIONS_MAP.values())),
            ],
        },
        "host": {
            "supported_directions": _TERM.GOOD_DIRECTIONS,
            "supported_options": lambda config : [
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
            "supported_directions": [ "IN", "OUT" ],
            "supported_options": lambda config : [
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
            "supported_directions": [ "FORWARD" ],
            "supported_options": lambda config : [
                BooleanKeywordOption('enable', config),
                ValueOption(config, log_level_forward=Proxmox._LOG_LEVELS),
                ValueOption(config, policy_forward=list(Proxmox._TERM.ACTIONS_MAP.values())),
            ],
        }
    }

    def __init__(self, pol: Policy, exp_info: int):
        self.proxmox_policies = []
        super().__init__(pol, exp_info)

    def _BuildTokens(self) -> Tuple[Set[str], Dict[str, Set[str]]]:
        """ returns the list of DSL + YAML supplementary tokens supported (proxmox-firewall specific) """
        supported_tokens, supported_sub_tokens = super()._BuildTokens()
        supported_tokens |= {
            # proxmox firewall only supports setting the source interface
            'source_interface',
        }
        supported_sub_tokens |= {
        }
        return supported_tokens, supported_sub_tokens


    def _TranslatePolicy(self, pol: policy.Policy, exp_info: int) -> None:
        for header, terms in pol.filters:
            self.filter_options = header.FilterOptions(self._PLATFORM)

            if len(self.filter_options) < 2:
                raise UnsupportedFilterOptionError("missing options, zone and direction are mandatory")

            filter_zone = self.filter_options[0]
            filter_direction = self.filter_options[1]

            if filter_zone not in self._BY_ZONE.keys():
                raise UnsupportedFilterOptionError("unknown zone")

            if filter_direction not in self._BY_ZONE[filter_zone]["supported_directions"]:
                raise UnsupportedFilterOptionError(
                    "direction " + filter_direction + " not supported for zone type " + filter_zone,
                )

            filter_config = dict()
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
                    "missing or incorrect value for filter option(s) %s",
                    incomplete_options
                )

            new_terms = []
            for term in terms:
                new_terms.append(
                    Term(
                        term,
                        filter_direction,
                    )
                )
            self.proxmox_policies.append(
                (header, filter_zone, filter_direction, filter_config, new_terms)
            )

    def __str__(self):
        target = []
        for header, zone, direction, filter_config, terms in self.proxmox_policies:
            target.append(str(filter_config))
            for term in terms:
                term_str = str(term)
                if term_str:
                    target.append(term_str)
        return '\n'.join(target) + '\n'
