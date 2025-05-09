from typing import Tuple, Set, Dict, Union

from aerleon.lib import aclgenerator, policy
from aerleon.lib.nacaddr import IPv6, IPv4
from aerleon.lib.policy import Policy


class Error(aclgenerator.Error):
    pass


class UnsupportedFilterOptionError(Error):
    pass


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


class Term(aclgenerator.Term):
    """
    (internal) representation of an individual proxmox-firewall term
    takes generic Term for conversion to internal type as an argument
    direction is IN, OUT, FORWARD (regardless of zone type, zone
    constraints should be handled by the client class)
    """
    GOOD_DIRECTIONS = [ 'IN', 'OUT', 'FORWARD' ]
    _ACTIONS = {
        'accept': 'ACCEPT',
        'deny': 'DENY',
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
            options = [ self.direction, self._ACTIONS[self.term.action[0]], "-proto %s" % protocol ]
            # proxmox firewall supports multiple sources/destinations per rule
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
    _LOG_LEVELS = {
    }
    _ZONES = [ "host", "vm", "vnet" ]
    _BY_ZONE = {
        "host": {
            "supported_directions": [ "IN", "OUT", "FORWARD" ]
        },
        "vm": {
            "supported_directions": [ "IN", "OUT" ],
        },
        "vnet": {
            "supported_directions": [ "FORWARD" ],
        }
    }

    def __init__(self, pol: Policy, exp_info: int):
        self.proxmox_policies = []
        super().__init__(pol, exp_info)

    def _BuildTokens(self) -> Tuple[Set[str], Dict[str, Set[str]]]:
        """ returns the list of DSL + YAML supplementary tokens supported (proxmox-firewall specific) """
        supported_tokens, supported_sub_tokens = super()._BuildTokens()
        # TODO fixme, can use in_interface or out_interface for this
        # TODO native logging can also be used
        supported_tokens |= {
            'network_interface',
            'logging',
        }
        supported_sub_tokens |= {
        }
        return supported_tokens, supported_sub_tokens


    def _TranslatePolicy(self, pol: policy.Policy, exp_info: int) -> None:
        for header, terms in pol.filters:
            self.filter_options = header.FilterOptions(self._PLATFORM)
            valid_options = self._ZONES + self._TERM.GOOD_DIRECTIONS

            for opt in self.filter_options:
                if opt not in valid_options:
                    raise UnsupportedFilterOptionError("unknown options")

            if len(self.filter_options) < 2:
                raise UnsupportedFilterOptionError("missing options, zone and direction are mandatory")

            filter_zone = self.filter_options[0]
            filter_direction = self.filter_options[1]

            if filter_zone not in self._ZONES:
                raise UnsupportedFilterOptionError("unknown zone")

            if filter_direction not in self._BY_ZONE[filter_zone]["supported_directions"]:
                raise UnsupportedFilterOptionError(
                    "direction " + filter_direction + " not supported for zone type " + filter_zone,
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
                (header, filter_zone, filter_direction, new_terms)
            )

    def __str__(self):
        target = []
        for header, zone, direction, terms in self.proxmox_policies:
            for term in terms:
                term_str = str(term)
                if term_str:
                    target.append(term_str)
        return '\n'.join(target) + '\n'
