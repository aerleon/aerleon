from typing import Tuple, Set, Dict, Union

from aerleon.lib import aclgenerator, policy
from aerleon.lib.nacaddr import IPv6, IPv4
from aerleon.lib.policy import Policy


class Term(aclgenerator.Term):
    """
    (internal) representation of an individual proxmox-firewall term
    takes generic Term for conversion to internal type as an argument
    direction is IN, OUT, FORWARD
    """
    _GOOD_DIRECTIONS = ['IN', 'OUT', 'FORWARD']
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
        ret = str()
        options = [self.direction, self.term.action[0]]

        def to_network_addr(i: Union[IPv6, IPv4]):
            return str(i.with_prefixlen)

        if self.term.destination_address:
            options.append("-dest " + ','.join(map(to_network_addr, self.term.destination_address)))
        if self.term.source_address:
            options.append("-source " + ','.join(map(to_network_addr, self.term.source_address)))
        if self.term.source_port:
            options.append("-sport " + ','.join(self.term.source_port))
        if self.term.destination_port:
            options.append("-dport " + ','.join(self.term.source_port))
        if self.term.protocol:
            options.append("-proto " + self.term.protocol[0])

        # should be in [IPSET something]
        # self.term.destination_prefix
        # self.term.source_prefix
        return ret + ' '.join(options)


class Proxmox(aclgenerator.ACLGenerator):
    """Proxmox firewall policy object"""

    # aerleon class props
    _PLATFORM = 'proxmox'
    SUFFIX = '.fw'
    # own class props
    _LOG_LEVELS = {
    }
    _OPTIONS = {
        "vnet": {
            'enable': ['0', '1'],
            'log_level_forward': ['alert', 'crit', 'debug', 'emerg', 'err', 'info', 'nolog', 'notice', 'warning'],
            'policy_forward': ['ACCEPT', 'DROP'],
        }
    }

    def __init__(self, pol: Policy, exp_info: int):
        self.proxmox_policies = []
        super().__init__(pol, exp_info)

    def _BuildTokens(self) -> Tuple[Set[str], Dict[str, Set[str]]]:
        """ returns the list of DSL + YAML supplementary tokens supported (proxmox-firewall specific) """
        supported_tokens, supported_sub_tokens = super()._BuildTokens()
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
            filter_name = self.filter_options[0]
            new_terms = []
            for term in terms:
                new_terms.append(
                    Term(
                        term,
                        'FORWARD'
                    )
                )
            self.proxmox_policies.append(
                (header, filter_name, new_terms)
            )

    def __str__(self):
        target = []
        for header, filter_name, terms in self.proxmox_policies:
            for term in terms:
                term_str = str(term)
                if term_str:
                    target.append(term_str)
        return '\n'.join(target)
