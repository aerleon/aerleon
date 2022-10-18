"""PolicyView is an immutable, configured wrapper around the Policy model."""


from functools import cached_property

from copy import deepcopy

from aerleon.lib.plugin import GeneratorConfiguration
from aerleon.lib.models import Filter, Policy, Term


class immutable_list(list):
    __slots__ = ()

    def append(self, _value):
        raise TypeError

    def clear(self):
        raise TypeError

    def __add__(self, _value):
        raise TypeError

    def __delitem__(self, _value):
        raise TypeError

    def __setitem__(self, _value):
        raise TypeError

    def extend(self, *_args):
        raise TypeError

    def insert(self, _value):
        raise TypeError

    def pop(self):
        raise TypeError

    def remove(self, _value):
        raise TypeError

    def reverse(self):
        raise TypeError

    def sort(self):
        raise TypeError

    def __copy__(self):
        new_list = immutable_list()
        for value in self:
            list.append(new_list, value)
        return new_list

    def __deepcopy__(self, memo):
        new_list = immutable_list()
        for value in self:
            list.append(new_list, deepcopy(value, memo=memo))
        return new_list


class PolicyView:
    policy: Policy
    config: GeneratorConfiguration

    def __init__(self, policy, config):
        self._policy = policy
        self._config = config

    @cached_property
    def filters(self):
        return immutable_list(self._policy.filters)

    @property
    def filename(self):
        return self._policy.filename


class FilterView:
    filter: Filter
    config: GeneratorConfiguration

    def __init__(self, filter, config):
        self._filter = filter
        self._config = config

    @cached_property
    def target(self):
        # NOTE: target isolation: only the relevant target is displayed to this generator
        return [target for target in self._filter.target if target.target == self._config.target]

    @cached_property
    def comment(self):
        return immutable_list(self._filter.comment)

    @cached_property
    def apply_groups(self):
        return immutable_list(self._filter.apply_groups)

    @cached_property
    def apply_groups_except(self):
        return immutable_list(self._filter.apply_groups_except)

    @cached_property
    def terms(self):
        return immutable_list(self._filter.terms)


class TermView:
    term: Term
    config: GeneratorConfiguration

    def __init__(self, term, config):
        self._term = term
        self._config = config

    @property
    def name(self):
        return self._term.name

    @cached_property
    def action(self):
        return immutable_list(self._term.action)

    @cached_property
    def address(self):
        return immutable_list(self._term.address)

    @cached_property
    def address_exclude(self):
        return immutable_list(self._term.address_exclude)

    @property
    def restrict_address_family(self):
        return self._term.restrict_address_family

    @cached_property
    def comment(self):
        return immutable_list(self._term.comment)

    @property
    def counter(self):
        return self._term.counter

    @property
    def expiration(self):
        return self._term.expiration

    @cached_property
    def destination_address(self):
        return immutable_list(self._term.destination_address)

    @cached_property
    def destination_address_exclude(self):
        return immutable_list(self._term.destination_address_exclude)

    @cached_property
    def destination_port(self):
        return immutable_list(self._term.destination_port)

    @cached_property
    def destination_prefix(self):
        return immutable_list(self._term.destination_prefix)

    @property
    def filter_term(self):
        return self._term.filter_term

    @cached_property
    def forwarding_class(self):
        return immutable_list(self._term.forwarding_class)

    @cached_property
    def forwarding_class_except(self):
        return immutable_list(self._term.forwarding_class_except)

    @cached_property
    def logging(self):
        return immutable_list(self._term.logging)

    @property
    def log_limit(self):
        return self._term.log_limit

    @property
    def log_name(self):
        return self._term.log_name

    @property
    def loss_priority(self):
        return self._term.loss_priority

    @cached_property
    def option(self):
        return immutable_list(self._term.option)

    @property
    def owner(self):
        return self._term.owner

    @property
    def policer(self):
        return self._term.policer

    @cached_property
    def port(self):
        return immutable_list(self._term.port)

    @cached_property
    def precedence(self):
        return immutable_list(self._term.precedence)

    @cached_property
    def protocol(self):
        return immutable_list(self._term.protocol)

    @cached_property
    def protocol_except(self):
        return immutable_list(self._term.protocol_except)

    @property
    def qos(self):
        return self._term.qos

    @cached_property
    def pan_application(self):
        return immutable_list(self._term.pan_application)

    @property
    def routing_instance(self):
        return self._term.routing_instance

    @cached_property
    def source_address(self):
        return immutable_list(self._term.source_address)

    @cached_property
    def source_address_exclude(self):
        return immutable_list(self._term.source_address_exclude)

    @cached_property
    def source_port(self):
        return immutable_list(self._term.source_port)

    @cached_property
    def source_prefix(self):
        return immutable_list(self._term.source_prefix)

    @property
    def ttl(self):
        return self._term.ttl

    @cached_property
    def verbatim(self):
        return immutable_list(self._term.verbatim)

    # juniper specific.
    @property
    def packet_length(self):
        return self._term.packet_length

    @property
    def fragment_offset(self):
        return self._term.fragment_offset

    @property
    def hop_limit(self):
        return self._term.hop_limit

    @cached_property
    def icmp_type(self):
        return immutable_list(self._term.icmp_type)

    @cached_property
    def icmp_code(self):
        return immutable_list(self._term.icmp_code)

    @cached_property
    def ether_type(self):
        return immutable_list(self._term.ether_type)

    @property
    def traffic_class_count(self):
        return self._term.traffic_class_count

    @cached_property
    def traffic_type(self):
        return immutable_list(self._term.traffic_type)

    @property
    def translated(self):
        return self._term.translated

    @property
    def dscp_set(self):
        return self._term.dscp_set

    @cached_property
    def dscp_match(self):
        return immutable_list(self._term.dscp_match)

    @cached_property
    def dscp_except(self):
        return immutable_list(self._term.dscp_except)

    @property
    def next_ip(self):
        return self._term.next_ip

    @cached_property
    def flexible_match_range(self):
        return immutable_list(self._term.flexible_match_range)

    @cached_property
    def source_prefix_except(self):
        return immutable_list(self._term.source_prefix_except)

    @cached_property
    def destination_prefix_except(self):
        return immutable_list(self._term.destination_prefix_except)

    @property
    def inactive(self):
        return self._term.inactive

    @property
    def encapsulate(self):
        return self._term.encapsulate

    @property
    def port_mirror(self):
        return self._term.port_mirror

    # srx specific
    @cached_property
    def destination_zone(self):
        return immutable_list(self._term.destination_zone)

    @cached_property
    def source_zone(self):
        return immutable_list(self._term.source_zone)

    @property
    def vpn(self):
        return self._term.vpn

    # gce specific
    @cached_property
    def source_tag(self):
        return immutable_list(self._term.source_tag)

    @cached_property
    def destination_tag(self):
        return immutable_list(self._term.destination_tag)

    @property
    def priority(self):
        return self._term.priority

    # iptables specific
    @property
    def source_interface(self):
        return self._term.source_interface

    @property
    def destination_interface(self):
        return self._term.destination_interface

    @cached_property
    def platform(self):
        return immutable_list(self._term.platform)

    @cached_property
    def platform_exclude(self):
        return immutable_list(self._term.platform_exclude)

    @cached_property
    def target_resources(self):
        return immutable_list(self._term.target_resources)

    @cached_property
    def target_service_accounts(self):
        return immutable_list(self._term.target_service_accounts)

    @property
    def timeout(self):
        return self._term.timeout

    @property
    def flattened(self):
        return self._term.flattened

    @property
    def flattened_addr(self):
        return self._term.flattened_addr

    @property
    def flattened_saddr(self):
        return self._term.flattened_saddr

    @property
    def flattened_daddr(self):
        return self._term.flattened_daddr

    @property
    def stateless_reply(self):
        return self._term.stateless_reply
