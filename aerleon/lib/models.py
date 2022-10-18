"""Core data models"""


import collections


class Policy:
    """A policy object, defined as the contents of a single policy file."""

    def __init__(self):
        self.filters = []  # TODO(jb) Semi-immutable list needed for policyview
        self.filename = ''


class Filter:
    def __init__(self):
        self.target = []
        self.comment = []
        self.apply_groups = []
        self.apply_groups_except = []
        self.terms = []  # TODO(jb) Semi-immutable list needed for policyview


class Term:
    def __init__(self):
        self.name = None

        self.action = []
        self.address = []
        self.address_exclude = []
        self.restrict_address_family = None
        self.comment = []
        self.counter = None
        self.expiration = None
        self.destination_address = []
        self.destination_address_exclude = []
        self.destination_port = []
        self.destination_prefix = []
        self.filter_term = None
        self.forwarding_class = []
        self.forwarding_class_except = []
        self.logging = []
        self.log_limit = None
        self.log_name = None
        self.loss_priority = None
        self.option = []
        self.owner = None
        self.policer = None
        self.port = []
        self.precedence = []
        self.protocol = []
        self.protocol_except = []
        self.qos = None
        self.pan_application = []
        self.routing_instance = None
        self.source_address = []
        self.source_address_exclude = []
        self.source_port = []
        self.source_prefix = []
        self.ttl = None
        self.verbatim = []
        # juniper specific.
        self.packet_length = None
        self.fragment_offset = None
        self.hop_limit = None
        self.icmp_type = []
        self.icmp_code = []
        self.ether_type = []
        self.traffic_class_count = None
        self.traffic_type = []
        self.translated = False
        self.dscp_set = None
        self.dscp_match = []
        self.dscp_except = []
        self.next_ip = None
        self.flexible_match_range = []
        self.source_prefix_except = []
        self.destination_prefix_except = []
        self.inactive = False
        self.encapsulate = None
        self.port_mirror = None
        # srx specific
        self.destination_zone = []
        self.source_zone = []
        self.vpn = None
        # gce specific
        self.source_tag = []
        self.destination_tag = []
        self.priority = None
        # iptables specific
        self.source_interface = None
        self.destination_interface = None
        self.platform = []
        self.platform_exclude = []
        self.target_resources = []
        self.target_service_accounts = []
        self.timeout = None
        self.flattened = False
        self.flattened_addr = None
        self.flattened_saddr = None
        self.flattened_daddr = None
        self.stateless_reply = False


class AddressBook(collections.OrderedDict):
    pass
