# Copyright 2025 Aerleon Project Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""NVIDIA NVUE API generator.

Generates ACL configurations for NVIDIA Cumulus Linux switches using the
NVUE (NVIDIA User Experience) REST API JSON format.

More information about NVUE:
https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-514/System-Configuration/NVIDIA-User-Experience-NVUE/
"""

import itertools
import json
from typing import Dict, List, Optional

try:
    from absl import logging
except ImportError:
    import logging

from aerleon.lib import aclgenerator, policy

_ACTION_TABLE = {
    'accept': 'permit',
    'deny': 'deny',
    'reject': 'deny',
}

_PROTO_TABLE = {
    'icmp': 'icmp',
    'icmpv6': 'icmpv6',
    'tcp': 'tcp',
    'udp': 'udp',
    'esp': 'esp',
    'ah': 'ah',
    'gre': 'gre',
    'ipv6-icmp': 'icmpv6',
    'sctp': 'sctp',
}

_ICMP_TYPE_TABLE = {
    'echo-reply': 'echo-reply',
    'echo-request': 'echo-request',
    'unreachable': 'destination-unreachable',
    'time-exceeded': 'time-exceeded',
}


class Error(aclgenerator.Error):
    """Base error class for NVUE generator."""


class NvueApiError(Error):
    """Raised when there's an error generating NVUE API config."""


class UnsupportedNvueFilterError(Error):
    """Raised when we can't create the requested acl."""


class Term(aclgenerator.Term):
    """Representation of an individual NVUE ACL rule."""

    _PLATFORM = 'nvueapi'

    def __init__(self, term: policy.Term, address_family: str = 'ipv4'):
        """Initialize NVUE term.

        Args:
            term: The policy term object
            address_family: 'ipv4' or 'ipv6'
        """
        super().__init__(term)
        self.term = term
        self.address_family = address_family

    def __str__(self) -> str:
        """Convert term to NVUE JSON rule format."""
        # This should not be called directly - use GenerateRules() instead
        # which handles the cartesian product of multiple addresses
        raise NotImplementedError("Use GenerateRules() method instead")

    def GenerateRules(self) -> list[dict]:
        """Generate NVUE rules handling multiple addresses.

        Since NVUE only supports single CIDR prefixes per rule (like iptables),
        we need to create separate rules for each combination of addresses.

        Returns:
            List of rule dictionaries
        """
        rules = []

        # Get address lists for this address family
        source_addrs = self._GetFilteredAddresses(self.term.source_address)
        dest_addrs = self._GetFilteredAddresses(self.term.destination_address)

        # If no addresses specified, use empty list to generate one rule
        if not source_addrs:
            source_addrs = [None]
        if not dest_addrs:
            dest_addrs = [None]

        # Get other rule components
        protocols = self._GetProtocols()
        dest_ports = self._GetPorts(self.term.destination_port)
        source_ports = self._GetPorts(self.term.source_port)
        icmp_types = self._GetIcmpTypes()

        # Generate cartesian product of all combinations using itertools
        for src_addr, dst_addr, protocol, dest_port, source_port, icmp_type in itertools.product(
            source_addrs, dest_addrs, protocols, dest_ports, source_ports, icmp_types
        ):
            rule_dict = self._CreateSingleRule(
                src_addr, dst_addr, protocol, dest_port, source_port, icmp_type
            )
            if rule_dict:  # Only add non-empty rules
                rules.append(rule_dict)

        return rules

    def _GetFilteredAddresses(self, addresses) -> list[str]:
        """Get addresses filtered by address family.

        Args:
            addresses: List of address objects to filter

        Returns:
            List of address strings matching the current address family
        """
        if not addresses:
            return []

        filtered = []
        for addr in addresses:
            if addr.version == 4 and self.address_family == 'ipv4':
                filtered.append(str(addr))
            elif addr.version == 6 and self.address_family == 'ipv6':
                filtered.append(str(addr))
        return filtered

    def _GetProtocols(self) -> list[Optional[str]]:
        """Get protocol list, translating Aerleon protocol names to NVUE format.

        Returns:
            List of protocol names in NVUE format, or [None] if no protocols specified
        """
        if not self.term.protocol:
            return [None]
        return [_PROTO_TABLE.get(p, p) for p in self.term.protocol]

    def _GetPorts(self, port_list) -> list[Optional[str]]:
        """Get port list in NVUE format (porta:portz).

        Args:
            port_list: List of port ranges from the policy term

        Returns:
            List of port strings in NVUE format, or [None] if no ports specified
        """
        if not port_list:
            return [None]

        ports = []
        for port_range in port_list:
            if port_range[0] == port_range[1]:
                ports.append(str(port_range[0]))
            else:
                # NVUE uses porta:portz format for ranges
                ports.append(f"{port_range[0]}:{port_range[1]}")
        return ports

    def _GetIcmpTypes(self) -> list[Optional[str]]:
        """Get ICMP type list, converting from Aerleon format to iptables format.

        Returns:
            List of ICMP type strings in iptables format, or [None] if no ICMP types specified
        """
        if not self.term.icmp_type:
            return [None]

        return [_ICMP_TYPE_TABLE.get(icmp_type, icmp_type) for icmp_type in self.term.icmp_type]

    def _CreateSingleRule(
        self,
        src_addr: Optional[str],
        dst_addr: Optional[str],
        protocol: Optional[str],
        dest_port: Optional[str],
        source_port: Optional[str],
        icmp_type: Optional[str],
    ) -> dict:
        """Create a single NVUE rule from the given parameters.

        Args:
            src_addr: Source IP address/network
            dst_addr: Destination IP address/network
            protocol: Protocol name
            dest_port: Destination port or port range
            source_port: Source port or port range
            icmp_type: ICMP type name

        Returns:
            Dictionary representing a single NVUE rule
        """
        rule_dict = {}

        # Set action - NVUE uses object format with empty dict values
        action_dict = {}

        # Handle primary action
        if self.term.action:
            action = self.term.action[0]
            nvue_action = _ACTION_TABLE.get(action, action)
            action_dict[nvue_action] = {}

        # Add logging if specified
        if self.term.logging:
            action_dict['log'] = {}

        # If no actions specified, default to permit
        if not action_dict:
            action_dict['permit'] = {}

        rule_dict['action'] = action_dict

        # Set remark/comment
        if self.term.comment:
            rule_dict['remark'] = ' '.join(self.term.comment)

        # Set match conditions
        match_dict = {}
        ip_dict = {}

        # Protocol matching
        if protocol:
            ip_dict['protocol'] = protocol

        # Source IP matching
        if src_addr:
            ip_dict['source-ip'] = src_addr

        # Destination IP matching
        if dst_addr:
            ip_dict['dest-ip'] = dst_addr

        # Destination port matching
        if dest_port:
            ip_dict['dest-port'] = dest_port

        # Source port matching
        if source_port:
            ip_dict['source-port'] = source_port

        # ICMP type matching
        if icmp_type and protocol == 'icmp' and self.address_family == 'ipv4':
            ip_dict['icmp-type'] = icmp_type
        elif icmp_type and protocol == 'icmpv6' and self.address_family == 'ipv6':
            ip_dict['icmpv6-type'] = icmp_type

        # TCP state matching for NVUE
        tcp_dict = {}
        if protocol == 'tcp' and self.term.option:
            for option in self.term.option:
                if option in ['established', 'tcp-established']:
                    tcp_dict['state'] = 'established'
                    break

        # Add IP match conditions if any exist
        if ip_dict:
            match_dict['ip'] = ip_dict

        # Add TCP conditions if any exist (at same level as ip)
        if tcp_dict:
            match_dict['tcp'] = tcp_dict

        # Add match conditions if any exist
        if match_dict:
            rule_dict['match'] = match_dict

        return rule_dict


class NvueApi(aclgenerator.ACLGenerator):
    """NVUE API generator class."""

    _PLATFORM = 'nvueapi'
    _DEFAULT_PROTOCOL = 'ip'
    SUFFIX = '.nvueapi.json'
    SUPPORTED_AF = {'inet', 'inet6'}
    SUPPORTED_TARGETS = frozenset(['nvueapi'])
    WARN_IF_UNSUPPORTED = frozenset(['translated', 'stateless_reply', 'counter', 'policer'])

    def __init__(self, policy_obj: policy.Policy, exp_info: int) -> None:
        """Initialize NVUE API generator.

        Args:
            policy_obj: The policy object
            exp_info: Expiration info integer
        """
        self.nvue_policies = []
        self.address_family = None
        super().__init__(policy_obj, exp_info)

    def _TranslatePolicy(self, pol: policy.Policy, exp_info: int) -> None:
        """Translate policy to NVUE format.

        Args:
            pol: The policy object
            exp_info: Expiration info
        """
        self.nvue_policies = []

        for header, terms in pol.filters:
            if self._PLATFORM not in [x.platform for x in header.target]:
                continue

            filter_options = header.FilterOptions(self._PLATFORM)[1]
            filter_name = header.FilterName(self._PLATFORM)

            # Determine address family from filter options
            # NVUE supports ipv4, ipv6, or mac, but Aerleon only supports IP-based ACLs
            if 'ipv6' in filter_options:
                self.address_family = 'ipv6'
            elif 'inet6' in filter_options:
                self.address_family = 'ipv6'
            elif 'mac' in filter_options:
                raise UnsupportedNvueFilterError(
                    'NVUE MAC ACLs are not supported by Aerleon. '
                    'Aerleon only supports IP-based access control.'
                )
            elif 'mixed' in filter_options:
                raise UnsupportedNvueFilterError(
                    'NVUE does not support mixed address family ACLs. '
                    'Use separate ipv4 and ipv6 ACLs instead.'
                )
            else:
                self.address_family = 'ipv4'

            # Build NVUE ACL structure
            acl_rules = {}
            rule_number = 10  # Start rule numbering at 10, increment by 10

            for term in terms:
                if term.expiration:
                    if term.expiration <= exp_info:
                        logging.info(
                            'INFO: Term %s in policy %s expires ' 'in less than two weeks.',
                            term.name,
                            filter_name,
                        )
                    if term.expiration <= exp_info:
                        logging.warning(
                            'WARNING: Term %s in policy %s is expired and '
                            'will not be rendered.',
                            term.name,
                            filter_name,
                        )
                        continue

                # Handle address family filtering
                if self.address_family == 'ipv4':
                    # Skip terms that only have IPv6 addresses
                    has_ipv4 = self._HasIPv4(term)
                    if not has_ipv4:
                        continue
                elif self.address_family == 'ipv6':
                    # Skip terms that only have IPv4 addresses
                    has_ipv6 = self._HasIPv6(term)
                    if not has_ipv6:
                        continue

                # Generate rules for this term (may be multiple due to address expansion)
                nvue_term = Term(term, self.address_family)
                term_rules = nvue_term.GenerateRules()

                for rule_dict in term_rules:
                    if rule_dict:  # Only add non-empty rules
                        acl_rules[str(rule_number)] = rule_dict
                        rule_number += 10

            # Create the full ACL structure
            acl_config = {'acl': {filter_name: {'type': self.address_family, 'rule': acl_rules}}}

            self.nvue_policies.append((filter_name, acl_config))

    def _HasIPv4(self, term: policy.Term) -> bool:
        """Check if term has IPv4 addresses.

        Args:
            term: Policy term to check

        Returns:
            True if term has IPv4 addresses or no addresses, False otherwise
        """
        for addr_list in [term.source_address, term.destination_address]:
            if addr_list:
                for addr in addr_list:
                    if addr.version == 4:
                        return True
        return True  # Allow terms without addresses

    def _HasIPv6(self, term: policy.Term) -> bool:
        """Check if term has IPv6 addresses.

        Args:
            term: Policy term to check

        Returns:
            True if term has IPv6 addresses or no addresses, False otherwise
        """
        for addr_list in [term.source_address, term.destination_address]:
            if addr_list:
                for addr in addr_list:
                    if addr.version == 6:
                        return True
        return True  # Allow terms without addresses

    def __str__(self) -> str:
        """Return the NVUE configuration as a JSON string."""
        if not self.nvue_policies:
            return ''

        # Combine all ACL configurations
        acl_config = {}

        for _, policy_config in self.nvue_policies:
            acl_config.update(policy_config['acl'])

        # Return ACL configuration directly without 'set:' wrapper
        nvue_config = {'acl': acl_config}

        return json.dumps(nvue_config, indent=2)

    def _BuildTokens(self):
        """Build supported tokens for the NVUE platform.

        Returns:
            Tuple of (supported_tokens, supported_sub_tokens) sets
        """
        supported_tokens, supported_sub_tokens = super()._BuildTokens()

        # Add NVUE-specific tokens
        supported_tokens |= {
            'action',
            'comment',
            'destination_address',
            'destination_port',
            'icmp_type',
            'logging',
            'name',
            'option',  # For TCP established state
            'protocol',
            'source_address',
            'source_port',
        }

        # Remove unsupported tokens
        supported_tokens -= {
            'verbatim',  # NVUE doesn't support verbatim rules
            'icmp_code',  # Not implemented yet
            'destination_address_exclude',  # NVUE doesn't support address exclusion
            'source_address_exclude',  # NVUE doesn't support address exclusion
            'stateless_reply',  # Not implementing stateless reply functionality
            'translated',  # Not implementing NAT functionality
        }

        # NVUE-specific sub-tokens
        supported_sub_tokens = {
            'action': {'accept', 'deny', 'reject'},
        }

        return supported_tokens, supported_sub_tokens
