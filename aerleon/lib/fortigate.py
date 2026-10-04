from collections import defaultdict
from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Any

from absl import logging

from aerleon.lib import aclgenerator, nacaddr, policy
from aerleon.lib.proxmox import BooleanKeywordOption
from aerleon.utils.options import (
    AbstractOption,
    ArbitraryValueOption,
    ProcessOptions,
)

FORTIGATE_SERVICES_ALL = 'ALL'
FORTIGATE_ADDRESS_ALL = 'all'
FORTIGATE_ADDRESS_NONE = 'none'
FORTIGATE_SCHEDULE_ALWAYS = '"always"'
SUPPORTED_ACTIONS = {'accept', 'deny'}
FORTIGATE_COMMENT_LIMIT = 1023
FORTIGATE_LOG_TRAFFIC_VALUES = {'log_traffic_mode_all', 'log_traffic_mode_disable'}
FORTIGATE_LOG_TRAFFIC_START_VALUES = {'log_traffic_start_session'}


class FortigateDefaultDictionary(defaultdict):
    def __init__(self, object_constructor, key_attribute_name):
        """
        Initializes the FortigateDefaultDictionary.

        Args:
            object_constructor: The class (or function) to call to create a new object.
                                Its __init__ or call signature must accept a keyword
                                argument named by key_attribute_name.
            key_attribute_name: The string name of the attribute in the object
                                that should be populated with the dictionary key.
        """
        super().__init__(None)  # Initialize defaultdict without a default_factory
        # We handle creation in __missing__
        if not callable(object_constructor):
            raise TypeError("object_constructor must be callable")
        self.object_constructor = object_constructor
        self.key_attribute_name = key_attribute_name

    def __missing__(self, key):
        """
        Called when a key is not found. Creates the object using the key.
        """
        kwargs = {self.key_attribute_name: key}
        value = self.object_constructor(**kwargs)
        self[key] = value
        return value


@dataclass(order=True, unsafe_hash=True)
class FortigateObjectGroup:
    name: str


class FortigateIcmpService(FortigateObjectGroup):
    def __init__(self, name: str, icmp_types: list[int]):
        self.name = f'{name}-icmp'
        self.icmp_types = [str(i) for i in icmp_types]

    def __str__(self) -> str:
        """Return string representation of Fortigate service."""
        output = []
        output.append(f'    edit {self.name}')
        output.append('        set protocol ICMP')
        output.append(f'        set icmptype {" ".join(self.icmp_types)}')
        output.append('    next')
        return '\n'.join(output)


class FortigateIPService(FortigateObjectGroup):
    def __init__(
        self,
        name: str,
        source_port: list[tuple[int, int]],
        destination_port: list[tuple[int, int]],
        protocols: list[str],
    ):
        self.name = name
        # Adding a suffix to the name to avoid conflicts with term names
        self.tcp_port_range = None
        self.udp_port_range = None
        for proto in protocols:
            if proto == 'tcp':
                self.tcp_port_range = GenerateFortinetServiceString(source_port, destination_port)
            elif proto == 'udp':
                self.udp_port_range = GenerateFortinetServiceString(source_port, destination_port)
            elif proto == 'icmp':
                # ICMP is supported in FortigateIcmpService
                pass
            else:
                raise ValueError(f"Unsupported protocol: {proto}")

    def __str__(self) -> str:
        """Return string representation of Fortigate service."""
        output = []
        output.append(f'    edit {self.name}')
        if self.tcp_port_range:
            output.append(f'        set tcp-portrange {self.tcp_port_range}')
        if self.udp_port_range:
            output.append(f'        set udp-portrange {self.udp_port_range}')
        output.append('    next')
        return '\n'.join(output)


class FortinetAddress(FortigateObjectGroup):
    def __init__(self, name: str, ip: nacaddr.IP):
        """
        Initializes the FortinetAddress object.
        Args:
            name: The name of the address.
            ip: The IP address object.
        """
        self.name = name
        self.ip = ip

    def __str__(self) -> str:
        """Return string representation of Fortigate address."""
        output = []
        output.append(f'    edit {self.name}')
        if self.ip.version == 6:
            output.append('        set type ipprefix')
            output.append(f'        set ip6 {str(self.ip)}')
        else:
            output.append('        set type ipmask')
            output.append(
                f'        set subnet {str(self.ip.network_address)} {str(self.ip.netmask)}'
            )
        output.append('    next')
        return '\n'.join(output)


class FortigateExcludeGroup(FortigateObjectGroup):
    def __init__(self, name: str, members: list[str], exclude: list[str]):
        """
        Initializes the FortigateExcludeGroup object.
        Args:
            name: The name of the address group.
        """
        super().__init__(name=name)
        if not members:
            self._members_cfg_list = [FORTIGATE_ADDRESS_NONE]
        else:
            self._members_cfg_list = [f'"{m}"' for m in sorted(set(members))]
        if not exclude:
            self._exclude_cfg_list = [FORTIGATE_ADDRESS_NONE]
        else:
            self._exclude_cfg_list = [f'"{e}"' for e in sorted(set(exclude))]

    def __str__(self):
        output = []
        output.append(f'    edit {self.name}')
        output.append(f'        set member {" ".join(self._members_cfg_list)}')
        output.append('        set exclude enable')
        output.append(f'        set exclude-member {" ".join(self._exclude_cfg_list)}')
        output.append('    next')
        return '\n'.join(output)


class FortigateAddressGroup(FortigateObjectGroup):
    def __init__(self, name: str):
        """
        Initializes the FortigateAddressGroup object.
        Args:
            name: The name of the address group.
        """
        self.name = name
        self._cached_fortigate_addrs: list[FortinetAddress] = []
        self._members = set()
        self._is_dirty = True

    def AddMember(self, ip: nacaddr.IP) -> None:
        """Add an IP address to the group."""
        if ip not in self._members:
            self._members.add(ip)
            self._is_dirty = True

    @property
    def fortigate_addrs(self) -> list[FortinetAddress]:
        if self._is_dirty or not self._cached_fortigate_addrs:
            self._cached_fortigate_addrs = []
            sorted_ips = sorted(list(self._members))
            for i, ip_obj in enumerate(sorted_ips):
                address_object_name = f"{self.name}_{i}"
                self._cached_fortigate_addrs.append(
                    FortinetAddress(name=address_object_name, ip=ip_obj)
                )
            self._is_dirty = False
        return self._cached_fortigate_addrs

    def __contains__(self, item: Any) -> bool:
        """Check if an item is in the address group."""
        return item in self._members

    def __str__(self) -> str:
        """Return string representation of Fortigate address."""
        output = []
        current_fortigate_addrs = self.fortigate_addrs
        if not current_fortigate_addrs:  # Don't render empty groups
            return ""
        output.append(f'    edit {self.name}')
        member_names = [f'"{addr.name}"' for addr in current_fortigate_addrs]
        output.append(f'        set member {" ".join(member_names)}')
        output.append('    next')
        return '\n'.join(output)

    def __len__(self):
        return len(self._members)

    def __iter__(self):
        return iter(self.fortigate_addrs)


class Term(aclgenerator.Term):
    SADDR_V4 = 'srcaddr'
    DADDR_V4 = 'dstaddr'
    SADDR_V6 = 'srcaddr6'
    DADDR_V6 = 'dstaddr6'

    def __init__(
        self,
        term: policy.Term,
        source_interface: str,
        destination_interface: str,
        addressgroups: FortigateDefaultDictionary,
        addressgroups_v6: FortigateDefaultDictionary,
        address_family: str,
    ):
        """
        Initializes the Term object.
        Args:
            term: The term object from the policy.
            source_interface: The source interface for the term.
            destination_interface: The destination interface for the term.
        """
        super().__init__(term)
        self.term = term

        # Validate self.term.action
        if not isinstance(self.term.action, list):
            raise TypeError("term.action must be a list.")
        if len(self.term.action) != 1:
            raise ValueError("term.action must contain exactly one element.")
        if self.term.action[0] not in SUPPORTED_ACTIONS:
            raise ValueError("term.action must contain only 'accept' or 'deny'.")

        self.source_interface = source_interface
        self.destination_interface = destination_interface
        self.address_family = address_family

        self.address_groups = addressgroups
        self.address_groups_v6 = addressgroups_v6
        self.services = []

        self._TranslateAddresses(term.source_address)
        self._TranslateAddresses(term.destination_address)
        self._TranslateAddresses(term.source_address_exclude)
        self._TranslateAddresses(term.destination_address_exclude)
        if term.source_address_exclude:
            self._TranslateExcludes(
                f"{self.term.name}-source", term.source_address, term.source_address_exclude
            )
        if term.destination_address_exclude:
            self._TranslateExcludes(
                f"{self.term.name}-destination",
                term.destination_address,
                term.destination_address_exclude,
            )

        if term.destination_port or term.source_port:
            service = FortigateIPService(
                term.name, term.source_port, term.destination_port, term.protocol
            )
            self.services.append(service)
        if term.icmp_type:
            service = FortigateIcmpService(
                term.name, self.NormalizeIcmpTypes(term.icmp_type, term.protocol, 4)
            )
            self.services.append(service)
        # Logging defaults to UTM on fortigate
        # Set those defaults and then if logging is enabled, check options for
        # deviations from defaults.
        self.logtraffic = 'utm'
        self.logtraffic_start = 'disabled'
        if self.term.logging:
            if all(opt in self.term.option for opt in FORTIGATE_LOG_TRAFFIC_VALUES):
                raise ValueError(
                    "Multiple logtraffic values cannot be used together. "
                    f"Valid values are: {', '.join(FORTIGATE_LOG_TRAFFIC_VALUES)}"
                )
            # logtraffic options.
            if 'log_traffic_mode_all' in self.term.option:
                self.logtraffic = 'log_traffic_mode_all'
            elif 'log_traffic_mode_disable' in self.term.option:
                self.logtraffic = 'log_traffic_mode_disable'

            # logtraffic-start options.
            if 'log_traffic_start_session' in self.term.option:
                self.logtraffic_start = 'log_traffic_start_session'

    def _TranslateExcludes(
        self, base_name: str, addrs: list[nacaddr.IP], excludes: list[nacaddr.IP]
    ) -> None:
        member_tokens_v4 = [i.token for i in addrs if i.version == 4]
        member_tokens_v6 = [i.token for i in addrs if i.version == 6]
        exclude_tokens_v4 = [i.token for i in excludes if i.version == 4]
        exclude_tokens_v6 = [i.token for i in excludes if i.version == 6]

        # Default members to "none" if addrs is empty but excludes exist
        effective_members_v4 = member_tokens_v4 if member_tokens_v4 else [FORTIGATE_ADDRESS_NONE]
        effective_members_v6 = member_tokens_v6 if member_tokens_v6 else [FORTIGATE_ADDRESS_NONE]

        if exclude_tokens_v4:  # Only create if there are actual v4 excludes
            v4_exclude_group_name = f"{base_name}"  # Differentiated name
            exclude_addrgrp_v4 = FortigateExcludeGroup(
                v4_exclude_group_name, effective_members_v4, exclude_tokens_v4
            )
            self.address_groups[v4_exclude_group_name] = exclude_addrgrp_v4
        if exclude_tokens_v6:  # Only create if there are actual v6 excludes
            v6_exclude_group_name = f"{base_name}"  # Differentiated name
            exclude_addrgrp_v6 = FortigateExcludeGroup(
                v6_exclude_group_name, effective_members_v6, exclude_tokens_v6
            )
            self.address_groups_v6[v6_exclude_group_name] = exclude_addrgrp_v6

    def _TranslateAddresses(self, addrs: list[nacaddr.IP]) -> None:
        """Inserts tokens into versioned addressbook and sets their members to the IPs."""
        for addr in addrs:
            if addr.version == 4:
                if self.address_family == 'inet6':
                    continue
                self.address_groups[addr.token].AddMember(addr)
            elif addr.version == 6:
                if self.address_family == 'inet':
                    continue
                self.address_groups_v6[addr.token].AddMember(addr)
            else:
                raise ValueError(f"Unsupported address version: {addr.version}")

    def _SetStrLogging(self, output):
        if self.term.logging:
            if self.logtraffic == 'log_traffic_mode_all':
                output.append('        set logtraffic all')
            elif self.logtraffic == 'log_traffic_mode_disable':
                output.append('        set logtraffic disable')
            if self.logtraffic_start == 'log_traffic_start_session':
                output.append('        set logtraffic-start enable')
        else:
            output.append('        set logtraffic disable')
        return output

    def _SetStrInterfaces(self, output):
        output.append(f'        set srcintf "{self.source_interface}"')
        output.append(f'        set dstintf "{self.destination_interface}"')
        return output

    def __str__(self):
        """Return string representation of Fortigate term."""
        output = []
        output.append(f'        set name "{self.term.name}"')
        output = self._SetStrInterfaces(output)
        if self.term.action[0] != 'deny':
            output.append(f'        set action {self.term.action[0]}')
        # Collecting all tokens into bins of src/dst and IP version.
        source_tokens_v4 = set()
        source_tokens_v6 = set()
        for i in self.term.source_address:
            if i.version == 4:
                source_tokens_v4.add(f'"{i.token}"')
            elif i.version == 6:
                source_tokens_v6.add(f'"{i.token}"')
        destination_tokens_v4 = set()
        destination_tokens_v6 = set()
        for i in self.term.destination_address:
            if i.version == 4:
                destination_tokens_v4.add(f'"{i.token}"')
            elif i.version == 6:
                destination_tokens_v6.add(f'"{i.token}"')

        # Sorting tokens
        source_tokens_v4 = sorted(source_tokens_v4)
        source_tokens_v6 = sorted(source_tokens_v6)
        destination_tokens_v4 = sorted(destination_tokens_v4)
        destination_tokens_v6 = sorted(destination_tokens_v6)

        has_v4_source_elements = bool(
            source_tokens_v4 or any(ex.version == 4 for ex in self.term.source_address_exclude)
        )
        has_v6_source_elements = bool(
            source_tokens_v6 or any(ex.version == 6 for ex in self.term.source_address_exclude)
        )
        has_v4_destination_elements = bool(
            destination_tokens_v4
            or any(ex.version == 4 for ex in self.term.destination_address_exclude)
        )
        has_v6_destination_elements = bool(
            destination_tokens_v6
            or any(ex.version == 6 for ex in self.term.destination_address_exclude)
        )

        generate_ipv4_policy = False
        generate_ipv6_policy = False

        if self.address_family == 'inet':
            generate_ipv4_policy = True
        elif self.address_family == 'inet6':
            generate_ipv6_policy = True
        elif self.address_family == 'mixed':
            # If there are any v4 elements (source or dest, include or exclude)
            # OR if there are no v6 elements at all (meaning v4 is the only option or it's truly 'any/any')
            if (has_v4_source_elements or has_v4_destination_elements) or not (
                has_v6_source_elements or has_v6_destination_elements
            ):
                generate_ipv4_policy = True

            # If there are any v6 elements (source or dest, include or exclude)
            # OR if there are no v4 elements at all
            if (has_v6_source_elements or has_v6_destination_elements) or not (
                has_v4_source_elements or has_v4_destination_elements
            ):
                generate_ipv6_policy = True

            # If both are true but one side has no elements, turn off the other.
            # e.g. if only v6 exclude exists, don't generate an empty/all v4 rule.
            if generate_ipv4_policy and generate_ipv6_policy:
                if not (has_v4_source_elements or has_v4_destination_elements):
                    generate_ipv4_policy = False
                if not (has_v6_source_elements or has_v6_destination_elements):
                    generate_ipv6_policy = False

            # If mixed and absolutely no address specifications (includes or excludes)
            # default to generating for both (Fortigate 'all'/'all')
            if not (
                has_v4_source_elements
                or has_v4_destination_elements
                or has_v6_source_elements
                or has_v6_destination_elements
            ):
                generate_ipv4_policy = True
                generate_ipv6_policy = True

        # Default actions
        src_v4_effective_val = FORTIGATE_ADDRESS_ALL
        if not has_v4_source_elements and self.term.source_address:
            src_v4_effective_val = FORTIGATE_ADDRESS_NONE

        dst_v4_effective_val = FORTIGATE_ADDRESS_ALL
        if not has_v4_destination_elements and self.term.destination_address:
            dst_v4_effective_val = FORTIGATE_ADDRESS_NONE

        src_v6_effective_val = FORTIGATE_ADDRESS_ALL
        if not has_v6_source_elements and self.term.source_address:
            src_v6_effective_val = FORTIGATE_ADDRESS_NONE

        dst_v6_effective_val = FORTIGATE_ADDRESS_ALL
        if not has_v6_destination_elements and self.term.destination_address:
            dst_v6_effective_val = FORTIGATE_ADDRESS_NONE

        # Generate IPv4 address groups from tokens or use default action if empty
        if generate_ipv4_policy:
            # Check if there's a v4-specific source exclude group
            source_v4_exclude_exists = any(
                ex.version == 4 for ex in self.term.source_address_exclude
            )
            if source_v4_exclude_exists:
                # Ensure the _TranslateExcludes created a V4 group for this term.
                # The name needs to be consistently generated.
                src_v4_to_set = f'"{self.term.name}-source"'  # Assumes _TranslateExcludes uses this name for the v4 version
            elif source_tokens_v4:
                src_v4_to_set = " ".join(source_tokens_v4)
            else:
                src_v4_to_set = f'"{src_v4_effective_val}"'  # Use effective default (all or none)

            destination_v4_exclude_exists = any(
                ex.version == 4 for ex in self.term.destination_address_exclude
            )
            if destination_v4_exclude_exists:
                dst_v4_to_set = f'"{self.term.name}-destination"'
            elif destination_tokens_v4:
                dst_v4_to_set = " ".join(destination_tokens_v4)
            else:
                dst_v4_to_set = f'"{dst_v4_effective_val}"'

            output.append(f'        set {self.SADDR_V4} {src_v4_to_set}')
            output.append(f'        set {self.DADDR_V4} {dst_v4_to_set}')

        # Generate IPv6 address groups
        if generate_ipv6_policy:
            source_v6_exclude_exists = any(
                ex.version == 6 for ex in self.term.source_address_exclude
            )
            if source_v6_exclude_exists:
                src_v6_to_set = (
                    f'"{self.term.name}-source"'  # This name might need adjustment if it clashes
                )
            elif source_tokens_v6:
                src_v6_to_set = " ".join(source_tokens_v6)
            else:
                src_v6_to_set = f'"{src_v6_effective_val}"'

            destination_v6_exclude_exists = any(
                ex.version == 6 for ex in self.term.destination_address_exclude
            )
            if destination_v6_exclude_exists:
                dst_v6_to_set = f'"{self.term.name}-destination"'
            elif destination_tokens_v6:
                dst_v6_to_set = " ".join(destination_tokens_v6)
            else:
                dst_v6_to_set = f'"{dst_v6_effective_val}"'

            output.append(f'        set {self.SADDR_V6} {src_v6_to_set}')
            output.append(f'        set {self.DADDR_V6} {dst_v6_to_set}')
        output.append(f'        set schedule {FORTIGATE_SCHEDULE_ALWAYS}')
        services = [f'"{service.name}"' for service in self.services]
        if not services:
            services = [f'"{FORTIGATE_SERVICES_ALL}"']
        output.append(f'        set service {"".join(services)}')

        # Multiple logging types are available, check if logging is true and then print relevant log statements.
        output = self._SetStrLogging(output)
        # Comments have a limited length. Add Owner to the comment and then join the term comment.
        # If the comment is too long warn the user and truncate.
        comment = []
        if self.term.owner:
            comment.append(f'Owner: {self.term.owner}')
        if self.term.comment:
            comment.append(' '.join(self.term.comment))
        comment = '\n'.join(comment)
        if len(comment) >= FORTIGATE_COMMENT_LIMIT:
            logging.warning(
                f"Fortigate comment cannot be longer than {FORTIGATE_COMMENT_LIMIT} characters, length was {len(comment)}, truncating comment."
            )
            comment = comment[:FORTIGATE_COMMENT_LIMIT]
        if comment:
            output.append(f'        set comments "{comment}"')
        return '\n'.join(output)


class LocalInTerm(Term):
    SADDR_V4 = 'srcaddr'
    DADDR_V4 = 'dstaddr'
    SADDR_V6 = 'srcaddr'
    DADDR_V6 = 'dstaddr'

    def _SetStrLogging(self, output):
        # No logging for Local in terms.
        return output

    def _SetStrInterfaces(self, output):
        output.append(f'        set intf "{self.source_interface}"')
        return output


class Fortigate(aclgenerator.ACLGenerator):
    """Fortigate ACL generator."""

    _PLATFORM = 'fortigate'
    SUFFIX = '.fgacl'
    _SUPPORTED_AF = frozenset(('inet', 'inet6', 'mixed'))

    def __init__(self, name, description):
        """Initialize Fortigate ACL generator.
        Args:
          name: Name of the ACL.
          description: Description of the ACL.
        """
        self.services = []
        self.terms = []
        self.local_in_terms_v4 = []
        self.local_in_terms_v6 = []
        self.term_names = set()
        self.address_groups = FortigateDefaultDictionary(FortigateAddressGroup, 'name')
        self.address_groups_v6 = FortigateDefaultDictionary(FortigateAddressGroup, 'name')
        super().__init__(name, description)

    @staticmethod
    def _SupportedOptions(config: MutableMapping) -> list[AbstractOption]:
        return [
            ArbitraryValueOption("from-zone", config),
            ArbitraryValueOption("to-zone", config),
            BooleanKeywordOption("mixed", config),
            BooleanKeywordOption("inet6", config),
            BooleanKeywordOption("inet", config),
        ]

    def _BuildTokens(self) -> tuple[set[str], dict[str, set[str]]]:
        """Build supported tokens for platform.

        Returns:
          tuple containing both supported tokens and sub tokens
        """
        supported_tokens, supported_sub_tokens = super()._BuildTokens()
        supported_tokens.remove('stateless_reply')
        supported_sub_tokens['action'] = SUPPORTED_ACTIONS
        supported_sub_tokens['option'] = (
            FORTIGATE_LOG_TRAFFIC_VALUES | FORTIGATE_LOG_TRAFFIC_START_VALUES
        )
        return supported_tokens, supported_sub_tokens

    def _TranslatePolicy(self, pol: policy.Policy, exp_info: int) -> None:
        for header, terms in pol.filters:
            filter_options = header.FilterOptions(self._PLATFORM)

            filter_config = ProcessOptions(
                self._SupportedOptions,
                filter_options,
            )

            if "from-zone" not in filter_config or "to-zone" not in filter_config:
                raise ValueError(
                    f'Fortigate requires that at least from-zone and to-zone interfaces/zone names be specified, found: {filter_options}'
                )
            source_interface = filter_config["from-zone"]
            destination_interface = filter_config["to-zone"]

            af = self._SUPPORTED_AF.intersection(filter_config.keys())
            if len(af) > 1:
                raise ValueError(
                    f"Only one address family is supported (inet, inet6, mixed) but found: {', '.join(af)}"
                )
            if destination_interface == "local-in-policy":
                if not af:
                    raise ValueError(
                        "Address family must be specified as 'inet' or 'inet6' for local-in-policy."
                    )
                af = next(iter(af))
                if af not in ('inet', 'inet6'):
                    raise ValueError("Only 'inet' or 'inet6' are supported for local-in-policy.")

            else:
                if not af:
                    af = 'mixed'
                else:
                    af = next(iter(af))
            TermClass = LocalInTerm if destination_interface == "local-in-policy" else Term

            for term in terms:
                fortigate_term = TermClass(
                    term,
                    source_interface,
                    destination_interface,
                    self.address_groups,
                    self.address_groups_v6,
                    af,
                )
                self.services.extend(fortigate_term.services)
                self.term_names.add(term.name)
                if destination_interface == "local-in-policy":
                    if af == "inet":
                        self.local_in_terms_v4.append(fortigate_term)
                    elif af == "inet6":
                        self.local_in_terms_v6.append(fortigate_term)
                    else:
                        raise ValueError(
                            "local-in-policy must specify 'inet' or 'inet6' as address family."
                        )
                else:
                    self.terms.append(fortigate_term)
        self._ValidateNoDuplicateTerms(self.terms)
        self._ValidateNoDuplicateTerms(self.local_in_terms_v4)
        self._ValidateNoDuplicateTerms(self.local_in_terms_v6)

    def _ValidateNoDuplicateTerms(self, term_list):
        seen = set()
        for term in term_list:
            if term.term.name in seen:
                raise ValueError(
                    f"Duplicate term name '{term.term.name}' found in the same term list."
                )
            seen.add(term.term.name)

    def _RenderPolicySection(self, output, section_name, terms):
        if terms:
            output.append(f'config firewall {section_name}')
            counter = 1
            for term in terms:
                output.append(f'    edit {counter}')
                output.append(str(term))
                counter += 1
                output.append('    next')
            output.append('end')
        return output

    def __str__(self) -> str:
        """Return string representation of Fortigate ACL."""
        output = []

        # IPv4
        if self.address_groups.values():
            # IPv4 Addresses
            output.append('config firewall address')
            for group_name in sorted(self.address_groups):
                group = self.address_groups[group_name]
                # Don't process excludes in addresses
                if isinstance(group, FortigateAddressGroup):
                    for addr in sorted(self.address_groups[group_name].fortigate_addrs):
                        output.append(str(addr))
            output.append('end')
            # Address Groups
            output.append('config firewall addrgrp')
            for addr_group in sorted(self.address_groups.values(), key=lambda item: item.name):
                output.append(str(addr_group))
            output.append('end')

        # IPv6 Space
        if self.address_groups_v6.values():
            # IPv6 Addresses
            output.append('config firewall address6')
            for group_name in sorted(self.address_groups_v6):
                group = self.address_groups_v6[group_name]
                # Don't process excludes in addresses
                if isinstance(group, FortigateAddressGroup):
                    for addr in sorted(self.address_groups_v6[group_name].fortigate_addrs):
                        output.append(str(addr))
            output.append('end')
            # Address Groups
            output.append('config firewall addrgrp6')
            for addr_group in sorted(self.address_groups_v6.values(), key=lambda item: item.name):
                output.append(str(addr_group))
            output.append('end')

        # Services
        if self.services:
            output.append('config firewall service custom')
            for service in sorted(self.services):
                output.append(str(service))
            output.append('end')

        # Firewall Policies

        output = self._RenderPolicySection(output, 'policy', self.terms)
        output = self._RenderPolicySection(output, 'local-in-policy', self.local_in_terms_v4)
        output = self._RenderPolicySection(output, 'local-in-policy6', self.local_in_terms_v6)
        return '\n'.join(output)


def FormatFortinetPortRange(low: int, high: int) -> str:
    """Formats a single port range according to Fortinet syntax."""
    if not (1 <= low <= 65535 and 1 <= high <= 65535):
        raise ValueError(f"Ports must be between 1 and 65535. Got: low={low}, high={high}")
    if low > high:
        raise ValueError(f"Low port cannot be greater than high port. Got: low={low}, high={high}")
    if low == high:
        return str(low)
    else:
        return f"{low}-{high}"


def GenerateFortinetServiceString(
    source_ranges: list[tuple[int, int]], destination_ranges: list[tuple[int, int]]
) -> str:
    """
    Generates a Fortinet service port range string by combining destination and source ranges.

    Args:
        destination_ranges: A list of tuples, where each tuple is (low_port, high_port)
                            for destination ports.
        source_ranges: A list of tuples, where each tuple is (low_port, high_port)
                    for source ports.

    Returns:
        A space-separated string suitable for Fortinet's [tcp|udp]-portrange commands.
        Example: "80:80-90 80:100 120-121:80-90 120-121:100"
    """
    output_parts = []

    for dst_low, dst_high in destination_ranges:
        dest_str = FormatFortinetPortRange(dst_low, dst_high)
        if not source_ranges:
            # If no source ranges are specified, only list destination ranges
            # (Fortinet defaults source to 1-65535)
            output_parts.append(dest_str)
        else:
            # If source ranges ARE specified, combine each dest with each source
            for src_low, src_high in source_ranges:
                src_str = FormatFortinetPortRange(src_low, src_high)
                output_parts.append(f"{dest_str}:{src_str}")

    return " ".join(output_parts)
