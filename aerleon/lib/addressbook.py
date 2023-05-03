import collections
import heapq
import ipaddress
import itertools
from dataclasses import dataclass
from typing import List, Union

from aerleon.lib.nacaddr import IPv4, IPv6


@dataclass
class AddressEntry:
    addresses: List[Union[IPv4, IPv6]]
    hostnames: List[str]


class Addressbook:
    def __init__(self) -> None:
        self.addressbook = collections.OrderedDict()

    def AddHostname(self, zone: str, hostname_list: List[str]):
        """Create an entry in the addressbook for a hostname.
        
        Args:
          zone: zone within the addressbook to insert into.
          hostname_list: A list of hostnames to add to the addressbook.
        """
        if zone not in self.addressbook:
            self.addressbook[zone] = collections.defaultdict(lambda: AddressEntry([], []))
        for parent_token, hostname_list in itertools.groupby(
            sorted(
                hostname_list,
                key=lambda host: (
                    host.parent_token,
                    ipaddress.get_mixed_type_key(host),
                ),
            ),
            key=lambda host: host.parent_token,
        ):
            self.addressbook[zone][parent_token].hostnames = [i.name for i in hostname_list]

    def AddAddresses(self, zone: str, address_list: List[Union[IPv4, IPv6]]):
        """Create the address book configuration entries.

        Args:
          zone: the zone these objects will reside in
          address_list: a list of naming library address objects
            that will reside in the zone

        _BuildAddressBook will add the given addresses to the address book
        for 'zone', grouped by address.parent_name. It will ignore any redundant networks.
        A redundant network is fully contained by an equal or larger network in the list.
        A smaller network already present in the address book will be removed if made redundant
        when new networks are added.
        """

        def _drop_subnets(address_list: List[Union[IPv4, IPv6]]):
            """Remove any network contained by another network in this list.

            Args:
                address_list: a list of IP objects sorted ascending by version and address.

            Yields:
                yields the items of the address list in order with redundant subnets removed.

            _drop_subnets uses the following strategy to identify and discard redundant subnets:
            (1) Assume address_list is a list of IPv{4,6} networks.
                (1A) The address_list must be sorted by (
                    address.version,
                    address.network_address,
                    address.netmask).
            (2) Partition the list by IP version.
            (3) Each partition is sorted by network_address (ascending) and netmask (ascending).
            (4) Network_address gives the low end of the network IP range and broadcast_address gives the
                high end. Broadcast address is always calculated as network_address | netmask.
            (5) A network is a subnet of another network if and only if it has broacast_address less than or equal
                to the highest broadcast address seen thus far. All networks seen thus far have network_address
                lower than or equal to network_address (the low end), so any time broadcast_address (the high end) is
                lower than or equal to the previous max we have definitely found a redundant subnet. And because all
                networks seen thus far have network_address lower than or equal to network_address AND a lower netmask,
                no previous network can be a subnet of the current network (unless they are exactly equal).
            """
            # Partition by IP version: address_list may contain mixed IPv4 / IPv6 addresses
            for _, address_list in itertools.groupby(
                address_list, key=lambda address: address.version
            ):
                last_broadcast_addr = None
                for address in address_list:
                    if (
                        last_broadcast_addr is not None
                        and address.broadcast_address <= last_broadcast_addr
                    ):
                        continue
                    last_broadcast_addr = address.broadcast_address
                    yield address

        if zone not in self.addressbook:
            self.addressbook[zone] = collections.defaultdict(lambda: AddressEntry([], []))

        # sort by (parent_token, version, address),
        # then partition by parent_token
        # the implicit sort key for address (always a network) is (version, network_address, netmask)
        for parent_token, address_list in itertools.groupby(
            sorted(
                address_list,
                key=lambda address: (
                    address.parent_token,
                    ipaddress.get_mixed_type_key(address),
                ),
            ),
            key=lambda address: address.parent_token,
        ):
            # merge sorted lists of IP objects
            self.addressbook[zone][parent_token].addresses = list(
                heapq.merge(
                    self.addressbook[zone][parent_token].addresses,
                    address_list,
                    key=ipaddress.get_mixed_type_key,
                )
            )

            # drop redundant addresses and networks
            self.addressbook[zone][parent_token].addresses = list(
                _drop_subnets(self.addressbook[zone][parent_token].addresses)
            )
