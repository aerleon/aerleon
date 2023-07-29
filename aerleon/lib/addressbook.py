import collections
import heapq
import ipaddress
import itertools
from typing import List, Union

from aerleon.lib.fqdn import FQDN
from aerleon.lib.nacaddr import IPv4, IPv6


class Addressbook:
    def __init__(self) -> None:
        self._fqdn_addressbook = collections.OrderedDict()
        self._ip_addressbook = collections.OrderedDict()

    def WalkAddressBook(self):
        return self._walk()
    def _walk(self):
        for zone in self._ip_addressbook:
            groups = self._ip_addressbook[zone].keys()
            groups.extend(self._fqdn_addressbook[zone].keys())
            for group in groups:
                ips = []
                if group in self._ip_addressbook[zone]:
                    ips = self._ip_addressbook[zone][group]
                yield zone, group
        
    def GetFQDN(self, zone: str, name: str):
        return self._fqdn_addressbook[zone][name]

    def GetAddressTokensInZone(self, zone: str):
        return [i for i in self._ip_addressbook['zone']]

    def GetFQDNTokensInZone(self, zone: str):
        return [i for i in self._fqdn_addressbook['zone']]

    def AddFQDNs(self, zone: str, fqdn_list: List[FQDN]):
        if zone not in self._fqdn_addressbook:
            self._ip_addressbook[zone] = collections.defaultdict(list)
            self._fqdn_addressbook[zone] = collections.defaultdict(list)
        for fqdn in fqdn_list:
            self._fqdn_addressbook[zone][fqdn.parent_token].append(fqdn)

    def GetAddress(self, zone: str, name: str):
        return self._ip_addressbook[zone][name]

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

        if zone not in self._ip_addressbook:
            self._ip_addressbook[zone] = collections.defaultdict(list)
            self._fqdn_addressbook[zone] = collections.defaultdict(list)

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
            self._ip_addressbook[zone][parent_token] = list(
                heapq.merge(
                    self._ip_addressbook[zone][parent_token],
                    address_list,
                    key=ipaddress.get_mixed_type_key,
                )
            )

            # drop redundant addresses and networks
            self._ip_addressbook[zone][parent_token] = list(
                _drop_subnets(self._ip_addressbook[zone][parent_token])
            )
