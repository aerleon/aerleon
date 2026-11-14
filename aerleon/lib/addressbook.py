import bisect
import collections
import heapq
import ipaddress
import itertools

from aerleon.lib.fqdn import FQDN
from aerleon.lib.nacaddr import IPv4, IPv6


class Addressbook:
    def __init__(self) -> None:
        self._fqdn_addressbook = collections.OrderedDict()
        self._ip_addressbook = collections.OrderedDict()

    def GetZoneNames(self) -> list:
        """Get each zone name contained within the address book.

        Returns:
          A list containing the names of each zone within the addressbook.
        """
        return list(self._ip_addressbook.keys())

    def Walk(self, zone=None):
        """Walks the addressbook by each zone and address/fqdns within.

        Args:
          zone_filter: A specific zone to walk rather than the entire addressbook.

        Yields:
          izone: The zone of the addressbook.
          group: The token of a set of address objects.
          ips: A list of nacaddr objects.
          fqdns: A list of FQDN objects.
        """
        for izone in self._ip_addressbook:
            if zone and izone != zone:
                continue
            groups = set(self._ip_addressbook[izone].keys())
            groups.update(list(self._fqdn_addressbook[izone].keys()))
            for group in sorted(groups):
                ips = []
                fqdns = []
                if group in self._ip_addressbook[izone]:
                    ips = self._ip_addressbook[izone][group]
                if group in self._fqdn_addressbook[izone]:
                    fqdns = self._fqdn_addressbook[izone][group]
                yield izone, group, ips, fqdns

    def GetFQDN(self, zone: str, name: str):
        """Gets an FQDN entry from the addressbook.
        Args:
          zone: The zone to retrieve from.
          name: The name of the address object to retrieve.
        Returns:
          A list of FQDN objects.
        """
        return self._fqdn_addressbook[zone][name]

    def GetAddressTokensInZone(self, zone: str):
        """Gets all address tokens in a zone.
        Args:
          zone: The zone to retrieve from.
        Returns:
          A list of address tokens."""
        return [i for i in self._ip_addressbook[zone]]

    def GetFQDNTokensInZone(self, zone: str):
        """Gets all FQDN tokens in a zone.
        Args:
          zone: The zone to retrieve from.
        Returns:
          A list of FQDN tokens
        """
        return [i for i in self._fqdn_addressbook[zone]]

    def AddFQDNs(self, zone: str, fqdn_list: list[FQDN], suffix=''):
        """Adds a list of FQDNs to the addressbook.
        Args:
          zone: The zone in which to add the FQDNs.
          fqdn_list: A list of FQDN objects.
          suffix: An optional suffix to add to the token.
        """
        if zone not in self._fqdn_addressbook:
            self._ip_addressbook[zone] = collections.defaultdict(list)
            self._fqdn_addressbook[zone] = collections.defaultdict(list)
        for fqdn in fqdn_list:
            self._fqdn_addressbook[zone][fqdn.parent_token + suffix].append(fqdn)

    def GetAddress(self, zone: str, name: str):
        """Gets an Nacaddr entry from the addressbook.
        Args:
          zone: The zone to retrieve from.
          name: The name of the address object to retrieve.
        Returns:
          A list of Nacaddr objects.
        """
        return self._ip_addressbook[zone][name]

    def AddAddresses(self, zone: str, address_list: list[IPv4 | IPv6]):
        """Create the address book configuration entries.

        Args:
          zone: the zone these objects will reside in
          address_list: a list of naming library address objects
            that will reside in the zone

        Add the given addresses to the address book for 'zone', grouped by parent_token.
        Ignore any redundant networks.
        A redundant network is fully contained by an equal or larger network in the list.
        A smaller network already present in the address book will be removed if made redundant
        when new networks are added.
        """

        def _address_key(address: IPv4 | IPv6):
            return address.version, int(address.network_address), address.prefixlen

        def _drop_subnets(address_list, integer_bounds: bool):
            """Drop contained networks from a list sorted by version, address, and mask.

            Earlier networks start at or below the current address, with broader
            networks first when starts are equal. A broadcast address at or below
            the previous maximum therefore identifies a contained network.
            """
            for _, address_list in itertools.groupby(
                address_list, key=lambda address: address.version
            ):
                last_broadcast_addr = None
                for address in address_list:
                    broadcast_addr = address.broadcast_address
                    if integer_bounds:
                        broadcast_addr = int(broadcast_addr)
                    if last_broadcast_addr is not None and broadcast_addr <= last_broadcast_addr:
                        continue
                    last_broadcast_addr = broadcast_addr
                    yield address

        if zone not in self._ip_addressbook:
            self._ip_addressbook[zone] = collections.defaultdict(list)
            self._fqdn_addressbook[zone] = collections.defaultdict(list)

        groups = collections.defaultdict(list)
        for address in address_list:
            groups[address.parent_token].append(address)

        for parent_token in sorted(groups):
            existing = self._ip_addressbook[zone][parent_token]
            combined = existing + groups[parent_token]
            integer_bounds = all(
                type(address) in (IPv4, IPv6)
                and getattr(address.network_address, 'scope_id', None) is None
                for address in combined
            )
            if integer_bounds:
                # Keep existing objects first on ties, including their metadata.
                if len(groups[parent_token]) == 1:
                    address = combined.pop()
                    bisect.insort_right(combined, address, key=_address_key)
                else:
                    combined.sort(key=_address_key)
            else:
                # Preserve scoped-address comparisons and subclass-defined sort keys.
                combined = heapq.merge(
                    existing,
                    sorted(groups[parent_token], key=ipaddress.get_mixed_type_key),
                    key=ipaddress.get_mixed_type_key,
                )
            self._ip_addressbook[zone][parent_token] = list(
                _drop_subnets(combined, integer_bounds)
            )
