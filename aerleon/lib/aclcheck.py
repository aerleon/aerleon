# Copyright 2011 Google Inc. All Rights Reserved.
# Modifications Copyright 2022-2023 Aerleon Project Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Check where hosts, ports and protocols are matched in an Aerleon policy."""

import logging
from collections import defaultdict
from collections.abc import Collection, Sequence, Set
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import DefaultDict, Literal, TypeAlias, TypedDict, cast

from typing_extensions import Self

from aerleon.lib import nacaddr, naming, policy, policy_builder, port

PossibleMatchReason: TypeAlias = Literal[
    "source-ip",
    "destination-ip",
    "source-port",
    "destination-port",
    "protocol",
    "protocol-except",
    "source-zone",
    "destination-zone",
    "first-frag",
    "frag-offset",
    "packet-length",
    "est",
    "tcp-est",
]


class Error(Exception):
    """Base error class."""


class AddressError(Error):
    """Incorrect IP address or format."""


class BadPolicyError(Error):
    """Item is not a valid policy object."""


class NoTargetError(Error):
    """Specified target platform not available in specified policy."""


class UnreachableMatchCaseError(AssertionError):
    """Unreachable match case hit - should be impossible"""

    def __init__(self, value):
        super().__init__(f"Unreachable match case hit: {value!r}")


class AclCheck:
    """Check where hosts, ports and protocols match in a NAC policy.

    Attributes:
      pol_obj: policy.Policy object.
      src: The source IP address or network.
      dst: The destination IP address or network.
      sport: The source port.
      dport: The destination port.
      proto: The protocol.
      source_zone: The source zone.
      destination_zone: The destination zone.
      matches: A list of term-related matches.
      exact_matches: A list of exact matches.

    Returns:
      An AclCheck Object

    Raises:
      port.BadPortValue: An invalid source port is used
      port.BadPortRange: A port is outside of the acceptable range 0-65535
      AddressError: Incorrect ip address or format
    """

    pol_obj: policy.Policy

    src: nacaddr.IPv4 | nacaddr.IPv6 | Literal["any", "all"]
    dst: nacaddr.IPv4 | nacaddr.IPv6 | Literal["any", "all"]
    sport: int | Literal["any", "all"]
    dport: int | Literal["any", "all"]
    proto: str | Literal["any", "all"]
    source_zone: str | Literal["any", "all"]
    destination_zone: str | Literal["any", "all"]

    matches: list["Match"]
    exact_matches: list["Match"]

    @classmethod
    def FromPolicyDict(
        cls,
        policy_dict: policy_builder.PolicyDict,
        definitions: naming.Naming,
        src: IPv4Address | IPv6Address | IPv4Network | IPv6Network | str | Literal["any", "all"],
        dst: IPv4Address | IPv6Address | IPv4Network | IPv6Network | str | Literal["any", "all"],
        sport: int | str | Literal["any", "all"],
        dport: int | str | Literal["any", "all"],
        proto: str | Literal["any", "all"],
        source_zone: str | Literal["any", "all"] | None = None,
        destination_zone: str | Literal["any", "all"] | None = None,
    ) -> Self:
        """Construct an AclCheck object from a PolicyDict + Naming object."""
        policy_obj = policy.FromBuilder(policy_builder.PolicyBuilder(policy_dict, definitions))
        return cls(
            policy_obj,
            src,
            dst,
            sport,
            dport,
            proto,
            source_zone or 'any',
            destination_zone or 'any',
        )

    def __init__(
        self,
        pol: policy.Policy,
        src: (
            IPv4Address | IPv6Address | IPv4Network | IPv6Network | str | Literal["any", "all"]
        ) = 'any',
        dst: (
            IPv4Address | IPv6Address | IPv4Network | IPv6Network | str | Literal["any", "all"]
        ) = 'any',
        sport: int | str | Literal["any", "all"] = 'any',
        dport: int | str | Literal["any", "all"] = 'any',
        proto: str | Literal["any", "all"] = 'any',
        source_zone: str | Literal["any", "all"] = 'any',
        destination_zone: str | Literal["any", "all"] = 'any',
    ) -> None:

        self.pol_obj = pol

        # validate proto
        if proto is None:
            self.proto = 'any'
        else:
            self.proto = proto

        # validate source port
        if not sport or sport == 'any':
            self.sport = 'any'
        elif sport == 'all':
            self.sport = 'all'
        else:
            self.sport = port.Port(sport)

        # validate destination port
        if not dport or dport == 'any':
            self.dport = 'any'
        elif dport == 'all':
            self.dport = 'all'
        else:
            self.dport = port.Port(dport)

        # validate source address
        if not src or src == 'any':
            self.src = 'any'
        elif src == 'all':
            self.src = 'all'
        else:
            try:
                self.src = nacaddr.IP(src)
            except ValueError:
                raise AddressError(f'bad source address: {src}\n')

        # validate destination address
        if not dst or dst == 'any':
            self.dst = 'any'
        elif dst == 'all':
            self.dst = 'all'
        else:
            try:
                self.dst = nacaddr.IP(dst)
            except ValueError:
                raise AddressError(f'bad destination address: {dst}\n')

        # validate source zone
        if not source_zone or source_zone == 'any':
            self.source_zone = 'any'
        else:
            self.source_zone = str(source_zone)

        # validate destination zone
        if not destination_zone or destination_zone == 'any':
            self.destination_zone = 'any'
        else:
            self.destination_zone = str(destination_zone)

        if not isinstance(self.pol_obj, (policy.Policy)):
            raise BadPolicyError('Policy object is not valid.')

        self.matches = []
        self.exact_matches = []
        for header, terms in self.pol_obj.filters:
            filtername = header.target[0].options[0]
            for term in terms:
                possible: set[PossibleMatchReason] = set()
                """Reasons a term may/may not match, depending on more specific information or context"""

                logging.debug('checking term: %s', term.name)

                match self._AddrMatch(self.src, term.source_address):
                    case "full":
                        logging.debug('srcaddr matches: %s', self.src)
                    case "partial":
                        possible.add('source-ip')
                        logging.debug('srcaddr too broadly matches: %s', self.src)
                    case False:
                        logging.debug('srcaddr does not match')
                        continue
                    case _:
                        raise UnreachableMatchCaseError

                match self._AddrMatch(self.dst, term.destination_address):
                    case "full":
                        logging.debug('dstaddr matches: %s', self.dst)
                    case "partial":
                        possible.add('destination-ip')
                        logging.debug('dstaddr too broadly matches: %s', self.dst)
                    case False:
                        logging.debug('dstaddr does not match')
                        continue
                    case _:
                        raise UnreachableMatchCaseError

                # source-zone matching if requested. If the term does not specify
                # a source_zone, treat it as 'any' (match all zones).
                match self._ZoneMatch(self.source_zone, term.source_zone):
                    case "full":
                        logging.debug('source zone matches: %s', self.source_zone)
                    case "partial":
                        possible.add('source-zone')
                        logging.debug('source zone too broadly matches: %s', self.source_zone)
                    case False:
                        logging.debug('source zone does not match')
                        continue
                    case _:
                        raise UnreachableMatchCaseError

                # destination-zone matching if requested. If the term does not specify
                # a destination_zone, treat it as 'any' (match all zones).
                match self._ZoneMatch(self.destination_zone, term.destination_zone):
                    case "full":
                        logging.debug('destination zone matches: %s', self.destination_zone)
                    case "partial":
                        possible.add('destination-zone')
                        logging.debug(
                            'destination zone too broadly matches: %s', self.destination_zone
                        )
                    case False:
                        logging.debug('destination zone does not match')
                        continue
                    case _:
                        raise UnreachableMatchCaseError

                match self._PortMatch(self.sport, term.source_port):
                    case "full":
                        logging.debug('sport matches: %s', self.sport)
                    case "partial":
                        possible.add('source-port')
                        logging.debug('sport too broadly matches: %s', self.sport)
                    case False:
                        logging.debug('sport does not match')
                        continue
                    case _:
                        raise UnreachableMatchCaseError

                match self._PortMatch(self.dport, term.destination_port):
                    case "full":
                        logging.debug('dport matches: %s', self.dport)
                    case "partial":
                        possible.add('destination-port')
                        logging.debug('dport too broadly matches: %s', self.dport)
                    case False:
                        logging.debug('dport does not match')
                        continue
                    case _:
                        raise UnreachableMatchCaseError

                if not term.protocol or self.proto == "any":
                    logging.debug('proto matches: %s', self.proto)
                elif self.proto == "all":
                    possible.add('protocol')
                    logging.debug('proto too broadly matches: %s', self.proto)
                elif self.proto not in term.protocol:
                    logging.debug('proto does not match')
                    continue

                if not term.protocol_except:
                    logging.debug('proto not excepted: %s', self.proto)
                elif self.proto == "all":
                    possible.add('protocol-except')
                    logging.debug(
                        'proto partially excepted by term, too broadly matches: %s', self.proto
                    )
                elif self.proto in term.protocol_except:
                    logging.debug('protocol excepted by term, no match.')
                    continue

                if not term.action:  # avoid any verbatim
                    logging.debug('term had no action (verbatim?), no match.')
                    continue
                logging.debug('term has an action')

                possible.update(self._PossibleMatch(term))
                self.matches.append(Match(filtername, term.name, possible, term.action, term.qos))
                if possible:
                    logging.debug('term has options: %s, not treating as exact match', possible)
                    continue

                # if we get here then we have a match, and if the action isn't next and
                # there are no possibles, then this is a "definite" match and we needn't
                # look for any further matches (i.e. later terms may match, but since
                # we'll never get there we shouldn't report them)
                if 'next' not in term.action:
                    self.exact_matches.append(
                        Match(filtername, term.name, frozenset(), term.action, term.qos)
                    )
                    break

    def Matches(self) -> list["Match"]:
        """Return list of matched terms."""
        return self.matches

    def ExactMatches(self) -> list["Match"]:
        """Return matched terms, but not terms with possibles or action next."""
        return self.exact_matches

    def ActionMatch(
        self,
        action: str | Literal['any'] = 'any',
    ) -> list["Match"]:
        """Return list of matched terms with specified actions."""
        match_list = []
        for match in self.matches:
            if match.action:
                if not match.possibles:
                    if action == 'any' or action in match.action:
                        match_list.append(match)
        return match_list

    def DescribeMatches(self) -> str:
        """Provide sentence descriptions of matches.

        Returns:
          ret_str: text sentences describing matches
        """
        ret_str = []
        for match in self.matches:
            text = str(match)
            ret_str.append(text)
        return '\n'.join(ret_str)

    def __str__(self) -> str:
        text = []
        summary = self.Summarize()
        for filter, terms in summary.items():
            text.append(f"{' ' * 2}filter: {filter}")
            for matches in terms.values():
                text.append(matches['message'])
        return '\n'.join(text)

    class SummarizeMatchTermDetails(TypedDict):
        possibles: frozenset[PossibleMatchReason]
        message: str

    def Summarize(
        self,
    ) -> DefaultDict[str, DefaultDict[str, "AclCheck.SummarizeMatchTermDetails"]]:
        summary = cast(
            DefaultDict[str, DefaultDict[str, "AclCheck.SummarizeMatchTermDetails"]],
            defaultdict(lambda: defaultdict(dict)),
        )
        for match in self.matches:
            summary[match.filter][match.term]["possibles"] = match.possibles
            text = []
            if match.possibles:
                text.append(f"{' ' * 10}term: {match.term} (possible match)")
                text.append(f"{' ' * 16}{match.action} if {sorted(match.possibles)}")
            else:
                text.append(f"{' ' * 10}term: {match.term}")
                text.append(f"{' ' * 16}{match.action}")
            summary[match.filter][match.term]["message"] = '\n'.join(text)
        return summary

    def _PossibleMatch(self, term) -> frozenset[PossibleMatchReason]:
        """Address overly broad partial matches and ignore some options and keywords that are edge cases.

        Args:
          term: term object to examine for edge-cases

        Returns:
          ret_str: a list of reasons this term may possibly match
        """
        ret_str = set()
        if 'first-fragment' in term.option:
            ret_str.add('first-frag')
        if term.fragment_offset:
            ret_str.add('frag-offset')
        if term.packet_length:
            ret_str.add('packet-length')
        if 'established' in term.option:
            ret_str.add('est')
        if 'tcp-established' in term.option and 'tcp' in term.protocol:
            ret_str.add('tcp-est')
        return frozenset(ret_str)

    def _ZoneMatch(
        self, zone: str | Literal["any", "all"], term_zone: Collection[str]
    ) -> Literal["full", "partial", False]:
        """Check if zone matches term zone.

        Args:
          zone: A string for the zone to check
          term_zone: A collection of zones from the term
        """
        if not term_zone or zone == 'any':
            return "full"
        elif zone == 'all':
            return "partial"
        elif zone in term_zone:
            return "full"
        else:
            return False

    def _PortMatch(
        self, port: int | Literal["any", "all"], term_ports: list[tuple[int, int]]
    ) -> Literal["full", "partial", False]:
        """Check if a port matches a port list"""
        if not term_ports or port == 'any':
            return "full"
        elif port == 'all':
            return "partial"
        elif self._PortInside(port, term_ports):
            return "full"
        else:
            return False

    def _AddrMatch(
        self,
        addr: nacaddr.IPv4 | nacaddr.IPv6 | Literal["any", "all"],
        addresses: Sequence[nacaddr.IPv4 | nacaddr.IPv6],
    ) -> Literal["full", "partial", False]:
        """Check if an address matches another address or group of addresses,
        as a full match, partial match, or no match.

        Args:
          addr: An IP address or network or text 'any'
          addresses: A list of ipaddr network or host addresses

        Returns:
          "full": if addr is fully matched by any of addresses (i.e. addr is a subnet) or is "any"
          "partial": if addr is partially matched by any of addresses, but not fully matched (i.e. addr is a supernet)
          False: if addr is not matched by any of addresses
        """
        if not addresses:
            return "full"  # always "full" if term has nothing to match
        if addr == 'any':
            # note that "any" behaves differently than 0.0.0.0/0 or ::/0 (which will return "partial")
            return "full"
        if addr == 'all':
            return "partial"

        partial_match: bool = False
        for ip in addresses:
            # ipaddr can incorrectly report ipv4 as contained with ipv6 addrs
            if addr.subnet_of(ip):
                return "full"
            elif addr.supernet_of(ip):
                partial_match = True

        if partial_match:
            return "partial"
        else:
            return False

    def _PortInside(self, myport: int, port_list: list[tuple[int, int]]) -> bool:
        """Check if a port matches a port list

        Args:
          myport: port number
          port_list: list of port ranges

        Returns:
          bool: True or False
        """
        if any(range_start <= myport <= range_end for range_start, range_end in port_list):
            return True
        return False


class Match:
    """A matching term and its associate values."""

    filter: str
    term: str
    possibles: frozenset[PossibleMatchReason]
    action: str
    qos: object | None

    def __init__(
        self,
        filtername: str,
        term: str,
        possibles: Set[PossibleMatchReason],
        action: Sequence[str],
        qos=None,
    ) -> None:
        self.filter = filtername
        self.term = term
        self.possibles = frozenset(possibles)
        self.action = action[0]
        self.qos = qos

    def __str__(self) -> str:
        text = ''
        if self.possibles:
            text += f"possible {self.action}"
        else:
            text += self.action
        text += f" in term {self.term} of filter {self.filter}"
        if self.possibles:
            text += f" with factors: {', '.join(sorted(self.possibles))!s}"
        return text


def main() -> None:
    pass


if __name__ == '__main__':
    main()
