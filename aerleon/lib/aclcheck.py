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
from collections.abc import Collection, Sequence
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Literal, TypeAlias, TypedDict, cast

from typing_extensions import Self

from aerleon.lib import nacaddr, naming, policy, policy_builder, port

PossibleMatchReason: TypeAlias = Literal[
    "source-ip",
    "destination-ip",
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

    src: nacaddr.IPv4 | nacaddr.IPv6 | Literal["any"]
    dst: nacaddr.IPv4 | nacaddr.IPv6 | Literal["any"]
    sport: int | Literal["any"]
    dport: int | Literal["any"]
    proto: str | Literal["any"]
    source_zone: str | Literal["any"]
    destination_zone: str | Literal["any"]

    matches: list["Match"]
    exact_matches: list["Match"]

    @classmethod
    def FromPolicyDict(
        cls,
        policy_dict: policy_builder.PolicyDict,
        definitions: naming.Naming,
        src: IPv4Address | IPv6Address | IPv4Network | IPv6Network | str | Literal["any"],
        dst: IPv4Address | IPv6Address | IPv4Network | IPv6Network | str | Literal["any"],
        sport: int | str | Literal["any"],
        dport: int | str | Literal["any"],
        proto: str | Literal["any"],
        source_zone: str | Literal["any"] | None = None,
        destination_zone: str | Literal["any"] | None = None,
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
        src: IPv4Address | IPv6Address | IPv4Network | IPv6Network | str | Literal["any"] = 'any',
        dst: IPv4Address | IPv6Address | IPv4Network | IPv6Network | str | Literal["any"] = 'any',
        sport: int | str | Literal["any"] = 'any',
        dport: int | str | Literal["any"] = 'any',
        proto: str | Literal["any"] = 'any',
        source_zone: str | Literal["any"] = 'any',
        destination_zone: str | Literal["any"] = 'any',
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
        else:
            self.sport = port.Port(sport)

        # validate destination port
        if not dport or dport == 'any':
            self.dport = 'any'
        else:
            self.dport = port.Port(dport)

        # validate source address
        if not src or src == 'any':
            self.src = 'any'
        else:
            try:
                self.src = nacaddr.IP(src)
            except ValueError:
                raise AddressError(f'bad source address: {src}\n')

        # validate destination address
        if not dst or dst == 'any':
            self.dst = 'any'
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
                possible = []
                logging.debug('checking term: %s', term.name)

                match self._AddrMatch(self.src, term.source_address):
                    case "full":
                        src_too_broad = False
                        logging.debug('srcaddr matches: %s', self.src)
                    case "partial":
                        src_too_broad = True
                        logging.debug('srcaddr too broadly matches: %s', self.src)
                    case False:
                        logging.debug('srcaddr does not match')
                        continue
                    case _:
                        raise AssertionError('unhandled switch case')

                match self._AddrMatch(self.dst, term.destination_address):
                    case "full":
                        dst_too_broad = False
                        logging.debug('dstaddr matches: %s', self.dst)
                    case "partial":
                        dst_too_broad = True
                        logging.debug('dstaddr too broadly matches: %s', self.dst)
                    case False:
                        logging.debug('dstaddr does not match')
                        continue
                    case _:
                        raise AssertionError('unhandled switch case')

                # source-zone matching if requested. If the term does not specify
                # a source_zone, treat it as 'any' (match all zones).
                if not self._ZoneMatch(self.source_zone, term.source_zone):
                    logging.debug('source zone does not match')
                    continue
                logging.debug('source zone matches: %s', self.source_zone)

                # destination-zone matching if requested. If the term does not specify
                # a destination_zone, treat it as 'any' (match all zones).
                if not self._ZoneMatch(self.destination_zone, term.destination_zone):
                    logging.debug('destination zone does not match')
                    continue
                logging.debug('destination zone matches: %s', self.destination_zone)

                if (
                    self.sport != 'any'
                    and term.source_port
                    and not self._PortInside(self.sport, term.source_port)
                ):
                    logging.debug('sport does not match')
                    continue
                logging.debug('sport matches: %s', self.sport)

                if (
                    self.dport != 'any'
                    and term.destination_port
                    and not self._PortInside(self.dport, term.destination_port)
                ):
                    logging.debug('dport does not match')
                    continue
                logging.debug('dport matches: %s', self.dport)

                if self.proto != 'any' and term.protocol and self.proto not in term.protocol:
                    logging.debug('proto does not match')
                    continue
                logging.debug('proto matches: %s', self.proto)

                if term.protocol_except and self.proto in term.protocol_except:
                    logging.debug('protocol excepted by term, no match.')
                    continue
                logging.debug('proto not excepted: %s', self.proto)

                if not term.action:  # avoid any verbatim
                    logging.debug('term had no action (verbatim?), no match.')
                    continue
                logging.debug('term has an action')

                possible = self._PossibleMatch(term, src_too_broad, dst_too_broad)
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
                        Match(filtername, term.name, [], term.action, term.qos)
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
        possibles: list[PossibleMatchReason]
        message: str

    def Summarize(
        self,
    ) -> defaultdict[str, defaultdict[str, "AclCheck.SummarizeMatchTermDetails"]]:
        summary: defaultdict[str, defaultdict[str, "AclCheck.SummarizeMatchTermDetails"]] = cast(
            defaultdict[str, defaultdict[str, "AclCheck.SummarizeMatchTermDetails"]],
            defaultdict(lambda: defaultdict(dict)),
        )
        for match in self.matches:
            summary[match.filter][match.term]["possibles"] = match.possibles
            text = []
            if match.possibles:
                text.append(f"{' ' * 10}term: {match.term} (possible match)")
                text.append(f"{' ' * 16}{match.action} if {match.possibles}")
            else:
                text.append(f"{' ' * 10}term: {match.term}")
                text.append(f"{' ' * 16}{match.action}")
            summary[match.filter][match.term]["message"] = '\n'.join(text)
        return summary

    def _PossibleMatch(
        self, term, src_too_broad: bool, dst_too_broad: bool
    ) -> list[PossibleMatchReason]:
        """Address overly broad partial matches and ignore some options and keywords that are edge cases.

        Args:
          term: term object to examine for edge-cases
          src_too_broad: boolean indicating if only a subnet of src matched the term
          dst_too_broad: boolean indicating if only a subnet of dst matched the term

        Returns:
          ret_str: a list of reasons this term may possibly match
        """
        ret_str = []
        if src_too_broad:
            ret_str.append('source-ip')
        if dst_too_broad:
            ret_str.append('destination-ip')
        if 'first-fragment' in term.option:
            ret_str.append('first-frag')
        if term.fragment_offset:
            ret_str.append('frag-offset')
        if term.packet_length:
            ret_str.append('packet-length')
        if 'established' in term.option:
            ret_str.append('est')
        if 'tcp-established' in term.option and 'tcp' in term.protocol:
            ret_str.append('tcp-est')
        return ret_str

    def _ZoneMatch(self, zone: str | Literal["any"], term_zone: Collection[str]) -> bool:
        """Check if zone matches term zone.

        Args:
          zone: A string for the zone to check
          term_zone: A collection of zones from the term
        """
        if not term_zone or zone == 'any':
            return True
        if zone not in term_zone:
            return False
        return True

    def _AddrMatch(
        self,
        addr: nacaddr.IPv4 | nacaddr.IPv6 | Literal["any"],
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

    def _PortInside(self, myport: int | Literal["any"], port_list: list[tuple[int, int]]) -> bool:
        """Check if a port matches a port list

        Args:
          myport: port number
          port_list: list of port ranges

        Returns:
          bool: True if `myport` is within any [start, end] port range in `port_list` (inclusive), otherwise False
        """
        if myport == 'any':
            return True
        if any(range_start <= myport <= range_end for range_start, range_end in port_list):
            return True
        return False


class Match:
    """A matching term and its associate values."""

    filter: str
    term: str
    possibles: list[PossibleMatchReason]
    action: str
    qos: str | None

    def __init__(
        self,
        filtername: str,
        term: str,
        possibles: list[PossibleMatchReason],
        action: Sequence[str],
        qos: str | None = None,
    ) -> None:
        self.filter = filtername
        self.term = term
        self.possibles = possibles
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
            text += f" with factors: {', '.join(self.possibles)!s}"
        return text


def main() -> None:
    pass


if __name__ == '__main__':
    main()
