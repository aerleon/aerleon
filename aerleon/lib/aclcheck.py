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

from aerleon.lib import nacaddr, naming, policy, policy_builder, port


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
      pol: policy.Policy object.
      src: A string for the source address.
      dst: A string for the destination address.
      sport: A string for the source port.
      dport: A string for the destination port.
      proto: A string for the protocol.
      matches: A list of term-related matches.
      exact_matches: A list of exact matches.

    Returns:
      An AclCheck Object

    Raises:
      port.BadPortValue: An invalid source port is used
      port.BadPortRange: A port is outside of the acceptable range 0-65535
      AddressError: Incorrect ip address or format

    """

    @classmethod
    def FromPolicyDict(
        cls,
        policy_dict: policy_builder.PolicyDict,
        definitions: naming.Naming,
        src,
        dst,
        sport,
        dport,
        proto,
    ):
        """Construct an AclCheck object from a PolicyDict + Naming object."""
        policy_obj = policy.FromBuilder(policy_builder.PolicyBuilder(policy_dict, definitions))
        return cls(policy_obj, src, dst, sport, dport, proto)

    def __init__(
        self,
        pol: policy.Policy,
        src='any',
        dst='any',
        sport='any',
        dport='any',
        proto='any',
        source_zone='any',
        destination_zone='any',
    ):
        self.pol_obj = pol
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
        # validate zones
        if not source_zone or source_zone == 'any':
            self.source_zone = 'any'
        else:
            self.source_zone = str(source_zone)

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
                if not self._AddrInside(self.src, term.source_address):
                    logging.debug('srcaddr does not match')
                    continue
                logging.debug('srcaddr matches: %s', self.src)
                if not self._AddrInside(self.dst, term.destination_address):
                    logging.debug('dstaddr does not match')
                    continue
                logging.debug('dstaddr matches: %s', self.dst)
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
                possible = self._PossibleMatch(term)
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

    def Matches(self):
        """Return list of matched terms."""
        return self.matches

    def ExactMatches(self):
        """Return matched terms, but not terms with possibles or action next."""
        return self.exact_matches

    def ActionMatch(self, action='any'):
        """Return list of matched terms with specified actions."""
        match_list = []
        for match in self.matches:
            if match.action:
                if not match.possibles:
                    if action == 'any' or action in match.action:
                        match_list.append(match)
        return match_list

    def DescribeMatches(self):
        """Provide sentence descriptions of matches.

        Returns:
          ret_str: text sentences describing matches
        """
        ret_str = []
        for match in self.matches:
            text = str(match)
            ret_str.append(text)
        return '\n'.join(ret_str)

    def __str__(self):
        text = []
        summary = self.Summarize()
        for filter, terms in summary.items():
            text.append(f"{' ' * 2}filter: {filter}")
            for matches in terms.values():
                text.append(matches['message'])
        return '\n'.join(text)

    def Summarize(self):
        summary = defaultdict(lambda: defaultdict(dict))
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

    def _PossibleMatch(self, term):
        """Ignore some options and keywords that are edge cases.

        Args:
          term: term object to examine for edge-cases

        Returns:
          ret_str: a list of reasons this term may possible match
        """
        ret_str = []
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
          term_zone: A list of zones from the term
        """
        if term_zone == [] or zone == 'any':
            return True
        if zone not in term_zone:
            return False
        return True

    def _AddrInside(self, addr, addresses):
        """Check if address is matched in another address or group of addresses.

        Args:
          addr: An ipaddr network or host address or text 'any'
          addresses: A list of ipaddr network or host addresses

        Returns:
          bool: True of false
        """
        if addr == 'any':
            return True  # always true if we match for any addr
        if not addresses:
            return True  # always true if term has nothing to match
        for ip in addresses:
            # ipaddr can incorrectly report ipv4 as contained with ipv6 addrs
            if addr.subnet_of(ip):
                return True
        return False

    def _PortInside(self, myport, port_list):
        """Check if port matches in a port or group of ports.

        Args:
          myport: port number
          port_list: list of ports

        Returns:
          bool: True of false
        """
        if myport == 'any':
            return True
        if [x for x in port_list if x[0] <= myport <= x[1]]:
            return True
        return False


class Match:
    """A matching term and its associate values."""

    def __init__(self, filtername, term, possibles, action, qos=None):
        self.filter = filtername
        self.term = term
        self.possibles = possibles
        self.action = action[0]
        self.qos = qos

    def __str__(self):
        text = ''
        if self.possibles:
            text += f"possible {self.action}"
        else:
            text += self.action
        text += f" in term {self.term} of filter {self.filter}"
        if self.possibles:
            text += f" with factors: {', '.join(self.possibles)!s}"
        return text


def main():
    pass


if __name__ == '__main__':
    main()
