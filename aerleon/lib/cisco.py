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

"""Cisco generator."""

import ipaddress
from typing import Any, Union, cast

from absl import logging

from aerleon.lib import aclgenerator, addressbook, nacaddr, summarizer
from aerleon.lib.nacaddr import IPv4, IPv6
from aerleon.lib.policy import Policy, Term
from aerleon.lib.summarizer import DSMNet

_ACTION_TABLE = {
    'accept': 'permit',
    'deny': 'deny',
    'reject': 'deny',
    'next': '! next',
    'reject-with-tcp-rst': 'deny',  # tcp rst not supported
}

_COMMENT_MAX_WIDTH = 70


# generic error class
class Error(aclgenerator.Error):
    """Generic error class."""


class CiscoDuplicateTermError(Error):
    """Raised on duplicate term names."""


class CiscoNextIpError(Error):
    """Raised when next-ip is misconfigured."""


class UnsupportedCiscoAccessListError(Error):
    """Raised when we're give a non named access list."""


class StandardAclTermError(Error):
    """Raised when there is a problem in a standard access list."""


class ExtendedACLTermError(Error):
    """Raised when there is a problem in an extended access list."""


class TermStandard:
    """A single standard ACL Term."""

    def __init__(
        self, term: Term, filter_name: str, platform: str = 'cisco', verbose: bool = True
    ) -> None:
        self.term = term
        self.filter_name = filter_name
        self.platform = platform
        self.options = []
        self.logstring = ''
        self.dscpstring = ''
        self.verbose = verbose
        # sanity checking for standard acls
        if self.term.protocol:
            raise StandardAclTermError('Standard ACLs cannot specify protocols')
        if self.term.icmp_type:
            raise StandardAclTermError(
                'ICMP Type specifications are not permissible in standard ACLs'
            )
        if (
            self.term.source_address
            or self.term.source_address_exclude
            or self.term.destination_address
            or self.term.destination_address_exclude
        ):
            raise StandardAclTermError('Standard ACLs cannot use source or destination addresses')
        if self.term.option:
            raise StandardAclTermError('Standard ACLs prohibit use of options')
        if self.term.source_port or self.term.destination_port:
            raise StandardAclTermError('Standard ACLs prohibit use of port numbers')
        if self.term.logging:
            logging.warning(
                'WARNING: Standard ACL logging is set in filter %s, term %s and '
                'may not implemented on all IOS versions',
                self.filter_name,
                self.term.name,
            )
            self.logstring = ' log'
        if self.term.dscp_match:
            logging.warning(
                'WARNING: dscp-match is set in filter %s, term %s and may not be '
                'implemented on all IOS version',
                self.filter_name,
                self.term.name,
            )
            self.dscpstring = f" dscp{self.term.dscp_match}"

    def __str__(self) -> str:
        ret_str = []

        # Term verbatim output - this will skip over normal term creation
        # code by returning early.  Warnings provided in policy.py.
        if self.term.verbatim:
            for next_verbatim in self.term.verbatim:
                if next_verbatim[0] == self.platform:
                    ret_str.append(str(next_verbatim[1]))
            return '\n'.join(ret_str)

        v4_addresses = [x for x in self.term.address if not isinstance(x, nacaddr.IPv6)]
        prefix = ''
        if self.filter_name.isdigit():
            prefix = f'access-list {self.filter_name}'

        if self.verbose:
            ret_str.append(f'{prefix} remark {self.term.name}')
            comments = aclgenerator.WrapWords(self.term.comment, _COMMENT_MAX_WIDTH)
            for comment in comments:
                ret_str.append(f'{prefix} remark {comment}')

        action = _ACTION_TABLE.get(str(self.term.action[0]))
        if v4_addresses:
            for addr in v4_addresses:
                if self.platform == 'arista':
                    if addr.prefixlen == 32:
                        ret_str.append(
                            f'{prefix} {action} host {addr.network_address}{self.logstring}{self.dscpstring}'
                        )
                    else:
                        ret_str.append(
                            f'{prefix} {action} {addr.network_address}/{addr.prefixlen}{self.logstring}{self.dscpstring}'
                        )
                elif addr.prefixlen == 32:
                    ret_str.append(
                        f'{prefix} {action} {addr.network_address}{self.logstring}{self.dscpstring}'
                    )
                else:
                    ret_str.append(
                        f'{prefix} {action} {addr.network_address} {addr.hostmask}{self.logstring}{self.dscpstring}'
                    )
        else:
            ret_str.append(f'{prefix} {action} any{self.logstring}{self.dscpstring}')

        return '\n'.join(ret_str)


class ObjectGroup:
    """Used for printing out the object group definitions.

    since the ports don't store the token name information, we have
    to fudge their names.  ports will be written out like

      object-group port <low_port>-<high_port>
        range <low-port> <high-port>
      exit

    where as the addressess can be written as

      object-group address ipv4 first-term-source-address
        172.16.0.0
        172.20.0.0 255.255.0.0
        172.22.0.0 255.128.0.0
        172.24.0.0
        172.28.0.0
      exit
    """

    def __init__(self) -> None:
        self.filter_name = ''
        self.addressbook = addressbook.Addressbook()
        self.terms = []

    def AddTerm(self, term: Term) -> None:
        if term.source_address:
            self.addressbook.AddAddresses('', term.source_address)
        if term.destination_address:
            self.addressbook.AddAddresses('', term.destination_address)
        self.terms.append(term)

    def AddName(self, filter_name: str) -> None:
        self.filter_name = filter_name

    def __str__(self) -> str:
        ret_str = ['\n']
        # netgroups will contain two-tuples of group name string and family int.
        netgroups = set()
        ports = {}

        # I don't have an easy way get the token name used in the pol file
        # w/o reading the pol file twice (with some other library) or doing
        # some other ugly hackery. Instead, the entire block of source and dest
        # addresses for a given term is given a unique, computable name which
        # is not related to the NETWORK.net token name.  that's what you get
        # for using cisco, which has decided to implement its own meta language.

        # Create network object-groups
        for zone, name, ips, _ in self.addressbook.Walk():
            for version in (4, 6):
                vips = [i for i in ips if i.version == version]
                if vips:
                    ret_str.append(f'object-group network ipv{version} {name}')
                    for ip in vips:
                        ret_str.append(f' {ip.network_address}/{ip.prefixlen}')
                    ret_str.append('exit\n')

            # Create port object-groups
        for term in self.terms:
            for port in term.source_port + term.destination_port:
                if not port:
                    continue
                port_key = f'{port[0]}-{port[1]}'
                if port_key not in ports:
                    ports[port_key] = True
                    ret_str.append(f'object-group port {port_key}')
                    if port[0] != port[1]:
                        ret_str.append(' range %d %d' % (port[0], port[1]))
                    else:
                        ret_str.append(' eq %d' % port[0])
                    ret_str.append('exit\n')
        return '\n'.join(ret_str)


class PortMap:
    """Map port numbers to service names."""

    # Define port mappings common to all protocols
    _PORTS_TCP = {
        179: 'bgp',
        19: 'chargen',
        514: 'cmd',
        13: 'daytime',
        9: 'discard',
        53: 'domain',
        7: 'echo',
        512: 'exec',
        79: 'finger',
        21: 'ftp',
        20: 'ftp-data',
        70: 'gopher',
        443: 'https',
        113: 'ident',
        194: 'irc',
        543: 'klogin',
        544: 'kshell',
        389: 'ldap',
        636: 'ldaps',
        513: 'login',
        515: 'lpd',
        2049: 'nfs',
        119: 'nntp',
        496: 'pim-auto-rp',
        109: 'pop2',
        110: 'pop3',
        1723: 'pptp',
        554: 'rtsp',
        5060: 'sip',
        25: 'smtp',
        22: 'ssh',
        111: 'sunrpc',
        49: 'tacacs',
        517: 'talk',
        23: 'telnet',
        540: 'uucp',
        43: 'whois',
        80: 'www',
    }

    _PORTS_UDP = {
        512: 'biff',
        68: 'bootpc',
        67: 'bootps',
        9: 'discard',
        195: 'dnsix',
        53: 'domain',
        7: 'echo',
        500: 'isakmp',
        434: 'mobile-ip',
        42: 'nameserver',
        138: 'netbios-dgm',
        137: 'netbios-ns',
        2049: 'nfs',
        123: 'ntp',
        496: 'pim-auto-rp',
        520: 'rip',
        161: 'snmp',
        162: 'snmptrap',
        111: 'sunrpc',
        514: 'syslog',
        49: 'tacacs',
        517: 'talk',
        69: 'tftp',
        37: 'time',
        513: 'who',
        177: 'xdmcp',
    }

    _TYPES_ICMP = {
        6: 'alternate-address',
        31: 'conversion-error',
        8: 'echo',
        0: 'echo-reply',
        16: 'information-reply',
        15: 'information-request',
        18: 'mask-reply',
        17: 'mask-request',
        32: 'mobile-redirect',
        12: 'parameter-problem',
        5: 'redirect',
        9: 'router-advertisement',
        10: 'router-solicitation',
        4: 'source-quench',
        11: 'time-exceeded',
        14: 'timestamp-reply',
        13: 'timestamp-request',
        30: 'traceroute',
        3: 'unreachable',
    }

    # Combine cisco-specific port mappings with common ones
    _CISCO_PORTS_TCP = {
        5190: 'aol',
        1494: 'citrix-ica',
        2748: 'ctiqbe',
        1720: 'h323',
        101: 'hostname',
        143: 'imap4',
        750: 'kerberos',
        1352: 'lotusnotes',
        139: 'netbios-ssn',
        5631: 'pcanywhere-data',
        1521: 'sqlnet',
    }
    _CISCO_PORTS_TCP.update(_PORTS_TCP)

    _CISCO_PORTS_UDP = {
        750: 'kerberos',
        5632: 'pcanywhere-status',
        1645: 'radius',
        1646: 'radius-acct',
        5510: 'secureid-udp',
        5060: 'sip',
    }
    _CISCO_PORTS_UDP.update(_PORTS_UDP)

    # Combine arista-specific port mappings with common ones
    _ARISTA_PORTS_TCP = {
        143: 'imap',
        88: 'kerberos',
    }
    _ARISTA_PORTS_TCP.update(_PORTS_TCP)

    _ARISTA_PORTS_UDP = {
        88: 'kerberos',
        1812: 'radius',
        1813: 'radius-acct',
    }
    _ARISTA_PORTS_UDP.update(_PORTS_UDP)

    # Full port map data structure
    _PORT_MAP = {
        'cisco': {'tcp': _CISCO_PORTS_TCP, 'udp': _CISCO_PORTS_UDP, 'icmp': _TYPES_ICMP},
        'arista': {'tcp': _ARISTA_PORTS_TCP, 'udp': _ARISTA_PORTS_UDP, 'icmp': _TYPES_ICMP},
    }

    @staticmethod
    def GetProtocol(port_num: int, proto: str, platform: str = 'cisco'):
        """Converts a port number to a name or returns the number.

        Args:
          port_num: integer representing the port number.
          proto: string representing proto (tcp, udp, etc).
          platform: string representing platform (cisco, arista)

        Returns:
          A name of the protocol or the port number that was provided.
        """
        try:
            port_map = PortMap._PORT_MAP[platform][proto]
            return port_map[port_num]
        except KeyError:
            return port_num


class Term(aclgenerator.Term):
    """This is an general Term object that all other Cisco Terms should inherite from."""

    ALLOWED_PROTO_STRINGS = [
        'eigrp',
        'gre',
        'icmp',
        'igmp',
        'igrp',
        'ip',
        'ipinip',
        'nos',
        'pim',
        'tcp',
        'udp',
        'sctp',
        'ahp',
    ]
    IPV4_ADDRESS = Union[nacaddr.IPv4, ipaddress.IPv4Network]
    IPV6_ADDRESS = Union[nacaddr.IPv6, ipaddress.IPv6Network]

    def __init__(
        self,
        term: Term,
        af: int = 4,
        proto_int: bool = True,
        enable_dsmo: bool = False,
        term_remark: bool = True,
        platform: str = 'cisco',
        verbose: bool = True,
        filter_type: str | None = None,
    ) -> None:
        self.term = term
        self.proto_int = proto_int
        self.options = []
        self.enable_dsmo = enable_dsmo
        self.term_remark = term_remark
        self.platform = platform
        self.verbose = verbose
        self.filter_type = filter_type
        # Our caller should have already verified the address family.
        assert af in (4, 6)
        self.af = af
        if af == 4:
            self.text_af = 'inet'
        else:
            self.text_af = 'inet6'

    def __str__(self) -> str:
        ret_str = ['\n']

        # Don't render icmpv6 protocol terms under inet, or icmp under inet6
        if (
            (self.af == 6 and 'icmp' in self.term.protocol)
            or (self.af == 6 and self.PROTO_MAP['icmp'] in self.term.protocol)
            or (self.af == 4 and 'icmpv6' in self.term.protocol)
            or (self.af == 4 and self.PROTO_MAP['icmpv6'] in self.term.protocol)
        ):
            if self.filter_type != 'mixed':
                logging.warning(
                    self.NO_AF_LOG_PROTO.substitute(
                        term=self.term.name, proto=', '.join(self.term.protocol), af=self.text_af
                    )
                )
            return ''

        # verbose
        if self.verbose:
            comments = []
            if self.term_remark:
                comments.append(self.term.name)
            if self.term.owner:
                comments.append(f'Owner: {self.term.owner}')
            comments.extend(self.term.comment)

            comments = aclgenerator.WrapWords(comments, _COMMENT_MAX_WIDTH)
            if comments and comments[0]:
                for comment in comments:
                    ret_str.append(f' remark {comment!s}')

        # Term verbatim output - this will skip over normal term creation
        # code by returning early.  Warnings provided in policy.py.
        if self.term.verbatim:
            for next_verbatim in self.term.verbatim:
                if next_verbatim[0] == self.platform:
                    ret_str.append(str(next_verbatim[1]))
            return '\n'.join(ret_str)

        # protocol
        if not self.term.protocol:
            if self.af == 6:
                protocol = ['ipv6']
            elif self.platform == 'ciscoxr':
                protocol = ['ipv4']
            else:
                protocol = ['ip']
        elif self.term.protocol == ['hopopt'] or self.term.protocol == self.PROTO_MAP['hopopt']:
            protocol = ['hbh']
        elif self.proto_int:
            protocol = [
                (
                    proto
                    if proto in self.ALLOWED_PROTO_STRINGS or proto.isnumeric()
                    else self.PROTO_MAP.get(proto)
                )
                for proto in self.term.protocol
            ]
        else:
            protocol = self.term.protocol
        # Arista can not process acls with esp/ah, these must appear as integers.
        if self.platform == 'arista':
            if 'esp' in protocol:
                protocol = [x if x != 'esp' else '50' for x in protocol]
            if 'ah' in protocol:
                protocol = [x if x != 'ah' else '51' for x in protocol]

        # addresses
        # source address
        if self.term.source_address:
            source_address = self.term.GetAddressOfVersion('source_address', self.af)
            source_address_exclude = self.term.GetAddressOfVersion(
                'source_address_exclude', self.af
            )
            if source_address_exclude:
                source_address = nacaddr.ExcludeAddrs(source_address, source_address_exclude)
            if not source_address:
                if self.filter_type != 'mixed':
                    logging.warning(
                        self.NO_AF_LOG_ADDR.substitute(
                            term=self.term.name, direction='source', af=self.text_af
                        )
                    )
                return ''
            if self.enable_dsmo:
                source_address = summarizer.Summarize(source_address)
        else:
            # source address not set
            source_address = [nacaddr.IPv4('0.0.0.0/0', token='any')]
        fixed_src_addresses = {x for x in source_address}

        # destination address
        if self.term.destination_address:
            destination_address = self.term.GetAddressOfVersion('destination_address', self.af)
            destination_address_exclude = self.term.GetAddressOfVersion(
                'destination_address_exclude', self.af
            )
            if destination_address_exclude:
                destination_address = nacaddr.ExcludeAddrs(
                    destination_address, destination_address_exclude
                )
            if not destination_address:
                if self.filter_type != 'mixed':
                    logging.warning(
                        self.NO_AF_LOG_ADDR.substitute(
                            term=self.term.name, direction='destination', af=self.text_af
                        )
                    )
                return ''
            if self.enable_dsmo:
                destination_address = summarizer.Summarize(destination_address)
        else:
            # destination address not set
            destination_address = [nacaddr.IPv4('0.0.0.0/0', token='any')]

        fixed_dst_addresses = {x for x in destination_address}

        # ports
        source_port = [()]
        destination_port = [()]

        # source port
        if self.term.source_port:
            source_port = self._FixConsecutivePorts(self.term.source_port)

        # destination port
        if self.term.destination_port:
            destination_port = self._FixConsecutivePorts(self.term.destination_port)

        # options
        opts = [str(x) for x in self.term.option]
        if (self.PROTO_MAP['tcp'] in protocol or 'tcp' in protocol) and (
            'tcp-established' in opts or 'established' in opts
        ):
            if 'established' not in self.options:
                self.options.append('established')
        # Using both 'fragments' and 'is-fragment', ref Github Issue #187
        if ('fragments' in opts) or ('is-fragment' in opts):
            if 'fragments' not in self.options:
                self.options.append('fragments')
        # ACL-based Forwarding
        if (
            (self.platform == 'ciscoxr')
            and not self.term.action
            and self.term.next_ip
            and ('nexthop1' not in opts)
        ):
            if len(self.term.next_ip) > 1:
                raise CiscoNextIpError(
                    f'The following term has more than one next IP value: {self.term.name}'
                )
            if not isinstance(self.term.next_ip[0], nacaddr.IPv4) and not isinstance(
                self.term.next_ip[0], nacaddr.IPv6
            ):
                raise CiscoNextIpError(
                    f'Next IP value must be an IP address. Invalid term: {self.term.name}'
                )
            if self.term.next_ip[0].num_addresses > 1:
                raise CiscoNextIpError(
                    f'The following term has a subnet instead of a host: {self.term.name}'
                )
            nexthop = self.term.next_ip[0].network_address
            nexthop_protocol = 'ipv4' if nexthop.version == 4 else 'ipv6'
            self.options.append(f'nexthop1 {nexthop_protocol} {nexthop}')
            action = _ACTION_TABLE.get('accept')

        # action
        if self.term.action:
            action = _ACTION_TABLE.get(str(self.term.action[0]))

        # logging
        if self.term.logging:
            self.options.append('log')

        # dscp; unlike srx, cisco only supports single, non-except values
        if self.term.dscp_match:
            if len(self.term.dscp_match) > 1:
                raise ExtendedACLTermError(
                    'Extended ACLs cannot specify more than one dscp match value'
                )
            else:
                self.options.append(f"dscp {' '.join(self.term.dscp_match)}")

        # icmp-types
        icmp_types = ['']
        if self.term.icmp_type:
            icmp_types = self.NormalizeIcmpTypes(self.term.icmp_type, self.term.protocol, self.af)
        icmp_codes = ['']
        if self.term.icmp_code:
            icmp_codes = self.term.icmp_code

        fixed_opts = {}
        for p in protocol:
            fixed_opts[p] = self._FixOptions(p, self.options)

        # temlet constructor
        for saddr in sorted(fixed_src_addresses):
            for daddr in sorted(fixed_dst_addresses):
                for sport in sorted(source_port):
                    for dport in sorted(destination_port):
                        for proto in sorted(protocol):
                            opts = fixed_opts[proto]
                            # cisconx uses icmp for both ipv4 and ipv6
                            if self.platform == 'cisconx':
                                if self.af == 6:
                                    proto = 'icmp' if proto == 'icmpv6' else proto
                            for icmp_type in sorted(icmp_types):
                                for icmp_code in sorted(icmp_codes):
                                    ret_str.extend(
                                        self._TermletToStr(
                                            action,
                                            proto,
                                            self._GetIpString(saddr),
                                            self._FormatPort(sport, proto),
                                            self._GetIpString(daddr),
                                            self._FormatPort(dport, proto),
                                            icmp_type,
                                            icmp_code,
                                            opts,
                                        )
                                    )

        return '\n'.join(ret_str)

    def _GetIpString(self, addr: IPv6 | IPv4 | DSMNet) -> str:
        """Formats the address object for printing in the ACL.

        Args:
          addr: str or ipaddr, address
        Returns:
          An address string suitable for the ACL.
        """
        # DSMO enabled
        if isinstance(addr, summarizer.DSMNet):
            return '%s %s' % summarizer.ToDottedQuad(addr, negate=True)
        if addr.prefixlen == 0:
            return 'any'
        if isinstance(addr, nacaddr.IPv4) or isinstance(addr, ipaddress.IPv4Network):
            addr = cast(self.IPV4_ADDRESS, addr)
            if addr.num_addresses > 1:
                if self.platform in ('arista', 'cisconx'):
                    return addr.with_prefixlen
                return f'{addr.network_address} {addr.hostmask}'
            if addr.num_addresses == 1 and self.platform == 'cisconx':
                return f'{addr.with_prefixlen}'
            return f'host {addr.network_address}'
        if isinstance(addr, nacaddr.IPv6) or isinstance(addr, ipaddress.IPv6Network):
            addr = cast(self.IPV6_ADDRESS, addr)
            if addr.num_addresses > 1:
                return addr.with_prefixlen
            return f'host {addr.network_address}'
        return addr

    def _FormatPort(self, port: tuple[()] | tuple[int, int], proto: int | str) -> str:
        """Returns a formatted port string for the range.

        Args:
          port: The port range represented as a tuple..
          proto: String or int representing a protocol.

        Returns:
          A string used to filter a single or range of ports..
        """
        if not port:
            return ''
        port0 = port[0]
        port1 = port[1]
        if self.platform == 'arista':
            port0 = PortMap.GetProtocol(port0, proto, self.platform)
            port1 = PortMap.GetProtocol(port1, proto, self.platform)

        if port[0] != port[1]:
            return f'range {port0} {port1}'
        return f'eq {port0}'

    def _FixOptions(self, proto: int | str, option: list[str | Any]) -> list[str | Any]:
        """Returns a set of options suitable for the given protocol.

        Fix done:
        - Filter out 'established' for UDP.
        - Filter out 'fragments' for TCP/UDP

        Args:
          proto: str or int, protocol
          option: list or none, optional, eg. 'logging' tokens.
        Returns:
          A list of options suitable for that protocol.
        """
        # Prevent UDP from appending 'established' to ACL line
        sane_options = list(option)
        if (proto == self.PROTO_MAP['udp'] or proto == 'udp') and 'established' in sane_options:
            sane_options.remove('established')
        return sane_options

    def _TermletToStr(
        self,
        action: str,
        proto: int | str,
        saddr: str,
        sport: str,
        daddr: str,
        dport: str,
        icmp_type: int | str,
        icmp_code: int | str,
        option: list[str],
    ) -> list[str]:
        """Take the various compenents and turn them into a cisco acl line.

        Args:
          action: str, action
          proto: str or int, protocol
          saddr: str, source address
          sport: str, the source port
          daddr: str, the destination address
          dport: str, the destination port
          icmp_type: icmp-type numeric specification (if any)
          icmp_code: icmp-code numeric specification (if any)
          option: list of options, eg. 'logging' tokens.

        Returns:
          string of the cisco acl line, suitable for printing.

        Raises:
          UnsupportedCiscoAccessListError: When unknown icmp-types specified
        """
        # str(icmp_type) is needed to ensure 0 maps to '0' instead of FALSE
        icmp_type = str(icmp_type)
        icmp_code = str(icmp_code)
        all_elements = [
            action,
            str(proto),
            saddr,
            sport,
            daddr,
            dport,
            icmp_type,
            icmp_code,
            ' '.join(option),
        ]
        non_empty_elements = [x for x in all_elements if x]
        return [f" {' '.join(non_empty_elements)}"]

    def _FixConsecutivePorts(self, port_list: list[tuple[int, int]]) -> list[tuple[int, int]]:
        """Takes a list of tuples and expands the tuple if the range is two.

            http://www.cisco.com/warp/public/cc/pd/si/casi/ca6000/tech/65acl_wp.pdf

        Args:
          port_list: A list of tuples representing ports.

        Returns:
          list of tuples
        """
        temporary_port_list = []
        for low_port, high_port in port_list:
            if low_port == high_port - 1:
                temporary_port_list.append((low_port, low_port))
                temporary_port_list.append((high_port, high_port))
            else:
                temporary_port_list.append((low_port, high_port))
        return temporary_port_list


class ExtendedTerm(Term):
    """A single ExtendedACL Term."""


class ObjectGroupTerm(Term):
    """An individual term of an object-group'd acl.

    Object Group acls are very similar to extended acls in their
    syntax except they use a meta language with address/service
    definitions.

    eg:

      permit tcp first-term-source-address 179-179 ANY

    where first-term-source-address, ANY and 179-179 are defined elsewhere
    in the acl.
    """

    def _FormatPort(self, port: tuple[()] | tuple[int, int], proto: str) -> str:
        """Returns a formatted port string for the range.

        Args:
          port: str list or none, the port range.
          proto: str representing proto (tcp, udp, etc).

        Returns:
          A string suitable for the ACL.
        """
        if not port:
            return ''
        return f'port-group {port[0]}-{port[1]}'

    def _GetIpString(self, addr: IPv4 | IPv6) -> str:
        """Formats the address object for printing in the ACL.

        Args:
          addr: str or ipaddr, address
        Returns:
          An address string suitable for the ACL.
        """
        if addr.prefixlen == 0:
            return f'{addr.parent_token}'
        return f'net-group {addr.parent_token}'


class Cisco(aclgenerator.ACLGenerator):
    """A cisco policy object."""

    _PLATFORM = 'cisco'
    _DEFAULT_PROTOCOL = 'ip'
    SUFFIX = '.acl'
    # Protocols should be emitted as numbers.
    _PROTO_INT = True
    _TERM_REMARK = True

    def _BuildTokens(self) -> tuple[set[str], dict[str, set[str]]]:
        """Build supported tokens for platform.

        Returns:
          tuple containing both supported tokens and sub tokens
        """
        supported_tokens, supported_sub_tokens = super()._BuildTokens()

        supported_tokens |= {
            'address',
            'restrict_address_family',
            'dscp_match',
            'icmp_code',
            'logging',
            'owner',
        }

        supported_sub_tokens.update(
            {
                'option': {'established', 'tcp-established', 'is-fragment', 'fragments'},
                # Warning, some of these are mapped
                # differently. See _ACTION_TABLE
                'action': {'accept', 'deny', 'reject', 'next', 'reject-with-tcp-rst'},
            }
        )
        return supported_tokens, supported_sub_tokens

    def _TranslatePolicy(self, pol: Policy, exp_info: int) -> None:
        self.cisco_policies = []
        # a mixed filter outputs both ipv4 and ipv6 acls in the same output file
        good_filters = ['extended', 'standard', 'object-group', 'inet6', 'mixed', 'enable_dsmo']

        for header, terms in pol.filters:
            obj_target = ObjectGroup()

            filter_options = header.FilterOptions(self._PLATFORM)
            filter_name = header.FilterName(self._PLATFORM)

            self.verbose = True
            if 'noverbose' in filter_options:
                filter_options.remove('noverbose')
                self.verbose = False

            # extended is the most common filter type.
            filter_type = 'extended'
            if len(filter_options) > 1:
                filter_type = filter_options[1]

            # check if filter type is renderable
            if filter_type not in good_filters:
                raise UnsupportedCiscoAccessListError(
                    'access list type %s not supported by %s (good types: %s)'
                    % (filter_type, self._PLATFORM, str(good_filters))
                )

            filter_list = [filter_type]
            if filter_type == 'mixed':
                # Loop through filter and generate output for inet and inet6 in sequence
                filter_list = ['extended', 'inet6']

            for next_filter in filter_list:
                # Numeric access lists can be extended or standard, but have specific
                # known ranges.
                if next_filter == 'extended' and filter_name.isdigit():
                    if int(filter_name) in list(range(1, 100)) + list(range(1300, 2000)):
                        raise UnsupportedCiscoAccessListError(
                            'Access lists between 1-99 and 1300-1999 are reserved for '
                            'standard ACLs'
                        )
                if next_filter == 'standard' and filter_name.isdigit():
                    if int(filter_name) not in list(range(1, 100)) + list(range(1300, 2000)):
                        raise UnsupportedCiscoAccessListError(
                            'Standard access lists must be numeric in the range of 1-99'
                            ' or 1300-1999.'
                        )

                term_dup_check = set()
                new_terms = []
                for term in terms:
                    if term.name in term_dup_check:
                        raise CiscoDuplicateTermError(f'You have a duplicate term: {term.name}')
                    term_dup_check.add(term.name)

                    term.name = self.FixTermLength(term.name)
                    af = 'inet'
                    if next_filter == 'inet6':
                        af = 'inet6'
                    term = self.FixHighPorts(term, af=af)
                    if not term:
                        continue

                    # Ignore if the term is for a different AF
                    if term.restrict_address_family and term.restrict_address_family != af:
                        continue

                    # render terms based on filter type
                    if next_filter == 'standard':
                        # keep track of sequence numbers across terms
                        new_terms.append(
                            TermStandard(term, filter_name, self._PLATFORM, self.verbose)
                        )
                    elif next_filter == 'extended':
                        enable_dsmo = (
                            len(filter_options) > 2 and filter_options[2] == 'enable_dsmo'
                        )
                        new_terms.append(
                            ExtendedTerm(
                                term,
                                proto_int=self._PROTO_INT,
                                enable_dsmo=enable_dsmo,
                                term_remark=self._TERM_REMARK,
                                platform=self._PLATFORM,
                                verbose=self.verbose,
                                filter_type=filter_type,
                            )
                        )
                    elif next_filter == 'object-group':
                        obj_target.AddTerm(term)
                        new_terms.append(self._GetObjectGroupTerm(term, verbose=self.verbose))
                    elif next_filter == 'inet6':
                        new_terms.append(
                            ExtendedTerm(
                                term,
                                6,
                                proto_int=self._PROTO_INT,
                                platform=self._PLATFORM,
                                verbose=self.verbose,
                                filter_type=filter_type,
                            )
                        )

                # cisco requires different name for the v4 and v6 acls
                if filter_type == 'mixed' and next_filter == 'inet6':
                    filter_name = f'ipv6-{filter_name}'
                self.cisco_policies.append(
                    (header, filter_name, [next_filter], new_terms, obj_target)
                )

    def _GetObjectGroupTerm(self, term: Term, verbose: bool = True) -> ObjectGroupTerm:
        """Returns an ObjectGroupTerm object."""
        return ObjectGroupTerm(term, verbose=verbose)

    def _AppendTargetByFilterType(self, filter_name: str, filter_type: str) -> list[str]:
        """Takes in the filter name and type and appends headers.

        Args:
          filter_name: Name of the current filter
          filter_type: Type of current filter

        Returns:
          list of strings

        Raises:
          UnsupportedCiscoAccessListError: When unknown filter type is used.
        """
        target = []
        if filter_type == 'standard':
            if filter_name.isdigit():
                target.append(f'no access-list {filter_name}')
            else:
                target.append(f'no ip access-list standard {filter_name}')
                target.append(f'ip access-list standard {filter_name}')
        elif filter_type == 'extended':
            target.append(f'no ip access-list extended {filter_name}')
            target.append(f'ip access-list extended {filter_name}')
        elif filter_type == 'object-group':
            target.append(f'no ip access-list extended {filter_name}')
            target.append(f'ip access-list extended {filter_name}')
        elif filter_type == 'inet6':
            target.append(f'no ipv6 access-list {filter_name}')
            target.append(f'ipv6 access-list {filter_name}')
        else:
            raise UnsupportedCiscoAccessListError(
                f'access list type {filter_type} not supported by {self._PLATFORM}'
            )
        return target

    def _RepositoryTagsHelper(
        self, target: list[str] | None = None, filter_type: str = '', filter_name: str = ''
    ) -> list[str]:
        if target is None:
            target = []
        if filter_type == 'standard' and filter_name.isdigit():
            target.extend(
                aclgenerator.AddRepositoryTags(
                    f'access-list {filter_name} remark ', date=False, revision=False
                )
            )
        else:
            target.extend(aclgenerator.AddRepositoryTags(' remark ', date=False, revision=False))
        return target

    def __str__(self) -> str:
        target_header = []
        target = []
        # add the p4 tags
        target.extend(aclgenerator.AddRepositoryTags('! '))

        for header, filter_name, filter_list, terms, obj_target in self.cisco_policies:
            for filter_type in filter_list:
                target.extend(self._AppendTargetByFilterType(filter_name, filter_type))
                if filter_type == 'object-group':
                    obj_target.AddName(filter_name)

                # Add the Perforce Id/Date tags, these must come after
                # remove/re-create of the filter, otherwise config mode doesn't
                # know where to place these remarks in the configuration.
                if self.verbose:
                    target = self._RepositoryTagsHelper(target, filter_type, filter_name)

                    # add a header comment if one exists

                    for comment in aclgenerator.WrapWords(header.comment, _COMMENT_MAX_WIDTH):
                        for line in comment.split('\n'):
                            if (
                                self._PLATFORM == 'cisco'
                                and filter_type == 'standard'
                                and filter_name.isdigit()
                            ):
                                target.append(f'access-list {filter_name} remark {line}')
                            else:
                                target.append(f' remark {line}')

                # now add the terms
                for term in terms:
                    term_str = str(term)
                    if term_str:
                        target.append(term_str)

            if obj_target.addressbook.GetZoneNames():
                target = [str(obj_target)] + target
            # ensure that the header is always first
            target = target_header + target
            target += ['', 'exit', '']
        return '\n'.join(target)
