from typing import Any, DefaultDict, Dict, List, Set, Tuple, Union
from collections import defaultdict
from absl import logging
from uuid import UUID, uuid5
from aerleon.lib import aclgenerator, nacaddr, policy
"""

Example header
header {
  target:: fortigate test-filter 
}
========
config firewall policy
edit 0
set srcintf port1
set dstintf port1
set schedule always
set service NTP
set srcaddr all
set dstaddr all
end
When configuring srcaddr it needs dstaddr or internet-service

default action is deny

Settings available in terms
status                       Enable or disable this policy.
name                         Policy name.
uuid                         Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
*srcintf                      Incoming (ingress) interface. REQUIRED
*dstintf                      Outgoing (egress) interface. REQUIRED
action                       Policy action (accept/deny/ipsec).
srcaddr                      Source IPv4 address and address group names.
dstaddr                      Destination IPv4 address and address group names.
srcaddr6                     Source IPv6 address name and address group names.
dstaddr6                     Destination IPv6 address name and address group names.
service                      Service and service group names. REQUIRED
logtraffic                   Enable or disable logging. Log all sessions or security profile sessions.
logtraffic-start             Record logs when a session starts.
comments                     Comment.
*schedule                     Schedule name. REQUIRED
srcaddr-negate               When enabled srcaddr specifies what the source address must NOT be.
srcaddr6-negate              When enabled srcaddr6 specifies what the source address must NOT be.
dstaddr-negate               When enabled dstaddr specifies what the destination address must NOT be.
dstaddr6-negate              When enabled dstaddr6 specifies what the destination address must NOT be.


=======
Cannot use plain IPs it seems, we must create address and service objects

for ipv6 it is usually just a 6 on the end of the name for configs
for example:
address                          Configure IPv4 addresses.
address6                         Configure IPv6 firewall addresses.
addrgrp                          Configure IPv4 address groups.
addrgrp6

    BUILT IN SERVICES
    AFS3	custom
    AH	custom
    ALL	custom
    ALL_ICMP	custom
    ALL_ICMP6	custom
    ALL_TCP	custom
    ALL_UDP	custom
    AOL	custom
    BGP	custom
    CVSPSERVER	custom
    DCE-RPC	custom
    DHCP	custom
    DHCP6	custom
    DNS	custom
    ESP	custom
    FINGER	custom
    FTP	custom
    FTP_GET	custom
    FTP_PUT	custom
    GOPHER	custom
    GRE	custom
    GTP	custom
    H323	custom
    HTTP	custom
    HTTPS	custom
    IKE	custom
    IMAP	custom
    IMAPS	custom
    INFO_ADDRESS	custom
    INFO_REQUEST	custom
    IRC	custom
    Internet-Locator-Service	custom
    KERBEROS	custom
    L2TP	custom
    LDAP	custom
    LDAP_UDP	custom
    MGCP	custom
    MMS	custom
    MS-SQL	custom
    MYSQL	custom
    NFS	custom
    NNTP	custom
    NONE	custom
    NTP	custom
    NetMeeting	custom
    ONC-RPC	custom
    OSPF    custom
    PC-Anywhere	custom
    PING	custom
    PING6	custom
    POP3	custom
    POP3S	custom
    PPTP	custom
    QUAKE	custom
    RADIUS	custom
    RADIUS-OLD	custom
    RAUDIO	custom
    RDP	custom
    REXEC	custom
    RIP	custom
    RLOGIN	custom
    RSH	custom
    RTSP	custom
    SAMBA	custom
    SCCP	custom
    SIP	custom
    SIP-MSNmessenger	custom
    SMB	custom
    SMTP	custom
    SMTPS	custom
    SNMP	custom
    SOCKS	custom
    SQUID	custom
    SSH	custom
    SYSLOG	custom
    TALK	custom
    TELNET	custom
    TFTP	custom
    TIMESTAMP	custom
    TRACEROUTE	custom
    UUCP	custom
    VDOLIVE	custom
    VNC	custom
    WAIS	custom
    WINFRAME	custom
    WINS	custom
    X-WINDOWS	custom
    Email Access	group
    Exchange Server	group
    Web Access	group
    Windows AD	group

custom services
   edit "ALL_UDP"
        set uuid ed6e3f88-2718-51f0-cf6d-d6c86c70ace5
        set category "General"
        set udp-portrange 1-65535
    next
    edit "ALL_ICMP"
        set uuid ed6e41a4-2718-51f0-4ce5-5685b8df33fa
        set category "General"
        set protocol ICMP
        unset icmptype
    next
    edit "ALL_ICMP6"
        set uuid ed6e4406-2718-51f0-169e-0a85ad443a18
        set category "General"
        set protocol ICMP6
        unset icmptype
    next
    edit "GRE"
        set uuid ed6e4622-2718-51f0-f643-43e7d7a45dfd
        set category "Tunneling"
        set protocol IP
        set protocol-number 47

    For UUIDs it would be good to use UUID5 which is based on a namespace and a name
    so we could use the name of the service and a namespace for the UUID
"""

INVARIANT_NAMESPACE = UUID("1661033d-c604-4db2-b9ec-b495a154ad95")
class Term(aclgenerator.Term):
    def __init__(self, term: policy.Term, source_iface: str, destination_iface: str):
        super().__init__(term)
        self.term = term
        self.source_iface = source_iface
        self.destination_iface = destination_iface
        
    def __str__(self):
        """Return string representation of Fortigate term."""
        output = []
        output.append(f'    edit 0')
        output.append(f'        set srcintf {self.source_iface}')
        output.append(f'        set dstintf {self.destination_iface}')
        output.append(f'        set srcaddr {" ".join(set([i.token for i in self.term.source_address]))}')
        output.append(f'        set dstaddr {" ".join(set([i.token for i in self.term.destination_address]))}')
        output.append(f'        set schedule always')
        output.append(f'        set service FTP')
        output.append(f'        set action {self.term.action[0]}')
        output.append(f'    next')
        return '\n'.join(output)

class FortigateDefaultDictionary(defaultdict):
    def __init__(self, object_constructor, key_attribute_name):
        """
        Initializes the KeyAwareDefaultDict.

        Args:
            object_constructor: The class (or function) to call to create a new object.
                                Its __init__ or call signature must accept a keyword
                                argument named by key_attribute_name.
            key_attribute_name: The string name of the attribute in the object
                                that should be populated with the dictionary key.
        """
        super().__init__(None) # Initialize defaultdict without a default_factory
                               # We handle creation in __missing__
        if not callable(object_constructor):
            raise TypeError("object_constructor must be callable")
        self.object_constructor = object_constructor
        self.key_attribute_name = key_attribute_name

    def __missing__(self, key):
        """
        Called when a key is not found. Creates the object using the key.
        """
        # Check if the key is already set (might happen in recursive scenarios)
        # Usually not necessary for simple cases but adds robustness.
        if key in self:
            return self[key]

        # Create the new object, passing the key as a keyword argument
        # corresponding to the specified attribute name.
        kwargs = {self.key_attribute_name: key}
        value = self.object_constructor(**kwargs)

        # Store the newly created object in the dictionary for this key
        self[key] = value

        # Return the newly created object
        return value
        
class FortigateAddressGroup():
    def __init__(self, name: str):
        self.name = name
        self.ips = set([])

    def addIP(self, ip: nacaddr.IP):
        self.ips.add(ip)

    def __str__(self) -> str:
        """Return string representation of Fortigate address."""
        output = []
        # create addresses
        output.append(f'config firewall address')

        for index, ip in enumerate(self.ips):
            output.append(f'    edit {self.name}_{index}')
            output.append(f'        set uuid {uuid5(INVARIANT_NAMESPACE, self.name+str(ip))}')
            output.append(f'        set type ipmask')
            output.append(f'        set subnet {str(ip)}')
            output.append('    next')
        output.append('end')
        output.append(f'config firewall addrgrp')
        output.append(f'    edit {self.name}')
        output.append(f'        set uuid {uuid5(INVARIANT_NAMESPACE, self.name)}')
        address_names = ' '.join([self.name+f'_{i}' for i in range(len(self.ips))])
        output.append(f'        set member {address_names}')
        
        return '\n'.join(output)

class Fortigate(aclgenerator.ACLGenerator):
    """Fortigate ACL generator."""

    _PLATFORM = 'fortigate'
    SUFFIX = '.fgacl'
    _SUPPORTED_AF = frozenset(('inet', 'inet6', 'mixed'))
    address_groups = FortigateDefaultDictionary(FortigateAddressGroup, 'name')
    terms = []

    def __init__(self, name, description):
        super().__init__(name, description)



    def _BuildTokens(self) -> Tuple[Set[str], Dict[str, Set[str]]]:
        """Build supported tokens for platform.

        Returns:
          tuple containing both supported tokens and sub tokens
        """
        print('Building tokens for Fortigate')
        supported_tokens, supported_sub_tokens = super()._BuildTokens()
        supported_sub_tokens['action'] = {'accept', 'deny'}
        return supported_tokens, supported_sub_tokens

    def _TranslatePolicy(self, pol: policy.Policy, exp_info: int) -> None:
        for header, terms in pol.filters:
            options = header.FilterOptions(self._PLATFORM)
            if len(options) < 3:
                logging.warning('Fortigate requires at least 3 options')
                continue
            header_name = options[0]
            source_iface = options[1]
            destination_iface = options[2]
            for term in terms:
                self._TranslateAddresses(term.source_address)
                self._TranslateAddresses(term.destination_address) 
                self._TranslateAddresses(term.source_address_exclude)
                self._TranslateAddresses(term.destination_address_exclude)
                # self._TranslateServices(term.sou)
                
                fortigate_term = Term(term, source_iface, destination_iface)
                self.terms.append(fortigate_term)
        pass
    def _TranslateAddresses(self, addrs: List[nacaddr.IP]) -> None:
        for addr in addrs:
            self.address_groups[addr.token].ips.add(addr)
        pass

    def __str__(self) -> str:
        """Return string representation of Fortigate ACL."""
        output = []
        output.append(f'config firewall policy')
        for addr_group in self.address_groups.values():
            output.append(str(addr_group))
        output.append('end')
        for term in self.terms:
            output.append(str(term))
        output.append('end')
        return '\n'.join(output)


class FortigateService():
    def __init__(self, name: str, protocol: str, port: int):
        self.name = name
        self.protocol = protocol
        self.port = port

    def __str__(self) -> str:
        """Return string representation of Fortigate service."""
        output = []
        output.append(f'config firewall service custom')
        output.append(f'edit {self.name}')
        output.append(f'set protocol {self.protocol}')
        output.append(f'set tcp-portrange {self.port}')
        output.append('next')
        return '\n'.join(output)
    

class FortigateAddress():
    pass

