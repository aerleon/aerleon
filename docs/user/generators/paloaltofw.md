# PaloAltoFW

The paloalto header designation has the following format:

```
target:: paloalto from-zone [zone name] to-zone [zone name] [address family] [address objects]
```

* _from-zone_: static keyword, followed by the source zone
* _to-zone_: static keyword, followed by the destination zone
* _address family_: specifies the address family for the resulting filter
    * _inet_: the filter should only render IPv4 addresses (default)
    * _inet6_: the filter should only render IPv6 addresses
    * _mixed_: the filter should render IPv4 and IPv6 addresses
* _address objects_: specifies whether custom address objects or
     network/mask definitions are used in security policy source and
     destination fields
    * _addr-obj_: specifies address groups are used in the security policy
      source and destination fields (default)
    * _no-addr-obj_: specifies network/mask definitions are used in the
       security policy source and destination fields
* _unique-term-prefixes_: specifies whether each term name should be generated
     with unique prefixes. The unique prefix is a hexdigest of from_zone and
     to_zone fields.

## Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address::_ One or more destination address tokens.
* _destination-port::_ One or more service definition tokens.
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _icmp-type::_ Specify icmp-type code to match, see section [ICMP TYPES](PolicyFormat#ICMP_TYPES.md) for list of valid arguments
* _logging::_ Specify that this packet should be logged via syslog.
* _name::_ Name of the term.
* _owner::_ Owner of the term, used for organizational purposes.
* _platform::_ one or more target platforms for which this term should ONLY be rendered.
* _protocol::_ the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _source-address::_ one or more source address tokens.
* _source-port::_ one or more service definition tokens.
* _timeout::_ specify application timeout. (default 60)

## Sub Tokens

### Actions

* _accept_
* _count_
* _deny_
* _log_
* _reject_

## Terms Section

### Optionally Supported Keywords

* _pan-application_:: paloalto target only.
    Specify applications for the security policy which can be predefined
    applications (https://applipedia.paloaltonetworks.com/)
    and custom application objects.

    * _Security Policy Service Setting_

        * When no _protocol_ is specified in the term, the service will be _application-default_.

        * When _protocol_ is tcp or udp, and no _source-port_ or _destination-port_ is specified, the service will be custom service objects for the protocols and all ports (0-65535).

        * When _protocol_ is tcp or udp, and a _source-port_ or _destination-port_ is specified, the service will be custom service objects for the protocols and ports.

        * _pan-application_ can only be used when no _protocol_ is specified in the term, or the protocols tcp and udp.
