# PaloAltoFW

## Header Format

The paloalto header designation has the following format:

```yaml
targets:
    paloalto: from-zone [zone name] to-zone [zone name] [address family] [address objects]
```

* _from-zone_: static keyword, followed by the source zone
* _to-zone_: static keyword, followed by the destination zone
* _address family_: specifies the address family for the resulting filter
  * _inet_: the filter should only render IPv4 addresses (default)
  * _inet6_: the filter should only render IPv6 addresses
  * _mixed_: the filter should render IPv4 and IPv6 addresses
* _address objects_: specifies whether custom address objects or network/mask definitions are used in security policy source and destination fields
  * _addr-obj_: specifies address groups are used in the security policy
      source and destination fields (default)
  * _no-addr-obj_: specifies network/mask definitions are used in the
       security policy source and destination fields
* _unique-term-prefixes_: specifies whether each term name should be generated with unique prefixes. The unique prefix is a hexdigest of from_zone and to_zone fields.

## Term Format

* for common keys see [common.md](common.md)

* _logging_: Specify that this packet should be logged via syslog.
* _owner_: Owner of the term, used for organizational purposes.
* _timeout_: specify application timeout. (default 60)

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
    applications (<https://applipedia.paloaltonetworks.com/>)
    and custom application objects.

  * _Security Policy Service Setting_

    * When no _protocol_ is specified in the term, the service will be _application-default_.
    * When _protocol_ is tcp or udp, and no _source-port_ or _destination-port_ is specified, the service will be custom service objects for the protocols and all ports (0-65535).
    * When _protocol_ is tcp or udp, and a _source-port_ or _destination-port_ is specified, the service will be custom service objects for the protocols and ports.
    * _pan-application_ can only be used when no _protocol_ is specified in the term, or the protocols tcp and udp.
