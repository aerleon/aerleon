# NVUE API

## Header Format

The NVUE API header designation has the following format:

```yaml
targets:
    nvueapi: [filter name] {ipv4|ipv6}
```

* _filter name_: defines the name of the NVUE ACL.
* _ipv4_: specifies that the resulting filter should only render IPv4 addresses. This is the default format.
* _ipv6_: specifies that the resulting filter should only render IPv6 addresses.

The NVUE API generator produces JSON configuration for NVIDIA Cumulus Linux switches using the NVUE (NVIDIA User Experience) REST API format. This generator follows iptables patterns for multiple address expansion, creating separate rules for each combination of source and destination addresses.

## Term Format

* for common keys see the [Common](common.md) page.

* _logging_: Specify that this packet should be logged via syslog.
* _option_: Supports TCP state matching with 'tcp-established' option.

## Sub Tokens

## Actions

* _accept_
* _deny_
* _reject_

## Option

* _tcp-established_: Only match established tcp connections, based on stateful match or TCP flags.

## Supported Features

* IPv4 and IPv6 address families (separate ACLs)
* TCP, UDP, ICMP, and ICMPv6 protocols
* Source and destination address matching (single CIDR per rule)
* Source and destination port matching (ranges supported in porta:portz format)
* ICMP type matching (converted to iptables format)
* TCP state matching (established connections)
* Action logging

## Limitations

* Does not support address exclusions (source-address-exclude, destination-address-exclude)
* Does not support MAC address filtering rules
* Does not support mixed address family ACLs (use separate IPv4 and IPv6 ACLs)
