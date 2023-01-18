# Juniper EVO

## Header Format

The Juniper EVO header designation has the following format:

```yaml
targets:
    juniperevo: [filter name] {inet|inet6|bridge} {dsmo} {not-interface-specific} {direction} {interface}
```

* _filter name_: defines the name of the Juniper EVO filter.
* _inet_: specifies the output should be for IPv4 only filters. This is the default format.
* _inet6_: specifies the output be for IPv6 only filters.
* _bridge_: specifies the output should render a Juniper EVO bridge filter.
* _dsmo_: Enable discontinuous subnet mask summarization.
* _direction_: The direction of the filter on an interface. Must be specified.
* _interface_: The type of interface on which the filter will be applied. Default in physical (non-loopback) interface.

When _inet4_ or _inet6_ is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses. The default format is _inet4_, and is implied if not other argument is given.

## Term Format

* for common keys see [common.md](common.md)

* _address_: One or more network address tokens, matches source or destination.
* _restrict-address-family_: Only include the term in the matching address family filter (eg. for mixed filters).
* _counter_: Update a counter for matching packets
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-prefix_: Specify destination-prefix matching (e.g. source-prefix:: configured-neighbors-only)
* _destination-prefix_except_: Specify destination-prefix exception(TODO:cmas Fill in more).
* _dscp_except_: Do not match the DSCP number.
* _dscp_match_: Match a DSCP number.
* _dscp_set_: Match a DSCP set.
* _ether_type_: Match EtherType field.
* _filter-term_: Include another filter
* _flexible-match-range Filter based on flexible match options.
* _forwarding-class_: Specify the forwarding class to match.
* _forwarding-class_except_: Do not match the specified forwarding classes.
* _fragement-offset_: specify a fragment offset of a fragmented packet
* _hop-limit_: Match the hop limit to the specified hop limit or set of hop limits.
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _loss-priority_: Specify loss priority.
* _next-ip_: Used in filter based forwarding.
* _owner_: Owner of the term, used for organizational purposes.
* _packet-length_: specify packet length.
* _policer_: specify which policer to apply to matching packets.
* _port_: Matches on source or destination ports. Takes a service token.
* _port-mirror_: Sends copies of the packets to a remote port, boolean value is used to render this config.
* _precedence_: specify precedence of range 0-7.  May be a single integer, or a space separated list.
* _protocol\_except_: allow all protocol "except" specified.
* _qos_: apply quality of service classification to matching packets (e.g. qos:: af4)
* _routing-instance_: specify routing instance for matching packets.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _source-prefix_: specify source-prefix matching (e.g. source-prefix:: configured-neighbors-only).
* _source-prefix-except_: specify destination-prefix exception(TODO:cmas Fill in more).
* _traffic-class-count_:
* _traffic-type_: specify traffic-type
* _ttl_: Matches on TTL.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

## Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _.*_: wat
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _first-fragment_: Only match on first fragment of a fragmented pakcet.
* _sample_: Samples traffic for netflow.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial_: Only match initial packet for TCP protocol.

## IPv6 Protocol Match

For Juniper EVO, the direction of the filter on an interface and the interface type determines the syntax to use; either `next-header` or `payload-protocol`. The syntax usage is sumarized below for the extension headers as well as the payload header.

* _Ingress (Physical)_: `next-header hop-by-hop` | `next-header fragment` | `next-header routing` | `payload-protocol tcp|udp|ah|esp|icmpv6`
* _Ingress (Loopback)_: `payload-protocol 0` | `payload-protocol 44` | `payload-protocol 43` | `payload-protocol tcp|udp|ah|esp|icmpv6`
* _Egress (Physical)_: `payload-protocol 0` | `payload-protocol 44` | `payload-protocol 43` | `payload-protocol tcp|udp|ah|esp|icmpv6`
* _Egress (Loopback)_: `payload-protocol 0` | `payload-protocol 44` | `payload-protocol 43` | `payload-protocol tcp|udp|ah|esp|icmpv6`
