# Ipset

Ipset is a system inside the Linux kernel, which can very efficiently store and match IPv4 and IPv6 addresses. This can be used to dramatically increase performance of iptables firewall.

## Header Format

The Ipset header designation follows the Iptables format above, but uses the target platform of 'ipset':

```yaml
targets:
    ipset: [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {truncatenames} {nostate} {inet|inet6}
```

## Term Format

* for common keys see [common.md](common.md)

* _counter_: Update a counter for matching packets
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-interface_: Specify specific interface a term should apply to (e.g. destination-interface:: eth3)
* _destination-prefix_: Specify destination-prefix matching (e.g. source-prefix:: configured-neighbors-only)
* _fragement-offset_: specify a fragment offset of a fragmented packet
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _owner_: Owner of the term, used for organizational purposes.
* _packet-length_: specify packet length.
* _routing-instance_: specify routing instance for matching packets.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _source-interface_: specify specific interface a term should apply to (e.g. source-interface:: eth3).
* _source-prefix_: specify source-prefix matching (e.g. source-prefix:: configured-neighbors-only).
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

## Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _ack_: Match on ACK flag being present.
* _all_: Matches all protocols.
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _fin_: Match on FIN flag being present.
* _first-fragment_: Only match on first fragment of a fragmented pakcet.
* _initial_: Only matches on initial packet.
* _is-fragment_: Matches on if a packet is a fragment.
* _none_: Matches none.
* _psh_: Match on PSH flag being present.
* _rst_: Match on RST flag being present.
* _sample_: Samples traffic for netflow.
* _syn_: Match on SYN flag being present.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial_: Only match initial packet for TCP protocol.
* _urg_: Match on URG flag being present.
