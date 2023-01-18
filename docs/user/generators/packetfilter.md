# PacketFilter

> Note: The PF generator is currently in alpha testing. The output should be compatible with OpenBSD v4.7 PF and later.

## Header Format

```yaml
targets:
    packetfilter: filter-name {inet|inet6|mixed} {in|out} {nostate}
```

* _filter-name_: a short, descriptive policy identifier
* _inet_: specifies that the resulting filter should only render IPv4 addresses.
* _inet6_: specifies that the resulting filter should only render IPv6 addresses.
* _mixed_: specifies that the resulting filter should only render IPv4 and IPv6 addresses (default).
* _in_: match ingoing packets (default: both directions).
* _out_: match outgoing packets (default: both directions).
* _nostate_: do not keep state on connections (default: keep state).

## Term Format

* for common keys see [common.md](common.md)

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-interface_: Specify the destination interface. Implicitly changes the term direction to **out** for this term. Mutually exclusive with _source-interface_:.
* _source-interface_: Specify the source interface. Implicitly changes the term direction to **in** for this term. Mutually exclusive with _destination-interface_:.
* _logging_: Specify that this packet should be logged via syslog.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

## Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_

### Option

* _ack_: Match on ACK flag being present.
* _all_: Matches all protocols.
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _fin_: Match on FIN flag being present.
* _is-fragment_: Matches on if a packet is a fragment.
* _psh_: Match on PSH flag being present.
* _rst_: Match on RST flag being present.
* _syn_: Match on SYN flag being present.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _urg_: Match on URG flag being present.
