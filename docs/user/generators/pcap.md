# PcapFilter

## Header Format

FILL ME IN

## Term Format

* for common keys see [common.md](common.md)

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _source-exclude_: exclude one or more address tokens from the specified source-address.

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
* _none_: Matches none.
* _psh_: Match on PSH flag being present.
* _rst_: Match on RST flag being present.
* _syn_: Match on SYN flag being present.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _urg_: Match on URG flag being present.
