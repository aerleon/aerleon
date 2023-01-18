# Cisco

## Header Format

The cisco header designation has the following format:

```yaml
targets:
    cisco: [filter name] {extended|standard|object-group|inet6|mixed} {enable_dsmo}
```

* _filter name_: defines the name or number of the cisco filter.
* _extended_: specifies that the output should be an extended access list, and the filter name should be non-numeric.  This is the default option.
* _standard_: specifies that the output should be a standard access list, and the filter name should be numeric and in the range of 1-99.
* _object-group_: specifies this is a cisco extended access list, and that object-groups should be used for ports and addresses.
* _inet6_: specifies the output be for IPv6 only filters.
* _mixed_: specifies output will include both IPv6 and IPv4 filters.
* _enable_dsmo_: Enable discontinuous subnet mask summarization.
When _inet4_ or _inet6_ is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses.
The default format is _inet4_, and is implied if not other argument is given.

## Term Format

* for common keys see [common.md](common.md)

* _address_: One or more network address tokens, matches source or destination.
* _restrict-address-family_: Only include the term in the matching address family filter (eg. for mixed filters).
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _dscp_match_: Match a DSCP number.
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _owner_: Owner of the term, used for organizational purposes.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

## Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _is-fragment_: Matches on if a packet is a fragment.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial_: Only match initial packet for TCP protocol.
