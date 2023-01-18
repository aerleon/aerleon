# Arista

## Header Format

The arista header designation has the following format:

```yaml
targets:
    arista: [filter name] {standard|extended|object-group|inet6}
```

<!--
```text
target:: arista [filter name] {standard|extended|object-group|inet6}
```
-->
* _filter name_: defines the name of the arista filter.
* _standard_: specifies that the output should be a standard access list
* _extended_: specifies that the output should be an extended access list
* _object-group_: specifies this is a arista extended access list, and that object-groups should be used for ports and addresses.
* _inet6_: specifies the output be for IPv6 only filters.
* _mixed_: #TODO: does this exist on all Cisco inherited platforms?
* _enable_dsmo_: #TODO: does this exist on all Cisco inherited platforms?

## Term Format

* for common keys see [common.md](common.md)

* _address_: One or more network address tokens, matches source or destination.
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _dscp_match_: Match a DSCP number.
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _owner_: Owner of the term, used for organizational purposes.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.
* _verbose_: adds additional remark statements with the term name, owner (if set) and the comment (if set) (default: True)

## Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

```yaml
option: {established|is-fragment|tcp-established}
```
<!--
```text
option:: {established|is-fragment|tcp-established}
```
-->
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024-65535 for udp if destination port is not defined.
* _is-fragment_: Matches on if a packet is a fragment.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
