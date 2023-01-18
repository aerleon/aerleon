# CiscoASA

## Header Format

The ciscoasa header designation has the following format:

```yaml
targets:
    ciscoasa: [filter name]
```

## Term Format

* for common keys see [common.md](common.md)

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
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
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
