# Fortigate

## Header Format

The Fortigate header designation has the following format:

```yaml
targets:
    fortigate: from-zone [source interface or zone] to-zone [destination interface or zone] {address_family}
```

* _source interface or zone_: Defines the source interface or source zone
* _destination interface or zone_: Defines the destination interface or destination zone
* _address_family_: Address family to use, valid inputs are `inet`, `inet6`, or `mixed`. (default: `mixed`)

## Term Format

* For common keys, see section [common](common.md) above.


## Sub Tokens

## Actions

* _accept_
* _deny_

## Option

* _log_traffic_mode_all_: Enables `set logtraffic all` in term.
* _log_traffic_start_session_: Enabled `set logtraffic-start` in term.
