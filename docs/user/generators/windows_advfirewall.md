# WindowsAdvFirewall

## Header Format

The Windows Advanced Firewall header designation has the following format:

```yaml
targets:
    windows_advfirewall: {out|in} {inet|inet6|mixed}
```

* _out_: Specifies that the direction of packet flow is out. (default)
* _in_: Specifies that the direction of packet flow is in.
* _inet_: specifies that the resulting filter should only render IPv4 addresses.
* _inet6_: specifies that the resulting filter should only render IPv6 addresses.

## Term Format

* for common keys see [common.md](common.md)

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _source-exclude_: exclude one or more address tokens from the specified source-address.

## Sub Tokens

### Actions

* _accept_
* _deny_
