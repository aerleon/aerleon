# Aruba

## Header Format

The aruba header designation has the following format:

```yaml
targets:
    aruba: [filter name] {ipv6}
```

* _filter name_: defines the name of the arista filter.
* _ipv6_: specifies the output be for IPv6 only filters.

## Term Format

* for common keys see [common.md](common.md)

* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

## Sub Tokens

### Actions

* _accept_
* _deny_

### Option

* _destination-is-user_: Aruba option to specify that the destination should be a user.
* _negate_: Used with DSM summarizer, negates the DSM.
* _source-is-user_: Aruba option to specify that the source should be a user.
