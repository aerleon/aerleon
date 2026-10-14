# Juniper MSMPC

## Header Format

The Juniper MSMPC header designation has the following format:

```yaml
targets:
    msmpc: [filter name] {inet|inet6|mixed} {noverbose} {ingress|egress} [no-apply-groups]
```

* _filter name_: defines the name of the Juniper msmpc filter.
* _inet6_: specifies the output be for IPv6 only filters.
* _mixed_: specifies the output be for IPv4 and IPv6 filters. This is the default format.
* _noverbose_: omit additional term and address comments. (optional)
* _ingress_: filter will be applied in the input direction.
* _egress_: filter will be appliced in the output direction.
* _no-apply-groups_: generate configuration without `apply-groups` (optional)

When inet4 or inet6 is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses.

When neither ingress or egress is specified, the filter will be applied in both (input-output) directions. This is the default.

## Term Format

TBD

## Sub Tokens

## Actions

* _accept_
* _deny_
* _reject_
