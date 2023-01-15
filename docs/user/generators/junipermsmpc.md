# Juniper MSMPC

The juniper header designation has the following format:

```yaml
targets:
    juniper: [filter name] {inet|inet6|mixed} {noverbose} {ingress|egress}
```

* _filter name_: defines the name of the juniper msmpc filter.
* _inet6_: specifies the output be for IPv6 only filters.
* _mixed_: specifies the output be for IPv4 and IPv6 filters. This is the default format.
* _noverbose_: omit additional term and address comments.
* _ingress_: filter will be applied in the input direction.
* _egress_: filter will be appliced in the output direction.

When inet4 or inet6 is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses.

When neither ingress or egress is specified, the filter will be applied in both (input-output) directions. This is the default.
