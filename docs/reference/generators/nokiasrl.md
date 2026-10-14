# Nokia SR Linux

## Header Format

The Nokia SR Linux header designation has the following format:

```yaml
targets:
    nokiasrl: {section_name} {inet|inet6|mixed} {stats} {r24.3} {r24.3.2}
```

* _section_name_: specifies the name of the section all terms in this header apply to.
* _inet_: specifies that the resulting filter should only render IPv4 addresses.
* _inet6_: specifies that the resulting filter should only render IPv6 addresses.
* _mixed_: specifies that the resulting filter should render both IPv4 and IPv6 addresses.
* _stats_: Collect stats for ACL entries
* _r24.3_: Use release 24.3.1 format
* _r24.3.2_: Use new format (post release 24.3.1)

(Required keywords option and verbatim are not supported)

## Term Format

* for common keys see the [Common](common.md) page.
* _source-prefix_: this should resolve to a named ipv4 or ipv6 prefix list under 'acl match-list'
* _destination-prefix_: this should resolve to a named ipv4 or ipv6 prefix list under 'acl match-list'

## Sub Tokens

## Actions

* _accept_
* _deny_
