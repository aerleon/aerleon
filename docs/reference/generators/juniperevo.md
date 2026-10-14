# Juniper EVO

The juniperevo generator is built on the [Juniper](juniper.md) generator. It supports exactly the same header options, tokens, actions and options, so see the Juniper tables. The only difference is how IPv6 protocols are matched (below).

## Header Format

The Juniper EVO header designation has the following format:

```yaml
targets:
    juniperevo: [filter name] {inet|inet6|mixed|bridge|ethernet-switching} {enable_dsmo} {not-interface-specific} {filter_enhanced_mode} {noverbose} {ingress|egress} {physical|loopback}
```

All options work as described for [Juniper](juniper.md), except:

| Option | Description | Notes |
|---|---|---|
| `ingress`, `egress` | Direction the filter is applied in. | **Required** for `inet6` and `mixed` filters; an error is raised without it. |
| `physical`, `loopback` | Type of interface the filter is applied to. | Optional. Defaults to `physical`. |

??? example "Header for an IPv6 loopback filter"
    ```yaml
    targets:
        juniperevo: LOOPBACK-V6 inet6 ingress loopback
    ```

## IPv6 Protocol Match

For Juniper EVO, the direction of the filter on an interface and the interface type determines the syntax to use; either `next-header` or `payload-protocol`. The syntax used for the extension headers and the payload header is summarized below.

| Direction | Interface | Extension headers (hop-by-hop, fragment, routing) | Payload (tcp, udp, ah, esp, icmpv6) |
|---|---|---|---|
| Ingress | Physical | `next-header hop-by-hop`, `next-header fragment`, `next-header routing` | `payload-protocol <proto>` |
| Ingress | Loopback | `payload-protocol 0`, `payload-protocol 44`, `payload-protocol 43` | `payload-protocol <proto>` |
| Egress | Physical | `payload-protocol 0`, `payload-protocol 44`, `payload-protocol 43` | `payload-protocol <proto>` |
| Egress | Loopback | `payload-protocol 0`, `payload-protocol 44`, `payload-protocol 43` | `payload-protocol <proto>` |
