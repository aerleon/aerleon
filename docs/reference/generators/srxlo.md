# SRXlo

SRX Loopback renders a stateless Juniper firewall filter for an SRX loopback interface. It is built on the [Juniper](juniper.md) generator and supports the same header options, tokens, actions and options, with the differences below.

## Header Format

```yaml
targets:
    srxlo: [filter name] {inet|inet6|mixed|bridge|ethernet-switching} {enable_dsmo} {not-interface-specific} {filter_enhanced_mode} {noverbose} {ingress|egress} {physical|loopback}
```

All options work as described for [Juniper](juniper.md).

## Differences from Juniper

| Area | Juniper | SRXlo |
|---|---|---|
| `flexible-match-range` | Supported | Not supported (MX/Trio only) |
| `encapsulate` | Supported | Not supported |
| `port-mirror` | Supported | Not supported |
| ICMPv6 protocol name | `icmpv6` | `icmp6` |
| File suffix | `.jcl` | `.jsl` |
