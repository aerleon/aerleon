# Juniper MSMPC

## Header Format

The Juniper MSMPC header designation has the following format:

```yaml
targets:
    msmpc: [filter name] {inet|inet6|mixed} {noverbose} {ingress|egress} {no-apply-groups}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the filter. | |
| `inet` | Render IPv4 only. | |
| `inet6` | Render IPv6 only. | |
| `mixed` | Render IPv4 and IPv6. | Default. |
| `noverbose` | Leave out term comments and owner. | Optional. |
| `ingress` | Apply the filter in the input direction. | Optional. |
| `egress` | Apply the filter in the output direction. | Optional. Without `ingress` or `egress`, the filter applies in both directions. |
| `no-apply-groups` | Leave `apply-groups` out of the configuration. | Optional. |

Only one address family and one direction can be given. When `inet` or `inet6` is specified, naming tokens that contain both IPv4 and IPv6 addresses are rendered using only the matching addresses.

## Term Format

For common keys see the [Common](common.md) page. MSMPC is stateful, so terms that use `established`/`tcp-established` or are stateless replies are skipped with a warning. The following tokens are specific to msmpc:

| Token | Description | Example | Notes |
|---|---|---|---|
| `destination-prefix` | Match a prefix-list already configured on the device. | `destination-prefix: local-addrs` | Renders as `destination-prefix-list`. |
| `destination-prefix-except` | Exclude a configured prefix-list. | `destination-prefix-except: vip-addrs` | Renders as `destination-prefix-list … except`. |
| `icmp-code` | ICMP code to match. | `icmp-code: 0` | |
| `logging` | Log matching packets. | `logging: true` | Adds `syslog`. `logging: disable` turns it off. |
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added to the term comment unless the header uses `noverbose`. |
| `source-prefix` | Match a prefix-list already configured on the device. | `source-prefix: configured-neighbors-only` | Renders as `source-prefix-list`. |
| `source-prefix-except` | Exclude a configured prefix-list. | `source-prefix-except: bad-neighbors` | Renders as `source-prefix-list … except`. |

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `accept` | |
| `deny` | `discard` | |
| `next` | `None;` | **Broken:** passes validation but has no MSMPC mapping. Don't use. |
| `reject` | `reject` | |
| `reject-with-tcp-rst` | `None;` | **Broken:** passes validation but has no MSMPC mapping. Don't use. |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established`, `tcp-established` | — | | The term is skipped with a warning, because MSMPC is stateful. |
| `inactive` | Render the term but mark it inactive. | `option: inactive` | Prefixes the term with `inactive:`. |

Any other option value is accepted but ignored.
