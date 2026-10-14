# CiscoASA

## Header Format

The ciscoasa header designation has the following format:

```yaml
targets:
    ciscoasa: [filter name] {enable_dsmo}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the access list. | |
| `enable_dsmo` | Turn on discontinuous subnet mask summarization. | Optional. |

## Term Format

For common keys see the [Common](common.md) page. The following tokens are specific to ciscoasa:

| Token | Description | Example | Notes |
|---|---|---|---|
| `logging` | Log matching packets. | `logging: true` | Adds `log`. Use `logging: disable` to render `log disable`. |
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added as a `remark`. |

Unlike [Cisco](cisco.md), ciscoasa does not support `address`, `restrict-address-family`, `dscp-match` or `icmp-code`.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `permit` | |
| `deny` | `deny` | |
| `next` | `! next` | Rendered as a comment. |
| `reject` | `deny` | |
| `reject-with-tcp-rst` | `deny` | TCP reset is not supported. |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established` | Match established TCP connections. | `option: established` | Adds `established` to TCP rules only. Unlike Cisco, no high ports are added for UDP. |
| `tcp-established` | Match established TCP connections. | `option: tcp-established` | Adds `established` to TCP rules. |
