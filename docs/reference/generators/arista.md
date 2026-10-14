# Arista

The arista generator is built on the [Cisco](cisco.md) generator, so its terms, actions and options work the same way.

## Header Format

The arista header designation has the following format:

```yaml
targets:
    arista: [filter name] {standard|extended|object-group|inet6|mixed} {enable_dsmo} {noverbose}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the access list. | |
| `standard` | Render a standard access list. | Numeric names must be in 1-99 or 1300-1999. |
| `extended` | Render an extended access list. | Default. |
| `object-group` | Render an extended access list that uses object-groups for ports and addresses. | |
| `inet6` | Render an IPv6-only access list. | |
| `mixed` | Render an IPv4 (extended) list and an IPv6 list together. | |
| `enable_dsmo` | Turn on discontinuous subnet mask summarization. | Optional. |
| `noverbose` | Leave out extra term and address comments. | Optional. |

## Term Format

For common keys see the [Common](common.md) page. The following tokens are specific to arista:

| Token | Description | Example | Notes |
|---|---|---|---|
| `address` | Address tokens matched as source **or** destination. | `address: INTERNAL` | Standard ACLs must use `address`; they reject `source-address`/`destination-address`. |
| `dscp-match` | Match a DSCP value. | `dscp-match: af41` | Only one value is allowed in extended ACLs. |
| `icmp-code` | ICMP code to match. | `icmp-code: 0` | |
| `logging` | Log matching packets. | `logging: true` | Adds `log` to the rule. |
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added as a comment. |
| `restrict-address-family` | Only render the term in the matching address family. | `restrict-address-family: inet` | Useful in `mixed` filters. |

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
| `established` | Match established connections. | `option: established` | Adds `established` for TCP. For UDP, sets the destination port to 1024-65535 if none is given. |
| `fragments` | Match fragments. | `option: fragments` | Same as `is-fragment`. |
| `is-fragment` | Match fragments. | `option: is-fragment` | Renders as `fragments`. |
| `tcp-established` | Match established TCP connections. | `option: tcp-established` | Adds `established`. TCP only. |
