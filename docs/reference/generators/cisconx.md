# CiscoNX

The cisconx generator is built on the [Cisco](cisco.md) generator. It supports exactly the same tokens, actions and options, so see the Cisco [Term Format](cisco.md#term-format), Actions and Option tables. The differences are listed below.

## Header Format

The cisconx header designation has the following format:

```yaml
targets:
    cisconx: [filter name] {extended|object-group|inet6|mixed} {enable_dsmo} {noverbose}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the access list. | |
| `extended` | Render an extended access list. | Default. |
| `object-group` | Render an extended access list that uses object-groups for ports and addresses. | |
| `inet6` | Render an IPv6-only access list. | |
| `mixed` | Render an IPv4 list and an IPv6 list together. | |
| `enable_dsmo` | Turn on discontinuous subnet mask summarization. | Optional. |
| `noverbose` | Leave out extra term and address comments. | Optional. |

## Differences from Cisco

| Area | Cisco | CiscoNX |
|---|---|---|
| `standard` access lists | Supported | Not supported (raises an error) |
| `extended` keyword in output | `ip access-list extended NAME` | `ip access-list NAME` |
| Protocols | Rendered as numbers where possible | Rendered by name, as written in the policy |
