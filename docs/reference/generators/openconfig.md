# OpenConfig

Renders ACL sets in the [OpenConfig ACL model](https://openconfig.net/projects/models/schemadocs/yangdoc/openconfig-acl.html) as JSON. [SONiC](sonic.md) and [Nokia SR Linux](nokiasrl.md) are built on this generator.

## Header Format

The OpenConfig header designation has the following format:

```yaml
targets:
    openconfig: [filter name] {inet|inet6|mixed}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the ACL set. | Rendered as `name` and `config.name`. If it's left out, both render as `null`. |
| `inet` | IPv4 only. | Default. ACL type `ACL_IPV4`. |
| `inet6` | IPv6 only. | ACL type `ACL_IPV6`. |
| `mixed` | IPv4 and IPv6. | ACL type `ACL_MIXED`. Each term is rendered once for IPv4 and once for IPv6. A term with no addresses of one family matches everything in that family; see [Known Issues](#known-issues). |

Any other header option is silently ignored.

## Term Format

For common keys see the [Common](common.md) page. OpenConfig does **not** support `platform`, `platform-exclude` or `verbatim` (they raise an error). It adds no tokens of its own.

| Token | How it's rendered | Notes |
|---|---|---|
| `comment` | — | Accepted, but not rendered. |
| `protocol` | `ipv4.config.protocol` (or `ipv6.…`) | Always rendered as a number. A name Aerleon doesn't know raises `OcFirewallError`; use the number instead. |
| `source-address`, `destination-address` | `ipv4.config.source-address` / `destination-address` (or `ipv6.…`) | Only addresses of the family being rendered are used. Exclusions are applied before rendering. |
| `source-port`, `destination-port` | `transport.config.source-port` / `destination-port` | A single port renders as a number, a range as `"start..end"`. |

One ACL entry is written for every combination of source address, destination address, source port, destination port and protocol. Entries get sequence IDs 5, 10, 15, …, and the numbering carries on across filters in the same policy.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `ACCEPT` | |
| `deny` | `DROP` | |
| `reject` | `REJECT` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `tcp-established` | Match established TCP sessions. | `option: tcp-established` | Renders `"detail-mode": "BUILTIN", "builtin-detail": "TCP_ESTABLISHED"` under `transport.config`. The term's `protocol` must be exactly `tcp`, otherwise `TcpEstablishedWithNonTcpError` is raised. |

## Known Issues

!!! bug "Known issues"
    * **A term with no addresses of the family being rendered matches everything.** In a `mixed` filter, a term with only IPv4 sources also renders an IPv6 entry with no source address, so it matches all IPv6 sources. The same happens in an `inet6` filter. Aerleon should skip the entry instead.
    * **`icmp-type` is silently ignored.** It is accepted, but not rendered, so a term meant to allow only `echo-request` allows all ICMP.
    * Exclusions crash with mixed-family address tokens (`TypeError: … are not of the same version`), as in [GCE](gce.md).
    * Because `platform-exclude` raises an error, a shared policy that uses `platform-exclude` to skip a term on another vendor can't be rendered for OpenConfig at all.
