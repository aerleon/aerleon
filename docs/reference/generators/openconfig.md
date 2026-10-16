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

### Common tokens

These tokens are included from the [Common](common.md) page.

!!! warning "Not supported on OpenConfig"
    OpenConfig doesn't support `platform`, `platform-exclude` or `verbatim`. A term that uses any of them raises an error.

--8<-- "docs/reference/generators/common.md:common-tokens"

### How tokens are rendered

OpenConfig adds no tokens of its own.

<!-- --8<-- [start:term-format] -->

| Token | How it's rendered | Notes |
|---|---|---|
| `comment` | — | Accepted, but not rendered. |
| `protocol` | `ipv4.config.protocol` (or `ipv6.…`) | Always rendered as a number. A name Aerleon doesn't know raises `OcFirewallError`; use the number instead. |
| `source-address`, `destination-address` | `ipv4.config.source-address` / `destination-address` (or `ipv6.…`) | Only addresses of the family being rendered are used. Exclusions are applied before rendering, but an exclusion on only one side crashes; see [Known Issues](openconfig.md#known-issues). |
| `source-port`, `destination-port` | `transport.config.source-port` / `destination-port` | A single port renders as a number, a range as `"start..end"`. |

One ACL entry is written for every combination of source address, destination address, source port, destination port and protocol. Entries get sequence IDs 5, 10, 15, …, and the numbering carries on across filters in the same policy.

<!-- --8<-- [end:term-format] -->

## Actions

<!-- --8<-- [start:actions] -->

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `ACCEPT` | |
| `deny` | `DROP` | |
| `reject` | `REJECT` | |

<!-- --8<-- [end:actions] -->

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `tcp-established` | Match established TCP sessions. | `option: tcp-established` | Renders `"detail-mode": "BUILTIN", "builtin-detail": "TCP_ESTABLISHED"` under `transport.config`. The term's `protocol` must be exactly `tcp`, otherwise `TcpEstablishedWithNonTcpError` is raised. |

## Output

Each policy file renders to one file with the same name and a `.oacl` extension, so `sample.yaml` renders `sample.oacl`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        openconfig: edge-inbound inet
--8<-- "docs/reference/generators.md:sample-terms"
```

```json title="sample.oacl"
[
  {
    "acl-entries": {
      "acl-entry": [
        {
          "actions": {
            "config": {
              "forwarding-action": "ACCEPT"
            }
          },
          "ipv4": {
            "config": {
              "protocol": 6,
              "source-address": "10.0.0.0/24"
            }
          },
          "sequence-id": 5,
          "transport": {
            "config": {
              "destination-port": 22
            }
          }
        },
        {
          "actions": {
            "config": {
              "forwarding-action": "ACCEPT"
            }
          },
          "ipv4": {
            "config": {
              "protocol": 6,
              "source-address": "192.168.10.0/24"
            }
          },
          "sequence-id": 10,
          "transport": {
            "config": {
              "destination-port": 22
            }
          }
        },
        {
          "actions": {
            "config": {
              "forwarding-action": "DROP"
            }
          },
          "sequence-id": 15
        }
      ]
    },
    "config": {
      "name": "edge-inbound",
      "type": "ACL_IPV4"
    },
    "name": "edge-inbound",
    "type": "ACL_IPV4"
  }
]
```

## Known Issues

!!! bug "Known issues"
    * **A term with no addresses of the family being rendered matches everything.** In a `mixed` filter, a term with only IPv4 sources also renders an IPv6 entry with no source address, so it matches all IPv6 sources. The same happens in an `inet6` filter. Aerleon should skip the entry instead.
    * **`icmp-type` is silently ignored.** It is accepted, but not rendered, so a term meant to allow only `echo-request` allows all ICMP.
    * Exclusions crash with mixed-family address tokens (`TypeError: … are not of the same version`), as in [GCE](gce.md).
    * Because `platform-exclude` raises an error, a shared policy that uses `platform-exclude` to skip a term on another vendor can't be rendered for OpenConfig at all.
    * **An exclusion on only one side crashes the generator.** A term with `source-exclude` but no `destination-exclude`, or the reverse, fails with `TypeError: 'NoneType' object is not iterable`. Exclusions only work when both sides have one.
