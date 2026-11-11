# OpenConfig Model

Renders ACL sets in the [OpenConfig ACL model](https://openconfig.net/projects/models/schemadocs/yangdoc/openconfig-acl.html) as JSON.

## Header Format

```yaml
targets:
    openconfig: [filter name] {inet|inet6|mixed}
```

<!-- --8<-- [start:header-options] -->

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the filter. | The first option is always the name. If unset, whichever option comes first takes its place and still takes effect, so a target of just `inet6` renders an IPv6 filter named `inet6`. With no options at all, the name renders as `null`. |
| `inet` | IPv4 only. | Default. |
| `inet6` | IPv6 only. | |
| `mixed` | IPv4 and IPv6. | Each term is rendered once for IPv4 and once for IPv6. A term with no addresses of one family matches everything in that family; see _[Known Issues](#known-issues)_. |

Any header option not listed on this page is silently ignored.

<!-- --8<-- [end:header-options] -->

## Term Format

### Common tokens

These tokens are included from the _[Common](common.md)_ page.

!!! warning "Not supported on OpenConfig"
    OpenConfig doesn't support `icmp-type`, `platform`, `platform-exclude` or `verbatim`. A term that uses any of them raises an error.

--8<-- "docs/reference/generators/common.md:common-tokens"

### How tokens are rendered

OpenConfig adds no tokens of its own.

<!-- --8<-- [start:term-format] -->

| Token | How it's rendered | Notes |
|---|---|---|
| `comment` | — | Accepted, but not rendered. |
| `protocol` | `ipv4.config.protocol` (or `ipv6.…`) | Always rendered as a number. A name Aerleon doesn't know raises `OcFirewallError`; use the number instead. |
| `source-address`, `destination-address` | `ipv4.config.source-address` / `destination-address` (or `ipv6.…`) | Only addresses of the family being rendered are used. Exclusions are applied before rendering, but an exclusion on only one side crashes; see _[Known Issues](openconfig.md#known-issues)_. |
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

### ACL set

<!-- --8<-- [start:acl-set] -->

Each filter renders as one `acl-set`:

| Field | Value |
|---|---|
| `name`, `config.name` | The filter name. |
| `type`, `config.type` | `ACL_IPV4` for `inet`, `ACL_IPV6` for `inet6`, `ACL_MIXED` for `mixed`. |

<!-- --8<-- [end:acl-set] -->

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

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

<!-- --8<-- [start:known-issues] -->

!!! bug "Known issues"
    * **A term with no addresses of the family being rendered matches everything.** In a `mixed` filter, a term with only IPv4 sources also renders an IPv6 entry with no source address, so it matches all IPv6 sources. The same happens in an `inet6` filter. Aerleon should skip the entry instead.
    * **More than one address family picks one unpredictably.** With `f1 inet inet6`, the family used can change from one run to the next, because the options are checked in an unordered set. Give only one of `inet`, `inet6` or `mixed`.
    * Exclusions crash with mixed-family address tokens (`TypeError: … are not of the same version`), as in _[GCE](gce.md)_.
    * Because `platform-exclude` raises an error, a shared policy that uses `platform-exclude` to skip a term on another vendor can't be rendered for OpenConfig at all.
    * **An exclusion on only one side crashes the generator.** A term with `source-exclude` but no `destination-exclude`, or the reverse, fails with `TypeError: 'NoneType' object is not iterable`. Exclusions only work when both sides have one.

<!-- --8<-- [end:known-issues] -->
