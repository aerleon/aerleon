# Juniper EVO

Renders ACLs for Junos EVO platform. The Junos EVO generator is built on the _[Juniper](juniper.md)_ generator.

## Header Format

```yaml
targets:
    juniperevo: [filter name] {inet|inet6|mixed|bridge|ethernet-switching} {enable_dsmo} {not-interface-specific} {filter_enhanced_mode} {noverbose} {ingress|egress} {physical|loopback}
```

### Inherited header options

These header options are included from the _[Juniper](juniper.md#header-format)_ page.

--8<-- "docs/reference/generators/juniper.md:header-options"

### Juniper EVO header options

The following header options are specific to Juniper EVO, or work differently than on Juniper:

| Option | Description | Notes |
|---|---|---|
| `ingress`, `egress` | Direction the filter is applied in. | **Required** for `inet6` and `mixed` filters; an error is raised without it. Sets how IPv6 protocols are matched; see _[IPv6 protocol match](#ipv6-protocol-match)_. |
| `physical`, `loopback` | Type of interface the filter is applied to. | Optional. Defaults to `physical`. Sets how IPv6 protocols are matched; see _[IPv6 protocol match](#ipv6-protocol-match)_. |

For an example, see _[IPv6 loopback filter](#examples-ipv6-loopback-filter)_.

## Term Format

### Common tokens

These tokens are included from the _[Common](common.md)_ page.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Inherited tokens

These tokens are included from the _[Juniper](juniper.md#juniper-tokens)_ page.

--8<-- "docs/reference/generators/juniper.md:term-format"

## Actions

### Inherited actions

These actions are included from the _[Juniper](juniper.md#actions)_ page.

--8<-- "docs/reference/generators/juniper.md:actions"

## Option

### Inherited options

These options are included from the _[Juniper](juniper.md#option)_ page.

--8<-- "docs/reference/generators/juniper.md:option"

## Output

Each policy file renders to one file with the same name and a `.evojcl` extension, so `sample.yaml` renders `sample.evojcl`.

### Differences from Juniper

| Area | Juniper | Juniper EVO |
|---|---|---|
| IPv6 `protocol` | `next-header` | `next-header` or `payload-protocol`, depending on the direction and interface type; see _[IPv6 protocol match](#ipv6-protocol-match)_ |
| IPv6 `protocol-except` | `next-header-except` | `next-header-except` or `payload-protocol-except`, by the same rules |

#### IPv6 protocol match

In an `inet6` filter, and in the IPv6 half of a `mixed` filter, the keyword depends on the header's direction and interface type, and on whether the term matches an extension header:

| Header | Hop-by-hop (`hopopt`) and fragment (`fragment`) | Other protocols |
|---|---|---|
| `ingress` (physical) | `next-header hop-by-hop`, `next-header fragment` | `payload-protocol <proto>` |
| `ingress loopback` | `payload-protocol 0`, `payload-protocol 44` | `payload-protocol <proto>` |
| `egress`, `egress loopback` | `payload-protocol 0`, `payload-protocol 44` | `payload-protocol <proto>` |

On `ingress` (physical), a term that lists an extension header uses `next-header` for all of its protocols: `protocol: tcp hopopt` renders `next-header [ tcp hop-by-hop ];`. The routing header (`ipv6-route`) isn't treated as an extension header; see _[Known Issues](#known-issues)_.

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

    ```yaml title="sample.yaml"
    filters:
      - header:
          targets:
            juniperevo: edge-inbound inet
    --8<-- "docs/reference/generators.md:sample-terms"
    ```

    ```text title="sample.evojcl"
    firewall {
        family inet {
            /*
             ** $Id:$
             ** $Date:$
             ** $Revision:$
             **
             */
            replace: filter edge-inbound {
                interface-specific;
                /*
                 ** Allow SSH from the management network.
                 */
                term allow-ssh {
                    from {
                        source-address {
                            10.0.0.0/24;
                            192.168.10.0/24;
                        }
                        protocol tcp;
                        destination-port 22;
                    }
                    then accept;
                }
                term default-deny {
                    then {
                        discard;
                    }
                }
            }
        }
    }
    ```

=== "IPv6 loopback filter"

    An `inet6` filter for a loopback interface, applied `ingress`. See _[IPv6 Protocol Match](#ipv6-protocol-match)_ for how the protocol is matched. It uses `SSH` from the sample definitions.

    ```yaml title="loopback.yaml"
    filters:
      - header:
          targets:
            juniperevo: LOOPBACK-V6 inet6 ingress loopback
        terms:
          - name: allow-ssh
            protocol: tcp
            destination-port: SSH
            action: accept
    ```

    ```text title="loopback.evojcl"
    firewall {
        family inet6 {
            /*
             ** $Id:$
             ** $Date:$
             ** $Revision:$
             **
             */
            replace: filter LOOPBACK-V6 {
                interface-specific;
                term allow-ssh {
                    from {
                        payload-protocol tcp;
                        destination-port 22;
                    }
                    then accept;
                }
            }
        }
    }
    ```

## Known Issues

!!! bug "Known issues"
    * **The routing header is matched as a payload protocol.** Only hop-by-hop and fragment are treated as extension headers, so `protocol: ipv6-route` always renders as `payload-protocol ipv6-route`, even on `ingress` (physical), where the other extension headers use `next-header`.

These known issues are included from _[Juniper](juniper.md#known-issues)_:

--8<-- "docs/reference/generators/juniper.md:known-issues"
