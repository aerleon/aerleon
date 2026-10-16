# Juniper EVO

The Juniper EVO generator is built on the [Juniper](juniper.md) generator. It supports exactly the same header options, tokens, actions and options. The only difference is how IPv6 protocols are matched (below).

!!! info "Tables included from Juniper"
    The shared tables under Term Format, Actions and Option are included from the [Juniper](juniper.md) page, so they always match it. Anything that differs on Juniper EVO is called out on this page.

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

For an example, see [IPv6 loopback filter](#ipv6-loopback-filter).

## IPv6 Protocol Match

For Juniper EVO, the direction of the filter on an interface and the interface type determines the syntax to use; either `next-header` or `payload-protocol`. The syntax used for the extension headers and the payload header is summarized below.

| Direction | Interface | Extension headers (hop-by-hop, fragment, routing) | Payload (tcp, udp, ah, esp, icmpv6) |
|---|---|---|---|
| Ingress | Physical | `next-header hop-by-hop`, `next-header fragment`, `next-header routing` | `payload-protocol <proto>` |
| Ingress | Loopback | `payload-protocol 0`, `payload-protocol 44`, `payload-protocol 43` | `payload-protocol <proto>` |
| Egress | Physical | `payload-protocol 0`, `payload-protocol 44`, `payload-protocol 43` | `payload-protocol <proto>` |
| Egress | Loopback | `payload-protocol 0`, `payload-protocol 44`, `payload-protocol 43` | `payload-protocol <proto>` |

## Term Format

### Common tokens

These tokens are included from the [Common](common.md) page.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Inherited tokens

These tokens are included from the [Juniper](juniper.md#juniper-tokens) page.

--8<-- "docs/reference/generators/juniper.md:term-format"

## Actions

### Inherited actions

These actions are included from the [Juniper](juniper.md#actions) page.

--8<-- "docs/reference/generators/juniper.md:actions"

## Option

### Inherited options

These options are included from the [Juniper](juniper.md#option) page.

--8<-- "docs/reference/generators/juniper.md:option"

## Output

Each policy file renders to one file with the same name and a `.evojcl` extension, so `sample.yaml` renders `sample.evojcl`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

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

#### IPv6 loopback filter

An `inet6` filter for a loopback interface, applied `ingress`. See [IPv6 Protocol Match](#ipv6-protocol-match) for how the protocol is matched. It uses `SSH` from the sample definitions.

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
