# Juniper EVO

The juniperevo generator is built on the [Juniper](juniper.md) generator. It supports exactly the same header options, tokens, actions and options. The only difference is how IPv6 protocols are matched (below).

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

??? example "Header for an IPv6 loopback filter"
    ```yaml
    targets:
        juniperevo: LOOPBACK-V6 inet6 ingress loopback
    ```

## IPv6 Protocol Match

For Juniper EVO, the direction of the filter on an interface and the interface type determines the syntax to use; either `next-header` or `payload-protocol`. The syntax used for the extension headers and the payload header is summarized below.

| Direction | Interface | Extension headers (hop-by-hop, fragment, routing) | Payload (tcp, udp, ah, esp, icmpv6) |
|---|---|---|---|
| Ingress | Physical | `next-header hop-by-hop`, `next-header fragment`, `next-header routing` | `payload-protocol <proto>` |
| Ingress | Loopback | `payload-protocol 0`, `payload-protocol 44`, `payload-protocol 43` | `payload-protocol <proto>` |
| Egress | Physical | `payload-protocol 0`, `payload-protocol 44`, `payload-protocol 43` | `payload-protocol <proto>` |
| Egress | Loopback | `payload-protocol 0`, `payload-protocol 44`, `payload-protocol 43` | `payload-protocol <proto>` |

## Term Format

For common keys see the [Common](common.md) page. The following tokens are the same as for [Juniper](juniper.md#term-format):

--8<-- "docs/reference/generators/juniper.md:term-format"

## Actions

Same as [Juniper](juniper.md#actions):

--8<-- "docs/reference/generators/juniper.md:actions"

## Option

Same as [Juniper](juniper.md#option):

--8<-- "docs/reference/generators/juniper.md:option"

## Output

Each policy file renders to one file with the same name and a `.evojcl` extension, so `sample.yaml` renders `sample.evojcl`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        juniperevo: edge-inbound inet
    terms:
      - name: allow-ssh
        comment: "Allow SSH from the management network."
        source-address: MGMT            # 10.0.0.0/24, 192.168.10.0/24
        protocol: tcp
        destination-port: SSH           # 22/tcp
        action: accept
      - name: default-deny
        action: deny
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
