# SRXlo

SRX Loopback renders a stateless Juniper firewall filter for an SRX loopback interface. It is built on the [Juniper](juniper.md) generator and supports the same header options, tokens, actions and options, with the differences below.

!!! info "Tables included from Juniper"
    The shared tables under Term Format, Actions and Option are included from the [Juniper](juniper.md) page, so they always match it. Anything that differs on SRXlo is called out on this page.

## Header Format

The SRXlo header designation has the following format:

```yaml
targets:
    srxlo: [filter name] {inet|inet6|mixed|bridge|ethernet-switching} {enable_dsmo} {not-interface-specific} {filter_enhanced_mode} {noverbose} {ingress|egress} {physical|loopback}
```

All options work as described for [Juniper](juniper.md).

## Differences from Juniper

| Area | Juniper | SRXlo |
|---|---|---|
| `flexible-match-range` | Supported | Not supported (MX/Trio only) |
| `encapsulate` | Supported | Not supported |
| `port-mirror` | Supported | Not supported |
| ICMPv6 protocol name | `icmpv6` | `icmp6` |
| File suffix | `.jcl` | `.jsl` |

## Term Format

### Common tokens

These tokens are included from the [Common](common.md) page.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Inherited tokens

These tokens are included from the [Juniper](juniper.md#juniper-tokens) page.

!!! warning "Not supported on SRXlo"
    `encapsulate`, `flexible-match-range` and `port-mirror` are listed in the Juniper table below, but SRXlo doesn't support them. A term that uses any of them raises an error.

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

Each policy file renders to one file with the same name and a `.jsl` extension, so `sample.yaml` renders `sample.jsl`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        srxlo: lo0-filter inet
--8<-- "docs/reference/generators.md:sample-terms"
```

```text title="sample.jsl"
firewall {
    family inet {
        /*
         ** $Id:$
         ** $Date:$
         ** $Revision:$
         **
         */
        replace: filter lo0-filter {
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
