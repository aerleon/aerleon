# SRXlo

SRX Loopback renders a stateless Juniper firewall filter for an SRX loopback interface. The SRXlo generator is built on the _[Juniper](juniper.md)_ generator.

## Header Format

```yaml
targets:
    srxlo: [filter name] {inet|inet6|mixed|bridge|ethernet-switching} {enable_dsmo} {not-interface-specific} {filter_enhanced_mode} {noverbose} {ingress|egress} {physical|loopback}
```

### Inherited header options

These header options are included from the _[Juniper](juniper.md#header-format)_ page.

--8<-- "docs/reference/generators/juniper.md:header-options"

## Term Format

### Common tokens

These tokens are included from the _[Common](common.md)_ page.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Inherited tokens

These tokens are included from the _[Juniper](juniper.md#juniper-tokens)_ page.

!!! warning "Not supported on SRXlo"
    `encapsulate`, `flexible-match-range` and `port-mirror` are listed in the Juniper table below, but SRXlo doesn't support them. A term that uses any of them raises an error.

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

Each policy file renders to one file with the same name and a `.jsl` extension, so `sample.yaml` renders `sample.jsl`.

### Differences from Juniper

| Area | Juniper | SRXlo |
|---|---|---|
| ICMPv6 protocol name | `icmpv6` | `icmp6` |

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

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

## Known Issues

These known issues are included from _[Juniper](juniper.md#known-issues)_:

--8<-- "docs/reference/generators/juniper.md:known-issues"
