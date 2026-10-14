# SRXlo

SRX Loopback renders a stateless Juniper firewall filter for an SRX loopback interface. It is built on the [Juniper](juniper.md) generator and supports the same header options, tokens, actions and options, with the differences below.

## Header Format

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

## Output

Each policy file renders to one file with the same name and a `.jsl` extension, so `sample.yaml` renders `sample.jsl`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        srxlo: lo0-filter inet
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
