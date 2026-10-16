# Juniper MSMPC

Renders Junos MS-MPC service filters.

## Header Format

The Juniper MSMPC header designation has the following format:

```yaml
targets:
    msmpc: [filter name] {inet|inet6|mixed} {noverbose} {ingress|egress} {no-apply-groups}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the filter. | |
| `inet` | Render IPv4 only. | |
| `inet6` | Render IPv6 only. | |
| `mixed` | Render IPv4 and IPv6. | Default. |
| `noverbose` | Leave out term comments and owner. | Optional. |
| `ingress` | Apply the filter in the input direction. | Optional. |
| `egress` | Apply the filter in the output direction. | Optional. Without `ingress` or `egress`, the filter applies in both directions. |
| `no-apply-groups` | Leave `apply-groups` out of the configuration. | Optional. |

Only one address family and one direction can be given. When `inet` or `inet6` is specified, naming tokens that contain both IPv4 and IPv6 addresses are rendered using only the matching addresses.

## Term Format

### Common tokens

These tokens are included from the [Common](common.md) page.

!!! warning "Not supported on Juniper MSMPC"
    MSMPC is stateful, so terms that use `established`/`tcp-established` or are stateless replies are skipped with a warning.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Juniper MSMPC tokens

The following tokens are specific to Juniper MSMPC:

| Token | Description | Example | Notes |
|---|---|---|---|
| `destination-prefix` | Match a prefix-list already configured on the device. | `destination-prefix: local-addrs` | Renders as `destination-prefix-list`. |
| `destination-prefix-except` | Exclude a configured prefix-list. | `destination-prefix-except: vip-addrs` | Renders as `destination-prefix-list … except`. |
| `icmp-code` | ICMP code to match. | `icmp-code: 0` | |
| `logging` | Log matching packets. | `logging: true` | Adds `syslog`. `logging: disable` turns it off. |
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added to the term comment unless the header uses `noverbose`. |
| `source-prefix` | Match a prefix-list already configured on the device. | `source-prefix: configured-neighbors-only` | Renders as `source-prefix-list`. |
| `source-prefix-except` | Exclude a configured prefix-list. | `source-prefix-except: bad-neighbors` | Renders as `source-prefix-list … except`. |

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `accept` | |
| `deny` | `discard` | |
| `next` | `None;` | **Broken:** passes validation but has no MSMPC mapping. Don't use. |
| `reject` | `reject` | |
| `reject-with-tcp-rst` | `None;` | **Broken:** passes validation but has no MSMPC mapping. Don't use. |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established`, `tcp-established` | — | | The term is skipped with a warning, because MSMPC is stateful. |
| `inactive` | Render the term but mark it inactive. | `option: inactive` | Prefixes the term with `inactive:`. |

Any other option value is accepted but ignored.

## Output

Each policy file renders to one file with the same name and a `.msmpc` extension, so `sample.yaml` renders `sample.msmpc`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        msmpc: edge-inbound inet
--8<-- "docs/reference/generators.md:sample-terms"
```

```text title="sample.msmpc"
groups {
    replace:
    /*
     ** $Id:$
     ** $Date:$
     ** $Revision:$
     **
     */
    edge-inbound {
        services {
            stateful-firewall {
                rule edge-inbound {
                    match-direction input-output;
                    /*
                     ** Allow SSH from the management network.
                     */
                    term allow-ssh {
                        from {
                            source-address {
                                10.0.0.0/24;
                                192.168.10.0/24;
                            }
                            application-sets edge-inboundallow-ssh-app;
                        }
                        then {
                            accept;
                        }
                    }
                    term default-deny {
                        then {
                            discard;
                        }
                    }
                }
            }
        }
        applications {
            application edge-inboundallow-ssh-app1 {
                protocol tcp;
                destination-port 22;
            }
            application-set edge-inboundallow-ssh-app {
                application edge-inboundallow-ssh-app1;
            }
        }
    }
}
apply-groups edge-inbound;
```
