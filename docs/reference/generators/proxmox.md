# Proxmox

Renders a Proxmox VE firewall configuration file (`[OPTIONS]` and `[RULES]` sections).

## Header Format

The Proxmox header designation has the following format:

```yaml
targets:
   proxmox: [cluster|host|vm|vnet] [IN|OUT|FORWARD] {zone options}
```

| Option | Description | Notes |
|---|---|---|
| `cluster`, `host`, `vm`, `vnet` | Firewall zone the file is for. | Required. All headers in a policy must use the same zone. |
| `IN`, `OUT`, `FORWARD` | Rule direction. | Required. See the zone table below for which directions each zone allows. |
| `zone options` | Settings for the `[OPTIONS]` section. | Optional, any order. Named exactly as in the [Proxmox firewall docs](https://pve.proxmox.com/pve-docs/chapter-pve-firewall.html). Options from all headers are merged. |

**Directions and options by zone:**

| Zone | Directions | Zone options |
|---|---|---|
| `cluster` | `IN`, `OUT`, `FORWARD` | `enable`, `ebtables`, `policy_in`, `policy_out`, `policy_forward` |
| `host` | `IN`, `OUT`, `FORWARD` | `enable`, `log_level_in`, `log_level_out`, `log_level_forward`, `log_nf_conntrack`, `ndp`, `nf_conntrack_allow_invalid`, `nf_conntrack_helpers`, `nf_conntrack_max`, `nf_conntrack_tcp_timeout_established`, `nf_conntrack_tcp_timeout_syn_recv`, `nftables`, `nosmurfs`, `protection_synflood`, `protection_synflood_burst`, `protection_synflood_rate`, `smurf_log_level`, `tcp_flags`, `tcp_flags_log_level` |
| `vm` | `IN`, `OUT` | `dhcp`, `enable`, `ipfilter`, `log_level_in`, `log_level_out`, `macfilter`, `ndp`, `policy_in`, `policy_out`, `radv` |
| `vnet` | `FORWARD` | `enable`, `log_level_forward`, `policy_forward` |

`policy_*` options take `ACCEPT`, `DROP` or `REJECT`; `log_level_*` options take a log level (`emerg` … `debug`, `nolog`).

## Term Format

### Common tokens

These tokens are included from the [Common](common.md) page.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Proxmox tokens

The following tokens are specific to Proxmox:

| Token | Description | Example | Notes |
|---|---|---|---|
| `icmp-code` | ICMP code to match. | `icmp-code: 0` | Combined with `icmp-type` into Proxmox's `-icmp-type` name. |
| `logging` | Log matching packets. | `logging: true` | Renders `-log <level>`. The level comes from a `log_*` option, otherwise the default. |
| `source-interface` | Match the incoming interface. | `source-interface: net0` | Renders `-iface net0`. Interface names aren't validated. |

* One rule is written per address family, protocol, ICMP type and code.
* Addresses are written as literal prefixes (`-source`, `-dest`), not IP sets, because IP sets live in a different file.
* `comment` is appended to the rule as `# <comment>`.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `ACCEPT` | |
| `deny` | `DROP` | |
| `next`, `reject-with-tcp-rst` | — | **Broken:** pass validation, then crash with `KeyError`. |
| `reject` | `REJECT` | |

## Option

Options set the log level used when the term has `logging`.

| Option | Description | Example | Notes |
|---|---|---|---|
| `log_alert` | Log at the `alert` level. | `option: log_alert` | |
| `log_critical` | Log at the `crit` level. | `option: log_critical` | |
| `log_debug` | Log at the `debug` level. | `option: log_debug` | |
| `log_emergency` | Log at the `emerg` level. | `option: log_emergency` | |
| `log_error` | Log at the `err` level. | `option: log_error` | |
| `log_info` | Log at the `info` level. | `option: log_info` | |
| `log_nolog` | Log at the `nolog` level. | `option: log_nolog` | Turns logging off for the term. |
| `log_notice` | Log at the `notice` level. | `option: log_notice` | |
| `log_warning` | Log at the `warning` level. | `option: log_warning` | |

## Output

Each policy file renders to one file with the same name and a `.prxmxfw` extension, so `sample.yaml` renders `sample.prxmxfw`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        proxmox: vm IN
--8<-- "docs/reference/generators.md:sample-terms"
```

```text title="sample.prxmxfw"
[OPTIONS]
enable: 1
[RULES]
IN ACCEPT -proto tcp -source 10.0.0.0/24,192.168.10.0/24 -dport 22 # Allow SSH from the management network.
IN DROP
```

#### Interface and logging

The sample `allow-ssh` term with `source-interface` and `logging`. It uses the sample definitions.

```yaml title="interface.yaml"
filters:
  - header:
      targets:
        proxmox: vm IN
    terms:
      - name: allow-ssh
        comment: "Allow SSH from the management network."
        source-address: MGMT
        protocol: tcp
        destination-port: SSH
        source-interface: net0
        logging: true
        action: accept
```

```text title="interface.prxmxfw"
[OPTIONS]
enable: 1
[RULES]
IN ACCEPT -proto tcp -iface net0 -source 10.0.0.0/24,192.168.10.0/24 -dport 22 -log warning # Allow SSH from the management network.
```
