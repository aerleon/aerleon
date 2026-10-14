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

??? example "Header"
    ```yaml
    targets:
       proxmox: vm IN dhcp log_level_in info ndp radv
    ```

## Term Format

For common keys see the [Common](common.md) page. The following tokens are specific to proxmox:

| Token | Description | Example | Notes |
|---|---|---|---|
| `icmp-code` | ICMP code to match. | `icmp-code: 0` | Combined with `icmp-type` into Proxmox's `-icmp-type` name. |
| `logging` | Log matching packets. | `logging: true` | Renders `-log <level>`. The level comes from a `log_*` option, otherwise the default. |
| `source-interface` | Match the incoming interface. | `source-interface: net0` | Renders `-iface net0`. Interface names aren't validated. |

* One rule is written per address family, protocol, ICMP type and code.
* Addresses are written as literal prefixes (`-source`, `-dest`), not IP sets, because IP sets live in a different file.
* `comment` is appended to the rule as `# <comment>`.

??? example "A term and its output"
    With header `proxmox: vm IN dhcp log_level_in info`:

    ```yaml
    - name: allow-ssh
      source-address: INTERNAL      # 10.0.0.0/8, 2001:db8::/32
      source-interface: net0
      protocol: tcp
      destination-port: SSH
      logging: true
      option: log_warning
      comment: "ssh in"
      action: accept
    ```

    ```text
    [OPTIONS]
    enable: 1
    dhcp: 1
    log_level_in: info
    [RULES]
    IN ACCEPT -proto tcp -iface net0 -source 10.0.0.0/8 -dport 22 -log warning # ssh in
    IN ACCEPT -proto tcp -iface net0 -source 2001:db8::/32 -dport 22 -log warning # ssh in
    ```

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `ACCEPT` | |
| `deny` | `DROP` | |
| `next`, `reject-with-tcp-rst` | — | **Broken:** pass validation, then crash with `KeyError`. |
| `reject` | `REJECT` | |

## Option

Options set the log level used when the term has `logging`.

| Option | Log level |
|---|---|
| `log_alert` | `alert` |
| `log_critical` | `crit` |
| `log_debug` | `debug` |
| `log_emergency` | `emerg` |
| `log_error` | `err` |
| `log_info` | `info` |
| `log_nolog` | `nolog` |
| `log_notice` | `notice` |
| `log_warning` | `warning` |
