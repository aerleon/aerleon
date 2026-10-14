# Proxmox

## Header Format
The Proxmox header designation has the following format:
```yaml
targets:
   proxmox: [cluster|host|vnet|vm] [IN|OUT|FORWARD] {zone_options}
```

Where `zone_options` differs from zone to zone, and is a set of options separated by spaces.
The order does not matter, and some options take one or more arguments, also separated by spaces.
The options are named exactly the same as in the
[Proxmox Firewall Documentation](https://pve.proxmox.com/pve-docs/chapter-pve-firewall.html).

The acceptable direction arguments (*IN, OUT or FORWARD*) vary depending on the zone type:
```text
| Zone    | Available directions |
|---------+----------------------|
| cluster | IN OUT FORWARD       |
| host    | IN OUT FORWARD       |
| vm      | IN OUT               |
| vnet    | FORWARD              |
```

Example:
```yaml
targets:
   proxmox: vm IN dhcp log_level_in info ndp radv
```

## Term Format
* For common keys, see section [common](common.md) above.
* _source-interface_: specify source interface via the `-iface` directive in the Proxmox Firewall rule.
  Please note no interface naming validation is done in the plugin.
## Sub Tokens
## Actions
* _accept_
* _deny_
* _reject_
## Option
* _log_nolog_: disable logging for the Term
* _log_emergency_: set log level to `emerg` for the Term
* _log_alert_: set log level to `alert` for the Term
* _log_critical_: set log level to `crit` for the Term
* _log_error_: set log level to `err` for the Term
* _log_notice_: set log level to `notice` for the Term
* _log_info_: set log level to `info` for the Term
* _log_debug_: set log level to `debug` for the Term
