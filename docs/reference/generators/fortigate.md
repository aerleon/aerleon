# Fortigate

Renders FortiOS firewall policies.

## Header Format

The Fortigate header designation has the following format:

```yaml
targets:
    fortigate: from-zone [source interface or zone] to-zone [destination interface or zone] {inet|inet6|mixed}
```

| Option | Description | Notes |
|---|---|---|
| `from-zone [name]` | Source interface or zone. | Required. |
| `to-zone [name]` | Destination interface or zone. | Required. Use `local-in-policy` to render a local-in policy instead of a firewall policy. |
| `inet` | IPv4 only. | |
| `inet6` | IPv6 only. | |
| `mixed` | IPv4 and IPv6. | Default. Not allowed with `local-in-policy`, which needs `inet` or `inet6`. |

Only one address family can be given.

## Term Format

For common keys see the [Common](common.md) page. Fortigate accepts all of them. It also reads these tokens:

| Token | Description | Example | Notes |
|---|---|---|---|
| `logging` | Turn on traffic logging for the policy. | `logging: true` | Without it, the policy gets `set logtraffic disable`. With it, Fortigate's default (UTM) is used unless a `log_traffic_*` option changes it. |
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added to the policy comment. |

Policy comments (owner plus `comment`) are cut to Fortigate's length limit, with a warning.

For an example, see [Logging options](#logging-options).

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `set action accept` | |
| `deny` | — | No `set action` line is written, so the policy uses the FortiOS default, `deny`. |

Other actions are rejected.

## Option

Options only take effect when the term also sets `logging`.

| Option | Description | Example | Notes |
|---|---|---|---|
| `log_traffic_mode_all` | Log all sessions. | `option: log_traffic_mode_all` | Renders `set logtraffic all`. Can't be combined with `log_traffic_mode_disable`. |
| `log_traffic_mode_disable` | Turn traffic logging off. | `option: log_traffic_mode_disable` | Renders `set logtraffic disable`. |
| `log_traffic_start_session` | Also log when a session starts. | `option: log_traffic_start_session` | Renders `set logtraffic-start enable`. Can be combined with either mode option. |

## Output

Each policy file renders to one file with the same name and a `.fgacl` extension, so `sample.yaml` renders `sample.fgacl`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        fortigate: from-zone internal to-zone wan
--8<-- "docs/reference/generators.md:sample-terms"
```

```text title="sample.fgacl"
config firewall address
    edit MGMT_0
        set type ipmask
        set subnet 10.0.0.0 255.255.255.0
    next
    edit MGMT_1
        set type ipmask
        set subnet 192.168.10.0 255.255.255.0
    next
end
config firewall addrgrp
    edit MGMT
        set member "MGMT_0" "MGMT_1"
    next
end
config firewall service custom
    edit allow-ssh
        set tcp-portrange 22
    next
end
config firewall policy
    edit 1
        set name "allow-ssh"
        set srcintf "internal"
        set dstintf "wan"
        set action accept
        set srcaddr "MGMT"
        set dstaddr "all"
        set schedule "always"
        set service "allow-ssh"
        set logtraffic disable
        set comments "Allow SSH from the management network."
    next
    edit 2
        set name "default-deny"
        set srcintf "internal"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set srcaddr6 "all"
        set dstaddr6 "all"
        set schedule "always"
        set service "ALL"
        set logtraffic disable
    next
end
```

#### Logging options

A term that turns on `logging` and uses `log_traffic_*` options to log all traffic from the start of the session.

```yaml title="logging.yaml"
filters:
  - header:
      targets:
        fortigate: from-zone internal to-zone wan
    terms:
      - name: deny-to-specific-hosts
        comment: "Deny access to specified public."
        destination-address: WEB_SERVERS MAIL_SERVERS
        logging: true
        option: log_traffic_mode_all log_traffic_start_session
        action: deny
```

```yaml title="definitions.yaml"
networks:
  WEB_SERVERS:
    values:
      - address: 203.0.113.10/32
  MAIL_SERVERS:
    values:
      - address: 203.0.113.25/32
```

```text title="logging.fgacl"
config firewall address
    edit MAIL_SERVERS_0
        set type ipmask
        set subnet 203.0.113.25 255.255.255.255
    next
    edit WEB_SERVERS_0
        set type ipmask
        set subnet 203.0.113.10 255.255.255.255
    next
end
config firewall addrgrp
    edit MAIL_SERVERS
        set member "MAIL_SERVERS_0"
    next
    edit WEB_SERVERS
        set member "WEB_SERVERS_0"
    next
end
config firewall policy
    edit 1
        set name "deny-to-specific-hosts"
        set srcintf "internal"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "MAIL_SERVERS" "WEB_SERVERS"
        set schedule "always"
        set service "ALL"
        set logtraffic all
        set logtraffic-start enable
        set comments "Deny access to specified public."
    next
end
```
