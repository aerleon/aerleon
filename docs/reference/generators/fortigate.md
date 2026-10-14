# Fortigate

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

??? example "A term with logging options"
    From `policies/pol/sample_fortigate.yaml`:

    ```yaml
    - name: deny-to-specific_hosts
      comment: "Deny access to specified public."
      destination-address: WEB_SERVERS MAIL_SERVERS
      logging: true
      option: log_traffic_mode_all log_traffic_start_session
      action: deny
    ```

## Actions

| Action | Notes |
|---|---|
| `accept` | |
| `deny` | |

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

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        fortigate: from-zone internal to-zone wan
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
