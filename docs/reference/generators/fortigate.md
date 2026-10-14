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
