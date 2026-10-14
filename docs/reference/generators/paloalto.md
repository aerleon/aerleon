# PaloAltoFW

Renders a Palo Alto Networks firewall configuration (security rules, address objects, services and custom applications) as XML.

## Header Format

The paloalto header designation has the following format:

```yaml
targets:
    paloalto: from-zone [zone name] to-zone [zone name] {inet|inet6|mixed} {addr-obj|no-addr-obj} {unique-term-prefixes}
```

The options are positional: to use `unique-term-prefixes` you must also give the address family and the address-object option.

| Option | Description | Notes |
|---|---|---|
| `from-zone [name]` | Source zone. | Required. Max 31 characters. |
| `to-zone [name]` | Destination zone. | Required. Max 31 characters. |
| `inet` | IPv4 only. | Default. |
| `inet6` | IPv6 only. | |
| `mixed` | IPv4 and IPv6. | |
| `addr-obj` | Use address groups in the rules' source and destination. | Default. |
| `no-addr-obj` | Use network/mask values directly in the rules. | All headers in a policy file must use the same choice. |
| `unique-term-prefixes` | Prefix each rule name with a hash of the from/to zones. | Makes rule names unique across policies. Not cryptographically guaranteed. |

## Term Format

For common keys see the [Common](common.md) page. PaloAltoFW does **not** support `verbatim`. It also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `logging` | Log sessions. | `logging: true` | `true`, `syslog` or `local`: `log-end`. `log-both`: `log-start` and `log-end`. `disable`: no logging. |
| `owner`, `timeout` | — | | Accepted, but ignored. |
| `pan-application` | Palo Alto applications to match. | `pan-application: ssl web-browsing` | Predefined applications (<https://applipedia.paloaltonetworks.com/>) or custom application objects. Only allowed with no `protocol`, or with `tcp`/`udp`. See the service table below. |
| `profile-settings` | Security profile group(s) for the rule. | `profile-settings: default-profile` | Rendered as `profile-setting` → `group`. |
| `tags` | Tags to add to the rule. | `tags: production web` | Also added to the global tag list. |

* `icmp-type` is rendered as a custom application using `ident-by-icmp-type`.
* Rule names are at most 63 characters.

**Service setting with `pan-application`:**

| Term has | Rule service |
|---|---|
| No `protocol` | `application-default` |
| `protocol: tcp`/`udp`, no ports | Custom service objects for the protocols and all ports (0-65535) |
| `protocol: tcp`/`udp` with ports | Custom service objects for the protocols and ports |

??? example "A term and its output"
    With header `paloalto: from-zone trust to-zone untrust`:

    ```yaml
    - name: allow-ping
      source-address: V4ONLY
      protocol: icmp
      icmp-type: echo-request
      action: accept
    ```

    ```xml
    <entry name="allow-ping">
      <to><member>untrust</member></to>
      <from><member>trust</member></from>
      <source><member>V4ONLY</member></source>
      <destination><member>any</member></destination>
      <service><member>application-default</member></service>
      <action>allow</action>
      <rule-type>interzone</rule-type>
      <application><member>icmp-echo-request</member></application>
    </entry>
    ```

    A matching custom application `icmp-echo-request` (`ident-by-icmp-type`, type 8) is also generated.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `allow` | |
| `deny` | `deny` | |
| `reject` | `reset-client` | |
| `reject-with-tcp-rst` | `reset-client` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established`, `tcp-established` | — | | The term is skipped with a warning (the firewall is stateful). |
