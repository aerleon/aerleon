# Windows Advanced Firewall

Renders `netsh advfirewall firewall add rule …` commands.

## Header Format

The Windows Advanced Firewall header designation has the following format:

```yaml
targets:
    windows_advfirewall: [out|in] {inet|inet6}
```

| Option | Description | Notes |
|---|---|---|
| `out` | Outbound rules (`dir=out`). | |
| `in` | Inbound rules (`dir=in`). | |
| `inet` | IPv4 only. | Default. |
| `inet6` | IPv6 only. | `mixed` is not accepted. |

The header also accepts `permit` or `block` as a default action, but the generator then raises "Windows generator does not support default actions", so don't use them.

## Term Format

For common keys see the [Common](common.md) page. Windows Advanced Firewall does **not** support `source-exclude`, `destination-exclude` (they raise an error) or `verbatim`.

* Rule names are `<first letter of direction>_<term>`, e.g. `o_allow-ssh`.
* For outbound rules, source is `local*` and destination is `remote*`; inbound is the reverse.
* ICMP types render as `icmpv4:<type>,any` (or `icmpv6:…`).

??? example "A term and its output"
    With header `windows_advfirewall: out inet`:

    ```yaml
    - name: allow-ssh
      destination-address: V4ONLY   # 192.168.0.0/16
      protocol: tcp
      destination-port: SSH
      action: accept
    ```

    ```text
    netsh advfirewall firewall add rule name=o_allow-ssh enable=yes interfacetype=any dir=out localip=any remoteip=192.168.0.0/16 remoteport=22 protocol=tcp action=allow
    ```

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `action=allow` | |
| `deny` | `action=block` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established`, `tcp-established` | — | | The term is skipped, without a warning. |

Any other option value is accepted but ignored, which makes the rule broader than intended (e.g. `option: syn` still allows all TCP).
