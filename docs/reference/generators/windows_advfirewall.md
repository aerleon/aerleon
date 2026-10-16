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

## Output

Each policy file renders to one file with the same name and a `.bat` extension, so `sample.yaml` renders `sample.bat`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        windows_advfirewall: in inet
--8<-- "docs/reference/generators.md:sample-terms"
```

```text title="sample.bat"
: Windows_advfirewall in Policy
: $Id:$
: $Date:$
: $Revision:$
: inet
netsh advfirewall firewall add rule name=i_allow-ssh enable=yes interfacetype=any dir=in remoteip=10.0.0.0/24,192.168.10.0/24 localip=any localport=22 protocol=tcp action=allow
netsh advfirewall firewall add rule name=i_default-deny enable=yes interfacetype=any dir=in remoteip=any localip=any protocol=any action=block
```
