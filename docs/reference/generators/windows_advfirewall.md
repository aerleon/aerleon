# Windows Advanced Firewall

Renders `netsh advfirewall firewall add rule …` commands.

## Header Format

```yaml
targets:
    windows_advfirewall: [out|in] {inet|inet6|mixed} {permit|block}
```

| Option | Description | Notes |
|---|---|---|
| `out` | Outbound rules (`dir=out`). | |
| `in` | Inbound rules (`dir=in`). | |
| `inet` | IPv4 only. | |
| `inet6` | IPv6 only. | |
| `mixed` | Both address families. | Default. netsh takes IPv4 and IPv6 addresses in one `remoteip`/`localip` list, so each term renders once with all its addresses. `icmp` and `icmpv6` both render; under `inet` only `icmp` does, and under `inet6` only `icmpv6`. |
| `permit`, `block` | The default action for this direction, on all profiles. | Optional. Renders `netsh advfirewall set allprofiles firewallpolicy`, with the other direction left `notconfigured`. Without it, the host's default is unchanged. |

A `block` default is the way to express default deny. A final deny-all term doesn't work on Windows: block rules take precedence over allow rules, so it would block the traffic the earlier terms allow.

## Term Format

### Common tokens

These tokens are included from the _[Common](common.md)_ page.

!!! warning "Not supported on Windows Advanced Firewall"
    Windows Advanced Firewall doesn't support `source-exclude`, `destination-exclude` or `verbatim`. A term that uses any of them raises an error.

--8<-- "docs/reference/generators/common.md:common-tokens"

### How tokens are rendered

* Rule names are `<first letter of direction>_<term>`, e.g. `o_allow-ssh`.
* For outbound rules, source is `local*` and destination is `remote*`; inbound is the reverse.
* ICMP types render as `icmpv4:<type>,any` (or `icmpv6:…`).

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `action=allow` | |
| `deny` | `action=block` | |

## Option

!!! info "Stateful firewall"
    Windows Firewall tracks sessions, so return traffic is allowed without a separate term. Terms that use `established` or `tcp-established` are skipped **without** a warning; see _[Known Issues](#known-issues)_. See _[Stateful firewalls](common.md#stateful-firewalls)_.

| Option | Description | Example | Notes |
|---|---|---|---|
| `established`, `tcp-established` | — | | The term is skipped, **without** a warning. |

Any other option value raises an error (`<term> contains unsupported keywords (<option>)`).

## Output

Each policy file renders to one file with the same name and a `.bat` extension, so `sample.yaml` renders `sample.bat`.

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

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

## Known Issues

!!! bug "Known issues"
    * **`established` and `tcp-established` terms are dropped silently.** The term is left out of the output with no warning or error, so nothing in the `aclgen` log shows that a rule from the policy is missing.
