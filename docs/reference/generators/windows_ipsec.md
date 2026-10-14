# WindowsIPSec

!!! warning "Not available"
    The `windows_ipsec` generator (`aerleon/lib/windows_ipsec.py`) is not registered as a built-in generator, so `windows_ipsec` targets are not rendered. This section describes the module as written.

Renders `netsh ipsec static add …` commands.

## Header Format

The Windows IPSec header designation has the following format:

```yaml
targets:
    windows_ipsec: [filter name] {inet|inet6}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the IPSec filter list. | |
| `inet` | IPv4 only. | Default. |
| `inet6` | IPv6 only. | |

## Term Format

For common keys see the [Common](common.md) page. WindowsIPSec does **not** support `icmp-type`, `source-exclude`, `destination-exclude` (they raise an error) or `verbatim`.

## Actions

| Action | Notes |
|---|---|
| `accept` | |
| `deny` | |

## Option

`established` and `tcp-established` terms are skipped without a warning. Other option values are accepted but ignored.
