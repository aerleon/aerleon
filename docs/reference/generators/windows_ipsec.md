# WindowsIPSec

!!! warning "Not available"
    The `windows_ipsec` generator (`aerleon/lib/windows_ipsec.py`) is not registered as a built-in generator, so `windows_ipsec` targets are not rendered. This section describes the module as written.

Renders `netsh ipsec static add …` commands.

## Header Format

The WindowsIPSec header designation has the following format:

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

### Common tokens

These tokens are included from the [Common](common.md) page. WindowsIPSec does **not** support `icmp-type`, `source-exclude`, `destination-exclude` (they raise an error) or `verbatim`.

--8<-- "docs/reference/generators/common.md:common-tokens"

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `action=permit` | |
| `deny` | `action=block` | |

## Option

`established` and `tcp-established` terms are skipped without a warning. Other option values are accepted but ignored.

## Output

`windows_ipsec` isn't registered, so `aclgen` doesn't write a file for it. If it were registered, the file would get the `.bat` extension (inherited from the Windows generator), so `sample.yaml` would render `sample.bat`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by calling `WindowsIPSec` directly:

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        windows_ipsec: edge-inbound inet
--8<-- "docs/reference/generators.md:sample-terms"
```

```text title="sample.bat"
: Windows_ipsec edge-inbound Policy
netsh ipsec static add policy name=edge-inbound-policy assign=yes

: $Id:$
: $Date:$
: $Revision:$
: inet
netsh ipsec static add filterlist name=e_allow-ssh-list 
netsh ipsec static add filteraction name=e_allow-ssh-action action=permit
netsh ipsec static add filter filterlist=e_allow-ssh-list mirrored=yes srcaddr=10.0.0.0 srcmask=24 dstaddr=any  dstport=22 protocol=tcp
netsh ipsec static add filter filterlist=e_allow-ssh-list mirrored=yes srcaddr=192.168.10.0 srcmask=24 dstaddr=any  dstport=22 protocol=tcp
netsh ipsec static add filterlist name=e_allow-ssh-list 
netsh ipsec static add filteraction name=e_allow-ssh-action action=permit
netsh ipsec static add rule name=e_allow-ssh-rule policy=edge-inbound filterlist=e_allow-ssh-list filteraction=e_allow-ssh-action 

netsh ipsec static add filterlist name=e_default-deny-list 
netsh ipsec static add filteraction name=e_default-deny-action action=block
netsh ipsec static add filter filterlist=e_default-deny-list mirrored=yes srcaddr=any  dstaddr=any  protocol=any
netsh ipsec static add filterlist name=e_default-deny-list 
netsh ipsec static add filteraction name=e_default-deny-action action=block
netsh ipsec static add rule name=e_default-deny-rule policy=edge-inbound filterlist=e_default-deny-list filteraction=e_default-deny-action
```
