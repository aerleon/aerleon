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

## Output

`windows_ipsec` isn't registered, so `aclgen` doesn't write a file for it. If it were registered, the file would get the `.bat` extension (inherited from the Windows generator), so `sample.yaml` would render `sample.bat`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by calling `WindowsIPSec` directly:

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        windows_ipsec: edge-inbound inet
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
