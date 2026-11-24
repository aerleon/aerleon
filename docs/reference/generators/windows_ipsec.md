# WindowsIPSec

Renders `netsh ipsec static add …` commands.

## Header Format

```yaml
targets:
    windows_ipsec: [filter name] {inet}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the IPSec filter list. | |
| `inet` | IPv4 only. |  |

A `permit` or `block` default action in the header raises "Windows generator does not support default actions".

## Term Format

### Common tokens

These tokens are included from the _[Common](common.md)_ page.

!!! warning "Not supported on WindowsIPSec"
    WindowsIPSec doesn't support `icmp-type`, `source-exclude`, `destination-exclude` or `verbatim`. A term that uses any of them raises an error.

--8<-- "docs/reference/generators/common.md:common-tokens"

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `action=permit` | |
| `deny` | `action=block` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established`, `tcp-established` | — | | The term is skipped, **without** a warning; see _[Known Issues](#known-issues)_. |

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
    netsh ipsec static add rule name=e_allow-ssh-rule policy=edge-inbound-policy filterlist=e_allow-ssh-list filteraction=e_allow-ssh-action 

    netsh ipsec static add filterlist name=e_default-deny-list 
    netsh ipsec static add filteraction name=e_default-deny-action action=block
    netsh ipsec static add filter filterlist=e_default-deny-list mirrored=yes srcaddr=any  dstaddr=any  protocol=any
    netsh ipsec static add rule name=e_default-deny-rule policy=edge-inbound-policy filterlist=e_default-deny-list filteraction=e_default-deny-action 
    ```

## Known Issues

!!! bug "Known issues"
    * **`established` and `tcp-established` terms are dropped silently.** The term is left out of the output with no warning or error, so nothing in the `aclgen` log shows that a rule from the policy is missing.
