# CiscoNX

Renders ACLs for Cisco NX platform. The CiscoNX generator is built on the _[Cisco](cisco.md)_ generator.

## Header Format

```yaml
targets:
    cisconx: [filter name] {extended|object-group|inet6|mixed} {enable_dsmo} {noverbose}
```

### Inherited header options

These header options are included from the _[Cisco](cisco.md#header-format)_ page.

!!! warning "Not supported on CiscoNX"
    `standard` is listed in the Cisco table below, but CiscoNX doesn't support it. A filter that uses it raises an error.

--8<-- "docs/reference/generators/cisco.md:header-options"

## Term Format

### Common tokens

These tokens are included from the _[Common](common.md)_ page.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Inherited tokens

These tokens are included from the _[Cisco](cisco.md#cisco-tokens)_ page.

--8<-- "docs/reference/generators/cisco.md:term-format"

## Actions

### Inherited actions

These actions are included from the _[Cisco](cisco.md#actions)_ page.

--8<-- "docs/reference/generators/cisco.md:actions"

## Option

### Inherited options

These options are included from the _[Cisco](cisco.md#option)_ page.

--8<-- "docs/reference/generators/cisco.md:option"

## Output

Each policy file renders to one file with the same name and a `.nxacl` extension, so `sample.yaml` renders `sample.nxacl`.

### Differences from Cisco

| Area | Cisco | CiscoNX |
|---|---|---|
| Access list line | `ip access-list extended NAME` | `ip access-list NAME` |
| IPv4 addresses | `10.0.0.0 0.0.0.255`, `host 10.1.1.1` | `10.0.0.0/24`, `10.1.1.1/32` |
| Protocols | Names outside Cisco's short list (`tcp`, `udp`, `icmp`, `gre`, …) are rendered as numbers, e.g. `esp` → `50` | Rendered by name, as written in the policy, except `vrrp` (`112`) |
| Repository tags | `remark $Id:$` | `remark "$Date:$"` and `remark "$Revision:$"` |

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

    ```yaml title="sample.yaml"
    filters:
      - header:
          targets:
            cisconx: edge-inbound
    --8<-- "docs/reference/generators.md:sample-terms"
    ```

    ```text title="sample.nxacl"
    ! $Id:$
    ! $Date:$
    ! $Revision:$
    no ip access-list edge-inbound
    ip access-list edge-inbound
    remark "$Date:$"
    remark "$Revision:$"


    remark allow-ssh
    remark Allow SSH from the management network.
    permit tcp 10.0.0.0/24 any eq 22
    permit tcp 192.168.10.0/24 any eq 22


    remark default-deny
    deny ip any any

    exit
    ```

## Known Issues

These known issues are included from _[Cisco](cisco.md#known-issues)_:

--8<-- "docs/reference/generators/cisco.md:known-issues"
