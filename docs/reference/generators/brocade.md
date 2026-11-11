# Brocade

Renders a Brocade switch ACL. The Brocade generator is built on the _[Cisco](cisco.md)_ generator.

## Header Format

```yaml
targets:
    brocade: [filter name] {extended|standard|object-group|inet6|mixed} {enable_dsmo} {noverbose}
```

### Inherited header options

These header options are included from the _[Cisco](cisco.md#header-format)_ page.

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

Each policy file renders to one file with the same name and a `.bacl` extension, so `sample.yaml` renders `sample.bacl`.

### Differences from Cisco

| Area | Cisco | Brocade |
|---|---|---|
| Protocols | Names outside Cisco's short list (`tcp`, `udp`, `icmp`, `gre`, …) are rendered as numbers, e.g. `esp` → `50` | Rendered by name, as written in the policy |
| Term name remark | Each term starts with `remark <term name>` | Not written in `extended` lists, or the IPv4 list of a `mixed` filter; see _[Known Issues](#known-issues)_ |

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

    ```yaml title="sample.yaml"
    filters:
      - header:
          targets:
            brocade: edge-inbound
    --8<-- "docs/reference/generators.md:sample-terms"
    ```

    ```text title="sample.bacl"
    ! $Id:$
    ! $Date:$
    ! $Revision:$
    no ip access-list extended edge-inbound
    ip access-list extended edge-inbound
    remark $Id:$


    remark Allow SSH from the management network.
    permit tcp 10.0.0.0 0.0.0.255 any eq 22
    permit tcp 192.168.10.0 0.0.0.255 any eq 22


    deny ip any any

    exit
    ```

## Known Issues

!!! bug "Known issues"
    * **The term name remark is only dropped from IPv4 lists.** Brocade leaves out `remark <term name>` in `extended` lists, but `inet6` and `object-group` lists still write it, so one policy renders differently depending on the list type.

These known issues are included from _[Cisco](cisco.md#known-issues)_:

--8<-- "docs/reference/generators/cisco.md:known-issues"
