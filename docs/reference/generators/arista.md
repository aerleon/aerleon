# Arista

Renders Arista EOS ACLs. The Arista generator is built on the _[Cisco](cisco.md)_ generator.

## Header Format

```yaml
targets:
    arista: [filter name] {standard|extended|object-group|inet6|mixed} {enable_dsmo} {noverbose}
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

Each policy file renders to one file with the same name and a `.eacl` extension, so `sample.yaml` renders `sample.eacl`.

### Differences from Cisco

| Area | Cisco | Arista |
|---|---|---|
| Access list line | `ip access-list extended NAME` | `ip access-list NAME` (also for `object-group`) |
| IPv4 addresses | `10.0.0.0 0.0.0.255` | `10.0.0.0/24` |
| Ports | Numbers, e.g. `eq 22` | Names where EOS has one, e.g. `eq ssh` |
| Protocols | Names outside Cisco's short list (`tcp`, `udp`, `icmp`, `gre`, …) are rendered as numbers, e.g. `esp` → `50` | Rendered by name, as written in the policy, except `esp` (`50`) and `ah` (`51`) |

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

    ```yaml title="sample.yaml"
    filters:
      - header:
          targets:
            arista: edge-inbound
    --8<-- "docs/reference/generators.md:sample-terms"
    ```

    ```text title="sample.eacl"
    ! $Id:$
    ! $Date:$
    ! $Revision:$
    no ip access-list edge-inbound
    ip access-list edge-inbound
    remark $Id:$


    remark allow-ssh
    remark Allow SSH from the management network.
    permit tcp 10.0.0.0/24 any eq ssh
    permit tcp 192.168.10.0/24 any eq ssh


    remark default-deny
    deny ip any any

    exit
    ```

## Known Issues

These known issues are included from _[Cisco](cisco.md#known-issues)_:

--8<-- "docs/reference/generators/cisco.md:known-issues"
