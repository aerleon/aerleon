# Arista

The Arista generator is built on the [Cisco](cisco.md) generator, so its terms, actions and options work the same way.

!!! info "Tables included from Cisco"
    The shared tables under Term Format, Actions and Option are included from the [Cisco](cisco.md) page, so they always match it. Anything that differs on Arista is called out on this page.

## Header Format

The Arista header designation has the following format:

```yaml
targets:
    arista: [filter name] {standard|extended|object-group|inet6|mixed} {enable_dsmo} {noverbose}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the access list. | |
| `standard` | Render a standard access list. | Numeric names must be in 1-99 or 1300-1999. |
| `extended` | Render an extended access list. | Default. |
| `object-group` | Render an extended access list that uses object-groups for ports and addresses. | |
| `inet6` | Render an IPv6-only access list. | |
| `mixed` | Render an IPv4 (extended) list and an IPv6 list together. | |
| `enable_dsmo` | Turn on discontinuous subnet mask summarization. | Optional. |
| `noverbose` | Leave out extra term and address comments. | Optional. |

## Term Format

### Common tokens

These tokens are included from the [Common](common.md) page.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Inherited tokens

These tokens are included from the [Cisco](cisco.md#cisco-tokens) page.

--8<-- "docs/reference/generators/cisco.md:term-format"

## Actions

### Inherited actions

These actions are included from the [Cisco](cisco.md#actions) page.

--8<-- "docs/reference/generators/cisco.md:actions"

## Option

### Inherited options

These options are included from the [Cisco](cisco.md#option) page.

--8<-- "docs/reference/generators/cisco.md:option"

## Output

Each policy file renders to one file with the same name and a `.eacl` extension, so `sample.yaml` renders `sample.eacl`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

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

These known issues are included from [Cisco](cisco.md#known-issues):

--8<-- "docs/reference/generators/cisco.md:known-issues"
