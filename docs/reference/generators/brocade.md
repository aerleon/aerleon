# Brocade

The Brocade generator is built on the [Cisco](cisco.md) generator. It supports exactly the same header options, tokens, actions and options. The differences are listed below.

!!! info "Tables included from Cisco"
    The shared tables under Term Format, Actions and Option are included from the [Cisco](cisco.md) page, so they always match it. Anything that differs on Brocade is called out on this page.

## Header Format

The Brocade header designation has the following format:

```yaml
targets:
    brocade: [filter name] {extended|standard|object-group|inet6|mixed} {enable_dsmo} {noverbose}
```

All options work as described for [Cisco](cisco.md).

## Differences from Cisco

| Area | Cisco | Brocade |
|---|---|---|
| Protocols | Rendered as numbers where possible | Rendered by name, as written in the policy |
| Term name remark | Each term starts with `remark <term name>` | Not written; only the term's `comment` is |

## Term Format

For common keys see the [Common](common.md) page. The following tokens are the same as for [Cisco](cisco.md#term-format):

--8<-- "docs/reference/generators/cisco.md:term-format"

## Actions

Same as [Cisco](cisco.md#actions):

--8<-- "docs/reference/generators/cisco.md:actions"

## Option

Same as [Cisco](cisco.md#option):

--8<-- "docs/reference/generators/cisco.md:option"

## Output

Each policy file renders to one file with the same name and a `.bacl` extension, so `sample.yaml` renders `sample.bacl`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        brocade: edge-inbound
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
