# CiscoXR

The CiscoXR generator is built on the [Cisco](cisco.md) generator. It supports the same tokens, actions and options, plus `next-ip`.

!!! info "Tables included from Cisco"
    The shared tables under Term Format, Actions and Option are included from the [Cisco](cisco.md) page, so they always match it. Anything that differs on CiscoXR is called out on this page.

## Header Format

The CiscoXR header designation has the following format:

```yaml
targets:
    ciscoxr: [filter name] {extended|object-group|inet6|mixed} {enable_dsmo} {noverbose}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the access list. | |
| `extended` | Render an IPv4 access list. | Default. Rendered as `ipv4 access-list`. |
| `object-group` | Render an IPv4 access list that uses object-groups for ports and addresses. | |
| `inet6` | Render an IPv6 access list. | |
| `mixed` | Render an IPv4 list and an IPv6 list together. | |
| `enable_dsmo` | Turn on discontinuous subnet mask summarization. | Optional. |
| `noverbose` | Leave out extra term and address comments. | Optional. |

## Term Format

For common keys see the [Common](common.md) page. CiscoXR adds:

| Token | Description | Example | Notes |
|---|---|---|---|
| `next-ip` | Forward matching packets to a next hop (ACL-based forwarding). | `next-ip: NEXTHOP_ROUTER` | Only used when the term has **no** `action`; the rule is rendered as `permit … nexthop1 ipv4 <ip>`. Must resolve to exactly one host address. |

??? example "ACL-based forwarding"
    ```yaml
    - name: send-to-scrubber
      destination-address: DDOS_TARGETS
      next-ip: SCRUBBER_NEXTHOP
    ```

The other tokens are the same as for [Cisco](cisco.md#term-format):

--8<-- "docs/reference/generators/cisco.md:term-format"

## Actions

Same as [Cisco](cisco.md#actions):

--8<-- "docs/reference/generators/cisco.md:actions"

## Option

Same as [Cisco](cisco.md#option):

--8<-- "docs/reference/generators/cisco.md:option"

## Output

Each policy file renders to one file with the same name and a `.xacl` extension, so `sample.yaml` renders `sample.xacl`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        ciscoxr: edge-inbound
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

```text title="sample.xacl"
! $Id:$
! $Date:$
! $Revision:$
no ipv4 access-list edge-inbound
ipv4 access-list edge-inbound
 remark $Id:$


 remark allow-ssh
 remark Allow SSH from the management network.
 permit tcp 10.0.0.0 0.0.0.255 any eq 22
 permit tcp 192.168.10.0 0.0.0.255 any eq 22


 remark default-deny
 deny ipv4 any any

exit
```
