# CiscoXR

Renders ACLs for the Cisco IOS XR platform. The CiscoXR generator is built on the _[Cisco](cisco.md)_ generator.

## Header Format

```yaml
targets:
    ciscoxr: [filter name] {extended|object-group|inet6|mixed} {enable_dsmo} {noverbose}
```

### Inherited header options

These header options are included from the _[Cisco](cisco.md#header-format)_ page.

!!! warning "Not supported on CiscoXR"
    `standard` is listed in the Cisco table below, but CiscoXR doesn't support it. It is accepted, but the output isn't valid IOS XR; see _[Known Issues](#known-issues)_.

--8<-- "docs/reference/generators/cisco.md:header-options"

## Term Format

### Common tokens

These tokens are included from the _[Common](common.md)_ page.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Inherited tokens

These tokens are included from the _[Cisco](cisco.md#cisco-tokens)_ page.

--8<-- "docs/reference/generators/cisco.md:term-format"

### CiscoXR tokens

CiscoXR adds:

| Token | Description | Example | Notes |
|---|---|---|---|
| `next-ip` | Forward matching packets to a next hop (ACL-based forwarding). | `next-ip: NEXTHOP_ROUTER` | Only used when the term has **no** `action`; the rule is rendered as `permit … nexthop1 ipv4 <ip>`. Must resolve to exactly one host address. |

For an example, see _[ACL-based forwarding](#examples-acl-based-forwarding)_.

## Actions

### Inherited actions

These actions are included from the _[Cisco](cisco.md#actions)_ page.

--8<-- "docs/reference/generators/cisco.md:actions"

## Option

### Inherited options

These options are included from the _[Cisco](cisco.md#option)_ page.

--8<-- "docs/reference/generators/cisco.md:option"

## Output

Each policy file renders to one file with the same name and a `.xacl` extension, so `sample.yaml` renders `sample.xacl`.

### Differences from Cisco

| Area | Cisco | CiscoXR |
|---|---|---|
| Access list line | `ip access-list extended NAME` | `ipv4 access-list NAME` |
| Term with no protocol | `permit ip any any` | `permit ipv4 any any` |
| Protocols | Names outside Cisco's short list (`tcp`, `udp`, `icmp`, `gre`, …) are rendered as numbers, e.g. `esp` → `50` | Rendered by name, as written in the policy |

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

    ```yaml title="sample.yaml"
    filters:
      - header:
          targets:
            ciscoxr: edge-inbound
    --8<-- "docs/reference/generators.md:sample-terms"
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

=== "ACL-based forwarding"

    A term with `next-ip` and no `action` forwards matching traffic to the next hop.

    ```yaml title="forwarding.yaml"
    filters:
      - header:
          targets:
            ciscoxr: edge-inbound
        terms:
          - name: send-to-scrubber
            destination-address: DDOS_TARGETS
            next-ip: SCRUBBER_NEXTHOP
    ```

    ```yaml title="definitions.yaml"
    networks:
      DDOS_TARGETS:
        values:
          - address: 203.0.113.0/24
      SCRUBBER_NEXTHOP:
        values:
          - address: 192.0.2.1/32
    ```

    ```text title="forwarding.xacl"
    ! $Id:$
    ! $Date:$
    ! $Revision:$
    no ipv4 access-list edge-inbound
    ipv4 access-list edge-inbound
     remark $Id:$


     remark send-to-scrubber
     permit ipv4 any 203.0.113.0 0.0.0.255 nexthop1 ipv4 192.0.2.1

    exit
    ```

## Known Issues

!!! bug "Known issues"
    * **`standard` lists mix IOS and IOS XR syntax.** `ciscoxr: 50 standard` renders an `ipv4 access-list 50` header followed by IOS-style `access-list 50 permit …` lines, which IOS XR doesn't accept.

These known issues are included from _[Cisco](cisco.md#known-issues)_:

--8<-- "docs/reference/generators/cisco.md:known-issues"
