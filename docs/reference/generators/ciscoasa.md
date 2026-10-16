# CiscoASA

Renders Cisco ASA access lists.

## Header Format

The CiscoASA header designation has the following format:

```yaml
targets:
    ciscoasa: [filter name] {enable_dsmo}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the access list. | |
| `enable_dsmo` | Turn on discontinuous subnet mask summarization. | Optional. |

## Term Format

For common keys see the [Common](common.md) page. The following tokens are specific to CiscoASA:

| Token | Description | Example | Notes |
|---|---|---|---|
| `logging` | Log matching packets. | `logging: true` | Adds `log`. Use `logging: disable` to render `log disable`. |
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added as a `remark`. |

Unlike [Cisco](cisco.md), ciscoasa does not support `address`, `restrict-address-family`, `dscp-match` or `icmp-code`.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `permit` | |
| `deny` | `deny` | |
| `next` | `! next` | Rendered as a comment. |
| `reject` | `deny` | |
| `reject-with-tcp-rst` | `deny` | TCP reset is not supported. |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established` | Match established TCP connections. | `option: established` | Adds `established` to TCP rules only. Unlike Cisco, no high ports are added for UDP. |
| `tcp-established` | Match established TCP connections. | `option: tcp-established` | Adds `established` to TCP rules. |

## Output

Each policy file renders to one file with the same name and a `.asa` extension, so `sample.yaml` renders `sample.asa`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        ciscoasa: edge-inbound
--8<-- "docs/reference/generators.md:sample-terms"
```

```text title="sample.asa"
clear configure access-list edge-inbound
access-list edge-inbound remark $Id:$
access-list edge-inbound remark $Date:$
access-list edge-inbound remark $Revision:$


access-list edge-inbound remark allow-ssh
access-list edge-inbound remark Allow SSH from the management network.
access-list edge-inbound extended permit tcp 10.0.0.0 255.255.255.0 any eq ssh
access-list edge-inbound extended permit tcp 192.168.10.0 255.255.255.0 any eq ssh


access-list edge-inbound remark default-deny
access-list edge-inbound extended deny ip any any
```
