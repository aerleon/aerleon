# CiscoXR

The ciscoxr generator is built on the [Cisco](cisco.md) generator. It supports the same tokens, actions and options, plus `next-ip`.

## Header Format

The ciscoxr header designation has the following format:

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

For common keys see the [common](common.md) section, and for `address`, `restrict-address-family`, `dscp-match`, `icmp-code`, `logging` and `owner` see [Cisco](cisco.md). ciscoxr adds:

| Token | Description | Example | Notes |
|---|---|---|---|
| `next-ip` | Forward matching packets to a next hop (ACL-based forwarding). | `next-ip: NEXTHOP_ROUTER` | Only used when the term has **no** `action`; the rule is rendered as `permit … nexthop1 ipv4 <ip>`. Must resolve to exactly one host address. |

??? example "ACL-based forwarding"
    ```yaml
    - name: send-to-scrubber
      destination-address: DDOS_TARGETS
      next-ip: SCRUBBER_NEXTHOP
    ```

## Actions

Same as [Cisco](cisco.md): `accept` → `permit`; `deny`, `reject` and `reject-with-tcp-rst` → `deny`; `next` → `! next`.

## Option

Same as [Cisco](cisco.md): `established`, `tcp-established`, `is-fragment` and `fragments`.
