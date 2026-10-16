# Cisco

Renders Cisco IOS access lists.

## Header Format

The Cisco header designation has the following format:

```yaml
targets:
    cisco: [filter name] {extended|standard|object-group|inet6|mixed} {enable_dsmo} {noverbose}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name or number of the access list. | |
| `extended` | Render an extended access list. | Default. Numeric names in 1-99 and 1300-1999 are reserved for standard lists. |
| `standard` | Render a standard access list. | Numeric names must be in 1-99 or 1300-1999. |
| `object-group` | Render an extended access list that uses object-groups for ports and addresses. | |
| `inet6` | Render an IPv6-only access list. | |
| `mixed` | Render an IPv4 (extended) list and an IPv6 list together. | |
| `enable_dsmo` | Turn on discontinuous subnet mask summarization. | Optional. |
| `noverbose` | Leave out extra term and address comments. | Optional. |

When `inet6` is specified, naming tokens that contain both IPv4 and IPv6 addresses are rendered using only the IPv6 addresses. Otherwise only IPv4 addresses are used, unless the filter is `mixed`.

## Term Format

### Common tokens

These tokens are included from the [Common](common.md) page. Cisco supports all of them.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Cisco tokens

The following tokens are specific to Cisco:

<!-- --8<-- [start:term-format] -->

| Token | Description | Example | Notes |
|---|---|---|---|
| `address` | Address tokens for a `standard` ACL. | `address: INTERNAL` | Standard ACLs must use `address`; they reject `source-address`/`destination-address`. Extended and object-group ACLs ignore `address` without a warning; see [Known Issues](cisco.md#known-issues). |
| `dscp-match` | Match a DSCP value. | `dscp-match: af41` | Only one value is allowed in extended ACLs. |
| `icmp-code` | ICMP code to match. | `icmp-code: 0` | |
| `logging` | Log matching packets. | `logging: true` | Adds `log` to the rule. |
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added as a comment. |
| `restrict-address-family` | Only render the term in the matching address family. | `restrict-address-family: inet` | Useful in `mixed` filters. |

<!-- --8<-- [end:term-format] -->

For an example, see [Cisco tokens in a mixed filter](#cisco-tokens-in-a-mixed-filter).

## Actions

<!-- --8<-- [start:actions] -->

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `permit` | |
| `deny` | `deny` | |
| `next` | `! next` | Rendered as a comment. |
| `reject` | `deny` | |
| `reject-with-tcp-rst` | `deny` | TCP reset is not supported. |

<!-- --8<-- [end:actions] -->

## Option

<!-- --8<-- [start:option] -->

| Option | Description | Example | Notes |
|---|---|---|---|
| `established` | Match established connections. | `option: established` | Adds `established` for TCP. For UDP, sets the destination port to 1024-65535 if none is given. |
| `fragments` | Match fragments. | `option: fragments` | Same as `is-fragment`. |
| `is-fragment` | Match fragments. | `option: is-fragment` | Renders as `fragments`. |
| `tcp-established` | Match established TCP connections. | `option: tcp-established` | Adds `established`. TCP only. |

<!-- --8<-- [end:option] -->

## Output

Each policy file renders to one file with the same name and a `.acl` extension, so `sample.yaml` renders `sample.acl`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        cisco: edge-inbound
--8<-- "docs/reference/generators.md:sample-terms"
```

```text title="sample.acl"
! $Id:$
! $Date:$
! $Revision:$
no ip access-list extended edge-inbound
ip access-list extended edge-inbound
 remark $Id:$


 remark allow-ssh
 remark Allow SSH from the management network.
 permit tcp 10.0.0.0 0.0.0.255 any eq 22
 permit tcp 192.168.10.0 0.0.0.255 any eq 22


 remark default-deny
 deny ip any any

exit
```

#### Cisco tokens in a mixed filter

A term that uses `restrict-address-family`, `logging` and `owner`. Because of `restrict-address-family: inet`, the term is only rendered in the IPv4 access list, although `MGMT_NETS` also holds an IPv6 range. It uses `SSH` from the sample definitions.

```yaml title="tokens.yaml"
filters:
  - header:
      targets:
        cisco: edge-inbound mixed
    terms:
      - name: permit-mgmt-v4-only
        source-address: MGMT_NETS
        restrict-address-family: inet
        protocol: tcp
        destination-port: SSH
        logging: true
        owner: netops@example.com
        action: accept
```

```yaml title="definitions.yaml"
networks:
  MGMT_NETS:
    values:
      - address: 10.0.0.0/24
      - address: 2001:db8:10::/64
```

```text title="tokens.acl"
! $Id:$
! $Date:$
! $Revision:$
no ip access-list extended edge-inbound
ip access-list extended edge-inbound
 remark $Id:$


 remark permit-mgmt-v4-only
 remark Owner: netops@example.com
 permit tcp 10.0.0.0 0.0.0.255 any eq 22 log

exit

no ipv6 access-list ipv6-edge-inbound
ipv6 access-list ipv6-edge-inbound
 remark $Id:$

exit
```

## Known Issues

<!-- --8<-- [start:known-issues] -->

!!! bug "Known issues"
    * **`address` is silently dropped outside standard ACLs.** In `extended` and `object-group` ACLs, a term's `address` is ignored without a warning, so `address: MGMT` with `protocol: tcp` renders `permit tcp any any …`. Use `source-address` or `destination-address` instead.

<!-- --8<-- [end:known-issues] -->
