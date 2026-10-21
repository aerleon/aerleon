# Aruba

Renders ArubaOS access lists.

## Header Format

The Aruba header designation has the following format:

```yaml
targets:
    aruba: [filter name] {inet6} {noverbose}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the session access list. | |
| `inet6` | Render IPv6 only. | Without it, only IPv4 is rendered. |
| `noverbose` | Leave out term comments and owner. | Optional. |

## Term Format

### Common tokens

These tokens are included from the [Common](common.md) page.

!!! warning "Not supported on Aruba"
    Aruba doesn't support `source-port`, `source-exclude`, `destination-exclude` or `icmp-type`. A term that uses any of them raises an error.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Aruba tokens

Aruba also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added as a comment unless the header uses `noverbose`. |

Addresses are written into `netdestination` (or `netdestination6`) blocks named `<term>_src` and `<term>_dst`, which the rule references with `alias`.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `permit` | |
| `deny` | `deny` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `destination-is-user` | Use `user` as the destination instead of an address. | `option: destination-is-user` | `destination-address` is ignored. |
| `negate` | Negate the rule. | `option: negate` | Prefixes the rule with `no`. |
| `source-is-user` | Use `user` as the source instead of an address. | `option: source-is-user` | `source-address` is ignored. |

## Output

Each policy file renders to one file with the same name and a `.aacl` extension, so `sample.yaml` renders `sample.aacl`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        aruba: edge-inbound
--8<-- "docs/reference/generators.md:sample-terms"
```

```text title="sample.aacl"
# $Id:$
# $Date:$
# $Revision:$
netdestination allow-ssh_src
  network 10.0.0.0 255.255.255.0
  network 192.168.10.0 255.255.255.0
!

ip access-list session edge-inbound
  # Allow SSH from the management network.
  alias allow-ssh_src any tcp 22 permit
  any any any deny
!
```

## Known Issues

!!! bug "Known issues"
    * A TCP or UDP term with no `destination-port` renders no rule at all.
    * Only one of `icmp`, `gre` and `esp` is rendered per term: `protocol: gre esp` produces a rule for `gre` only.
