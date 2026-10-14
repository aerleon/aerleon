# Aruba

## Header Format

The aruba header designation has the following format:

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

For common keys see the [Common](common.md) page. Aruba does **not** support `source-port`, `source-exclude`, `destination-exclude` or `icmp-type`. It also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added as a comment unless the header uses `noverbose`. |

Addresses are written into `netdestination` (or `netdestination6`) blocks named `<term>_src` and `<term>_dst`, which the rule references with `alias`.

??? example "A term and its output"
    ```yaml
    - name: allow-dns
      destination-address: INTERNAL
      destination-port: DNS
      protocol: udp
      action: accept
    ```

    ```text
    netdestination allow-dns_dst
      network 10.0.0.0 255.0.0.0
    !
    ip access-list session test
      any alias allow-dns_dst udp 53 permit
    ```

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

## Known Issues

!!! bug "Known issues"
    * A TCP or UDP term with no `destination-port` renders no rule at all.
    * Only one of `icmp`, `gre` and `esp` is rendered per term: `protocol: gre esp` produces a rule for `gre` only.
