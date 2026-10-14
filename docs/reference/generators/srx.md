# JuniperSRX

## Header Format

```yaml
targets:
    srx: from-zone [zone name] to-zone [zone name] {inet|inet6|mixed} {address-book-global|address-book-zone} {expresspath} {noverbose}
```

| Option | Description | Notes |
|---|---|---|
| `from-zone [name]` | Source security zone. | Required, and must come first. |
| `to-zone [name]` | Destination security zone. | Required. Use `from-zone all to-zone all` for a global policy. `all` can't be used for only one of the two. |
| `inet` | IPv4 only. | |
| `inet6` | IPv6 only. | |
| `mixed` | IPv4 and IPv6. | Default. |
| `address-book-global` | Put addresses in the global address book. | Default. |
| `address-book-zone` | Put addresses in per-zone address books. | Not allowed with a global policy. All headers in a policy must use the same address-book type. |
| `expresspath` | Offload accepted traffic. | Renders `accept` as `services-offload`. |
| `noverbose` | Leave out term comments and owner. | Optional. |

Zone names can't be any of the option keywords above.

## Term Format

For common keys see the [Common](common.md) page. SRX is stateful, so terms that use `established`/`tcp-established` or are stateless replies are skipped with a warning. Other `option` values are accepted but ignored. The following tokens are specific to srx:

| Token | Description | Example | Notes |
|---|---|---|---|
| `destination-fqdn` | Match FQDN tokens as the destination. | `destination-fqdn: EXAMPLE_COM` | Added to the address book with an `_FQDN` suffix. |
| `destination-zone` | Match one or more destination zones. | `destination-zone: untrust` | Global policies only. |
| `dscp-except` | Match anything except these DSCP values. | `dscp-except: be` | |
| `dscp-match` | Match DSCP values. | `dscp-match: af41` | |
| `dscp-set` | Rewrite the DSCP value. | `dscp-set: af41` | |
| `logging` | Log sessions. | `logging: true` | See the logging table below. |
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added to the term comment unless the header uses `noverbose`. |
| `source-fqdn` | Match FQDN tokens as the source. | `source-fqdn: EXAMPLE_COM` | Added to the address book with an `_FQDN` suffix. |
| `source-zone` | Match one or more source zones. | `source-zone: trust` | Global policies only (`from-zone all to-zone all`). |
| `timeout` | Application inactivity timeout, in seconds. | `timeout: 300` | Defaults to 60. |
| `vpn` | Send accepted traffic through an IPsec VPN. | `vpn: {name: site-a-vpn, policy: site-a-pair}` | Only applies to `accept`. `policy` (the pair-policy) is optional. |

**Logging output** (see Juniper [KB16506](https://kb.juniper.net/InfoCenter/index?page=content&id=KB16506) for background):

| `logging` value | `action: accept` | Any other action |
|---|---|---|
| `true` | `log { session-close; }` | `log { session-init; }` |
| `log-both` | `log { session-init; session-close; }` | `log { session-init; session-close; }` |

??? example "A global policy term"
    ```yaml
    - name: allow-web-to-dmz
      source-zone: trust
      destination-zone: dmz
      destination-address: WEB_SERVERS
      destination-port: HTTP HTTPS
      protocol: tcp
      logging: log-both
      action: accept
    ```

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `permit` | `services-offload` when the header has `expresspath`. |
| `count` | `count` | |
| `deny` | `deny` | |
| `dscp` | `dscp` | |
| `log` | `log` | |
| `reject` | `reject` | |
