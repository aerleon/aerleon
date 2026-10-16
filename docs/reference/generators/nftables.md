# Nftables

Renders an nftables ruleset for the `nft` command. Each term becomes its own chain, and a base chain jumps to each one in order.

## Header Format

The Nftables header designation has the following format:

```yaml
targets:
    nftables: [inet|inet6|mixed] [input|output|forward] {ACCEPT} {priority} {noverbose}
```

There is no filter name: the address family must come first and the hook second.

| Option | Description | Notes |
|---|---|---|
| `inet` | IPv4 only. | Renders `table ip filtering_policies`. |
| `inet6` | IPv6 only. | Renders `table ip6 filtering_policies`. |
| `mixed` | IPv4 and IPv6. | Renders `table inet filtering_policies`. Every rule is currently rendered twice; see [Known Issues](#known-issues). |
| `input`, `output`, `forward` | Netfilter hook for the base chain. | `forward` is for routed/transit traffic; pair it with `source-interface` / `destination-interface`. |
| `ACCEPT` | Default policy `accept` for unmatched packets. | Without it the default policy is `drop`. Must be uppercase. |
| `priority` | An integer: the base chain priority. | Optional. Defaults to `0`. Only one integer is allowed. |
| `noverbose` | Leave out header and term comments. | Optional. |

## Stateful firewall only

This generator always builds a stateful ruleset using [conntrack](https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation):

* Every base chain starts with `ct state established,related accept`, so return traffic is always allowed.
* Every non-deny rule gets `ct state new`, so only new connections match. Invalid packets fall through to the default policy.
* Terms that use `established` or `tcp-established`, and stateless reply terms, are skipped with a warning, because the base chain already allows return traffic.

## ICMP Types

Some Aerleon ICMP type names are changed to the names nftables expects. Names with no nftables equivalent are passed through unchanged, and `nft` will reject them.

### IPv4

| Type | Aerleon name | nftables name |
|---|---|---|
| 0 | `echo-reply` | `echo-reply` |
| 3 | `unreachable` | `destination-unreachable` |
| 4 | `source-quench` | `source-quench` |
| 5 | `redirect` | `redirect` |
| 6 | `alternate-address` | *none*: passed through unchanged |
| 8 | `echo-request` | `echo-request` |
| 9 | `router-advertisement` | `router-advertisement` |
| 10 | `router-solicitation` | `router-solicitation` |
| 11 | `time-exceeded` | `time-exceeded` |
| 12 | `parameter-problem` | `parameter-problem` |
| 13 | `timestamp-request` | `timestamp-request` |
| 14 | `timestamp-reply` | `timestamp-reply` |
| 15 | `information-request` | `info-request` |
| 16 | `information-reply` | `info-reply` |
| 17 | `mask-request` | `address-mask-request` |
| 18 | `mask-reply` | `address-mask-reply` |
| 31 | `conversion-error` | *none*: passed through unchanged |
| 32 | `mobile-redirect` | *none*: passed through unchanged |

### IPv6

| Type | Aerleon name | nftables name |
|---|---|---|
| 1 | `destination-unreachable` | `destination-unreachable` |
| 2 | `packet-too-big` | `packet-too-big` |
| 3 | `time-exceeded` | `time-exceeded` |
| 4 | `parameter-problem` | `parameter-problem` |
| 128 | `echo-request` | `echo-request` |
| 129 | `echo-reply` | `echo-reply` |
| 130 | `multicast-listener-query` | `mld-listener-query` |
| 131 | `multicast-listener-report` | `mld-listener-report` |
| 132 | `multicast-listener-done` | `mld-listener-done` or `mld-listener-reduction` |
| 133 | `router-solicit` | `nd-router-solicit` |
| 134 | `router-advertisement` | `nd-router-advert` |
| 135 | `neighbor-solicit` | `nd-neighbor-solicit` |
| 136 | `neighbor-advertisement` | `nd-neighbor-advert` |
| 137 | `redirect-message` | `nd-redirect` |
| 138 | `router-renumbering` | `router-renumbering` |
| 139 | `icmp-node-information-query` | *none*: passed through unchanged |
| 140 | `icmp-node-information-response` | *none*: passed through unchanged |
| 141 | `inverse-neighbor-discovery-solicitation` | `ind-neighbor-solicit` |
| 142 | `inverse-neighbor-discovery-advertisement` | `ind-neighbor-advert` |
| 143 | `version-2-multicast-listener-report` | `mld2-listener-report` |
| 144 | `home-agent-address-discovery-request` | *none*: passed through unchanged |
| 145 | `home-agent-address-discovery-reply` | *none*: passed through unchanged |
| 146 | `mobile-prefix-solicitation` | *none*: passed through unchanged |
| 147 | `mobile-prefix-advertisement` | *none*: passed through unchanged |
| 148 | `certification-path-solicitation` | *none*: passed through unchanged |
| 149 | `certification-path-advertisement` | *none*: passed through unchanged |
| 151 | `multicast-router-advertisement` | *none*: passed through unchanged |
| 152 | `multicast-router-solicitation` | *none*: passed through unchanged |
| 153 | `multicast-router-termination` | *none*: passed through unchanged |

_source:_ <https://www.netfilter.org/projects/nftables/manpage.html>

## Term Format

### Common tokens

These tokens are included from the [Common](common.md) page. Nftables does **not** support `verbatim`.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Nftables tokens

Nftables also reads the following tokens. It does **not** support `owner` or other generator-specific tokens.

| Token | Description | Example | Notes |
|---|---|---|---|
| `counter` | Count matching packets. | `counter: ssh-hits` | Renders an anonymous `counter`. The name is ignored: named counters aren't used, since each term already has its own chain. |
| `destination-interface` | Match the outgoing interface. | `destination-interface: eth1` | Renders `oifname "eth1"`. |
| `logging` | Log matching packets. | `logging: true` | Renders `log prefix "<term>"`. `true`, `syslog` and `local` all do the same; `disable` turns it off. |
| `source-interface` | Match the incoming interface. | `source-interface: eth0` | Renders `iifname "eth0"`. |

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `accept` | Adds `ct state new`. |
| `deny` | `drop` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established`, `tcp-established` | — | | The term is skipped with a warning. See [Stateful firewall only](#stateful-firewall-only). |

## Output

Each policy file renders to one file with the same name and a `.nft` extension, so `sample.yaml` renders `sample.nft`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        nftables: inet input
--8<-- "docs/reference/generators.md:sample-terms"
```

```text title="sample.nft"
table ip filtering_policies {
    chain allow-ssh {
        comment "Allow SSH from the management network."
        ip saddr { 10.0.0.0/24, 192.168.10.0/24 } tcp dport 22 ct state new accept
    }
    chain default-deny {
        drop
    }
    chain root0 {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        jump allow-ssh
        jump default-deny
    }
}
```

## Known Issues

!!! bug "Known issues"
    * **`mixed` filters render every rule twice.** With a `mixed` header, each address is combined with the protocol/port statements from both address families. Every rule appears twice, and a term with a protocol but no ports also gets both an `ip protocol` and a `meta l4proto` rule.
    * **A single `icmp-type` value crashes the generator.** A term such as `icmp-type: echo-request` fails with `TypeError: can only concatenate str (not "list") to str`, for both `icmp` and `icmpv6`. Two or more values work.

When reporting a bug about this generator, include:

1. Example policy (.pol or .yaml file)
1. Observed output (.nft file)
1. Expected (correct) output in nftables syntax
