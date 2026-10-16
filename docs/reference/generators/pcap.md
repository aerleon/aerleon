# PcapFilter

Renders a pcap/BPF filter expression (for `tcpdump`, Wireshark, etc.) that matches the traffic the policy would **accept**. pcap isn't a firewall language, so this is for analysis, not enforcement.

## Header Format

The PcapFilter header designation has the following format:

```yaml
targets:
    pcap: [filter name] {inet|inet6|mixed} {in|out}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the filter. | Not used in the output. |
| `inet` | IPv4 only. | |
| `inet6` | IPv6 only. | |
| `mixed` | IPv4 and IPv6. | Default. |
| `in` | Only match traffic to this host. | Adds `dst net localhost`. Replace `localhost` with the host's real addresses before use. |
| `out` | Only match traffic from this host. | Adds `src net localhost`. Replace as above. |

Several headers are joined with `or`.

## Term Format

### Common tokens

These tokens are included from the [Common](common.md) page. PcapFilter does **not** support `verbatim`.

--8<-- "docs/reference/generators/common.md:common-tokens"

### PcapFilter tokens

PcapFilter also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `icmp-code` | ICMP code to match. | `icmp-code: 0` | Adds `icmp[icmpcode] == <code>`. |
| `logging` | — | | Accepted, but ignored. |

* The output is `(accept terms) and not (deny terms)`.
* Exclusions render as `not src net …` / `not dst net …`.
* Port ranges render as `portrange <start>-<end>`.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | The "match" side of the filter | |
| `deny`, `reject` | The "and not" side of the filter | |
| `next` | — | Accepted, but the term is dropped. |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `all`, `none` | TCP flag sets. | `option: none` | TCP flags, not protocols. |
| `established` | — | | Accepted, but ignored: the filter matches all traffic for the protocol. |
| `syn`, `ack`, `fin`, `rst`, `urg`, `psh` | Match packets with these TCP flags set. | `option: syn` | Combined into one `tcp[tcpflags]` test. |
| `tcp-established` | Match TCP packets with ACK set. | `option: tcp-established` | `tcp[tcpflags] & (tcp-ack) == (tcp-ack)`. |

## Output

Each policy file renders to `-accept.pcap` and `-deny.pcap` files, so `sample.yaml` renders `sample-accept.pcap` and `sample-deny.pcap`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by the Python API (`aerleon.api.Generate`).

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        pcap: edge-inbound inet
--8<-- "docs/reference/generators.md:sample-terms"
```

```text title="sample-accept.pcap"
((((dst net 10.0.0.0/24 or dst net 192.168.10.0/24) and (proto \tcp) and (dst port 22))
))
```

```text title="sample-deny.pcap"
((((dst net 10.0.0.0/24 or dst net 192.168.10.0/24) and (proto \tcp) and (dst port 22))
))
```

## Known Issues

!!! bug "Known issues"
    * **`aclgen` can't render pcap.** It crashes with `ValueError: Invalid suffix '-accept.pcap'`. The Python API (`aerleon.api.Generate`) works.
    * **Source addresses are rendered as destinations.** Both `source-address` and `destination-address` render as `dst net …`.
    * **The `-deny` file can be identical to the `-accept` file.** A deny term with no match criteria (such as `default-deny`) renders to nothing, so the inverted filter is just the accept clause again.
    * **Multiple accept terms never match.** Accept terms are joined with `and` instead of `or`, so a policy that accepts SSH and HTTP renders `(dst port 22) and (dst port 80)`.
    * Duplicate term names aren't detected.
    * `in`/`out` leaks from one header to the next.
