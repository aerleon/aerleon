# PcapFilter

Renders a pcap/BPF filter expression (for `tcpdump`, Wireshark, etc.) that matches the traffic the policy would **accept**. pcap isn't a firewall language, so this is for analysis, not enforcement.

## Header Format

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

For common keys see the [Common](common.md) page. PcapFilter does **not** support `verbatim`. It also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `icmp-code` | ICMP code to match. | `icmp-code: 0` | Adds `icmp[icmpcode] == <code>`. |
| `logging` | — | | Accepted, but ignored. |

* The output is `(accept terms) and not (deny terms)`.
* Exclusions render as `not src net …` / `not dst net …`.
* Port ranges render as `portrange <start>-<end>`.

??? example "A term and its output"
    With header `pcap: test inet`:

    ```yaml
    - name: allow-ssh
      protocol: tcp
      destination-port: SSH
      action: accept
    ```

    ```text
    ((((proto \tcp) and (dst port 22))
    ))
    ```

## Actions

| Action | Notes |
|---|---|
| `accept` | Added to the "match" side of the filter. |
| `deny`, `reject` | Added to the "and not" side of the filter. |
| `next` | Accepted, but the term is dropped. |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `all`, `none` | TCP flag sets. | `option: none` | TCP flags, not protocols. |
| `established` | — | | Accepted, but ignored: the filter matches all traffic for the protocol. |
| `syn`, `ack`, `fin`, `rst`, `urg`, `psh` | Match packets with these TCP flags set. | `option: syn` | Combined into one `tcp[tcpflags]` test. |
| `tcp-established` | Match TCP packets with ACK set. | `option: tcp-established` | `tcp[tcpflags] & (tcp-ack) == (tcp-ack)`. |

## Known Issues

!!! bug "Known issues"
    * **Multiple accept terms never match.** Accept terms are joined with `and` instead of `or`, so a policy that accepts SSH and HTTP renders `(dst port 22) and (dst port 80)`.
    * Duplicate term names aren't detected.
    * `in`/`out` leaks from one header to the next.
