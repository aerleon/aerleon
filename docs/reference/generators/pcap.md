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
| `in` | Only match traffic to this host. | Adds `dst net localhost`. Replace `localhost` with the host's real addresses before use; `tcpdump` rejects the filter until you do. |
| `out` | Only match traffic from this host. | Adds `src net localhost`. Replace as above. |

Several headers are joined with `or`.

## Term Format

### Common tokens

These tokens are included from the _[Common](common.md)_ page.

!!! warning "Not supported on PcapFilter"
    PcapFilter doesn't support `logging` or `verbatim`. A term that uses either raises an error.

--8<-- "docs/reference/generators/common.md:common-tokens"

### PcapFilter tokens

PcapFilter also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `icmp-code` | ICMP code to match. | `icmp-code: 0` | Adds `icmp[icmpcode] == <code>`. |

* Terms are matched in order, and the first matching term decides, as on a firewall. The `-accept` file matches packets whose first matching term is `accept`; the `-deny` file matches packets whose first matching term is `deny` or `reject`.
* A file that matches no packets renders `(len < 0)`, since libpcap has no keyword for false.
* Exclusions render as `and not (src net …)` / `and not (dst net …)`.
* Duplicate term names raise `DuplicateTermError`.
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
| `syn`, `ack`, `fin`, `rst`, `urg`, `psh` | Match packets with these TCP flags set. | `option: syn` | Combined into one `tcp[tcpflags]` test. |
| `established`, `tcp-established` | Match TCP packets with ACK set. | `option: tcp-established` | `tcp[tcpflags] & (tcp-ack) == (tcp-ack)`. |

## Output

Each policy file renders to `-accept.pcap` and `-deny.pcap` files, so `sample.yaml` renders `sample-accept.pcap` and `sample-deny.pcap`.

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

    ```yaml title="sample.yaml"
    filters:
      - header:
          targets:
            pcap: edge-inbound inet
    --8<-- "docs/reference/generators.md:sample-terms"
    ```

    ```text title="sample-accept.pcap"
    ((src net 10.0.0.0/24 or src net 192.168.10.0/24) and (proto \tcp) and (dst port 22))
    ```

    ```text title="sample-deny.pcap"
    not ((src net 10.0.0.0/24 or src net 192.168.10.0/24) and (proto \tcp) and (dst port 22))
    ```

## Known Issues

!!! bug "Known issues"
    * **Excluding all of IPv6 drops the address match.** A term with `source-exclude` set to `::/0` renders with no source condition, so it matches every source instead of none.
    * **An exclusion without an address matches only the excluded range.** A term with `source-exclude` but no `source-address` renders `(src net <excluded>)` instead of `not (src net <excluded>)`. The same applies to `destination-exclude`.
