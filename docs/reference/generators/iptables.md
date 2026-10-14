# IpTables

!!! note
    IpTables produces output that must be passed, line by line, to the `iptables`/`ip6tables` command line. For `iptables-restore` compatible output, use the [Speedway](speedway.md) generator.

## Header Format

The IpTables header designation has the following format:

```yaml
targets:
    iptables: [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {inet|inet6} {nostate} {abbreviateterms} {truncateterms} {noverbose} {nochainedterms}
```

| Option | Description | Notes |
|---|---|---|
| `INPUT`, `OUTPUT`, `FORWARD` | Built-in chain to attach the terms to. | |
| `custom` | Any other name creates a custom chain. | Logs a warning: the chain does nothing until you jump to it from a built-in chain (e.g. `iptables -A INPUT -j custom`). |
| `ACCEPT`, `DROP` | Default policy for a built-in chain (`-P <chain> <policy>`). | `FORWARD` defaults to `DROP`. Other chains get no `-P` line unless one is given. |
| `inet` | IPv4 only. | Default. |
| `inet6` | IPv6 only. | |
| `nostate` | Don't use connection tracking. | `established` then only works for TCP, using TCP flags. Leaks into later filters; see [Known Issues](#known-issues). |
| `abbreviateterms` | Shorten long term names using a built-in abbreviation table. | Names longer than 24 characters raise an error unless this or `truncateterms` is set. |
| `truncateterms` | Cut long term names to 24 characters. | Applied after `abbreviateterms`. |
| `noverbose` | Leave out term comments and owner. | |
| `nochainedterms` | Put every rule directly in the filter's chain instead of one chain per term. | |

## Term Format

For common keys see the [Common](common.md) page. The following tokens are specific to IpTables:

<!-- --8<-- [start:term-format] -->

| Token | Description | Example | Notes |
|---|---|---|---|
| `counter`, `routing-instance` | — | | Accepted, but ignored. |
| `destination-interface` | Match the outgoing interface. | `destination-interface: eth1` | Renders `-o eth1`. |
| `fragment-offset` | Match fragment offset. | `fragment-offset: 1-8191` | Renders a `-m u32` match. |
| `icmp-code` | ICMP code to match. | `icmp-code: 0` | |
| `log-limit` | Rate-limit the log rule. | `log-limit: 10/minute` | Requires `logging`. Currently renders invalid syntax; see [Known Issues](iptables.md#known-issues). |
| `logging` | Log matching packets. | `logging: true` | Adds a `-j LOG --log-prefix <term>` rule before the action rule. |
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added to the comment unless the header uses `noverbose`. |
| `packet-length` | Match packet length. | `packet-length: 64-1500` | Renders `-m length --length 64:1500`. |
| `source-interface` | Match the incoming interface. | `source-interface: eth0` | Renders `-i eth0`. |
| `source-prefix`, `destination-prefix` | — | | Not supported by iptables. An `accept` or `next` term is replaced by a `# skipped` comment; any other action raises an error. |

<!-- --8<-- [end:term-format] -->

## Actions

<!-- --8<-- [start:actions] -->

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `-j ACCEPT` | With state tracking, also adds `-m state --state NEW,ESTABLISHED,RELATED`. |
| `deny` | `-j DROP` | |
| `next` | `-j RETURN` | |
| `reject` | `-j REJECT --reject-with icmp-host-prohibited` | `icmp6-adm-prohibited` for `inet6`. |
| `reject-with-tcp-rst` | `-j REJECT --reject-with tcp-reset` | |

<!-- --8<-- [end:actions] -->

## Option

<!-- --8<-- [start:option] -->

| Option | Description | Example | Notes |
|---|---|---|---|
| `all`, `none` | TCP flag sets `ALL` and `NONE`. | `option: none` | Used in the `--tcp-flags` match, e.g. to catch null scans. These are TCP flags, not protocols. |
| `established` | Match established connections. | `option: established` | Renders `-m state --state ESTABLISHED,RELATED`. With `nostate`, TCP-only terms use ACK/RST flags instead. For TCP/UDP, also sets the destination port to 1024-65535 if none is given. |
| `first-fragment` | Match the first fragment of a fragmented packet. | `option: first-fragment` | Renders `-m u32 --u32 4&0x3FFF=0x2000`. |
| `initial` | Match the first packet of a TCP connection. | `option: initial` | Renders `--syn`. |
| `sample` | — | | Accepted, but ignored. |
| `syn`, `ack`, `fin`, `rst`, `urg`, `psh` | Match packets with this TCP flag set. | `option: syn` | Combined into one `--tcp-flags` match. |
| `tcp-established` | Match established TCP connections. | `option: tcp-established` | Same as `established`, but raises an error if the term matches anything other than `tcp`. |
| `tcp-initial` | Match the first packet of a TCP connection. | `option: tcp-initial` | Renders `--syn`. |

<!-- --8<-- [end:option] -->

## Output

Each policy file renders to one file with the same name and **no extension**, so `sample.yaml` renders `sample`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        iptables: INPUT DROP
    terms:
      - name: allow-ssh
        comment: "Allow SSH from the management network."
        source-address: MGMT            # 10.0.0.0/24, 192.168.10.0/24
        protocol: tcp
        destination-port: SSH           # 22/tcp
        action: accept
      - name: default-deny
        action: deny
```

```text title="sample"
# Iptables INPUT Policy
# $Id:$
# $Date:$
# $Revision:$
# inet
-P INPUT DROP
-N I_allow-ssh
-A INPUT -j I_allow-ssh
-A I_allow-ssh -m comment --comment "Allow SSH from the management network."
-A I_allow-ssh -p tcp --dport 22 -s 10.0.0.0/24 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
-A I_allow-ssh -p tcp --dport 22 -s 192.168.10.0/24 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
-N I_default-deny
-A INPUT -j I_default-deny
-A I_default-deny -p all -j DROP
```

## Known Issues

!!! bug "Known issues"
    * **Header options leak between filters.** `nostate`, `noverbose`, `nochainedterms` and the default policy aren't reset between headers. If a policy has several iptables filters, later filters inherit these settings from earlier ones.
    * **`log-limit` renders invalid syntax.** The log rule is rendered as `-m --limit 10/minute …`, which iptables rejects. It should be `-m limit --limit 10/minute …`.
