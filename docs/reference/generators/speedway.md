# Speedway

> NOTE: Speedway produces Iptables filtering output that is suitable for passing to the 'iptables-restore' command.

The speedway generator is built on the [IpTables](iptables.md) generator. It supports exactly the same header options, tokens, actions and options (including the known issues), so see the IpTables tables.

## Header Format

```yaml
targets:
    speedway: [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {inet|inet6} {nostate} {abbreviateterms} {truncateterms} {noverbose} {nochainedterms}
```

## Differences from IpTables

| Area | IpTables | Speedway |
|---|---|---|
| Output format | One `iptables` command per line | `iptables-restore` format, wrapped in `*filter` … `COMMIT` |
| Default policy line | `-P INPUT ACCEPT` | `:INPUT ACCEPT [0:0]` |
| `FORWARD` default policy | `DROP` if none is given | None unless given |
| Jump to term chain | Before the term's rules | After the term's rules |
| File suffix | none | `.ipt` |

??? example "A term and its output"
    With header `speedway: INPUT ACCEPT`:

    ```yaml
    - name: allow-ssh
      protocol: tcp
      destination-port: SSH
      action: accept
    ```

    ```text
    *filter
    :INPUT ACCEPT [0:0]
    -N I_allow-ssh
    -A I_allow-ssh -p tcp --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
    -A INPUT -j I_allow-ssh
    COMMIT
    ```
