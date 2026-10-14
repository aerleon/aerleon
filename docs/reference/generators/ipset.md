# Ipset

Ipset is a system inside the Linux kernel, which can very efficiently store and match IPv4 and IPv6 addresses. This can be used to dramatically increase performance of iptables firewall.

The ipset generator is built on the [IpTables](iptables.md) generator. Terms, actions and options work the same way; the differences are below.

## Header Format

```yaml
targets:
    ipset: [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {inet|inet6} {nostate} {abbreviateterms} {truncateterms} {noverbose} {exists}
```

All options work as described for [IpTables](iptables.md), except:

| Option | Description | Notes |
|---|---|---|
| `exists` | Add `-exist` to the `create` and `add` commands, so re-running them doesn't fail. | ipset only. |
| `nochainedterms` | — | Not accepted (raises an error). ipset never uses per-term chains anyway: rules always go directly in the filter's chain. |

## Differences from IpTables

When a term has more than one source or destination address, the addresses are put in an ipset instead of one rule per address. The output starts with the set commands, between `# begin:ipset-rules` and `# end:ipset-rules`, followed by the iptables rules.

| Item | Format | Notes |
|---|---|---|
| Set name | `<term>-src`, `<term>-dst` | `-v6` is added for `inet6`. Names are cut to 31 characters. |
| Set type | `hash:net` | `hashsize` and `maxelem` are sized to the number of addresses. |
| Rule match | `-m set --match-set <set> src` (or `dst`) | A single address uses plain `-s`/`-d`. |
| Exclusions | Applied before the set is built | The set only holds the remaining addresses. |
| Chains | Rules go directly in the filter's chain | No `-N <term>` chain per term, unlike iptables. |

??? example "A term and its output"
    With header `ipset: INPUT ACCEPT`, and `INTERNAL = 10.0.0.0/8 192.168.0.0/16`:

    ```yaml
    - name: allow-ssh
      source-address: INTERNAL
      protocol: tcp
      destination-port: SSH
      action: accept
    ```

    ```text
    # begin:ipset-rules
    create allow-ssh-src hash:net family inet hashsize 4 maxelem 4
    add allow-ssh-src 10.0.0.0/8
    add allow-ssh-src 192.168.0.0/16
    # end:ipset-rules
    ...
    -P INPUT ACCEPT
    -A INPUT -p tcp --dport 22 -m set --match-set allow-ssh-src src -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
    ```
