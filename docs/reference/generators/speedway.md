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

## Output

Each policy file renders to one file with the same name and a `.ipt` extension, so `sample.yaml` renders `sample.ipt`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        speedway: INPUT DROP
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

```text title="sample.ipt"
*filter
# Speedway INPUT Policy
# $Id:$
# $Date:$
# $Revision:$
# inet
:INPUT DROP [0:0]
-N I_allow-ssh
-A I_allow-ssh -m comment --comment "Allow SSH from the management network."
-A I_allow-ssh -p tcp --dport 22 -s 10.0.0.0/24 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
-A I_allow-ssh -p tcp --dport 22 -s 192.168.10.0/24 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
-A INPUT -j I_allow-ssh
-N I_default-deny
-A I_default-deny -p all -j DROP
-A INPUT -j I_default-deny
COMMIT
```
