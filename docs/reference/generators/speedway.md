# Speedway

!!! note
    Speedway produces IpTables filtering output that is suitable for passing to the `iptables-restore` command.

The Speedway generator is built on the [IpTables](iptables.md) generator. It supports exactly the same header options, tokens, actions and options. The differences are listed below.

!!! info "Tables included from IpTables"
    The shared tables under Term Format, Actions and Option are included from the [IpTables](iptables.md) page, so they always match it. Anything that differs on Speedway is called out on this page.

## Header Format

The Speedway header designation has the following format:

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

## Term Format

### Common tokens

These tokens are included from the [Common](common.md) page. Speedway supports all of them.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Speedway tokens

These are the same as for [IpTables](iptables.md#iptables-tokens):

--8<-- "docs/reference/generators/iptables.md:term-format"

## Actions

Same as [IpTables](iptables.md#actions):

--8<-- "docs/reference/generators/iptables.md:actions"

## Option

Same as [IpTables](iptables.md#option):

--8<-- "docs/reference/generators/iptables.md:option"

## Output

Each policy file renders to one file with the same name and a `.ipt` extension, so `sample.yaml` renders `sample.ipt`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        speedway: INPUT DROP
--8<-- "docs/reference/generators.md:sample-terms"
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

## Known Issues

Speedway has the same known issues as [IpTables](iptables.md#known-issues).
