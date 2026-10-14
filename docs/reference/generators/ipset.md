# Ipset

Ipset is a system inside the Linux kernel, which can very efficiently store and match IPv4 and IPv6 addresses. This can be used to dramatically increase performance of iptables firewall.

The ipset generator is built on the [IpTables](iptables.md) generator. It supports exactly the same header options, tokens, actions and options. The differences are listed below.

!!! info "Tables included from IpTables"
    The shared tables under Term Format, Actions and Option are included from the [IpTables](iptables.md) page, so they always match it. Anything that differs on Ipset is called out on this page.

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

## Term Format

For common keys see the [Common](common.md) page. The following tokens are the same as for [IpTables](iptables.md#term-format):

--8<-- "docs/reference/generators/iptables.md:term-format"

## Actions

Same as [IpTables](iptables.md#actions):

--8<-- "docs/reference/generators/iptables.md:actions"

## Option

Same as [IpTables](iptables.md#option):

--8<-- "docs/reference/generators/iptables.md:option"

## Output

Each policy file renders to one file with the same name and a `.ips` extension, so `sample.yaml` renders `sample.ips`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        ipset: INPUT DROP
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

```text title="sample.ips"
# begin:ipset-rules
create allow-ssh-src hash:net family inet hashsize 4 maxelem 4
add allow-ssh-src 10.0.0.0/24
add allow-ssh-src 192.168.10.0/24
# end:ipset-rules
# Ipset INPUT Policy
# $Id:$
# $Date:$
# $Revision:$
# inet
-P INPUT DROP
-A INPUT -m comment --comment "Allow SSH from the management network."
-A INPUT -p tcp --dport 22 -m set --match-set allow-ssh-src src -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p all -j DROP
```

## Known Issues

Ipset has the same known issues as [IpTables](iptables.md#known-issues).
