# IPSet

Renders [IPSet](https://ipset.netfilter.org) rules. The IPSet generator is built on the _[Iptables](iptables.md)_ generator.

## Header Format

```yaml
targets:
    ipset: [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {inet|inet6} {nostate} {abbreviateterms} {truncateterms} {noverbose} {exists}
```

### Inherited header options

These header options are included from the _[Iptables](iptables.md#header-format)_ page.

!!! warning "Not supported on IPSet"
    `nochainedterms` is listed in the Iptables table below, but IPSet doesn't support it. A filter that uses it raises an error. IPSet never uses per-term chains anyway: rules always go directly in the filter's chain.

--8<-- "docs/reference/generators/iptables.md:header-options"

### IPSet header options

The following header options are specific to IPSet, or work differently than on Iptables:

| Option | Description | Notes |
|---|---|---|
| `exists` | Add `-exist` to the `create` and `add` commands, so re-running them doesn't fail. | |

## Term Format

### Common tokens

These tokens are included from the _[Common](common.md)_ page.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Inherited tokens

These tokens are included from the _[Iptables](iptables.md#iptables-tokens)_ page.

--8<-- "docs/reference/generators/iptables.md:term-format"

## Actions

### Inherited actions

These actions are included from the _[Iptables](iptables.md#actions)_ page.

--8<-- "docs/reference/generators/iptables.md:actions"

## Option

### Inherited options

These options are included from the _[Iptables](iptables.md#option)_ page.

--8<-- "docs/reference/generators/iptables.md:option"

## Output

Each policy file renders to one file with the same name and a `.ips` extension, so `sample.yaml` renders `sample.ips`.

### Differences from Iptables

When a term has more than one source or destination address, the addresses are put in an ipset instead of one rule per address. The output starts with the set commands, between `# begin:ipset-rules` and `# end:ipset-rules`, followed by the iptables rules.

| Item | Format | Notes |
|---|---|---|
| Set name | `<term>-src`, `<term>-dst` | `-v6` is added for `inet6`. Names are cut to 31 characters. |
| Set type | `hash:net` | `hashsize` and `maxelem` are sized to the number of addresses. |
| Rule match | `-m set --match-set <set> src` (or `dst`) | A single address uses plain `-s`/`-d`. |
| Exclusions | Applied before the set is built | The set only holds the remaining addresses. |
| Chains | Rules go directly in the filter's chain | No `-N <term>` chain per term, unlike iptables. |

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

    ```yaml title="sample.yaml"
    filters:
      - header:
          targets:
            ipset: INPUT DROP
    --8<-- "docs/reference/generators.md:sample-terms"
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

These known issues are included from _[Iptables](iptables.md#known-issues)_:

--8<-- "docs/reference/generators/iptables.md:known-issues"
