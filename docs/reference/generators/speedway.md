# Speedway

Renders iptables rules compatible with the `iptables-restore` command. The Speedway generator is built on the _[Iptables](iptables.md)_ generator.

## Header Format

```yaml
targets:
    speedway: [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {inet|inet6} {nostate} {abbreviateterms} {truncateterms} {noverbose} {nochainedterms}
```

### Inherited header options

These header options are included from the _[Iptables](iptables.md#header-format)_ page.

--8<-- "docs/reference/generators/iptables.md:header-options"

### Speedway header options

The following header options are specific to Speedway, or work differently than on Iptables:

| Option | Description | Notes |
|---|---|---|
| `ACCEPT`, `DROP` | Default policy for a built-in chain (`:<chain> <policy> [0:0]`). | Defaults to `DROP` for every built-in chain. Iptables only defaults `FORWARD`. |

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

Each policy file renders to one file with the same name and a `.ipt` extension, so `sample.yaml` renders `sample.ipt`.

### Differences from Iptables

| Area | Iptables | Speedway |
|---|---|---|
| Output format | One `iptables` command per line | `iptables-restore` format, wrapped in `*filter` … `COMMIT` |
| Default policy line | `-P INPUT ACCEPT` | `:INPUT ACCEPT [0:0]` |
| Jump to term chain | Before the term's rules | After the term's rules |

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

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

These known issues are included from _[Iptables](iptables.md#known-issues)_:

--8<-- "docs/reference/generators/iptables.md:known-issues"
