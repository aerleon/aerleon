# PacketFilter

Renders OpenBSD/FreeBSD `pf.conf` rules. Address tokens become `pf` tables (`table <NAME> { … }`) that the rules reference.

## Header Format

The PacketFilter header designation has the following format:

```yaml
targets:
    packetfilter: [filter name] {inet|inet6|mixed} {in|out} {nostate}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | A short, descriptive policy identifier. | Used in the header comment. |
| `inet` | IPv4 only. | Default. |
| `inet6` | IPv6 only. | |
| `mixed` | IPv4 and IPv6. | |
| `in`, `out` | Only match packets in this direction. | Default: both directions. |
| `nostate` | Don't keep state (`no state`). | Default: `keep state`, with `flags S/SA` for TCP. Leaks into later filters; see [Known Issues](#known-issues). |

## Term Format

For common keys see the [Common](common.md) page. The following tokens are specific to PacketFilter:

| Token | Description | Example | Notes |
|---|---|---|---|
| `destination-interface` | Match packets leaving on this interface. | `destination-interface: em1` | Renders `out … on em1`. Can't be combined with `source-interface`. |
| `logging` | Log matching packets. | `logging: true` | Adds `log`. |
| `source-interface` | Match packets arriving on this interface. | `source-interface: em0` | Renders `in … on em0`. Can't be combined with `destination-interface`. |

* Table names are the address token names, cut to the platform's length limit. Two tokens that shorten to the same name raise `DuplicateShortenedTableNameError`.
* A term without an `action` uses `block drop`.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `pass quick` | |
| `deny` | `block drop quick` | |
| `next` | `pass` | Without `quick`, so later rules can still match. |
| `reject` | `block return quick` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `all` | All TCP flags (`SAFRUP`). | `option: all` | A TCP flag set, not a protocol. |
| `established`, `tcp-established` | Match established TCP connections. | `option: tcp-established` | Renders `flags A/A`. Can't be combined with TCP flag options. |
| `syn`, `ack`, `fin`, `rst`, `urg`, `psh` | Match packets with these TCP flags set. | `option: syn` | Combined into one `flags X/Y` match. TCP only. |

## Output

Each policy file renders to one file with the same name and a `.pf` extension, so `sample.yaml` renders `sample.pf`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        packetfilter: edge-inbound
--8<-- "docs/reference/generators.md:sample-terms"
```

```text title="sample.pf"
table <MGMT> {10.0.0.0/24,\
192.168.10.0/24}
# Packetfilter edge-inbound Policy
# $Id:$
# $Date:$
# $Revision:$
# inet

# term allow-ssh
# Allow SSH from the management network.
pass quick inet proto { tcp } from { <MGMT> } to { any } port { 22 } flags S/SA keep state

# term default-deny
block drop quick inet from { any } to { any } flags S/SA
```

#### Logging

The sample `allow-ssh` term with `logging`. It uses the sample definitions.

```yaml title="logging.yaml"
filters:
  - header:
      targets:
        packetfilter: edge-inbound
    terms:
      - name: allow-ssh
        comment: "Allow SSH from the management network."
        source-address: MGMT
        protocol: tcp
        destination-port: SSH
        logging: true
        action: accept
```

```text title="logging.pf"
table <MGMT> {10.0.0.0/24,\
192.168.10.0/24}
# Packetfilter edge-inbound Policy
# $Id:$
# $Date:$
# $Revision:$
# inet

# term allow-ssh
# Allow SSH from the management network.
pass quick log inet proto { tcp } from { <MGMT> } to { any } port { 22 } flags S/SA keep state
```

## Known Issues

!!! bug "Known issues"
    * **`nostate` leaks between filters.** `nostate` isn't reset between headers. If a policy has several packetfilter filters, every filter after one with `nostate` is also stateless.
    * **`verbatim`-only terms crash.** A term that only has `verbatim` (and so no `action`) fails with `IndexError` while setting the default action.
