# Nokia SR Linux

Renders Nokia SR Linux ACL filters as JSON. It is built on the OpenConfig generator.

## Header Format

The Nokia SR Linux header designation has the following format:

```yaml
targets:
    nokiasrl: [filter name] {inet|inet6|mixed} {stats} {r24.3|r24.3.2}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the ACL filter. | |
| `inet` | IPv4 only. | Default. |
| `inet6` | IPv6 only. | |
| `mixed` | IPv4 and IPv6. | Renders one IPv4 and one IPv6 filter. |
| `stats` | Collect statistics per entry. | Adds `statistics-per-entry: true`. |
| `r24.3` | Use the SR Linux 24.3.1 filter syntax. | Renders `acl-filter` with a `type`, instead of `ipv4-filter`/`ipv6-filter`. |
| `r24.3.2` | Use the syntax for SR Linux 24.3.2 and later. | Same as `r24.3`, plus matches are nested under `ipv4`/`ipv6`/`transport`, and `logging` works with any action. |

## Term Format

For common keys see the [Common](common.md) page. Nokia SR Linux does **not** support `platform`, `platform-exclude` or `verbatim`. It also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `destination-prefix` | Match a named prefix list under `acl match-list`. | `destination-prefix: DC-NETS` | Can't be combined with `destination-address`. |
| `logging` | Log matching packets. | `logging: true` | Without `r24.3.2`, only allowed on `deny` terms (raises an error otherwise). |
| `source-prefix` | Match a named prefix list under `acl match-list`. | `source-prefix: CORP-NETS` | Can't be combined with `source-address`. |

The term name becomes the entry `description`, and `comment` becomes `_annotate_description` (max 255 characters). Entries get sequence IDs 5, 10, 15, …

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `accept` | |
| `deny` | `drop` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established` | Match established connections. | `option: established` | TCP: <code>tcp-flags: ack&#124;rst</code>. UDP: sets the destination port to 1024-65535. Requires a `tcp` or `udp` protocol. |
| `first-fragment` | Match the first fragment. | `option: first-fragment` | `first-fragment: true`. |
| `is-fragment`, `fragments` | Match fragments. | `option: is-fragment` | `fragment: true`. |
| `not-syn-ack` | Match TCP packets that are not SYN+ACK. | `option: not-syn-ack` | `tcp-flags: !(syn&ack)`. |
| `tcp-established` | Match established TCP connections. | `option: tcp-established` | <code>tcp-flags: ack&#124;rst</code>. TCP only. |
| `tcp-initial` | Match the first packet of a TCP connection. | `option: tcp-initial` | `tcp-flags: syn`. |

Options that set `tcp-flags` also set the protocol to TCP.

## Output

Each policy file renders to one file with the same name and a `.srl_acl` extension, so `sample.yaml` renders `sample.srl_acl`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        nokiasrl: edge-inbound inet
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

```json title="sample.srl_acl"
[
  {
    "ipv4-filter": {
      "_annotate": "$Id:$ $Date:$ $Revision:$",
      "description": "",
      "entry": [
        {
          "_annotate_description": "Allow SSH from the management network.",
          "action": {
            "accept": {}
          },
          "description": "allow-ssh",
          "match": {
            "destination-port": {
              "value": 22
            },
            "protocol": 6,
            "source-ip": {
              "prefix": "10.0.0.0/24"
            }
          },
          "sequence-id": 5
        },
        {
          "_annotate_description": "Allow SSH from the management network.",
          "action": {
            "accept": {}
          },
          "description": "allow-ssh",
          "match": {
            "destination-port": {
              "value": 22
            },
            "protocol": 6,
            "source-ip": {
              "prefix": "192.168.10.0/24"
            }
          },
          "sequence-id": 10
        },
        {
          "action": {
            "drop": {}
          },
          "description": "default-deny",
          "match": {},
          "sequence-id": 15
        }
      ],
      "name": "edge-inbound"
    }
  }
]
```

## Known Issues

!!! bug "Known issues"
    * **A term with no addresses of the family being rendered matches everything.** In a `mixed` filter, a term with only IPv4 sources also renders an IPv6 entry with no source address, so it matches all IPv6 sources. See [OpenConfig](openconfig.md).
    * **`icmp-type` is silently ignored.** It is accepted, but not rendered, so a term meant to allow only `echo-request` allows all ICMP.
    * Exclusions crash with mixed-family address tokens (`TypeError: … are not of the same version`), as in [GCE](gce.md).
    * **An exclusion on only one side crashes the generator.** A term with `source-exclude` but no `destination-exclude`, or the reverse, fails with `TypeError: 'NoneType' object is not iterable`. See [OpenConfig](openconfig.md#known-issues).
