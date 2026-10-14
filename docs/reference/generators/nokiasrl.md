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

??? example "A term and its output"
    With header `nokiasrl: test inet`:

    ```yaml
    - name: allow-ping
      source-address: V4ONLY        # 192.168.0.0/16
      protocol: icmp
      action: accept
    ```

    ```json
    {
      "ipv4-filter": {
        "name": "test",
        "description": "",
        "entry": [
          {
            "action": {"accept": {}},
            "description": "allow-ping",
            "match": {"protocol": 1, "source-ip": {"prefix": "192.168.0.0/16"}},
            "sequence-id": 5
          }
        ]
      }
    }
    ```

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

## Known Issues

!!! bug "Known issues"
    * **A term with no addresses of the family being rendered matches everything.** In a `mixed` filter, a term with only IPv4 sources also renders an IPv6 entry with no source address, so it matches all IPv6 sources. See [OpenConfig](openconfig.md).
    * **`icmp-type` is silently ignored.** It is accepted, but not rendered, so a term meant to allow only `echo-request` allows all ICMP.
    * Exclusions crash with mixed-family address tokens (`TypeError: … are not of the same version`), as in [GCE](gce.md).
