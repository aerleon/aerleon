# Arista Traffic-Policy

## Header Format

The arista_tp header designation has the following format:

```yaml
targets:
    arista_tp: [filter name] {inet|inet6|mixed} {noverbose}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the traffic-policy. | |
| `inet` | Render IPv4 addresses only. | |
| `inet6` | Render IPv6 addresses only. | |
| `mixed` | Render both IPv4 and IPv6 match statements. | Default. |
| `noverbose` | Leave out term comments and owner. | Optional. |

## Term Format

For common keys see the [Common](common.md) page. The following tokens are specific to arista_tp:

| Token | Description | Example | Notes |
|---|---|---|---|
| `counter` | Count matching packets in a named counter. | `counter: ssh-replies` | Adds `count <name>` to the term's actions and lists the name in the policy's `counter` line. A `.` in the name is replaced with `-`. |
| `destination-prefix` | Match a field-set already configured on the device. | `destination-prefix: DC-NETS` | Renders as `destination prefix field-set …`. |
| `dscp-set` | Set a DSCP value. | `dscp-set: af41` | Accepted, but not currently rendered in the output. |
| `fragment-offset` | Match on fragment offset. | `fragment-offset: 1-8191` | Renders as `fragment offset …`. |
| `hop-limit` | Match on IPv6 hop limit. | `hop-limit: 255` | Also renders as `ttl …`. |
| `icmp-code` | ICMP code to match. | `icmp-code: 0` | Only applied when the term has a single `icmp-type`. |
| `logging` | Log matching packets. | `logging: true` | Only rendered for non-accept actions. On an `accept` term it is skipped with a warning. |
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added to the term comment unless the header uses `noverbose`. |
| `packet-length` | Match on IP packet length. | `packet-length: 1-1500` | Renders as `ip length …`. |
| `protocol-except` | Match every protocol except the ones listed. | `protocol-except: tcp udp` | Renders as a protocol number range with the listed protocols removed. |
| `source-prefix` | Match a field-set already configured on the device. | `source-prefix: CORP-NETS` | Renders as `source prefix field-set …`. Aerleon does not create the field-set. |
| `ttl` | Match on TTL. | `ttl: 1` | Renders as `ttl …`. |

!!! warning "Accepted but not rendered"
    A term that uses `port`, `dscp-match`, `dscp-except`, `ether-type`, `flexible-match-range`, `forwarding-class`, `forwarding-class-except`, `next-ip` or `traffic-type` is skipped with a warning.

??? example "A term using arista_tp tokens"
    From `policies/pol/sample_arista_tp_yaml.yaml`:

    ```yaml
    - name: accept-ssh-replies
      source-port: SSH
      protocol: tcp
      option: tcp-established
      counter: ssh-replies
      action: accept
    ```

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | *(no action)* | Traffic-policies allow by default, so no `actions` block is written unless `counter` or `logging` is set. |
| `deny` | `drop` | |
| `next` | — | Not supported; the term is skipped with a warning. |
| `reject` | `drop` | Not supported by traffic-policies; rendered as `drop`. |
| `reject-with-tcp-rst` | `drop` | Not supported by traffic-policies; rendered as `drop`. |

Note, within traffic-policies not configuring an explicit `deny` action (or `reject` variant) will result in an implicit allow for a term.

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established` | Match established connections. | `option: established` | Adds the `established` flag for TCP-only terms. |
| `first-fragment` | — | | Not supported; the term is skipped with a warning. |
| `initial` | Match the initial packet of a TCP connection. | `option: initial` | TCP-only terms. |
| `is-fragment` | Match fragments. | `option: is-fragment` | Renders as `fragment`. Raises an error in an `inet6` filter. In a `mixed` filter the IPv6 version of the term is skipped. Can't be combined with port matches (term is skipped). |
| `rst` | Match TCP packets with RST set. | `option: rst` | TCP-only terms. |
| `sample` | — | | Not supported; the term is skipped with a warning. |
| `tcp-established` | Match established TCP connections. | `option: tcp-established` | Raises an error if the term matches anything other than `tcp`. |

Any other option value is accepted but ignored.

## How terms are rendered

### Address families

A traffic-policy holds IPv4 and IPv6 matches side by side. What Aerleon renders depends on the header:

| Header | What is rendered | Term names in the output |
|---|---|---|
| `mixed` (default) | Each term twice: once for IPv4, once for IPv6. | `<term>` for IPv4, `ipv6-<term>` for IPv6. |
| `inet` | IPv4 only. | `<term>` |
| `inet6` | IPv6 only. | `<term>` |

If a term's `source-address` or `destination-address` has no addresses in a family, the term is skipped for that family. With `inet` or `inet6`, EOS still adds its own default term for the other family (see [Default terms](#default-terms)).

### Address exclusions

EOS can't use `except` inside a match statement. So when a term uses `source-exclude` or `destination-exclude`, Aerleon writes a **field-set** that holds the included and excluded prefixes, and the term matches on that field-set.

| Token | IPv4 field-set name | IPv6 field-set name (`mixed`) | IPv6 field-set name (`inet6`) |
|---|---|---|---|
| `source-exclude` | `src-<term>` | `src-ipv6-<term>` | `src-<term>` |
| `destination-exclude` | `dst-<term>` | `dst-ipv6-<term>` | `dst-<term>` |

Destination field-sets currently mix address families; see [Known Issues](#known-issues).

Excluded prefixes that don't fall inside any included prefix are dropped.

??? example "Source exclusion in a mixed filter"
    Policy (`INTERNAL` holds IPv4 and IPv6 ranges, `SOME_HOST` holds hosts inside them):

    ```yaml
    - name: FS_MIXED
      source-address: INTERNAL
      source-exclude: SOME_HOST
      action: accept
    ```

    Output (from the `testSrcFsMixed` regression test):

    ```text
    traffic-policies
       field-set ipv4 prefix src-FS_MIXED
          8.8.4.0/24
          8.8.8.0/24
          except 8.8.4.4/32
          except 8.8.8.8/32
       !
       field-set ipv6 prefix src-ipv6-FS_MIXED
          2001:4860:4860::/64
          2001:4860:4861::/64
          except 2001:4860:4860::8844/128
          except 2001:4860:4861::8888/128
       !
       no traffic-policy test-filter
       traffic-policy test-filter
          match FS_MIXED ipv4
             source prefix field-set src-FS_MIXED
          !
          match ipv6-FS_MIXED ipv6
             source prefix field-set src-ipv6-FS_MIXED
          !
    ```

### Ports

Ports are rendered inline as port lists, for example `source port 53` or `destination port 22 1024-65535`. EOS also allows `all` or a port field-set, but Aerleon doesn't generate either. A term that uses the `port` token (source **or** destination) is skipped with a warning.

### Default terms

EOS adds two built-in terms to every traffic-policy, one per address family: `ipv4-default-all` and `ipv6-default-all`. They match whatever no other term matched.

To set what these terms do, write a term whose name starts with `default-`. Aerleon renames it to `ipv4-default-all` and/or `ipv6-default-all`, according to the header's address family. Give it an action (and optionally `counter` or `logging`) but no match criteria. Only one `default-` term is allowed per filter; a second one causes a duplicate-term error.

??? example "Default deny"
    Policy:

    ```yaml
    - name: default-term-1
      action: deny
    ```

    Output in a `mixed` filter (from the `testDefaultDeny` regression test):

    ```text
    traffic-policies
       no traffic-policy test-filter
       traffic-policy test-filter
          match ipv4-default-all ipv4
             actions
                drop
          !
          match ipv6-default-all ipv6
             actions
                drop
          !
    ```

### Terms with no match criteria

A term that isn't a [default term](#default-terms) must match on at least one of these, or it is skipped with a warning:

`source-address`, `source-exclude`, `source-port`, `source-prefix`, `destination-address`, `destination-exclude`, `destination-port`, `destination-prefix`, `protocol`, `protocol-except`, `port`, `fragment-offset`, `ttl`, `hop-limit`

Other match tokens, such as `packet-length` or `option`, don't count on their own. For example, a term that only sets `packet-length` is skipped.

## Documentation

* [Arista EOS: Support for traffic-policy on interfaces](https://eos.arista.com/eos-4-25-0f/support-for-traffic-policy-on-interfaces/)

## Known Issues

!!! bug "Known issues"
    * **`destination-exclude` field-sets mix address families.** Unlike source field-sets, destination field-sets are not split by address family. Each one lists **every** IPv4 and IPv6 prefix and exclusion, so `field-set ipv4 prefix dst-<term>` can contain IPv6 prefixes. Excluded prefixes outside the included ones are not dropped either. See the `testDstFsMixed` regression test output.
