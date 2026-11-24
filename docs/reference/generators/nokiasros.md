# Nokia SR OS

Renders Nokia SR OS IP filters and CPM filters as JSON for the `nokia-conf` YANG model, ready to load with NETCONF, gRPC or pySROS.

## Header Format

```yaml
targets:
    nokiasros: [filter name] {inet|inet6|mixed} {accept|drop} {pktlenfilter} {syslog-profile [id]}
    nokiasros: [filter name] cpm {inet|inet6} {syslog-profile [id]}
```

### IP filter options

The filter name is rendered as `filter-name`, even when it's a number. The `filter-id` is left to the device, so dynamic filter ID generation must be enabled on it.

| Option | Description | Notes |
|---|---|---|
| `inet` | Render an IPv4 `ip-filter`. | Default. |
| `inet6` | Render an IPv6 `ipv6-filter`. | |
| `mixed` | Render an `ip-filter` and an `ipv6-filter` with the same name. | Each term is rendered in the filter of its address family. |
| `accept` | Set `default-action` to `accept`. | |
| `drop` | Set `default-action` to `drop`. | Default. |
| `pktlenfilter` | Set the filter `type` to `packet-length`. | Required to match `ttl` or `hop-limit`. |
| `syslog-profile [id]` | Filter log used by entries with `logging`. | 101 to 199. Default `102`. |

### CPM filter options

| Option | Description | Notes |
|---|---|---|
| `cpm` | Render a CPM filter instead of an IP filter. | A filter named `cpm` is also a CPM filter. The name isn't rendered, as the device has one CPM filter per address family. |
| `inet` | Render the IPv4 CPM filter. | Default. |
| `inet6` | Render the IPv6 CPM filter. | |
| `syslog-profile [id]` | Filter log used by entries with `logging`. | 101 to 199. Default `102`. |

An option can only be given once, and only one address family and one default action can be set. An option that isn't listed for the filter type raises an error, so `mixed`, `accept`, `drop` and `pktlenfilter` can't be used on a CPM filter.

## Term Format

### Common tokens

These tokens are included from the _[Common](common.md)_ page.

!!! warning "Not supported on Nokia SR OS"
    Nokia SR OS doesn't support `verbatim`. A term that uses it raises an error.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Nokia SR OS tokens

Nokia SR OS also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `hop-limit` | IPv6 hop limit to match, a value or a range. | `hop-limit: 0-1` | `hop-limit: {eq: N}` or `hop-limit: {range: {start: N, end: M}}`. Requires `pktlenfilter`, so not available in CPM filters. Not rendered in IPv4 filters. |
| `icmp-code` | ICMP codes to match. | `icmp-code: 3 4` | Requires exactly one `icmp-type`. One entry per code. |
| `logging` | Log matching packets. | `logging: true` | Adds `log` with the header's syslog profile. `logging: disable` doesn't. |
| `policer` | Rate-limit matching packets. | `policer: icmp-policer` | Adds `rate-limit: {policer: [name]}` to the action. The policer must exist on the device. |
| `ttl` | IPv4 TTL to match, a value or a range. | `ttl: 0-1` | `ttl: {eq: N}` or `ttl: {range: {start: N, end: M}}`. Requires `pktlenfilter`, so not available in CPM filters. Not rendered in IPv6 filters. |

**Other behavior:**

* SR OS entries match a single prefix, port, protocol, ICMP type and ICMP code, so each term becomes one entry per combination of source address, destination address, source port, destination port, protocol, ICMP type and ICMP code.
* The entry `description` is the term's `comment`, or the term name if it has none.
* The header `comment` is the filter's `description`. CPM filters have no description, so the comment is put before the first entry's description, as `[comment] | [description]`.
* Protocols are rendered by name, except `esp`, which is rendered as `50`. IPv6 filters match the protocol with `next-header`, and `icmpv6` is rendered as `ipv6-icmp`.
* A term is skipped, with a warning, when it can't match anything in the filter's address family:
    * its source or destination addresses all belong to the other family;
    * its protocols all do: `icmp` in an `inet6` filter, `icmpv6` in an `inet` filter;
    * it matches `hop-limit` but not `ttl` in an IPv4 filter, or `ttl` but not `hop-limit` in an IPv6 filter;
    * it uses `option: ip-options` in an IPv6 filter.

    If only some of the protocols belong to the other family, for example `protocol: tcp icmp` in an `inet6` filter, only those are left out, with a warning. In `mixed` filters no warning is logged, because the other family's filter renders them.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `accept` | |
| `deny` | `drop` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established` | Match established connections. | `option: established` | Adds 1024-65535 to the destination ports, as the _[Juniper](juniper.md)_ generator does. With `protocol: tcp` alone, also adds `tcp-established`. Requires `tcp`, `udp` or both (raises an error otherwise). |
| `first-fragment` | Match the first fragment. | `option: first-fragment` | `fragment: first-only`. Raises an error in CPM filters, whose model only has `fragment true` or `false`. |
| `ip-options` | Match IPv4 packets with any IP option. | `option: ip-options` | `option-present: true`. IPv6 has no IP options, so the term is skipped in IPv6 filters. |
| `is-fragment`, `fragments` | Match fragments. | `option: is-fragment` | `fragment: true`. |
| `tcp-established` | Match established TCP connections. | `option: tcp-established` | IP filters: the `tcp-established` leaf. CPM filters: `tcp-flags: {ack: true}`. Requires `protocol: tcp` alone (raises an error otherwise). |

## Output

Each policy file renders to one file with the same name and a `.sros_acl` extension, so `sample.yaml` renders `sample.sros_acl`.

The file is a JSON list with one item per filter. Each item is keyed by its filter type, which tells where to load it:

| Key | Configuration path |
|---|---|
| `ip-filter` | `/nokia-conf:configure/filter/ip-filter[filter-name=NAME]` |
| `ipv6-filter` | `/nokia-conf:configure/filter/ipv6-filter[filter-name=NAME]` |
| `cpm-ip-filter` | `/nokia-conf:configure/system/security/cpm-filter/ip-filter` |
| `cpm-ipv6-filter` | `/nokia-conf:configure/system/security/cpm-filter/ipv6-filter` |

IP filters are rendered with `scope: template`. CPM filters are rendered with `admin-state: enable`.

### Entry IDs

Each term gets a block of 1000 entry IDs: the entries of term N are numbered `N * 1000`, `N * 1000 + 1`, and so on. A term that isn't rendered still uses its block, so the IDs of the terms after it don't change. Generation fails if:

* a term expands to more than 1000 entries, or
* an entry ID goes over the model's maximum: 2097151 for IP filters (2097 terms), 131072 for CPM filters (131 terms).

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

    ```yaml title="sample.yaml"
    filters:
      - header:
          targets:
            nokiasros: edge-inbound inet
    --8<-- "docs/reference/generators.md:sample-terms"
    ```

    ```json title="sample.sros_acl"
    [
        {
            "ip-filter": {
                "nokia-conf:scope": "template",
                "nokia-conf:default-action": "drop",
                "nokia-conf:filter-name": "edge-inbound",
                "nokia-conf:entry": [
                    {
                        "description": "Allow SSH from the management network.",
                        "action": {
                            "accept": [
                                null
                            ]
                        },
                        "match": {
                            "src-ip": {
                                "address": "10.0.0.0/24"
                            },
                            "dst-port": {
                                "eq": 22
                            },
                            "protocol": "tcp"
                        },
                        "entry-id": 1000
                    },
                    {
                        "description": "Allow SSH from the management network.",
                        "action": {
                            "accept": [
                                null
                            ]
                        },
                        "match": {
                            "src-ip": {
                                "address": "192.168.10.0/24"
                            },
                            "dst-port": {
                                "eq": 22
                            },
                            "protocol": "tcp"
                        },
                        "entry-id": 1001
                    },
                    {
                        "description": "default-deny",
                        "action": {
                            "drop": [
                                null
                            ]
                        },
                        "entry-id": 2000
                    }
                ]
            }
        }
    ]
    ```

=== "CPM filter"

    An IPv4 CPM filter that logs to syslog profile 101. The header comment goes in the first entry's description, and `tcp-established` is rendered as `tcp-flags`. `PEERS` also holds an IPv6 address, which isn't rendered in the IPv4 filter.

    ```yaml title="cpm.yaml"
    filters:
      - header:
          comment: "Protect the control plane."
          targets:
            nokiasros: cpm-v4 cpm inet syslog-profile 101
        terms:
          - name: allow-bgp
            source-address: PEERS
            protocol: tcp
            destination-port: BGP
            action: accept
          - name: allow-bgp-replies
            source-address: PEERS
            protocol: tcp
            source-port: BGP
            option: tcp-established
            action: accept
          - name: default-deny
            logging: true
            action: deny
    ```

    ```yaml title="definitions.yaml"
    networks:
      PEERS:
        values:
          - address: 192.0.2.1/32
          - address: 2001:db8::1/128
    services:
      BGP:
        - port: 179
          protocol: tcp
    ```

    ```json title="cpm.sros_acl"
    [
        {
            "cpm-ip-filter": {
                "nokia-conf:admin-state": "enable",
                "nokia-conf:entry": [
                    {
                        "description": "Protect the control plane. | allow-bgp",
                        "action": {
                            "accept": [
                                null
                            ]
                        },
                        "match": {
                            "src-ip": {
                                "address": "192.0.2.1/32"
                            },
                            "dst-port": {
                                "eq": 179
                            },
                            "protocol": "tcp"
                        },
                        "entry-id": 1000
                    },
                    {
                        "description": "allow-bgp-replies",
                        "action": {
                            "accept": [
                                null
                            ]
                        },
                        "match": {
                            "src-ip": {
                                "address": "192.0.2.1/32"
                            },
                            "src-port": {
                                "eq": 179
                            },
                            "protocol": "tcp",
                            "tcp-flags": {
                                "ack": true
                            }
                        },
                        "entry-id": 2000
                    },
                    {
                        "description": "default-deny",
                        "action": {
                            "drop": [
                                null
                            ]
                        },
                        "log": 101,
                        "entry-id": 3000
                    }
                ]
            }
        }
    ]
    ```

=== "TTL, hop limit and policer"

    A `mixed` packet-length filter with a default action of `accept`. `ttl` is rendered in the IPv4 filter and `hop-limit` in the IPv6 filter. `logging` uses the default syslog profile, 102.

    ```yaml title="pktlen.yaml"
    filters:
      - header:
          comment: "Edge filter with TTL checks."
          targets:
            nokiasros: edge-ttl mixed accept pktlenfilter
        terms:
          - name: deny-low-ttl
            ttl: 0-1
            hop-limit: 0-1
            logging: true
            action: deny
          - name: police-ping
            protocol: icmp icmpv6
            icmp-type: echo-request
            policer: icmp-policer
            action: accept
    ```

    ```json title="pktlen.sros_acl"
    [
        {
            "ip-filter": {
                "nokia-conf:scope": "template",
                "nokia-conf:type": "packet-length",
                "nokia-conf:description": "Edge filter with TTL checks.",
                "nokia-conf:default-action": "accept",
                "nokia-conf:filter-name": "edge-ttl",
                "nokia-conf:entry": [
                    {
                        "description": "deny-low-ttl",
                        "action": {
                            "drop": [
                                null
                            ]
                        },
                        "match": {
                            "ttl": {
                                "range": {
                                    "start": 0,
                                    "end": 1
                                }
                            }
                        },
                        "log": 102,
                        "entry-id": 1000
                    },
                    {
                        "description": "police-ping",
                        "action": {
                            "accept": [
                                null
                            ],
                            "rate-limit": {
                                "policer": "icmp-policer"
                            }
                        },
                        "match": {
                            "protocol": "icmp",
                            "icmp": {
                                "type": 8
                            }
                        },
                        "entry-id": 2000
                    }
                ]
            }
        },
        {
            "ipv6-filter": {
                "nokia-conf:scope": "template",
                "nokia-conf:type": "packet-length",
                "nokia-conf:description": "Edge filter with TTL checks.",
                "nokia-conf:default-action": "accept",
                "nokia-conf:filter-name": "edge-ttl",
                "nokia-conf:entry": [
                    {
                        "description": "deny-low-ttl",
                        "action": {
                            "drop": [
                                null
                            ]
                        },
                        "match": {
                            "hop-limit": {
                                "range": {
                                    "start": 0,
                                    "end": 1
                                }
                            }
                        },
                        "log": 102,
                        "entry-id": 1000
                    },
                    {
                        "description": "police-ping",
                        "action": {
                            "accept": [
                                null
                            ],
                            "rate-limit": {
                                "policer": "icmp-policer"
                            }
                        },
                        "match": {
                            "next-header": "ipv6-icmp",
                            "icmp": {
                                "type": 128
                            }
                        },
                        "entry-id": 2000
                    }
                ]
            }
        }
    ]
    ```

=== "Options and ICMP codes"

    `established` on UDP and on TCP, `first-fragment`, `ip-options`, and an `icmp-code` match with one entry per code.

    ```yaml title="options.yaml"
    filters:
      - header:
          targets:
            nokiasros: edge-options inet
        terms:
          - name: allow-dns-replies
            protocol: udp
            source-port: DNS
            option: established
            action: accept
          - name: allow-tcp-replies
            protocol: tcp
            option: established
            action: accept
          - name: deny-first-fragment
            option: first-fragment
            action: deny
          - name: deny-ip-options
            option: ip-options
            action: deny
          - name: allow-unreachable
            protocol: icmp
            icmp-type: unreachable
            icmp-code: 3 4
            action: accept
    ```

    ```yaml title="definitions.yaml"
    services:
      DNS:
        - port: 53
          protocol: udp
    ```

    ```json title="options.sros_acl"
    [
        {
            "ip-filter": {
                "nokia-conf:scope": "template",
                "nokia-conf:default-action": "drop",
                "nokia-conf:filter-name": "edge-options",
                "nokia-conf:entry": [
                    {
                        "description": "allow-dns-replies",
                        "action": {
                            "accept": [
                                null
                            ]
                        },
                        "match": {
                            "src-port": {
                                "eq": 53
                            },
                            "dst-port": {
                                "range": {
                                    "start": 1024,
                                    "end": 65535
                                }
                            },
                            "protocol": "udp"
                        },
                        "entry-id": 1000
                    },
                    {
                        "description": "allow-tcp-replies",
                        "action": {
                            "accept": [
                                null
                            ]
                        },
                        "match": {
                            "dst-port": {
                                "range": {
                                    "start": 1024,
                                    "end": 65535
                                }
                            },
                            "protocol": "tcp",
                            "tcp-established": [
                                null
                            ]
                        },
                        "entry-id": 2000
                    },
                    {
                        "description": "deny-first-fragment",
                        "action": {
                            "drop": [
                                null
                            ]
                        },
                        "match": {
                            "fragment": "first-only"
                        },
                        "entry-id": 3000
                    },
                    {
                        "description": "deny-ip-options",
                        "action": {
                            "drop": [
                                null
                            ]
                        },
                        "match": {
                            "option-present": true
                        },
                        "entry-id": 4000
                    },
                    {
                        "description": "allow-unreachable",
                        "action": {
                            "accept": [
                                null
                            ]
                        },
                        "match": {
                            "protocol": "icmp",
                            "icmp": {
                                "type": 3,
                                "code": 3
                            }
                        },
                        "entry-id": 5000
                    },
                    {
                        "description": "allow-unreachable",
                        "action": {
                            "accept": [
                                null
                            ]
                        },
                        "match": {
                            "protocol": "icmp",
                            "icmp": {
                                "type": 3,
                                "code": 4
                            }
                        },
                        "entry-id": 5001
                    }
                ]
            }
        }
    ]
    ```
