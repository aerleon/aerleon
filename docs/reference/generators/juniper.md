# Juniper

## Header Format

The Juniper header designation has the following format:

```yaml
targets:
    juniper: [filter name] {inet|inet6|mixed|bridge|ethernet-switching} {enable_dsmo} {not-interface-specific} {filter_enhanced_mode} {noverbose} {ingress|egress} {physical|loopback}
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the firewall filter. | |
| `inet` | Render an IPv4 filter. | Default. |
| `inet6` | Render an IPv6 filter. | |
| `mixed` | Render an IPv4 and an IPv6 filter. | The filter names get a `4` or `6` suffix. |
| `bridge` | Render a bridge filter. | |
| `ethernet-switching` | Render an ethernet-switching filter. | |
| `enable_dsmo` | Turn on discontinuous subnet mask summarization. | Optional. |
| `not-interface-specific` | Leave `interface-specific` out of the filter. | Optional. |
| `filter_enhanced_mode` | Add `enhanced-mode` to the filter. | Optional. |
| `noverbose` | Leave out term comments and owner. | Optional. |
| `ingress`, `egress` | Direction the filter is applied in. | Optional. Used by subclasses such as Juniper EVO. |
| `physical`, `loopback` | Type of interface the filter is applied to. | Optional. Used by subclasses such as Juniper EVO. |

The address family must come straight after the filter name. When `inet` or `inet6` is specified, naming tokens that contain both IPv4 and IPv6 addresses are rendered using only the matching addresses.

## Term Format

For common keys see the [Common](common.md) page. The following tokens are specific to juniper.

**Match conditions** (rendered under `from`):

| Token | Description | Example | Notes |
|---|---|---|---|
| `address` | Address tokens matched as source **or** destination. | `address: INTERNAL` | |
| `destination-prefix` | Match a prefix-list already configured on the device. | `destination-prefix: local-addrs` | Renders as `destination-prefix-list`. |
| `destination-prefix-except` | Exclude a configured prefix-list. | `destination-prefix-except: vip-addrs` | Rendered as `… except;` inside `destination-prefix-list`. |
| `dscp-except` | Match anything except these DSCP values. | `dscp-except: be` | Renders as `traffic-class-except` in IPv6 filters. |
| `dscp-match` | Match DSCP values. | `dscp-match: af41 af42` | Renders as `traffic-class` in IPv6 filters. |
| `ether-type` | Match EtherType. | `ether-type: arp` | |
| `flexible-match-range` | Match on raw packet bytes. | see example below | Keys: `match-start` (`layer-3`, `layer-4`, `payload`), `byte-offset`, `bit-offset`, `bit-length`, `range`, `range-except`, `flexible-range-name`. Quote hex values. |
| `forwarding-class` | Match forwarding classes. | `forwarding-class: [best-effort]` | |
| `forwarding-class-except` | Match anything except these forwarding classes. | `forwarding-class-except: [network-control]` | |
| `fragment-offset` | Match fragment offset. | `fragment-offset: 1-8191` | |
| `hop-limit` | Match hop limit. | `hop-limit: 255` | IPv6 filters only. |
| `icmp-code` | ICMP code to match. | `icmp-code: 0` | |
| `packet-length` | Match packet length. | `packet-length: 64-1500` | |
| `port` | Service tokens matched as source **or** destination port. | `port: DNS` | |
| `precedence` | Match IP precedence. | `precedence: 5 6` | Values must be 0-7. |
| `protocol-except` | Match every protocol except the ones listed. | `protocol-except: tcp` | |
| `restrict-address-family` | Only render the term in the matching address family. | `restrict-address-family: inet6` | Useful in `mixed` filters. |
| `source-prefix` | Match a prefix-list already configured on the device. | `source-prefix: configured-neighbors-only` | Renders as `source-prefix-list`. |
| `source-prefix-except` | Exclude a configured prefix-list. | `source-prefix-except: bad-neighbors` | Rendered as `… except;` inside `source-prefix-list`. |
| `traffic-type` | Match traffic type. | `traffic-type: broadcast` | |
| `ttl` | Match TTL. | `ttl: 1` | IPv4 filters only. |

**Actions and modifiers** (rendered under `then`):

| Token | Description | Example | Notes |
|---|---|---|---|
| `counter` | Count matching packets. | `counter: ssh-hits` | Renders `count <name>`. |
| `dscp-set` | Rewrite the DSCP value. | `dscp-set: af41` | Renders as `traffic-class` in IPv6 filters. |
| `encapsulate` | Encapsulate matching packets using a tunnel profile. | `encapsulate: gre-profile` | |
| `filter-term` | Call another filter from this term. | `filter-term: common-filter` | Renders `filter <name>;` and nothing else. |
| `logging` | Log matching packets. | `logging: true` | `local` renders `log`; any other value renders `syslog`. |
| `loss-priority` | Set loss priority. | `loss-priority: low` | |
| `next-ip` | Forward matching packets to a next hop (filter-based forwarding). | `next-ip: NEXTHOP_ROUTER` | Must resolve to a single host address. |
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added to the term comment unless the header uses `noverbose`. |
| `policer` | Police matching packets. | `policer: rate-limit-1m` | The policer must exist on the device. |
| `port-mirror` | Send a copy of matching packets to the port mirror. | `port-mirror: true` | |
| `qos` | Set the forwarding class. | `qos: af4` | Renders `forwarding-class <value>`. |
| `routing-instance` | Send matching packets to a routing instance. | `routing-instance: scrubbing` | Replaces the normal action. |
| `traffic-class-count` | Count by traffic class. | `traffic-class-count: tcc` | |

??? example "Terms using juniper tokens"
    ```yaml
    - name: police-bgp
      source-prefix: configured-neighbors-only
      protocol: tcp
      destination-port: BGP
      counter: bgp-hits
      policer: bgp-policer
      action: accept

    - name: match-flex
      flexible-match-range:
        match-start: payload
        byte-offset: 16
        bit-offset: 7
        bit-length: 8
        range: "0x08"
      action: deny
    ```

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `accept` | |
| `deny` | `discard` | |
| `next` | `next term` | |
| `reject` | `reject` | |
| `reject-with-tcp-rst` | `reject tcp-reset` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| *any other value* | Passed through as-is. | `option: syn-flag` | Rendered as `<value>;` under `from`. Aerleon does not check it. |
| `established` | Match established connections. | `option: established` | Adds `tcp-established` for TCP-only terms. For UDP, sets the destination port to 1024-65535 if none is given. |
| `first-fragment` | Match the first fragment of a fragmented packet. | `option: first-fragment` | |
| `inactive` | Render the term but mark it inactive. | `option: inactive` | Prefixes the term with `inactive:`. |
| `initial` | Match the first packet of a TCP connection. | `option: initial` | Renders `tcp-initial`. Only applied when the term matches `tcp`. |
| `is-fragment` | Match fragments. | `option: is-fragment` | Raises an error in IPv6 filters. |
| `not-syn-ack` | Match TCP packets that are not SYN+ACK. | `option: not-syn-ack` | Renders `tcp-flags "!(syn&ack)"`. |
| `rst` | Match TCP packets with RST set. | `option: rst` | Renders `tcp-flags "rst"`. |
| `sample` | Sample matching traffic. | `option: sample` | Adds `sample` to the term's actions. |
| `tcp-established` | Match established TCP connections. | `option: tcp-established` | Raises an error if the term matches anything other than `tcp`. |
| `tcp-initial` | Match the first packet of a TCP connection. | `option: tcp-initial` | |

## Output

Each policy file renders to one file with the same name and a `.jcl` extension, so `sample.yaml` renders `sample.jcl`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        juniper: edge-inbound inet
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

```text title="sample.jcl"
firewall {
    family inet {
        /*
         ** $Id:$
         ** $Date:$
         ** $Revision:$
         **
         */
        replace: filter edge-inbound {
            interface-specific;
            /*
             ** Allow SSH from the management network.
             */
            term allow-ssh {
                from {
                    source-address {
                        10.0.0.0/24;
                        192.168.10.0/24;
                    }
                    protocol tcp;
                    destination-port 22;
                }
                then accept;
            }
            term default-deny {
                then {
                    discard;
                }
            }
        }
    }
}
```
