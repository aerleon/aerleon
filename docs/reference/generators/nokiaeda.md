# Nokia EDA

Renders native Nokia Event Driven Automation (EDA) resources from the `filters.eda.nokia.com/v1` API as YAML: one `Filter`, or one `ControlPlaneFilter` with the `cpm` option, per header. The output is ready to apply to EDA with replace semantics.

## Header Format

```yaml
targets:
    nokiaeda: [filter name] {inet|inet6|mixed} {stats} namespace [namespace]
    nokiaeda: [filter name] cpm {inet|inet6|mixed} {stats} namespace [namespace] {node-selector [key] [value]}... {node [node]}...
```

The filter name is the resource's `metadata.name`. It must be a valid Kubernetes name: lowercase letters, digits, `-` and `.`.

| Option | Description | Notes |
|---|---|---|
| `inet` | Render IPv4 entries only. | Default. |
| `inet6` | Render IPv6 entries only. | |
| `mixed` | Render IPv4 and IPv6 entries in the same resource. | Each term renders its IPv4 entries, then its IPv6 entries, before the next term. |
| `stats` | Collect statistics per entry. | Adds `statisticsPerEntry: true`. |
| `namespace [namespace]` | The EDA namespace of the resource. | Required. Rendered as `metadata.namespace`. Must be a valid Kubernetes namespace. |
| `cpm` | Render a `ControlPlaneFilter` instead of a `Filter`. | Needs at least one `node-selector` or `node`. |
| `node-selector [key] [value]` | TopoNode label selector. | `cpm` only, can be repeated. Rendered as `[key]=[value]` in `nodeSelectors`. Key and value are separate words, because `=` isn't accepted in a target. |
| `node [node]` | TopoNode name. | `cpm` only, can be repeated. Rendered in `nodes`. |

Options other than `node-selector` and `node` can only be given once, and only one address family can be set. An unknown option raises an error, as does a second resource with the same kind, namespace and name.

## Term Format

### Common tokens

These tokens are included from the _[Common](common.md)_ page.

!!! warning "Not supported on Nokia EDA"
    Nokia EDA doesn't support `verbatim`. A term that uses it raises an error.

--8<-- "docs/reference/generators/common.md:common-tokens"

### Nokia EDA tokens

Nokia EDA also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `icmp-code` | ICMP codes to match. | `icmp-code: 3 4` | Requires exactly one `icmp-type`. Rendered as `icmpCodes`. |
| `logging` | Log matching packets. | `logging: true` | Adds `log: true`, except for `logging: disable`. |

`counter` and `policer` are accepted but not rendered. They're only reported in the debug log.

**Other behavior:**

* EDA entries match a single prefix, port, protocol and ICMP type, so each term becomes one entry per combination of source address, destination address, source port, destination port, protocol and ICMP type.
* Protocols are rendered as `protocolNumber`. A single port is rendered as `PortOperator: Equals` with `PortNumber`, a port range as `PortRange` (`start-end`).
* A term whose addresses all belong to the other address family is skipped, with a warning. So is a term whose protocols all do: `icmp` in an `inet6` filter, `icmpv6` in an `inet` filter. If only some of the protocols belong to the other family, for example `protocol: tcp icmp` in an `inet6` filter, only those are left out, with a warning. In `mixed` filters no warning is logged, because the other family renders them.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `Accept` | |
| `deny` | `Drop` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established` | Match established connections. | `option: established` | TCP: same as `tcp-established`. UDP: sets the destination port to 1024-65535 if the term has no `destination-port`. Requires `protocol: tcp` or `protocol: udp` alone (raises an error otherwise). |
| `first-fragment` | Match the first fragment. | `option: first-fragment` | `firstFragment: true`. Can't be combined with `is-fragment` or `fragments`. |
| `is-fragment`, `fragments` | Match fragments. | `option: is-fragment` | `fragment: true`. |
| `not-syn-ack` | Match TCP packets that are not SYN+ACK. | `option: not-syn-ack` | `tcpFlags: '!(SYN&ACK)'`. |
| `tcp-established` | Match established TCP connections. | `option: tcp-established` | <code>tcpFlags: ACK&#124;RST</code>. |
| `tcp-initial` | Match the first packet of a TCP connection. | `option: tcp-initial` | `tcpFlags: SYN`. |

Options that set `tcpFlags` set the protocol to TCP, and raise an error if the term has another protocol. A term can only use one of them.

## Output

Each policy file renders to one file with the same name and a `.eda.yaml` extension, so `sample.yaml` renders `sample.eda.yaml`. Each header is one YAML document.

### Differences from Nokia SR Linux

Nokia EDA renders the same filters as _[Nokia SR Linux](nokiasrl.md)_, as EDA resources that EDA then pushes to the nodes:

| Area | Nokia SR Linux | Nokia EDA |
|---|---|---|
| Filter | `ipv4-filter` and/or `ipv6-filter` (JSON) | One `Filter` or `ControlPlaneFilter` resource (YAML) holding both families, with `type: IPv4` or `type: IPv6` on each entry |
| Sequence IDs | 5, 10, 15, … | None: EDA numbers the entries from their order in the list |
| Term `comment` | `_annotate_description` | YAML comments above the term's first entry. They're in the file but aren't sent to EDA. |
| Header `comment` | `description` | `aerleon/comment` annotation |
| Repository tags | `_annotate` | `aerleon/revision` annotation |
| `destination-prefix`, `source-prefix` | Supported | Not supported |
| `platform`, `platform-exclude` | Not supported | Supported |

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

    ```yaml title="sample.yaml"
    filters:
      - header:
          targets:
            nokiaeda: edge-inbound namespace eda
    --8<-- "docs/reference/generators.md:sample-terms"
    ```

    ```yaml title="sample.eda.yaml"
    ---
    apiVersion: filters.eda.nokia.com/v1
    kind: Filter
    metadata:
      name: edge-inbound
      namespace: eda
      annotations:
        aerleon/revision: $Id:$ $Date:$ $Revision:$
    spec:
      entries:
      # Allow SSH from the management network.
      - description: allow-ssh
        type: IPv4
        ipEntry:
          action: Accept
          sourcePrefix: 10.0.0.0/24
          protocolNumber: 6
          destinationPortOperator: Equals
          destinationPortNumber: 22
      - description: allow-ssh
        type: IPv4
        ipEntry:
          action: Accept
          sourcePrefix: 192.168.10.0/24
          protocolNumber: 6
          destinationPortOperator: Equals
          destinationPortNumber: 22
      - description: default-deny
        type: IPv4
        ipEntry:
          action: Drop
    ```

=== "ControlPlaneFilter"

    A `mixed` control plane filter with statistics and logging, applied to the nodes labelled `eda.nokia.com/role=leaf` and to the node `spine1`.

    ```yaml title="cpm.yaml"
    filters:
      - header:
          comment: "Protect the control plane of the leaves."
          targets:
            nokiaeda: protect-cpm cpm mixed stats namespace eda node-selector eda.nokia.com/role leaf node spine1
        terms:
          - name: allow-bgp
            source-address: PEERS
            protocol: tcp
            destination-port: BGP
            action: accept
          - name: allow-ping
            protocol: icmp icmpv6
            icmp-type: echo-request
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

    ```yaml title="cpm.eda.yaml"
    ---
    apiVersion: filters.eda.nokia.com/v1
    kind: ControlPlaneFilter
    metadata:
      name: protect-cpm
      namespace: eda
      annotations:
        aerleon/revision: $Id:$ $Date:$ $Revision:$
        aerleon/comment: Protect the control plane of the leaves.
    spec:
      nodeSelectors:
      - eda.nokia.com/role=leaf
      nodes:
      - spine1
      statisticsPerEntry: true
      entries:
      - description: allow-bgp
        type: IPv4
        ipEntry:
          action: Accept
          sourcePrefix: 192.0.2.1/32
          protocolNumber: 6
          destinationPortOperator: Equals
          destinationPortNumber: 179
      - description: allow-bgp
        type: IPv6
        ipEntry:
          action: Accept
          sourcePrefix: 2001:db8::1/128
          protocolNumber: 6
          destinationPortOperator: Equals
          destinationPortNumber: 179
      - description: allow-ping
        type: IPv4
        ipEntry:
          action: Accept
          protocolNumber: 1
          icmpTypeNumber: 8
      - description: allow-ping
        type: IPv6
        ipEntry:
          action: Accept
          protocolNumber: 58
          icmpTypeNumber: 128
      - description: default-deny
        type: IPv4
        ipEntry:
          action: Drop
          log: true
      - description: default-deny
        type: IPv6
        ipEntry:
          action: Drop
          log: true
    ```

=== "Options and ICMP codes"

    `tcp-established`, `established` on UDP, `is-fragment`, and an `icmp-code` match.

    ```yaml title="options.yaml"
    filters:
      - header:
          targets:
            nokiaeda: edge-options namespace eda
        terms:
          - name: allow-tcp-replies
            protocol: tcp
            option: tcp-established
            action: accept
          - name: allow-dns-replies
            protocol: udp
            source-port: DNS
            option: established
            action: accept
          - name: deny-fragments
            option: is-fragment
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

    ```yaml title="options.eda.yaml"
    ---
    apiVersion: filters.eda.nokia.com/v1
    kind: Filter
    metadata:
      name: edge-options
      namespace: eda
      annotations:
        aerleon/revision: $Id:$ $Date:$ $Revision:$
    spec:
      entries:
      - description: allow-tcp-replies
        type: IPv4
        ipEntry:
          action: Accept
          protocolNumber: 6
          tcpFlags: ACK|RST
      - description: allow-dns-replies
        type: IPv4
        ipEntry:
          action: Accept
          protocolNumber: 17
          sourcePortOperator: Equals
          sourcePortNumber: 53
          destinationPortRange: 1024-65535
      - description: deny-fragments
        type: IPv4
        ipEntry:
          action: Drop
          fragment: true
      - description: allow-unreachable
        type: IPv4
        ipEntry:
          action: Accept
          protocolNumber: 1
          icmpTypeNumber: 3
          icmpCodes:
          - 3
          - 4
    ```
