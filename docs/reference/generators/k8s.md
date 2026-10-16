# K8s

Renders Kubernetes `NetworkPolicy` resources as YAML, one policy per term, wrapped in a `NetworkPolicyList`.

## Header Format

The K8s header designation has the following format:

```yaml
targets:
    k8s: {INGRESS|EGRESS}
```

| Option | Description | Notes |
|---|---|---|
| `INGRESS` | Render ingress policies. | Default. |
| `EGRESS` | Render egress policies. | Policy names get an `-e` suffix. |

## Term Format

For common keys see the [Common](common.md) page. K8s does **not** support `source-port`, `icmp-type`, `option` or `verbatim`, and only matches the protocols `tcp`, `udp` and `sctp`. It also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added as an `owner` annotation. |

**Direction rules** (each raises a `K8sNetworkPolicyError` if broken):

| Direction | Must have | Must not have |
|---|---|---|
| `INGRESS` | `source-address` | `destination-address` |
| `EGRESS` | `destination-address` | `source-address` |

**Other behavior:**

* Each address becomes an `ipBlock`. `source-exclude` / `destination-exclude` become its `except` list.
* `comment` becomes a `comment` annotation. If the term has no `comment`, the header comment is used.
* Term names must be valid Kubernetes object names (lowercase letters, digits and dashes).
* If excluding addresses leaves none, the term is skipped with an error message.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | An `ingress` or `egress` rule | |
| `deny` | A `NetworkPolicy` with no rules | Only allowed for a default deny: a `deny` term with no match criteria. The empty policy blocks all traffic in that direction. Any other `deny` term raises an error. |

## Output

Each policy file renders to one file with the same name and a `.yml` extension, so `sample.yaml` renders `sample.yml`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        k8s: INGRESS
--8<-- "docs/reference/generators.md:sample-terms"
```

```yaml title="sample.yml"
apiVersion: networking.k8s.io/v1
items:
- apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    annotations:
      comment: Allow SSH from the management network.
    name: allow-ssh
  spec:
    ingress:
    - from:
      - ipBlock:
          cidr: 10.0.0.0/24
      - ipBlock:
          cidr: 192.168.10.0/24
      ports:
      - port: 22
        protocol: TCP
    podSelector: {}
    policyTypes:
    - Ingress
- apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    annotations: {}
    name: default-deny
  spec:
    podSelector: {}
    policyTypes:
    - Ingress
kind: NetworkPolicyList
```

#### Owner

The sample `allow-ssh` term with `owner`. It uses the sample definitions.

```yaml title="owner.yaml"
filters:
  - header:
      targets:
        k8s: INGRESS
    terms:
      - name: allow-ssh
        comment: "Allow SSH from the management network."
        source-address: MGMT
        protocol: tcp
        destination-port: SSH
        owner: netops@example.com
        action: accept
```

```yaml title="owner.yml"
apiVersion: networking.k8s.io/v1
items:
- apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    annotations:
      comment: Allow SSH from the management network.
      owner: netops@example.com
    name: allow-ssh
  spec:
    ingress:
    - from:
      - ipBlock:
          cidr: 10.0.0.0/24
      - ipBlock:
          cidr: 192.168.10.0/24
      ports:
      - port: 22
        protocol: TCP
    podSelector: {}
    policyTypes:
    - Ingress
kind: NetworkPolicyList
```

## Known Issues

!!! bug "Known issues"
    * **Exclusions crash with mixed-family address tokens.** If `source-address` (or `destination-address`) holds both IPv4 and IPv6 addresses and the term uses an exclusion, generation fails with `TypeError: … are not of the same version`.
