# GCP Hierarchical Firewall

Renders a Google Cloud [hierarchical firewall policy](https://cloud.google.com/firewall/docs/firewall-policies) as JSON. All filters in a policy file go into one firewall policy.

## Header Format

The gcp_hf header designation has the following format:

```yaml
targets:
    gcp_hf: [policy name] {INGRESS|EGRESS} {inet|inet6|mixed} {beta|ga} {max cost}
```

| Option | Description | Notes |
|---|---|---|
| `policy name` | Name of the firewall policy. | Required. Lowercase letters, digits and dashes, starting with a letter and not ending with a dash, at most 63 characters. Every header in the policy file must use the same name. |
| `INGRESS` | Render ingress rules. | Default. |
| `EGRESS` | Render egress rules. | |
| `inet` | IPv4 only. | Default. |
| `inet6` | IPv6 only. | |
| `mixed` | IPv4 and IPv6. | Each term becomes an IPv4 rule and an IPv6 rule. The IPv6 rule's description starts with `<term>-v6`. |
| `beta` | Use the beta API field names. | Default. The policy name renders as `displayName`, and matches are nested under `match.config`. |
| `ga` | Use the GA API field names. | The policy name renders as `shortName`, and matches sit directly under `match`. |
| `max cost` | A number. Fail if the policy's total rule cost goes over it. | Default 100, maximum 65536. Must be the same in every header. Raises `ExceededCostError`. |

Any other header option raises a `HeaderError`.

The **cost** of a rule is its number of addresses, plus its number of protocols and ports, plus its number of target resources. The limit is checked against the total for the whole policy file.

## Term Format

For common keys see the [Common](common.md) page. gcp_hf does **not** support `source-port`, `icmp-type`, `option`, `source-exclude`, `destination-exclude`, `expiration` or `verbatim` (they raise an error). It also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `logging` | Turn on firewall rule logging. | `logging: true` | Renders `"enableLogging": true`. |
| `source-tag`, `destination-tag` | — | | Accepted by validation, then rejected with "Hierarchical Firewall does not support tags". |
| `target-resources` | VPC networks the rule applies to, as `(project, network)` pairs. | `target-resources: ["(my-project,my-vpc)"]` | Rendered as `targetResources` URLs. At most 256. `[my-project, my-vpc]` and `my-project,my-vpc` also work. |

**Addresses by direction:**

| Direction | Address used | Rendered as |
|---|---|---|
| `INGRESS` | `source-address` | `srcIpRanges` |
| `EGRESS` | `destination-address` | `destIpRanges` |

The other address is ignored without a warning; see [Known Issues](#known-issues).

**Other behavior:**

* The rule description is `<term>: <comment>`, cut to 64 characters.
* Priorities start at 1 and go up by one for each rule, across all filters.
* A term without `protocol` matches all protocols (`"ipProtocol": "all"`). Protocols other than `tcp`, `udp`, `icmp`, `esp`, `ah`, `ipip` and `sctp` are rendered by number.
* A term with addresses, but none of the family being rendered, is skipped with a warning. Likewise, `icmp` is dropped from IPv6 rules, and `icmpv6` and `igmp` from IPv4 rules.
* A term with more than 256 addresses is split into several rules. More than 256 destination ports raises an error.
* A `deny` term with no match criteria becomes a default deny for `0.0.0.0/0` (and `::/0` for `mixed`).

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `allow` | |
| `deny` | `deny` | |
| `next` | `goto_next` | Hands the decision to the next policy in the hierarchy. |

## Output

Each policy file renders to one file with the same name and a `.gcphf` extension, so `sample.yaml` renders `sample.gcphf`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`. This page adds `logging` to show gcp_hf-specific tokens.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        gcp_hf: org-policy
    terms:
      - name: allow-ssh
        comment: "Allow SSH from the management network."
        source-address: MGMT            # 10.0.0.0/24, 192.168.10.0/24
        protocol: tcp
        destination-port: SSH           # 22/tcp
        logging: true
        action: accept
      - name: default-deny
        action: deny
```

```json title="sample.gcphf"
[
  {
    "displayName": "org-policy",
    "rules": [
      {
        "action": "allow",
        "description": "allow-ssh: Allow SSH from the management network.",
        "direction": "INGRESS",
        "enableLogging": true,
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "tcp",
                "ports": [
                  "22"
                ]
              }
            ],
            "srcIpRanges": [
              "10.0.0.0/24",
              "192.168.10.0/24"
            ]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 1
      },
      {
        "action": "deny",
        "description": "default-deny: ",
        "direction": "INGRESS",
        "enableLogging": false,
        "match": {
          "config": {
            "layer4Configs": [
              {
                "ipProtocol": "all"
              }
            ],
            "srcIpRanges": [
              "0.0.0.0/0"
            ]
          },
          "versionedExpr": "FIREWALL"
        },
        "priority": 2
      }
    ],
    "type": "FIREWALL"
  }
]
```

## Known Issues

!!! bug "Known issues"
    * **The other address is silently dropped.** An `INGRESS` term's `destination-address` and an `EGRESS` term's `source-address` are ignored without a warning. A term meant to allow traffic to one host is rendered as "allow from anywhere to anything".
