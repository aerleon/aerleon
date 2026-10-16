# GCE

Renders Google Compute Engine VPC firewall rules as JSON.

## Header Format

The GCE header designation has the following format:

```yaml
targets:
    gce: [network] {INGRESS|EGRESS} {inet|inet6|mixed} {max attribute count}
```

| Option | Description | Notes |
|---|---|---|
| `network` | VPC network the rules apply to, e.g. `global/networks/default`. | Also used as the filter name. The last path segment prefixes every rule name. |
| `INGRESS` | Render ingress rules. | Default. |
| `EGRESS` | Render egress rules. | Rule names get an `-e` suffix. |
| `inet` | IPv4 only. | Default. |
| `inet6` | IPv6 only. | |
| `mixed` | IPv4 and IPv6. | Each term becomes two rules; the IPv6 one gets a `-v6` suffix. |
| `max attribute count` | A number. Fail if the policy's total attribute count goes over it. | Optional. Raises `ExceededAttributeCountError`. |

## Term Format

### Common tokens

These tokens are included from the [Common](common.md) page.

!!! warning "Not supported on GCE"
    GCE doesn't support `source-port`, `icmp-type`, `option` or `verbatim`. A term that uses any of them raises an error.

--8<-- "docs/reference/generators/common.md:common-tokens"

### GCE tokens

GCE also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `destination-tag` | Instance network tags the rule applies to. | `destination-tag: db-servers` | Rendered as `targetTags`. `INGRESS` only. Max 70. |
| `logging` | Turn on firewall rule logging. | `logging: true` | Adds `logConfig: {enable: true}`. |
| `owner` | Owner of the term, for record-keeping. | `owner: netops@example.com` | Added to the description. |
| `priority` | Rule priority (lower wins). | `priority: 1000` | |
| `source-tag` | Instance network tags to match. | `source-tag: web-servers` | `INGRESS`: rendered as `sourceTags`. `EGRESS`: rendered as `targetTags`. Max 30. |

**Direction rules** (each raises a `GceFirewallError` if broken):

| Direction | Must have | Must not have |
|---|---|---|
| `INGRESS` | `source-address` or `source-tag` | `destination-address` |
| `EGRESS` | `destination-address` | `source-address`, `destination-tag` |

So `source-exclude` only works on ingress terms and `destination-exclude` only on egress terms.

**Other behavior:**

* A term without `protocol` matches all protocols.
* If the term has no `comment`, the header comment is used as the description.
* Term names must be lowercase letters, digits and dashes, at most 53 characters.
* A term with more than 256 addresses is split into several rules (`-1`, `-2`, …). More than 256 ports raises an error.
* If the last term is a plain `deny` with no match criteria, it becomes a default deny: priority 65534, protocol `all`, and any source (ingress) or destination (egress).

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `allowed` | |
| `deny` | `denied` | |

## Output

Each policy file renders to one file with the same name and a `.gce` extension, so `sample.yaml` renders `sample.gce`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        gce: global/networks/default
--8<-- "docs/reference/generators.md:sample-terms"
```

```json title="sample.gce"
[
  {
    "allowed": [
      {
        "IPProtocol": "tcp",
        "ports": [
          "22"
        ]
      }
    ],
    "description": "Allow SSH from the management network.",
    "direction": "INGRESS",
    "name": "default-allow-ssh",
    "network": "global/networks/default",
    "sourceRanges": [
      "10.0.0.0/24",
      "192.168.10.0/24"
    ]
  },
  {
    "denied": [
      {
        "IPProtocol": "all"
      }
    ],
    "description": "",
    "direction": "INGRESS",
    "name": "default-default-deny",
    "network": "global/networks/default",
    "priority": 65534,
    "sourceRanges": [
      "0.0.0.0/0"
    ]
  }
]
```

#### Rule priority

The sample `allow-ssh` term with `priority`. It uses the sample definitions.

```yaml title="priority.yaml"
filters:
  - header:
      targets:
        gce: global/networks/default
    terms:
      - name: allow-ssh
        comment: "Allow SSH from the management network."
        source-address: MGMT
        protocol: tcp
        destination-port: SSH
        priority: 1000
        action: accept
```

```json title="priority.gce"
[
  {
    "allowed": [
      {
        "IPProtocol": "tcp",
        "ports": [
          "22"
        ]
      }
    ],
    "description": "Allow SSH from the management network.",
    "direction": "INGRESS",
    "name": "default-allow-ssh",
    "network": "global/networks/default",
    "priority": "1000",
    "sourceRanges": [
      "10.0.0.0/24",
      "192.168.10.0/24"
    ]
  }
]
```

## Known Issues

!!! bug "Known issues"
    * **Exclusions crash with mixed-family address tokens.** If `source-address` (or `destination-address`) holds both IPv4 and IPv6 addresses and the term uses an exclusion, generation fails with `TypeError: … are not of the same version`. This happens even with an `inet` header.
