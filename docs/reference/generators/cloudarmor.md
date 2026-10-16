# Cloud Armor

Renders Google Cloud Armor security policy rules as JSON. Cloud Armor rules here only match on the client's source IP address.

## Header Format

The Cloud Armor header designation has the following format:

```yaml
targets:
    cloudarmor: {inet|inet6|mixed} {noverbose}
```

There is no filter name. All filters in a policy file go into one list of rules.

| Option | Description | Notes |
|---|---|---|
| `inet` | IPv4 only. | Default, with a warning if no family is given. |
| `inet6` | IPv6 only. | |
| `mixed` | IPv4 and IPv6 in the same rule. | |
| `noverbose` | Leave out rule descriptions. | |

The address family must be the first option after `noverbose` is removed. Any other options after it are ignored.

## Term Format

For common keys see the [Common](common.md) page. Cloud Armor only supports `name`, `comment`, `source-address` and `action`. Every other common token raises an error, including `destination-address`, `protocol`, the ports, exclusions, `option`, `expiration`, `platform`, `platform-exclude` and `verbatim`.

| Token | How it's rendered | Notes |
|---|---|---|
| `comment` | `description` | Cut to 64 characters. Left out with `noverbose`. |
| `name` | — | Not rendered. Use `comment` to identify the rule. |
| `source-address` | `match.config.srcIpRanges` | Only addresses of the header's family. With no `source-address`, the rule matches everything (`"*"`). So does a term with no addresses of the header's family; see [Known Issues](#known-issues). |

* Rules are numbered by priority starting at 1, in term order.
* A term with more than 5 source ranges is split into several rules with consecutive priorities, and the descriptions get a `[1/3]`, `[2/3]`, … suffix.
* More than 200 rules in total raises `ExceededMaxTermsError`, and more than 190 logs a warning.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `allow` | |
| `deny` | `deny(404)` | Clients get an HTTP 404. |

## Output

Each policy file renders to one file with the same name and a `.gca` extension, so `sample.yaml` renders `sample.gca`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`. Cloud Armor only matches on source addresses, so `protocol` and `destination-port` are left out.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        cloudarmor: inet
    terms:
      - name: allow-ssh
        comment: "Allow SSH from the management network."
        source-address: MGMT            # 10.0.0.0/24, 192.168.10.0/24
        action: accept
      - name: default-deny
        action: deny
```

```json title="sample.gca"
[
  {
    "action": "allow",
    "description": "Allow SSH from the management network.",
    "match": {
      "config": {
        "srcIpRanges": [
          "10.0.0.0/24",
          "192.168.10.0/24"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 1
  },
  {
    "action": "deny(404)",
    "match": {
      "config": {
        "srcIpRanges": [
          "*"
        ]
      },
      "versionedExpr": "SRC_IPS_V1"
    },
    "preview": false,
    "priority": 2
  }
]
```

## Known Issues

!!! bug "Known issues"
    * **A term with no addresses of the header's family matches everything.** For example, in an `inet` filter, a term whose `source-address` is IPv6-only renders `"srcIpRanges": ["*"]`. Aerleon should skip the term instead.
    * **Priorities restart at 1 for each filter**, but all filters go into the same rule list, so a policy file with two filters renders rules with the same priority.
