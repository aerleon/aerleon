# NVUE API

Renders JSON configuration for NVIDIA Cumulus Linux switches, in the NVUE (NVIDIA User Experience) REST API format. Like iptables, one rule is created for every combination of source address, destination address, protocol and port.

## Header Format

The NVUE API header designation has the following format:

```yaml
targets:
    nvueapi: [filter name] [ipv4|ipv6]
```

| Option | Description | Notes |
|---|---|---|
| `filter name` | Name of the NVUE ACL. | |
| `ipv4` | IPv4 ACL. | `inet` also works. |
| `ipv6` | IPv6 ACL. | `inet6` also works. |

`mixed` and `mac` ACLs are not supported and raise an error. Use separate IPv4 and IPv6 ACLs. Always give the address family; see [Known Issues](#known-issues).

## Term Format

### Common tokens

These tokens are included from the [Common](common.md) page. NVUE does **not** support `source-exclude`, `destination-exclude` or `verbatim`.

--8<-- "docs/reference/generators/common.md:common-tokens"

### NVUE API tokens

NVUE API also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `logging` | Log matching packets. | `logging: true` | Adds `log` to the rule's action. |

* Rules are numbered 10, 20, 30, …
* `comment` becomes the rule's `remark`.
* Terms with no addresses in the ACL's family are skipped.
* Port ranges are rendered as `start:end`.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `permit` | |
| `deny` | `deny` | |
| `reject` | `deny` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established`, `tcp-established` | Match established TCP connections. | `option: tcp-established` | Adds `tcp: {state: established}`. Only applied to `tcp`; on other protocols it is silently ignored, so the rule is broader than intended. |

Any other option value is accepted but ignored.

## Output

Each policy file renders to one file with the same name and a `.nvueapi.json` extension, so `sample.yaml` renders `sample.nvueapi.json`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        nvueapi: edge-inbound ipv4
--8<-- "docs/reference/generators.md:sample-terms"
```

```json title="sample.nvueapi.json"
{
  "acl": {
    "edge-inbound": {
      "type": "ipv4",
      "rule": {
        "10": {
          "action": {
            "permit": {}
          },
          "remark": "Allow SSH from the management network.",
          "match": {
            "ip": {
              "protocol": "tcp",
              "source-ip": "10.0.0.0/24",
              "dest-port": "22"
            }
          }
        },
        "20": {
          "action": {
            "permit": {}
          },
          "remark": "Allow SSH from the management network.",
          "match": {
            "ip": {
              "protocol": "tcp",
              "source-ip": "192.168.10.0/24",
              "dest-port": "22"
            }
          }
        },
        "30": {
          "action": {
            "deny": {}
          }
        }
      }
    }
  }
}
```

## Known Issues

!!! bug "Known issues"
    * **The address family is required.** Leaving out the address family crashes with `IndexError`, even though IPv4 is meant to be the default. Always give `ipv4` or `ipv6`.
    * **`expiration` crashes the generator.** Any term with an `expiration` date fails with `TypeError: '<=' not supported between instances of 'datetime.date' and 'int'`.
