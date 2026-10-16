# SONiC

Renders ACL sets for [SONiC](https://sonicfoundation.dev/) switches as JSON. The sonic generator is built on the [OpenConfig](openconfig.md) generator and supports exactly the same header options, tokens and actions. The only difference is how `tcp-established` is rendered.

!!! info "Tables included from OpenConfig"
    The shared tables under Term Format and Actions are included from the [OpenConfig](openconfig.md) page, so they always match it. Anything that differs on SONiC is called out on this page.

## Header Format

The SONiC header designation has the following format:

```yaml
targets:
    sonic: [filter name] {inet|inet6|mixed}
```

All options work as described for [OpenConfig](openconfig.md#header-format).

## Term Format

For common keys see the [Common](common.md) page. Like OpenConfig, SONiC does **not** support `platform`, `platform-exclude` or `verbatim` (they raise an error). The following tokens are the same as for [OpenConfig](openconfig.md#term-format):

--8<-- "docs/reference/generators/openconfig.md:term-format"

## Actions

Same as [OpenConfig](openconfig.md#actions):

--8<-- "docs/reference/generators/openconfig.md:actions"

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `tcp-established` | Match established TCP sessions. | `option: tcp-established` | Renders `"tcp-session-established": true` under `transport.config`, instead of OpenConfig's `"detail-mode": "BUILTIN", "builtin-detail": "TCP_ESTABLISHED"`. The term's `protocol` must be exactly `tcp`, otherwise `TcpEstablishedWithNonTcpError` is raised. |

For an example, see [`tcp-established`](#tcp-established).

## Output

Each policy file renders to one file with the same name and a `.oacl` extension, so `sample.yaml` renders `sample.oacl`. OpenConfig uses the same extension, so rendering one policy for both `openconfig` and `sonic` writes both to the same file.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        sonic: edge-inbound inet
--8<-- "docs/reference/generators.md:sample-terms"
```

```json title="sample.oacl"
[
  {
    "acl-entries": {
      "acl-entry": [
        {
          "actions": {
            "config": {
              "forwarding-action": "ACCEPT"
            }
          },
          "ipv4": {
            "config": {
              "protocol": 6,
              "source-address": "10.0.0.0/24"
            }
          },
          "sequence-id": 5,
          "transport": {
            "config": {
              "destination-port": 22
            }
          }
        },
        {
          "actions": {
            "config": {
              "forwarding-action": "ACCEPT"
            }
          },
          "ipv4": {
            "config": {
              "protocol": 6,
              "source-address": "192.168.10.0/24"
            }
          },
          "sequence-id": 10,
          "transport": {
            "config": {
              "destination-port": 22
            }
          }
        },
        {
          "actions": {
            "config": {
              "forwarding-action": "DROP"
            }
          },
          "sequence-id": 15
        }
      ]
    },
    "config": {
      "name": "edge-inbound",
      "type": "ACL_IPV4"
    },
    "name": "edge-inbound",
    "type": "ACL_IPV4"
  }
]
```

#### `tcp-established`

A term with `option: tcp-established`. SONiC renders it as `tcp-session-established` (see [Option](#option)).

```yaml title="established.yaml"
filters:
  - header:
      targets:
        sonic: edge inet
    terms:
      - name: established
        protocol: tcp
        option: tcp-established
        action: accept
```

```json title="established.oacl"
[
  {
    "acl-entries": {
      "acl-entry": [
        {
          "actions": {
            "config": {
              "forwarding-action": "ACCEPT"
            }
          },
          "ipv4": {
            "config": {
              "protocol": 6
            }
          },
          "sequence-id": 5,
          "transport": {
            "config": {
              "tcp-session-established": true
            }
          }
        }
      ]
    },
    "config": {
      "name": "edge",
      "type": "ACL_IPV4"
    },
    "name": "edge",
    "type": "ACL_IPV4"
  }
]
```

## Known Issues

SONiC has the same known issues as [OpenConfig](openconfig.md#known-issues).
