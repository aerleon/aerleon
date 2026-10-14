# SONiC

Renders ACL sets for [SONiC](https://sonicfoundation.dev/) switches as JSON. The sonic generator is built on the [OpenConfig](openconfig.md) generator and supports exactly the same header options, tokens, actions and options, including the known issues. See the OpenConfig tables.

## Header Format

```yaml
targets:
    sonic: [filter name] {inet|inet6|mixed}
```

All options work as described for [OpenConfig](openconfig.md#header-format).

## Differences from OpenConfig

| Area | OpenConfig | SONiC |
|---|---|---|
| `option: tcp-established` | `"detail-mode": "BUILTIN", "builtin-detail": "TCP_ESTABLISHED"` | `"tcp-session-established": true` |

The file suffix is `.oacl` for both, so rendering the same policy for `openconfig` and `sonic` writes both to the same output file.

??? example "`tcp-established` and its output"
    With header `sonic: edge inet`:

    ```yaml
    - name: established
      protocol: tcp
      option: tcp-established
      action: accept
    ```

    ```json
    {
      "actions": {"config": {"forwarding-action": "ACCEPT"}},
      "ipv4": {"config": {"protocol": 6}},
      "sequence-id": 5,
      "transport": {"config": {"tcp-session-established": true}}
    }
    ```

## Output

Each policy file renders to one file with the same name and a `.oacl` extension, so `sample.yaml` renders `sample.oacl`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        sonic: edge-inbound inet
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

## Known Issues

SONiC has the same known issues as [OpenConfig](openconfig.md#known-issues).
