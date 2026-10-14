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

## Known Issues

SONiC has the same known issues as [OpenConfig](openconfig.md#known-issues).
