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

For common keys see the [Common](common.md) page. NVUE does **not** support `source-exclude`, `destination-exclude` or `verbatim`. It also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `logging` | Log matching packets. | `logging: true` | Adds `log` to the rule's action. |

* Rules are numbered 10, 20, 30, …
* `comment` becomes the rule's `remark`.
* Terms with no addresses in the ACL's family are skipped.
* Port ranges are rendered as `start:end`.

??? example "A term and its output"
    With header `nvueapi: myacl ipv4`:

    ```yaml
    - name: allow-ssh
      source-address: INTERNAL
      protocol: tcp
      destination-port: SSH
      action: accept
    ```

    ```json
    {
      "acl": {
        "myacl": {
          "type": "ipv4",
          "rule": {
            "10": {
              "action": {"permit": {}},
              "match": {"ip": {"protocol": "tcp", "source-ip": "10.0.0.0/8", "dest-port": "22"}}
            }
          }
        }
      }
    }
    ```

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

## Known Issues

!!! bug "Known issues"
    * **The address family is required.** Leaving out the address family crashes with `IndexError`, even though IPv4 is meant to be the default. Always give `ipv4` or `ipv6`.
    * **`expiration` crashes the generator.** Any term with an `expiration` date fails with `TypeError: '<=' not supported between instances of 'datetime.date' and 'int'`.
