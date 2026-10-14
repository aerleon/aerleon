# NSXt

Renders a VMware NSX-T `SecurityPolicy` (category `Application`) as JSON.

## Header Format

The nsxt header designation has the following format:

```yaml
targets:
    nsxt: [section name] [inet|inet6|mixed] {section id} {securitygroup [securitygroupId]}
```

| Option | Description | Notes |
|---|---|---|
| `section name` | Name (and ID) of the security policy. | Required. |
| `inet`, `inet6`, `mixed` | Address family. | Required, but **currently ignored** (see known issues). |
| `section id` | ID of the security policy. | Optional. |
| `securitygroup [id]` | Apply the policy to this group. | Optional. A bare name is expanded to `/infra/domains/default/groups/<id>`; a value starting with `/` is used as-is. Defaults to `ANY`. |

Only one nsxt header is allowed per policy file; more raise `NsxtUnsupportedManyPoliciesError`.

## Term Format

For common keys see the [Common](common.md) page. Some common tokens are silently ignored; see [Known Issues](#known-issues). NSXt also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `logging` | Log matching traffic. | `logging: true` | Sets `"logged": true`. |

* Addresses become `source_groups` / `destination_groups`; a term without addresses uses `ANY`.
* Protocols, ports and ICMP types become `service_entries`.
* `comment` becomes the rule's `notes`.
* Every rule has `"direction": "IN_OUT"` and `"ip_protocol": "IPV4_IPV6"`.

??? example "A term and its output"
    With header `nsxt: sec inet`:

    ```yaml
    - name: allow-ssh
      source-address: V4ONLY        # 192.168.0.0/16
      protocol: tcp
      destination-port: SSH
      action: accept
    ```

    ```json
    {
      "rules": [
        {
          "action": "ALLOW",
          "resource_type": "Rule",
          "display_name": "allow-ssh",
          "source_groups": ["192.168.0.0/16"],
          "destination_groups": ["ANY"],
          "services": ["ANY"],
          "profiles": ["ANY"],
          "scope": ["ANY"],
          "logged": false,
          "notes": "",
          "direction": "IN_OUT",
          "ip_protocol": "IPV4_IPV6",
          "service_entries": [
            {"l4_protocol": "TCP", "resource_type": "L4PortSetServiceEntry", "destination_ports": ["22-22"]}
          ]
        }
      ],
      "resource_type": "SecurityPolicy",
      "display_name": "sec",
      "id": "sec",
      "category": "Application",
      "is_default": "false",
      "scope": ["ANY"]
    }
    ```

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `ALLOW` | |
| `deny` | `DROP` | |
| `next` | — | Accepted, but has no mapping (renders `null`). |
| `reject` | `REJECT` | |
| `reject-with-tcp-rst` | `REJECT` | TCP reset is not supported. |

## Known Issues

!!! bug "Known issues"
    * **Some tokens are silently ignored.** These are accepted without an error, but have no effect, which can make a rule **broader** than intended:

      * `source-exclude` and `destination-exclude`: excluded addresses are still allowed.
      * `option` (e.g. `tcp-established`).
      * The header address family: an `inet6` header still renders IPv4 addresses, and vice versa.
      * `verbatim`.
