# NSXt

Renders a VMware NSX-T `SecurityPolicy` (category `Application`) as JSON.

## Header Format

The NSXt header designation has the following format:

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

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `ALLOW` | |
| `deny` | `DROP` | |
| `next` | — | Accepted, but has no mapping (renders `null`). |
| `reject` | `REJECT` | |
| `reject-with-tcp-rst` | `REJECT` | TCP reset is not supported. |

## Output

Each policy file renders to one file with the same name and a `.nsxt` extension, so `sample.yaml` renders `sample.nsxt`.

### Examples

#### Sample policy

The [sample policy](../generators.md#sample-policy) used on every generator page, rendered by `aclgen`.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        nsxt: edge-inbound inet
--8<-- "docs/reference/generators.md:sample-terms"
```

```json title="sample.nsxt"
{
  "rules": [
    {
      "action": "ALLOW",
      "resource_type": "Rule",
      "display_name": "allow-ssh",
      "source_groups": [
        "10.0.0.0/24",
        "192.168.10.0/24"
      ],
      "destination_groups": [
        "ANY"
      ],
      "services": [
        "ANY"
      ],
      "profiles": [
        "ANY"
      ],
      "scope": [
        "ANY"
      ],
      "logged": false,
      "notes": "Allow SSH from the management network.",
      "direction": "IN_OUT",
      "ip_protocol": "IPV4_IPV6",
      "service_entries": [
        {
          "l4_protocol": "TCP",
          "resource_type": "L4PortSetServiceEntry",
          "destination_ports": [
            "22-22"
          ]
        }
      ]
    },
    {
      "action": "DROP",
      "resource_type": "Rule",
      "display_name": "default-deny",
      "source_groups": [
        "ANY"
      ],
      "destination_groups": [
        "ANY"
      ],
      "services": [
        "ANY"
      ],
      "profiles": [
        "ANY"
      ],
      "scope": [
        "ANY"
      ],
      "logged": false,
      "notes": "",
      "direction": "IN_OUT",
      "ip_protocol": "IPV4_IPV6"
    }
  ],
  "resource_type": "SecurityPolicy",
  "display_name": "edge-inbound",
  "id": "edge-inbound",
  "category": "Application",
  "is_default": "false",
  "scope": [
    "ANY"
  ]
}
```

## Known Issues

!!! bug "Known issues"
    * **Some tokens are silently ignored.** These are accepted without an error, but have no effect, which can make a rule **broader** than intended:

      * `source-exclude` and `destination-exclude`: excluded addresses are still allowed.
      * `option` (e.g. `tcp-established`).
      * The header address family: an `inet6` header still renders IPv4 addresses, and vice versa.
      * `verbatim`.
