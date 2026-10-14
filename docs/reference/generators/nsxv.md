# NSXv

Renders a VMware NSX-V distributed firewall section as XML.

## Header Format

The nsxv header designation has the following format:

```yaml
targets:
    nsxv: [section name] [inet|inet6|mixed] {section id} {securitygroup [securitygroupId]}
```

| Option | Description | Notes |
|---|---|---|
| `section name` | Name of the firewall section. | Required. |
| `inet`, `inet6`, `mixed` | Address family to render. | Required. `mixed` renders each term once per family. |
| `section id` | ID of an existing section to update. | Optional. Without it, a warning is logged that a new section will be created. |
| `securitygroup [id]` | Apply the rules to this security group (`appliedTo`). | Optional. The ID is required if `securitygroup` is given. |

## Term Format

For common keys see the [Common](common.md) page. NSXv does **not** support `option` (except as below) or `verbatim`. It also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `logging` | Log matching traffic. | `logging: true` | Sets `logged="true"` on the rule. |

* `comment` becomes the rule's `<notes>`.
* Exclusions are applied before rendering: the remaining address space is written out as a list of CIDRs, which can be long.
* ICMP types are rendered as `<subProtocol>`.

??? example "A term and its output"
    With header `nsxv: sec inet`:

    ```yaml
    - name: allow-ssh
      source-address: V4ONLY        # 192.168.0.0/16
      protocol: tcp
      destination-port: SSH
      action: accept
    ```

    ```xml
    <section name="sec">
      <rule logged="false">
        <name>allow-ssh</name>
        <action>allow</action>
        <sources excluded="false">
          <source>
            <type>Ipv4Address</type>
            <value>192.168.0.0/16</value>
          </source>
        </sources>
        <services>
          <service>
            <protocol>6</protocol>
            <destinationPort>22</destinationPort>
          </service>
        </services>
      </rule>
    </section>
    ```

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `allow` | |
| `deny` | `deny` | |
| `reject` | `reject` | |
| `reject-with-tcp-rst` | `reject` | TCP reset is not supported. |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established`, `tcp-established` | — | | The term is skipped, **without** a warning. |

Any other option raises an `NsxvAclTermError`.
