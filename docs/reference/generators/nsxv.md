# NSXv

Renders a VMware NSX-V distributed firewall section as XML.

## Header Format

```yaml
targets:
    nsxv: [section name] [inet|inet6|mixed] {section id} {securitygroup [securitygroupId]}
```

| Option | Description | Notes |
|---|---|---|
| `section name` | Name of the firewall section. | Required. |
| `inet`, `inet6`, `mixed` | Address family to render. | Required. `mixed` renders a single term with both families. |
| `section id` | ID of an existing section to update. | Optional. Without it, a warning is logged that a new section will be created. |
| `securitygroup [id]` | Apply the rules to this security group (`appliedTo`). | Optional. The ID is required if `securitygroup` is given. |

## Term Format

### Common tokens

These tokens are included from the _[Common](common.md)_ page.

!!! warning "Not supported on NSXv"
    NSXv doesn't support `option` (except as described below) or `verbatim`. A term that uses any of them raises an error.

--8<-- "docs/reference/generators/common.md:common-tokens"

### NSXv tokens

NSXv also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `logging` | Log matching traffic. | `logging: true` | Sets `logged="true"` on the rule. |

* `comment` becomes the rule's `<notes>`.
* Exclusions are applied before rendering: the remaining address space is written out as a list of CIDRs, which can be long.
* ICMP types are rendered as `<subProtocol>`.

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `allow` | |
| `deny` | `deny` | |
| `reject` | `reject` | |
| `reject-with-tcp-rst` | `reject` | TCP reset is not supported. |

## Option

!!! info "Stateful firewall"
    NSX-V tracks sessions, so return traffic is allowed without a separate term. Terms that use `established` or `tcp-established` are skipped **without** a warning; see _[Known Issues](#known-issues)_. See _[Stateful firewalls](common.md#stateful-firewalls)_.

| Option | Description | Example | Notes |
|---|---|---|---|
| `established`, `tcp-established` | — | | The term is skipped, **without** a warning. |

Any other option raises an `NsxvAclTermError`.

## Output

Each policy file renders to one file with the same name and a `.nsx` extension, so `sample.yaml` renders `sample.nsx`.

### Examples

=== "Sample policy"

    The _[sample policy](../generators.md#sample-policy)_ used on every generator page, rendered by `aclgen`.

    ```yaml title="sample.yaml"
    filters:
      - header:
          targets:
            nsxv: edge-inbound inet
    --8<-- "docs/reference/generators.md:sample-terms"
    ```

    ```xml title="sample.nsx"
    <?xml version="1.0" ?>
    <!--
    $Id:$
    $Date:$
    $Revision:$
    -->
    <section name="edge-inbound">
      <rule logged="false">
        <name>allow-ssh</name>
        <action>allow</action>
        <sources excluded="false">
          <source>
            <type>Ipv4Address</type>
            <value>10.0.0.0/24</value>
          </source>
          <source>
            <type>Ipv4Address</type>
            <value>192.168.10.0/24</value>
          </source>
        </sources>
        <services>
          <service>
            <protocol>6</protocol>
            <destinationPort>22</destinationPort>
          </service>
        </services>
        <notes>Allow SSH from the management network.</notes>
      </rule>
      <rule logged="false">
        <name>default-deny</name>
        <action>deny</action>
      </rule>
    </section>
    ```

## Known Issues

!!! bug "Known issues"
    * **`established` and `tcp-established` terms are dropped silently.** The term is left out of the output with no warning or error, so nothing in the `aclgen` log shows that a rule from the policy is missing.
