# PaloAltoFW

Renders a Palo Alto Networks firewall configuration (security rules, address objects, services and custom applications) as XML.

## Header Format

The paloalto header designation has the following format:

```yaml
targets:
    paloalto: from-zone [zone name] to-zone [zone name] {inet|inet6|mixed} {addr-obj|no-addr-obj} {unique-term-prefixes}
```

The options are positional: to use `unique-term-prefixes` you must also give the address family and the address-object option.

| Option | Description | Notes |
|---|---|---|
| `from-zone [name]` | Source zone. | Required. Max 31 characters. |
| `to-zone [name]` | Destination zone. | Required. Max 31 characters. |
| `inet` | IPv4 only. | Default. |
| `inet6` | IPv6 only. | |
| `mixed` | IPv4 and IPv6. | |
| `addr-obj` | Use address groups in the rules' source and destination. | Default. |
| `no-addr-obj` | Use network/mask values directly in the rules. | All headers in a policy file must use the same choice. |
| `unique-term-prefixes` | Prefix each rule name with a hash of the from/to zones. | Makes rule names unique across policies. Not cryptographically guaranteed. |

## Term Format

For common keys see the [Common](common.md) page. PaloAltoFW does **not** support `verbatim`. It also reads:

| Token | Description | Example | Notes |
|---|---|---|---|
| `logging` | Log sessions. | `logging: true` | `true`, `syslog` or `local`: `log-end`. `log-both`: `log-start` and `log-end`. `disable`: no logging. |
| `owner`, `timeout` | — | | Accepted, but ignored. |
| `pan-application` | Palo Alto applications to match. | `pan-application: ssl web-browsing` | Predefined applications (<https://applipedia.paloaltonetworks.com/>) or custom application objects. Only allowed with no `protocol`, or with `tcp`/`udp`. See the service table below. |
| `profile-settings` | Security profile group(s) for the rule. | `profile-settings: default-profile` | Rendered as `profile-setting` → `group`. |
| `tags` | Tags to add to the rule. | `tags: production web` | Also added to the global tag list. |

* `icmp-type` is rendered as a custom application using `ident-by-icmp-type`.
* Rule names are at most 63 characters.

**Service setting with `pan-application`:**

| Term has | Rule service |
|---|---|
| No `protocol` | `application-default` |
| `protocol: tcp`/`udp`, no ports | Custom service objects for the protocols and all ports (0-65535) |
| `protocol: tcp`/`udp` with ports | Custom service objects for the protocols and ports |

## Actions

| Action | Rendered as | Notes |
|---|---|---|
| `accept` | `allow` | |
| `deny` | `deny` | |
| `reject` | `reset-client` | |
| `reject-with-tcp-rst` | `reset-client` | |

## Option

| Option | Description | Example | Notes |
|---|---|---|---|
| `established`, `tcp-established` | — | | The term is skipped with a warning (the firewall is stateful). |

## Output

Each policy file renders to one file with the same name and a `.xml` extension, so `sample.yaml` renders `sample.xml`.

### Example

The [sample policy](index.md#sample-policy) used on every generator page, rendered by `aclgen`. This page adds `icmp-type` to show paloalto-specific tokens.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        paloalto: from-zone trust to-zone untrust
    terms:
      - name: allow-ssh
        comment: "Allow SSH from the management network."
        source-address: MGMT            # 10.0.0.0/24, 192.168.10.0/24
        protocol: tcp
        destination-port: SSH           # 22/tcp
        action: accept
      - name: allow-ping
        protocol: icmp
        icmp-type: echo-request
        action: accept
      - name: default-deny
        action: deny
```

```xml title="sample.xml"
<?xml version="1.0" ?>
<config urldb="paloaltonetworks" version="8.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <application>
            <entry name="icmp-echo-request">
              <category>networking</category>
              <subcategory>ip-protocol</subcategory>
              <technology>network-protocol</technology>
              <description>icmp-echo-request</description>
              <default>
                <ident-by-icmp-type>
                  <type>8</type>
                </ident-by-icmp-type>
              </default>
              <risk>4</risk>
            </entry>
          </application>
          <application-group/>
          <!-- Services -->
          <service>
            <entry name="service-allow-ssh-tcp">
              <protocol>
                <tcp>
                  <port>22</port>
                </tcp>
              </protocol>
            </entry>
          </service>
          <!-- Rules -->
          <rulebase>
            <security>
              <rules>
                <entry name="allow-ssh">
                  <description>Allow SSH from the management network.</description>
                  <to>
                    <member>untrust</member>
                  </to>
                  <from>
                    <member>trust</member>
                  </from>
                  <source>
                    <member>MGMT</member>
                  </source>
                  <destination>
                    <member>any</member>
                  </destination>
                  <service>
                    <member>service-allow-ssh-tcp</member>
                  </service>
                  <action>allow</action>
                  <rule-type>interzone</rule-type>
                  <application>
                    <member>any</member>
                  </application>
                </entry>
                <entry name="allow-ping">
                  <to>
                    <member>untrust</member>
                  </to>
                  <from>
                    <member>trust</member>
                  </from>
                  <source>
                    <member>any-ipv4</member>
                  </source>
                  <destination>
                    <member>any-ipv4</member>
                  </destination>
                  <service>
                    <member>application-default</member>
                  </service>
                  <action>allow</action>
                  <rule-type>interzone</rule-type>
                  <application>
                    <member>icmp-echo-request</member>
                  </application>
                </entry>
                <entry name="default-deny">
                  <to>
                    <member>untrust</member>
                  </to>
                  <from>
                    <member>trust</member>
                  </from>
                  <source>
                    <member>any-ipv4</member>
                  </source>
                  <destination>
                    <member>any-ipv4</member>
                  </destination>
                  <service>
                    <member>any</member>
                  </service>
                  <action>deny</action>
                  <rule-type>interzone</rule-type>
                  <application>
                    <member>any</member>
                  </application>
                </entry>
              </rules>
            </security>
          </rulebase>
          <!-- Address Groups -->
          <address-group>
            <entry name="MGMT">
              <static>
                <member>MGMT_0</member>
                <member>MGMT_1</member>
              </static>
            </entry>
          </address-group>
          <!-- Addresses -->
          <address>
            <entry name="MGMT_0">
              <description>MGMT_0</description>
              <ip-netmask>10.0.0.0/24</ip-netmask>
            </entry>
            <entry name="MGMT_1">
              <description>MGMT_1</description>
              <ip-netmask>192.168.10.0/24</ip-netmask>
            </entry>
            <entry name="any-ipv4">
              <description>Object to match all IPv4 addresses; negate to match all IPv6 addresses.</description>
              <ip-range>0.0.0.0-255.255.255.255</ip-range>
            </entry>
          </address>
          <tag/>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
```
