# YAML Policy Files

## Usage

Aerleon supports policy files written in YAML as well as the traditional .pol
format. It will search for files named \*.pol.yaml in the same places it would
search for \*.pol files.

Include files can also be written in YAML. Cross-format includes are not
allowed. A YAML file can include files named \*.pol-include.yaml while a .pol
file can include files named \*.inc .

YAML files are loaded in PyYAML's "safe" mode.

## General structure

```
filters:
  - header:
      comment: |
        Denies all traffic to internal IPs except established tcp replies.
        Also denies access to certain public allocations.
      targets:
        cisco: allowtointernet
    terms:
      - name: accept-dhcp
        comment: "Optional - allow forwarding of DHCP requests."
        destination-port: DHCP
        protocol: udp
        action: accept
```

Policy files written in YAML follow the same domain model as .pol files. Each
policy file contains one or more filters. Each filter contains a header with a
list of targets and a term list implementing the policy filter.

## Differences from .pol

This section assumes some familiarity with the YAML file format.

Policy files written in YAML look similar to .pol files. Most value expressions
(right hand side values) accept a single word or a space-separated list of words
and that continues to the the case in YAML files.

```
      - name: accept-icmp
        protocol: icmp
        counter: icmp-loopback
        icmp-type: echo-request echo-reply
        action: accept
```

```
term accept-icmp {
    protocol:: icmp
    counter:: icmp-loopback
    icmp-type:: echo-request echo-reply
    action:: accept
}
```

### Repeated-Key Fields

YAML cannot accept repeated keys. Fields that would have been expressed through
repeated keys in a .pol file must be expressed differently in YAML.

### Comments

Multi-line comments can be expressed as multi-line strings in YAML.

```
      comment: |
        Denies all traffic to internal IPs except established tcp replies.
        Also denies access to certain public allocations.
```

```
  comment:: Denies all traffic to internal IPs except established tcp replies.
  comment:: Also denies access to certain public allocations.
```

### Verbatim blocks

Verbatim blocks should be organized as a mapping from target name to a single
string. Multi-line YAML strings can be used to represent a multi-line verbatim
block.

```
      verbatim:
        aruba: |
            aruba uses some odd ACL format
            which is kinda like, weird
        cisco: But Cisco's format is Ok, tho.
        juniper: And Juniper's is the best!
```

```
  verbatim:: aruba "aruba uses some odd ACL format"
  verbatim:: aruba "which is kinda like, weird"
  verbatim:: aruba ""
  verbatim:: cisco "But Cisco's format is Ok, tho."
  verbatim:: juniper "And Juniper's is the best!"
```

### Targets

The list of targets in a filter header should be organized as a mapping from
target name to an options list. An empty option list is allowed.

```
      targets:
        paloalto: from-zone internal to-zone external
        srx: from-zone internal to-zone external
```

```
  target:: paloalto from-zone internal to-zone external
  target:: srx from-zone internal to-zone external
```

### Tuple Representation

Target resources should be expressed as a YAML list of strings containing tuples
or a string containing a single tuple. Note that YAML does allow a list on a
single line using square brackets, but the contents must be clearly marked as
strings.

```
      target-resources: (proj1,vpc1)
--- or ---
      target-resources:
        - (proj1,vpc1)
        - (proj2,vpc2)
--- or ---
      target-resources: ["(proj1,vpc1)", "(proj1,vpc1)"]
```

```
  target-resources:: [(proj1,vpc1), (proj1,vpc1)]
--- or ---
  target-resources:: (proj1,vpc1)
  target-resources:: (proj1,vpc1)
```

### Flexible-Match-Range

Flexible match range criteria should be expressed as a mapping from attribute
name to value.

```
  flexible-match-range:
    bit-length: 8
    range: 0x08
    match-start: payload
    byte-offset: 16
    bit-offset: 7
```

```
  flexible-match-range:: bit-length 8
  flexible-match-range:: range 0x08
  flexible-match-range:: match-start payload
  flexible-match-range:: byte-offset 16
  flexible-match-range:: bit-offset 7
```

### Alternative Representation: YAML Value Types

Values should mostly be expressed as YAML strings. Support for values expressed
using non-string YAML value types is limited. Best practice would be to use
string representations unless a non-string value type is explicitly supported in
the file spec.

Authors unfamiliar with YAML files should be aware that YAML treats unquoted
strings with lower precedence than other value types, meaning YAML will
determine the type of a value expression dynamically based on the content of the
value.

```
- "tcp"         # string
- "1"           # string
- "true"        # string
- "2001-01-31"  # string
- tcp           # string (unquoted)
- 1             # integer
- true          # boolean
- 2001-01-31    # date
```

### Alternative Representation: Lists

Any value that can be expressed as space-separated list of words may also be
expressed as a YAML list of words. This representation is more canonical and may
be easier to construct during programmatic assembly of YAML.

```
        icmp-type: echo-request echo-reply
        protocol: tcp udp
--- equivalent to ---
        icmp-type:
          - echo-request
          - echo-reply
        protocol:
          - tcp
          - udp
```

### Includes

Place a term item in the list of terms with a key "include" containing a file
path to include that file. All terms found in the include file will be inserted
into the terms list. The include file will be resolved relative to the base
directory. The include file name must match \*.pol-include.yaml.

```
# example.pol.yaml
filters:
- header:
# ...
  terms:
  - name: deny-to-reserved
    destination-address: RESERVED
    action: deny
  - include: include_1.pol-include.yaml
  - name: allow-web-to-mail
    source-address: WEB_SERVERS
    destination-address: MAIL_SERVERS
    action: accept
```

```
# include_1.pol-include.yaml
terms:
- name: deny-to-bogons
  destination-address: RESERVED
  action: deny
```

### YAML Aliases and Anchors

YAML supports in-file code reuse through aliases and anchors. This is not an
Aerleon-specific feature; YAML automatically resolves aliases as part of the
loading process.

# YAML Policy File Spec

| File Structure          |                                                           |
| ----------------------- | --------------------------------------------------------- |
| filters                 | Required, list of filters                                 |
| filter[].header.targets | Required, see [Configuring Targets](#configuring-targets) |
| filter[].header.\*      | See [Field Reference](#full-field-syntax-reference)       |
| filter[].terms          | Required, list of terms                                   |
| filter[].terms[].name   | Required, see [Configuring Terms](#configuring-terms)     |
| filter[].terms[].\*     | See [Field Reference](#full-field-syntax-reference)       |

## Configuring Targets

`filter[].header.targets` must be present in every filter. It must contain a
mapping from a target name to a list of words configuring the target generator.
The list of words may be empty.

A platform-specific ACL will be generated from this filter for each target in
this mapping. If multiple filters are present in this policy file, each
platform's generated configuration file will contain only the filters that
included that platform as a target.

## Configuring Terms

`filter[].terms` must be present in every filter. It must contain a non-empty
list of mappings (Terms).

A Term containing a single key, `include`, will be replaced by all Terms found
in the named file. See section [Includes](#includes) above.

A Term must contain a `name` field naming the term.

## Full Field Syntax Reference

- TODO - flesh out targets
- TODO - flesh out action spec, options list, etc
- TODO - double check for platform-specific keys or value constraints

| Path                              | Platform   | Value Type                   | Allowed Syntax                                                                                             |
| --------------------------------- | ---------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------- |
| header.targets                    |            | mapping                      | `"[TARGET_NAME]": "[PLATFORM_OPTION] ..."`                                                                 |
| header.apply-groups               | SRX        | list of words                | `apply-groups: "[filter name] [filter name]..."`                                                           |
| header.apply-groups               | SRX        | list of words                | `apply-groups: ["filter name", ...]`                                                                       |
| header.apply-groups-except        | SRX        | list of words                | `apply-groups-except: "[filter name] [filter name]..."`                                                    |
| header.apply-groups-except        | SRX        | list of words                | `apply-groups-except: ["filter name", ...]`                                                                |
| header.comment                    |            | any string                   | `comment: "comment body"`                                                                                  |
| terms[].name                      |            | word                         | `name: "[term-name]"`                                                                                      |
| terms[].action                    |            | word                         | `action: "[ACTION] ..."`                                                                                   |
| terms[].address                   |            | list of words                | `address: "[IP \| CIDR \| NAME] ..."`                                                                      |
| terms[].address                   |            | list of words                | `address: ["[IP \| CIDR \| NAME]", ...]`                                                                   |
| terms[].address-exclude           |            | list of words                | `address-exclude: "[IP \| CIDR \| NAME] ..."`                                                              |
| terms[].address-exclude           |            | list of words                | `address-exclude: ["[IP \| CIDR \| NAME]", ...]`                                                           |
| terms[].restrict-address-family   | Cisco      | word                         | `restrict-address-family: "{inet \| inet6}"`                                                               |
| terms[].restrict-address-family   | Juniper    | word                         | `restrict-address-family: "{inet \| inet6}"`                                                               |
| terms[].comment                   |            | any string                   | `comment: "comment body"`                                                                                  |
| terms[].counter                   |            | word                         | `counter: "[COUNTER_NAME]"`                                                                                |
| terms[].expiration                |            | date                         | `expiration: "YYYY-MM-DD"`                                                                                 |
| terms[].expiration                |            | date                         | `expiration: YYYY-MM-DD`                                                                                   |
| terms[].destination-address       |            | list of words                | `destination-address: "[IP \| CIDR \| NAME] ..."`                                                          |
| terms[].destination-address       |            | list of words                | `destination-address: ["[IP \| CIDR \| NAME]", ...]`                                                       |
| terms[].destination-exclude       |            | list of words                | `destination-exclude: "[IP \| CIDR \| NAME] ..."`                                                          |
| terms[].destination-exclude       |            | list of words                | `destination-exclude: ["[IP \| CIDR \| NAME]", ...]`                                                       |
| terms[].destination-port          |            | list of words                | `destination-port: "[PORT_NUMBER \| NAME] ..."`                                                            |
| terms[].destination-port          |            | list of words                | `destination-port: ["[PORT_NUMBER \| NAME]", ...]`                                                         |
| terms[].destination-prefix        |            | list of words                | `destination-prefix: "[IP \| CIDR \| NAME] ..."`                                                           |
| terms[].destination-prefix        |            | list of words                | `destination-prefix: ["[IP \| CIDR \| NAME]", ...]`                                                        |
| terms[].destination-prefix-except |            | list of words                | `destination-prefix-except: "[IP \| CIDR \| NAME] ..."`                                                    |
| terms[].destination-prefix-except |            | list of words                | `destination-prefix-except: ["[IP \| CIDR \| NAME]", ...]`                                                 |
| terms[].destination-zone          |            | list of words                | `destination-zone: ["[ZONE]", ...]`                                                                        |
| terms[].destination-zone          |            | list of words                | `destination-zone: ["[ZONE]", ...]`                                                                        |
| terms[].destination-tag           |            | list of words                | `destination-tag: ["[TAG]", ...]`                                                                          |
| terms[].destination-tag           |            | list of words                | `destination-tag: ["[TAG]", ...]`                                                                          |
| terms[].destination-interface     |            | word                         | `destination-interface: "[INTERFACE_NAME]"`                                                                |
| terms[].filter-name               |            | word                         | `filter-name: "[FILTER_NAME]"`                                                                             |
| terms[].forwarding-class          |            | list of words                | `forwarding-class: "[TRAFFIC_CLASS] ..."`                                                                  |
| terms[].forwarding-class          |            | list of words                | `forwarding-class: ["[TRAFFIC_CLASS]", ...]`                                                               |
| terms[].forwarding-class-except   |            | list of words                | `forwarding-class-except: "[TRAFFIC_CLASS] ..."`                                                           |
| terms[].forwarding-class-except   |            | list of words                | `forwarding-class-except: ["[TRAFFIC_CLASS]", ...]`                                                        |
| terms[].logging                   |            | word                         | `logging: "{disable \| local \| log-both \| syslog}"`                                                      |
| terms[].logging                   |            | word                         | `logging: "{true \| false \| True \| False}"`                                                              |
| terms[].logging                   |            | boolean                      | `logging: true \| false"`                                                                                  |
| terms[].log-limit                 |            | rate                         | `log-limit: "[FREQUENCY]/[PERIOD]"`                                                                        |
| terms[].log-name                  |            | any string                   | `log-name: "[LOG_MESSAGE_PREFIX]"`                                                                         |
| terms[].loss-priority             |            | word                         | `loss-priority: "[LOSS_PRIORITY]"`                                                                         |
| terms[].option                    |            | list of words                | `option: "[OPTION] ..."`<br>`option: ["[OPTION]", ...]`                                                    |
| terms[].owner                     |            | word                         | `owner: "[OWNER]"`                                                                                         |
| terms[].policer                   |            | word                         | `policer: "[POLICER_NAME]"`                                                                                |
| terms[].port                      |            | list of words                | `port: "[PORT_NUMBER \| NAME] ..."`                                                                        |
| terms[].port                      |            | list of words                | `port: ["[PORT_NUMBER \| NAME]", ...]`                                                                     |
| terms[].precedence                |            | list of numbers              | `precedence: "{0-7} ..."`                                                                                  |
| terms[].precedence                |            | list of numbers              | `precedence: {0-7}`                                                                                        |
| terms[].precedence                |            | list of numbers              | `precedence: ["{0-7}", ...]`                                                                               |
| terms[].precedence                |            | list of numbers              | `precedence: [{0-7}, ...]`                                                                                 |
| terms[].protocol                  |            | list of numbers or words     | `protocol: "[PROTOCOL_NAME \| NUMBER] ..."`                                                                |
| terms[].protocol                  |            | list of numbers or words     | `protocol: ["[PROTOCOL_NAME \| NUMBER]" \| [NUMBER], ...]`                                                 |
| terms[].protocol-except           |            | list of numbers or words     | `protocol-except: "[PROTOCOL_NAME \| NUMBER] ..."`                                                         |
| terms[].protocol-except           |            | list of numbers or words     | `protocol-except: ["[PROTOCOL_NAME \| NUMBER]" \| [NUMBER], ...]`                                          |
| terms[].qos                       | Juniper    | word                         | `qos: "[TRAFFIC_CLASS]"`                                                                                   |
| terms[].pan-application           | PaloAltoFW | list of words                | `pan-application: "[APPLICATION_NAME] ..."`                                                                |
| terms[].pan-application           | PaloAltoFW | list of words                | `pan-application: ["[APPLICATION_NAME]", ...]`                                                             |
| terms[].routing-instance          |            | word                         | `routing-instance: "[ROUTING_INSTANCE_NAME]"`                                                              |
| terms[].source-address            |            | list of words                | `source-address: "[IP \| CIDR \| NAME] ..."`                                                               |
| terms[].source-address            |            | list of words                | `source-address: ["[IP \| CIDR \| NAME]", ...]`                                                            |
| terms[].source-exclude            |            | list of words                | `source-exclude: "[IP \| CIDR \| NAME] ..."`                                                               |
| terms[].source-exclude            |            | list of words                | `source-exclude: ["[IP \| CIDR \| NAME]", ...]`                                                            |
| terms[].source-port               |            | list of words                | `source-port: "[PORT_NUMBER \| NAME] ..."`                                                                 |
| terms[].source-port               |            | list of words                | `source-port: ["[PORT_NUMBER \| NAME]", ...]`                                                              |
| terms[].source-prefix             |            | list of words                | `source-prefix: "[IP \| CIDR \| NAME] ..."`                                                                |
| terms[].source-prefix             |            | list of words                | `source-prefix: ["[IP \| CIDR \| NAME]", ...]`                                                             |
| terms[].source-prefix-except      |            | list of words                | `source-prefix-except: "[IP \| CIDR \| NAME] ..."`                                                         |
| terms[].source-prefix-except      |            | list of words                | `source-prefix-except: ["[IP \| CIDR \| NAME]", ...]`                                                      |
| terms[].source-zone               |            | list of words                | `source-zone: ["[ZONE]", ...]`                                                                             |
| terms[].source-zone               |            | list of words                | `source-zone: ["[ZONE]", ...]`                                                                             |
| terms[].source-tag                |            | list of words                | `source-tag: ["[TAG]", ...]`                                                                               |
| terms[].source-tag                |            | list of words                | `source-tag: ["[TAG]", ...]`                                                                               |
| terms[].source-interface          |            | word                         | `source-interface: "[INTERFACE_NAME]"`                                                                     |
| terms[].ttl                       |            | number                       | `ttl: "[TTL]"`                                                                                             |
| terms[].ttl                       |            | number                       | `ttl: [TTL]`                                                                                               |
| terms[].verbatim                  |            | mapping from word to strings | `verbatim: {"[TARGET_NAME]": "Verbatim content"}`                                                          |
| terms[].packet-length             |            | number range                 | `packet-length: "[MIN]-[MAX]"`                                                                             |
| terms[].packet-length             |            | number                       | `packet-length: "[MAX]"`                                                                                   |
| terms[].packet-length             |            | number                       | `packet-length: [MAX]`                                                                                     |
| terms[].fragment-offset           |            | number range                 | `fragment-offset: "[START]-[END]"`                                                                         |
| terms[].fragment-offset           |            | number                       | `fragment-offset: "[END]"`                                                                                 |
| terms[].fragment-offset           |            | number                       | `fragment-offset: [END]`                                                                                   |
| terms[].hop-limit                 |            | number range                 | `hop-limit: "[MIN]-[MAX]"`                                                                                 |
| terms[].hop-limit                 |            | number                       | `hop-limit: "[MAX]"`                                                                                       |
| terms[].hop-limit                 |            | number                       | `hop-limit: [MAX]`                                                                                         |
| terms[].icmp-type                 |            | list of words                | `icmp-type: "[ICMP_TYPE] ..."`<br>`icmp-type: ["[ICMP_TYPE]", ...]`<br>See [ICMP_TYPE](#icmp_type).        |
| terms[].icmp-code                 |            | list of numbers              | `icmp-code: "[CODE] ..."`                                                                                  |
| terms[].icmp-code                 |            | list of numbers              | `icmp-code: ["[CODE]", ...]`                                                                               |
| terms[].icmp-code                 |            | list of numbers              | `icmp-code: [[CODE], ...]`                                                                                 |
| terms[].icmp-code                 |            | number                       | `icmp-code: "[CODE]"`                                                                                      |
| terms[].icmp-code                 |            | number                       | `icmp-code: [CODE]`                                                                                        |
| terms[].ether-type                |            | list of words                | `ether-type: "[ETHERNET_TYPE] ..."`                                                                        |
| terms[].ether-type                |            | list of words                | `ether-type: ["[ETHERNET_TYPE]", ...]`                                                                     |
| terms[].traffic-class-count       |            | word                         | `traffic-class-count: "[COUNTER_NAME]"`                                                                    |
| terms[].traffic-type              | Juniper    | list of words                | `traffic-type: "[TRAFFIC_TYPE] ..."`                                                                       |
| terms[].traffic-type              | Juniper    | list of words                | `traffic-type: ["[TRAFFIC_TYPE]", ...]`                                                                    |
| terms[].dscp-set                  | Juniper    | DSCP traffic class           | `dscp-set: "[DSCP]"`                                                                                       |
| terms[].dscp-match                | Juniper    | DSCP traffic class range     | `dscp-match: "[DSCP]-[DSCP]"`                                                                              |
| terms[].dscp-except               | Juniper    | DSCP traffic class range     | `dscp-except: "[DSCP]-[DSCP]"`                                                                             |
| terms[].next-ip                   |            | word                         | `next-ip: "[NEXT_IP]"`                                                                                     |
| terms[].flexible-match-range      | Juniper    | mapping                      | `flexible-match-range: {"[FLEX_MATCH_ATTR]": [VALUE]}`<br>See [Flex Match Values](#flexible-match-values). |
| terms[].encapsulate               | Juniper    | word                         | `encapsulate: "[TEMPLATE_NAME]"`                                                                           |
| terms[].port-mirror               | Juniper    | word                         | `port-mirror: "{true}"`                                                                                    |
| terms[].port-mirror               | Juniper    | boolean                      | `port-mirror: true`                                                                                        |
| terms[].vpn                       | Juniper    | mapping                      | `vpn: {"name": "[VPN_NAME]", ["policy"]: "[POLICY_NAME]"}`                                                 |
| terms[].priority                  | GCE        | number                       | `priority: "[NUMBER]"`                                                                                     |
| terms[].priority                  | GCE        | number                       | `priority: [NUMBER]`                                                                                       |
| terms[].platform                  |            | list of words                | `platform: "[TARGET_NAME] ..."`                                                                            |
| terms[].platform                  |            | list of words                | `platform: ["[TARGET_NAME]", ...]`                                                                         |
| terms[].platform-exclude          |            | list of words                | `platform-exclude: "[TARGET_NAME] ..."`                                                                    |
| terms[].platform-exclude          |            | list of words                | `platform-exclude: ["[TARGET_NAME]", ...]`                                                                 |
| terms[].target-resources          | GCP        | list of tuples               | `target-resources: ["([PROJECT_NAME], [NETWORK_NAME])", ...]`                                              |
| terms[].timeout                   |            | number                       | `timeout: "[NUMBER]"`                                                                                      |

## Value Types

- "word": A "word" is a space-free string consisting of unicode word characters
  plus `-` `_` `+` `.` `@` `/`. A word may only start with a unicode word
  character.
- "number": A "number" is a space-free string consisting of only numeric digits.
  YAML integers may be used.
- "date": A "date" is a space-free string of the format "YYYY-MM-DD". A YAML
  date may be used.
- "hex": A "hex" value is a space-free string starting with "0x" followed by one
  or more hexadecimal digits (0-9 plus a-f).
- "number range": A "number range" is a string containing two numbers separated
  by the character `-`. Number ranges are not necessarily space-free.
- "rate": A "rate" value is a string containing a number (the frequency), the
  character `/`, and a word describing the period (e.g. "hour"). Rate values are
  not necessarily space-free.
- "DSCP traffic class": A space-free DSCP traffic class name. See [DSCP](#dscp)
  for details.
- "DSCP traffic class range": A range of DSCP traffic classes containing two
  DSCP traffic classes separated by the character `-` Not necessarily
  space-free.
- "space-separated list of words": Since words are space-free, a list of words
  may be unambiguously expressed as a string containing one or more words
  separated by spaces. A YAML list containing one word per entry may be used.
- "any string": Any string value.

## ICMP_TYPE

The following options are allowed for field icmp-type:

### IPv4

- echo-reply
- unreachable
- source-quench
- redirect
- alternate-address
- echo-request
- router-advertisement
- router-solicitation
- time-exceeded
- parameter-problem
- timestamp-request
- timestamp-reply
- information-request
- information-reply
- mask-request
- mask-reply
- conversion-error
- mobile-redirect

### IPv6

- destination-unreachable
- packet-too-big
- time-exceeded
- parameter-problem
- echo-request
- echo-reply
- multicast-listener-query
- multicast-listener-report
- multicast-listener-done
- router-solicit
- router-advertisement
- neighbor-solicit
- neighbor-advertisement
- redirect-message
- router-renumbering
- icmp-node-information-query
- icmp-node-information-response
- inverse-neighbor-discovery-solicitation
- inverse-neighbor-discovery-advertisement
- version-2-multicast-listener-report
- home-agent-address-discovery-request
- home-agent-address-discovery-reply
- mobile-prefix-solicitation
- mobile-prefix-advertisement
- certification-path-solicitation
- certification-path-advertisement
- multicast-router-advertisement
- multicast-router-solicitation
- multicast-router-termination

## DSCP

The following options are allowed for DSCP traffic classes:

- A 6-bit DSCP code point, e.g. “b010011”.
- An Assured Forwarding class, e.g. “af23”.
- A Class Selector class, e.g. “cf4”.
- The Expedited Forwarding class, “ef”.
- The class “be”.
- An integer value.

## Flexible Match Values
