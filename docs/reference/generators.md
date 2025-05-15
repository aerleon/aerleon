# Generator Reference

## Common

This lists contains all the common keys that are used across all generators (with a few highlighted exceptions).

### Term Format

* _action_: The action to take when matched. See the Actions section for each generator.
* _comment_: A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address_: One or more destination address tokens.
* _destination-port_: One or more service definition tokens.
* _expiration_: Stop rendering this term after specified date in YYYY-MM-DD format. E.g. 2000-12-31.
* _icmp-type_: Specify icmp-type code to match, see [ICMP types](#icmp-types_1) for list of valid arguments (**Not** supported on: **aruba**, **gce**, **k8s**)
* _name_: Name of the term.
* _option_: See platforms supported Options section. (**Not** supported on: **k8s**, **gce**, **windows_advfirewall**, **windows_ipsec**)
* _platform_: one or more target platforms for which this term should ONLY be rendered.
* _platform-exclude_: one or more target platforms for which this term should NEVER be rendered.
* _protocol_: the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _source-address_: one or more source address tokens.
* _source-port_: one or more service definition tokens. (**Note** supported on: **aruba**, **k8s**)

<!--
build_in tokens:
            #'action',
            #'comment',
            #'destination_address',
            'destination_address_exclude',
            #'destination_port',
            #'expiration',
            #'icmp_type',
            'stateless_reply',
            #'name',  # obj attribute, not token
            #'option',
            #'protocol',
            #'platform',
            #'platform_exclude',
            #'source_address',
            'source_address_exclude',
            #'source_port',
            'translated',  # obj attribute, not token
            #'verbatim', -> too many exceptions
-->

***

## Arista Traffic-Policy

### Header Format

The arista_tp header designation has the following format:

```yaml
targets:
    arista_tp: [filter name] {inet|inet6|mixed}
```

* _inet_: specifies that the resulting filter should only render IPv4 addresses.
* _inet6_: specifies the output be for IPv6 only filters.
* _mixed_: specifies output will include both IPv6 and IPv4 filters. (default)

### Filter types

Traffic-policies are dual-address-family by default (i.e.: mixed). A term may be either of type ipv4 or ipv6. If the filter type is defined as mixed (the default), then match/action statements for each address family will be generated.

If the operator wishes to create an ipv4 or ipv6 only filter, the inet and inet6 tokens within the header will be honored and only addresses from the respective address family will be rendered. However, EOS will still, by default, create an 'ipvX-default-all' term for the alternate address family. (see below)

### Term Format

The following tokens are supported:

* for common keys see the [common](#common) section above.

* _counter_:
* _destination-exclude_:
* _destination-prefix_: this should resolve to a configured field-set in traffic-policy format.
* _fragment-offset_:
* _icmp-type_:
* _logging_:
* _packet-length_:
* _source-exclude_:
* _source-prefix_: this should resolve to a configured field-set in traffic-policy format.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _reject_
* _reject-with-tcp-rst_

The fully supported actions are: `accept`, and `deny`. Use of `reject`, or `reject-with-tcp-rst` will result in the generation of deny actions in the rendered traffic policy.

Note, within traffic-policies not configuring an explicit `deny` action (or `reject` variant) will result in an implicit allow for a term.

### Counter

* If counter are specified in a term, a traffic-policy named-counter stanza will be generated in the rendered output.
* Counter names should not contain a (`.`). If a (`.`) is embedded in a counter name it will be replaced w/ a dash (`-`).

### (source|destination)-address-exclude

Currently, (as of Jan-2021), EOS does not support the use of 'except' inline within match statements. If an exclude/except token is used, a traffic-policy field-set will be generated and referenced in the match-term output. This field-set will be named `<direction>-<term.name>` where direction is either **src** or **dst** depending on the direction of the token in use.

If the filter type is mixed, both address-families will have the respective field-sets generated. The field-set for the ipv4 address family will have the field-set generated with no prefix, while the ipv6 field-set will have `ipv6` inserted into the field-set name after the direction and before the name. (form: `src|dst-ipv6-term_name`)

### Option

```yaml
option: {established|tcp-established|initial|rst|first-fragment}
```

* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024-65535 for udp if destination port is not defined.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _initial_
* _rst_
* _first-fragment_: this will be rendered as a _fragment_ match.

### Ports

In EOS traffic-policies, ports can be configured using:

* `source [ all | port-list | field-set ]`
* `destination [ all | port-list | field-set ]`

Currently, all and field-sets are not supported for ports. Only port-lists are supported.

### default-terms

EOS has (2) default terms per traffic-policy, one for each address family:

* `ipv4-default-all`
* `ipv6-default-all`

If there is no match criteria associated with a term _and_ the term name in the policy begins with `default-`, the contents will be rendered into the default terms for the appropriate address family.

### Empty match criteria

If there is no match criteria specified, and the term name does _not_ start with `default-` the term will not be rendered and a warning will be logged.

### Documentation

The official documentation for traffic-policies can be found at the following URL.

* <https://eos.arista.com/eos-4-25-0f/support-for-traffic-policy-on-interfaces/>

***

## Arista

### Header Format

The arista header designation has the following format:

```yaml
targets:
    arista: [filter name] {standard|extended|object-group|inet6} {noverbose}
```

<!--
```text
target:: arista [filter name] {standard|extended|object-group|inet6}
```
-->
* _filter name_: defines the name of the arista filter.
* _standard_: specifies that the output should be a standard access list
* _extended_: specifies that the output should be an extended access list
* _object-group_: specifies this is a arista extended access list, and that object-groups should be used for ports and addresses.
* _inet6_: specifies the output be for IPv6 only filters.
* _noverbose_: omit additional term and address comments. (optional)
* _mixed_: #TODO: does this exist on all Cisco inherited platforms?
* _enable_dsmo_: #TODO: does this exist on all Cisco inherited platforms?

### Term Format

* for common keys see the [common](#common) section above.

* _address_: One or more network address tokens, matches source or destination.
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _dscp-match_: Match a DSCP number.
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _owner_: Owner of the term, used for organizational purposes.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

```yaml
option: {established|is-fragment|tcp-established}
```
<!--
```text
option:: {established|is-fragment|tcp-established}
```
-->
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024-65535 for udp if destination port is not defined.
* _is-fragment_: Matches on if a packet is a fragment.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.

***

## Aruba

### Header Format

The aruba header designation has the following format:

```yaml
targets:
    aruba: [filter name] {ipv6}
```

* _filter name_: defines the name of the arista filter.
* _ipv6_: specifies the output be for IPv6 only filters.

### Term Format

* for common keys see the [common](#common) section above.

* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_

### Option

* _destination-is-user_: Aruba option to specify that the destination should be a user.
* _negate_: Used with DSM summarizer, negates the DSM.
* _source-is-user_: Aruba option to specify that the source should be a user.

***

## Brocade

### Header Format

The brocade header designation has the following format:

```yaml
targets:
    brocade: [filter name] {extended|standard|object-group|inet6|mixed} {enable_dsmo}
```

See [cisco](#cisco) for details.

### Term Format

See [cisco](#cisco) for details.

### Sub Tokens

### Actions

See [cisco](#cisco) for details.

### Option

See [cisco](#cisco) for details.

***

## Cisco

### Header Format

The cisco header designation has the following format:

```yaml
targets:
    cisco: [filter name] {extended|standard|object-group|inet6|mixed} {enable_dsmo} {noverbose}
```

* _filter name_: defines the name or number of the cisco filter.
* _extended_: specifies that the output should be an extended access list, and the filter name should be non-numeric.  This is the default option.
* _standard_: specifies that the output should be a standard access list, and the filter name should be numeric and in the range of 1-99.
* _object-group_: specifies this is a cisco extended access list, and that object-groups should be used for ports and addresses.
* _inet6_: specifies the output be for IPv6 only filters.
* _noverbose_: omit additional term and address comments. (optional)
* _mixed_: specifies output will include both IPv6 and IPv4 filters.
* _enable_dsmo_: Enable discontinuous subnet mask summarization.
When _inet4_ or _inet6_ is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses.
The default format is _inet4_, and is implied if not other argument is given.

### Term Format

* for common keys see the [common](#common) section above.

* _address_: One or more network address tokens, matches source or destination.
* _restrict-address-family_: Only include the term in the matching address family filter (eg. for mixed filters).
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _dscp-match_: Match a DSCP number.
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _owner_: Owner of the term, used for organizational purposes.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _is-fragment_: Matches on if a packet is a fragment.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial_: Only match initial packet for TCP protocol.

***

## CiscoASA

### Header Format

The ciscoasa header designation has the following format:

```yaml
targets:
    ciscoasa: [filter name]
```

### Term Format

* for common keys see the [common](#common) section above.

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _logging_: Specify that this packet should be logged via syslog.
* _owner_: Owner of the term, used for organizational purposes.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.

***

## CiscoNX

### Header Format

The cisconx header designation has the following format:

```yaml
targets:
    cisconx: [filter name] {extended|object-group|inet6|mixed} {enable_dsmo} {noverbose}
```

* _filter name_: defines the name or number of the cisconx filter.
* _extended_: specifies that the output should be an extended access list, and the filter name should be non-numeric.  This is the default option.
* _object-group_: specifies this is a cisconx extended access list, and that object-groups should be used for ports and addresses.
* _inet6_: specifies the output be for IPv6 only filters.
* _noverbose_: omit additional term and address comments. (optional)
* _mixed_: specifies output will include both IPv6 and IPv4 filters.
* _enable_dsmo_: Enable discontinuous subnet mask summarization.
When _inet4_ or _inet6_ is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses.
The default format is _inet4_, and is implied if not other argument is given.

### Term Format

* for common keys see the [common](#common) section above.

* _address_: One or more network address tokens, matches source or destination.
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _dscp-match_: Match a DSCP number.
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _owner_: Owner of the term, used for organizational purposes.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _is-fragment_: Matches on if a packet is a fragment.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial_: Only match initial packet for TCP protocol.

***

## CiscoXR

### Header Format

The ciscoxr header designation has the following format:

```yaml
targets:
    ciscoxr: [filter name] {inet6} {noverbose}
```

* _filter name_: defines the name or number of the cisco filter.
* _inet6_: specifies the output be for IPv6 only filters.
* _noverbose_: omit additional term and address comments. (optional)

### Term Format

* for common keys see the [common](#common) section above.

* _address_: One or more network address tokens, matches source or destination.
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _dscp-match_: Match a DSCP number.
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _next_ip_: next hop (address token -> single IP) for ACL based forwarding
* _owner_: Owner of the term, used for organizational purposes.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _is-fragment_: Matches on if a packet is a fragment.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial_: Only match initial packet for TCP protocol.

***

## Fortigate

### Header Format

The Fortigate header designation has the following format:

```yaml
targets:
    fortigate: [filter name] [source interface] [destination interface] {inet, inet6, mixed}
```

* _filter name_: Defines the name of the Fortinet filter.
* _source interface_: Defines the source interface
* _destination_interface_: Defines the destination interface
* _address_family: Address family to use, valid inputs are `inet`, `inet6`, or `mixed`. (default: `mixed`)

### Term Format

* for common keys see the [common](#common) section above.


### Sub Tokens

### Actions

* _accept_
* _deny_

### Option

* _log_traffic_mode_all_: Enables `set logtraffic all` in term.
* _log_traffic_start_session_: Enabled `set logtraffic-start` in term.


***

## GCE

### Header Format

The GCE header designation has the following format:

```yaml
targets:
    gce: [filter name] [direction]
```

* _filter name_: defines the name of the gce filter.
* _direction_: defines the direction, valid inputs are INGRESS and EGRESS (default:INGRESS)

### Term Format

* for common keys see the [common](#common) section above.

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-tag_: Tag name to be used for destination filtering.
* _owner_: Owner of the term, used for organizational purposes.
* _priority_ Relative priority of rules when evaluated on the platform.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _source-tag_: Tag name used for source filtering.

### Sub Tokens

### Actions

* _accept_
* _deny_

***

## Ipset

Ipset is a system inside the Linux kernel, which can very efficiently store and match IPv4 and IPv6 addresses. This can be used to dramatically increase performance of iptables firewall.

### Header Format

The Ipset header designation follows the Iptables format above, but uses the target platform of 'ipset':

```yaml
targets:
    ipset: [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {truncatenames} {nostate} {inet|inet6}
```

### Term Format

* for common keys see the [common](#common) section above.

* _counter_: Update a counter for matching packets
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-interface_: Specify specific interface a term should apply to (e.g. destination-interface:: eth3)
* _destination-prefix_: Specify destination-prefix matching (e.g. source-prefix:: configured-neighbors-only)
* _fragement-offset_: specify a fragment offset of a fragmented packet
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _owner_: Owner of the term, used for organizational purposes.
* _packet-length_: specify packet length.
* _routing-instance_: specify routing instance for matching packets.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _source-interface_: specify specific interface a term should apply to (e.g. source-interface:: eth3).
* _source-prefix_: specify source-prefix matching (e.g. source-prefix:: configured-neighbors-only).
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _ack_: Match on ACK flag being present.
* _all_: Matches all protocols.
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _fin_: Match on FIN flag being present.
* _first-fragment_: Only match on first fragment of a fragmented pakcet.
* _initial_: Only matches on initial packet.
* _is-fragment_: Matches on if a packet is a fragment.
* _none_: Matches none.
* _psh_: Match on PSH flag being present.
* _rst_: Match on RST flag being present.
* _sample_: Samples traffic for netflow.
* _syn_: Match on SYN flag being present.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial_: Only match initial packet for TCP protocol.
* _urg_: Match on URG flag being present.

***

## IpTables

> NOTE: Iptables produces output that must be passed, line by line, to the 'iptables/ip6tables' command line.  For 'iptables-restore' compatible output, please use the [Speedway](#speedway) generator.

### Header Format

The Iptables header designation has the following format:

```yaml
targets:
    iptables: [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {truncatenames} {nostate} {inet|inet6}
```

* _INPUT_: apply the terms to the input filter.
* _OUTPUT_: apply the terms to the output filter.
* _FORWARD_: apply the terms to the forwarding filter.
* _custom_: create the terms under a custom filter name, which must then be linked/jumped to from one of the default filters (e.g. iptables -A input -j custom)
* _ACCEPT_: specifies that the default policy on the filter should be 'accept'.
* _DROP_: specifies that the default policy on the filter should be to 'drop'.
* _inet_: specifies that the resulting filter should only render IPv4 addresses.
* _inet6_: specifies that the resulting filter should only render IPv6 addresses.
* _truncatenames_: specifies to abbreviate term names if necessary (see lib/iptables.py:_CheckTerMLength for abbreviation table)
* _nostate_: specifies to produce 'stateless' filter output (e.g. no connection tracking)

### Term Format

* for common keys see the [common](#common) section above.

* _counter_: Update a counter for matching packets
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-interface_: Specify specific interface a term should apply to (e.g. destination-interface:: eth3)
* _destination-prefix_: Specify destination-prefix matching (e.g. source-prefix:: configured-neighbors-only)
* _fragement-offset_: specify a fragment offset of a fragmented packet
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _owner_: Owner of the term, used for organizational purposes.
* _packet-length_: specify packet length.
* _routing-instance_: specify routing instance for matching packets.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _source-interface_: specify specific interface a term should apply to (e.g. source-interface:: eth3).
* _source-prefix_: specify source-prefix matching (e.g. source-prefix:: configured-neighbors-only).
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _ack_: Match on ACK flag being present.
* _all_: Matches all protocols.
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _fin_: Match on FIN flag being present.
* _first-fragment_: Only match on first fragment of a fragmented pakcet.
* _initial_: Only matches on initial packet.
* _is-fragment_: Matches on if a packet is a fragment.
* _none_: Matches none.
* _psh_: Match on PSH flag being present.
* _rst_: Match on RST flag being present.
* _sample_: Samples traffic for netflow.
* _syn_: Match on SYN flag being present.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial_: Only match initial packet for TCP protocol.
* _urg_: Match on URG flag being present.

***

## Juniper

### Header Format

The Juniper header designation has the following format:

```yaml
targets:
    juniper: [filter name] {inet|inet6|bridge} {dsmo} {not-interface-specific}
```

* _filter name_: defines the name of the Juniper filter.
* _inet_: specifies the output should be for IPv4 only filters. This is the default format.
* _inet6_: specifies the output be for IPv6 only filters.
* _bridge_: specifies the output should render a Juniper bridge filter.
* _dsmo_: Enable discontinuous subnet mask summarization.
* _not-interface-specific_: Toggles "interface-specific" inside of a term.
* _direction_: The direction of the filter on an interface (optional). Use when a term needs this signal.
* _interface_: The type of interface on which the filter will be applied (optional). Use when a term needs this signal.

When _inet4_ or _inet6_ is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses. The default format is _inet4_, and is implied if not other argument is given.

### Term Format

* for common keys see the [common](#common) section above.

* _address_: One or more network address tokens, matches source or destination.
* _restrict-address-family_: Only include the term in the matching address family filter (eg. for mixed filters).
* _counter_: Update a counter for matching packets
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-prefix_: Specify destination-prefix matching (e.g. source-prefix:: configured-neighbors-only)
* _destination-prefix-except_: Specify destination-prefix exception(TODO:cmas Fill in more).
* _dscp-except_: Do not match the DSCP number.
* _dscp-match_: Match a DSCP number.
* _dscp-set_: Match a DSCP set.
* _ether-type_: Match EtherType field.
* _filter-term_: Include another filter
* _flexible-match-range_: Filter based on flexible match options.
* _forwarding-class_: Specify the forwarding class to match.
* _forwarding-class-except_: Do not match the specified forwarding classes.
* _fragement-offset_: specify a fragment offset of a fragmented packet
* _hop-limit_: Match the hop limit to the specified hop limit or set of hop limits.
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _loss-priority_: Specify loss priority.
* _next-ip_: Used in filter based forwarding.
* _owner_: Owner of the term, used for organizational purposes.
* _packet-length_: specify packet length.
* _policer_: specify which policer to apply to matching packets.
* _port_: Matches on source or destination ports. Takes a service token.
* _port-mirror_: Sends copies of the packets to a remote port, boolean value is used to render this config.
* _precedence_: specify precedence of range 0-7.  May be a single integer, or a space separated list.
* _protocol-except_: allow all protocol "except" specified.
* _qos_: apply quality of service classification to matching packets (e.g. qos:: af4)
* _routing-instance_: specify routing instance for matching packets.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _source-prefix_: specify source-prefix matching (e.g. source-prefix:: configured-neighbors-only).
* _source-prefix-except_: specify destination-prefix exception(TODO:cmas Fill in more).
* _traffic-class-count_:
* _traffic-type_: specify traffic-type
* _ttl_: Matches on TTL.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _.*_: wat
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _first-fragment_: Only match on first fragment of a fragmented pakcet.
* _sample_: Samples traffic for netflow.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial_: Only match initial packet for TCP protocol.

***

## Juniper EVO

### Header Format

The Juniper EVO header designation has the following format:

```yaml
targets:
    juniperevo: [filter name] {inet|inet6|bridge} {dsmo} {not-interface-specific} {direction} {interface}
```

* _filter name_: defines the name of the Juniper EVO filter.
* _inet_: specifies the output should be for IPv4 only filters. This is the default format.
* _inet6_: specifies the output be for IPv6 only filters.
* _bridge_: specifies the output should render a Juniper EVO bridge filter.
* _dsmo_: Enable discontinuous subnet mask summarization.
* _direction_: The direction of the filter on an interface. Must be specified.
* _interface_: The type of interface on which the filter will be applied. Default in physical (non-loopback) interface.

When _inet4_ or _inet6_ is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses. The default format is _inet4_, and is implied if not other argument is given.

### Term Format

* for common keys see the [common](#common) section above.

* _address_: One or more network address tokens, matches source or destination.
* _restrict-address-family_: Only include the term in the matching address family filter (eg. for mixed filters).
* _counter_: Update a counter for matching packets
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-prefix_: Specify destination-prefix matching (e.g. source-prefix:: configured-neighbors-only)
* _destination-prefix-except_: Specify destination-prefix exception(TODO:cmas Fill in more).
* _dscp-except_: Do not match the DSCP number.
* _dscp-match_: Match a DSCP number.
* _dscp-set_: Match a DSCP set.
* _ether-type_: Match EtherType field.
* _filter-term_: Include another filter
* _flexible-match-range_: Filter based on flexible match options.
* _forwarding-class_: Specify the forwarding class to match.
* _forwarding-class-except_: Do not match the specified forwarding classes.
* _fragement-offset_: specify a fragment offset of a fragmented packet
* _hop-limit_: Match the hop limit to the specified hop limit or set of hop limits.
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _loss-priority_: Specify loss priority.
* _next-ip_: Used in filter based forwarding.
* _owner_: Owner of the term, used for organizational purposes.
* _packet-length_: specify packet length.
* _policer_: specify which policer to apply to matching packets.
* _port_: Matches on source or destination ports. Takes a service token.
* _port-mirror_: Sends copies of the packets to a remote port, boolean value is used to render this config.
* _precedence_: specify precedence of range 0-7.  May be a single integer, or a space separated list.
* _protocol-except_: allow all protocol "except" specified.
* _qos_: apply quality of service classification to matching packets (e.g. qos:: af4)
* _routing-instance_: specify routing instance for matching packets.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _source-prefix_: specify source-prefix matching (e.g. source-prefix:: configured-neighbors-only).
* _source-prefix-except_: specify destination-prefix exception(TODO:cmas Fill in more).
* _traffic-class-count_:
* _traffic-type_: specify traffic-type
* _ttl_: Matches on TTL.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _.*_: wat
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _first-fragment_: Only match on first fragment of a fragmented pakcet.
* _sample_: Samples traffic for netflow.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial_: Only match initial packet for TCP protocol.

### IPv6 Protocol Match

For Juniper EVO, the direction of the filter on an interface and the interface type determines the syntax to use; either `next-header` or `payload-protocol`. The syntax usage is sumarized below for the extension headers as well as the payload header.

* _Ingress (Physical)_: `next-header hop-by-hop` | `next-header fragment` | `next-header routing` | `payload-protocol tcp|udp|ah|esp|icmpv6`
* _Ingress (Loopback)_: `payload-protocol 0` | `payload-protocol 44` | `payload-protocol 43` | `payload-protocol tcp|udp|ah|esp|icmpv6`
* _Egress (Physical)_: `payload-protocol 0` | `payload-protocol 44` | `payload-protocol 43` | `payload-protocol tcp|udp|ah|esp|icmpv6`
* _Egress (Loopback)_: `payload-protocol 0` | `payload-protocol 44` | `payload-protocol 43` | `payload-protocol tcp|udp|ah|esp|icmpv6`

***

## Juniper MSMPC

### Header Format

The Juniper MSMPC header designation has the following format:

```yaml
targets:
    msmpc: [filter name] {inet|inet6|mixed} {noverbose} {ingress|egress} [no-apply-groups]
```

* _filter name_: defines the name of the Juniper msmpc filter.
* _inet6_: specifies the output be for IPv6 only filters.
* _mixed_: specifies the output be for IPv4 and IPv6 filters. This is the default format.
* _noverbose_: omit additional term and address comments. (optional)
* _ingress_: filter will be applied in the input direction.
* _egress_: filter will be appliced in the output direction.
* _no-apply-groups_: generate configuration without `apply-groups` (optional)

When inet4 or inet6 is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses.

When neither ingress or egress is specified, the filter will be applied in both (input-output) directions. This is the default.

### Term Format

TBD

### Sub Tokens

### Actions

* _accept_
* _deny_
* _reject_

***

## JuniperSRX

### Header Format

```yaml
targets:
    srx: from-zone [zone name] to-zone [zone name] {inet}
```

* _from-zone_: static keyword, followed by user specified zone
* _to-zone_: static keyword, followed by user specified zone
* _inet_: Address family (only IPv4 tested at this time)

NOTE: For generating global policies use `from-zone all to-zone all {inet}`.

### Term Format

* for common keys see the [common](#common) section above.

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-fqdn_: One or more destination FQDNs to filter.
* _destination-zone_: one or more destination zones tokens. Only supported by global policy
* _dscp-except_: Do not match the DSCP number.
* _dscp-match_: Match a DSCP number.
* _dscp-set_: Match a DSCP set.
* _logging_: Specify that these packets should be logged.
    * Based on the input value the resulting logging actions will follow this logic:

        * _action_ is 'accept':

            * _logging_ is 'true': resulting SRX output will be 'log { session-close; }'
            * _logging_ is 'log-both': resulting SRX output will be 'log { session-init; session-close; }'
        * _action_ is 'deny':
            * _logging_ is 'true': resulting SRX output will be 'log { session-init; }'
            * _logging_ is 'log-both': resulting SRX output will be 'log { session-init; session-close; }'
        * See [here](https://kb.juniper.net/InfoCenter/index?page=content&id=KB16506) for explanation.
* _owner_: Owner of the term, used for organizational purposes.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _source-fqdn_: One or more source FQDNs to filter.
* _source-zone_: one or more source zones tokens. Only supported by global policy
* _timeout_: specify application timeout. (default 60)
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.
* _vpn_: Encapsulate outgoing IP packets and decapsulate incomfing IP packets.

### Sub Tokens

### Actions

* _accept_
* _count_
* _deny_
* _dscp_
* _log_
* _reject_

***

## K8s

### Header Format

The K8s header designation has the following format:

```yaml
targets:
    k8s: [direction]
```

* _direction_: defines the direction, valid inputs are INGRESS and EGRESS (default:INGRESS)

### Term Format

* for common keys see the [common](#common) section above.

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _owner_: Owner of the term, used for organizational purposes.
* _source-exclude_: exclude one or more address tokens from the specified source-address.

### Sub Tokens

### Actions

* _accept_
* _deny_: Only permitted for a default deny

***

## Nftables

### Header Format

The NFTables header designation has the following format:

```yaml
targets:
    newnftables: [nf_address_family] [nf_hook] {default_policy_override} {int: base chain priority} {noverbose}
```

Unless otherwise stated, all fields are required unless they're marked optional.

* nf_address_family: defines the IP address family for the policies. (inet, inet6, mixed)
* nf_hook: defines the traffic direction and the nftables hook for the rules. (input, output)
* default_policy_override: **OPTIONAL** defines the default action (ACCEPT, DROP) for non-matching packets. Default behavior is DROP.
* priority: **OPTIONAL** By default, this generator creates base chains with a starting priority of 0. Defining an integer value will override this behavior.
* noverbose: **OPTIONAL** Disable header and term comments in final ACL output. Default behavior is verbose.

### Important: stateful firewall only

This NFTables ACL generator generates stateful policies via  [conntrack](https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation). Each NFTables base chain will accept valid return packets via (`ct state established,related accept`).

When a non-deny term is processed for ACL generation, the `ct state new` is added to the resulting policy to ensure only valid incoming connections for that term is accepted. This means invalid state packets are dropped by default.

An implementation design for this generator is that terms with options 'established', 'tcp-established' will not rendered in the final NFT configuration.

### Reporting bugs

When reporting bugs about this generator ensure to include:

1. Example policy (.pol file)
1. Observed output (.nft file)
1. Expected (correct) output in Nftables syntax (.nft syntax)

### Term Format

* for common keys see the [common](#common) section above.

* _logging_: NFTables system logging (host-based).
* _counter_: NFTables counter for specific term.

### Sub-tokens

### Actions

* _accept_
* _drop_

### Logging

* _disable_ no packets will be logged on syslog.

All of the below values are accepted, but outcome is exactly the same.

* _true_
* _syslog_
* _local_

### Counter

Any string sub-token in `counter` is accepted. Do note this generator _does not_ implement NFTables `named counters` - this is primarily due to original design decisions to keep each Term into its own chain structure, any support of named counters would simply make the configuration .nft file longer without any additional benefit with the possible exception of the ability to use a single counter-name for multiple terms.

### ICMP Types

This generator normalizes certain aerleon policy.py string types to NFTables semantically correct values. The below tables summarize the supported ICMP type codes, the policy.py parent class definition and the NFtables specific value for the same type.

#### IPv4

```text
| ICMPv4 type code | Aerleon (policy.py)  | NFtables manual         |
|------------------|----------------------|-------------------------|
| 0                | echo-reply           | echo-reply              |
| 3                | unreachable          | destination-unreachable |
| 4                | source-quench        | source-quench           |
| 5                | redirect             | redirect                |
| 6                | alternate-address    |                         |
| 8                | echo-request         | echo-request            |
| 9                | router-advertisement | router-advertisement    |
| 10               | router-solicitation  | router-solicitation     |
| 11               | time-exceeded        | time-exceeded           |
| 12               | parameter-problem    | parameter-problem       |
| 13               | timestamp-request    | timestamp-request       |
| 14               | timestamp-reply      | timestamp-reply         |
| 15               | information-request  | info-request            |
| 16               | information-reply    | info-reply              |
| 17               | mask-request         | address-mask-request    |
| 18               | mask-reply           | address-mask-reply      |
| 31               | conversion-error     |                         |
| 32               | mobile-redirect      |                         |
```

#### IPv6

```text
| ICMPv6 type code | Aerleon (policy.py)                      | NFtables manual                             |
|------------------|------------------------------------------|---------------------------------------------|
| 1                | destination-unreachable                  | destination-unreachable                     |
| 2                | packet-too-big                           | packet-too-big                              |
| 3                | time-exceeded                            | time-exceeded                               |
| 4                | parameter-problem                        | parameter-problem                           |
| 128              | echo-request                             | echo-request                                |
| 129              | echo-reply                               | echo-reply                                  |
| 130              | multicast-listener-query                 | mld-listener-query                          |
| 131              | multicast-listener-report                | mld-listener-report                         |
| 132              | multicast-listener-done                  | mld-listener-done OR mld-listener-reduction |
| 133              | router-solicit                           | nd-router-solicit                           |
| 134              | router-advertisement                     | nd-router-advert                            |
| 135              | neighbor-solicit                         | nd-neighbor-solicit                         |
| 136              | neighbor-advertisement                   | nd-neighbor-advert                          |
| 137              | redirect-message                         | nd-redirect                                 |
| 138              | router-renumbering                       | router-renumbering                          |
| 139              | icmp-node-information-query              |                                             |
| 140              | icmp-node-information-response           |                                             |
| 141              | inverse-neighbor-discovery-solicitation  | ind-neighbor-solicit                        |
| 142              | inverse-neighbor-discovery-advertisement | ind-neighbor-advert                         |
| 143              | version-2-multicast-listener-report      | mld2-listener-report                        |
| 144              | home-agent-address-discovery-request     |                                             |
| 145              | home-agent-address-discovery-reply       |                                             |
| 146              | mobile-prefix-solicitation               |                                             |
| 147              | mobile-prefix-advertisement              |                                             |
| 148              | certification-path-solicitation          |                                             |
| 149              | certification-path-advertisement         |                                             |
| 151              | multicast-router-advertisement           |                                             |
| 152              | multicast-router-solicitation            |                                             |
| 153              | multicast-router-termination             |                                             |
```

_source:_ https://www.netfilter.org/projects/nftables/manpage.html

### Option

* _tcp-established_ and _established_ will cause the term to not be rendered in the final NFT configuration. See 'Important' section above.

***

## Nokia SR Linux

### Header Format

The Nokia SR Linux header designation has the following format:

```yaml
targets:
    nokiasrl: {section_name} {inet|inet6|mixed} {stats} {r24.3} {r24.3.2}
```

* _section_name_: specifies the name of the section all terms in this header apply to.
* _inet_: specifies that the resulting filter should only render IPv4 addresses.
* _inet6_: specifies that the resulting filter should only render IPv6 addresses.
* _mixed_: specifies that the resulting filter should render both IPv4 and IPv6 addresses.
* _stats_: Collect stats for ACL entries
* _r24.3_: Use release 24.3.1 format
* _r24.3.2_: Use new format (post release 24.3.1)

(Required keywords option and verbatim are not supported)

### Term Format

* for common keys see the [common](#common) section above.

### Sub Tokens

### Actions

* _accept_
* _deny_

***

## NSXv

### Header Format

The nsx header designation has the following format:

```yaml
targets:
    nsxv: {section_name} {inet|inet6|mixed} section-id securitygroup securitygroupId
```

* _section_name_: specifies the name of the section all terms in this header apply to.
* _inet_: specifies that the resulting filter should only render IPv4 addresses.
* _inet6_: specifies that the resulting filter should only render IPv6 addresses.
* _mixed_: specifies that the resulting filter should render both IPv4 and IPv6 addresses.
* _section-id_: specifies the id for the section (optional)
* _securitygroup_: specifies that the appliedTo should be security group (optional)
* _securitygroupId_: specifies the Id of the security group (mandatory if securitygroup is given)

(Required keywords option and verbatim are not supported in NSX)

### Term Format

* for common keys see the [common](#common) section above.

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _logging_: Specify that this packet should be logged via syslog.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _reject_
* _reject-with-tcp-rst_

***

# NSXT

The nsx header designation has the following format:

```
target:: nsxt {section_name} {inet|inet6|mixed} section-id securitygroup securitygroupId
section_name: specifies the name of the section all terms in this header apply to.
inet: specifies that the resulting filter should only render IPv4 addresses.
inet6: specifies that the resulting filter should only render IPv6 addresses.
mixed: specifies that the resulting filter should render both IPv4 and IPv6 addresses.
sectionId: specifies the Id for the section [optional]
securitygroup: specifies that the appliedTo should be security group [optional]
securitygroupId: specifies the Id of the security group [mandatory if securitygroup is given]
(Required keywords option and verbatim are not supported in NSX)
```

## Nsxt
The nsxt header designation has the following format:
```
targets:
    nsxt: {section_name} {inet|inet6|mixed} section-id securitygroup securitygroupId
```
  * _section_name_: specifies the name of the dfw rule all terms in this header apply to. [mandatory field]
  * _inet_: specifies the output should be for IPv4 only filters. This is the default format.
  * _inet6_: specifies the output be for IPv6 only filters.
  * _mixed_: specifies that the resulting filter should render both IPv4 and IPv6 addresses.
  * _sectionId_: specifies the Id for the section [optional]
  * _securitygroup_: specifies that the appliedTo should be security group [optional]
  * _securitygroupId_: specifies the Id of the security group [mandatory if securitygroup is given]
(Required keywords option and verbatim are not supported in NSX)
## Term Format
* _action::_ The action to take when matched. See Actions section for valid options.
* _comment::_ A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address::_ One or more destination address tokens
* _destination-exclude::_ Exclude one or more address tokens from the specified destination-address
* _destination-port::_ One or more service definition tokens
* _expiration::_ stop rendering this term after specified date. [YYYY](YYYY.md)-[MM](MM.md)-[DD](DD.md)
* _icmp-type::_ Specify icmp-type code to match, see section [ICMP TYPES](PolicyFormat#ICMP_TYPES.md) for list of valid arguments
* _logging::_ Specify that this packet should be logged via syslog.
* _name::_ Name of the term.
* _option::_ See platforms supported Options section.
* _platform::_ one or more target platforms for which this term should ONLY be rendered.
*_platform-exclude:: one or more target platforms for which this term should NEVER be rendered.
* _protocol::_ the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _source-address::_ one or more source address tokens.
* _source-exclude::_ exclude one or more address tokens from the specified source-address.
* _source-port::_ one or more service definition tokens.
* _verbatim::_ this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.
## Sub Tokens
### Actions
* _accept_
* _deny_
* _reject_
* _reject-with-tcp-rst_


## PacketFilter

### Header Format

```yaml
targets:
    packetfilter: filter-name {inet|inet6|mixed} {in|out} {nostate}
```

* _filter-name_: a short, descriptive policy identifier
* _inet_: specifies that the resulting filter should only render IPv4 addresses.
* _inet6_: specifies that the resulting filter should only render IPv6 addresses.
* _mixed_: specifies that the resulting filter should only render IPv4 and IPv6 addresses (default).
* _in_: match ingoing packets (default: both directions).
* _out_: match outgoing packets (default: both directions).
* _nostate_: do not keep state on connections (default: keep state).

### Term Format

* for common keys see the [common](#common) section above.

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-interface_: Specify the destination interface. Implicitly changes the term direction to **out** for this term. Mutually exclusive with _source-interface_:.
* _source-interface_: Specify the source interface. Implicitly changes the term direction to **in** for this term. Mutually exclusive with _destination-interface_:.
* _logging_: Specify that this packet should be logged via syslog.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_

### Option

* _ack_: Match on ACK flag being present.
* _all_: Matches all protocols.
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _fin_: Match on FIN flag being present.
* _is-fragment_: Matches on if a packet is a fragment.
* _psh_: Match on PSH flag being present.
* _rst_: Match on RST flag being present.
* _syn_: Match on SYN flag being present.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _urg_: Match on URG flag being present.

***

## PaloAltoFW

### Header Format

The paloalto header designation has the following format:

```yaml
targets:
    paloalto: from-zone [zone name] to-zone [zone name] [address family] [address objects]
```

* _from-zone_: static keyword, followed by the source zone
* _to-zone_: static keyword, followed by the destination zone
* _address family_: specifies the address family for the resulting filter
    * _inet_: the filter should only render IPv4 addresses (default)
    * _inet6_: the filter should only render IPv6 addresses
    * _mixed_: the filter should render IPv4 and IPv6 addresses
* _address objects_: specifies whether custom address objects or network/mask definitions are used in security policy source and destination fields
    * _addr-obj_: specifies address groups are used in the security policy
      source and destination fields (default)
    * _no-addr-obj_: specifies network/mask definitions are used in the
       security policy source and destination fields
* _unique-term-prefixes_: specifies whether each term name should be generated with unique prefixes. The unique prefix is a hexdigest of from_zone and to_zone fields.

### Term Format

* for common keys see the [common](#common) section above.

* _logging_: Specify that this packet should be logged via syslog.
* _owner_: Owner of the term, used for organizational purposes.
* _timeout_: specify application timeout. (default 60)

### Sub Tokens

### Actions

* _accept_
* _count_
* _deny_
* _log_
* _reject_

### Terms Section

### Optionally Supported Keywords

* _pan-application_:: paloalto target only.
    Specify applications for the security policy which can be predefined
    applications (<https://applipedia.paloaltonetworks.com/>)
    and custom application objects.

    * _Security Policy Service Setting_

        * When no _protocol_ is specified in the term, the service will be _application-default_.
        * When _protocol_ is tcp or udp, and no _source-port_ or _destination-port_ is specified, the service will be custom service objects for the protocols and all ports (0-65535).
        * When _protocol_ is tcp or udp, and a _source-port_ or _destination-port_ is specified, the service will be custom service objects for the protocols and ports.
        * _pan-application_ can only be used when no _protocol_ is specified in the term, or the protocols tcp and udp.

***

## PcapFilter

### Header Format

FILL ME IN

### Term Format

* for common keys see the [common](#common) section above.

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _source-exclude_: exclude one or more address tokens from the specified source-address.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_

### Option

* _ack_: Match on ACK flag being present.
* _all_: Matches all protocols.
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _fin_: Match on FIN flag being present.
* _is-fragment_: Matches on if a packet is a fragment.
* _none_: Matches none.
* _psh_: Match on PSH flag being present.
* _rst_: Match on RST flag being present.
* _syn_: Match on SYN flag being present.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _urg_: Match on URG flag being present.

***

## Speedway

> NOTE: Speedway produces Iptables filtering output that is suitable for passing to the 'iptables-restore' command.

### Header Format

The Speedway header designation has the following format:

```yaml
targets:
    speedway: [INPUT|OUTPUT|FORWARD|custom] {ACCEPT|DROP} {truncatenames} {nostate} {inet|inet6}
```

* _INPUT_: apply the terms to the input filter.
* _OUTPUT_: apply the terms to the output filter.
* _FORWARD_: apply the terms to the forwarding filter.
* _custom_: create the terms under a custom filter name, which must then be linked/jumped to from one of the default filters (e.g. iptables -A input -j custom)
* _ACCEPT_: specifies that the default policy on the filter should be 'accept'.
* _DROP_: specifies that the default policy on the filter should be to 'drop'.
* _inet_: specifies that the resulting filter should only render IPv4 addresses.
* _inet6_: specifies that the resulting filter should only render IPv6 addresses.
* _truncatenames_: specifies to abbreviate term names if necessary (see lib/iptables.py: CheckTermLength for abbreviation table)
* _nostate_: specifies to produce 'stateless' filter output (e.g. no connection tracking)

### Term Format

* for common keys see the [common](#common) section above.

* _counter_: Update a counter for matching packets
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-interface_: Specify specific interface a term should apply to (e.g. destination-interface:: eth3)
* _destination-prefix_: Specify destination-prefix matching (e.g. source-prefix:: configured-neighbors-only)
* _fragement-offset_: specify a fragment offset of a fragmented packet
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _owner_: Owner of the term, used for organizational purposes.
* _packet-length_: specify packet length.
* _routing-instance_: specify routing instance for matching packets.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _source-interface_: specify specific interface a term should apply to (e.g. source-interface:: eth3).
* _source-prefix_: specify source-prefix matching (e.g. source-prefix:: configured-neighbors-only).
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _ack_: Match on ACK flag being present.
* _all_: Matches all protocols.
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _fin_: Match on FIN flag being present.
* _first-fragment_: Only match on first fragment of a fragmented pakcet.
* _initial_: Only matches on initial packet.
* _is-fragment_: Matches on if a packet is a fragment.
* _none_: Matches none.
* _psh_: Match on PSH flag being present.
* _rst_: Match on RST flag being present.
* _sample_: Samples traffic for netflow.
* _syn_: Match on SYN flag being present.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial_: Only match initial packet for TCP protocol.
* _urg_: Match on URG flag being present.

***

## SRXlo

SRX Loopback is a stateless Juniper ACL with minor changes. Please see code for changes.

### Header Format

The Juniper header designation has the following format:

```yaml
targets:
    srxlo: [filter name] {inet|inet6|bridge} {dsmo} {not-interface-specific}
```

* _filter name_: defines the name of the Juniper filter.
* _inet_: specifies the output should be for IPv4 only filters. This is the default format.
* _inet6_: specifies the output be for IPv6 only filters.
* _bridge_: specifies the output should render a Juniper bridge filter.
* _dsmo_: Enable discontinuous subnet mask summarization.
* _not-interface-specific_: Toggles "interface-specific" inside of a term.
* _direction_: The direction of the filter on an interface (optional). Use when a term needs this signal.
* _interface_: The type of interface on which the filter will be applied (optional). Use when a term needs this signal.

When _inet4_ or _inet6_ is specified, naming tokens with both IPv4 and IPv6 filters will be rendered using only the specified addresses. The default format is _inet4_, and is implied if not other argument is given.

### Term Format

* for common keys see the [common](#common) section above.

* _address_: One or more network address tokens, matches source or destination.
* _counter_: Update a counter for matching packets
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-prefix_: Specify destination-prefix matching (e.g. source-prefix:: configured-neighbors-only)
* _destination-prefix-except_: Specify destination-prefix exception(TODO:cmas Fill in more).
* _dscp-except_: Do not match the DSCP number.
* _dscp-match_: Match a DSCP number.
* _dscp-set_: Match a DSCP set.
* _ether-type_: Match EtherType field.
* _forwarding-class_: Specify the forwarding class to match.
* _forwarding-class-except_: Do not match the specified forwarding classes.
* _fragement-offset_: specify a fragment offset of a fragmented packet
* _hop-limit_: Match the hop limit to the specified hop limit or set of hop limits.
* _icmp-code_: Specifies the ICMP code to filter on.
* _logging_: Specify that this packet should be logged via syslog.
* _loss-priority_: Specify loss priority.
* _next-ip_: Used in filter based forwarding.
* _owner_: Owner of the term, used for organizational purposes.
* _packet-length_: specify packet length.
* _policer_: specify which policer to apply to matching packets.
* _port_: Matches on source or destination ports. Takes a service token.
* _precedence_: specify precedence of range 0-7.  May be a single integer, or a space separated list.
* _protocol-except_: allow all protocol "except" specified.
* _qos_: apply quality of service classification to matching packets (e.g. qos:: af4)
* _routing-instance_: specify routing instance for matching packets.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _source-prefix_: specify source-prefix matching (e.g. source-prefix:: configured-neighbors-only).
* _source-prefix-except_: specify destination-prefix exception(TODO:cmas Fill in more).
* _traffic-class-count_:
* _traffic-type_: specify traffic-type
* _ttl_: Matches on TTL.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

### Sub Tokens

### Actions

* _accept_
* _deny_
* _next_
* _reject_
* _reject-with-tcp-rst_

### Option

* _.*_: wat
* _established_: Only match established connections, implements tcp-established for tcp and sets destination port to 1024- 65535 for udp if destination port is not defined.
* _first-fragment_: Only match on first fragment of a fragmented pakcet.
* _sample_: Samples traffic for netflow.
* _tcp-established_: Only match established tcp connections, based on statefull match or TCP flags. Not supported for other protocols.
* _tcp-initial_: Only match initial packet for TCP protocol.

***

## Windows Advanced Firewall

### Header Format

The Windows Advanced Firewall header designation has the following format:

```yaml
targets:
    windows_advfirewall: {out|in} {inet|inet6|mixed}
```

* _out_: Specifies that the direction of packet flow is out. (default)
* _in_: Specifies that the direction of packet flow is in.
* _inet_: specifies that the resulting filter should only render IPv4 addresses.
* _inet6_: specifies that the resulting filter should only render IPv6 addresses.

### Term Format

* for common keys see the [common](#common) section above.

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _source-exclude_: exclude one or more address tokens from the specified source-address.

### Sub Tokens

### Actions

* _accept_
* _deny_

***

## WindowsIPSec

### Header Format

The Windows IPSec header designation has the following format:

```yaml
targets:
    windows_ipsec: [filter_name]
```

* _filter name_: defines the name of the Windows IPSec filter.

### Term Format

* for common keys see the [common](#common) section above.
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _source-exclude_: exclude one or more address tokens from the specified source-address.

### Sub Tokens

### Actions

* _accept_
* _deny_

***

## ICMP Types

### IPv4

* echo-reply
* unreachable
* source-quench
* redirect
* alternate-address
* echo-request
* router-advertisement
* router-solicitation
* time-exceeded
* parameter-problem
* timestamp-request
* timestamp-reply
* information-request
* information-reply
* mask-request
* mask-reply
* conversion-error
* mobile-redirect

### IPv6

* destination-unreachable
* packet-too-big
* time-exceeded
* parameter-problem
* echo-request
* echo-reply
* multicast-listener-query
* multicast-listener-report
* multicast-listener-done
* router-solicit
* router-advertisement
* neighbor-solicit
* neighbor-advertisement
* redirect-message
* router-renumbering
* icmp-node-information-query
* icmp-node-information-response
* inverse-neighbor-discovery-solicitation
* inverse-neighbor-discovery-advertisement
* version-2-multicast-listener-report
* home-agent-address-discovery-request
* home-agent-address-discovery-reply
* mobile-prefix-solicitation
* mobile-prefix-advertisement
* certification-path-solicitation
* certification-path-advertisement
* multicast-router-advertisement
* multicast-router-solicitation
* multicast-router-termination
