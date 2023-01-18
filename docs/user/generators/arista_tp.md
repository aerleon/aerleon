# Arista Traffic-Policy

## Header Format

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

## Term Format

The following tokens are supported:

* for common keys see [common.md](common.md)

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

## Sub Tokens

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

## Ports

In EOS traffic-policies, ports can be configured using:

* `source [ all | port-list | field-set ]`
* `destination [ all | port-list | field-set ]`

Currently, all and field-sets are not supported for ports. Only port-lists are supported.

## default-terms

EOS has (2) default terms per traffic-policy, one for each address family:

* `ipv4-default-all`
* `ipv6-default-all`

If there is no match criteria associated with a term _and_ the term name in the policy begins with `default-`, the contents will be rendered into the default terms for the appropriate address family.

## Empty match criteria

If there is no match criteria specified, and the term name does _not_ start with `default-` the term will not be rendered and a warning will be logged.

## Documentation

The official documentation for traffic-policies can be found at the following URL.

* <https://eos.arista.com/eos-4-25-0f/support-for-traffic-policy-on-interfaces/>
