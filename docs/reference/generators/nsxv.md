# NSXv

## Header Format

The nsxv header designation has the following format:

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

## Term Format

* for common keys see the [Common](common.md) page.

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _logging_: Specify that this packet should be logged via syslog.
* _source-exclude_: exclude one or more address tokens from the specified source-address.

## Sub Tokens

## Actions

* _accept_
* _deny_
* _reject_
* _reject-with-tcp-rst_
