# NSXt

## Header Format

The nsxt header designation has the following format:

```yaml
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
