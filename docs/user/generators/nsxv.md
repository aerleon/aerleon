# NSXv

## Header Format

The nsx header designation has the following format:

```yaml
targets:
    nsxv: {section_name} {inet|inet6|mixed} section-id securitygroup securitygroupId
```

* _section_name_: specifies the name of the section all terms in this header apply to.
* _inet_: specifies that the resulting filter should only render IPv4 addresses.
* _inet6_: specifies that the resulting filter should only render IPv6 addresses.
* _mixed_: specifies that the resulting filter should render both IPv4 and IPv6 addresses.
* _sectionId_: specifies the Id for the section (optional)
* _securitygroup_: specifies that the appliedTo should be security group (optional)
* _securitygroupId_: specifies the Id of the security group (mandatory if securitygroup is given)

(Required keywords option and verbatim are not supported in NSX)

## Term Format

* for common keys see [common.md](common.md)

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _logging_: Specify that this packet should be logged via syslog.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.

## Sub Tokens

### Actions

* _accept_
* _deny_
* _reject_
* _reject-with-tcp-rst_
