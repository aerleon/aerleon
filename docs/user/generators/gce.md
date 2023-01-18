# GCE

## Header Format

The GCE header designation has the following format:

```yaml
targets:
    gce: [filter name] [direction]
```

* _filter name_: defines the name of the gce filter.
* _direction_: defines the direction, valid inputs are INGRESS and EGRESS (default:INGRESS)

## Term Format

* for common keys see [common.md](common.md)

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination_tag_: Tag name to be used for destination filtering.
* _owner_: Owner of the term, used for organizational purposes.
* _priority_ Relative priority of rules when evaluated on the platform.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _source-tag_: Tag name used for source filtering.

## Sub Tokens

### Actions

* _accept_
* _deny_
