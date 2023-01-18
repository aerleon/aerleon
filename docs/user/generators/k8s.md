# K8s

## Header Format

The K8s header designation has the following format:

```yaml
targets:
    k8s: [direction]
```

* _direction_: defines the direction, valid inputs are INGRESS and EGRESS (default:INGRESS)

## Term Format

* for common keys see [common.md](common.md)

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _owner_: Owner of the term, used for organizational purposes.
* _source-exclude_: exclude one or more address tokens from the specified source-address.

## Sub Tokens

### Actions

* _accept_
* _deny_: Only permitted for a default deny
