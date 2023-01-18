# WindowsIPSec

## Header Format

The Windows IPSec header designation has the following format:

```yaml
targets:
    windows_ipsec: [filter_name]
```

* _filter name_: defines the name of the Windows IPSec filter.

## Term Format

* for common keys see [common.md](common.md)
* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _source-exclude_: exclude one or more address tokens from the specified source-address.

## Sub Tokens

### Actions

* _accept_
* _deny_
