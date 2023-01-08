# Address Files

Address book files define symbolic names for IP networks, hosts, and services. Policy files may reference these names.

```yaml
terms:
  - name: deny-to-bad-destinations
    destination-address: RFC1918 BOGON RESERVED
    action: deny
```

```
RFC1918 = 10.0.0.0/8      # non-public
          172.16.0.0/12   # non-public
          192.168.0.0/16  # non-public

BOGON = 0.0.0.0/8
        192.0.0.0/24
...skipped...

RESERVED = 0.0.0.0/8      # reserved
           RFC1918
           LOOPBACK
...skipped...
```

Users may wish to auto-generate address book files to keep them up to date. JSON and CSV are accepted for this reason.