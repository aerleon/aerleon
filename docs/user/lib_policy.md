# Policy Files

A policy file describes a security policy using _header_ and _term_ blocks. Header blocks describe how to generate the output configuration of the security policy. Term blocks define the access control rules within an ACL.

In .pol.yaml files, each ACL has exactly one header and one or more term sections. In .pol file format, each ACL is defined by a top-level header block followed by one or more top-level term blocks.

```yaml
acls:
  - header:
      comment:
        this is a sample policy for a zone based filter that generates multiple
        output formats. It checks logging options, tcp, udp and icmp type
        options.
      targets:
        - target: paloalto
          options: from-zone internal to-zone external
        - target: srx
          options: from-zone internal to-zone external
    terms:
      - name: test-tcp-log-both
        comment: Testing log-both for tcp.
        protocol: tcp
        logging: log-both
        action: accept
      - name: test-udp-log
        comment: Testing logging for udp.
        protocol: udp
        logging: true
        action: accept
```

See [Policy Files](../../dev/design/policy/) for full details.
