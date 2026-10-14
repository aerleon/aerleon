# Brocade

The brocade generator is built on the [Cisco](cisco.md) generator. It supports exactly the same header options, tokens, actions and options, so see the Cisco tables.

## Header Format

```yaml
targets:
    brocade: [filter name] {extended|standard|object-group|inet6|mixed} {enable_dsmo} {noverbose}
```

All options work as described for [Cisco](cisco.md).

## Differences from Cisco

| Area | Cisco | Brocade |
|---|---|---|
| Protocols | Rendered as numbers where possible | Rendered by name, as written in the policy |
| Term name remark | Each term starts with `remark <term name>` | Not written; only the term's `comment` is |
