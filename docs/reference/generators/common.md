# Common

These keys are accepted by every generator unless a generator's page says otherwise. The token table is also included on every generator page, and [Support by generator](#support-by-generator) lists the exceptions.

!!! note "Where these lists come from"
    Supported tokens are defined in code. The base set lives in `ACLGenerator._BuildTokens()` (`aerleon/lib/aclgenerator.py`), and each generator extends or trims it in its own `_BuildTokens()`. A term that uses a token outside that set is rejected with an `UnsupportedFilterError` (a few tokens, such as `counter`, `logging` and `owner`, only log a warning instead).

## Term Format

Every generator page includes this table at the start of its Term Format section, followed by the tokens that generator adds.

<!-- --8<-- [start:common-tokens] -->

| Token | Description | Example | Notes |
|---|---|---|---|
| `action` | What to do with matching traffic. | `action: accept` | Valid values are listed in each generator's Actions table. |
| `comment` | Free-text comment rendered with the term. | `comment: "Allow SSH from bastions"` | Use a YAML block scalar for multi-line comments. |
| `destination-address` | One or more destination address tokens. | `destination-address: WEB_SERVERS` |  |
| `destination-exclude` | Address tokens to remove from `destination-address`. | `destination-exclude: MAIL_SERVERS` |  |
| `destination-port` | One or more destination service tokens. | `destination-port: HTTP HTTPS` |  |
| `expiration` | Stop rendering the term after this date (`YYYY-MM-DD`). | `expiration: 2030-12-31` | Expired terms are skipped with a warning. Use `--exp_info` to be told about terms that expire soon. |
| `icmp-type` | ICMP types to match. | `icmp-type: echo-request echo-reply` | See [ICMP Types](icmp_types.md) for valid values. |
| `name` | Name of the term. | `name: accept-ssh` | Must be unique within a filter. Some platforms shorten long names. |
| `option` | Extra match options. | `option: tcp-established` | Valid values are listed in each generator's Option table. |
| `platform` | Render this term **only** for the listed targets. | `platform: juniper cisco` |  |
| `platform-exclude` | **Never** render this term for the listed targets. | `platform-exclude: gce` |  |
| `protocol` | Protocols to match, by name or number. | `protocol: tcp udp` |  |
| `source-address` | One or more source address tokens. | `source-address: INTERNAL` | Tokens are resolved from the naming definitions. |
| `source-exclude` | Address tokens to remove from `source-address`. | `source-exclude: RFC1918` |  |
| `source-port` | One or more source service tokens. | `source-port: DNS` |  |
| `verbatim` | Text copied into the output unchanged, keyed by target. | `verbatim: {juniper: "count my-counter;"}` | Only the entry for the target being generated is used. Handy as a stop-gap for features Aerleon doesn't support yet. A verbatim term can't contain other match tokens. |

<!-- --8<-- [end:common-tokens] -->

## Support by generator

Common tokens that some generators reject. Each generator page also lists the ones it doesn't support.

| Token | Not supported on | Notes |
|---|---|---|
| `destination-address` | cloudarmor |  |
| `destination-exclude` | aruba, cloudarmor, gcp_hf, nvueapi, windows_advfirewall, windows_ipsec |  |
| `destination-port` | cloudarmor |  |
| `expiration` | cloudarmor, gcp_hf |  |
| `icmp-type` | aruba, cloudarmor, gce, gcp_hf, k8s, windows_ipsec | Silently ignored on nokiasrl, openconfig and sonic (known issue). On nftables, a single value crashes the generator (known issue). |
| `option` | cloudarmor, gce, gcp_hf, k8s |  |
| `platform` | cloudarmor, nokiasrl, openconfig, sonic |  |
| `platform-exclude` | cloudarmor, nokiasrl, openconfig, sonic |  |
| `protocol` | cloudarmor |  |
| `source-exclude` | aruba, cloudarmor, gcp_hf, nvueapi, windows_advfirewall, windows_ipsec |  |
| `source-port` | aruba, cloudarmor, gce, gcp_hf, k8s |  |
| `verbatim` | cloudarmor, gce, gcp_hf, k8s, nftables, nokiasrl, nvueapi, openconfig, paloalto, pcap, sonic, windows_advfirewall, windows_ipsec |  |

## Example

A term that uses most of the common keys, rendered by the [Juniper](juniper.md) generator. Because of `platform-exclude: gce`, the term would be left out of a `gce` filter.

```yaml title="common.yaml"
filters:
  - header:
      targets:
        juniper: edge-inbound inet
    terms:
      - name: accept-ssh
        comment: "Allow SSH from bastions to internal hosts."
        source-address: BASTIONS
        destination-address: INTERNAL
        destination-exclude: MAIL_SERVERS
        destination-port: SSH
        protocol: tcp
        expiration: 2030-12-31
        platform-exclude: gce
        action: accept
```

```yaml title="definitions.yaml"
networks:
  BASTIONS:
    values:
      - address: 10.0.0.10/32
  INTERNAL:
    values:
      - address: 10.1.0.0/16
  MAIL_SERVERS:
    values:
      - address: 10.1.2.25/32
```

```text title="common.jcl"
firewall {
    family inet {
        /*
         ** $Id:$
         ** $Date:$
         ** $Revision:$
         **
         */
        replace: filter edge-inbound {
            interface-specific;
            /*
             ** Allow SSH from bastions to internal hosts.
             */
            term accept-ssh {
                from {
                    source-address {
                        10.0.0.10/32;
                    }
                    destination-address {
                        10.1.0.0/16;
                        10.1.2.25/32 except;
                    }
                    protocol tcp;
                    destination-port 22;
                }
                then accept;
            }
        }
    }
}
```
