# Generator Reference

A generator turns an Aerleon policy into the configuration format for one platform. The `targets` key in a filter's header picks the generator, and the rest of that line sets its options:

```yaml
filters:
  - header:
      targets:
        juniper: edge-inbound inet
    terms:
      - ...
```

Each generator has its own page with:

* **Header Format**: the options that can follow the target name.
* **Term Format**: the tokens the generator adds to the [Common](generators/common.md) set, or drops from it.
* **Actions** and **Option**: the `action` and `option` values the generator accepts, and how each one is rendered.
* **Output**: the output file's name and extension, then examples: the [sample policy](#sample-policy) rendered by the generator, and examples of the generator's own tokens, each with its rendered output.
* **Known Issues**: bugs that affect the generated output. Always the last section, and left out when there are none.

## Generators

Address families are listed as they are written in the header. The default is in **bold**. "Both" means the generator always renders IPv4 and IPv6 and takes no family option.

| Generator | Target | Renders | Address families | File suffix | Built on |
|---|---|---|---|---|---|
| [Arista](generators/arista.md) | `arista` | EOS access lists | **`inet`**, `inet6`, `mixed` | `.eacl` | Cisco |
| [Arista Traffic-Policy](generators/arista_tp.md) | `arista_tp` | EOS traffic-policies | `inet`, `inet6`, **`mixed`** | `.atp` | |
| [Aruba](generators/aruba.md) | `aruba` | ArubaOS access lists | **IPv4**, `inet6` | `.aacl` | |
| [Brocade](generators/brocade.md) | `brocade` | Brocade access lists | **`inet`**, `inet6`, `mixed` | `.bacl` | Cisco |
| [Cisco](generators/cisco.md) | `cisco` | IOS access lists | **`inet`**, `inet6`, `mixed` | `.acl` | |
| [CiscoASA](generators/ciscoasa.md) | `ciscoasa` | ASA access lists | IPv4 only | `.asa` | Cisco |
| [CiscoNX](generators/cisconx.md) | `cisconx` | NX-OS access lists | **`inet`**, `inet6`, `mixed` | `.nxacl` | Cisco |
| [CiscoXR](generators/ciscoxr.md) | `ciscoxr` | IOS XR access lists | **`inet`**, `inet6`, `mixed` | `.xacl` | Cisco |
| [Cloud Armor](generators/cloudarmor.md) | `cloudarmor` | Google Cloud Armor security policy rules (JSON) | **`inet`**, `inet6`, `mixed` | `.gca` | |
| [Fortigate](generators/fortigate.md) | `fortigate` | FortiOS firewall policies | `inet`, `inet6`, **`mixed`** | `.fgacl` | |
| [GCE](generators/gce.md) | `gce` | Google Compute Engine VPC firewall rules (JSON) | **`inet`**, `inet6`, `mixed` | `.gce` | |
| [GCP Hierarchical Firewall](generators/gcp_hf.md) | `gcp_hf` | Google Cloud hierarchical firewall policies (JSON) | **`inet`**, `inet6`, `mixed` | `.gcphf` | |
| [Ipset](generators/ipset.md) | `ipset` | iptables rules backed by ipset sets | **`inet`**, `inet6` | `.ips` | IpTables |
| [IpTables](generators/iptables.md) | `iptables` | `iptables-restore` rules | **`inet`**, `inet6` | none | |
| [Juniper](generators/juniper.md) | `juniper` | Junos firewall filters | **`inet`**, `inet6`, `mixed`, `bridge`, `ethernet-switching` | `.jcl` | |
| [Juniper EVO](generators/juniperevo.md) | `juniperevo` | Junos EVO firewall filters | as Juniper | `.evojcl` | Juniper |
| [Juniper MSMPC](generators/msmpc.md) | `msmpc` | Junos MS-MPC service filters | `inet`, `inet6`, **`mixed`** | `.msmpc` | |
| [JuniperSRX](generators/srx.md) | `srx` | SRX security policies | `inet`, `inet6`, **`mixed`** | `.srx` | |
| [K8s](generators/k8s.md) | `k8s` | Kubernetes `NetworkPolicy` (YAML) | Both | `.yml` | |
| [Nftables](generators/nftables.md) | `nftables` | `nft` rulesets | `inet`, `inet6`, `mixed` (required) | `.nft` | |
| [Nokia SR Linux](generators/nokiasrl.md) | `nokiasrl` | SR Linux ACL filters (JSON) | **`inet`**, `inet6`, `mixed` | `.srl_acl` | OpenConfig |
| [NSXv](generators/nsxv.md) | `nsxv` | NSX-V distributed firewall section (XML) | `inet`, `inet6`, `mixed` (required) | `.nsx` | |
| [NSXt](generators/nsxt.md) | `nsxt` | NSX-T security policy (JSON) | `inet`, `inet6`, `mixed` (required, but ignored) | `.nsxt` | |
| [NVUE API](generators/nvueapi.md) | `nvueapi` | Cumulus Linux NVUE ACLs (JSON) | `ipv4`, `ipv6` (required) | `.nvueapi.json` | |
| [OpenConfig](generators/openconfig.md) | `openconfig` | OpenConfig ACL sets (JSON) | **`inet`**, `inet6`, `mixed` | `.oacl` | |
| [PacketFilter](generators/packetfilter.md) | `packetfilter` | OpenBSD/FreeBSD `pf.conf` rules | **`inet`**, `inet6`, `mixed` | `.pf` | |
| [PaloAltoFW](generators/paloalto.md) | `paloalto` | PAN-OS security rules (XML) | **`inet`**, `inet6`, `mixed` | `.xml` | |
| [PcapFilter](generators/pcap.md) | `pcap` | pcap/BPF filter expressions | `inet`, `inet6`, **`mixed`** | `.pcap` | |
| [Proxmox](generators/proxmox.md) | `proxmox` | Proxmox VE firewall files | Both | `.prxmxfw` | |
| [SONiC](generators/sonic.md) | `sonic` | SONiC ACL sets (JSON) | **`inet`**, `inet6`, `mixed` | `.oacl` | OpenConfig |
| [Speedway](generators/speedway.md) | `speedway` | `iptables-restore` rules | **`inet`**, `inet6` | `.ipt` | IpTables |
| [SRXlo](generators/srxlo.md) | `srxlo` | Junos filters for SRX loopbacks | as Juniper | `.jsl` | Juniper |
| [Windows Advanced Firewall](generators/windows_advfirewall.md) | `windows_advfirewall` | `netsh advfirewall` commands | **`inet`**, `inet6` | `.bat` | |
| [WindowsIPSec](generators/windows_ipsec.md) | `windows_ipsec` | `netsh ipsec` commands. **Not available:** the generator isn't registered. | **`inet`**, `inet6` | `.bat` | |

## Sample policy

Every generator page's Examples section starts with this policy rendered by that generator, so you can compare the output across platforms. Only the `targets` line changes; the terms are included from this page. The exception is [Cloud Armor](generators/cloudarmor.md), which only matches on source addresses, so its sample leaves out `protocol` and `destination-port`. Examples after the sample show generator-specific tokens.

```yaml title="sample.yaml"
filters:
  - header:
      targets:
        juniper: edge-inbound inet
# --8<-- [start:sample-terms]
    terms:
      - name: allow-ssh
        comment: "Allow SSH from the management network."
        source-address: MGMT
        protocol: tcp
        destination-port: SSH
        action: accept
      - name: default-deny
        action: deny
# --8<-- [end:sample-terms]
```

```yaml title="definitions.yaml"
networks:
  MGMT:
    values:
      - address: 10.0.0.0/24
      - address: 192.168.10.0/24
services:
  SSH:
    - port: 22
      protocol: tcp
```

Each output file is named after the policy file, with the generator's extension (see the File suffix column above). The outputs are the files `aclgen` writes, unchanged. The exceptions are [PcapFilter](generators/pcap.md), which `aclgen` currently can't render, and [WindowsIPSec](generators/windows_ipsec.md), which isn't registered. Their pages say how their output was produced.

## Reference

* [Common](generators/common.md): the tokens every generator accepts.
* [ICMP Types](generators/icmp_types.md): valid `icmp-type` names and their type numbers.
