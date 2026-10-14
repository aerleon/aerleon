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
* **Term Format**: the tokens the generator adds to the [Common](common.md) set, or drops from it.
* **Actions** and **Option**: the `action` and `option` values the generator accepts, and how each one is rendered.
* **Known Issues**: bugs that affect the generated output. Always the last section, and left out when there are none.

## Generators

Address families are listed as they are written in the header. The default is in **bold**. "Both" means the generator always renders IPv4 and IPv6 and takes no family option.

| Generator | Target | Renders | Address families | File suffix | Built on |
|---|---|---|---|---|---|
| [Arista](arista.md) | `arista` | EOS access lists | **`inet`**, `inet6`, `mixed` | `.eacl` | Cisco |
| [Arista Traffic-Policy](arista_tp.md) | `arista_tp` | EOS traffic-policies | `inet`, `inet6`, **`mixed`** | `.atp` | |
| [Aruba](aruba.md) | `aruba` | ArubaOS access lists | **IPv4**, `inet6` | `.aacl` | |
| [Brocade](brocade.md) | `brocade` | Brocade access lists | **`inet`**, `inet6`, `mixed` | `.bacl` | Cisco |
| [Cisco](cisco.md) | `cisco` | IOS access lists | **`inet`**, `inet6`, `mixed` | `.acl` | |
| [CiscoASA](ciscoasa.md) | `ciscoasa` | ASA access lists | IPv4 only | `.asa` | Cisco |
| [CiscoNX](cisconx.md) | `cisconx` | NX-OS access lists | **`inet`**, `inet6`, `mixed` | `.nxacl` | Cisco |
| [CiscoXR](ciscoxr.md) | `ciscoxr` | IOS XR access lists | **`inet`**, `inet6`, `mixed` | `.xacl` | Cisco |
| [Cloud Armor](cloudarmor.md) | `cloudarmor` | Google Cloud Armor security policy rules (JSON) | **`inet`**, `inet6`, `mixed` | `.gca` | |
| [Fortigate](fortigate.md) | `fortigate` | FortiOS firewall policies | `inet`, `inet6`, **`mixed`** | `.fgacl` | |
| [GCE](gce.md) | `gce` | Google Compute Engine VPC firewall rules (JSON) | **`inet`**, `inet6`, `mixed` | `.gce` | |
| [GCP Hierarchical Firewall](gcp_hf.md) | `gcp_hf` | Google Cloud hierarchical firewall policies (JSON) | **`inet`**, `inet6`, `mixed` | `.gcphf` | |
| [Ipset](ipset.md) | `ipset` | iptables rules backed by ipset sets | **`inet`**, `inet6` | `.ips` | IpTables |
| [IpTables](iptables.md) | `iptables` | `iptables-restore` rules | **`inet`**, `inet6` | none | |
| [Juniper](juniper.md) | `juniper` | Junos firewall filters | **`inet`**, `inet6`, `mixed`, `bridge`, `ethernet-switching` | `.jcl` | |
| [Juniper EVO](juniperevo.md) | `juniperevo` | Junos EVO firewall filters | as Juniper | `.evojcl` | Juniper |
| [Juniper MSMPC](msmpc.md) | `msmpc` | Junos MS-MPC service filters | `inet`, `inet6`, **`mixed`** | `.msmpc` | |
| [JuniperSRX](srx.md) | `srx` | SRX security policies | `inet`, `inet6`, **`mixed`** | `.srx` | |
| [K8s](k8s.md) | `k8s` | Kubernetes `NetworkPolicy` (YAML) | Both | `.yml` | |
| [Nftables](nftables.md) | `nftables` | `nft` rulesets | `inet`, `inet6`, `mixed` (required) | `.nft` | |
| [Nokia SR Linux](nokiasrl.md) | `nokiasrl` | SR Linux ACL filters (JSON) | **`inet`**, `inet6`, `mixed` | `.srl_acl` | OpenConfig |
| [NSXv](nsxv.md) | `nsxv` | NSX-V distributed firewall section (XML) | `inet`, `inet6`, `mixed` (required) | `.nsx` | |
| [NSXt](nsxt.md) | `nsxt` | NSX-T security policy (JSON) | `inet`, `inet6`, `mixed` (required, but ignored) | `.nsxt` | |
| [NVUE API](nvueapi.md) | `nvueapi` | Cumulus Linux NVUE ACLs (JSON) | `ipv4`, `ipv6` (required) | `.nvueapi.json` | |
| [OpenConfig](openconfig.md) | `openconfig` | OpenConfig ACL sets (JSON) | **`inet`**, `inet6`, `mixed` | `.oacl` | |
| [PacketFilter](packetfilter.md) | `packetfilter` | OpenBSD/FreeBSD `pf.conf` rules | **`inet`**, `inet6`, `mixed` | `.pf` | |
| [PaloAltoFW](paloalto.md) | `paloalto` | PAN-OS security rules (XML) | **`inet`**, `inet6`, `mixed` | `.xml` | |
| [PcapFilter](pcap.md) | `pcap` | pcap/BPF filter expressions | `inet`, `inet6`, **`mixed`** | `.pcap` | |
| [Proxmox](proxmox.md) | `proxmox` | Proxmox VE firewall files | Both | `.prxmxfw` | |
| [SONiC](sonic.md) | `sonic` | SONiC ACL sets (JSON) | **`inet`**, `inet6`, `mixed` | `.oacl` | OpenConfig |
| [Speedway](speedway.md) | `speedway` | `iptables-restore` rules | **`inet`**, `inet6` | `.ipt` | IpTables |
| [SRXlo](srxlo.md) | `srxlo` | Junos filters for SRX loopbacks | as Juniper | `.jsl` | Juniper |
| [Windows Advanced Firewall](windows_advfirewall.md) | `windows_advfirewall` | `netsh advfirewall` commands | **`inet`**, `inet6` | `.bat` | |
| [WindowsIPSec](windows_ipsec.md) | `windows_ipsec` | `netsh ipsec` commands. **Not available:** the generator isn't registered. | **`inet`**, `inet6` | `.bat` | |

## Reference

* [Common](common.md): the tokens every generator accepts.
* [ICMP Types](icmp_types.md): valid `icmp-type` names and their type numbers.
