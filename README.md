# Aerleon

Generate firewall configs for multiple platforms at once.

Aerleon is a fork of Capirca with the following enhancements:

- Support for new firewall platforms can be added through plugins. Plugins for
  common platforms are built-in. Users with experimental or non-public platforms
  can add support without forking this repo.
- Policy files can be given as YAML (.pol.yaml).
- Address Book data can be loaded from standard data formats like JSON, CSV.
- Existing .net, .svc and .pol files are still supported.
- Remote Address Book sources are supported. Users can link directly to IPAM.
- Performance is generally faster.
- A well-documented Python API is provided which accepts native types.
- A cleaner test harness is provided for end-to-end tests.
- "Shade checking" is faster and more correct.
- --help mode is much cleaner.

## Using Aerleon

Aerleon provides a command-line script `aclgen` which will generate firewall
ACLs from high-level policy files.

Each [policy file](#policy-files) in the input directory is visited and ACLs are
generated from the _term_ and _header_ blocks within. ACLs are then rendered to
one or more platform-specific configs according to the ‘target’ keyword(s) used.

Symbolic names can be used for IP networks, hosts, and services defined in the
[Address Book](#address-book).

A [Getting Started](wiki/getting-started.md) guide can be found on the wiki.

### Examples

The `aclgen` script will visit each policy file in the policies directory
`./policies` and place generated firewall configs in the current directory. To
get started, create a policy file and run:

```
aclgen
```

You can configure the input and output directories through the command line:

```
aclgen --input-dir ./acl-policies \
  --input-dir ./address-book-generated \
  --input-dir ./address-book-static \
  --output-dir ./acl-generated
```

See [Usage](#usage) for more details.

### Supported Platforms

The following list contains links to the documentation of the individual policy
generators:

<!-- begin-generator-term-links -->

- [`arista`](./doc/generators/arista.md): Arista
- [`aruba`](./doc/generators/aruba.md): Aruba
- [`brocade`](./doc/generators/brocade.md): Brocade
- [`cisco`](./doc/generators/cisco.md): Cisco
- [`ciscoasa`](./doc/generators/ciscoasa.md): Cisco ASA
- [`cisconx`](./doc/generators/cisconx.md): Cisco NX
- [`ciscoxr`](./doc/generators/ciscoxr.md): Cisco XR
- [`cloudarmor`](./doc/generators/cloudarmor.md): cloudarmor
- [`gce`](./doc/generators/gce.md): GCE
- `gcp_hf`
- [`ipset`](./doc/generators/ipset.md): ipset
- [`iptables`](./doc/generators/iptables.md): iptables
- [`juniper`](./doc/generators/juniper.md): Juniper
- [`juniperevo`](./doc/generators/juniperevo.md): Juniper EVO
- [`junipermsmpc`](./doc/generators/junipermsmpc.md): Juniper
- [`junipersrx`](./doc/generators/junipersrx.md): Juniper SRX
- [`k8s`](./doc/generators/k8s.md): Kubernetes NetworkPolicy
- [`nftables`](./doc/generators/nftables.md): nftables
- [`nsxv`](./doc/generators/nsxv.md): NSX
- [`packetfilter`](./doc/generators/packetfilter.md): PacketFilter
- [`paloaltofw`](./doc/generators/paloaltofw.md): Palo Alto PANOS
- [`pcap`](./doc/generators/pcap.md): PcapFilter
- [`speedway`](./doc/generators/speedway.md): Speedway
- [`srxlo`](./doc/generators/srxlo.md): Stateless Juniper ACL
- [`windows_advfirewall`](./doc/generators/windows_advfirewall.md): Windows
  Advanced Firewall <!-- begin-generator-term-links -->

See also [Adding A Platform Generator](wiki/adding-a-platform-generator.md) on
the wiki.

### Usage

```
  Usage: aclgen [OPTION]... Generate firewall configs for multiple platforms at
  once

  Each policy file (.pol, .pol.yaml) in the input directory is visited and ACLs
  are generated from the term and header blocks within. Symbolic names that
  reference address book files (.net) in the input directory can be used for IP
  networks, hosts, and services. ACLs are then rendered to one or more
  platform-specific configs according to the ‘target’ keyword(s) used.

  Policy files can be given as .pol files or .pol.yaml files. Address books are
  defined by .net, .net.json, or .net.csv files.

  Where OPTION is:

    --input-dir=DIRECTORY: Search this directory recursively for input files.
    Defaults to ‘./policies’. If ‘--input-dir’ is given multiple times, all given
    directories will be searched.

    --output-dir=DIRECTORY: Place all generated files here. Defaults to the current
    working directory.

    --config=FILE: Read configuration options from FILE (JSON). Defaults to
    ‘./config.json’. The command line value is used if an option is provided in both
    the command line and the configuration file. Some options are only available in
    the configuration file.

    --plugin-dir=DIRECTORY: Search this directory recursively for plugins. Defaults
    to ‘./plugins. If ‘--plugin-dir’ is given multiple times, all given directories
    will be searched.

    --dry-run: Do not write out any output files.

    --help: Display this message.

    --version: Display version information.
```

## Policy Files

A policy file describes a security policy using _header_ and _term_ blocks.
Header blocks describe how to generate the output configuration of the security
policy. Term blocks define the access control rules within an ACL.

In .pol.yaml files, each ACL has exactly one header and one or more term
sections. In .pol file format, each ACL is defined by a top-level header block
followed by one or more top-level term blocks.

```yaml
acls:
  - header:
      comment:
        this is a sample policy for a zone based filter that generates multiple
        output formats. It checks logging options, tcp, udp and icmp type
        options.
      targets:
        paloalto: from-zone internal to-zone external
        srx: from-zone internal to-zone external
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

See [Policy Files](wiki/policy-files.md) on the wiki for full details.

## Address Book

Address book files define symbolic names for IP networks, hosts, and services.
Policy files may reference these names.

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

Users may wish to auto-generate address book files to keep them up to date. JSON
and CSV are accepted for this reason. See [Address Book](wiki/address-book.md)
on the wiki for full details.

## Advanced Usage

The `aerleon` Python package also provides a Python API. See
[Python Package](wiki/python-package.md) on the wiki.

To build from source, see
[Getting Started With Source](wiki/getting-started-source.md) on the wiki.

## Contributing

Contributions are welcome. Please review the contributing guidelines and code of
conduct for this project.

The [Getting Started With Source](wiki/getting-started-source.md) guide has
information on how to approach code changes to this project.

## Resources

Aerleon is a fork of Capirca.

Additional documentation:

- [aclcheck library](./doc/wiki/AclCheck-library.md)
- [policy reader library](./doc/wiki/PolicyReader-library.md)
- [policy library](./doc/wiki/Policy-library.md)
- [naming library](./doc/wiki/Naming-library.md)
- [capirca design doc](./doc/wiki/Capirca-design.md)

External links, resources and references:

- [Brief Overview (4 slides):](https://docs.google.com/present/embed?id=dhtc9k26_13cz9fphfb&autoStart=true&loop=true&size=1)
- [Nanog49; Enterprise QoS](http://www.nanog.org/meetings/nanog49/presentations/Tuesday/Chung-EnterpriseQoS-final.pdf)
- [#aerleon at NetworkToCode Slack](https://networktocode.slack.com/)

## Credit

Files and code included in this project from Capirca are copyright Google and
are included under the terms of the Apache License, Version 2.0. You may obtain
a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Contributors who wish to modify files bearing a copyright notice are obligated
by the terms of the Apache License, Version 2.0 to include at the top of the
file a prominent notice stating as much. Copyright notices must not be removed
from files in this repository.

This README file may contain phrases and sections that are copyright Google.
This file is modified from the original.
