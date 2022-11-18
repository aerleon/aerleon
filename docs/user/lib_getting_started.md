# Getting Started with the App

## Install the App

To install the App, please follow the instructions detailed in the [Installation Guide](../admin/install.md).

## Add Addresses

Create address objects that you will be able to refer to later in your firewall rules. Create a `.net` file, as an example:

```
RFC1918 = 10.0.0.0/8      # non-public
          172.16.0.0/12   # non-public
          192.168.0.0/16  # non-public

INTERNAL = RFC1918
```

For a more details on managing addresses, see [Address Files](../lib_address/).

## Add Services

Create address objects that you will be able to refer to later in your firewall rules. Create a `.svc` file, as an example:

```
SSH = 22/tcp
TELNET = 23/tcp
```

For a more details on managing services, see [Service Files](../lib_service/).

## Add Policy

Create policies that represent the firewall rules. Create a `.pol` file, as an example:

```
header {
  comment:: "sample arista traffic policy"
  target:: arista_tp MIXED-TRAFFIC-POLICY mixed
}

term accept-icmp {
  protocol:: icmp
  counter:: icmp-loopback
  icmp-type:: echo-request echo-reply
  action:: accept
}
```

For a more details on managing polcies, see [Policy Files](../lib_policy/).


## Usage

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

## Examples

The `aclgen` script will visit each policy file in the policies directory `./policies` and place generated firewall configs in the current directory. To get started, create a policy file and run:

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