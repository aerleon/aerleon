# Getting Started with Aerleon

The following sections will take you through a guided tour of Aerleon. We will cover general concepts such as Policy files, Network and Service defintions and putting them together to output firewall configurations.

## Setup
You will want to make a temporary directory with the following folder structure.
```bash
temp_dir
    ├── defs
    ├── policies
    │   └── pol
```
You can do this by executing the following mkdir commands
```bash
mkdir -p aerleon_test/defs
mkdir -p aerleon_test/policies/pol
```

## Definition Files
Definition files allow you to define Networks and Services used in your policies. Generally it is much easier to read a name like `WEB_SERVERS` rather than a list of IP addresses. It is also beneficial to composit definitions together in certain places.

```yaml
networks:
  RFC1918:
    values:
      - ip: 10.0.0.0/8
      - ip: 172.16.0.0/12
      - ip: 192.168.0.0/16
  WEB_SERVERS:
    values:
      - ip: 10.0.0.1/32
        comment: Web Server 1
      - ip: 10.0.0.2/32
        comment: Web Server 2
  MAIL_SERVERS:
    values:
      - ip: 10.0.0.3/32
        comment: Mail Server 1
      - ip: 10.0.0.4/32
        comment: Mail Server 2
  ALL_SERVERS:
    values:
      - WEB_SERVERS
      - MAIL_SERVERS
services:
  HTTP:
    - protocol: tcp
      port: 80
  HTTPS:
    - protocol: tcp
      port: 443
  WEB:
    - HTTP
    - HTTPS
  HIGH_PORTS:
    - FIX ME

```

Above we have a couple of networks and services defined.
* `RFC1918` is defined as three IP subnets.
* `WEB_SERVERS` and `MAIL_SERVERS` are both two IP hosts and include a comment about those IPs.
* `ALL_SERVERS` is a composit of both `WEB_SERVERS` and `MAIL_SERVERS`.
* `HTTP` is defined as port 80 over TCP while `HTTPS` is port 443 over TCP.
* `WEB` is a composit of both `HTTP` and `HTTPS`.
* `HIGH_PORTS` is a port range of of 1024 to 65535 over both TCP and UDP.

Take the yaml above and insert it into a file in the defs directory.
<details>
  <summary>Bash command</summary>
  ```bash
 echo "networks:
  RFC1918:
    values:
      - ip: 10.0.0.0/8
      - ip: 172.16.0.0/12
      - ip: 192.168.0.0/16
  WEB_SERVERS:
    values:
      - ip: 10.0.0.1/32
        comment: Web Server 1
      - ip: 10.0.0.2/32
        comment: Web Server 2
  MAIL_SERVERS:
    values:
      - ip: 10.0.0.3/32
        comment: Mail Server 1
      - ip: 10.0.0.4/32
        comment: Mail Server 2
  ALL_SERVERS:
    values:
      - WEB_SERVERS
      - MAIL_SERVERS
services:
  HTTP:
    - protocol: tcp
      port: 80
  HTTPS:
    - protocol: tcp
      port: 443
  WEB:
    - HTTP
    - HTTPS
  HIGH_PORTS:
    - FIX ME" > tmp/defs/definitions.yml
  
  ```
</details>

# Policy Files
A policy file describes a set of filters to be used to filter traffic at some point in your network. For a simple inline filter you may have only ingress and egress filters. For more complex setups there may be many filters. For example you may have a firewall with filters controlling access between the internet, your dmz, your corporate network and your production. For this example we will create a 

In policy files, each ACL has exactly one header and one or more term sections.

```yaml
acls:
  - header:
      comment: This is our inbound filter
      targets:
        - target: cisco
          options: inbound mixed
        - target: juniper
          options: inbound inet
    terms:
      - name: accept-web-servers
        comment: Accept connections to our web servers
        destination-address: WEB_SERVERS
        destination-port: WEB_SERVICES
        protocol: tcp
        action: accept
      - name: default-deny
        comment: Deny anything else.
        action: deny
  - header:
      comment: This is our outbound filter
      targets:
        - target: cisco
          options: inbound mixed
        - target: juniper
          options: inbound inet
    terms:
      - name: default-accept
        comment: Accept outgoing connections
        action: accept
```
The above is an ACL containing two filters, one for inbound and outbound. In this example we want `mixed` for cisco while `juniper` has `inet` as an option. This means that for Cisco outputs we want to 

The Terms section contains repeated `term` objects. These are the rules that you want to have in your firewalls. Each keyword such as `destination-address`, `protocol`, and `action` affect what is outputted. Each generator is different and some may support unique keywords. You should refer to the generator documentation<user/generators> for an exhaustive list.


 
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