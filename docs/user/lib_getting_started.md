# Getting Started with Aerleon

The following sections will take you through a guided tour of Aerleon. We will cover general concepts such as Policy files, Network and Service defintions and putting them together to output firewall configurations.

## Setup
This tutorial assumes you are working on a Linux operating system and have completed the installation instructions

You will want to make a temporary directory with the following folder structure.
```bash
.
├── def
└── policies
    └── pol
```
You can do this by executing the following mkdir commands
```bash
mkdir -p aerleon_test/def
mkdir -p aerleon_test/policies/pol
cd aerleon_test
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
      - FIX ME" > defs/definitions.yml

  ```
</details>


# Policy Files
A policy file describes rules to be used to filter traffic at some point in your network. This may be a single point or multiple points that all share the same rules. With Aerleon you define your rules in YAML and output the correct syntax for different firewalls. In our example we will make a simple firewall that filters both ingress and egress traffic.

```yaml
acls:
  - header:
      comment: Example inbound
      targets:
        - target: cisco
          options: inbound mixed
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
```
The above YAML is an basic example with almost the minimum neccesary to output an ACL. We have `acl` as the top keyword and a single `header` `terms` pair.

Inside of the `header` we have a comment to explain what this ACL is for, a `target` of cisco meaning we wish to output that syntax, and options for the cisco generator.

`terms` contains a list of terms which are translated into rules within the ACL. In this case there are two rules. `accept-web-servers` and `default-deny`. We see that in `accept-web-servers` there are a few fields such as `comment`, `destination-address`, `action` and more. You can find more information on every field available in [insert link](foobar). `destination-address` and `destination-port` each refer to names we configured in our definitions. When this rule gets translated the definitions will be referenced and used to define the IPs and ports for this rule.

<details>
  <summary>Bash command</summary>

  ```bash
  echo "acls:
  - header:
      comment: Example inbound
      targets:
        - target: cisco
          options: inbound mixed
    terms:
      - name: accept-web-servers
        comment: Accept connections to our web servers
        destination-address: WEB_SERVERS
        destination-port: WEB_SERVICES
        protocol: tcp
        action: accept
      - name: default-deny
        comment: Deny anything else.
        action: deny" > policies/pol/example.yml

  ```
</details>