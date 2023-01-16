# Getting Started with Aerleon

The following sections will take you through a guided tour of Aerleon. We will cover general concepts such as Policy files, Network and Service definitions and putting them together to output firewall configurations.

## Setup
> **_NOTE:_**  This tutorial assumes you are working on a Linux operating system and have completed the [installation instructions](/en/latest/user/install/).

You will want to make a temporary directory with the following structure.
```bash
.
├── def
└── policies
    └── pol
```
You can do this with the following commands.
```bash
mkdir -p aerleon_test/def
mkdir -p aerleon_test/policies/pol
cd aerleon_test
```

The rest of this walkthrough will assume you are within the `aerleon_test` directory.
## Definition Files
Definition files allow you to define Networks and Services used in your policies. Generally it is much easier to read a name like `WEB_SERVERS` rather than a list of IP addresses. It is also beneficial to compose definitions together in certain places.

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

Above we have defined a couple of networks and services.
* `RFC1918` is defined as three IP subnets.
* `WEB_SERVERS` and `MAIL_SERVERS` are both two IP hosts and include a comment about those IPs.
* `ALL_SERVERS` is a composite of both `WEB_SERVERS` and `MAIL_SERVERS`.
* `HTTP` is defined as port 80 over TCP while `HTTPS` is port 443 over TCP.
* `WEB` is a composit of both `HTTP` and `HTTPS`.
* `HIGH_PORTS` is a port range of of 1024 to 65535 over both TCP and UDP.

Take the YAML above and insert it into a file in the `defs` directory.
<details>
  <summary>Bash command</summary>

  ```bash
  $ echo "networks:
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
" > def/definitions.yaml

  ```
</details>


## Policy Files
A policy file describes rules to be used to filter traffic at some point in your network. This may be a single point or multiple points that all share the same rules. With Aerleon you define your rules in YAML and output the correct syntax for different firewalls. In our example we will make a simple firewall that filters both ingress and egress traffic.

```yaml
filters:
  - header:
      comment: Example inbound
      targets:
        cisco: inbound extended
    terms:
      - name: accept-web-servers
        comment: Accept connections to our web servers.
        destination-address: WEB_SERVERS
        destination-port: WEB
        protocol: tcp
        action: accept
      - name: default-deny
        comment: Deny anything else.
        action: deny
```
The above YAML is a basic example with almost the minimum necessary to output an ACL. We have `filters` as the top keyword and a single `header` `terms` pair.

Inside of the `header` we have a comment to explain what this ACL is for, a `target` of cisco meaning we wish to output that syntax, and options for the cisco generator.

`terms` contains a list of terms which are translated into rules within the ACL. In this case there are two rules. `accept-web-servers` and `default-deny`. We see that in `accept-web-servers` there are a few fields such as `comment`, `destination-address`, `action` and more. You can find more information on every field available in [insert link](foobar). `destination-address` and `destination-port` each refer to names we configured in our definitions. When this rule gets translated the definitions will be referenced and used to define the IPs and ports for this rule.

<details>
  <summary>Bash command</summary>

  ```bash
  $ echo "filters:
  - header:
      comment: Example inbound
      targets:
        cisco: inbound extended
    terms:
      - name: accept-web-servers
        comment: Accept connections to our web servers
        destination-address: WEB_SERVERS
        destination-port: WEB
        protocol: tcp
        action: accept
      - name: default-deny
        comment: Deny anything else.
        action: deny" > policies/pol/example.pol.yaml

  ```
</details>

## Running ACLGen

At this point we have definitions and a policy. We can run `aclgen` to get the config we can use on our firewall.

```bash
$ aclgen
I0116 04:17:57.260641 139822104141824 aclgen.py:451] finding policies...
W0116 04:17:57.263273 139822104141824 aclgen.py:369] --> policies/pol (1 pol files found)
I0116 04:17:57.396398 139822104141824 plugin_supervisor.py:249] 0 plugins active.
I0116 04:17:57.397953 139822104141824 plugin_supervisor.py:250] 27 generators registered.
I0116 04:17:57.401166 139822104141824 aclgen.py:297] file changed: example.pol.acl
I0116 04:17:57.423281 139822104141824 aclgen.py:384] writing 1 files to disk...
I0116 04:17:57.424398 139822104141824 aclgen.py:403] writing file: example.pol.acl
I0116 04:17:57.427682 139822104141824 aclgen.py:517] done.
```

We can see in the output that a file with the extension `.acl` has been written to the directory. Inspecting this file we can see it contains the rules we configured in our YAML file but translated to Cisco format.

## Adding Additional ACLs

We currently have an inbound ACL but we wish to add an outbound ACL. In this case we append another `header` and `terms` section to our `filters`.

```yaml
filters:
  - header:
      comment: Example inbound
      targets:
        cisco: inbound extended
    terms:
      - name: accept-web-servers
        comment: Accept connections to our web servers
        destination-address: WEB_SERVERS
        destination-port: WEB
        protocol: tcp
        action: accept
      - name: default-deny
        comment: Deny anything else.
        action: deny
  - header:
      comment: Example outbound
      targets:
        cisco: outbound mixed
    terms:
      - name: deny-bad-destinations
        destination-address: RFC1918
        action: deny
      - name: default-accept
        action: accept
```


<details>
  <summary>Bash command</summary>

  ```bash
  echo "filters:
  - header:
      comment: Example inbound
      targets:
        cisco: inbound extended
    terms:
      - name: accept-web-servers
        comment: Accept connections to our web servers
        destination-address: WEB_SERVERS
        destination-port: WEB
        protocol: tcp
        action: accept
      - name: default-deny
        comment: Deny anything else.
        action: deny
  - header:
      comment: Example outbound
      targets:
        cisco: outbound extended
    terms:
      - name: deny-bad-destinations
        destination-address: RFC1918
        action: deny
      - name: default-accept
        action: accept" > policies/pol/example.pol.yaml
  ```
</details>

If you run `aclgen` again you will see it notices the difference in the YAML file and writes over the old ACL. This new ACL contains both the inbound and outbound ACLs we wanted.

## Adding Additional Platforms
In this example we have been generating a Cisco config. What happens though if you want to switch over to Juniper for some reason. Either you bought a new Juniper device and are migrating, or you have a one off that requires the same rules. This is simple to do, we just add a header option for Juniper.

```yaml
filters:
  - header:
      comment: Example inbound
      targets:
        cisco: inbound extended
        juniper: inbound
    terms:
      - name: accept-web-servers
        comment: Accept connections to our web servers
        destination-address: WEB_SERVERS
        destination-port: WEB
        protocol: tcp
        action: accept
      - name: default-deny
        comment: Deny anything else.
        action: deny
  - header:
      comment: Example outbound
      targets:
        cisco: outbound mixed
        juniper: outbound
    terms:
      - name: deny-bad-destinations
        destination-address: RFC1918
        action: deny
      - name: default-accept
        action: accept
```

<details>
  <summary>Bash command</summary>

  ```bash
  echo "filters:
  - header:
      comment: Example inbound
      targets:
        cisco: inbound extended
        juniper: inbound
    terms:
      - name: accept-web-servers
        comment: Accept connections to our web servers
        destination-address: WEB_SERVERS
        destination-port: WEB
        protocol: tcp
        action: accept
      - name: default-deny
        comment: Deny anything else.
        action: deny
  - header:
      comment: Example outbound
      targets:
        cisco: outbound mixed
        juniper: outbound
    terms:
      - name: deny-bad-destinations
        destination-address: RFC1918
        action: deny
      - name: default-accept
        action: accept" > policies/pol/example.pol.yaml
  ```
</details>

If you run `aclgen` again you should see that it wrote two files now, the new one being `.jcl`. This is the Juniper file we wanted and will contain all the exact same rules but in the Juniper syntax.