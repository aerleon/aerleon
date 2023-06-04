# Introduction

The naming library is used by the Aerleon system to parse definitions of network
and service data. These definitions are based on 'tokens' that are used in the
high-level [policy language](yaml_reference.md).

## Basic Usage

**Create a directory to hold the definitions files**

```bash
mkdir /path/to/definitions/directory
```

**Create a definition YAML file**

```
cat > /path/to/definitions/directory/definitions.yaml
networks:
  INTERNAL:
    values:
      - address: 10.0.0.0/8
        comment: "RFC1918"
      - address: 172.16.0.0/12
        comment: "RFC1918"
      - address: 192.168.0.0/16
        comment: "RFC1918"
  WEB_SERVERS:
    values:
      - address: 200.3.2.1/32
        comment: "webserver-1"
      - address: 200.3.2.4/32
        comment: "webserver-2"
  MAIL_SERVERS:
    values:
      - address: 200.3.2.5/32
        comment: "mailserver-1"
      - address: 200.3.2.6/32
        comment: "mailserver-2"
services:
  MAIL_SERVICES:
    - name: SMTP
    - name: ESMTP
    - name: SMTP_SSL
    - name: POP_SSL
  SMTP:
    - port: 25
      protocol: tcp
  DNS:
    - port: 53
      protocol: tcp
    - port: 53
      protocol: udp
  HTTP:
    - port: 80
      protocol: tcp
      comment: "web traffic"
  SMTP_SSL:
    - port: 465
      protocol: tcp
  ESMTP:
    - port: 587
      protocol: tcp
  POP_SSL:
    - port: 995
      protocol: tcp
^D
```

**Create a Naming object**

```
from aerleon.lib import naming
defs = naming.Naming('/path/to/definitions/directory')
```

**Access Definitions From the Naming Object**

```
defs.GetNet('INTERNAL')
defs.GetService('MAIL')
defs.GetServiceByProto('DNS','udp')
```

## Methods

### Network Query Methods

#### Naming.GetNet(query: str) -> List[Union[IPv4, IPv6]]
::: aerleon.lib.naming.Naming.GetNet
    options:
      show_source: false
      show_root_heading: false
      show_root_toc_entry: false

#### Naming.GetIpParents(query: str) -> List[str]
::: aerleon.lib.naming.Naming.GetIpParents
    options:
      show_source: false
      show_root_heading: false
      show_root_toc_entry: false

#### Naming.GetNetParents(query: str) -> List[str]
::: aerleon.lib.naming.Naming.GetNetParents
    options:
      show_source: false
      show_root_heading: false
      show_root_toc_entry: false

#### Naming.GetNetChildren(query: str) -> List[str]
::: aerleon.lib.naming.Naming.GetNetChildren
    options:
      show_source: false
      show_root_heading: false
      show_root_toc_entry: false

#### Naming.GetFQDN(query: str) -> List[str]
::: aerleon.lib.naming.Naming.GetFQDN
    options:
      show_source: false
      show_root_heading: false
      show_root_toc_entry: false

### Service Query Methods

#### Naming.GetService(query: str) -> List[str]
::: aerleon.lib.naming.Naming.GetService
    options:
      show_source: false
      show_root_heading: false
      show_root_toc_entry: false

#### Naming.GetServiceByProto(query: str, proto: str) -> List[str]
::: aerleon.lib.naming.Naming.GetServiceByProto
    options:
      show_source: false
      show_root_heading: false
      show_root_toc_entry: false

#### Naming.GetPortParents(query: str) -> List[str]
::: aerleon.lib.naming.Naming.GetPortParents
    options:
      show_source: false
      show_root_heading: false
      show_root_toc_entry: false

#### Naming.GetServiceParents(query: str) -> List[str]
::: aerleon.lib.naming.Naming.GetServiceParents
    options:
      show_source: false
      show_root_heading: false
      show_root_toc_entry: false

### Data Loading Methods

#### Naming.ParseYaml
::: aerleon.lib.naming.Naming.ParseYaml
    options:
      show_source: false
      show_root_heading: false
      show_root_toc_entry: false

#### Naming.ParseDefinitionsObject
::: aerleon.lib.naming.Naming.ParseDefinitionsObject
    options:
      show_source: false
      show_root_heading: false
      show_root_toc_entry: false
