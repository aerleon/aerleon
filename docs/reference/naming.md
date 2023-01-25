# Introduction

The naming library is used by the Aerleon system to parse definitions of network
and service data. These definitions are based on 'tokens' that are used in the
high-level [policy language](Policy-format.md).

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

```
**GetIpParents(self, query)**
> Return network tokens that contain IP in query.
> Args:
> > query: an ip string ('10.1.1.1') or nacaddr.IP object
> Returns:
> > rval2: a list of tokens containing this IP
**GetNet(self, query)**
> Expand a network token into a list of nacaddr.IP objects.
> Args:
> > query: Network definition token which may include comment text
> Raises:
> > BadNetmaskTypeError: Results when an unknown netmask\_type is
> > specified.  Acceptable values are 'cidr', 'netmask', and 'hostmask'.
> Returns:
> > List of nacaddr.IP objects
> Raises:
> > UndefinedAddressError: for an undefined token value
**GetNetAddr(self, token)**
> Given a network token, return a list of nacaddr.IP objects.
> Args:
> > token: A name of a network definition, such as 'INTERNAL'
> Returns:
> > A list of nacaddr.IP objects.
> Raises:
> > UndefinedAddressError: if the network name isn't defined.
**GetService(self, query)**
> Given a service name, return a list of associated ports and protocols.
> Args:
> > query: Service name symbol or token.
> Returns:
> > A list of service values such as ['80/tcp', '443/tcp', '161/udp', ...]
**GetServiceByProto(self, query, proto)**
> Given a service name, return list of ports in the service by protocol.
> Args:
> > query: Service name to lookup.
> > proto: A particular protocol to restrict results by, such as 'tcp'.
> Returns:
> > A list of service values of type 'proto', such as ['80', '443', ...]
**GetServiceParents(self, query)**
> Given a service, return any tokens containing the value.
> Args:
> > query: a service or token name, such as 53/tcp or DNS
> Returns:
> > rval2: a list of tokens that contain query or parents of query
**ParseNetworkList(self, data)**
> Take an array of network data and import into class.
> This method allows us to pass an array of data that contains network
> definitions that are appended to any definitions read from files.
> Args:
> > data: array of text lines containing net definitions.
**ParseServiceList(self, data)**
> Take an array of service data and import into class.
> This method allows us to pass an array of data that contains service
> definitions that are appended to any definitions read from files.
> Args:
> > data: array of text lines containing service definitions.
```
