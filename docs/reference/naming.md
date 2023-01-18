# Introduction

The naming library is used by the Aerleon system to parse definitions of network
and service data. These definitions are based on 'tokens' that are used in the
high-level [policy language](Policy-format.md).

## Basic Usage

**Create a directory to hold the definitions files**

```bash
mkdir /path/to/definitions/directory
```

**Create network definitions files**
_(network defintions files must end in '.net')_

```
cat > /path/to/definitions/directory/NETWORKS.net
INTERNAL = 10.0.0.0/8     # RFC1918
           172.16.0.0/12  # RFC1918
           192.168.0.0/16 # RFC1918
WEBSERVERS = 200.3.2.1/32 # webserver-1
             200.3.2.4/32 # webserver-2
MAILSERVER = 200.3.2.5/32 # mailserver-1
^D
```

**Create service definitions files**
_(service defintions files must end in '.svc')_

```
cat > /path/to/definitions/directory/SERVICES.svc
HTTP = 80/tcp  # web traffic
MAIL = 25/tcp  # smtp port
       465/tcp # smtp over ssl
DNS = 53/tcp
      53/udp
^D
```

**Create a naming object**

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
