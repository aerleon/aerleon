# aclcheck library

The `aclcheck` library (see `aclcheck.py`) to allow simple and easy checks on
how a particular network session will react when it passes through a policy
file.

## Goals

* Create an ACL verification library that permits easy integration into future tools
* Create ability to ensure critical services are not blocked when ACL changes occur resulting in service outages
* Allow secops engineers and customers to easily verify how specific connections may be handled by network filters
* Include command-line functionality for standalone usage

## Methods

An `AclCheck` object has the following methods available:

* `Matches()`: Return a list of aclcheck.Match objects.
* `ExactMatches()`: Do not return matches that are conditional, such as requiring an established TCP connection, or would continue on to the next term with an action of 'next'.
* `ActionMatch(action='foo')`: Only return matches where the action taken would be one of the following: _'accept', 'deny', 'reject', 'next', 'reject-with-tcp-rst'_.
* `DescribeMatches()`: Returns a text blob describing the matches that would occur.

## Match Object Methods

Most `AclCheck` methods return "match" objects which have the following properties:

* `action`: The action that will be taken in this matching term
* `filter`: The name of the filter containing this term
* `possibles`: A list of strings containing reasons why this may or may not match
* `qos`: The quality of service level applied to this term
* `term`: The name of the matching term

## Usage

The `AclCheck` code is designed to be used as a library. However, for ease of use a command-line interface is provided in the top directory of the installation.

```
./aclcheck_cmdline.py:
  --definitions-directory: Directory where the definitions can be found.
    (default: './def')
  -p,--policy-file: The NAC policy file to check (default='./policies/sample.pol')
  -d,--destination: Desintation IP address (default='200.1.1.1')
  -s,--source: Source IP address (default='11.1.1.1')
  --protocol: Protocol (default='tcp')
  --destination-port: Destination port number (default=80)
  --source-port: Source port number (default=1025)
```

e.g.:

```
 ./aclcheck.py --source-port 4096 --destination-port 80 -s 64.142.101.1 \
   -d 200.1.1.0/24 --protocol tcp -p ./policies/sample.pol
```

## Initialization

The `AclCheck` library must be initialized with the following arguments:

* [policy filename](PolicyFormat.md) (filename, text-blob of a policy, or policy object)
* source address (ip address)
* destination address (ip address)
* source port (numeric port)
* destination port (numeric port)
* protocol (tcp, udp, icmp, etc.)

The initialization process immediately processes the information to generate a list of possible matches. These matches are objects of type aclcheck.Match. A list of aclcheck.Match objects can be retrieved by calling the Matches() method. The Match objects have the following properties:

* filter (the specific filter within the policy that this match occured)
* term (the specific term within the filter that this match occured)
* action (the action specified by the matched term)
* possibles (a list of characteristics that may cause this term to match or not match, such as fragmentation or tcp flags.

## Primer

The following code snippet generates the prediction about a particular
network flow.

```python
from lib import naming
from lib import policy
from lib import aclcheck
defs = naming.Naming('./def')
pol = policy.ParsePolicy(open('./policies/sample.pol').read(), defs)
src = '64.142.101.126'
dst = '200.1.1.1'
sport = '4096'
dport = '25'
proto = 'tcp'
check = aclcheck.AclCheck(pol, src, dst, sport, dport, proto)
print str(check)
```

The output follows:

```
  filter: edge-inbound
          term: permit-tcp-established (possible match)
                accept if ['tcp-est']
          term: default-deny
                deny
  filter: edge-outbound
          term: default-accept
                accept
```

Alternatively, the individual details of each match can be used as follows:

```python
for match in check.Matches():
  print match.filter
  print match.term
  print match.action
  for next in match.possibles:
    print next
  print '---'
```

The output follows:

```
edge-inbound
permit-tcp-established
accept
tcp-est
---
edge-inbound
default-deny
deny
---
edge-outbound
default-accept
accept
---
```

When exact matches are desired (e.g. not tcp-established, action "next", etc.), you can access the ExactMatches() method:

```python
for match in check.ExactMatches():
  print match.filter
  print match.term
  print match.action
  for next in match.possibles:
    print next
  print '---'
```

The output follows:

```
edge-inbound
default-deny
deny
---
edge-outbound
default-accept
accept
---
```

Notice that `ExactMatches()` method output differs from Matches() in that the term "permit-tcp-established" no longer appears, since the terms has the "optional" argument requiring the session be an established TCP session.

## Future Development

The `AclCheck` was written to provide a common library for the development of network access control assurance and investigative tools.  The `AclCheck` class supports taking a policy argument that consists of either a filename, text-blob, or a policy object.  If a policy object is passed to `AclCheck`, the [naming](NamingLibrary.md) definitions_directory argument is ignored and may be set to `None`.  By passing an already existing policy object to `AclCheck`, the run-time is greatly reduced for making multiple calls compared to re-reading the policy and definitions for individual checks.
