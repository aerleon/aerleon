# Capirca Design Doc

Status: Final

Author: Tony Watson

Created: Nov 2, 2007

Last Updated: May 5, 2010

## Objective

Define a common meta-language to describe security policies, and a standardized interconnect between meta-language and actual policy rules. The meta-language should be flexible enough to support most common network access control (NAC) devices, but simple enough to be clear and easy to understand. The interconnect should provide a common understanding of how and where the meta-language and actual policy rules are stored.

## Goals

* Provide a standard meta-language to describe NAC policies
* Avoid the proliferation of differing ACL meta-language formats
* Provide a common framework for maintaining both meta-language policies and the actual applied NAC policy
* Provide a foundation for expanding automation of NAC processes
* Eliminate confusion and guesswork when implementing a new output format generator

## Background

Currently, the security group utilizes a variety of tools to automate the generation of ACL, F10, JCL, and Iptables policies. Historically, many automation tools have been built using Ruby around the naming.rb library. As these tools have been developed they have usually had unique limitations or requirements that resulted in slightly differing input and output formats. The problem is not serious today, but must be resolved soon in order to avoid serious headaches in the future.

## Problems

A standardized model is needed to bring existing tools into a happy co-existence, as well as to prevent continued deviations in future tools. The following is a list of some of the existing concerns:

* JCL meta-policy is embedded within comments inside the actual JCL policy files. The resulting output simply replaces in-line terms and replaces the original input file with the generated output file. Meta-policies are maintained in comments immediately after the policies own 'term' statement and any non-replaced lines in the policy are appended verbatim to the output.

* Speedway uses separate meta-policy and generated iptables policy files. Meta-policies are parsed and the output sent to the policy module files in another directory. Speedway meta-policy defines new policies using the 'policy' keyword and all other content in the meta is appended verbatim to the output.

* F10 meta-policy uses separate meta-policy and generated ACL policy files. Meta-policies are parsed and the output sent to the policy module files in the same directory. F10 generator meta-policy defines new policies using the 'term' keyword and all non-term content is ignored.

Generator Type

* Meta-Policy Definition Location
* New Policy Keyword
* File Naming Standards
* Comments and Non-Meta-Policy Lines
* Juniper
* inline
* uses existing policy 'term' statement
* inline with .jcl files
* non-replaced term lines are appended verbatim to output
* Speedway
* separate files, different directories
* policy xyz {
* meta-policy filename mirrors generated policy in different directories
* non meta-policy lines are appended verbatim to output
* Cisco
* separate files, same directory
* term xyz {
* meta-policy and generated policy have .pol and .acl extension in same directory
* non meta-policy lines are ignored
* others ...


## Meta-Policy Integration

**Files:**

The policy file will consist of terms, comments, and other directives. Terms are the specific rules relating a variety of properties such as source/destination addresses, protocols, ports, actions, etc. Directives may be used to specific that a particular policy should only be generated for a specific platform target, such as cisco. The policy file has the following properties:

* Comments are ignored. They are not accessible outside the policy class.
* Directives are acted on by the compiler. They may be accessible through the policy class.
* Terms are interpreted and used to populate the policy object.

**File Names and Locations:**

The policy files shall be named appropriately to describe their functionality and purpose. Policy files will use a .pol file extension. The network ACL perforce repository will maintain separate 'pol' sub-directory beneath each 'acl' directory, to contain the policy description file and the generated filters respectively. The following diagram illustrates the suggested directory structure:

```
                          ./network/acl
                                |
     -+------------+------------+------------+-
      |            |            |            |
     Def         Corp          Prod        Sysops
      |            |            |            |
     -+------------+------------+------------+-
                   |            |            |
                 Policy        Policy      Policy
```

Generated output will be stored in files with identical filenames, but lacking the .pol extension.


## Policy Description Language Definition

The NAC team needs a standardized meta-policy that can support a wide variety of platforms such as Cisco, Juniper, F10, Netscreen, and Iptables. The language needs to be flexible enough to support diverse platforms, but rigid enough in its definition to ensure consistency between policy definitions.

Each policy description file consists of one or more sections. Each section must begin with a 'header' block, followed by one or more 'term' blocks.

## Header Description Format

The header section is used to specify options that apply to all terms blocks within the policy, such as the target output platform and any arguments needed by output platform generator.

```
     comment:: [doublequoted text]3
     target:: [platform] [arguments]
```

The arguments for each platform are passed directly to the output generator as a list, and vary depending on the needs of the generator. Below is a list of currently supported generators and their argument lists. Arguments in [.md](.md)'s are required, arguments in {}'s are optional.

```
      target:: cisco [named-access-list] {extended|standard|object-group|inet6|mixed}
      target:: juniper [filter-name] {inet | inet6 | bridge}[1]
      target:: iptables [INPUT | OUTPUT | FORWARD] {ACCEPT | DROP}[2]
```

* `[1]` The juniper generator defaults to inet (ipv4) output, but ipv6 and bridge filters can also be specified in the optional filter\_type argument.
* `[2]` The iptables generator target must specify a filter which the terms will apply to. The optional 'default action' of ACCEPT or DROP may be used to include output to set the default action of the named filter.

Example:

```
      header {
        comment:: "This is an example header "
        comment:: "used in policy definition files..."
        target:: juniper inbound-edge-filter inet6
        target:: iptables INPUT DROP
      }
```

## Term Definition Format

Tokens / keywords that must be supported.

* source-address:: [token](token.md)
* source-exclude:: [token](token.md)
* destination-address:: [token](token.md)
* destination-exclude:: [token](token.md)
* source-port:: [token](token.md)
* destination-port:: [token](token.md)
* protocol:: \[tcp,udp,icmp, or protocol #\]
* action:: \[accept/reject/deny/next\]
* option:: \[established, sample, rst, initial, other arbitrary user supplied\]
* verbatim:: [platform](target.md) [text field](doublequoted.md)

Tokens / keywords that may be supported.

* packet-length:: \[text,None (default None)\]
* fragment-offset:: \[text,None (default None)\]
* counter:: \[text,None (default None)\]
* policer:: \[text,None (default None)\]
* logging:: \[text,None(default)\]
* direction:: \[inbound, outbound, both(default)\]
* qos:: (text,None (default None) for juniper = forwarding-class)
* target:: \[juniper, cisco, iptables\] [type; inet, inet6, bridge (juniper specific)](filter.md) \[options; default filter action in iptables\]
* comment:: "doublequoted text field"
* source-prefix:: "text" (prefix lists are used in juniper and are comparable to address directives except that they're defined on the router itself)
* destination-prefix:: "text"
* Policy files should render equivalent output for any given renderer/target.
* Generators may not support all keywords, they can ignore keywords as desired but should produce warnings.
* Generators must produce equivalent access lists from the same policy file.
* Documentation comments consist of any hash mark (#) through EOL and should be passed to generators in the order they appear in the meta policy.
* Generators should ignore comments.
* Per term comments in meta-policy can be included in sections such as header and terms, using the following notation: comment:: "[text](text.md)".   All text between double quotes, including newlines, becomes the comment
* Terms in meta-policy will be indicated by opening and closing identifiers: term x { .... }
* A header section shall begin each meta-policy. The header section shall be denoted by the following notation: header { ... }
* A header must contain at least one target:: section, which specifies the platform or platforms for which the following terms will be rendered
* A header section may span multiple lines.
* A header may contain a comment section, denoted as comment:: "[text](text.md)"
* The option 'established' shall imply adding high-ports to terms with TCP or UDP only protocols, tcp-flag checking on TCP only terms, and may imply stateful checking for generators that support it.
* The option 'tcp-established' shall imply tcp-flag checking for terms where only the TCP protocol is specified. It may imply stateful checking for generators that support it.
* other?

### Policy Object

A policy object is collection of sections, such as header and terms, as well as their associated properties. Each section includes a variety of properties such as source/destination addresses, protocols, ports, actions, etc.

The policy.py module generates policy objects from policy files.

#### ParsePolicy

A policy object can be created by passing a string containing a policy to the ParsePolicy() class.

```
      policy = policy.ParsePolicy(policy_text)
```

#### Headers

```
      for header, terms in policy.filters:
          header.target
          header.target.filter_name
```

#### Terms

```
      for header, terms in policy.filters:
        terms[x].action[]

        # addresses - lists of google3.ops.security.lib.nacaddr objects
        terms[x].address[]
        terms[x].destination_address[]
        terms[x].destination_address_exclude[]
        terms[x].source_address[]
        terms[x].source_address_exclude[]

        # ports - list of tuples.
        terms[x].port[]
        terms[x].destination_port[]
        terms[x].source_port[]

        # list of strings
        terms[x].comment[]
        terms[x].protocol[]
        terms[x].option[]
        terms[x].verbatim[x].value

        # string
        terms[x].counter
        terms[x].name
```

#### Example

A contrived example follows:

```
      header {
        comment:: "this is an example filter"
        target:: junniper example-filter
        target:: cisco example-filter inet
      }

      term term-1 {
        source-address:: BIG_NETWORK
        destination-address:: BIG_NETWORK
        protocol:: tcp
        action:: accept
      }
```

this would output a juniper filter of:

```
    family inet {
        replace:
        filter example-filter {
            interface-specific;
            term term-1 {
                from {
                    source-address {
                        10.0.0.0/8;
                    }
                    destination-address {
                        10.0.0.0/8;
                    }
                    protocol tcp;
                }
                then {
                    accept;
                }
            }
        }
    }
```

and a cisco filter of:

```
    no ip access-list extended example-filter
    ip access-list extended example-filter

    permit tcp 10.0.0.0 0.255.255.255 10.0.0.0 0.255.255.255
```

#### IPv6

IPv6 support has been added to the policy language. Currently only Cisco, Juniper and Iptables can render ipv6 filters. The syntax for an ipv6 filter is exactly the same as ipv4 filters except for the inet6 keyword on the target line. Making an ipv6 filter is as easy as

```
      header {
        target:: juniper some-v6-filter inet6
      }
```

Be sure that the addresses you reference in your subsequent terms have ipv6 definitions. ie, if you have

```
      term my-v6-term {
        source-address:: PRODUCTION_NETWORK
        destination-address:: CORPORATE_NETWORK
        protocol:: tcp
        action:: accept
      }
```

When PRODUCTION\_NETWORK or CORPORATE\_NETWORK tokens are only defined with ipv4 addresses, this will error out. Tokens can include both IPv4 and IPv6 addresses, and rendering IPv6 output will include only IPv6 addresses associated with a given token.


### Definitions

The following are words that we have defined for the purposes of NAC discourse and this project. Some of these words may be defined somewhat differently than you are used to.

* **Generator:** A program that utilizes the data contained in a Policy to create an output rulebase suitable for applying to a specific target platform. Generators will be specific for each target platform, such as juniper, cisco, f10, iptables, etc.
* **Global Directive:** Keywords contained outside of a term or comment within a policy, that define a default value for a particular term property. Global directives can be overwritten within an individual term by specific redefinition within the term. Global directives are limited to only those keywords allowed within a term definition.
* **NAC:** Network Access Control. Concerning issues related to security at layer 3 and 4 in the OSI model.
* **Flow:** A network flow, given as a tuple of the following form: (src(s), dst(s), src-port(s), dst-port(s), protocol)
* **Service:** A set of tuples of the form ((server/network), port, protocol, [application](application.md) ) that share a common logical function.
* **Term:** A flow to/from a service, the action applied to this flow, and where this action is enforced (e.g., what PEP(s)). A term is expressed in the form of a tuple:
    * (src(s), dst(s), src-port(s), dst-port(s), protocol, action = {permit/drop/deny, etc.}, modifier(s) = {QOS, negation, counters, etc.}, PEP(s) )
* **Policy:** A policy is the set of all terms which apply to a particular service.
* **Rule:** A rule is the device-specific implementation of a term.
* **Rulebase:** A rulebase is the set of all rules on a device.
* **Logical Rule:** The set of all device-specific implementations of a term.
* **Logical Rulebase:** The set of all device-specific implementations of terms pertaining to a particular policy.
* **Narrative:** The narrative is the English language description of a given service's policy, along with the justification for these policies and meta-information about the service. (Who is authorized to make changes, what the procedure is for making changes, etc.). One requirement is that the English language description is sufficiently unique that we have a mapping between section of narrative -> terms of policy -> rules of rulebase.
* **PEP:** Policy enforcement point. A PEP is any location on the network where the terms of a policy can be enforced as rules.
* **LPEP:** Logical PEP. The set of all devices and/or interfaces that enforce a logical security boundary.
