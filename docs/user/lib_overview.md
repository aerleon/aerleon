# App Overview

Aerleon is a lightweight library which generates firewall configurations from a normalized data model. Users of the library provide their intention in the form of data (which can be expressed in several ways) and the library generates configuration.

## Description

Aerleon provides a per operating system configuration generator, each of which ingests the data and generates the expected configuration.

The data primarily consists of:

* [Policy Files](../lib_policy/) that represent the actual firewall rules
* [Address Files](../lib_address/) that represent the addresses, in the form of named objects
* [Service Files](../lib_service/) that represent the services, in the form of named objects

The library support formats of:

* Legacy Capirca pol, net, svc files
* JSON
* YAML
* Native Python

## Audience (User Personas)

* Anyone who is managing firewall configurations.
* Anyone who wants to manage configurations using Infrastructure as Code (IaC) concepts.
* Anyone who wants to manage a multi-firewall configuration in a single normalized manner.

# Using Aerleon

Aerleon provides a command-line script `aclgen` which will generate firewall ACLs from high-level policy files.

Each [policy file](../lib_policy/) in the input directory is visited and ACLs are generated from the _term_ and _header_ blocks within. ACLs are then rendered to one or more platform-specific configs according to the ‘target’ keyword(s) used.

Symbolic names can be used for IP networks, hosts, and services defined in the [Address Files](../lib_address/).

## Authors and Maintainers

* "Rob Ankeny <ankenyr@gmail.com>"
* "Jason Benterou <jason.benterou@gmail.com>"
