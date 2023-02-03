# Aerleon Overview

Aerleon is a lightweight library which generates firewall configurations from a normalized data model. Users of the library provide their intention in the form of data (which can be expressed in several ways) and the library generates configuration.

## Description

Aerleon provides a per firewall platform configuration generator. It loads data in a single standard format and generates a configuration for each target platform.

The data primarily consists of:

* Policy Files that represent the actual firewall rules.
* Address Files that represent the addresses, in the form of named objects.
* Service Files that represent the services, in the form of named objects.

## Supported Configuration Formats

* Legacy Capirca formats
* YAML
* Native Python

## Core Supported Generators

* Arista
* Aruba
* Brocade
* Cisco
    * Cisco ASA
    * Cisco NX
    * Cisco XR
* Cloud Armor
* Google
    * Cloud Armor
    * GCE
    * GCP
* IPSet
* IPTables
* Juniper
    * JuniperSRX
    * Juniper EVO
    * Juniper MPC
* Kubernetes
* NFTables
* VMWare NSXV
* Packet Filter
* Palo Alto
* PCAP Filters
* Windows
    * Advanced Firewall
    * IPSec

## Audience (User Personas)

* Anyone who is managing firewall configurations.
* Anyone who wants to manage configurations using Infrastructure as Code (IaC) concepts.
* Anyone who wants to manage a multi-firewall configuration in a single normalized manner.

## Authors and Maintainers

* "Rob Ankeny <ankenyr@gmail.com>"
* "Jason Benterou <jason.benterou@gmail.com>"
