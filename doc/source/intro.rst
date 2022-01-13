..
  SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0

===============================================================================
Introduction
===============================================================================

neuropil is a small c-library which by default adds two layers of encryption to communication channels.
It allows you to address identities (a device, an application, a service or a person) worldwide without compromise 
for privacy or security requirements. 

The project embraces modern concepts like named-data networks, self-sovereign 
identities, zero trust architectures and attributes based access control to increase the cybersecurity level of it's 
users beyond the current state-of-technology. In effect its users will benefit from the new way of secure, scalable 
and souvereign data integration to easily comply with legal, organizational, operational and compliance regulations 
and requirements.

All neuropil enabled applications or devices form an ad-hoc cluster of connected nodes which
constantly exchange messages to detect failures and to exchange information. Nodes can connect and
disconnect at any time, messages will still be transported to their destinations.

.. raw:: html

   <hr width=200>


Use Cases
===============================================================================

* global and secure nano / micro-service driver
* establishment of data ownerships based on distributed ACL/ABAC rules
* enable exclusive access to devices / resources for partners
* establish secure application defined networks (ADN) and ad-hoc VPN connections

.. raw:: html

   <hr width=200>


Features
===============================================================================

* zero-trust framework to comply with high data protection and security laws
* zero discovery of identities and data channels
* distributed cybersecurity mesh with built-in governance capabilities
* implementation of group encryption (fan-out messaging)
* technical double encryption layer to implement zero-knowledge infrastructures
* message chunking to prevent side channel analysis from network sniffers
* type-safe recursive tree structure for (de-)serializing message
* pre-defined message exchange pattern that ease development
* C99 compliant and able to run from embedded devices to enterprise applications
* only one dependency to the external encryption library (libsodium)
* pull based message exchange to prevent overload and to enable lean management for it services
* event / task driven architecture (coroutine inspired) which executes small pieces of code asynchronously

.. raw:: html

   <hr width=200>


Roadmap
===============================================================================

* implement realm concept
* finalize message exchange pattern definitions (missing: one-to-subgroup only)
* implement back-pressure routing algorithm
* implement windowing to transmit several messages in one data paket
* implement multicast encryption
* allow more than one identity on top of a node
* allow more configuration options
* add relaying example node
* identity import/export from NPKS (neuropil key store)
* define message callbacks in case of undelivered messages
* hook in a javascript bindings for message callback handling
* finalize token / message structure
* more documentation and test cases
* ... and many many more ideas ...


Achieved goals
===============================================================================

* NGI ZeroDiscovery: a privacy preserving search index
* pubsub group encryption is working
* scale-up test to thousands of nodes
* distinguish between virtual, private, protected and public mx properties
* there is an existing Lua and Python binding
* Token and message structure has been defined
