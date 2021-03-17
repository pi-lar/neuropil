..
  SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0

************
Introduction
************

neuropil is a small messaging library which by default adds two layers of encryption.
It allows you to address identities (a device, an application, a service or a person) worldwide 
without compromise for privacy or security requirements.

All neuropil enabled applications or devices form an ad-hoc cluster of connected nodes which
constantly exchange messages to detect failures and to exchange informations. Nodes can connect and
disconnect at any time, messages will still be transported to their destinations.

.. raw:: html

   <hr width=200>


Use Cases
*********

* global and secure micro-service driver
* establishment of data ownerships based on distributed ACL/ABAC rules
* enable exclusive access to devices / resources for partners
* establish secure application defined networks (ADN) and ad-hoc VPN connections

.. raw:: html

   <hr width=200>


Features
********

* zero-trust framework to comply with high data protection and security laws
* zero discovery of identities and data channels
* distributed messaging layer with built-in governance capbilities
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
*******

* finalize message exchange pattern definitions (currently one-to-one only)
* implement backpressure routing algorithm
* implement group encryption
* define message callbacks in case of undelivered messages
* hook in a javascript bindings for message callback handling
* finalize token / message structure
* more documentation and test cases
* ... and many many more ideas ...


Achieved goals
**************

* there is an existing Lua and Python binding
* Token and message structure has bee defined
