Introduction
************
neuropil is a small messaging library which by default adds two layers of encryption.
It allows you to address devices, applications, persons worldwide without compromise for 
privacy or security requirements.

All neuropil enabled applications or devices form an ad-hoc cluster of connected nodes which
constantly exchange messages to detect failures and to exchange informations. Nodes can connect and
disconnect at any time, messages will still be transported to their destinations.

.. raw:: html

   <hr width=200>

*********
Use Cases
*********

* B2B message exchange with Kerberos like AAA capabilites
* global and secure micro-service driver
* establish data ownership with ACL
* enable exclusive access to devices / resources for partners
* establish secure application defined networks (ADN)

.. raw:: html

   <hr width=200>

********
Features
********

* distributed messaging layer with built-in governance capbilities
* technical double encryption layer to implement zero-knowledge infrastructures
* message chunking to prevent side channel analysis from network sniffers
* type-safe recursive tree structure for (de-)serializing message
* pre-defined message exchange pattern that ease development
* C99 compliant and able to run from embedded devices to enterprise applications
* only one dependency to the external encryption library (libsodium)
* pull based message exchange to prevent overload and to enable lean management for it services
* event / task driven architecture (coroutine inspired) which executes small pieces of code asynchronously
* three levels of message acknowledgement: hop-by-hop, destination, client_ack

.. raw:: html

   <hr width=200>

*******
Roadmap
*******

* more documentation
* finalize message exchange pattern definitions (currently one-to-one only)
* implement backpressure routing algorithm
* implement group encryption
* review and formalize message and token structure
* define message callbacks in case of undelivered messages
* hook in a javascript / lua / python bindings for message callback handling
* more test cases
* ... and many many more ideas ...
