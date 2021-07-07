..
  SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0
  
What is the neuropil messaging layer ?
======================================

We find it really hard to explain our cyber security approach, and often we experience that people
misunderstand our intention or the full potential of the neuropil messaging layer. One important misunderstanding
is that we have implemented a kind of a blockchain, probably because we are using hashing and a distributed hash
table. neuropil is not a blockchain! 

As our company is originating from a background of integration projects, one of the pillars of neuropil
obviously is a message orientated middleware. The difference: we know that operating a enterprise service bus
imposes certain restrictions and requirements stemming from security and privacy. This is one reason why 
our approach lacks a central system, but rather embraces a fully de-centralized setup. Furthermore we assisted
a few B2B projects in the past, and we know that the security measures for B2B data transfer are "heavier" than
within a company. Take these two important aspects together and you're directly there, many design choices
and details are based one of these two main aspects: de-centralized security and messaging, but central governance. 


As you'll see, the neuropil is a structure that sits in between all systems using it. It is and will be designed to 
enable interoperability between all connected devices, applications, processes and users. Of we go with some other 
explanation to grasp what the neuropil messaging is or can be.


Mathematical: the implementation of a 256bit hypercube graph
------------------------------------------------------------

When using the library a "node" is created, which acts as a vertices of a hypercube graph. 
Each network connection then is an edge, and in neuropil meaning each vertice can talk to another 
through a PPRL protected interface. As we cannot build up and manage a network connection to each 
vertice of the full hybercube graph, we only choose log(n) network connection based on the network 
topology criteria like latency and quality (others measures may follow). We also know that network
topologies and physical restrictions will be hindering the setup of a perfect hypercube, therefore 
we added additional routing measures to ensure that all vertices can talk to each other. 
In theory, the vertices of the message subject space, the identity space and the node space overlap.
We use the node space vertices as our overlay structure and use it protect the privacy of the users.
From the hypercube we inherit the high scalability of the protocol. From the mathematical theory there
is no limit to the number of devices that you attach our network, from our experience we know that
this may not be true in practice.


Technical: a development framework for access control and secure data transfer
------------------------------------------------------------------------------

The technical reference implementation enforces the use of digital identities, SSI paradigms and
modern encryption. When the internet was build, it was build with the assumption that there is no 
or little need for secure data transactions. History has proven that this assumption was wrong,
therefore our framework is an implementation of the opposite: It is very easy to implement end-to-end
encrypted data transfer, but difficult to go without any encryption at all. For the users of 
our library there are only two aspects to consider: which entities do I authenticate do build up SDN 
structures, and which entities do I authorize to exchange data with. Insecure data transfer just means
that that you authorize all recipients, but this still involves a consent phase between the interacting parties.


Security: an obfuscated data space with a flat address structure to reduce the attack surface 
---------------------------------------------------------------------------------------------

Each hash value that is visible refers to "something that you know" and enables the users of the 
messaging layer to make sense and to share information. Structures thus become visible to a 
specific user (group) only, which in parts reverts the current approach of how the internet works. 

Our model enforces coopetition between involved parties. Central structures are only needed to build 
up or let entities emerge from the flat address space. neuropil increases and strengthens integrity, 
confidentiality and availability measures, the important 'CIA' of cyber security. You may add a 'P'
for privacy as an important additional concept.


You'll find many of the above mentioned concepts in other products or services, but you will not find them
in a self-contained small c library that scales like hell (in theory)!


