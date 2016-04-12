Tutorial
********

The following chapter will give a quickstart to use neuro:pil as a messaging layer
It mainly consists of three different parts, the fourth part will explore some more details in-depth.

***********************
Setting up a controller
***********************
.. include-comment:: ../../test/neuropil_controller.c

topics you may be interested to look at now:

* realms and identities
* add more nodes to our neuropil network layer

*********************
Setting up a listener
*********************
.. include-comment:: ../../test/neuropil_receiver_cb.c

topics you may be interested to look at now:

* receive more than pure text data
* change your interface from public to private
* change your interface from single to group receiver (load-balancing or fault-tolerant)

*******************
Setting up a sender
*******************
.. include-comment:: ../../test/neuropil_sender.c

topics you may be interested to look at now:

* send more than pure text data
* change your interface from public to private
* add more callback hooks for timed out messages
* use more than one sender


***************
Setting details
***************

.. _to_join_or_to_be_joined:

To join or to be joined
-----------------------

The neuro:pil subsystem establishes a cluster of nodes when started. Each node needs one entry point,
afterwards other nodes will be detected and joined automatically.

The main question when thinking about the setup of neuro:pil nodes are:

* would you like to have one single bootstrap instance which will start up all your nodes
  (can this central instance access all hosts in your environment ?)
* would you like to have one single bootstrap instance where all nodes will connect to when starting up
  (do all nodes have physical access this central instance ?)
* would you like to allow that all nodes can use arbitrary nodes to get started
* would you like to use our neuro:pil network of connected nodes to connect you devices, systems, etc ...

Based on this decision you will have implement:

* your join callback function accordingly: check for correct realm(s), 
  implement other authentication measures when receiving join requests
* your firewall rules to allow the traffic to central/distributed node(s) 
  (they will still be a lot simpler than before if you stick to the standard port)
* implement you authentication and authorization callback functions accordingly

Even if you do not want to implement a central bootstrap node, you will still be able to authenticate
and authorize new nodes as they enter the network, because already connected nodes can forward these 
join requests to the central node.


