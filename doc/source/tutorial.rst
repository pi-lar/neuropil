Tutorial
********

The following chapter will give a quickstart to use neuropil as a messaging layer
It mainly consists of three different parts, the fourth part will explore some more details in-depth.


********************************************
Setting up a bootstrap node (aka controller)
********************************************

As a starting point we need a node which will serve as a bootstrap node for all other nodes.
This bootstrap node will not neccessarily be engaged with messaging later on, but it is required
as a starting point.

.. NOTE::
   source code of this example is available at test/np_controller.c

.. include-comment:: ../../test/neuropil_controller.c


topics you may be interested to look at now:

* realms and identities
* add more nodes to our neuropil network layer

.. raw:: html

   <hr width=200>

*********************
Setting up a listener
*********************

As a next step we will add an listener to our network of nodes. It will join the bootstrap node setup
in the step before, but will communicate with other nodes in the network as well. Note that addressing
and configuration of devices is done via the subject of a message. subjects are a form of abstraction and
help to reduce configuration efforts for IP addresses etc.

.. NOTE::
   source code of this example is available at test/np_receiver_cb.c

.. include-comment:: ../../test/neuropil_receiver_cb.c

topics you may be interested to look at now:

* receive more than pure text data
* change your interface from public to private
* change your interface from single to group receiver (load-balancing or fault-tolerant)

.. raw:: html

   <hr width=200>

*******************
Setting up a sender
*******************

As the last step we will implement the sender node. Again we send a join message to the bootstrap node.
We have to know the subject of the listener, otherwise we will not be able to push the data over.

.. NOTE::
   source code of this example is available at test/np_sender.c

.. include-comment:: ../../test/neuropil_sender.c

topics you may be interested to look at now:

* tweak you message exchange parameter
* send more than pure text data
* change your interface from public to private
* add more callback hooks for timed out messages
* use more than one sender

.. raw:: html

   <hr width=200>

******************
Setting up details
******************

.. _to_join_or_to_be_joined:

To join or to be joined
-----------------------

The neuropil subsystem establishes a cluster of connected nodes when started. Each node needs one entry or bootstrap
node, afterwards other nodes will be detected and joined automatically.

The main question when thinking about the setup of neuropil nodes are:

* would you like to have one single bootstrap instance which will start up all your nodes
  (can this central instance access all hosts in your environment ?)
* would you like to have one single bootstrap instance where all nodes will connect to when starting up
  (do all nodes have physical access this central instance ?)
* would you like to allow that all nodes can use arbitrary nodes to get started
* would you like to use our neuropil network of connected nodes to connect you devices, systems, etc ...

Based on this decision you will have implement:

* your join callback function accordingly: check for correct realm(s), 
  implement other authentication measures when receiving join requests
* your firewall rules to allow the traffic to central/distributed node(s) 
  (the rules will still be a lot simpler than before if you stick to the standard port)
* implement you authentication and authorization callback functions accordingly

Even if you do not want to implement a central bootstrap node, you will still be able to authenticate
and authorize new nodes as they enter the network. Already connected nodes can forward join requests 
to a central or realm node.

.. raw:: html

   <hr width=200>


.. _tweak_your_mx_parameter:

tweak you message exchange parameter
------------------------------------

The neuropil messaging layer uses a "pull" principle to establish communication between nodes. Apart from the 
messages that are required to maintain the DHT, message subjects are annotated by the sender and receiver. This
additional message exchange paramter are exchanged with tokens when a sender and receiver try to communicate with each 
other over the same subject. This message exchange token protect sender and receiver from each other. Without a valid
token the correct hash value is not available to the sender, and the receiver is able to throw away messages after the 
token has expired.

Once a token pair has been exchanged, the communication between the sender and receiver can be done directly, as
long as the token is valid. In contrast to the classic HTTP protocol this offers a much tighter control over the data
that is transported between nodes.

As a consequence, a sender will not be able to send more data than the receiver allows him to send. At the same time
the receiver is able to increase the amount of messages slowly. This is why we call it "pulling" messages. The receiver
will periodically re-publish it's current threshold sizes to inform all senders of messages to his subject about its 
current state.

There is no hard upper limit to the number of messages a receiver could receive. But please bear in mind that the in 
memory cache size will have exactly the same size as the number of messages that you configure. You can therefore setup
a receiver that will receive 1000 messages per minute or more. Sender and receiver threshold are two different settings.
Each sender may have only a threshold of 10 messages, but one receiver may have a threshold of 100 messages to receive
data from 10 different sender. 
So the main difference is that you're able to control the amount of data. Small devices may only exchange single 
messages, large enterprise system may exchange more ...

Please inspect the :c:type:`np_msgproperty_t` structure and the ttl and max_threshold fields to tweak to your desired
behaviour. Also note that you can specify which messages get purged from memory first by changing the cache_policy 
field.

.. raw:: html

   <hr width=200>


.. _send_more_than_pure_text:

send more than pure text data
-----------------------------

The examples given above only exchange a simple string as the payload. But the neuropil message format actually is
composed of a json structure. The binary serialization protocol is usin the `msgpack`_ protocol, data types are 
statically typed.

This allows you to send a message with a nested tree structure. There is no technical limit to the nesting depth, but 
smaller devices obviously cannot decode too large messages (and could actually throw away too large messages).

A message is composed of 5 different parts, each part is a tree structure. Three of these parts are not accesible 
and are filled with the neuropil internal routing information. Two tree structures are under the full control of sender
and receiver. 

The first user cntrolled part is called "message properties" and should contain technical or business data that are
required before reading the real message body. Consider it as a way to filter or dispatch messages. The HTTP protocol 
contains the header fields which are the equivalent construct. You can also use it to inject additional encryption
paramters of the message body.

The second user controlled part is called "message body" and should contain the real payload. No great explanation is 
required here.

You should consider to publish your message formats to our public github repository (TODO on our side) so that they can
be used by other persond to exchange data with you.

.. raw:: html

   <hr width=200>


.. _change_interface_from_public_to_private:

change your interface from public to private
--------------------------------------------

The message exchange tokens provide the way to authenticate and authorize participants. If you would like to expose your
interface to the public, then you should consider to make your message format and your subject name available to the 
public. This allows your partners to implement a receiver or sender independant of your own product or service.

When switching to a private message format you have to implement the authentication and authorization callbacks. This
will enable you to see who is requesting access to your messages. In addition you can change the subject name. Note that
the hash value of the subject is used internally to match sender and receiver of messages. Without a valid sender name
communication between sender and receiver is not possible, even a small change of the subject will change the hash value
in a non predictable way. Some call this "security by obscurity", but together with the authentication and authorization
callbacks it is a valid protection against message exchange with unwanted partners. 



.. _msgpack: https://www.msgpack.org/
