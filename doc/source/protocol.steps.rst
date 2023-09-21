..
  SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0

.. _protocol_steps:

===============================================================================
Protocol steps
===============================================================================

The following chapter describes the protocol phases of the neuropil cybersecurity mesh.

Step 1: handshake and Diffie-Hellman (DH) key exchange
===============================================================================

The first message sent to another node is a *handshake message*. Its purpose is
to exchange public and session keys with another node. The handshake message is
composed of the node token and a self-signature using the private key of the
node token.

The node that receives the handshake message must verify the signature and
contents of the received node token before responding with a handshake
message of its own. Additionally, the receiving node calculates a shared secret
using its own private key and the public key of its new peer via Diffie-Hellman
key exchange.

When the initiating node receives a valid, authentic handshake response, it
derives matching session keys. Any follow-up messages must be encrypted and
have their integrity protected using session keys derived from the shared
secret, or else they will be discarded.

Each participant is now aware of the node token values of their peer. The
predefined fields are:

 * realm
 * subject
 * issuer
 * audience
 * uuid of the token
 * expiration and not_before timestamps
 * additional extensions containing physical node attributes:

   * hostname
   * port

.. NOTE:
   The token exchanged during the handshake is **not** encrypted and can be read
   by anyone observing the network. It must not contain passwords or other
   secret data.


Step 2: joining the network
===============================================================================

The initiating node transmits a *join message* to its peer. The join message
contains the identity that uses the node. This identity may or may not be
identical to the node token. If they differ, then the identity must also
contain the fingerprint of the node token in an attribute field. Later on, this
reference is used for routing purposes.

The receiving node can now authenticate and authorize the identity that is
requesting access to its network in the callbacks defined for this purpose. If
the identity cannot be authenticated, the handshake protocol sends a
*not-acknowledged message* back to the initiator, and the identity and node
data is marked as obsolete and deleted later, because sending the
not-acknowledged message still requires the established session key.

.. NOTE::
   If the identity is in a realm but cannot be authenticated at this time, the
   receiving node might forward the incoming token to the realm leader in order
   to defer authentication. Depending on the response of the realm leader, the
   receiving node might authorize the identity on its next attempt to join the
   network.

If the initiating node has been authenticated and authorized, it is added to
the routing table of the receiving node, and the join message is acknowledged
to the initiator. Additionally, existing peers of the network will receive an
*update message* which notifies them of the newly joined node.

After receiving the acknowledgment, the initiating node may begin to exchange
further messages with the nodes in the network.


Step 3: growing the peer-to-peer network
========================================

Authenticated and authorized nodes exchange update and *piggy messages* in
order to exchange information about other peers known to them. After receiving
an update or piggy message, a node decides whether it would like to join the
new nodes, or whether it will merely forward the information.

The decision to join a new node is based on the distance between the node’s own
fingerprint and the fingerprint of the peer’s node token, as well as the soft
state of its routing table (i.e., occupancy and individual route health
inferred from latency).


Step 4: message exchange: communicating message availability and interest
=========================================================================

Two nodes in the network that would like to exchange information about a given
*subject* get in touch as follows. Each node communicates their special
interest (sending or receiving) of a subject to the *subject coordinator*: the
node whose node token fingerprint is the closest to the subject hash at the
time. The subject coordinator then collects both requests, and passes on the
information to the peers involved. Filtering of tokens based on the *audience*
field will be applied here.

Message interest and availability are encoded as tokens that contain additional
information about the type of message exchange, the current threshold and some
other values as well, and are signed by their originating identity.

Each node can once more authenticate and authorize the identified peer by
verifying the exchanged token. Once the correct peer has been identified,
message exchange happens independently from the coordinator.


.. raw:: html
    :file: ./transport_types.svg


A data channel or message exchange always happens with an :c:data:`np_subject`.
An np_subject can be created by calling the function :c:func:`np_generate_subject` 
repeated times on the same data structures. Internally the function will use a hash 
chaining approach that defines the final np_subject for a data channel.


.. raw:: javascript
	 
   // example generation of a private np_subject for your data exchange
   np_subject subject_id = {0};
	 np_generate_subject(&subject_id, "urn:my:subject", strnlen("urn:my:subject", 14));
	 np_generate_subject(&subject_id, "v1.0", strnlen("v1.0", 4));
	 np_generate_subject(&subject_id, "AES-GCM", strnlen("AES-GCM", 7));
   // you could push anything to the np_subject generation ...


Step 4a: Virtual MX: communicating intent, attributes and availability only
-------------------------------------------------------------------------------

When using a virtual communication channel, the user merely send out their
interest (the intent token) and the corresponding attributes to each peer
that has subscribed to this channel. As intent token will be refreshed
periodically, there is an implicit heartbeat signalling to peers that your
node is still active and interested in this communication. However, as this
is a virtual data channel, no messages can be send. Even if somebody
would do so, messages would just be discarded.


Step 4b: Public MX: open communication channels for groups
-------------------------------------------------------------------------------

This is the usual standard: communicate on a given subject with one or more
partners. Messages will be group encrypted for the authorized peers in 
your local node. That means that each node could have a different set of
authorized peers, and each node will use a different encryption for its
messages.


Step 4c: Protected MX: communicating channel for mutual partners
-------------------------------------------------------------------------------

The same as a public data channel, with the subtle difference: the audience
field has to be filled with the fingerprint of a specific peer. The end 
result is a mutual authenticated / authorized data channel. Intent token that
do not match the fingerprint will not be passed on into the user space 
authorization handler.


Step 4d: Private MX: untraceable data channels with better access control
-------------------------------------------------------------------------------

First of all a private data channel lets you define a specific authorization 
handler for each subject (all other modes before use the global authorization 
callback function).
Secondly you should call :c:func:`np_generate_subject` several times with 
different input strings. This helps you to obfuscate the hash space, as only
the final :c:data:`np_subject` hash value will be visible.
