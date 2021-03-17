..
  SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0

Security review / discussions about neuropil
============================================

This page will give a brief overview about the several security related questions.
If you feel that there is something wrong or we should include a chapter about specific topic,
please get in contact with us.


Handshake messages
------------------
The handshake messages are the most vulnerable point of the neuropil protocol, because they are
the only messages that are being send in plaintext (binary encoding). However, the information
in this handshake message contains the public key and the hash value of the initiaing node, and 
this message is integrity protected with a signeture. An attacker therefore cannot become a
man-in-the-middle between any two nodes. Once the handshake messages have been exchanged, the 
channel is encrypted by deriving a perfect forward secure secret used to encrypt the all followup
messages.

What can an attacker learn from the content of the handshake message? 
The IP address or hostname, port, protocol and the hash value of the node (not the hash value of 
an identity using this node!). In addition there is the public key and the signature.
Most of these informations are already known to the attacker before (IP/hostname and port can
obviously also be detected by an network scan). Because the public key of the node is not related
to the identity, no additional information is disclosed.

Join message information retrieval
----------------------------------
An attacker may try to connect to a node in order to retrieve some information about the identity.
However, the attacker then is the first to disclose some information about himself, making him 
visible in the network and detectable e.g. by SIEM tooling.
The answer to this question heavily depends on the way you have decided to run and manage your 
neuropil mesh network. E.g. if you decided to connect most nodes in passive mode, then joining
a network is only possible by using a bootstrap node. Although this bootstrap node is then a 
single point of attack, it is not required to actually run your mesh network. It is only required
to add new particpants (which could become important when you want to dynamically renew relam 
memberships or do release updates).

DHT messages
------------
The messages to maintain and uphold the distributed hash table carry no nore meaning than node infromation.
Ping messages are used to measure latency between two hops. Update messages are send to introduce new 
nodes into the network, the same applies to the piggy messages. Leave messages just indicate that a node
wishes to stop the connection. 
Acknowledge messages only carry the uuid of the initial message, indicating that a certain message exchange
needs an explicit confirmation (and thus giving a hint about the importance of the initial message).
However, acl messages and the initial message do not neccessarily travel along the same route.

Userspace messages
------------------
Before a message is sent, the neuropil messaging layer sends out pheromone messages. These pheromone messages
only carry "scents" of a message exchange. The scent consists of a bloom filter based on the hash of the
message subject, plus a bloom filter about other attributes. Only if a bllom filter has detected a match
with a peer, a message intent is sent out to establish the second, end-to-end encrypted data channel.
This intent message carries a token, which contains the hash value of the identity, plus the public key
of the identity and the node hash value.
As of now the message subjects are transported in plain text, that means an attacker who has gained access
to the neuropil mesh network can deduct some information about the data being send. Because the messages
are transported through the hash table, only a fraction of all used message subjects are visible to him.
In the future we will replace the message subject and plan to use hash values instead, taken the attacker
the chance to reason about message subjects and message content.
Payload messages containing sensitive material are transported end-to-end encrypted to authorized peers only.
An attacker may try to become part of the receivers (group), again at the expense of becoming visible and
thus detectable by SIEM tooling.


Eclipse attack
---------------
In our opinion an eclipse attack is not possible. The hashvalues that are generated are based 
on a cryptographic algortithm, thus they should be distributed uniformly across the available 
hash space. If an attacker tries to get as many connections to its target as possible, he will 
have to regenerate new instances of neuropil nodes that fulfil the neighbouring and routing table
criteria that we have implemented. As latency is one of the routing table criteria, we think that 
it will not be possible to completely replace all neighbouring and routing table nodes. As an
additional countermeasure against eclipse attacks you could add the same kind of nodes to your 
network as an attacker. This will continoulsy change the addressable hash space, but it will also
prevent an attacker from launching its attack.

Sybil attack
------------
A sybil attack tries to get hold of the majority of hash nodes. If more than fifty percent of the 
nodes belong to an attacker, he would be able to disturb the message flow significantly or he could 
destroy the overall network by stopping all of his nodes at the same time.
We think that this attack could be possible, but only if the authentication rules can be circumvented
by any means. A new node can only become part of a mesh network, if at least one other node has
auctenticated the new node and introduces it as a valid peer. But the new node will still be authenticated
by all other peers (there is no automatic trust or friend-of-a-friend in neuropil!). Authentication
is based on digitil identities. Being able to forge an identity means access to the private key of
this identity (meaning you have more serious problems than the sybil attack).

