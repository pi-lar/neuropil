Protocol
========

The following chapter describes the protocol of the neuropil messaging layer.

1st step: handshake, DH key exchange
************************************

the first message send to another node is used to exchange the public keys of the node's.
The message is composed of the serialized token of the node (not the identity).
This serialized token is then signed with the private key of the sending node.

After receiving a handshake message the receiving node also sends his own data to the new
participant in the same way. Additionally the receiver calculates a shared secret with the
public key of the new partner and expects follow-up message to be encrypted with the shared secret.

After the first sending node has received the handshake message of the requested node, it can
also calculate the shared secret.

Each particpant now knows the aaatoken values of the partner, which are:

 * realm
 * subject
 * issuer
 * audience
 * uuid of the token
 * expiration and not_before timestamps
 * additional extensions containing the physical node values:

   * hostname
   * port

The token structure could be extended with user supplied data if required. Each node could already
stop (re-)acting if this data is not as expected.
The token data structure can also be read by anyone on the network, so no password or other data should be
supplied on the node handshake level.

All communication following this point must be send encrypted by using the shared secret or will be discarded.
The nodes now proceed with the second step of the protocol, joining the network.


2nd step: handshake, joining the network
****************************************

The sending node now transmits a join message to the other node, which contains the identity using the node.
The node token can be the same as the identity, but doesn't have to be. If the differ, then the identity also contains
the hash value of the node to identify the correct node (also used for routing purposes later).

The receiving node now can authenticate / authorize the identity requesting access to its network, either by using the
defined callback functions, or by forwarding the data to a different node (assuming that this node is somehow smarter).

If the node requesting join access cannot be verified, the handshake protocol sends not-acknowledge back to the
sender, the identity and node data is marked as obsolete and deleted later (because sending the not-acknowledge still
requires the established session key).

Else, if the node has been authenticated and authorized, the node is added to the routing table.
Additionally the join request is acknowledged and send back to the initiator. Already existing partner nodes in the
network will receive an update that a new node has joined the network.

After receiving the acknowledge the initial node can now start to exchange update and piggy messages. These messages
will give the node additional information about the network it has joined. It can then decide whether it would like to
join other nodes on the network as well.


3rd step: growing the peer-to-peer network
******************************************

Authenticated and authorized nodes exchange update and piggy messages to share their knowledge about existing nodes.
After receiving an update or piggy message, a node decides whether it would like to join the new nodes or whether it
will simply pass an the knowledge of the new nodes. The decision to join a new node is based on the distance of the
two node hash values and the routing table. Each node is using either his local callback functions to verify peer
nodes, or uses other sources to authenticate and authorize peer nodes.


4th step: message exchange, sending message availablity / interest
******************************************************************

Two nodes in the network would like to exchange information about a given "subject".
Each node sends his special interest (sending or receiving) of the subject to the subjects hash value.
The node with the hash value closest to the subject hash value then collects both requests, and sends the information
on to the identified partners. Filtering of tokens bases on the field "audience" of the token will be applied here.

The message interest / availability is encoded as a aaatoken, but contains additional information about the type
of message exchange, the current threshold and some other values as well. These tokens are again signed by the
sending/receiving identity.

Each partner can now again authenticate or authorize if the identified partner is the correct one by inspecting the
token. Once the correct partner has been identified, data exchange will happen "directly" between the two nodes.

The routing to the hash value of the subject has nothing to do with the routing of the message exchange after the 
handshake is complete.
