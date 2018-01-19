Protocol
========

The following chapter describes the protocol of the Neuropil messaging layer.

Phase 1: handshake and Diffie-Hellman (DH) key exchange
*******************************************************

The first message sent to another node is a *handshake message*. It is used to
exchange public keys with another node. The handshake message is composed of
the serialized node token and a signature of the serialized token created using
the private key of the sending node.

The node that receives the handshake message must verify the signature and
contents of the received token before responding with a handshake message of
its own. Additionally, the receiving node calculates a shared secret using its
own private key and the public key of its new peer via Diffie-Hellman key
exchange.

When the initiating node receives a valid, authentic handshake response, it
derives matching session keys. Any follow-up messages must be encrypted and
authenticated using session keys derived from the shared secret, or else they
will be discarded.

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

Note: the token exchanged during the handshake is **not** encrypted and can be
read by anyone observing the network. It must not contain passwords or other
secret data.


Phase 2: joining the network
****************************

The initiating node transmits a *join message* to its peer. The join message
contains the identity of the entity that owns the node. This identity may be
identical to the node identity. If they differ, then the identity also contains
the token hash of the node token to identify the correct node (also used for
routing purposes later).

The receiving node can authenticate and authorize the identity requesting
access to its network, either by providing the defined callback functions, or
by forwarding the data to a different, authoritative node.

If the identity of the node requesting join access cannot be
authenticated, the handshake protocol sends a *not-acknowledge message* back to
the sender, and the identity and node data is marked as obsolete and deleted
later (because sending the not-acknowledge still requires the established
session key).

Otherwise, the initiating node has been authenticated and authorized, and will
be added to the peer’s routing table. Additionally the join request is
acknowledged to the initiator. Existing peers of the network will receive an
*update message*, notifying them that a new node has joined the network.

After receiving the acknowledgement, the initiating node can begin to exchange
update and *piggy messages*. These messages will supply the node with
additional information about the network it has joined. It can then decide
whether it would like to join other nodes on the network as well.


Phase 3: growing the peer-to-peer network
******************************************

Authenticated and authorized nodes exchange update and piggy messages in order
to exchange information about other peers known to them. After receiving an
update or piggy message, a node decides whether it would like to join the new
nodes, or whether it will merely forward the information.

The decision to join a new node is based on the distance between the node’s own
token hash and the hash of the peer’s node token, as well as the soft state of
its routing table (i.e., occupancy and individual route health inferred from
latency).


Phase 4: message exchange; communicating message availability and interest
**************************************************************************

Two nodes in the network that would like to exchange information about a given
*subject* get in touch as follows. Each node communicates his special interest
(sending or receiving) of a subject to the *subject coordinator*: the node
whose node token hash is the closest to the subject hash at the time. The
subject coordinator then collects both requests, and passes on the information
to the peers involved. Filtering of tokens based on the *audience* field will
be applied here.

Message interest and availability are encoded as tokens that contain additional
information about the type of message exchange, the current threshold and some
other values as well, and are signed by their originating identity.

Each node can once more authenticate and authorize the identified peer by
verifying the exchanged token. Once the correct peer has been identified,
message exchange happens independent of the coordinator.
