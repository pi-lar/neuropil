..
  SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0

.. _realms:

===============================================================================
Realms
===============================================================================

When an identity references another identity as its *realm*, it allows itself
to be subordinated to that identity. In this case, the former is called the 
*realm follower* and the latter the *realm leader*. The realm follower has to 
be authenticate and authorize by consulting with the realm leader.

Followers within the same realm only need to trust the realm leader, but not
each others individually. By rallying around a realm leader, a central entity
can extend authorization, but also revoke it, without consulting with the
followers individually.

The following picture identifies the interaction that are needed to realize a complete
realm space. We will describe each step in the following listing to later add some
more details towards an implementation.

.. raw:: html
    :file: ./realm.svg


Step 0: bootstrapping
===============================================================================

Any node may use so called bootstrapping nodes to connect to a larger system.
A bootstrap node must only be used for authentication, it is not allowed to receive
any data through another authorization. Bootstrap nodes can be operated with
certain SLA aggreements and mainly serve as entry points into the neuropil network.
If each company operates a bootstrap node, which are cross-connected, then no
central entity will be needed. 


Step 1: Registration
===============================================================================


any node may register, or rather aplly for a registration at a realm. The realm 
can decide on its own whether it would like to add the new node as a follower.


Step 2: Attribute application
===============================================================================


If the node has been accepted by the realm, it will receive a set of attributes.
This can happen for each subject, or for the identity token only. It will also receive a 
signature of the realm for it's identity token or for the subject token only.

neuropil allows the addition of several (but not infinite) signatures to a token,
which allows for two factor authorizations, i.e. the subject token must contain two 
signatures.


Step 3: Data exchange
===============================================================================


In the initial step the security token or message intent token between the participating 
nodes are exchanges. Each token has been equipped with the corresponding attributes and
signatures of the realm.


Step 4: Realm validation request
===============================================================================


Each node can forward the received token to their respective realm for inspection and
authorization purposes. The local node is either freed from the decision, or it will 
receive a policy from their realm that allows the verification on its own.


Step 5: Realm verification
===============================================================================


A realm may consult with another realm to see whether the infromation provided in the
security token is correct. The communication could also happen upfront, that is a realm
can pro-actively inform other realms of their information exchange interest.


During the realm validation and verification phase at least two different subjects weill be needed. 
The first one will transport the currently active supported child nodes, the second one will be used
to transport revoked nodes. As an option there could be a third where the time-to-live has ended.
As a format for the transportation the XMSS scheme (see RFC 8391) is currently our candidate.

