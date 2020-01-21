Zero discovery / privacy by design
====================================

How do the overlay network and token structures mentioned in the core concepts 
relate to the "privacy by design" approach of neuropil?

The DHT of the neuropil messaging layer introduces already a first important step to
ensure privacy: Connections are build up based on hash distance. This is in contrast
with the traditional internet, where first a lookup of DNS name happens, and then
connect to a specific server. Just tracing your DNS lookups can already be enough for
conclusions to be drawn about your life. Using the hash distance builds up arbitrary 
connections that do not carry any further meaning than ... hash distance. 
Second, we use stacked digital identies: the user or application identity is stacked 
upon the node identity (with an automated cross-signing). Only the node identity should
be visible to neighbour nodes, and, at least in theory, the node could change frequently
its fingerprint. 
The message intents are the place where both idenities play together, so the only thing
of the application identity that remains visible is its public key and its fingerprint. 
The exchange of the message intents can be seen as the "DNS lookups" of the neuropil 
messaging layer, but we only try to discover named data channels (and yes, a name may 
refer to an IP address).

.. NOTE::
   The following work on this page will be part of our funding granted by NGI Zero.
   We are very happy and pleased that we have been selected with our proposal.

.. image:: _static/ngizero.png
   :align: left
   :alt: NGI Zero discovery
   :target: https://www.ngi.eu/about/ngi-zero/

A quick recap of the token structure will show you: neuropil hides everything
within a 256-bit address space or a fingerprint. It doesn't matter whether for identities,
message topics, realms or simple physical nodes: all are mapped and forced into the same 
addressing scheme. When looking especially at a 256-bit hash of a simple string, the real 
string is hidden and finding the reverse mapping is ... hm ... difficult. 

.. image:: _static/nlnet.gif
   :width: 50%
   :align: right
   :alt: NLnet Stichting
   :target: https://www.nlnet.nl

But: there is still a one to one mapping between the two. Which reveals the true problem 
when talking about privacy: communications could still be traced to single entities. Even 
if the real entities behind a 256-bit hash are unknown when looking only at neuropil, a 
real entitiy could be revealed with added additional information from outside (i.e. just 
trying the 256-bit hash of an mail address could be a good start).

The question thus arises: which additional measures could we implement to prevent 
this kind of discovery and attribution of messages to single entities? The 
answer is pretty simple: we need a form pseudonymization. Pseudomization in general
means: you are further obfuscating data in a way that it cannot be traced back to a
single entitiy, but rather to a group. 
Discovery of identities, message topics and realms should be done without a "one to one"
mapping. But what is a proper way to pseudonymize 256 bit hash values?


Entering the Bloomiverse
************************

A while ago we stumbled upon :ref:`Bloom filter<neuropil_knowhow_bloomfilter>`, 
which can be used to identify a set of entities within a universe. The set of 
entities (the ones would like to detect) is usually known beforehand. There 
are a couple of alternative Bloom filter designs that enable you to handle different 
scenarios. Bloom filter belong to a class of probability algorithms, because the 
answer given is not "true" or "false", but rather "maybe" and "false". A Bloom 
filter always introduces a uncertaintity for results, or in other words: a false 
positive rate. 

Our idea is simple: use the false positive rate of a Bloom filter as a form of 
pseudonymization for neuropil. We can simple use the 256 bit hash value and map
it to the bits of Bloom filter in order to have a pseudonymized form. The false 
positive rate (e.g. 1-in-1024) defines the rate of "similarity" (read: every 1024th
node/entity/topic could have the same Bloom filter like you).


Improvements for neuropil
*************************

We can use this to our advantage for a couple of improvements in neuropil:

- message subject or message subject discovery can be transported as a Bloom filter only.
  we don't care about exact values, but prefer the distribution of probability information 
  together with a distance info.

- this information can then be broadcasted to our neighbour nodes. Using a max distance
  will prevent the spreading of local information across several networks (where they
  do not belong). At the same time we enable the global discovery of subjects by simply
  allowing more "distance". (This is actually following the :ref:`ant based routing protocols<neuropil_knowhow_routing>`)

- if a node and its subjects disappear, the information will not be "refreshed" and the 
  corresponding Bloom filter will simply disappear for routing decisions. ("distance" and
  "age" can be seen as synonyms). Other nodes will use the concept of "decaying" our Bloom
  filter to purge old information from their cache.

- travelling messages with content re-juvenate the "age" and further strengthen cache entries. 
  This will result in a dynamic establishment of delivery trees across the overlay network. 
  Each delivery tree is completely independant from the base topology. The discovery of
  content channels would work in mesh / radio networks as well as in connection based systems.

- we could add further information about the strength of each node for the delivery
  of messages. "stronger" nodes should be preferred

- to exchange the public keys for the end-to-end encryption we still have to tranposrt the 
  full token structure across the overlay network. The difference is: we do this now with
  a strong indicator where our partners are, and do not blindly send some data to its nearest
  hash value (although there will still be a "target" value).


First technical design
**********************

.. NOTE::
   The technical design to implement Bloom filter is work in progress

We orientate on the scaleBF Bloom filter implementation, which unfortunately lacks the ability
to delete items from it.

- A bloom filter is treated as an 3D cube (with each edge length (el_?) being a prime number) and
  with (el_x != el_y != el_z). For the calculation of the (bit) position in one cube(x)
  (= H(x)%el_x * H(x)%el_y * H(x)%el_z). Furthermore we will use four 3D cubes per filter. 
  We can split our existing 256-hash values (e.g. the hash of a topic, H(topic) = 256bit hash) 
  into a eight tuples and then use two values per cube. i.e. we can interpret the first 2 uint32_t
  for the first cube, the next two for the second cube and so on. One single Bloom filter then 
  consists of 4 cubes.

- The values in this cube will not be a single bit, but we would like to use two uint8_t values. 
  The first uint8_t for the distance from origin using simple << operator (max distance is 8 hops). 
  The second uint8_t as a counting Bloom filter. This will allows us to react on a possible deletion 
  of elements, but more important it will give a better indicator how many times a value has been
  referenced.

- The filters will be organized with a simple hash map, the size of the hash map will be 257 bytes.
  The index position of the hash table will be calculated by a modulo division ( H(topc)%257 ).
  Each hash map position will not contain a simple list of bloom filter. Instead we will create 
  an array of 32 bloom filter, where the first bloom filter will just contain the union of the
  remaining 31 entries. If the first 32 cubes have reached their capacity, we can add another 
  array of 32 bloom filter. Together with each bloom filter entry we store a np_dhkey_t of the peer
  where the filter was coming from. That means that there could be more than one np_dhkey_t
  for a given topic, i.e. if more than one receiver is attached to a sender.

- To transport a bloom filter, the serialized form of such a Bloom filter will really just be: 
  uint16_t       : hash map position
  uint8_t        : age of the bloom filter
  4*(uint16_t)[2]: list of four uint16_t[2] arrays, indicating the position in the cubes
  This serialization (19 bytes) will in most cases be less than the real size of the Bloom filter. 
  Pushing more than one bloom filter into a message will be possible.

- when sending data, this table can be inspected in addition to the normal routing table. The 
  heuristic value for a given topic can be used to alter the routing decision which is just based
  on minimizing hash distance. The current routing decision already covers latency (double) and health
  status of a peer connection. In addition we can now add the heuristic value to the set. A message 
  will thus be routed to a peer if a certain threshold value has been reached.

- on a regular basis the filter will loose information, i.e. the reference count will be decreased.
  If a single bllom filter has reached zero, it will be deleted from the set.


use two bloom filter for two purposes ?
- transport the "topic" alone
- transport "topic" plus content annotations



General Remarks
***************

- a 256bit hash of a string is not a good password encoding, i.e. it is not salted!
- we still need to transport public keys for enable trust an confidentiality.

