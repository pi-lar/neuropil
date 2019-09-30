Zero discovery / privacy by design
====================================

.. NOTE::
   The work on this page will be part of the funding of NGI Zero.
   We are very happy and pleased that we have been selected with our proposal


How do the overlay network and token structures mentioned in the core concepts 
relate to the "privacy by design" approach of neuropil?

A quick recap of the token structure will show you: neuropil hides everything
within a 256-bit address space. It doesn't matter whether for identities, message topics,
realms or simple physical nodes: all are mapped and forced into the same addressing
scheme.

When looking especially at a 256-bit hash of a simple string, the real string is hidden and
it finding the reverse mapping is ... hm ... difficult. But there is still a one to one mapping
between the two. Which reveals the true problem when talking about privacy: 
communications could still be traced to a single entity. Even if the real 
entities behind a 256-bit hash are unknown when looking only at neuropil, a 
real entitiy could be revealed with added additional information from outside 
(i.e. just trying the 256-bit hash of an mail address could be a good start).

The question thus arises: which additional measures could we implement to prevent 
this kind of discovery and attribution of messages to single entities? The 
answer is pretty simple: we need pseudonymization. Discovery of identities, 
message topics and realms must be done without a "one to one" mapping. 
Pseudomization in general means: you are further obfuscating data in a 
way that it cannot be traced back to a single entitiy, but rather to a group. 
But what is a proper way to pseudonymize 256 bit hash values?


Entering the Bloomiverse
************************

A while ago we stumbled upon :ref:`Bloom filter<neuropil_knowhow_bloomfilter>`, 
which can be used to identify a set of entities within a universe. The set of 
entities, that one would liek to detect, is usually is known beforehand. There 
are a couple of alternative Bloom filter designs that enable you to handle different 
scenarios. Bloom filter belong to a class of probability algorithms, because the 
answer given is not "true" or "false", but rather "maybe" and "false". A Bloom 
filter always introduces a uncertaintity for results, or in other words: a false 
positive rate. 

What does this mean for privacy? The false positive rate of a Bloom filter defines
the pseudonymization level that neuropil requires. We can simple use the 256 bit 
hash value and map it to the bits of Bloom filter in order to have a pseudonymized
form. The false positive rate (e.g. 1-in-1024) defines the rate of "similarity" 
(read: every 1024th node/entity/topic could have the same Bloom filter like you).


Improvements for the neuropil
*****************************

We can use this to our advantage for a couple of improvements in neuropil:

- message subject or message subject discovery can be transported as a Bloom filter only.
  we don't care about exact values, but prefer the distribution of probability information 
  together with a distance info.

- this information can be broadcasted to our neighbour nodes. Using a max distance
  will prevent the spreading of local information across several networks (where they
  do not belong). At the same time we enable the global discovery of subjects by simply
  allowing more "distance". (This is actually following the :ref:`ant based routing protocols<neuropil_knowhow_routing>`)

- if a node and its subjects disappear, the information will not be "refreshed" and the 
  corresponding Bloom filter will simply disappear for routing decitions. ("distance" and
  "age" can be seen as synonyms). Other nodes will use the concept of "decaying" our Bloom
  filter to purge old information from the cache.

- travelling messages with content re-juvenate the "age" and further strengthen. this
  will result in a dynamic establishment of delivery trees across the overlay network. 
  each delivery tree is completely independant from the base topology. The discovery of
  content channels would work in mesh / radio networks as well as in connection based systems.

- we could add further information about the strength of each node for the delivery
  of messages. "stronger" nodes should be preferred


Technical design
****************

.. NOTE::
   The technical design to implement Bloom filter is work in progress

What is our technical design to enable all these capabilities?

We orientate on the scaleBF Bloom filter implementation, which unfortunately lacks the ability
to delete items from it.

A bloom filter is treated as an 3D cube (with each edge length (el_?) being a prime number) and
with (el_x != el_y != el_z).

For the calculation of the position in the cube(xyz) (= H(x)%el_x * H(x)%el_y * H(x)%el_z)

We will use 2 points per cube: 
With the hash of a topic resulting in a 256bit hash value ( H(topic) = 256bit hash), we can interpret
the first 2 uint32_t for the first cube, the next two for the second cube and so on. 
One single Bloom filter then consists of 4 cubes.

The values in this cube will not be single bit, but we would like to use two uint8_t values. 
The first uint8_t for the distance from origin using simple << operator (max distance is 8 hops). 
The second uint8_t as a counting Bloom filter, to be able to remove elements.

When the first of this Bloom filter cubes has reached its capacity, we add four new cubes.
A set of Bloom filter could be organized with a simple hash map with a prime number size:
The position in the simple hash map can be found by a modulo division of the hash value of the topic
with the simple hash map size.

A serialized form of such a Bloom filter could really just be:
(uint8_t): hash map position
4*[ (uint16_t)/(uint16_t) ]: a list of uint16_t[2] array, indicating the position and the values

which is many cases will be less than real size of the Bloom filter (17 bytes min).
with a higher fill ratio it could be better to simply transport the binary form of
the filter.


General Remarks
***************

- a 256bit hash of a string is not a good password encoding, i.e. it is not salted!
- we still need to transport public keys for enable trust an confidentiality.

