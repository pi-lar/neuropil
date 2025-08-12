..
  SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0


===============================================================================
Zero Discovery / Privacy by Design
===============================================================================


How do the overlay network and token structures mentioned in the core concepts 
relate to the "privacy by design" approach of neuropil?

The DHT of the neuropil cybersecurity mesh introduces already a first important step to
ensure privacy: Connections are build up based on hash distance. This is in contrast
with the traditional internet, where first a lookup of DNS name happens, and then
the connection to a specific server is established. Using the hash distance builds up
arbitrary connections that do not carry any further meaning than ... hash distance.

Second, we use stacked digital identities: the user or application identity is stacked 
upon the node identity (with an automated cross-signing between the both). Only the node
identity should be visible to neighbor nodes. At least in theory the node fingerprint 
could change frequently or an identity could use several nodes to gather data from peers.

Third, our realm concept changes the fingerprint of an application identity. As the 
fingerprint is the most important part to identify partners in the network, you can 
easily establish different fingerprints for different purposes or for different roles. 
The public key is then the only link between these different tokens. But with each realm
that is used a user will receive a different pseudonym (different fingerprint).

The message intents are the place where node and application identity play together. 
The only thing of the application identity that remains visible is its public key and 
its fingerprint. The exchange of the message intents can be seen as the "DNS lookups" 
of the neuropil cybersecurity mesh. But we only try to discover named data channels (and 
yes, a name may refer to an IP address). The difference of these intents to DNS lookups
that they are cryptographically signed and that they are attribute bearer token.

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

But: there is still a one to one mapping between the two. Which reveals the real problem 
when talking about privacy: communications could still be traced to single entities. Even 
if the real entities behind a 256-bit hash are unknown when looking only at neuropil, a 
real entity could be revealed with added additional information from outside (i.e. just 
trying the 256-bit hash of an mail address could be a good start). The message intents 
also carry more information than we would like to present to other nodes after the first 
contact.

The question thus arises: which additional measures could we implement to enhance our 
discovery and attribution of messages to single entities? The answer is pretty simple: 
we need a form pseudonymization. Pseudonymization in general means: you are further obfuscating 
data in a way that it cannot be traced back to a single entity, but rather to a group. 
Discovery of identities, message topics and realms should be done without a "one to one"
mapping. But what is a proper way to pseudonymize 256 bit hash values? How can you pseudonymize
a set of attributes?


Entering the Bloomiverse
===============================================================================

A while ago we stumbled upon :ref:`Bloom filter<neuropil_knowhow_bloomfilter>`, which can be
used to identify a set of entities within a universe. The set of entities (the ones we would
like to detect) is usually known beforehand. Bloom filter belong to a class of probability
algorithms, because the answer given is not "true" or "false", but rather "maybe" and "false".
A Bloom filter always introduces a uncertainty for results, or in other words: a false 
positive rate. There are a couple of alternative Bloom filter designs that enable you to handle
different scenarios, ranging from data duplicate detection to black- or whitelisting.

Our idea is simple: use the false positive rate of a Bloom filter as a form of 
pseudonymization for neuropil. We can simple use the 256 bit hash value and map
it to the bits of Bloom filter in order to obtain a pseudonymized form. The false 
positive rate (e.g. 1-in-1024) defines the rate of "similarity" (read: every 1024th
node/entity/topic could have the same Bloom filter like you).


Improvements for neuropil
===============================================================================

We can use this to our advantage for a couple of improvements in neuropil:

- message subject or message subject discovery can be transported as a Bloom filter only.
  we don't care about exact values, but prefer the distribution of probability information 
  together with a distance info as the first step.


- this information can then be broadcasted to our neighbor nodes. Using a max distance
  will prevent the spreading of local information across several networks (where they
  do not belong). At the same time we enable the global discovery of subjects by simply
  allowing more "distance". (This is actually following the :ref:`ant based routing protocols<neuropil_knowhow_routing>`)


- if a node and its subjects disappear, the information will not be "refreshed" and the 
  corresponding Bloom filter will simply disappear for routing decisions. ("distance" and
  "age" can be seen as synonyms). Other nodes will use the concept of "decaying" our Bloom
  filter to purge old information from their cache.


- travelling messages with content rejuvenate the "age" and further strengthen cache entries. 
  This will result in a dynamic establishment of delivery trees across the overlay network. 
  Each delivery tree is completely independent from the base topology! The discovery of
  content channels would work in mesh / radio networks as well as in connection based systems.


- we could add further information about the strength of each node for the delivery
  of messages. "stronger" nodes should be preferred when routing messages to target peers.


- just to be sure: to exchange the public keys for the end-to-end encryption we still have 
  to transport the full token structure across the overlay network. The difference is: we 
  do this now with a strong indicator where our partners are, and do not blindly send some 
  data to its nearest hash value


- as the last step: we could remove the "target" (and our sender?) field from our message 
  structure. This would save us 128bit of message size and decrease our technical security
  payload a lot.


.. raw:: html
   :file: ./pheromone.svg


First technical design
===============================================================================

.. NOTE::
   The technical design to implement our neuropil bloom filter and the lookup table is work 
   in progress.

We orientate on the scaleBF (see :ref:`scaleBF<neuropil_knowhow_bloomfilter>`) Bloom filter 
implementation, which unfortunately lacks the ability to delete items from it.

- A bloom filter is treated as an 3D cube (with each edge length (el) being a prime number) and
  with `el(x) != el(y) != el(z)`. For the calculation of the (bit) position in one cube(x)
  (`= H(x)%el(x) * H(x)%el(y) * H(x)%el(z)`). Furthermore we will use four 3D cubes per filter, 
  because we can split our existing 256bit hash values (e.g. the hash value of a topic `H(topic)`) 
  into a eight uint32_t tuples and then use two values per cube. I.e. we can interpret the first 
  two uint32_t for the first cube, the next two for the second cube and so on. One single Bloom 
  filter then consists of four cubes.


- The values in this cube will not be a single bit, but we would like to use two uint8_t values. 
  The first uint8_t for the distance from origin using simple bit shift << operator (max distance is 
  8 hops). The second uint8_t as a counting Bloom filter. This will allows us to react on a possible 
  deletion of elements, but more important it will give a better indicator how many times a value 
  has been referenced.


- The filters will be organized with a simple hash map, the size of the hash map will be 257 bytes.
  The index position of the hash table will be calculated by a modulo division ( `H(topic)%257` ).
  Each hash map position will not contain a simple list of bloom filter. Instead we create an array
  of 32 bloom filter, where the first bloom filter will just contain the union of the remaining 31
  entries. Together with each bloom filter entry we store a np_dhkey_t of the peer where the filter
  was coming from. That means that there could be more than one np_dhkey_t for a given topic, i.e.
  if more than one receiver is attached to a sender.

.. NOTE::
  Unfortunately we were unable to prove the scalability of the scaleBF filter, so we cannot simply
  add another bloom filter for the next 32 elements. For the first attempt the partitioning via the
  hash map will be sufficient to handle most intents. The implementation could handle `257*32 > 8000`
  different intent scents.


- To transport a bloom filter, the serialized form of such a Bloom filter will really just be
  an `uint16_t` indicating the hash map position and `uint16_t[8]` array indicating the position 
  in the cubes. This serialization (17 bytes) will be less than the real size of the Bloom filter. 
  Pushing more than one bloom filter into update/intent message will be possible. Update/Intent
  messages will receive an additional signature (chained hmac) by each node on the path. Each node can 
  therefore calculate the age or distance of the bloom filter itself.


- upon sending data, this table can be inspected in addition to the normal routing table. The 
  heuristic value for a given topic can be used to alter the routing decision which is just based
  on minimizing hash distance. The current routing decision already covers latency (double) and 
  health status of a peer connection. In addition we can now add the heuristic value to the set. 
  A message will thus be routed to a multiple peers if a certain threshold value has been reached.


- on a regular basis our the filter will loose information, i.e. the reference count will be decreased.
  If a single bloom filter has reached zero, it will be deleted from the set.


What have we achieved after completing this step: sender and receiver can do an discovery of shared interests
based on a probability of our bloom filter. Before sending out any further full intent token, we can check for
the chance that our intent could reach its goal. 

On the next step, we will show you how we can further improve our discovery.


What are our nodes actually talking about?
===============================================================================


As shown in the paragraph above the bloom filter give us an different abstraction layer. It allows us to hide
plaintext values behind bloom filters. On the downside of it is the fact that we now are unable to
match intents to each other while they are spread out, because we only see the bloom filter.

But an even bigger topic that we have to tackle is the specific semantic content of intent messages. 
Consider the following example: you create an intent token and attached to it a set of attributes. 
These attributes can describe usage policies, license information or access policies / rules. Usually 
there is a definition of the complete "business" semantic, defining the description logic / predicates 
which has to be done before a protocol is used. You can treat this definition of the semantic as a rather 
heavyweight task, and each semantic definition adds it's own quirks, execution size and rules. But if 
each user of the neuropil cybersecurity mesh can add new additional attribute / attribute values or a new 
semantic definition, then the neuropil cybersecurity mesh will never be able to match these intents to each 
other! Out of experience we can tell you: Implementing these always changing semantics into a middleware 
is no going to work! (It's not that these semantics are not necessary, it is just that a classic middleware
must be agnostic up to a certain point against it's payloads definitions). We have to accept the fact that 
we do not know (and will never know) the precise format/semantics of all values or attributes. But still 
we would like to be able to compare two intents to each other, to enforce certain rules and behavior before
an application has to deal with it (i.e. HTTP is a protocol that has never thought about this specific aspect,
and each addition of HTTP is adding exactly the complexity that I've been describing above).

Luckily, the bloom filters described above are there to help us again!
Here is how: instead of comparing the values or a semantic vocabulary directly, we build a bloom filter from 
the set of attributes. Let's stay practical and look at an example. Let's say we have the following token, 
plus a list of required and optional attributes:

.. code-block:: JSON

   {
      "iss": "a9624ed8",
      "sub": "048271ba", // this field indicates the topic
      "iat": 1516239022,
      „pub“: <binary data>
      required {
         „max_size“: 3000,
         "sessionid": 7201937673920183,
         "roles": <bf(role)>
         „usage“: „scientific“
      }
      optional {
         license: „Creative Commons 4.0“
      } 
   } + sig


Then we can turn these attributes into a kind of "normalized" bloom filter format with three different sections:

.. code-block:: javascript

   bloom filter (subject):
   bfsub +=  bf(sub)

   bloom filter (required):
   bfR += bf(„max_size“) + bf(3000) // check for both: key and value
   bfR +=  bf(„sessionid")          // leave out the value here because we only want
                                    // a sessionid to be present
   bfR += bf(„roles“)               // the key
   bfR |= <bf(role)>                // and adding the role bf by doing an intersection
   bfR += bf(„usage“) + bf(„scientific“)

   bloom filter (optional):
   bfO += bf("license") + bf(„Creative Commons 4.0“)


The point is: we are able to compare attributes of any token in a easy and fast way, yielding a result that
matches the probability of our bloom filter. Thus we are filtering many wrong or malicious uses of services
or data content without actually understanding the meaning of what has been send.

In the first step we compare two message intent token if they share the same subject:

.. code-block:: javascript

   bfsub (Sender)  == bfsub (Receiver)


In the second step we can check whether all required attributes are contained in the opposite token:

- we can create an intersection of the sender and the receiver bloom filter. This intersection will give us 
  our "Match" bloom filter, which can be the be used by

- doing the intersection of the "Match" bloom filter with the receiver/sender bloom filter. This should return 
  the receiver/sender bloom filter again, otherwise an required attribute is been missing.

.. code-block:: javascript

   bf (Match) = bfR (Sender) & bfR (Receiver)

   bf (Match) & bfR (Receiver) == bfR(Match)?
   bf (Match) & bfR (Sender) == bfR(Match)?


As a third and last step it is possible to create the union of sender and receiver intents and their contained
optional attributes. This gives us an impression how many common items the two filter have. The result is a 
probability, the higher the probability score is the more likely it is that two intent could match. We could 
also use the hamming distance to count the number of "1" that are different between the two bloom filter.

.. code-block:: javascript

   bfO (Sender) | bfO (Receiver)


Please note that these steps can be performed anywhere within the neuropil network without prior knowledge of 
a vocabulary or message definition. By using arbitrary key/value pairs a user can always create it's own 
"security" domain which is enforced through the neuropil network. 

.. NOTE::
   The last check is always on the end user!
   We just make sure that the intents users receive have high probability of success.


The above mentioned comparison (using intersections and unions) is also known as the Jaccard-Similarity
and is calculate by dividing the intersection (e.g. the number of bits set after doing the intersection)
with the union (e.g. the number of bits set after doing the union). The result is again a probability
between 0 and 1 (e.g. 0.66). We can use this information especially in a later step when comparing the
optional fields of two attribute sets.


To summarize the two previous chapters:
Discovery is performed by sending out pheromone messages. These pheromone messages bear the scent of 
the data object itself, but also a set of required attributes encoded as a bloom filter.
If a message is send, it just has to follow the path of the pheromones and will reach its target.

As messages also carry attributes it is an option to match these attributes against the bloom filter 
of the pheromones at each step. Then the bloom filter would also act as a "filter" for data objects,
and we could establish highly dynamic delivery chains of data objects throughout the network.


More than just a bunch of strings
===============================================================================

In the example above we have only used simple strings for keys and values to illustrate the basic principles.
In the real world you will have complex structures that need to be compared. For example you could use WS-Policy
to express more technical details about your access token:

.. code-block:: javascript

   <wsp:Policy
        xmlns:sp="http://schemas.xmlsoap.org/ws/2005/07/securitypolicy"
        xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" >
      <!-- Intersection of P1 and P2 -->
      <wsp:ExactlyOne>
         <wsp:All>
            <sp:SignedParts >
               <sp:Body />
               <sp:Header Namespace="http://schemas.xmlsoap.org/ws/2004/08/addressing" />
            </sp:SignedParts>
            <sp:EncryptedParts>
               <sp:Body />
            </sp:EncryptedParts>
            <sp:SignedParts />
            <sp:EncryptedParts>
               <sp:Body />
            </sp:EncryptedParts>
         </wsp:All>
      </wsp:ExactlyOne>
   </wsp:Policy>

We could also use a ODRL policy to indicate the desired usage for your data objects. The below example
is a rather generic allowance to use a movie data object (copied from the ODRL samples webpage):

.. code-block:: javascript

   {
      "@context": "http://www.w3.org/ns/odrl.jsonld",
      "@type": "Set",
      "uid": "http://example.com/policy:1010",
      "permission": [{
        "target": "http://example.com/asset:9898.movie",
        "action": "use"
      }]
   }


How can we add these complex structures into our attribute set and filtering? Luckily there is 
another way to compare a set of words, and the algorithm is called "minhash".


Minhashing data structures
===============================================================================

The "minhash" algorithm basically creates a fingerprint of a document. This fingerprint is based on
the calculation of the minimum hash values for a given input. Defining the input is a bit difficult.
You can use k-grams, that is you divide your text into equally sized "text blocks". Or you can use 
shingles, that is teh breakdown of a text into set of words. Let us look at the second example above
and write it as a 9-gram (read nine characters) and as an 3-shingled (three words) document: 

.. code-block:: javascript

   {"@contex
   t":"http:
   //www.w3.
   org/ns/od
   rl.jsonld
   ","@type"
   :"Set","u
   id": "htt
   p://examp
   le.com/po
   licy:1010
   ","permis
   sion":[{"
   target":"
   http://ex
   ample.com
   /asset:98
   98.movie"
   ,"action"
   : "use"}]
   }


.. code-block:: javascript

   { "@context" : 
   "@context" : "http://www.w3.org/ns/odrl.jsonld"
   : "http://www.w3.org/ns/odrl.jsonld" ,
   "http://www.w3.org/ns/odrl.jsonld" , "@type"
   , "@type" :
   "@type" : "Set"
   : "Set" , 
   "Set" , "uid"
   , "uid" : 
   "uid" : "http://example.com/policy:1010"
  : "http://example.com/policy:1010" , 
  "http://example.com/policy:1010" , "permission"
   , "permission" : 
   "permission" : [
   : [ { 
   [ { "target"
   { "target" :
   "target" : "http://example.com/asset:9898.movie"
   : "http://example.com/asset:9898.movie" , 
   "http://example.com/asset:9898.movie" , "action"
   , "action" :
   "action" : "use"
   : "use" }
   "use" } ]
   } ] }


It is actually very important which integer values you use for k-grams and n-shingles. As a matter 
of fact, the human language carries an in-build bias. E.g. news generally use shorter words, and 
you  can identify news websites because of this. The human language also contains a lot of so 
called stop words (like "the") that do not carry any meaning and usually are filtered out because 
the result of minhashing this text would be flawed. So on the downside of it the human language in 
general seems to be tricky to handle and needs manual re-adjustment and tweaking of the algorithm 
details. On the positive side you should recognize that it actually doesn't matter what you are
analyzing with the minhash algorithm (could be sound, genetic sequences, ...), because what you 
will get is the similarity of two sets of "words"!


.. NOTE::
   For the full mathematical details please read the online book "Mining of massive data sets"
   (http://www.mmds.org/)


So for each of the above mentioned k-gram or n-shingles the minhash algorithm will calculate m hash
values, and use the lowest one. The calculate the hash values, you can use m different hash functions, 
or use random permutation. Hash function can be "seeded" for additional randomization, but if you 
would like to compare two set or words, then the same seed has to be used.

From all created hash values a so called minhash signature can be collected, which just is an array 
of the smallest hash values. This signature is the equivalent of a random selection of words for a 
document (the selection of these words is based on the minimum hash value).

If two signatures have been created for two different ODRL policies, then it is possible to compare
these two policies by their minhash signature! This comparison is again based on the Jaccard-Simmilarity,
but is is much easier to calculate. Plus it is not required to compare each single document pair, but 
only those that we are actually interested in.


Technical design of the neuropil minhash signatures 
===============================================================================

- If the value of an attribute is longer than 64 bytes, then we will create minhash signatures
  to compare against. For required attribute values we can expect a 100% match, for optional attributes
  this value can be lower


- to create a minhash signature we will use n-shingles (5-shingles for a start). Furthermore we will seed
  the used hash function with the cryptographic hash value of the message subject to prevent possible 
  duplicate. Our hash function will be the siphash-2-4 family (already defined and implemented in libsodium)


- for each semantic input model like e.g. ODRL policies the definition of the used n-shingles has to be 
  done and implemented. This input mapping can be different for each attribute set that we would like
  to compare. As the attribute key indicates the type of an object


- stop words of the specific sematic input model will be removed (e.g. "@context" is part of the semantic
  definition that will not help to identify different policies)


- the minhash signature for attributes will be smaller than for full size text document. For a start we 
  will only use 16 32-bit integers, which is still better than transporting 10kB of text in the pheromone
  messages.


- messages for a given subject can be attributed with a minhash signature as well. Comparing the minhash
  signature of a message with the minhash signature of a pheromone is not expensive. That means we can 
  establish distributed filter sets for each data channels (yay)!


This closes our first part of the NGI Zero Discovery implementation. I hope you found some information
on this page useful. If you have any questions or comments, please do not hesitate to get in contact 
with us.


General Remarks
===============================================================================

- a 256bit hash of a string is not a good password encoding, e.g. it is not salted!
- we still need to transport public keys for enable trust an confidentiality.


https://www.w3.org/Submission/WS-Policy/

https://www.w3.org/TR/odrl-model/#infoModel

