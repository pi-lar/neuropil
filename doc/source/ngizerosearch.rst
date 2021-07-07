..
  SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0

Zero Search / a Paradigm Shift
==============================

How do the overlay network and token structures mentioned in the core concepts and the ngi zero 
discovery page relate to the "privacy by design" search capabilities of neuropil?

According to the FAIR principle each data set has to conform to the following four principles 
(I will not comment fully, just with respect to our work):

- Findable
  data needs an identifier and (searchable) metadata. In neuropil the metadata are 
  our intent token, and they can be send to an hash value in the DHT, ready for other
  participants to find them.

- Accessible
  neuropil is a standardized, free and open communication protocol, and the main 
  purpose of the intent token are mutual authentication and, even more important, 
  authorization or delegated authorization. 

- Interoperable
  The hash value of a data set hash can be used as a link to other documents, resulting
  in different DAG on top of the DHT. Although neuropil is not able to understand 
  complete vocabularies, it is possible to match attributes and even more to each other. 

- Re-usable
  Data objects can be attributed with an owner and a signature, in addition to any other 
  attribute that a data owner defines. Data objects in neuropil are therefore re-usable, 
  although technically it will not be possible to guarantee accuracy and relevance of each 
  (sorry, that belongs into the OSI level eight !)


.. NOTE::
   The following work on this page will be part of our funding granted by NGI Zero.
   We are very happy and pleased that we have been selected with our proposal.

.. image:: _static/ngizero.png
   :align: left
   :alt: NGI Zero discovery
   :target: https://www.ngi.eu/about/ngi-zero/


Why is this important? We will just citation of our sponsor:

Search and discovery are some of the most important and essential use cases of the internet. 
When you are in school and need to give a presentation or write a paper, when you are looking 
for a job, trying to promote your business or finding relevant commercial or public services 
you need, most of the time you will turn to the internet and more importantly the search bar 
in your browser to find answers. Searching information and making sure your name, company or 
idea can be discovered is crucial for users, but they actually have little control over this. 
Search engines decide what results you see, how your website can be discovered and what information 
is logged about your searches. What filters and algorithms are are used remains opaque for users. 
They can only follow the rules laid out for them, instead of deciding on their own what, where 
and how to find the information they are looking for.

By incorporating search and discovery specifications into our protocol, we are able to eliminate 
the need for a central broker or search engine. The internet does not belong to a single entity, 
but is rather supported by many users and stakeholders. Each stakeholder can support each other 
in their endeavor to find answers and to discover topics and create new ideas.

Let us not forget: There is the need for resources (hardware/energy/skills/...) to maintain and 
uphold a search index. This task that has been taken by large companies in the past, and they have
not asked for money because of their ability to sell advertisement. This approach has served us
well so far, but unfortunately also with more or less privacy gaps and other related frauds.


Entering the Zero Search
************************

Our initial idea was simple: We can use the hash values of the DHT in neuropil as a kind of
catchword index. For each single document we can distribute its metadata token to several
places in the DHT. This can be done by first calculating the minhash signatures of each token
and its corresponding document / object. This signature is then distributed and, using the LSH
schemes, it is possible to compare two documents and find matches of contained data objects, 
without actually knowing anything about the real data content.

However, there is one fundamental difference in our approach: In addition to its own search 
contents, each participant will contribute a bit of search capacity for others as well. 
index content for other peers. There lies no danger in this: the only "content" that is stored 
are the intent token, the public part of the search content. The full article / dataset still 
stays behind the usual access limitations that neuropil gives you. This is the only way how
search can be maintained at no costs, but carried by many participants.


Improvements for neuropil
*************************

The implementation of the LSH comparison matrix is a clear benefit for neuropil. 
We do not have to compare each token with each other, but just the ones we have 
stored at a certain position in the hash table. This limits the amount of required 
comparison steps (which is the main purpose af LSH anyway). Furthermore we can fine 
tune the result set to only match data objects that have a probability 0.8 or more. 

In the case of our discovery algorithm we used the hash value of the message subject
so that token could meet, but we always just forward and do not store any token, based 
on the pseudonymized meta-data available at each routing step. 

For searching we need a new content based rendezvous points, where search index entries 
and search queries can meet and exchange. Thus we have to construct a new 
distributed data structure sitting on top of the DHT, that is maintained and managed 
by "search" nodes only. This makes perfectly sense as not all nodes of the DHT will have 
enough resources to add search capabilities. We have to explicitly define and implement "search"
nodes withing the DHT, that are able to handle the expected load. And we now would like 
to store more data and possibly also an access token in our DHT. 

Starting point for search content
*********************************

This also opens the path to a first data definition that will be needed for search content. Our 
main data object is the intent token, and this will already give a good data ownership. As most 
parts of the intent token contains hash values, they are not good to derive any further searchable
content, therefore the attributes (claims) of an intent token can be used for datatype specific extensions.
E.g. one could use the meta tags of HTML pages (please ignore for now that these elements are ignored 
by crawlers). Let's have a look:


.. code-block:: html

    <meta name="description" content="Lorem ipsum dolor sit amet, consetetur sadipscing elitr." /> 
    <meta name="keywords" content="keyword_1, keyword_2, keyword_3" /> 
    <meta name="author" content="Author Name" /> 
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" /> 
    <meta http-equiv="expires" content="Expiry in seconds" /> 


The same kind of meta data can be defined for other documents as well. We enrich the intent token
with the needed data structures to create and distribute searchable entities.


Comparing search content
************************

In order to reduce the needed semantic complexity, the above intent token (plus it's attributes) will be 
added to a bloom filter. Quite nicely, PPRL (privacy preserving record linkage) defines the layout of
such a data structures based on bloom filter. To our own surprise, our neuropil bloom filter, implemented
in our NGI discovery part of the project, are matching the PPRL definitions, with a few limitations or
constraints, e.g. for single values we always use Blake2b hashing and do not allow for any other hashing.
The size of our PPRL is fixed (around 1020 bits). For a list of keywords we will add minhash signatures 
that are implemented on shingling, not n-grams (but that could be changed later).

Comparing search entries is thus just a matter of comparing a set of bloom filter, namely the CLKHash 
(Cryptographic Longterm Keys) representation derived from our intent token. As these are just bloom
filter values, the implementation of comparing CLK data structures should be possible in an efficient way.


New content index for search content
************************************

We still need a new rendezvous point for the above data structures. There are several LSH approaches
out in the world, but we found most of them unsuitable for our specific approach. Either the targeted
probability is static (classic LSH), or the LSH scheme uses a dynamic number of bits (LSH Forest). 
Several schemes have elaborated on the fact that a query contains mostly a smaller dataset than the
actual document (EnsembleLSH), or that the used buckets could be too full (BoundedLSH). Each of the 
mentioned has positive characteristics, but also some drawbacks. 

Data dependent hashing or Locality Preserving Hashing (LPH) is an alternative approach that is widely
used in malware detection or for similarity of documents. E.g. SSDEEP allows you to detect changes in 
a document, even if only the last part of the document has been changed. This is a interesting
capability of the algorithm, because it allows you detect which parts of a text are similar. TLSH is
a newer approach (a "fuzzy hash"), which is more robust against attacks. All data dependent hashing 
schemes share one common property: they have a variable length.

Our goal is to find a kind of data dependent hashing scheme, that works well on / only uses 256-bits 
for the final rendezvous point. Once this rendezvous point has been found, the corresponding node can
any database system to store and compare CLKHash values, returning/forwarding the attached intent token
of sender/receiver to the identified actors. 

So finally: what is our content index (aka rendezvous point, aka clustering index)?

We use a counting bloom filter and treat item of the filter as if it would be representing one table
(or a LSH bucket). We then hash the attributes and the minhash signature of keywords (or text) into
the filter, which gives us a hint of the relative importance of each bucket for the specific search content.
Across this counting bloom filter we apply the TLSH technique: the resulting count across the buckets
can be split into octile values, each bucket then falls into a specific octile. After a iteration over
all buckets we get the data dependent bitset that represents the relative importance of each bucket.
It is a bit weird, because we are only looking at the importance of buckets in relation to their minhash
values, but: it works. We have succesfully distributed search entries over a set of 4096 nodes and were
able to find all inserted entries. 

.. NOTE::
   There are several variations possible to the scheme, and we still have to experiment with more data 
   to verify that our approach works for a) many different and b) huge number of data sets.

The data dependency allows us also to compare only parts of the new content index. Even if the first bits do
not match, later bits may show a series of common bits / importance and we can identify the corresponding 
node in the network which closely matches this bitset (in terms of hamming sub-distance).

So our final search entry actually can be defined as follows:

.. code-block:: javascript

    struct np_index;   // the new rendezvous point
    struct clkhash;    // the cryptographic longterm key of the search entry
    struct intent_jwt; // the intent token plus its attributes


The nice part of this structure is: starting with the intent token, the other two properties can be
derived from this single structure. There is no way of flooding an index node with content that doesn't 
match the intent token, because this could be re-constructed at any time in the network. And as each 
participant in the neuropil network can be identified with its digital identity, the author of each 
search entry is known as well (contributing to data provenance).

How can a node tell the other nodes that it would like to participate in the global search endeavor?
It simply picks a random hash value and registers with two virtual neuropil MX properties (virtual 
because there will be no data transmitted over the data channels, we just need them to transport our
identity information and to setup the search hash space). When a node receives a new node it can check
which random hash value this node will be taking care of and add it to its internal search table. In 
addition we can derive an encryption between these two nodes which will be used to encrypt the data 
for communication between these two nodes. In addition to these two mx properties, each node will 
listen to the random hash value and listen on it for queries and new search entries.

.. code-block:: javascript

    enum np_data_return np_set_mxp_attr_bin(ac, "urn:np:search:node:add", NP_ATTR_INTENT, "urn:np:random:hash", <random hash value>, NP_PUBLIC_KEY_BYTES);
    struct np_mx_properties search_node_add = np_get_mx_properties(ac, "urn:np:search:node:add");   // announcing a search node
    struct np_mx_properties search_node_rem = np_get_mx_properties(ac, "urn:np:search:node:remove");   // removing a search node

    struct np_mx_properties search_entry = np_get_mx_properties(ac, "urn:np:search:entry:<random hash>");   // announcing a search node
    struct np_mx_properties search_query = np_get_mx_properties(ac, "urn:np:search:query:<random hash>");   // announcing a search node



    // use more than one search "subject"!
    // "search" + shingle size + search space = dhkey for msg subject
    // query contains target probability that is used for searching documents
    // query contains a "required" bloom filter that is used to compare and search for data objects
    // "required" bloom filter always has a target probability of 1.0
    // query contains a "optional" bloom filter that is used to compare and search for data objects
    // "optional" bloom filter will use the target probability of the query to match elements
    // --> the target probability can be used for comparing Jaccard similarity of minhash results

    // each node can define to which shingle size it would like to respond to
    // for each searchable document plus it defines an attribute bloom filter:
    // add required document attributes to the required bloom filter
    // add minhash signature and optional document attributes to the optional bloom filter
    // --> size of optional bloom filter depends on shingle size (e.g.256 for 1 shingles, then double)
    // --> size of optional bloom filter depends on shingle size (e.g.512 for 2 shingles, then doubled)
    // --> ...
    
    // just like in our pheromone routing: each search node can add other search fingerprints to
    // its own database (a skiplist). Each node forwards its search entries to other nodes
    // we do not need to use dhkeys, but the bloom filter structure as the ordering element
    // additionaly we keep/maintain a skipgraph that matches "closer" search entries.

    // How is the membership vector of a search defined? 
    // construct the (several) dhkey from a minhash, size of minhash has to be a multiple of 8*uint32_t,
    // minimum size is one octet(= dhkey)
    // several dhkeys can be added to get more than one point in search "space", same effect as hashing concatenated rows
    // -> entries can be added multiple times (in different hash tables) with different levels of detail
    // whether a node will add an entry to its skiplist depends on a comparison of node dhkey and the 
    // concatenated bloom filter. It is possible to take other search peers into account to further divide
    // the available search space.
    // Additionally we can use the Jaccard similarity as a measure whether similar bloom filter can be 
    // joined into a single filter, or to limit the length of each skiplist.

    // we reverted the search queries: search data structures are made available from bottom down 
    // to "upper levels", queries can then be forwarded to the nodes where the bloom filter matches best.
    // the final nodes can match their own search content and then return their contained access token 
    // (possibly including a abstract text) to the querying node.

    // even a query only node could keep a local skiplist with cached results.
    // each query node can select one or more of the different query subjects and initiate searches.
    // most probably it will make sense to only choose some of the bands, and certainly it doesn't make
    // sense to use the 9-shingle space when only a single search item has been entered.
    // a user could be able to define a set of required attributes. These attributes can be extracted
    // from common search objects or standards like A5.
    // a query node will collect data and sort by number of matching entries or number of matching 
    // links/dhkey

    // we have to use a special identity for search nodes, otherwise each person who would like to query
    // would have to accept an arbitrary amount of token. This is not related to the content owners who
    // can transmit their identities later when a search ws successful. It is required for the first 
    // stage of searched. 

    // when searching, start with initial dhkey and lookup entries
    // entries could contain more data / larger minhash signatures 
    // -> continue with additional data and search until no result is found
    // attach result to continued search and do map/reduce in each visited node
    // return found entries to querying node with match rate





// other stuff

Rendezvous Hashing:
each node -> seed + weight (weight defines how many entries a node can handle)
--> weighted score := hash(key, seed) -> 64bit int -> to float -> score = 1/log(float) -> weight * score
--> node selection := for each node -> weighted score -> pick nodes with highest score


skip list:
l0:    x -- x -- x -- x -- x -- x -- x -- x -- x -- x -- x 
l1:    x -- - -- - -- x -- x -- - -- x -- - -- x -- - -- x
l2:    - -- - -- - -- x -- - -- - -- x -- - -- - -- - -- x
l3:    - -- - -- - -- x -- - -- - -- x -- - -- - -- - -- -


skip graph:
each x can be a skip list on its own
definition into which lists an element has to be: membership vector (x)

prefix trie:  a --> ab --> ab4 ...
              a --> a0 --> a0d ...
              x --> c1 --> c12 ...


forest lsh:
variable length signature := concatenated hash function(key) = (H1(key),H2(key),H3(key),H4(key),...)
length signature can be extended if the result is not unique
-> create and use several trees, query returns m items from each tree


---------------------------------------------------
| Distance/Similarity metric | LSH implementation |
---------------------------------------------------
| Euclidean Distance         | Random Projection  |
| Jaccard Similarity         | MinHash            |
| Hamming Distance           | Bit Sampling       |
| Cosine Similarity          | SimHash            |
---------------------------------------------------


First technical design
**********************

.. NOTE::
   The technical design to implement our neuropil bloom filter and the lookup table is work 
   in progress.


Literature / Links:

qptries : https://github.com/fanf2/qp
use hamming distance and __popcount(x) as an index to a trie
'''
You can use popcount() to implement a sparse array of length N containing M < N members 
using bitmap of length N and a packed vector of M elements. A member i is present in the 
array if bit i is set, so M == popcount(bitmap). The index of member i in the packed vector 
is the popcount of the bits preceding i.
    mask = 1 << i;
    if(bitmap & mask)
        member = vector[popcount(bitmap & mask-1)]
'''

TresholdLSH (TLSH) / https://tlsh.org/

Skip Graph: http://cs-www.cs.yale.edu/homes/shah/pubs/soda2003.pdf

Coral / DSHT (distributed sloppy hash table): https://www.coralcdn.org/docs/coral-iptps03.pdf

visual presentation of numbers: https://www.exploratorium.edu/blogs/tangents/composite-patterns

CRUSH partitioning protocol: https://ceph.com/wp-content/uploads/2016/08/weil-crush-sc06.pdf

ring-cover-trees for ANN: https://homes.cs.washington.edu/~sham/papers/ml/cover_tree.pdf
                          http://www.corelab.ntua.gr/~ebamp/oldpage/material/Approximate%20Nearest%20Neighbors.pdf

LSH Forest: http://infolab.stanford.edu/~bawa/Pub/similarity.pdf

https://aerodatablog.wordpress.com/2017/11/29/locality-sensitive-hashing-lsh/#E2LSH-ref

CIFF - Common Index File Format // https://github.com/osirrc/ciff

https://www.uni-due.de/~hq0215/documents/2013/Schnell_2013_PPRL_ISI.pdf

CLK Hash : https://clkhash.readthedocs.io/

