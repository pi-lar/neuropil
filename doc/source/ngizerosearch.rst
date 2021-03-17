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
but is rather supoorted by many users and stakeholders. Each stakeholder can support each other 
in their endeavor to find answers and to discover topics and create new ideas.

Let us not forget: There is the need for resources (hardware/energy/skills/...) to maintain and 
uphold a search index. This task that has been taken by large companies in the past, and they have
not asked for money because of of their ability to sell advertisement. This approach has served us
well so far, but unfortunately also with more or less privacy gaps and other related frauds.


Entering the Zero Search
************************

Our initial idea was simple: We can use the hash values of the DHT in neuropil as a kind of
catchword index. For each single document we can distribute its metadata token to several
places in the DHT. This can be done by firt calculating the minhash signatures of each token
and its corresponding document / object. This siganture is then distributed and, using the LSH
schemes, it is possible to compare two documents and find matches of contained data objects, 
without actually knowing anything about the real data content.


Improvements for neuropil
*************************

The implementation of the LSH comparison matrix is a clear benefit for neuropil. 
We do not have to compare each token with each other, but just the ones we have 
stored at a certain position in the hash table. This limits the amount of required 
comparison steps. Furthermore we can fine tune the result set to only match data 
objects that have a probability 0.8 or more. 

In the case of our discovery algorithm we used the hash value of the message subject
so that token could meet, but we always just forward and do not store any token, based 
on the pseudonymized meta-data available at each routing step.

Talking about searching: we now would like to store more data and possibly also access 
token in our DHT. Furthermore not all nodes will have enough resources to add search 
capabilities. We have to explicitly define and implement "search" nodes withing the DHT.
that are able to handle the expected load. There is another problem to solve: What is 
the best rendezvous point where the different data searches can meet ? We have to construct 
a new distributed data structure sitting on top of the DHT, that is maintained and managed 
by "search" nodes only.

However, there is one fundamental difference in our approach: In addition to its own search 
contents, each participant will contribute a bit of search capacity for others as well.

    // use more than one search "subject"!
    // "search" + shingle size + search space = dhkey for msg subject
    // query contains target probability that is used for searching documents
    // query contains a "required" bloom filter that is used to compare and search for data objects
    // "required" bloom filter always has a target probability of 1.0
    // query contains a "optional" bloom filter that is used to compare and search for data objects
    // "optional" bloom filter will use the target probability of the query to match elements
    // --> the target probability can be used for comparing jaccard similarity of minhash results

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
    // Additionaly we can use the jaccard similarity as a measure whether similar bloom filter can be 
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



Literature:

Skip Graph: http://cs-www.cs.yale.edu/homes/shah/pubs/soda2003.pdf

Coral / DSHT (distributed sloppy hash table): https://www.coralcdn.org/docs/coral-iptps03.pdf

visual presentation of numbers: https://www.exploratorium.edu/blogs/tangents/composite-patterns

CRUSH partitioning protocol: https://ceph.com/wp-content/uploads/2016/08/weil-crush-sc06.pdf

ring-cover-trees for ANN: https://homes.cs.washington.edu/~sham/papers/ml/cover_tree.pdf
                          http://www.corelab.ntua.gr/~ebamp/oldpage/material/Approximate%20Nearest%20Neighbors.pdf

LSH Forest: http://infolab.stanford.edu/~bawa/Pub/similarity.pdf


https://aerodatablog.wordpress.com/2017/11/29/locality-sensitive-hashing-lsh/#E2LSH-ref


