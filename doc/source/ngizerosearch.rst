..
  SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0

===============================================================================
Zero Search / a Paradigm Shift
===============================================================================

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
  complete vocabularies, it is possible to match attributes and more to each other. 

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
===============================================================================

Our initial idea was simple: We can use the hash values of the DHT in neuropil as a kind of
catchword index. For each single document we can distribute its metadata token to several
places in the DHT. This can be done by first calculating the minhash signature of each token
or its corresponding document / object. This signature is then distributed and, using the LSH
schemes, it is possible to compare two documents and find matches of contained data objects, 
without actually knowing anything about the real data content.

There is one fundamental difference in our approach: In addition to his own search 
contents, each participant will contribute a bit of search capacity for others as well. 
There is no danger in this: the only "content" that is stored is a digitally signed intent token, 
the public part of the search content. The full article / dataset still stays behind the usual 
access limitations that neuropil gives you. This is the only way how search can be maintained 
at no costs, because each participant will contribute a part of his resource to the overall index.


Improvements for neuropil
===============================================================================

The implementation of the LSH comparison matrix is a clear benefit for neuropil. 
We do not have to compare each token with each other, but just the ones we have 
stored at a certain position in the hash table. This limits the amount of required 
comparison steps (which is the main purpose af LSH anyway). Furthermore we can fine 
tune the result set to only match data objects that have a certain probability threshold or more. 

In the case of our discovery algorithm we used the blake2b hash value of the message subject
so that token/participants could establish a communication channel. But we always forward and do 
not store any token, based on the pseudonymized meta-data available at each routing step. 

For searching we need to store the token somewhere. Thus we need a new content based rendezvous points, 
where search index entries and search queries can meet and exchange. Thus we have to construct a new 
distributed data structure sitting on top of the DHT, that is maintained and managed by "search" nodes 
only. This makes perfectly sense as not all nodes of the DHT will have enough resources to add search 
capabilities. We have to explicitly define and implement "search" nodes withing the DHT, that are able
to handle the expected load. And we now would like to store more data and possibly also an access token 
in our DHT. 


Starting point for search content
===============================================================================

This also opens the path to a first data definition that will be needed for search content. Our 
main data object is the intent token, and this will already give a good data ownership. As most 
parts of the intent token contains hash values, they are not good to derive any further searchable
content, therefore the attributes (claims) of an intent token can be used for datatype specific extensions.
E.g. one could use the meta tags of HTML pages (please ignore for now that these elements are not used 
by crawlers). Let's have a look:


.. code-block:: html

   <meta name="description" content="Lorem ipsum dolor sit amet, consetetur sadipscing elitr." /> 
   <meta name="keywords" content="keyword_1, keyword_2, keyword_3" /> 
   <meta name="author" content="Author Name" /> 
   <meta http-equiv="Content-Type" content="text/html; charset=utf-8" /> 
   <meta http-equiv="expires" content="Expiry in seconds" /> 


The same kind of meta data can be defined for other documents as well. We enrich the intent token
with the needed data structures to create and distribute searchable entities. In the absence of a 
description or keywords, we can use algorithms like TF-IDF or BM25+ to find the most important words. 
The description could be taken from the first 250 words of each webpage.

.. NOTE::
   For our first implementation our project concentrates on a very simplistic text processing.
   We will analyze each line in a text file. The lines are put to lowercase, only words with more
   than 3 letters are used, and we will us a simple 1-shingle on these words.


This kind of text analysis shows, that there is no silver bullet for text search. This impression 
continues once you start to play with the algorithm for search content. It is clear that there will 
be no universal set that can be applied to all kinds of documents. The different formats and data 
structures need different treatment and analysis. I.e. before building a minhash signature, there is 
the choice how text will be added to the signature, giving several options like shingling (in
various forms) or k-mer split up. During our project we experimented with various shingling variants
and data-dependant schemes, and they have all become part of the library.


.. raw:: html
   :file: ./search_process_1.svg


Comparing search content
===============================================================================

In order to reduce the needed semantic complexity, the above intent token (plus it's attributes) will be 
added to a bloom filter. Quite nicely, PPRL (privacy preserving record linkage) respectively CLKHash 
defines the layout of such a data structures based on bloom filter. To our own surprise, our neuropil 
bloom filter, implemented in our first NGI discovery part of the project, are matching the PPRL 
definitions, with a few limitations or constraints. E.g. for single values we always use blake2b 
hashing and do not allow for any other hashing. The size of our PPRL is fixed (around 1020 bits). 
For a list of keywords we will add minhash signatures that are implemented on shingling, not n-grams 
(but that could be changed later).

Comparing search entries is thus just a matter of comparing a set of bloom filter, namely the CLKHash 
(Cryptographic Longterm Keys) representation derived from the search content. As these are just bloom
filter values, the implementation of comparing CLK data structures will be possible in an efficient way,
and even more important, in a privacy preserving way.


New content index for search content
===============================================================================

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

Our goal is to find a kind of data dependent hashing scheme, that works well on/only uses 256-bits 
for the final rendezvous point. Once this rendezvous point has been found, the corresponding node can
any database system to store and compare CLKHash values, returning/forwarding the attached intent token
of sender/receiver to the identified actors. 

So finally: what is our content index (aka rendezvous point, aka clustering index)?

We use a counting bloom filter and treat each index of the filter as if it would be representing one table
(or a LSH bucket). We then hash the attributes and the minhash signature of keywords (or text) into
the filter. This gives us a hint of the relative importance of each bucket for the specific search content.

Across this counting bloom filter we apply the TLSH technique: the resulting count across the buckets
can be split into octile values, each bucket then falls into a specific octile. After a iteration over
all buckets we get the data dependent bitset that represents the relative importance of each bucket.
It is a bit weird, because we are only looking at the importance of buckets in relation to their minhash
values, but: it works. We have successfully distributed search entries over a set of 4096 nodes and were
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
listen to the random hash value and listens on it for queries and new search entries.

.. code-block:: javascript

   enum np_data_return np_set_mxp_attr_bin(ac, "urn:np:search:node:v1", NP_ATTR_INTENT, "urn:np:random:hash", <random hash value>, NP_PUBLIC_KEY_BYTES);

   struct np_mx_properties search_entry = np_get_mx_properties(ac, "urn:np:search:entry:v1:<random hash>");   // announcing a search node
   struct np_mx_properties search_query = np_get_mx_properties(ac, "urn:np:search:query:v1:<random hash>");   // announcing a search node


As message intents get refreshed by neuropil periodically, we have an implicit heartbeat whether 
nodes are still present in the network or not. In addition it is possible calculate the required 
hash distance that is used internally. As more nodes enter the scene, the hash distance will decrease 
over time, meaning that it is also possible to evict data over time. 

.. raw:: html
   :file: ./search_process_2.svg


The same applies for search content: Search content will be refreshed once a day (the exact timing 
requirements need to be specified). As the search entry is represented by a attenuated bloom filter,
it is possible to decrease the "age" of a search entry without directly loosing it. A refresh of a 
search entry will not add a new dataset, but only the age information of the attenuated bloom filter 
will be increased. Old internet content, that is not refreshed from peers, will vanish automatically 
from the tables over time.

Storing search entries in more than one node (because the hash distance could be the same) will lead 
to a certain degree of fragmentation and double entries. If we discover that fragmentation causes 
problems, we will have to add another metric when adding entries to search nodes.


Querying for data sets works the same as adding entries. Based on our search text it is possible to create 
the search hash value and the query can then be forwarded to the correct rendezvous point. The query object 
itself is a bit different, and can be defined as follows:

.. code-block:: javascript

   uint8_t query_id;             // a query id to correlate replies to send out queries (needed?)
   np_id result_idx;             // the reply subject for incoming results (could be different for each query)
   np_searchentry_t query_entry; // a searchentry, that is used for querying. simply reuse the existing data structure


Search queries travel through the DHT table as search entries. Once the hash distance is closing in, the search entries
can be compared to the search query in each node. The good news is, as the query message travels on, the searching happens
in parallel without any further intervention. The hard part will be to make the search efficient. Searching should
only happen on the least nodes required. 

In addition to the similarity measurement of the bloom filter it will be possible to match the found entries against a set
of required attributes in the search query. This acts as an early "map" of the map-reduce algorithm and filters specific entries. 
E.g. a user could search only for documents that have been verified by a specific third party ("green" content provider),
the signature of this third party can be verified in remote peers already.

Matching results (aka search entries) can then be send back to the query node via the result_idx hash value. Each user can
define his own ranking algorithms, but quite obviously the similarity and how often a document was found plays a crucial
role.


New approach for search metrics
===============================================================================

In addition we could implement one optional feature: the search query item could be forwarded to the original author 
of the search entry (the necessary data is contained in the intent token). Doing it would give each participant an 
automated metric whether and how often his search entries were found. In fact searching could become a mutual experience,
giving both participants, the searcher and the content provider, the required data and insights. As most data and 
participant in neuropil are identified by their hash value only, the evaluation of search would not impact the privacy
of any participant. The last step, getting in contact with each other, has to be triggered by each user and is left out
of the current implementation (as it could happen through other transport protocols than neuropil anyway). 

Sending search content owners the queries which led to a hit has a high impact: There is doubt that the amount of queries 
could a) be beneficial for the user and b) be handled efficiently by the data owner.


Identities and searching
===============================================================================

There is a special problem in the way how neuropil interacts with each other, that is yet documented. If each participant
in the neuropil network can add his search entries, then we open the black hole of authorizations, as we would have to 
authorize everybody when adding search entries or when querying the distributed data structure.

In our first version, we circumvented this: After a node has been added to the list of nodes with a certain hash distance, 
we explicitly allow those nodes that are "near" to our own node to add content or to query for content. In a later setup 
we plan to add verified content only. A search entry needs the seal of a search entry optimizer (SEO) so that it will be 
accepted from nodes. As there could be several SEO provider in the market, the person who would like to share documents 
has to pick one (or more) provider to get his search content online. The proof that a SEO has indeed verified the contents
needs new way of publishing trusted content, but that is (for now) not our main goal.

For our search subjects, to add or query for content, we will use the private mode for message subjects. The private
mode allows to set explicit authorization callbacks per message subject. This decouples the authorization callbacks for 
search entries from the authorization callbacks of the remaining implementation.

.. NOTE::
   Using the private mode for data exchange should be the best practice. Apart from setting a dedicated authorization 
   callback, it allows you to either localize an interface to your identity, or it allows you to hide your interface 
   in the hash space that neuropil uses. 


In addition to this this also allows the creation of different search domains. E.g. during our experiments we have already
seen that different kind of data will need different kind of hashing / minhashing data. (e.g. a news feed has some typical
characteristics that is not the same as for a novel). To overcome these limitations (that also have been mentioned earlier) 
we will allow to seed the private message subjects with a different hash for each of these application domains of search . 
In this way we can layer several search domains which do not interfere with each other. For a client searching for content 
this setup allows to search in different domains at the same time. The results from each domain can then be merged locally 
by his own algorithms deployed locally.


Final thoughts
===============================================================================

The NGI ZeroDiscovery project was a challenge for us. To implement our initial idea we had to re-read a lot of the Literature.
Understanding the different algorithms and how they can be applied to solve a specific search problem was the key to build the
solution. And although we have just fully implemented a simple text search, we are very happy with the results. During our
journey we were able to build up capabilities and knowhow that we can apply in other areas. The gained knowledge can be
be applied to other real world problems, and there are enough of them. E.g. in the field of cybersecurity you just have to
think about spam mails, virus detection or fraudulent site indexing where our solution could be applied in a ecosystem. 

We also see several limitations and extension to our chosen approach. The authorization hole mentioned above is one example 
of such a limitation that hinders us to simple move on. But the same hole points us into the right direction: who should
be allowed to add content, algorithms or processes to our distributed search structure? We need a better understanding of
the search process and it's roles and responsibilities. 

Adding search content should not be possible for everybody. Although this sounds harsh the reality is: it is not helpful 
to have garbage in your search index. On one hand we have experienced in our project that understanding and choosing the 
right algorithm is important before adding content. Just pushing content will create search results which will be 
disappointing for everybody (the content owner and the people searching for content). Why do we accept the this quality?  
Are the current search results really the best what can be achieved? I guess no ...

There are so many different data formats our there, why should there be just a single search instance in the world serving 
our search? The monolithic approach to search is hindering all of us, there should be more variety. With the ability 
to host different search domains for different groups we aim to strike a balance, to have several content curators working
together. The algorithms that we have implemented and mixed together are just the technical foundation for collaboration.

As such our open source project is just the starting point for interested groups to establish search domains. In case you
need help with the algorithms: we are there to help you, and we will be able to add more algorithms to the set (this 
could be the role that we will be playing in the game ...).



Links & Literature
===============================================================================

`[Approximate Nearest Neighbors.pdf] <http://www.corelab.ntua.gr/~ebamp/oldpage/material/Approximate%20Nearest%20Neighbors.pdf>`_ approximate nearest neighbour / removing the curse of dimensionality

`[CIFF] <https://github.com/osirrc/ciff>`_ Common Index File Format (CIFF)

`[CLKHash] <https://clkhash.readthedocs.io/>`_ CLK Hash

`[composite-patterns] <https://www.exploratorium.edu/blogs/tangents/composite-patterns>`_ visual presentation of prime numbers

`[Coral / DSHT] <https://www.coralcdn.org/docs/coral-iptps03.pdf>`_ Coral / DSHT (distributed sloppy hash table)

`[CRUSH] <https://ceph.com/wp-content/uploads/2016/08/weil-crush-sc06.pdf>`_ CRUSH partitioning protocol

`[Efficient Record Linkage] <http://openproceedings.org/2016/conf/edbt/paper-56.pdf>`_ Efficient Record Linkage Using a Compact Hamming Space

`[Efficient Processing of Hamming-Distance Similarity Search] <http://openproceedings.org/2015/conf/edbt/paper-263.pdf>`_ Efficient Processing of Hamming-Distance-Based Similarity-Search Queries Over MapReduce

`[Information Retrieval in Peer-To-Peer Systems] <http://alumni.cs.ucr.edu/~csyiazti/papers/msc/html/index.html#2381>`_ Information Retrieval in Peer-To-Peer Systems

`[LSH Forest] <http://infolab.stanford.edu/~bawa/Pub/similarity.pdf>`_ LSH Forest

`[LSH] <https://aerodatablog.wordpress.com/2017/11/29/locality-sensitive-hashing-lsh/#E2LSH-ref>`_ Locality Sensitive Hashing

`[P2P Information Retrieval] <http://oak.cs.ucla.edu/~sia/tp3.pdf>`_ P2P Information Retrieval: A self-organizing paradigm

`[PPRL] <https://www.uni-due.de/~hq0215/documents/2013/Schnell_2013_PPRL_ISI.pdf>`_ privacy preserving record linkage (PPRL)

`[Ring Cover Trees] <https://homes.cs.washington.edu/~sham/papers/ml/cover_tree.pdf>`_ ring-cover-trees for ANN

`[Skip Graph] <https://cs-www.cs.yale.edu/homes/shah/pubs/soda2003.pdf>`_ Skip Graph

`[TLSH] <https://tlsh.org/>`_ TresholdLSH (TLSH)

`[Variable Length Hashing] <https://openaccess.thecvf.com/content_cvpr_2016/papers/Ong_Improved_Hamming_Distance_CVPR_2016_paper.pdf>`_ Improved Hamming Distance Search using Variable Length Hashing

`[Wikipedia N-Gram] <https://en.wikipedia.org/wiki/N-gram>`_ n-gram

