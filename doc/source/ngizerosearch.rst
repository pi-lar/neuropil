Zero Search / a Paradigm Shift
==============================

How do the overlay network and token structures mentioned in the core concepts 
and the ngi zero discover page relate to the "privacy by design" search capabilities 
of neuropil?

According to the FAIR principle each data set has to conform to the following four 
principles (I will not comment fully, just with respect to our work):

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
  although technicall it will not be possible to guarantee accuracy and relevance of each 
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

By incorporating search and discovery protocol specifications into our protocol, we are able to 
eliminate the need for a central broker or search engine. The internet does not belong to a single
entity, but is rather supoorted by many users and stakeholders. Each stakeholder can support each
other in their endeavor to find answers and to discover topics and create new ideas.

Let us not forget: There is the need for resources (hardware/energy/skills/...) to maintain and 
uphold a search index. This task that has been taken by large companies in the past, and they have
not asked for money because of of their ability to sell advertisement. This approach has served us
well so far, but unfortunately also with more or less privacy gaps and releated frauds.


Entering the Zero Search
************************

Our idea is simple: We can use the hash values of the DHT in neuropil as a catchword index. 
For each single document we can distribute its metadata token to several places in the DHT.



Improvements for neuropil
*************************

tbd


First technical design
**********************

.. NOTE::
   The technical design to implement our neuropil bloom filter and the lookup table is work 
   in progress.


tbd

