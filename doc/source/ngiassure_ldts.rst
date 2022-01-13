..
  SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0


===============================================================================
Democratized Access Control 
===============================================================================

In 2021 we applied for additional funding, because from our NGIZeroSearch project we saw the need to extend
our solution in a couple of ways. There were two main findings from our setup, and within this chapter we
would like to introduce one of the open questions: How can we approve search entries from remote peers?

That sounds simple, but in fact is very difficult. Just imagine that there are millions of search entries, and
we only want to add search entries that have been approved by a set of 'search engine optimizer' entities (SEO). 
In addition there could be more than one SEO, which also raises the question which entity assigns these SEO 
entities their rights. As a matter of fact: Simple digital signatures and hierarchical PKI structures won't be
of any help for us.

.. NOTE::
   The following work on this page will be part of our funding granted by NGI Assure.
   We are very happy and pleased that we have been selected with our proposal.

.. image:: _static/NGIAssure_tag.svg
   :alt: NGI Assure
   :width: 45%
   :target: https://www.assure.ngi.eu/

.. image:: _static/nlnet.gif
   :width: 45%
   :alt: NLnet Stichting
   :target: https://www.nlnet.nl


Let's start with a more trivial use case that we would like to enable with our project, and which shows the 
needed interaction between two (or three) parties.


I Am Who I Am - Really?
===============================================================================

In our first use-case a worker would like to use an internal desktop system to start working on the tasks
ahead. Unfortunately, until now, that means he has to get a local account on this specific system, which 
automatically leads to a local password. In reality however, the worker already has an identity. He only
needs to be enabled to act in his new role as a worker. So how can he prove to the internal system that 
he (with his digital identity) is sitting in front of the desktop?

Or in other words, how can two entities get an approval about each other, without sharing passwords.


.. raw:: html
   :file: ./Remote_Identity_Attestation.svg


The desktop system displays a digital identity as an qrcode on its screen. Any user, who would like to 
use or operate on this pc, can use his own digital identity on his smartphone. He thus simply make a photo
of the qrcode, and approves with his own identity that he would like to "use" the desktop. We do not want
add a signature to the digital identity of the desktop! We just create a digital proof (a content based 
signature of the zkproof), plus then adding the timestamp and a signature, storing both in the TSA 
based protocol of the user. By publishing this attestation to the company (by means of e.g. an relay server) 
the company receives the user identification. How can the user unlock the desktop? By supplying a zkproof 
attribute (based on random data) to the desktop as the password. Any server within the company can then 
check to zkproof added to the desktop identity with the published TSA entry.

We could extend the example above with the user management system in the company, but let's return to our 
initial search-entry use-case, and add more components that we would need.


Adding Distributed Search Entries
===============================================================================


In our NGIZeroDiscover we build up the capabilities to store search records in our identity hash table (IHT).
Nevertheless, if everybody could add search entries, the database would be full soon, and there could
be lot of malicious content floating around. Although we only store the PPRL and the public access token in our 
search entries, the potential for misuse is already high enough. So how can we build a governance structure, 
that on one side helps people to be found by queries, and on the other hand allows to enable a governance on 
the search entries?

.. raw:: html
    :file: ./Remote_SearchEntry_Attestation.svg


We have to divide the use-case into several parts and look at the responsibilities of each. On one end we would 
like to enable an organization (let's call it the OpenSearchFoundation for now :-) to assign SEO entities the power
to approve search entries. All this entity has to do is to add the content based signature of each SEO entity it 
assigns to his TSA based protocol. This information can then be forwarded to the search nodes which actually store
the search entries, because they need to know which SEO entities they should have trust in.

There can be many different forms of SEO entities: some could be looking at the the search entry from the 
perspective of sustainability, another one from the perspective of law. There are many different aspects, 
and each SEO can specialize in his expertise and approve search entries (of companies) as valid if they match 
their criteria and if the content description is in a good shape to be found ("sanitized" input). Each SEO 
could set up his own search space, or they could work in a shared search space that allows them to host a 
bigger dataset that each one alone. If a company requests to be verified by a SEO, the SEO can check e.g. 
the webpage, and creates the necessary TSA protocol entry that matches the digital identity of the company / 
webpage. We do not want to add the digital watermark of each webpage at this step, because then we would 
need to distribute this to all search nodes.

The company can then add the digital content watermark and record it in its own TSA. Since the digital identity
(a disposible or temporary identity) was previously approved by the SEO  entity, the link between the final
record up to the SEO approver company is complete, and can be verified. The company can then, after possible
modification to its webpages according to the SEO, publish his own search entries. Each search index node can 
check whether the company temporary identity has been approved by an SEO. 

The added benefit for a user of this kind of search setup is: he can select a set of SEO entities, that he 
would like to trust. All search entries returned to him that do not match his selection will be filtered out.
With this setup we prevent the need to check each webpage, but enable a market of SEO provider that can
can compete on different aspects and expertise.

However, the picture is still not complete in fully. Let's have a look at our third and last use case before
moving into abstract definitions.

Adding Distributed Intrusion Detection
===============================================================================


The third use case that we would like to realize is the implementation of a remote intrusion detection 
system. Each system is able to record its own state, and can do so periodically. Each system is also able 
to send it's attestation result to a different peer (it's system administrator) to verify that the results 
conform to desired state of the system.

.. raw:: html
   :file: ./Intrusion_Detection.svg


When a third party steps by and would like to use this system, he can inspect two different attestation 
results: The one from the machine, the one form the administrator, and he could even compare the result 
to a desired state that he expects the system to be in.

From this intrusion detection use case we can see, that there is one missing role that we have to add to 
achieve the full potential of our NGI Assure project.


The Missing Link Or The Full Picture
===============================================================================


Investigative or Reporting Activities play a crucial role in our previous examples, and this role has been
added silently under the hood in the other examples as well. It is an important information source that has 
to be included. If users don't have trust into a specific kind of information, they will disregard it. How 
can any authority check whether the chain of trust is complete? We need independent reviewer that are able 
to send feedback so that changes in the trust chain can be applied. 

.. raw:: html
   :file: ./Rule_Approval_Process.svg

Let's take step back and see what we have laid down:

1) In the beginning there is an authority, which is defining attributes or rules it would like to be applied
a set of information. We call this role the judicative role, because it lays out the available set.

2) However, we do not allow this authority to distributes these attributes, we only allow
it to select peers, that are then able to assign attributes or validate other identities based on the given
set. This distribution could be used to react on different laws and regulations in different countries, e.g.
the age when young persons are allowed to drive a car differs between countries. Thus we call this role the 
legislative role. 

3) Again we restrict the rights of the distributor in the meaning that he may not act upon the distributed 
attributes. In the example of the search engine the SEO need the help of the search nodes, which check and 
allow only the selected content. We thus call this role the executive role. 

4) Last but not least: All these steps need to be monitored, evaluated and improved. Thus we have to define 
our last role, the investigative role: it's task is to monitor and report on given findings.

All mentioned roles record their decision into their own TSA protocol definition. These entries will reference
each other, but they do not need to be stored together. In addition we can make one additional remark: these 
roles may not be assigned to the same entity, thus we need at least four different entities. Furthermore a 
judicative role may choose it legislative successor, but not the executive nor the investigative. The same 
applies to the roles as well: a legislative role will only allowed to pick it's executive, an executive role 
may only pick it's investigative counterpart. All TSA entries that are created have to be available for the 
corresponding selected peers. They have to be published before so that the next role can act accordingly.

The setup enables us to achieve one of our primary goals: Democratized Access Control. The four different 
roles and responsibilities enable a clear separation of duties (as it is requested in information security 
anyway). But it also resembles how our society has solved to strike balance between different interests.


Linked-Data Timestamping Authorities (TSA)
===============================================================================


In our point of view Linked-Data Timestamping Authorities are the solution to the above mentioned use cases.
They allow us to create the desired entries in a efficient way. They also seem to contain the needed security 
proof that we need for this kind of protocol. 

There is not much literature our there, and we have far too less (open source) systems who are acting on the 
laid down principles and use-cases. There is currently no system or protocol out there which distinguishes 
between the different roles and their required relationship and interactions. 
Please note that the protocol we are aiming for is not related to consensus protocols. From our point of view 
there is no need to store each data record, but linking and referencing data records will be a crucial component. 
One idea would thus be to create the timestamping signature by including a kind of reference counter, in order to 
see whether some partner is still referencing to a specific data set. We also think that it must be possible to 
delete older / unused entries in an efficient way from the TSA.

In a way we see that part of neuropil protocol already uses the same approach: By becoming a member of a IHT, 
each node automatically is attesting it's peer nodes by their hash value (based on the signature of the identity).
Each subject that you define becomes part of your node identity, and could be easily added to a structure that 
proofs to others that you're really interested in this subject. What is missing is exactly this structure, and
the ability to efficiently exchange requested TSA information.


What's next ?
===============================================================================

We would like to review and reuse what is there, but extend it with the requirements that we have defined. 
Would you like to join our efforts? Hop over to https://www.gitlab.com/pi-lar/neuropil-ldtsa and share your
point of view. Any feedback, question or hint can make the difference. We are aiming to build an RfC that 
can be implemented by others as well, but it will for sure be an integral part of our neuropil cybersecurity mesh!



Links & Literature
===============================================================================


`[ISO/IEC 18014] <https://www.iso.org/standard/50678.html>`_ ISO/IEC 18014

`[ANSI ASC X9.95 Standard] <https://en.wikipedia.org/wiki/ANSI_ASC_X9.95_Standard>`_ ANSI ASC X9.95 Standard

`[Optimally Efficient Accountable Time-Stamping] <https://www.researchgate.net/publication/2591566_Optimally_Efficient_Accountable_Time-Stamping>`_ Optimally Efficient Accountable Time-Stamping

`[Timestamping messages and events in a distributed system using synchronous communication] <https://personal.utdallas.edu/~neerajm/publications/journals/timestamping.pdf>`_ Timestamping messages and events in a distributed system using synchronous communication

`[DIF Sidetree protocol] <https://identity.foundation/sidetree/spec/>`_ DIF Sidetree protocol

`[Keyless Signatures Infrastructure] <https://eprint.iacr.org/2013/834.pdf>`_ Keyless Signature Infrastructure

`[StackExchange: Is KIS a Post-Quantum Scheme] <https://crypto.stackexchange.com/questions/37466/keyless-signature-infrastructures-as-a-secure-post-quantum-scheme>` Comment on the post-quantum security of KIS