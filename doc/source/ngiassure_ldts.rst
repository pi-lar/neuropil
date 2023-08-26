..
  SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0


===============================================================================
Democratic Access Control 
===============================================================================

In 2021 we applied for additional funding, because from our NGIZeroSearch project we saw the need to extend
our solution in a couple of ways. There were two main findings from our setup, and within this chapter we
would like to introduce one of the open questions: How can we approve search entries from remote peers?

That sounds simple, but in fact is very difficult. Just imagine that there are millions of search entries, 
and we only want to add search entries that have been approved by a set of 'search engine optimizer' entities
(SEO). In addition there could be more than one SEO, which also raises the question which entity assigns
these SEO entities their rights. As a matter of fact: Simple digital signatures and hierarchical PKI 
structures won't be of any help for us.


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


The desktop system could displays its own digital identity as an qrcode on its screen. Any user, who would
like to use or operate on this pc, can use his own digital identity on his smartphone. He thus simply takes 
a photo of the qrcode, and approves with his own identity that he would like to "use" the desktop. We do not
want to add a signature to the digital identity of the desktop! We just need to create the digital proof 
in terms of a content based signature or zero knowledge proof (zkproof). The user adds the timestamp and a 
signature, and stores both in his time stamped attestation (TSA) based protocol. By publishing this TSA to the 
company the user identification can be carried out before the user actually logs into the computer. 
How can the user unlock the desktop? E.g. by supplying the zkproof attribute (which could be based on random 
data) to the desktop as the password. Any server within the company can then check the zkproof added to the 
desktop identity with the published TSA entry and "knows" which user is currently operating on the desktop 
system.

We could extend the example above with more details on the the user management system of the company. But 
let's return to our initial search-entry use-case, and add more components that we could need.


Adding Distributed Search Entries
===============================================================================


In our NGIZeroDiscovery project we build up the capabilities to store search records in our identity hash
table (IHT). Nevertheless, if everybody could add search entries, the database would be full soon, and 
there could be lot of malicious content floating around. Although we only store privacy preserving record
linkage (PPRL) and the public access token in our search entries, the potential for misuse is already high
enough. Currently there would be no governance structure, that on one side helps people to be found by 
queries, and on the other hand allows to augment and moderate the search entries?

.. raw:: html
    :file: ./Remote_SearchEntry_Attestation.svg


We have to divide this use-case into several parts and look at the responsibilities of each participant. 
On one end we would like to enable an organization (the SEO Approver) to assign SEO entities the power 
to approve search entries. All this entity has to do is to add the content based signature of each SEO 
entity it assigns to his TSA based protocol. This information can then be forwarded to the search nodes 
which actually store the search entries, because they need to know which SEO entities they should have 
trust in.

There can be many different forms of SEO entities: some could be looking at the the search entry from the 
perspective of sustainability, another one from the perspective of law. In this way many different aspects 
can be handled by specialized SEO with their expertise. Their role and task is to approve search entries 
(of companies) as valid if they match their criteria and if the content description is in a good shape to 
be found ("sanitizing" search entry with respect to their expertise). Each SEO could set up his own search 
space, or they could work in a shared search space/domain that allows them to host a bigger dataset that 
each one alone. If a company requests to be verified by a SEO, the SEO can check e.g. the webpage, and 
creates his necessary TSA protocol entry that matches the digital identity of the company / webpage. The
SEO does not want to add the digital watermark of each single webpage to his TSA at this step, because then 
we would need to distribute this to all search nodes.

The company can then add the digital content watermark and record it in its own TSA. Since his own digital 
identity (a specialized search identity representing the company) was previously approved by the SEO entity, 
the link between the final record up to the SEO approver is complete, and can be always verified. The 
company can then, after possible modification of it's webpages according to the SEO, publish his own search 
entries. Each search index node can check whether the companies identity has been approved by an SEO, but it 
doesn't need to check each record individually.

The added benefit for a user, who is searching for content, in this kind of search setup is: he can select 
a set of SEO entities, that he would like to trust. All search entries returned to him that do not match his
selection will be filtered out. With this setup we prevent the need to check each webpage, but enable a
market of SEO provider that can compete on different aspects and expertise.

However, the picture is still not complete. Let's have a look at our third and last use case before
moving into abstract definitions.


Adding Distributed Intrusion Detection
===============================================================================


The third use case that we would like to realize is the implementation of a remote intrusion detection 
system. Each system is able to record its own state / system configuration, and it can do so periodically. 
Each system is also able to send it's attestation result to a different peer (i.e. to the system administrator) 
to compare the results with the desired state of the system and to approve conformity.

.. raw:: html
   :file: ./Intrusion_Detection.svg


When a third party steps by and would like to use this system, it is now possible to inspect different
attestation results: The one from the machine, the one from the administrator, and it would even be possible 
to compare the result with a desired state that he expects the system to be in.

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
a set of information. We call this role the judiciary role, because it lays out the available set.

2) However, we do not allow this authority to distributes these attributes. We only allow it to select peers, 
that are then able to assign attributes or validate other identities based on the given set. This distribution
could be used to react on different laws and regulations in different countries, e.g. intellectual property 
protection laws ad regulations are different between countries. Thus we call this role the legislative role. 

3) Again we restrict the rights of the distributor in the meaning that he may not act upon the distributed 
attributes. In the example of the search engine the SEO need the help of the search nodes, which check and 
allow only the selected content. We thus call this role the executive role. 

4) Last but not least: All these steps need to be monitored, evaluated and improved. Thus we have to define 
our last role, the investigative role: it's task is to monitor and report on given findings.

All mentioned roles record their decision into their own TSA protocol definition. These entries will reference
each other, but they do not need to be stored together. In addition we can make one additional remark: these 
roles may not be assigned to the same entity, thus we need at least four different entities. Furthermore a 
judiciary role may choose it legislative successor, but not the executive nor the investigative. The same 
applies to the roles as well: a legislative role will only be allowed to pick it's executive, an executive 
role may only pick it's investigative counterpart. All TSA entries that are created have to be available for 
all the corresponding selected peers. They have to be published in the public so that the other roles can act 
accordingly.

The setup enables us to achieve one of our primary goals: Democratic Access Control. The four different 
roles and responsibilities enable a clear separation of duties (as it is requested in information security 
anyway). But it also resembles how our society has solved to strike balance between different interests.


Linked-Data Timestamping Authorities (TSA)
===============================================================================


In our point of view Linked-Data Timestamping Authorities are one technical building block for the above 
mentioned use cases. They allow us to create the desired entries in a efficient way. They also seem to 
contain the needed security proof that we need for this kind of protocol.

There is not much literature out there, and we have far too less (open source) systems who are acting on 
the laid down principles and use-cases. There is currently no system or protocol out there which distinguishes 
between the different roles and their required relationship and interactions. Please note that the protocol 
we are aiming for is not related to consensus protocols. From our point of view there is no need to store 
each data record. Linking and referencing relevant data records will be a crucial component. One idea would 
thus be to create the timestamping signature and including a kind of reference counter, in order to see 
whether some partner is still referencing to a specific data set. We also think that it must be possible 
to delete older / unused entries in an efficient way from the public TSA structures

In a way we see that part of neuropil protocol already uses the same approach: By becoming a member of a IHT, 
each node automatically is attesting it's peer nodes by their hash value (based on the signature of the 
identity). Each subject that you define becomes part of your node identity, and could be easily added to 
a structure that proofs to others that you're really interested in this subject. What is missing is exactly 
the linking structure of data, and the ability to efficiently exchange requested TSA information.


What's next ?
===============================================================================

We would like to review and reuse what is there, but extend it with the requirements that we have defined
and described in the use cases. Would you like to join our efforts? 
Hop over to https://www.gitlab.com/pi-lar/neuropil-ldtsa and share your point of view. Any feedback, 
question or hint can make the difference. We are aiming to build an RfC that can be implemented by others 
as well, but it will for sure be an integral part of our neuropil cybersecurity mesh!



Links & Literature
===============================================================================


`[ISO/IEC 18014] <https://www.iso.org/standard/50678.html>`_ ISO/IEC 18014

`[ANSI ASC X9.95 Standard] <https://en.wikipedia.org/wiki/ANSI_ASC_X9.95_Standard>`_ ANSI ASC X9.95 Standard

`[Optimally Efficient Accountable Time-Stamping] <https://www.researchgate.net/publication/2591566_Optimally_Efficient_Accountable_Time-Stamping>`_ Optimally Efficient Accountable Time-Stamping

`[Timestamping messages and events in a distributed system using synchronous communication] <https://personal.utdallas.edu/~neerajm/publications/journals/timestamping.pdf>`_ Timestamping messages and events in a distributed system using synchronous communication

`[DIF Sidetree protocol] <https://identity.foundation/sidetree/spec/>`_ DIF Sidetree protocol

`[Keyless Signatures Infrastructure] <https://eprint.iacr.org/2013/834.pdf>`_ Keyless Signature Infrastructure

`[StackExchange: Is KIS a Post-Quantum Scheme] <https://crypto.stackexchange.com/questions/37466/keyless-signature-infrastructures-as-a-secure-post-quantum-scheme>`_ Comment on the post-quantum security of KIS