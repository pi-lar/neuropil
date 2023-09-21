..
  SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0


===============================================================================
De-centralized Time Measurement and Alignment 
===============================================================================

Time information and time synchronization has been tackled since many years, and there are existing solutions that 
allow you to synchronize time with your own system. Unfortunately there are also a couple of attacks out there that
use the existing time protocol or their respective implementations. The question is: what can be do better than 
existing approaches? What is the use case behind our De-central time measurement and alignment proposal?

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


First Contact 
===============================================================================

In projects with partners we have seen that time is a critical component in the neuropil cybersecurity mesh.
Our identity token contain timestamps and validity information, as well as our messages. If time is not synched 
between the different systems, our protocol will fail in the meaning of 'fail-safe': it will not send/reveal any 
information. However, this also imposes a problem, because we have to rely on an information (the time) that we 
currently cannot verify within our system.

Especially devices without RTC (real time clock) need to trust other peers on first contact, regardless whether 
their current time is in line or not. Running our system on ESP32 or RaspberryPi Zero modules leads to failure as
soon as we connect to the first peer. When looking at broadcast protocols things become more fragile.

Larger peer nodes could trust smaller devices, because of the knowledge that there is no RTC on board. And 
smaller systems could have a certain trust into larger nodes and that their time is "better" than their own. 
So what happens if we trust the time information of our first contact, but treat it in a isolated way?

Huygens and the Environment 
===============================================================================

From the environment of our devices we can actually draw conclusions about the current time. Let's see how time
calculations work between two nodes first before we take the next step (just briefly, hop to the link section 
for all the details).


.. raw:: html
   :file: ./time-calculations.svg


With the exchange of time messages we thus receive different kind of information from our peer node. 
What is important to understand is: the time mentioned in the message itself, using it stand-alone, is not 
quite useful. We could trust it or not, but it won't help us. Each clock in each system has a so called skew,
which will make the time run faster or slower depending on this skew. Each clock als has a drift and a drift
rate, which measures the relative difference in clock frequency. Last but not least we have to take into
account the message delay that is added by the network latency.

What we need is an understanding how the time on one system will evolve over time. Do you have higher 
trust in a clock that is always exactly 5 minutes off? Compare to a clock which oscillates it's time around 
the current time by +- 2 minutes? Both clocks have their advantages, if we know the associated error of each.

Using only a single reference system will not enable us to actually detect this kind of behavior. We can detect 
a certain error on the time information (which actually means we use e.g. the standard deviation around reported 
time values), but it will not tell us whether that is the correct time. It will just tell us what our peer 
thinks is the correct time. We need more systems to calculate the standard deviation of all deviations, which
in turn allows us to draw conclusions about the real time. So in addition to an understanding how the time of 
one system will evolve over time, we add an understanding how time evolves over space as well.

.. seealso::
   `<https://www.usenix.org/conference/nsdi18/presentation/geng>`__


IHT and Time
===============================================================================

By applying this principle to our IHT, it will lead to the following setup: 
The IHT gives us random peers, and thus random time examples that can be used to derive, test and verify 
the local time. Because our local node will receive more time information than before, and because our 
time information is guaranteed to be stemming from different sources, the distribution of the received 
values can be measured and aggregated into a local time information. This local time will be more resilient 
than previous approaches, because of it's various sources across the connected peers and devices.

.. raw:: html
   :file: ./time-space-calculations.svg


We see the following benefits from our approach: 

- the addition of various sources will allow a faster conversion to the final time (replacing time with
  space). 

- the derived time could be more precise or better aligned across many nodes because of the addition of 
  more time sources ("could" because we don't know yet whether this can be achieved)

- all time information will be stemming from authentic sources and we don't need to add back/reply 
  channels (which led to misuse in the past). 
  
- last but not least: we may even communicate with a system if it is off by 5 minutes, because by knowing 
  the difference we can isolate the error and adjust for it.


The distributed time information will also release some of the load of large time servers. Though these time 
server systems are still a part of our setup and are a crucial component: they are the systems which can actually 
ignore the distributed time for the sake of synchronization. In contrast the distributed time measurement can be 
used as a kind of check how "well-defined" the local network currently behaves. A time server could thus decide to
increase its publishing frequency of time information to it's peers, or it could issue a warning to system
administrators that some system is not behaving as defined.

Because of the publish-subscribe semantics of our protocol the time information that have been issued by a local
time server will be forwarded (as in reference broadcasts). We can further enhance this approach by appending 
time information of hops that forward the messages to other peer nodes. There must be an overall length restriction 
on the amount of hops which can add time information, and a receiving node can pick from the contained list of 
time information: There is a authenticated root time, plus a variety of nodes that added their respective current 
understanding of time. Using the linked-data approach will allow to attach time information to sub-elements, or 
relating it to the root. 


Further Improvements
===============================================================================

By aligning the time information between nodes also allows to us to streamline and improve our message passing. 
As of now nodes simply publish specific information based on internal timing information. E.g. our heartbeat
message, that help to measure the latency and stability of peer nodes, are send out at a specific interval. This
can lead to the situation, that peer nodes receive too many heartbeat messages at the same millisecond. Thus
the processing time for heartbeat messages increases, and affects the latency measurements.

But if nodes are aligned on their respective time information, it becomes much easier to streamline our heartbeat
messages. A node could e.g. instruct it's peer node to send the next heartbeat message at a specific point in the
future. This ability, to send DHT messages at a specific point in time, allows us to synchronize on the expected 
data load and to prevent certain overload situations.


What's next ?
===============================================================================

We clearly see the benefit of transporting smaller pieces of time information across a variety of protocols. 
The highly distributed approach will make it easier to check for timing attacks, and will time information
resilient. Identifying the pieces and implementing them is one part of our work. Supplying the proper algorithms
to calculate a local picture of the distributed time measurement is the second step. Aligning the local clocks
with our distributed time and thus aligning all systems on a common understanding of time is the last step. 
Many pieces are already there, and we are mainly aiming at re-organizing them in a different way to allow for a 
de-centralized time measurement and alignment.

Would you like to join our efforts? Hop over to https://www.gitlab.com/pi-lar/neuropil-dtma and share your
point of view. Any feedback, question or hint can make the difference. We are aiming to build an RfC that 
can be implemented by others as well, but it will for sure be an integral part of our neuropil cybersecurity mesh!


Links & Literature
===============================================================================

`[A Design of a Time Synchronization Protocol Based on Dynamic Route and Forwarding Certification] <https://pubmed.ncbi.nlm.nih.gov/32899934/>`_ A Design of a Time Synchronization Protocol Based on Dynamic Route and Forwarding Certification

`[The Flooding Time Synchronization Protocol] <http://www.math.u-szeged.hu/tagok/mmaroti/okt/2010t/ftsp.pdf>`_ The Flooding Time Synchronization Protocol

`[The Berkeley UNIX Time Synchronization Protocol] <https://docs.freebsd.org/44doc/smm/12.timed/paper.pdf>`_ The Berkeley UNIX Time Synchronization Protocol

`[Time-division multiple access] <https://en.wikipedia.org/wiki/Time-division_multiple_access>`_ Time-division multiple access

`[Exploiting a Natural Network Effect for Scalable, Fine-grained Clock Synchronization] <https://www.usenix.org/system/files/conference/nsdi18/nsdi18-geng.pdf>`_ Exploiting a Natural Network Effect for Scalable, Fine-grained Clock Synchronization

`[DTP: Double-Pairwise Time Protocol for Disruption Tolerant Networks] <https://ieeexplore.ieee.org/document/4595902>`_ DTP: Double-Pairwise Time Protocol for Disruption Tolerant Networks

`[Network Time Protocol Version 4: Protocol and Algorithms Specification] <https://www.ietf.org/rfc/rfc5905.txt]>`_ Network Time Protocol Version 4: Protocol and Algorithms Specification

`[A New Distributed Time Synchronization Protocol for Multihop Wireless Networks] <http://cesg.tamu.edu/wp-content/uploads/2012/03/ps_files/solborkum06.pdf>`_ A New Distributed Time Synchronization Protocol for Multihop Wireless Networks

`[Distributed Implicit Timing Synchronization for Multihop Mesh Networks] <https://wcsl.ece.ucsb.edu/sites/default/files/publications/implicitTimingSyncTR.pdf]>`_ Distributed Implicit Timing Synchronization for Multihop Mesh Networks

`[Fine-Grained Network Time Synchronization using Reference Broadcasts] <https://cs.brown.edu/courses/cs295-1/broadcast-osdi.pdf>`_ Fine-Grained Network Time Synchronization using Reference Broadcasts