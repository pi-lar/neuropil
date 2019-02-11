.. _compared_to:

****************
Comparison Chart
****************

This page gives you a short overview of how we compare the neuropil messaging layer to some of the other products / 
standards on the market. It is also meant to give you an overview of existing solutions and/or measures, but you'll 
soon notice that neuropil messaging layer draws from many sources and creates its own unique value proposition.


Digital Identities
******************

==================== ==================== ==================== ==================== ====================
category             neuropil             |MQTT|               |TCP/TLS|            |WeaveNet|
==================== ==================== ==================== ==================== ====================
- identities         :term:`token`        based http/TLS       x509                 based http/TLS
- username/password  no                   yes                  no                   no
- asymmetric         yes                  no                   yes                  yes
- symmetric          no                   no                   no                   no
- attributes         yes (dynamic)        no                   yes (fixed set)      yes (fixed set)
- pki supported      yes                  yes                  yes                  yes
==================== ==================== ==================== ==================== ====================

Depending on the layer that you're acting on, there are different competing standards. Unfortunately,
people still have to use passwords to identify themselves, although other mechanisms are in place.
The current standard for machines and applications is probably the X.509 certificate, which can be created by anyone.
The real value of such a X.509 certificate stems from signatures of trusted third parties, because they
allow you to establish a chain of trust.

Although X.509 and TLS are a good method for transport level security, it is interesting to note and see that
it has limitations when being used for persons. For some reasons X.509 has never made it to the upper OSI layers,
and if you would like to use them you have to add additional standards like e.g. SAML and WS-Security.
When looking at the REST/JSON world, those concepts never really made it and instead JWT is used. Or
|WeaveNet| comes into play to integrate security as a cross concern.

Neuropil captures the strength of digital identities based on asymmetric cryptography, but adds the dynamic
approach of JWT to it. Thus, neuropil can support attribute based security measures as they can be found in
SAML / RBAC settings.


Authentication
**************

Let's move on to a different topic, the ways to authenticate your partners:

==================== ==================== ==================== ==================== ====================
category             neuropil             |MQTT|                 |TCP/TLS|              |WeaveNet|
==================== ==================== ==================== ==================== ====================
- pki                yes                  based on TLS         yes                  based on TLS
- web of trust       yes                                       no                   no
- identity provider  yes                  partly               no 
- username/password  no                   yes                  no
- realm              yes                  no                   no
- pre-seed identity  yes                  yes                  yes                  yes
- SRP                no                   no                   no                   no
==================== ==================== ==================== ==================== ====================

PKI setups are most widely used today for application security, and identity provider (e.g. OpenIDConnect)
is used to authenticate persons. Sometimes two factor authentication is added to an identity provider, but most
still use username/password to identify persons. For X.509 certificates, you can either decide to trust
all certificates issued by a different identity, or you can use certificate pinning (trust individual X.509).

Web of trust is mostly found for pgp / mail security. Although it can be used to encrypt text as well, we
have never encountered it for message encryption. Sometimes it is found for DevOps settings today.

But how can you discover that you don't want to trust somebody or that a certificate has been revoked?
In our point of view CRL (certificate revocation lists) are too large for smaller devices (assuming 1 million
certs and an error rate of 1%) and they are implemented as black list. OCSP (Online Certificate Status Protocol)
suffers from the same 'black list' weakness, but is at least better suited for online checks.

Neuropil uses a :term:`DHT`, and each identity has a place in this :term:`DHT` and is authenticated at least once.
The size of the :term:`DHT` is exactly large enough to cover all used identities, and can be used to lookup identity
information.

And I just realized a to-do on our side: we need to add a secure remote password (SRP) library to neuropil.


Authorization
*************

==================== ==================== ==================== ==================== ====================
category             neuropil             |MQTT|                 |TCP/TLS|              |WeaveNet|
==================== ==================== ==================== ==================== ====================
- local config       possible             yes                  yes                  yes
- rule based         yes                  no                   no                   yes
- attribute based    yes                  no                   no                   no
- realm based        yes                  no                   no                   no
==================== ==================== ==================== ==================== ====================

Finally, we are hitting the main advantage of neuropil. Explicit authorization is a missing link in todays IT / IoT
architecture. With TLS you either authorize one application (certificate pinning), or a complete set of
applications (PKI / chain of trust). In chain of trust settings you are limiting yourself to only one attribute
(the additional signature), and you're mostly limited on the hostname with all its resources.

In neuropil you can add any attribute you would like to. Thus neuropil enables you to throttle your traffic,
because there is an attribute for it. It let's you define dedicated time slots, because you can easily adjust
your tokens to it. TLS and certificates are too long-living for this purpose.

Local configurations are almost never a good idea. Keeping security relevant information on a device calls
for trouble. With neuropil you can remote-control those authorizations with a level of detail.


Transport Encryption
********************

==================== ==================== ==================== ==================== ====================
category             neuropil             |MQTT|                 |TCP/TLS|              |WeaveNet|
==================== ==================== ==================== ==================== ====================
transport encryption yes                  yes (based on TLS)   yes                  yes (based on TLS)
- asymmetric         yes                                       yes
- symmetric          yes                                       yes
- key exchange       DHKE (as TLS 1.3)                         TLS 1.3 or TLS 1.2
- multicast          yes (based on attr.)                      no
- broadcast          yes (based on attr.)                      no
- multi-hop          yes (based on attr.)                      no
==================== ==================== ==================== ==================== ====================

Seen for a single connection, there is nothing that neuropil could do better than TLS. We are using the same
concepts here as TLS 1.3. With the benefit that you do not have to manage the old TLS 1.2 stack in your network:
Did you know that a single old system can degrade your entire TLS setup if not properly isolated?

With neuropil we always take into account the "next hop", that is why we are using end-to-end
encryption (and no, TLS is not end-to-end encryption in our opinion. Only in very specific use cases.)

When looking at multicast or broadcast scenarios neuropil again excels. By assigning cryptographic attributes
to a :term:`node` (e.g. with an end-to-end encrypted message), you can implement different encryption schemes on
the same physical transport. Think about it: your thermostats use a different encryption than your machines
and than your maintenance engineer!

If you are missing a 'yes' for |MQTT| multicast/broadcast in this table: we are talking about physical network layer encryption.
Doing pub/sub with |MQTT| follows later on, and has it's very own quirk.


Payload Encryption
******************

==================== ==================== ==================== ==================== ====================
category             neuropil             |MQTT|                 |TCP/TLS|              |WeaveNet|
==================== ==================== ==================== ==================== ====================
- encrypted content  yes (automatic)      no                   no                   no
- signed content     via neuropil_data.h  no                   no                   no
- single field enc.  via neuropil_data.h  no                   no                   no
==================== ==================== ==================== ==================== ====================

Another big plus for neuropil: because our protocol covers the application layer as well, you can
add payload encryption signatures easily. When sending a multicast message, you can encrypt the credit
card number for one of the receivers, and then send the messag to all receivers. The sending system just
has to send the message once, it will be duplicated by the neuropil messaging layer.

All other components leave you in the dark: please use an additional standard ...


Message Exchange Pattern
************************

==================== ==================== ==================== ==================== ====================
category             neuropil             |MQTT|                 |TCP/TLS|              |WeaveNet|
==================== ==================== ==================== ==================== ====================
- one-to-one         yes                  yes                  yes                  yes
- one-to many        yes                  yes                  no                   no
- many-to-many       yes                  yes                  no                   no
- load-balanced      yes                  yes                  no                   (additional lb/fw)
- fault-tolerance    yes                  yes                  no                   (additional lb/fw)
==================== ==================== ==================== ==================== ====================

No surprise, neither TLS nor |WeaveNet| have an answer for sending messages to more than one component.
You have to use an additional 'microservice' called |MQTT| (or any other messaging system). But then you
have to get the resources for it and scale it accordingly as well. Be aware that there is a potential
security gap: although technically decoupling sender and receiver (which is good!), these systems also decouple
identities from knowing each other. You can attach an additional receiver to any of the current messaging
servers, and the sender will never know about it! Any messaging server in your application landscape will
be the honey pot for any attacker. Together with password based authentication and possible TLS degradation
because of old TLS version: this may lead to very unpleasant results soon (hint: some |MQTT| implementations
let you define the TLS connection per partner).


Protocol Efficiency
*******************

==================== ====================== ==================== ==================== ====================
category             neuropil               |MQTT|               |TCP/TLS|            |WeaveNet|
==================== ====================== ==================== ==================== ====================
internal protocol    binary/:term:`msgpack` binary               binary               http
==================== ====================== ==================== ==================== ====================

For small devices and machines plain text (http) is not an option. Therefore neuropil supports the binary
:term:`msgpack` protocol and also uses it for parts of its internal messages.
|MQTT| itself is agnostic towards the payload, you have to choose one yourself. HTTP also usually requires
an extra protocol definition on top (e.g. COAP).


Cryptographic Primitives
************************

==================== ==================== ==================== ==================== ====================
category             neuropil             |MQTT|                 |TCP/TLS|              |WeaveNet|
==================== ==================== ==================== ==================== ====================
- based on           libsodium            openssl              openssl              openssl
- algorithm          curve, poly1905                           you have to manage
                                                               CIPHER_SPEC
==================== ==================== ==================== ==================== ====================

Currently not much to write here: neuropil only supports the cryptographic routines available from libsodium.
The curve algorithms are well suited for IIoT. For TLS you have to manage your cipher specs, and there
are also a lot of old protocols implemented (even a NULL cipher).


External Dependencies
*********************

==================== ==================== ==================== ==================== ====================
category             neuropil             |MQTT|                 |TCP/TLS|              |WeaveNet|
==================== ==================== ==================== ==================== ====================
- DNS (security)     no                   yes                  yes                  yes
- NTP                no (tbs.)            yes                  yes                  yes
- other              no                                                             kubernetes
- firewall setup     simple keep state    yes                                       yes
                     rules
- IIoT size ready    yes                  no                   no                   no
- B2B exchange       yes                  no                   yes                  no
==================== ==================== ==================== ==================== ====================

Last comparison: which other external dependencies can be solved with the mentioned competitors ?
For all TLS based systems you also have to get your DNS (DNSSEC) and NTP settings right. In addition, you
have to use load-balancer to finally implement the security that you would like to have.

Neuropil is the only system that doesn't have restrictions for the mentioned topics:
 * the :term:`DHT` acts as an DNSSEC layer as well, no privacy leak by DNS lookups
 * a secure variant of the NTP protocol could be implemented easily
 * a simple OS installation is enough to get you started
 * the simplest firewall set (keep-state for TCP connections) let's you connect your protected devices worldwide
 * IIoT size is not a problem (the :term:`DHT` address space is large enough to cover all atoms in the universe)
 * B2B exchange is not a problem, because neuropil has 'SLA included' (e.g. limit throughput based on attributes and
   digital identities)


Your Conclusions?
*****************

After having shared our thoughts and insights: Did we leave something unmentioned or would you like to discuss
some of the details with us? We are open to criticism, suggestions and your feedback! 

To get in touch, just send us a short email. 
If you have no questions: when and where will you give the neuropil messaging layer a shot? Just curious ...


  [1]: MQTT: https://MQTT.org

  [2]: TCP/TLS: https://datatracker.ietf.org/wg/tls/documents

  [3]: WeaveNet: https://www.weave.works/oss/net

.. |MQTT| raw:: html

  <a href="https://MQTT.org/" target="_blank">MQTT</a>

.. |TCP/TLS| raw:: html

  <a href="https://datatracker.ietf.org/wg/tls/documents/" target="_blank">TCP/TLS</a>

.. |WeaveNet| raw:: html

  <a href="https://www.weave.works/oss/net/" target="_blank">WeaveNet</a>

