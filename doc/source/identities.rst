Digital Identities
==================

neuropil uses digital identities to identify users, systems and to protect data content.
The following section will define and explain how digital identites are used in the neuropil 
messaging layer.

In general a digital identity in neuropil is loosely modeled after the OpenID Connect JWT standard. 
These token are mainly a signed JSON data structure, that can be serialized in base64 format. There 
are two notable differences for neuropil. The first difference is the serialization format which is
msgpack (or cbor and this CWT), the second difference is the use of standardized cryptographic primitives (ed25519),
which allows us to remove the first tuple of the JWT token (all token currently use the same cryptographic
primitives, but this could change in future versions).

neuropil uses three different kind of digitial identities to protect its users. 

1) The physical address space is build from the fingerprint of the "node" token. A node token is
   automatically build when a program starts, and changed each time the program starts. The node
   token is used obfuscate the address space, and to protect identities from being discovered. A 
   node can host several "identity" token (currently one only), and there is an automatic cross
   signing between the node token and the identity token.
2) The next token type is an "identity" token. The identity token is closely related to the traditional
   X509 certificate. It is a portable version of your identity, and can be saved to disk. When used
   on top of a running node, the fingerprint of the node will be added to the attribute set of the 
   identity token. A identity can be used with one or more neuropil nodes, i.e. for each purpose.
   The fingerprint of a identity token is a virtual address in the address space that has been build 
   up by the neuropil nodes. A identity token has a longer lifetime, ranging from months to years.
3) A message intent token is the tie between nodes and identities that would like to exchange information.
   The subject of the message intent (or the blake2b hash of a string) is the common ground (virtual address) 
   and can be mapped into the physical address space of the neuropil nodes. The message intent is automatically
   composed from informations of the node and the identity. Especially the attribute set will be merged 
   from identity and node attributes. The subject also enables neuropil to match corresponding sender/receiver.
   A message intent is a like a security session object for communication channels. A message intent token
   has a limited lifetime, ranging from minutes or days to weeks.

For each of these token there it is possible to create an additional fingerprint: the fingerpint of the token
extended with the attributes and its signature: This additional fingerprint is then designed for a specific use
case. The relationship between these three kind of tokens changes with each usage, and only somebody using the
token can make sense of the resulting hahs values.

More important is the way how identities are handled and can be used in neuropil. Let's beging with a 
simple setup and then extend it step by step.

identity identifiers
********************

consider that you need to create yourself an identity that you can use for any followup actions. As 
you would like to be identifies, you may choose to create yourself an iniial identity, that you can
use later on for other purposes as well.

.. code-block:: JSON

   {
     "iss": "a9624ed8",
     "sub": "mail:hey-its-me@example.com",
     „pub“: <binary data>
   } + sig

We left out the reminding parts of the token structure. The important aspect is that you created yourself
private key and associated two kind of data with it: your mail address ind the subject field, and the
Blake2B hash of your mail address in the issuer field. In addition you get something very useful: from 
the signature that neuropil creates from your token we build the Blake2B hash value ( H(id1) ) again, so
your identity token is uniqely identifiable within the neuropil network. This is commonly referred to as 
the fingerprint ( FP(id1) ) of the token.

This signature has is very useful, because you can use it and send it to peers to identify you. Together 
with the public there is only one single person that create a token using this public/private key pair and 
this hash value. This is in no way different than in other existing solutions, expect one thing: neuropil 
allows you to use hash values as addresses.

So without any further delay you could decide to listen for messages on the subject "H(sig)". Since there 
is only one single entity in the world that can create this hash value, everybody will be able to uniqely 
identify the correct digital identity behind it, namely you! Internally the neuropil library will create 
additional message intent token that look like this:

.. code-block:: JSON

   {
     "iss": "FP(id1)",
     "sub": "FP(id1)",
     „pub“: <binary data>
   } + sig


You may opt to add your public identity token as an attribute to this message intent token, and together 
with both informations at hand everybody will be able send you messages, if you authorize him! If you do 
not authorize him, then everybody would be able to send you messages, but since they are encrypted the 
neuropil library will have nearly no effort in deleting encrypted spam. Be aware that we do not recommend 
this approach, because it would allow a DoS attack on your identitiy (well, only if the atacker knows your
fingerprint).

So instead it is time to become a bit more careful to whom and about what you would like to talk about with 
peers. So instead, it is time to create yourself a first pseudonym:


pseudonyms
**********

You may hide behind a pseudonym for data exchange to further obfuscate the attack space. There are two ways
to create sub-identities for the initial one that we create above. 

The first way is the way PKI infratstructures work, you create a new identity and use your identity hash into
the issuer field. As a next step you have to add the signature of your initial identity to the attribute set.

.. code-block:: JSON

   {
     "iss": "FP(id1)",
     "sub": "did:example:123456abcdef",
     „pub“: <binary data>
   } + sig

   + add signature of FP(id1) to attribute set


This will give you one additional hash value (let's call it FP(p) ) that will appear in the message intent token, because 
internally the neuropil library will create again a message intent token of the following form:

.. code-block:: JSON

   {
     "iss": "FP(p)",
     "sub": "what:you:always:wanted:to:talk:about",
     „pub“: <binary data>
   } + sig


The second way is a different and follows more the web of trust approach: you add the fingerprint of an identity that can
approve your identity. This second fingerprint has to be an addressable identity for authentication, authorization and/or
accounting requests only(!), because everybody who will receive your token needs to be able to check if the realm is really 
approving the membership. The realm field will change the signature of your token, and thus also the fingerprint of your pseudonym.

.. code-block:: JSON

   {
     "realm": "FP(id1)",
     "sub": "mail:pseudonym@example.com",
     „pub“: <binary data>
   } + sig


In reality the realm would be e.g. a companies fingerprint, thus combining the PKI and the web of trust (this relieves your
company from building a password database, while still maintaining a valid user base):

.. code-block:: JSON

   {
     "realm": "FP(thirdparty)",
     "iss": "FP(id1)",
     "sub": "mail:pseudonym@example.com",
     „pub“: <binary data>
   } + sig

Each of those token will have a different fingerprint, and the different fingerprints can be used to identify you in the 
current context that you are acting in. As each token has a limited lifetime, it enables you to grant a person access to 
data with a temporary identifier, that can be created before the access will actually happen, or on a short term adhoc basis.


verifiable identifiers
**********************

(see also https://www.w3.org/TR/vc-data-model/ and https://en.wikipedia.org/wiki/Attribute-based_access_control)

Having decentralized security token for the identities, node and message intents is a first step towards the right direction. 
The token fingerprint of the identities really serve as a de-centralized identifier. Instead of a meaningful subject 
you could also use 'did:example:123456abcdef' as the subject of our identity token.

As already mentioned we can use the attributes of token to add more context specific information about the current environment,
in the wording of verifiable identitfiers you are adding 'claims' claims. In any case, the opposite peer can use and verify the
attributes that he received, and partly becomes independant from all the identities he may need to know. He can also put
his trust into a attribute / verifiable credential that has been signed by a known third party. In fact in neuropil each 
peer can contact his third party and ask if this attribute has really been given to an entity. 

In the same way verififier can be transported as attributes of a token, or proofs can be send as extra messages to entities in the 
network who require this infromation. Smaller devices, which are lecking the capability to execute the prrof code, could forward
the request to a trusted party via an connection. E.g. for machines it becomes irrelevant for a single machine to know each 
single entity. It is sufficient to verify the received attribute set against the proof.

There is one important aspect about attributes in neuropil and how they are handled. Attributes or claims in neuropil can be issued 
with a specific inheritance level. If an attribute is assigned to an identity only, you will only find it when the identity 
token is exchanged. But it is also possible to assign an attribute that is valid for each message (for a given message subject),
which can be used a verifiable credential for a session. In addition to add claims on each level (identity (public) or message 
intent (protected) or message/private) it is possible to share attributes for more than one level, that is it would be used 
attached to the identity token and to the message intent token.

Using verifiale credentials and identifiers is also possible by other technical means, it is just very easy to transport them with 
neuropil to the correct destination: a fingerprint is all that you need.
