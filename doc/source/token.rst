Protocol
========
   
Within the neuropil library we us the aaatokne structure to fulfil authentication, authorization and accounting 
purposes. The usage and meaning of each token for/in each sepcific case is ambigously and somethime s confusing (even
for us).

This chapter will try to add the neccessary details how tokens are used. Let us recall first how the token structure 
is composed before diving into the details:

   // depicts the protocol version used by a node / identity
   double version; 

   // who is the owner
   char realm[64];
   // who issued this token 
   char issuer[65];
   // what is this token about
   char subject[255];
   // who is the intended audience
   char audience[64]; 

   // token creation time
   double issued_at; 
   // to be used at
   double not_before;
   // not to be used after  
   double expires_at;
   // internal state of the token
   aaastate_type state;
   // uuid of this token
   char* uuid;

   // public key of this token
   unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
   // private key of this token (not to be send over the wire
   unsigned char private_key[crypto_sign_SECRETKEYBYTES];

   // signature of the token 
   unsigned char signature[crypto_sign_BYTES];

   // key/value extension list
   np_tree_t* extensions;

One of the most important aspects is the use of the realm, issuer, subject and audience fields that interact with 
each other and reference each other as the library build up its network structure. Therefore we will concentrate 
on these four for the following chapter.

1: handshaking
**************
For the handshake we need to send some core informations to the other node, so the fields will contain:

   realm      := <empty> | <fingerprint(realm)>                              64
   issuer     := <empty> | <fingerprint(issuer)>                             64
   subject    := 'urn:np:node:<protocol>:<hostname>:<port>'                 255
   audience   := <empty> | <fingerprint(realm)> | <fingerprint(issuer)>      64
   extensions := { <session key for DHKE> }                                  64
   public_key := <pk(node)>                                                  32
   signature  := <signature of above fields>                                 64
                                                                           -----
                                                                       max  602  bytes

Please remember that the main purpose here is to establish a secure conversation channel between any two nodes.
The cleartext hostname and port could also be found by doing a network scan.
From the above structure you can create a node fingerprint (nfp), which is unique to this specific token.
This fingerprint again is used as the visible part of the DHT, which can be addressed.
 
   nfp = hash(nodetoken, signature)

If a node hosts more than one idenity (currently not possible), then the issuer field should be blank. A separate 
node token will be supplied in the join message.


2: joining the network
**********************
The join message contains the token of the identity which is using a node. Identity token can be exported 
and imported and are available in the userspace.

   realm      := <empty> | <fingerprint(realm)>                               64
   issuer     := <empty> | <fingerprint(issuer)>                              64
   subject    := 'urn:np:id:'<hash(userdata)>'                               255
   audience   := <empty> | <fingerprint(realm)> | <fingerprint(issuer)>       64
   extensions := { target_node: nfp, <?user supplied data> }              min 64
   public_key := <pk(identity)>                                               32
   signature  := <signature of all above fields>                              64
                                                                             ----
                                                                         min 602

Again we can create a fingerprint of this token ('infp'). This fingerprint is not the same as the fingeprint of a 
pure identity (ifp), as we do not know in advance which 'nfp' this idenity will use. A pure identity token of does
not contain the 'nfp'. But we can still calculate the fingeprint afterwards, because:

   ifp = hash(idtoken, signature)
   infp = hash(idtoken, signature, nfp)

'nfp' potentially contains the idtoken fingerprint in the issuer field again. But if a technical node hosts more 
than one identity, then the join message will also contain again the node token, this time in full length and 
containing the required identity fingerprint:

   realm      := <empty> | <fingerprint(realm)>
   issuer     := <empty> | <fingerprint(issuer)>
   subject    := 'urn:np:node:<protocol>:<hostname>:<port>'
   audience   := <empty> | <fingerprint(realm)> | <fingerprint(issuer)>
   extensions := { identity: ifp, <?user supplied data> }
   public_key := <pk(node)>
   signature  := <signature of all above fields>

The second transmit of the node token is only there to certify that this identity is really running on this specific
node.

2: sending message intents
**************************
If an identity would like to exchange informations with another identity in the network, it sends out its message
intents, where we use token again.:

   realm      := <empty> | <fingerprint(realm)>
   issuer     := <empty> | <ifp> | <fingerprint(issuer)>
   subject    := 'urn:np:subject:'<hash(subject)>'
   audience   := <empty> | <fingerprint(realm)> | <fingerprint(issuer)>
   extensions := { target_node: nfp, <mx properties>, <?user supplied data> }
   public_key := <pk(identity)>
   signature  := <signature of all above fields>

Please note that a message intent is somehow different, as you may get a message intent of an identity that your node
may not have any connection to. So first you need to authenticate the issuer of this message intent. you can
accomplish this by doing one of the three steps:
   - you implement a callback that is able to properly authenticate peers (using MerkleTree / Secure Remote Passowrd /
     shamirs shared secret schems / ...)
   - you forward the recieved token to do the authn work for your node: either to your own realm, or to the realm set 
     in the message intent, or you ask the target_node contained in the token whether the identity is really known 
   - you do some sort of out-of-band deployment for know public idenity tokens. you could even use neuropil itself to 
     inject a trusted public identity token into a device.
Once you know, that the recieved peer is the vorrect one, you do the second step and authorize the message exchange.
Again you have the three options above with the follwoing restriction to the second choice:
   - you forward the recieved token to do the authz work for your node to your own realm 


3: pki setups
*************
Sometimes it is desirable to choose a pki setup for the tokens that you use. For this case the issuer field of the 
token strutcure can be used. It indicates whether a token has been signed by another party. There is no pre-defined
setup for this kind of , but the usual setup as you know it from certificates is required. Especially you will have 
to add your signature token to the extensions of an identity token.

One interesting feature of the neuropil message layer is the use of fingerprints as hash values, which are addressable
via the DHT. Without any further configuration we can exchange message intents with a realm or an issuer, and there
can be only one identity in the whole DHT which is able to create such identity or message intent tokens.

Therefore we (ourselves) favor the use of realms, because it lets you create 'online' registration instances without 
pre-issuing and deploying public tokens. A fingerprint of an identity token is enough to identify the right partner or
to find a third party (realm) who is willing to proove the authenticity of a device, application or person.
In a similar way you can remote control your devices, because for authorization requests each device, application or
person is able to contact your realm for allowance. 


4: conclusion
*************
you can create arbitrary complex hierarchical token constructs and facilitate them in the way we have descibed them.
Please do not overdo it! Setting up a new realm and rejoining your devices and applications is easier than creating
complex pki hierarchies, and it can be done online ! Try this with certifates/pki and you know that you have fallen
into a trap ...

