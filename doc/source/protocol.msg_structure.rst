.. _protocol_message_structure:

.. note::
   The documentation of the message structure is work in progress. Documentation and implementation will
   change as we progress with a standardization of the neuropil protocol.

   
1024 byte structure of neuropil messages
****************************************

The neuropil messaging layer uses a layered approach as many other internet protocols
as well. The general message format consists of seven distinct sections, which are shown below:

.. code-block:: c

   ------------------------------------------------------------------------
   | mac(n) | instructions | mac(i) | header | attributes | body  | nonce |
   ------------------------------------------------------------------------


  * mac(n): the MAC between to be used for the next hop nodes
  * instructions: short extra information required for the communication between two nodes
  * mac(i): mac of the message (including header)
  * header: initial header of the original sender. cannot be modified after creation (see mac(i))
  * attributes: extra attributes of a message (similar to http header fields)
  * body: the real payload
  * nonce: a nonce to further secure the crypto routines


Node to node encryption details
*******************************

Messages between two nodes are encrypted with the following pattern, if the payload is already end-to-end encrypted:

.. code-block:: c

   | mac(n) | instructions | mac(i) | header | attributes | body  | nonce |
            | <- crypted         -> | <- sig                           -> |


  *  mac(n) = arg(mac / maclen_p)
  *  instructions header = arg(m / mlen)
  *  attributes / body / mac(i) / nonce = arg(ad / adlen)
  *  nonce = arg(npub)

Otherwise the transport encryption between two nodes uses the following layout:

.. code-block:: c

   | mac(n) | instructions | mac(i) | header | attributes | body  | nonce |
            | <- crypted                                       -> | sig?  |


  *  mac(n) = arg(mac / maclen_p)
  *  instructions / header / attributes / body / mac(i) = arg(m / mlen)
  *  nonce = arg(ad / adlen) ?
  *  nonce = arg(npub)


End to end encryption details
*****************************

The end-to-end encryption covers only the inner part of the message structure:

.. code-block:: c

   | mac(n) | instructions | mac(i) | header | attributes | body | nonce |
                           | mac(i) | <sig>  | <- e2e crypted -> |


  *  mac(i) = arg(mac/maclen_p)
  *  body / attributes = arg(m / mlen)
  *  header / nonce = arg(ad / adlen) ?
  *  nonce = arg(npub)

Even if no transport encryption is applied, the body contents are still safe. Only metadata hash values will be visible.

Key exchange and messages
*************************

  *  the n2n key generation is based on the PFS/DHKE by exchanging handshake messages. We plan to extend tranport
     encryption with attribute based chained hmac values in the future.
  *  the e2e key generation is based on random symmetric key data. attribute based chained hmac values are also an option
     for later releases
  *  the required e2e key exchange is handled by encrypting the symmetric key with PFS taken from discovery messages
     *  send it over with separate message sequence number of '0/4'
     *  the body of this message contains the encrypted symmetric key plus the uuid of the token to be used
  *  the follow up e2e encryption of messages after the key exchange:
     *  messages will be encrypted with the symmetric key
     *  seq number will then be '1/4' to '4/4'
  *  we voluntarily do not use ratcheting. the possibility to do attribute based encryption brings us a greater benefit.

Message encryption
******************

For the encryption the XCacha20 algoithms are used, for the signature the Poly1305 tags are added to the messages.
Both are covered in the following libsodium function::

  .. code-block:: c

     int crypto_aead_xchacha20poly1305_ietf_encrypt_detached(unsigned char *c,
                                                             unsigned char *mac,
                                                             unsigned long long *maclen_p,
                                                             const unsigned char *m,
                                                             unsigned long long mlen,
                                                             const unsigned char *ad,
                                                             unsigned long long adlen,
                                                             const unsigned char *nsec,
                                                             const unsigned char *npub,
                                                             const unsigned char *k);

with:

* `c` := the encrypted message (part)

* `mac` := the message authentication code

* `maclen` := the length of message authentication code

* `m` := the message (part) to encrypt

* `mlen` := the length of the message (part) to encrypt

* `ad` := the additional data to sign

* `adlen` := the length of the additional data to sign

* `nsec` := not used

* `npub` := the nonce to use for encryption / signatures

* `k` := the key material to use for encryption


Protocol messages and signed / crypted content details
******************************************************

1.  Handshake message
*********************

Handshake messages are exchanged to establish transport encryption layer.

.. code-block:: c

   | mac(n) | instructions | mac(i) | header | attributes | body  | nonce |
            | n2n crypted  (mlen=0 !!!)                           |


2.  Pure node to node messages (join, leave)
********************************************

Join and leave messages to inform peers about starting/stopping nodes.
 
.. code-block:: c

   | mac(n) | instructions | mac(i) | header | attributes | body  | nonce |
                           | e2e crypted (mlen=0 !!!)             |
            | n2n crypted                                         |


3. Pure node to node messages (ping, piggy, ...)
************************************************

Simple messages for healthchecks and exchange of peer nodes.

.. code-block:: c

   | mac(n) | instructions | mac(i) | header | attributes | body  | nonce |
                           | e2e crypted (mlen=0 !!!)             |
            | n2n crypted                                         |


  *note*: node token 'from' header hash value must be used to verify signature of the node


4.  forward modified node to node messages (update, ...)
********************************************************

Some internal message types are forwarded to additional nodes but require a little modification.

1st hop:

.. code-block:: c

   | mac(n) | instructions | mac(i) | header | attributes | body  | nonce |
                           | e2e crypted (mlen=0 !!!)             |
            | n2n crypted                                         |


  *note*: id token in body contains hash value of node token, which is present in the header

  *note*: node token and it's public key has been transmitted in the handshake message


5.  Forward unmodified/discovery messages
*****************************************

Specific definition of discovery messages (additional MAC on the body of the message)

.. code-block:: c

   | mac(n) | instructions | mac(i) | header | attributes | body  | nonce |
                           | e2e crypted (mlen=0 !!!)             |
            | n2n crypted                                         |

  *  body contains signed message intent token


6.  End-to-end encrypted messages
*********************************

.. code-block:: c

   | mac(n) | instructions | mac(i) | header | attributes | body  | nonce |
                           | e2e crypted                          |
            | n2n crypted                                         |


Message serialization format
****************************

We use the :term:`msgpack` format to serialize messages. Some parts of the message can still be used directly, as the position
in the 1024 byte blocks is always is the same. The message object can then be composed of the following parts:

.. code-block:: c

   message := fixarray(7)(mac(n)|instructions|mac(i)|header|attr|body|nonce) (1)


  * mac(n) := bin8(16) (17)
  * instructions := int32 | int16 (8)
  * mac(i) := bin8(16) (17)
  * header := ts | int32 | bin8(32) | bin8(32) | bin8(32) | bin8(18) | uint32 | uint8 | uint16 | uint16
  * attr() := bin(16) (min 3)
  * body() := bin(32) (min 5)
  * nonce  := bin8(24) (25)

  * ts := ext8(40-bit signed int) | ext8(24-bit uint) (14)


All together this sums up to 220 bytes of protocol parts (1+17+8+17+150+3+5+25=236)
:term:`msgpack` definitions sum up to 29 bytes and could be optimized (removed) further in the future.
Right now it is easier to keep msg protocol definitions to ba able to add further fields in the future.


Message parts details
*********************

The following three sections define each single part of a message.

Message header contents
***********************

* `tstamp` | (int = 5 bytes) | int 3 bytes | sent timestamp of message (signed second + unsigned nanoseconds)

* `ttl` | (double = 4 bytes) | time to live for the message (in seconds)

* `to` | (8 * uint32_t = 32 bytes) | np_id of the receiver (can be an abstract np_id)

* `subj` | (8 * uint32_t = 32 bytes) | np_id of the message subject

* `from` | (8 * uint32_t = 32 bytes) | np_id of the sending node

* `parts` | (2 * uint16_t = 4 bytes) | current/total number of message parts

* `mhop` | (uint8_t = 1 bytes) | max numbers of hops for this message

* `seq` | (uint32_t = 4 bytes) | sender id sequence number (always increasing)

* `uuid` unique id for each message (18 bytes)

in total: 135 bytes

.. code-block:: c

   0                8               16               24               32 bytes
   [-------------------------------------------------------------------]
   [16 bytes MAC(n)                  ]XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   [----------------|----------------|----------------|----------------]
   [instructions                                                       ]
   ...
   [----------------|----------------|----------------|----------------]
   [16 bytes MAC(i)                  ]XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   [----------------|----------------|----------------|----------------]
   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX[tstamp(8)       |ttl(4)  XXXXXXXX]
   [subj(32)                                                           ]
   [to (32)                                                            ]
   [from(32)                                                           ]
   [uuid(18)                           |seq(4)|mhops(1)|parts(4)]XXXXXXX  sum=135 bytes
   [-------------------------------------------------------------------]
   [attributes                                                         ]
   ...
   [-------------------------------------------------------------------]
   [body                                                               ]
   ...
   [-------------------------------------------------------------------]
   [NONCE                                             ]XXXXXXXXXXXXXXXXX


Message instructions contents
*****************************

`_np.seq` | (uint32_t = 4 bytes) | intermediate node sequence number (always increasing)

`_np.sendnr` | (uint32_t = 2 bytes) | resend / hop counter. each (intermediate) node increases this counter for a given message. If too high (greater than maxhop of the message), then the message will be dropped.


.. code-block:: c

   0                8               16               24               32 bytes
   [----------------|----------------|----------------|----------------]
   [MAC                              ]XX
   [----------------|----------------|----------------|----------------]
   [instructions                                                       ]
   [seq(4) |sendnr(2)]XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX  sum = 6 bytes
   [-------------------------------------------------------------------]
   [MAC                              ]XX
   [----------------|----------------|----------------|----------------]
   [header                                                             ]
   ...
   [-------------------------------------------------------------------]
   [attributes                                                         ]
   ...
   [-------------------------------------------------------------------]
   [body                                                               ]
   ...
   [-------------------------------------------------------------------]
   [NONCE                                             ]XXXXXXXXXXXXXXXXX


Message mac/nonce details
*************************

`_np.nonce` | (24 bytes) | a uniqe nonce for each single message on the transport

`_np.mac(n)` | (16 bytes) | an  mac using authentication code of the node

`_np.mac(i)` | (16 bytes) | an  mac using authentication code of the identity

.. code-block:: c

   0                8               16               24               32 bytes
   [16 bytes MAC(n)                  ]XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   [----------------|----------------|----------------|----------------]
   [instructions                                                       ]
   ...
   [----------------|----------------|----------------|----------------]
   [16 bytes MAC(i)                  ]XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   [----------------|----------------|----------------|----------------]
   [header                                                             ]
   ...
   [-------------------------------------------------------------------]
   [attributes                                                         ]
   ...
   [-------------------------------------------------------------------]
   [body                                                               ]
   ...
   [-------------------------------------------------------------------]
   [24 bytes NONCE                                    ]XXXXXXXXXXXXXXXXX

