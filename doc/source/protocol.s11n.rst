..
  SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
..
  SPDX-License-Identifier: OSL-3.0

.. _protocol_s11n:

===============================================================================
Protocol serialization (CBOR)
===============================================================================

The following chapter gives a brief outline how neuropil uses the cose / cwt standard to serialize
token and messages.

.. note::
   The documentation of the cose / cwt is work in progress. Documentation and implementation will
   change as we progress with a standardization of the neuropil protocol.

CBOR tags
===============================================================================

The neuropil cybersecurity mesh has switched to the CBOR serialization format to transmit messages 
exchange information. CBOR allows to define and use so called "tags" to identify special content. 
The neuropil library currently uses the following tags when serializing internal structures:

===================================== ===== ======================================================
data type                             tag   description                                                 
===================================== ===== ======================================================
NP_CBOR_REGISTRY_ENTRIES              31415 base tag value, add it to each value below
np_treeval_type_short                 1     int8 value
np_treeval_type_int                   2     int16 value
np_treeval_type_long                  3     int32 value
np_treeval_type_long_long             4     int64 value
np_treeval_type_float                 5     float (4-bytes)
np_treeval_type_double                6     double (8 bytes)
np_treeval_type_char_ptr              7     string (char array)
np_treeval_type_char                  8     single character
np_treeval_type_unsigned_char         9     single unsigned character
np_treeval_type_unsigned_short        10    uint8 value
np_treeval_type_unsigned_int             11 uint16 value
np_treeval_type_unsigned_long            12 uint32 value
np_treeval_type_unsigned_long_long       13 uint64 value
np_treeval_type_uint_array_2             14 array of two uint26 values
np_treeval_type_float_array_2            15 array of two float values
np_treeval_type_char_array_8             16 array of eight characters
np_treeval_type_unsigned_char_array_8    17 array of eight unsigned character
np_treeval_type_void                     18 unused
np_treeval_type_bin                      19 binary value (length, bytes)
np_treeval_type_jrb_tree                 20 basically an key-value (can containing sub-arrays)
np_treeval_type_dhkey                    21 a fingerprint (e.g. of an token)
np_treeval_type_hash                     22 a hash value (any kind of hash value)
np_treeval_type_npobj                    23 unused
np_treeval_type_npval_count              24 unused
np_treeval_type_special_char_ptr         25 indicates a fixed string 
np_treeval_type_cwt                      26 a CWT (np_token)
np_treeval_type_cose_signed              27 a code signed data structure
np_treeval_type_cose_encrypted           28 an cose encrypted data structure 
===================================== ===== ======================================================


We hope to get rid of most these tags, as they are currently mainly motivated by a generic key-value
list. However, the following tags will probably stay and also will be registered in the cbor registry.

===================================== ===== ======================================================
data type                             tag   description                                                 
===================================== ===== ======================================================
np_treeval_type_dhkey                    21 see above
np_treeval_type_hash                     22 see above
np_treeval_type_cwt                      26 see above
np_treeval_type_cose_signed              27 see above
np_treeval_type_cose_encrypted           28 see above
===================================== ===== ======================================================

we are looking forward to add the following types:

===================================== ===== ======================================================
data type                             tag   description                                                 
===================================== ===== ======================================================
np_treeval_type_pheromone             29    a serialized form of a pheromone (content routing)
===================================== ===== ======================================================


CWT (CBOR web token)
===============================================================================

The np_token structure is inspired by the JWT, which again inspired CWT. Therefore it only makes sense
to re-use the CWT serialization format and tags when storing np_token on the disk (data-at-rest). When
storing/serializing an np_token the neuropil library *never* adds the secret key of the ed15519 keypair. 
The secret key can only be stored in an additional file (see below).

A np_token is serialized in the following format:

TODO:

This serialization format is the AEAD encrypted with a passphrase and a nonce to protect the plain-text 
information contained the the attribute set (to prevent collusion). An encrypted np_token on the disk 
currently has the following format:

TODO:


Neuropil Identity
===============================================================================

A neuropil identity contains the secret key of the ed25519 keypair, and it may contain a fingerprint
if it has to be used on conjunction with a np_token. 

The secret key is stored AEAD encrpyted with a passphrase and a nonce on the disk in the following format:

TODO:


Neuropil Keystore
===============================================================================

A keystore is the composition of several fingerprints of np_token. A keystore can be created for 
message intent token or digital identities. The current implementation only allows for a single directory,
but that could change in the future.

The keystore serializes each np_token into a separate file, where the filename is composed with the fingerprint
of the corresponding np_token. The actual keystore then only stores an array of fingerprints.

The array of fingerprints is AEAD encrypted with a passphrase and a nonce, because otherwise an attacker could
simply add entries to the file (or directory) to add malicious np_token.

The current implementation of the keystore has the following format:

TODO:


Neuropil Wallet
===============================================================================

to be developed :-)

