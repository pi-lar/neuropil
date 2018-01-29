//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/** \toggle_keepwhitespaces  */
/** 
The structure np_aaatoken_t is used for authorization, authentication and accounting purposes.
Add-on information can be stored in a nested jtree structure. Several analogies have been used as a baseline for this structure:
json web token, kerberos and diameter. Tokens do get integrity protected by adding an additional signature based on
the issuers public/private key pair

The structure is described here to allow users the proper use of the :c:func:`np_set_identity` function and to implement the
AAA callback functions :c:func:`np_setauthenticate_cb`, :c:func:`np_setauthorizing_cb` and :c:func:`np_setaccounting_cb`.

*/

#ifndef _NP_AAATOKEN_H_
#define _NP_AAATOKEN_H_

#include <pthread.h>

#if defined(__APPLE__) && defined(__MACH__)
#include <uuid/uuid.h>
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <uuid.h>
#endif

#include "sodium.h"

#include "np_dhkey.h"
#include "np_list.h"
#include "np_memory.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// sodium defines several length of its internal key size, but they always are 32U long
// crypto_scalarmult_BYTES, crypto_scalarmult_curve25519_BYTES, crypto_sign_ed25519_PUBLICKEYBYTES
// crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES

typedef enum np_aaastate_e aaastate_type;

enum np_aaastate_e
{
	AAA_UNKNOWN       = 0x00,
	AAA_VALID         = 0x01,
	AAA_AUTHENTICATED = 0x02,
	AAA_AUTHORIZED    = 0x04,
	AAA_ACCOUNTING    = 0x08
} NP_ENUM NP_API_EXPORT;

#define AAA_INVALID (~AAA_VALID)

#define IS_VALID(x) (AAA_VALID == (AAA_VALID & x ))
#define IS_INVALID(x) (!IS_VALID(x))

#define IS_AUTHENTICATED(x) (AAA_AUTHENTICATED  == (AAA_AUTHENTICATED & x))
#define IS_NOT_AUTHENTICATED(x) (!IS_AUTHENTICATED(x))

#define IS_AUTHORIZED(x) (AAA_AUTHORIZED  == (AAA_AUTHORIZED & x))
#define IS_NOT_AUTHORIZED(x) (!IS_AUTHORIZED(x))

#define IS_ACCOUNTING(x) (AAA_ACCOUNTING  == (AAA_ACCOUNTING & x))
#define IS_NOT_ACCOUNTING(x) (!IS_ACCOUNTING(x))

/**
.. c:type:: np_aaatoken_t

   The np_aaatoken_t structure consists of the following data types:

.. c:member:: char[255] realm

   each token belongs to a realm which can be used to group several different tokens.
   (type should change to np_key_t in the future)

.. c:member:: char[255] issuer

   the sender or issuer of a token (type should change to np_key_t in the future)

.. c:member:: char[255] subject

   the subject which describes the contents of this token. can be a message subject (topic) or could be
   a node identity or ... (type should change to np_key_t in the future)

.. c:member:: char[255] audience

   the intended audience of a token. (type should change to np_key_t in the future)

.. c:member:: double issued_at

   date when the token was created

.. c:member:: double not_before

   date when the token will start to be valid

.. c:member:: double expires_at

   expires_at date of the token

.. c:member:: aaastate_type state

   internal state indicator whether this token is valid (remove ?)

.. c:member:: uuid_t uuid

   a uuid to identify this token (not sure if this is really required)

.. c:member:: unsigned char public_key[crypto_sign_BYTES]

   the public key of a identity

.. c:member:: unsigned char session_key[crypto_scalarmult_SCALARBYTES]

   the shared session key (used to store the node-2-node encryption)

.. c:member:: unsigned char private_key[crypto_sign_SECRETKEYBYTES]

   the private key of an identity

.. c:member:: np_tree_t* extensions

   a key-value jtree structure to add arbitrary information to the token

   neuropil nodes can use the realm and issuer hash key information to request authentication and authorization of a subject
   token can then be send to gather accounting information about message exchange

*/
struct np_aaatoken_s
{
	// link to memory management
	np_obj_t* obj;

	double version;

	char realm[255]; // owner or parent entity

	char issuer[65]; // from (can be self signed)
	char subject[255]; // about
	char audience[255]; // to

	double issued_at;
	double not_before;
	double expires_at;

	aaastate_type state;

	char* uuid;

	unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
	unsigned char private_key[crypto_sign_SECRETKEYBYTES];
	np_bool private_key_is_set;

	unsigned char* signed_hash;
	unsigned char signature[crypto_sign_BYTES];
	np_bool is_signature_verified;

	// key/value extension list
	np_tree_t* extensions;
	/*
	A core token only has a subset of defined en-/decoded  values and may only be used to 
	instanciate a cryptographic safe communication
	*/
	np_bool is_core_token;
} NP_API_EXPORT;

#ifndef SWIG
_NP_GENERATE_MEMORY_PROTOTYPES(np_aaatoken_t);
#endif

// serialization of the np_aaatoken_t structure
NP_API_INTERN
void np_aaatoken_encode(np_tree_t* data, np_aaatoken_t* token);
NP_API_INTERN
void np_aaatoken_core_encode(np_tree_t* data, np_aaatoken_t* token, np_bool standalone);
NP_API_INTERN
void np_aaatoken_decode(np_tree_t* data, np_aaatoken_t* token);

/**
.. c:function::np_bool token_is_valid(np_aaatoken_t* token)

   checks if a token is valid.
   performs a cryptographic integrity check with a checksum verification on the main data elements

   :param token: the token to check
   :return: a boolean indicating whether the token is valid

*/
NP_API_EXPORT
np_bool _np_aaatoken_is_valid(np_aaatoken_t* token);

NP_API_INTERN
np_dhkey_t _np_aaatoken_create_dhkey(np_aaatoken_t* identity);

// neuropil internal aaatoken storage and exchange functions

NP_API_INTERN
void _np_aaatoken_add_sender(char* subject, np_aaatoken_t *token);
NP_API_INTERN
sll_return(np_aaatoken_ptr) _np_aaatoken_get_all_sender(const char* const subject, const char* const audience);
NP_API_INTERN
np_aaatoken_t* _np_aaatoken_get_sender(const char* const subject, const char* const sender);

NP_API_INTERN
void _np_aaatoken_add_receiver(char* subject, np_aaatoken_t *token);
NP_API_INTERN
sll_return(np_aaatoken_ptr) _np_aaatoken_get_all_receiver(const char* const subject, const char* const audience);
NP_API_INTERN
np_aaatoken_t* _np_aaatoken_get_receiver(const char* const subject, np_dhkey_t* target);

NP_API_INTERN
void _np_aaatoken_add_signature(np_aaatoken_t* msg_token);

NP_API_INTERN
np_aaatoken_t* _np_aaatoken_get_local_mx(const char* const subject);
NP_API_INTERN
void _np_aaatoken_add_local_mx(char* subject, np_aaatoken_t *token);
NP_API_INTERN
unsigned char* _np_aaatoken_get_fingerprint(np_aaatoken_t* msg_token, np_bool full);
NP_API_INTERN
np_bool _np_aaatoken_is_core_token(np_aaatoken_t* token);
NP_API_INTERN
void _np_aaatoken_mark_as_core_token(np_aaatoken_t* token);
NP_API_INTERN
void _np_aaatoken_mark_as_full_token(np_aaatoken_t* token);
NP_API_INTERN
void _np_aaatoken_upgrade_core_token(np_key_t* key_with_core_token, np_aaatoken_t* full_token);
NP_API_INTERN
void np_aaatoken_decode_with_secrets(np_tree_t* data, np_aaatoken_t* token);
NP_API_INTERN
void np_aaatoken_encode_with_secrets(np_tree_t* data, np_aaatoken_t* token);
NP_API_INTERN
np_aaatoken_t* _np_aaatoken_new(char issuer[64], char node_subject[255], double expires_at);
#ifdef __cplusplus
}
#endif

#endif // _NP_AAATOKEN_H_
