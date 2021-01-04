//
// neuropil is copyright 2016-2021 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

/**
The structure np_aaatoken_t is used for authorization, authentication and accounting purposes.
Add-on information can be stored in a nested jtree structure. Several analogies have been used as a baseline for this structure:
json web token, kerberos and diameter. Tokens do get integrity protected by adding an additional signature based on
the issuers public/private key pair

The structure is described here to allow users the proper use of the :c:func:`_np_set_identity` function and to implement the
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
#include "util/np_list.h"
#include "np_threads.h"
#include "np_memory.h"

#include "np_types.h"
#include "neuropil.h"
#include "np_crypto.h"

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

/*
Type enum for np_aaatoken_t objects, has impact on serialization and usage
FLAG
*/
enum np_aaatoken_type {
    np_aaatoken_type_undefined      = 0x00,
    np_aaatoken_type_identity       = 0x01,
    np_aaatoken_type_node           = 0x02,
    np_aaatoken_type_message_intent = 0x04,
    np_aaatoken_type_handshake      = 0x08,
};

enum np_aaatoken_scope {
    np_aaatoken_scope_private = 1,
    // np_aaatoken_scope_private_available defines a state where the token does not hold the privatekey itself but we do have the privekey available (ex.: creation of a message intent token)
    np_aaatoken_scope_private_available,
    np_aaatoken_scope_public,
    np_aaatoken_scope_undefined,
};

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

	// protocol version
	double version;

	// attributes to exchange
	char uuid[NP_UUID_BYTES];
	// owner or parent entity
	char realm[255];

	// from (if self signed empty)
	char issuer[65];

	// about
	char subject[255];

	// to
	char audience[255];

	double issued_at;
	double not_before;
	double expires_at;

	// key/value extension list
	np_attributes_t attributes;
	np_signature_t  attributes_signature;
	//np_tree_t* extensions;
	//np_tree_t* extensions_local;

	np_crypto_t crypto;
	np_signature_t signature;
	// attributes to exchange END

	// internal attributes
	aaastate_type state;
	/*
	FLAG
	*/
	enum np_aaatoken_type type;
	enum np_aaatoken_scope scope;
	bool private_key_is_set;

	np_aaatoken_t* issuer_token;

	bool is_signature_verified;
	bool is_signature_attributes_verified;
} NP_API_EXPORT;

_NP_GENERATE_MEMORY_PROTOTYPES(np_aaatoken_t);

// serialization of the np_aaatoken_t structure
NP_API_INTERN
void np_aaatoken_encode(np_tree_t* data, np_aaatoken_t* token);
NP_API_INTERN
bool np_aaatoken_decode(np_tree_t* data, np_aaatoken_t* token);

/**
.. c:function::bool token_is_valid(np_aaatoken_t* token)

   checks if a token is valid.
   performs a cryptographic integrity check with a checksum verification on the main data elements

   :param token: the token to check
   :return: a boolean indicating whether the token is valid

*/
NP_API_EXPORT
bool _np_aaatoken_is_valid(np_aaatoken_t* token, enum np_aaatoken_type expected_type);

NP_API_INTERN
np_dhkey_t np_aaatoken_get_fingerprint(np_aaatoken_t* token, bool include_extensions);

// neuropil internal aaatoken storage and exchange functions

NP_API_INTERN
sll_return(np_aaatoken_ptr) _np_aaatoken_get_all_sender(np_state_t* context, const char* const subject, const char* const audience);
NP_API_INTERN
np_aaatoken_t* _np_aaatoken_get_sender_token(np_state_t* context, const char* const subject, const np_dhkey_t* const sender_dhkey);

NP_API_INTERN
sll_return(np_aaatoken_ptr) _np_aaatoken_get_all_receiver(np_state_t* context, const char* const subject, const char* const audience);
NP_API_INTERN
np_aaatoken_t* _np_aaatoken_get_receiver(np_state_t* context, const char* const subject, np_dhkey_t* target);

NP_API_INTERN
np_aaatoken_t* _np_aaatoken_get_local_mx(np_state_t* context, const char* const subject);
NP_API_INTERN
void _np_aaatoken_add_local_mx(char* subject, np_aaatoken_t *token);
NP_API_INTERN
unsigned char* _np_aaatoken_get_hash(np_aaatoken_t* msg_token);
NP_API_INTERN
int __np_aaatoken_generate_signature(np_state_t* context, unsigned char* hash, unsigned char* private_key, unsigned char* save_to);
NP_API_INTERN
void _np_aaatoken_update_scope(np_aaatoken_t* self);
NP_API_INTERN
void np_aaatoken_set_partner_fp(np_aaatoken_t*self, np_dhkey_t partner_fp);
NP_API_INTERN
np_dhkey_t np_aaatoken_get_partner_fp(np_aaatoken_t* self);
NP_API_INTERN
void _np_aaatoken_set_signature(np_aaatoken_t* self, np_aaatoken_t* signee);
NP_API_INTERN
void _np_aaatoken_update_attributes_signature(np_aaatoken_t* self);
NP_API_INTERN
unsigned char* __np_aaatoken_get_attributes_hash(np_aaatoken_t* self);
NP_API_INTERN
void np_aaatoken_ref_list(np_sll_t(np_aaatoken_ptr, sll_list), const char* reason, const char* reason_desc);
NP_API_INTERN
void np_aaatoken_unref_list(np_sll_t(np_aaatoken_ptr, sll_list), const char* reason);
NP_API_INTERN
np_dhkey_t _np_aaatoken_get_issuer(np_aaatoken_t* self);

#ifdef DEBUG
NP_API_INTERN
void _np_aaatoken_trace_info(char* desc, np_aaatoken_t* token);
#else
#define _np_aaatoken_trace_info(desc,token);
#endif
NP_API_INTERN
struct np_token* np_aaatoken4user(struct np_token* dest, np_aaatoken_t* src);
NP_API_INTERN
np_aaatoken_t*  np_user4aaatoken(np_aaatoken_t* dest, struct np_token* src);
#ifdef __cplusplus
}
#endif

#endif // _NP_AAATOKEN_H_
