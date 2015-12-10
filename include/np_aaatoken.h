/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_AAATOKEN_H_
#define _NP_AAATOKEN_H_

#include <pthread.h>
#include <uuid/uuid.h>

#include "sodium.h"

#include "include.h"
#include "np_container.h"
#include "np_memory.h"

// sodium defines several length of its internal key size, but they always are 32U long
// crypto_scalarmult_BYTES, crypto_scalarmult_curve25519_BYTES, crypto_sign_ed25519_PUBLICKEYBYTES
// crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES

/** np_aaatoken_t
 *
 *  we use np_aaatoken_t for authorization, authentication and accounting purposes
 *  the data structure is the same, any addon information is stored in a jrb structure
 *  several analogies have been used as a baseline for this structure: json web token, kerberos and diameter
 *  in principal any user/system/node can be identified by it's hash key (subject)
 *  a subject/issuer belongs to a realm
 *  a token for a subject has been issued by somebody, and there is an intended audience
 *  all data fields are just hash keys
 *
 *  neuropil nodes can use the realm and issuer hash key informations to request authentication and authorization
 *  of a subject
 *  accounting information will/can/should be send to the accounting audience
 **/
struct np_aaatoken_s {

	// link to memory management
	np_obj_t* obj;

	double version;

	char realm[255]; // owner or parent entity

	char issuer[255]; // from (can be self signed)
	char subject[255]; // about
	char audience[255]; // to

	double issued_at;
	double not_before;
	double expiration;

	np_bool valid;

	uuid_t uuid;

	unsigned char public_key[crypto_sign_BYTES];
	unsigned char session_key[crypto_scalarmult_SCALARBYTES];
	unsigned char private_key[crypto_sign_SECRETKEYBYTES];

	// key/value extension list
	np_jtree_t* extensions;
};

_NP_GENERATE_MEMORY_PROTOTYPES(np_aaatoken_t);

void np_encode_aaatoken(np_jtree_t* data, np_aaatoken_t* token);
void np_decode_aaatoken(np_jtree_t* data, np_aaatoken_t* token);

np_bool token_is_valid(np_aaatoken_t* token);

void np_add_sender_token(np_state_t *state, char* subject, np_aaatoken_t *token);
sll_return(np_aaatoken_t) np_get_sender_token_all(np_state_t *state, char* subject);
np_aaatoken_t* np_get_sender_token(np_state_t *state, char* subject, char* sender);

void np_add_receiver_token(np_state_t *state, char* subject, np_aaatoken_t *token);
sll_return(np_aaatoken_t) np_get_receiver_token_all(np_state_t *state, char* subject);
np_aaatoken_t* np_get_receiver_token(np_state_t *state, char* subject);

#endif // _NP_AAATOKEN_H_
