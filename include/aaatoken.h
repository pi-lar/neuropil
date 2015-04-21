/**
 ** $Id: np.h,v 1.19 2006/06/07 09:21:28 krishnap Exp $
 **
 ** Matthew Allen
 ** description:
 **/
#ifndef _NP_AAATOKEN_H_
#define _NP_AAATOKEN_H_

#include <pthread.h>
#include <uuid/uuid.h>

#include "include.h"
#include "key.h"
#include "sodium.h"

// sodium defines several length of its internal key size, but they always are 32U long
// crypto_scalarmult_BYTES, crypto_scalarmult_curve25519_BYTES, crypto_sign_ed25519_PUBLICKEYBYTES
// crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES
#define crypto_bytes crypto_box_PUBLICKEYBYTES


struct np_aaatoken_cache_t {

	np_jrb_t* authentication_token;
	np_jrb_t* authorization_token;
	np_jrb_t* accounting_token;

	pthread_mutex_t aaa_account_mutex;	/* for future security enhancement */
	pthread_mutex_t aaa_authorize_mutex;	/* for future security enhancement */
	pthread_mutex_t aaa_authenticate_mutex;	/* for future security enhancement */
};

// we use np_aaatoken_t for authorization, authentication and accounting purposes
// the data structure is the same, any addon information is stored in a jrb structure
struct np_aaatoken_t {

	double version;

	char realm[255]; // owner or parent entitiy

	char issuer[255]; // from
	char subject[255]; // about
	char audience[255]; // to

	double issued_at;
	double not_before;
	double expiration;

	Key*   token_id;
	uuid_t uuid;

	unsigned char public_key[crypto_bytes];
	unsigned char session_key[crypto_bytes];
	unsigned char private_key[crypto_bytes];

	np_jrb_t* extensions;

	// reference counter
    int ref_count;
    np_aaatoken_cache_t* cache;
};

np_aaatoken_cache_t* np_init_aaa_cache();

np_aaatoken_t* np_aaatoken_create();
void np_aaatoken_retain (np_aaatoken_t* cache);
void np_aaatoken_release (np_aaatoken_t* cache);

void np_free_aaatoken(np_aaatoken_cache_t* cache, const np_aaatoken_t* token);
void np_register_authorization_token(np_aaatoken_cache_t* cache, const np_aaatoken_t* token, Key* key);
void np_register_authentication_token(np_aaatoken_cache_t* cache, const np_aaatoken_t* token, Key* key);
void np_register_accounting_token(np_aaatoken_cache_t* cache, const np_aaatoken_t* token, Key* key);

np_aaatoken_t* np_get_authorization_token(np_aaatoken_cache_t* cache, Key* key);
np_aaatoken_t* np_get_authentication_token(np_aaatoken_cache_t* cache, Key* key);
np_aaatoken_t* np_get_accounting_token(np_aaatoken_cache_t* cache, Key* key);

void np_encode_handshake(pn_data* data, Key* from, Key* to);

#endif // _NP_AAATOKEN_H_
