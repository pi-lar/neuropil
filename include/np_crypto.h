//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdlib.h>
#include "sodium.h"
#include "np_types.h"
#include "np_memory.h"

#ifndef _NP_CRYPTO_H_
#define _NP_CRYPTO_H_

typedef struct np_crypto_encrypted_intermediate_key_s {
	bool freeable;
	np_dhkey_t target;
	unsigned char data[crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES];
}np_crypto_encrypted_intermediate_key_t;

typedef np_crypto_encrypted_intermediate_key_t* np_crypto_encrypted_intermediate_key_ptr;

NP_SLL_GENERATE_PROTOTYPES(np_crypto_encrypted_intermediate_key_ptr)

struct np_crypto_session_s {
	bool
		session_key_to_read_is_set,
		session_key_to_write_is_set
		;
	unsigned char
		session_key_to_read[crypto_kx_SESSIONKEYBYTES],
		session_key_to_write[crypto_kx_SESSIONKEYBYTES];
};

struct np_crypto_s {
	bool
		ed25519_public_key_is_set,
		ed25519_secret_key_is_set,
		derived_kx_public_key_is_set,
		derived_kx_secret_key_is_set
		;
	unsigned char
		ed25519_public_key[crypto_sign_ed25519_PUBLICKEYBYTES],
		ed25519_secret_key[crypto_sign_ed25519_SECRETKEYBYTES];

	unsigned char
		derived_kx_public_key[crypto_kx_PUBLICKEYBYTES],
		derived_kx_secret_key[crypto_kx_SECRETKEYBYTES];
};

typedef struct np_crypto_transport_message_s {
	size_t data_length;
	void* encrypted_data;
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
}np_crypto_transport_message_t;


typedef struct np_crypto_E2E_message_s {
	np_crypto_transport_message_t t;

	np_sll_t(np_crypto_encrypted_intermediate_key_ptr, encrypted_intermediate_keys);

	unsigned char _intermediate_key[crypto_secretbox_KEYBYTES];
	unsigned char _sender_secret_key[crypto_kx_SECRETKEYBYTES];
}np_crypto_E2E_message_t;

_NP_GENERATE_MEMORY_PROTOTYPES(np_crypto_t)

void np_crypto_init(np_crypto_t* self);
// generates new keypairs, buffer may be NULL
np_crypto_t* np_cryptofactory_new(np_context* context, np_crypto_t* buffer);
np_crypto_t* np_cryptofactory_by_public(np_context* context, np_crypto_t* buffer, unsigned char ed25519_public_key[crypto_sign_ed25519_PUBLICKEYBYTES]);
np_crypto_t* np_cryptofactory_by_secret(np_context* context, np_crypto_t* buffer, unsigned char ed25519_secret_key[crypto_sign_ed25519_SECRETKEYBYTES]);
// generates new keypairs, buffer may be NULL
int np_crypto_session(np_state_t* context, np_crypto_t* my_container, np_crypto_session_t* session, np_crypto_t* remote_container, bool remote_is_client);

int np_crypto_generate_signature(np_crypto_t* self, unsigned char * signature_buffer, void* data_to_sign, size_t data_size);
int np_crypto_verify_signature(np_crypto_t* self, unsigned char signature_buffer[crypto_sign_BYTES], void* data_to_verify, size_t data_size);

np_crypto_E2E_message_t * np_crypt_E2E_init(
	np_crypto_E2E_message_t * buffer,
	np_crypto_t* sender,
	void* data_to_encrypt,
	size_t data_size
);
void np_crypto_E2E_message_t_free(np_crypto_E2E_message_t* container);
// buffer needs to be at least the same size as data_to_encrypt
int np_crypt_E2E_encrypt(np_crypto_E2E_message_t* container, np_crypto_t* receiver_crypto, np_dhkey_t receiver, np_crypto_encrypted_intermediate_key_t* buffer);

// buffer needs to be at least the same size as data_to_decrypt
int np_crypt_E2E_decrypt(np_state_t* context, np_crypto_t* self, np_dhkey_t local, np_crypto_t* remote, void* decrypted_data_buffer, void* data_to_decrypt);
void np_crypt_E2E_serialize(np_crypto_E2E_message_t* container, np_tree_t* out_buffer);
int np_crypt_E2E_deserialize(np_crypto_E2E_message_t* container, np_tree_t* buffer);

// buffer needs to be at least the same size as data_to_encrypt
int np_crypt_transport_encrypt(np_crypto_session_t* session, unsigned char* buffer, void* data_to_encrypt, size_t data_size);

// buffer needs to be at least the same size as data_to_decrypt
int np_crypt_transport_decrypt(np_state_t* context, np_crypto_session_t* session, void* buffer, void* data_to_decrypt);
void np_crypt_transport_serialize(np_crypto_transport_message_t* tmessage, np_tree_t* out_buffer);
int np_crypt_transport_deserialize(np_crypto_transport_message_t* tmessage, np_tree_t* buffer);

void np_crypt_export(np_crypto_t* self, struct np_token *dest);


uint32_t np_crypt_rand();
uint32_t np_crypt_rand_mm(uint32_t min, uint32_t max);



//TODO: rm after dhke rework
int  __np_crypt_decrypt(np_crypto_transport_message_t* tmessage, unsigned char* secret_key, void* buffer);

#endif // _NP_CRYPTO_H_
