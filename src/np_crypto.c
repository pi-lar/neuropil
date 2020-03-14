//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include "sodium.h"
#include <assert.h>
#include <inttypes.h>

#include "np_constants.h"
#include "np_types.h"
#include "np_log.h"
#include "np_tree.h"
#include "np_memory.h"
#include "np_serialization.h"
#include "np_crypto.h"

#include <stdio.h>

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_crypto_encrypted_intermediate_key_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_crypto_encrypted_intermediate_key_ptr);

void _np_crypto_t_new(NP_UNUSED np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* data) {
	np_crypto_init((np_crypto_t*)data);
}
void np_crypto_init(np_crypto_t* self) {
	self->ed25519_public_key_is_set = false;
	self->ed25519_secret_key_is_set = false;
	self->derived_kx_public_key_is_set = false;
	self->derived_kx_secret_key_is_set = false;
}
void _np_crypto_t_del(NP_UNUSED np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, NP_UNUSED void* data) {
	// np_crypto_t* obj = (np_crypto_t*)data;
}

// generates new keypairs, buffer may be NULL
np_crypto_t* np_cryptofactory_new(np_context* context, np_crypto_t* buffer) {
	np_crypto_t* ret = buffer;
	if (ret == NULL) {
		np_new_obj(np_crypto_t, ret, FUNC);
	}

	if (ret != NULL) {
		if (0 != crypto_sign_ed25519_keypair(ret->ed25519_public_key, ret->ed25519_secret_key)) {
			log_msg(LOG_ERROR, "Could not create ed25519 keypair!");
			if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
			ret = NULL;
		}
		else {
			ret->ed25519_public_key_is_set = true;
			ret->ed25519_secret_key_is_set = true;
		}
	}
	if (ret != NULL) {
		if (0 != crypto_sign_ed25519_sk_to_curve25519(ret->derived_kx_secret_key, ret->ed25519_secret_key)) {
			log_msg(LOG_ERROR, "Could not convert ed25519 secret key to session secret key!");
			if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
			ret = NULL;
		}
		else {
			ret->derived_kx_secret_key_is_set = true;
		}
	}
	if (ret != NULL) {
		if (0 != crypto_sign_ed25519_pk_to_curve25519(ret->derived_kx_public_key, ret->ed25519_public_key)) {
			log_msg(LOG_ERROR, "Could not convert ed25519 public key to session public key!");
			if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
			ret = NULL;
		}
		else {
			ret->derived_kx_public_key_is_set = true;
		}
	}
	return ret;
}
np_crypto_t* np_cryptofactory_by_secret(np_context* context, np_crypto_t* buffer, unsigned char ed25519_secret_key[crypto_sign_ed25519_SECRETKEYBYTES]) {
	np_crypto_t* ret = buffer;
	if (ret == NULL) {
		np_new_obj(np_crypto_t, ret, FUNC);
	}

	if (ret != NULL) {
		memcpy(ret->ed25519_secret_key, ed25519_secret_key, crypto_sign_ed25519_SECRETKEYBYTES);
		ret->ed25519_secret_key_is_set = true;

		if (0 != crypto_sign_ed25519_sk_to_pk(ret->ed25519_public_key, ret->ed25519_secret_key)) {
			log_msg(LOG_ERROR, "Cannot convert ed25519 public key from given secret key");
			if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
			ret = NULL;
		}
		else {
			ret->ed25519_public_key_is_set = true;
		}
	}
	if (ret != NULL) {
		if (0 != crypto_sign_ed25519_sk_to_curve25519(ret->derived_kx_secret_key, ret->ed25519_secret_key)) {
			log_msg(LOG_ERROR, "Could not convert ed25519 secret key to curve25519 secret key!");
			if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
			ret = NULL;
		}
		else {
			ret->derived_kx_secret_key_is_set = true;
		}
	}
	if (ret != NULL) {
		if (0 != crypto_sign_ed25519_pk_to_curve25519(ret->derived_kx_public_key, ret->ed25519_public_key)) {
			log_msg(LOG_ERROR, "Could not convert ed25519 public key to curve25519 public key!");
			if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
			ret = NULL;
		}
		else {
			ret->derived_kx_public_key_is_set = true;
		}
	}
	return ret;
}
np_crypto_t* np_cryptofactory_by_public(np_context* context, np_crypto_t* buffer, unsigned char ed25519_public_key[crypto_sign_ed25519_PUBLICKEYBYTES]) {
	np_crypto_t* ret = buffer;
	if (ret == NULL) {
		np_new_obj(np_crypto_t, ret, FUNC);
	}

	if (ret != NULL) {
		memcpy(ret->ed25519_public_key, ed25519_public_key, crypto_sign_ed25519_PUBLICKEYBYTES);
		ret->ed25519_public_key_is_set = true;
	}
	if (ret != NULL && ret->ed25519_public_key_is_set) {
		if (0 != crypto_sign_ed25519_pk_to_curve25519(ret->derived_kx_public_key, ret->ed25519_public_key)) {
			log_msg(LOG_ERROR, "Could not convert ed25519 public key to session public key!");
			if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
			ret = NULL;
		}
		else {
			ret->derived_kx_public_key_is_set = true;
		}
	} 
	ret->ed25519_secret_key_is_set = false;
	ret->derived_kx_secret_key_is_set = false;
	return ret;
}

// generates new keypairs, buffer may be NULL
int np_crypto_session(
	np_state_t* context,
	np_crypto_t* my_container,
	np_crypto_session_t* session,
	np_crypto_t* remote_container,
	bool remote_is_client
) {
	assert(context != NULL);
	assert(my_container != NULL);
	assert(session != NULL);
	assert(remote_container != NULL);
	assert(remote_container->derived_kx_public_key_is_set);
	//assert(remote_container_to_be_filled != NULL);
	//assert(remote_session_public_key != NULL);

	int ret = -2;
	if (my_container->derived_kx_public_key_is_set && my_container->derived_kx_secret_key_is_set) {
		ret = -3;

		//np_crypto_t* remote_container_to_use = np_cryptofactory_by_public(context, remote_container_to_be_filled, remote_session_public_key);


		if (remote_is_client) {
			ret = crypto_kx_server_session_keys(
				session->session_key_to_read,
				session->session_key_to_write,
				my_container->derived_kx_public_key,
				my_container->derived_kx_secret_key,
				remote_container->derived_kx_public_key);
		}
		else {
			ret = crypto_kx_client_session_keys(
				session->session_key_to_read,
				session->session_key_to_write,
				my_container->derived_kx_public_key,
				my_container->derived_kx_secret_key,
				remote_container->derived_kx_public_key);
		}
	}
	if (ret == 0) {
		session->session_key_to_read_is_set = true;
		session->session_key_to_write_is_set = true;
	}
	return ret;
}

int  __np_crypt_encrypt(np_crypto_transport_message_t* tmessage, unsigned char* secret_key, void* data_to_encrypt, size_t data_size) {
	assert(tmessage != NULL);
	assert(secret_key != NULL);
	assert(data_to_encrypt != NULL);
	int ret = -1;
	randombytes_buf(tmessage->nonce, sizeof tmessage->nonce);
	tmessage->data_length = data_size + crypto_secretbox_MACBYTES;
	tmessage->encrypted_data = calloc(1, tmessage->data_length);
	ret = crypto_secretbox_easy(
		tmessage->encrypted_data,
		data_to_encrypt,
		data_size,
		tmessage->nonce,
		secret_key
	);

	return ret;
}
int __np_crypt_decrypt(np_crypto_transport_message_t* tmessage, unsigned char* secret_key, void* buffer) {
	assert(tmessage != NULL);
	assert(secret_key != NULL);
	assert(buffer != NULL);

	int ret = crypto_secretbox_open_easy(
		buffer,
		tmessage->encrypted_data,
		tmessage->data_length,
		tmessage->nonce,
		secret_key);
	 
	return ret;
}

int np_crypto_generate_signature(np_crypto_t* self, unsigned char* signature_buffer, void* data_to_sign, size_t data_size) {
	assert(self != NULL);
	assert(signature_buffer != NULL);
	assert(data_to_sign != NULL);
	int ret = -2;
	if(self->ed25519_secret_key_is_set) {
		ret = crypto_sign_detached(signature_buffer,
			NULL,
			data_to_sign, data_size,
			self->ed25519_secret_key);
	}
	return ret;
}
int np_crypto_verify_signature(np_crypto_t* self, unsigned char signature_buffer[crypto_sign_BYTES], void* data_to_verify, size_t data_size) {
	assert(self != NULL);
	assert(data_to_verify != NULL);
	int ret = -2;
	if (self->ed25519_public_key_is_set) {
		ret = crypto_sign_verify_detached(signature_buffer, data_to_verify, data_size, self->ed25519_public_key);
	}
	return ret;
}

void _np_crypt_transport_init_parts(np_crypto_transport_message_t* container) {
	assert(container != NULL);
	container->encrypted_data = NULL;
}
void np_crypto_transport_message_t_free(np_crypto_transport_message_t* container) {
	assert(container != NULL);
	// free intermediate keys from container
	if (container->encrypted_data != NULL) free(container->encrypted_data);
}

void np_crypt_transport_serialize(np_crypto_transport_message_t* tmessage, np_tree_t* out_buffer) {
	assert(tmessage != NULL);
	assert(out_buffer != NULL);
	np_tree_insert_str(out_buffer, NP_NONCE, np_treeval_new_bin(tmessage->nonce, sizeof tmessage->nonce));
	np_tree_insert_str(out_buffer, NP_ENCRYPTED, np_treeval_new_bin(tmessage->encrypted_data, tmessage->data_length));
}
int np_crypt_transport_deserialize(np_crypto_transport_message_t* tmessage, np_tree_t* buffer) {
	assert(tmessage != NULL);
	assert(buffer != NULL);
	int ret = 0;
	np_tree_elem_t* tmp;
	if (NULL == (tmp = np_tree_find_str(buffer, NP_NONCE))) {
		ret = -1;
	}
	else {
		assert(sizeof tmessage->nonce == tmp->val.size);
		memcpy(tmessage->nonce, tmp->val.value.bin, sizeof tmessage->nonce);
		if (NULL == (tmp = np_tree_find_str(buffer, NP_ENCRYPTED))) {
			ret = -2;
		}
		else {
			tmessage->encrypted_data = malloc(tmp->val.size);
			memcpy(tmessage->encrypted_data, tmp->val.value.bin, tmp->val.size);
			tmessage->data_length = tmp->val.size;
		}
	}
	return ret;
}

// buffer needs to be at least the same size as data_to_encrypt
int np_crypt_transport_encrypt(np_crypto_session_t* session, unsigned char* buffer, void* data_to_encrypt, size_t data_size) {
	assert(session != NULL);
	assert(buffer != NULL);
	assert(data_to_encrypt != NULL);
	assert(data_size <= MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40);

	int ret= -2;
	if (session->session_key_to_write_is_set) {
		ret = -3;
		np_crypto_transport_message_t tmessage;
		_np_crypt_transport_init_parts(&tmessage);
		// extend data to 1024

		void * extended_data = data_to_encrypt;
		if (data_size < MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40) {
			extended_data = malloc(MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40);
			memcpy(extended_data, data_to_encrypt, data_size);
		}
		ret = __np_crypt_encrypt(&tmessage, session->session_key_to_write, extended_data, MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40);
		if (data_size < MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40) {
			free(extended_data);
		}

		memcpy(buffer, tmessage.nonce, sizeof tmessage.nonce);
		memcpy(buffer + sizeof tmessage.nonce, tmessage.encrypted_data, tmessage.data_length);
		uint32_t totalLength = sizeof tmessage.nonce + tmessage.data_length;
		// TODO: rm if buffer is filled by random bytes externally
		if (totalLength < MSG_CHUNK_SIZE_1024) {
			randombytes_buf(buffer + totalLength, MSG_CHUNK_SIZE_1024 - totalLength);
		}
		np_crypto_transport_message_t_free(&tmessage);
	}
	return ret;
}

// buffer needs to be at least the same size as data_to_decrypt
int np_crypt_transport_decrypt(np_state_t* context, np_crypto_session_t* session, void* buffer, void* data_to_decrypt) {
	assert(context != NULL);
	assert(session != NULL);
	assert(buffer != NULL);
	int ret = -2;
	if (session->session_key_to_read_is_set) {
		ret = -3;
		
		np_crypto_transport_message_t container = { 0 };
		_np_crypt_transport_init_parts(&container);
		memcpy(&container.nonce, data_to_decrypt, sizeof container.nonce);
		container.data_length = MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES;
		container.encrypted_data = malloc(container.data_length);
		memcpy(container.encrypted_data, data_to_decrypt + sizeof container.nonce, container.data_length);

		ret = 100 * __np_crypt_decrypt(&container, session->session_key_to_read, buffer);

		np_crypto_transport_message_t_free(&container);
		
	}
	return ret;
}

void _np_crypt_E2E_init_parts(np_crypto_E2E_message_t* container) {
	assert(container != NULL);
	sll_init(np_crypto_encrypted_intermediate_key_ptr, container->encrypted_intermediate_keys);
	_np_crypt_transport_init_parts(&container->t);
}

np_crypto_E2E_message_t * np_crypt_E2E_init(
	np_crypto_E2E_message_t * buffer,
	np_crypto_t* sender,
	void* data_to_encrypt,
	size_t data_size
) {
	assert(buffer != NULL);
	assert(sender != NULL);
	assert(data_to_encrypt != NULL);
	np_crypto_E2E_message_t * ret = NULL;
	if (sender->derived_kx_secret_key_is_set) {
		ret = buffer;
		if (ret == NULL) {
			ret = calloc(1, sizeof(np_crypto_E2E_message_t));
		}
		_np_crypt_E2E_init_parts(ret);
		crypto_secretbox_keygen(ret->_intermediate_key);
		memcpy(ret->_sender_secret_key, sender->derived_kx_secret_key, sizeof ret->_sender_secret_key);

		if (0 != __np_crypt_encrypt(&ret->t, ret->_intermediate_key, data_to_encrypt, data_size)) {			
			np_crypto_E2E_message_t_free(ret);
			if (buffer == NULL) free(ret);
			ret = NULL;
		}
	}
	return ret;
}
void np_crypto_E2E_message_t_free(np_crypto_E2E_message_t* container) {
	assert(container != NULL);
	// free intermediate keys from container
	sll_iterator(np_crypto_encrypted_intermediate_key_ptr)  keys = sll_first(
		container->encrypted_intermediate_keys
	);
	while (keys != NULL) {
		if (keys->val->freeable) free(keys->val);
		sll_next(keys);
	}
	sll_free(np_crypto_encrypted_intermediate_key_ptr, container->encrypted_intermediate_keys);
	np_crypto_transport_message_t_free(&container->t);
}

void np_crypt_E2E_serialize(np_crypto_E2E_message_t* container, np_tree_t* out_buffer) {
	assert(container != NULL);
	assert(out_buffer != NULL);
	np_crypt_transport_serialize(&container->t, out_buffer);
	assert(sll_size(container->encrypted_intermediate_keys) > 0);
	np_tree_t* intermediate_keys = np_tree_create();
	sll_iterator(np_crypto_encrypted_intermediate_key_ptr) keys = sll_first(container->encrypted_intermediate_keys);
	while (keys != NULL)
	{
		np_tree_insert_dhkey(
			intermediate_keys,
			keys->val->target,
			np_treeval_new_bin(keys->val->data, sizeof keys->val->data)
		);
		sll_next(keys);
	}
	np_tree_insert_str(out_buffer, NP_SYMKEY, np_treeval_new_tree(intermediate_keys));
	np_tree_free(intermediate_keys);
}
int np_crypt_E2E_deserialize(np_crypto_E2E_message_t* container, np_tree_t* buffer) {
	assert(container != NULL);
	assert(buffer != NULL);
	int ret = 0;
	
	if (0 == (ret = 100 * np_crypt_transport_deserialize(&container->t, buffer))) {
		np_tree_elem_t* symkeys = np_tree_find_str(buffer, NP_SYMKEY);
		if (symkeys != NULL) {
			np_tree_elem_t* iter = RB_MIN(np_tree_s, symkeys->val.value.tree);
			while (iter != NULL) {
				np_crypto_encrypted_intermediate_key_t* key = calloc(1, sizeof(np_crypto_encrypted_intermediate_key_t));
				key->freeable = true;
				key->target = iter->key.value.dhkey;
				memcpy(key->data, iter->val.value.bin, sizeof key->data);
				sll_append(np_crypto_encrypted_intermediate_key_ptr, container->encrypted_intermediate_keys, key);
				iter = RB_NEXT(np_tree_s, symkeys->val.value.tree, iter);
			}
		}
	}
	return ret;
}

int np_crypt_E2E_encrypt(np_crypto_E2E_message_t* container, np_crypto_t* receiver_crypto, np_dhkey_t receiver, np_crypto_encrypted_intermediate_key_t* buffer) {
	assert(container != NULL);
	assert(receiver_crypto != NULL);
	assert(buffer != NULL);
	buffer->target = receiver;
	int ret = -2;
	if (receiver_crypto->derived_kx_public_key_is_set) {
		ret = crypto_box_easy(
			buffer->data,
			container->_intermediate_key,
			sizeof container->_intermediate_key,
			container->t.nonce,
			receiver_crypto->derived_kx_public_key,
			container->_sender_secret_key
		);
		sll_append(np_crypto_encrypted_intermediate_key_ptr, container->encrypted_intermediate_keys, buffer);
	}
	return ret; 
}

int8_t __np_crypt_E2E_sll_cmp_target(np_crypto_encrypted_intermediate_key_ptr const a, np_crypto_encrypted_intermediate_key_ptr const b) {	
	return _np_dhkey_cmp(&a->target, &b->target);
}
// buffer needs to be at least the same size as data_to_decrypt
int np_crypt_E2E_decrypt(np_state_t* context, np_crypto_t* self, np_dhkey_t local, np_crypto_t* remote, void* decrypted_data_buffer, void* data_to_decrypt) {
	assert(context != NULL);
	assert(self != NULL);
	assert(remote != NULL);
	assert(decrypted_data_buffer != NULL);
	assert(data_to_decrypt != NULL);
	int ret = -2;

	if (remote->derived_kx_public_key_is_set && self->derived_kx_secret_key_is_set) {
		ret = -3;
		// 1. deserialize
		// 2. decrypt matching intermediate key
		// 3. decrypt data content with intermediate key

		// 1. deserialize
		np_tree_t* tmp_E2E_container = np_tree_create();
		cmp_ctx_t cmp;
		cmp_init(&cmp, data_to_decrypt, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
		if (np_tree_deserialize(context, tmp_E2E_container, &cmp)) {

			ret = -4;
			np_crypto_E2E_message_t container;
			_np_crypt_E2E_init_parts(&container);

			if (0 == (ret = 10 * np_crypt_E2E_deserialize(&container, tmp_E2E_container))) {
				ret = -5;
				// 2. decrypt matching intermediate key
				np_crypto_encrypted_intermediate_key_t search = { .target = local };
				np_crypto_encrypted_intermediate_key_t* intermediate_key = sll_find(
					np_crypto_encrypted_intermediate_key_ptr,
					container.encrypted_intermediate_keys,
					&search,
					__np_crypt_E2E_sll_cmp_target,
					NULL
				);

				if (intermediate_key != NULL) {
					ret = -6;
					unsigned char decyrypted_intermediate_key[crypto_secretbox_KEYBYTES];
					if (0 == crypto_box_open_easy(
						decyrypted_intermediate_key,
						intermediate_key->data,
						sizeof intermediate_key->data,
						container.t.nonce,
						remote->derived_kx_public_key,
						self->derived_kx_secret_key)
						) {						
						// 3. decrypt data content with intermediate key
						ret = 1000 * __np_crypt_decrypt(&container.t, decyrypted_intermediate_key, decrypted_data_buffer);
					}
				}

				np_crypto_E2E_message_t_free(&container);
			}
		}
		np_tree_free(tmp_E2E_container);
	}
	return ret;
}

void np_crypt_export(np_crypto_t* self, struct np_token *dest) {
	assert(self != NULL);
	assert(dest != NULL);
	assert(sizeof(dest->public_key) == sizeof(self->ed25519_public_key));
	memcpy(dest->public_key, self->ed25519_public_key, sizeof(self->ed25519_public_key));
	assert(sizeof(dest->secret_key) == sizeof(self->ed25519_secret_key));
	memcpy(dest->secret_key, self->ed25519_secret_key, sizeof(self->ed25519_secret_key));
}

uint32_t np_crypt_rand() {
	uint32_t ret;
	randombytes_buf(&ret, sizeof ret);
	return ret;
}

uint32_t np_crypt_rand_mm(uint32_t min, uint32_t max) {
	assert(max >= min);
	uint32_t ret = randombytes_uniform(max - min);
	if (ret < min) ret = min;
	return ret;
}
