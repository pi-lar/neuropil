//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>

#include "event/ev.h"
#include "sodium.h"

#include "np_aaatoken.h"

#include "dtime.h"
#include "np_log.h"
#include "np_legacy.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_threads.h"
#include "np_settings.h"
#include "np_util.h"
#include "np_constants.h"
#include "neuropil.h"
#include "np_serialization.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_aaatoken_t);

NP_SLL_GENERATE_IMPLEMENTATION(np_aaatoken_ptr);

NP_PLL_GENERATE_IMPLEMENTATION(np_aaatoken_ptr);

void _np_aaatoken_t_new(np_state_t *context, uint8_t type, size_t size, void* token)
{
	log_trace_msg(LOG_TRACE | LOG_AAATOKEN, "start: void _np_aaatoken_t_new(void* token){");
	np_aaatoken_t* aaa_token = (np_aaatoken_t*) token;

	aaa_token->version = 0.60;

	// aaa_token->issuer;
	memset(aaa_token->realm,    0, 255);
	memset(aaa_token->issuer,   0,  65);
	memset(aaa_token->subject,  0, 255);
	memset(aaa_token->audience, 0, 255);

	aaa_token->private_key_is_set = false;

	memset(aaa_token->public_key, 0, crypto_sign_PUBLICKEYBYTES*(sizeof(unsigned char)));

	memset(aaa_token->signature, 0, crypto_sign_BYTES*(sizeof(unsigned char)));
	aaa_token->is_signature_verified = false;

	char* uuid = aaa_token->uuid;
	np_uuid_create("generic_aaatoken", 0, &uuid);

	aaa_token->issued_at = np_time_now();
	aaa_token->not_before = aaa_token->issued_at;

	int expire_sec =  ((int)randombytes_uniform(20)+10);

	aaa_token->expires_at = aaa_token->not_before + expire_sec;
	log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "aaatoken expires in %d sec", expire_sec);

	aaa_token->extensions = np_tree_create();
	aaa_token->state |= AAA_INVALID;
	aaa_token->extensions_local = aaa_token->extensions;

	aaa_token->type = np_aaatoken_type_undefined;
	aaa_token->scope = np_aaatoken_scope_undefined;
	aaa_token->issuer_token = aaa_token;
	_np_aaatoken_trace_info("new", aaa_token);
}

void _np_aaatoken_t_del (np_state_t *context, uint8_t type, size_t size, void* token)
{
	np_aaatoken_t* aaa_token = (np_aaatoken_t*) token;
	// clean up extensions
	if (aaa_token->extensions != aaa_token->extensions_local) {
		np_tree_free(aaa_token->extensions_local);
	}
	np_tree_free(aaa_token->extensions);
}

void _np_aaatoken_upgrade_handshake_token(np_key_t* key_with_core_token, np_node_public_token_t* full_token)
{
	np_state_t *context = np_ctx_by_memory(key_with_core_token);
	ASSERT(FLAG_CMP(full_token->type ,np_aaatoken_type_node), "full_token needs to be a public node token");

	np_tryref_obj(np_aaatoken_t, key_with_core_token->aaa_token, core_token_available, core_token);
	if (!core_token_available || FLAG_CMP(core_token->type, np_aaatoken_type_handshake)) {
		np_ref_switch(np_aaatoken_t, key_with_core_token->aaa_token, ref_key_aaa_token, full_token);
	}
	else {
		log_debug_msg(LOG_ERROR, "trying to upgrade non handshake token on %s ",_np_key_as_str(key_with_core_token));
	}

	if(core_token_available) np_unref_obj(np_aaatoken_t, core_token, FUNC);
}

void _np_aaatoken_encode(np_tree_t* data, np_aaatoken_t* token, bool trace)
{
	log_trace_msg(LOG_TRACE | LOG_AAATOKEN, "start: void np_aaatoken_encode(np_tree_t* data, np_aaatoken_t* token){");

	if(trace) _np_aaatoken_trace_info("encode", token);
	// included into np_token_handshake
	np_tree_replace_str( data, "np.t.u", np_treeval_new_s(token->uuid));
	np_tree_replace_str( data, "np.t.r", np_treeval_new_s(token->realm));
	np_tree_replace_str( data, "np.t.i", np_treeval_new_s(token->issuer));
	np_tree_replace_str( data, "np.t.s", np_treeval_new_s(token->subject));
	np_tree_replace_str( data, "np.t.a", np_treeval_new_s(token->audience));
	np_tree_replace_str( data, "np.t.p", np_treeval_new_bin(token->public_key, crypto_sign_PUBLICKEYBYTES));

	np_tree_replace_str( data, "np.t.ex", np_treeval_new_d(token->expires_at));
	np_tree_replace_str( data, "np.t.ia", np_treeval_new_d(token->issued_at));
	np_tree_replace_str( data, "np.t.nb", np_treeval_new_d(token->not_before));
	np_tree_replace_str( data, "np.t.si", np_treeval_new_bin(token->signature, crypto_sign_BYTES));

	np_tree_replace_str( data, "np.t.e", np_treeval_new_tree(token->extensions));

	if(token->scope <= np_aaatoken_scope_private_available) {
		_np_aaatoken_update_extensions_signature(token, token->issuer_token);
	}

	np_tree_replace_str( data, "np.t.signature_extensions", np_treeval_new_bin(token->signature_extensions, crypto_sign_BYTES));
}

void np_aaatoken_encode(np_tree_t* data, np_aaatoken_t* token)
{
	_np_aaatoken_encode(data, token, true);
}
void np_aaatoken_encode_with_secrets(np_tree_t* data, np_aaatoken_t* token) {
	np_aaatoken_encode(data, token);

	np_tree_replace_str( data, "np.t.private_key_is_set", np_treeval_new_ush(token->private_key_is_set));
	if(token->private_key_is_set){
		np_tree_replace_str( data, "np.t.private_key", np_treeval_new_bin(&token->private_key, crypto_sign_SECRETKEYBYTES));
	}
}

void np_aaatoken_decode_with_secrets(np_tree_t* data, np_aaatoken_t* token) {
	np_aaatoken_decode(data, token);

	np_tree_elem_t* private_key_is_set = np_tree_find_str(data, "np.t.private_key_is_set");
	np_tree_elem_t* private_key = np_tree_find_str(data, "np.t.private_key");

	if (NULL != private_key_is_set && NULL != private_key )
	{
		token->private_key_is_set = private_key_is_set->val.value.ush;
		memcpy(&token->private_key, private_key->val.value.bin, crypto_sign_SECRETKEYBYTES);
		token->scope = np_aaatoken_scope_private;

		np_tree_del_str(data, "np.t.private_key_is_set");
		np_tree_del_str(data, "np.t.private_key");
	}
}
/*
	@return: true if all medatory filds are present
*/
bool np_aaatoken_decode(np_tree_t* data, np_aaatoken_t* token)
{
	np_ctx_memory(token);
	assert (NULL != data);
	assert (NULL != token);
	bool ret = true;

	// get e2e encryption details of sending entity

	np_tree_elem_t* tmp;
	token->scope = np_aaatoken_scope_undefined;
	token->type = np_aaatoken_type_undefined;

	if (ret && NULL !=(tmp = np_tree_find_str(data, "np.t.u")))
	{		 
		strncpy(token->uuid, np_treeval_to_str(tmp->val, NULL), NP_UUID_BYTES);
	}
	else { ret = false;/*Mendatory field*/ }
	
	if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.r")))
	{
		strncpy(token->realm,  np_treeval_to_str(tmp->val, NULL), 255);
	}
	if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.i")))
	{
		strncpy(token->issuer,  np_treeval_to_str(tmp->val, NULL), 64);
	}
	else { ret = false;/*Mendatory field*/ }
	if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.s")))
	{
		strncpy(token->subject,  np_treeval_to_str(tmp->val, NULL), 255);
	}
	else { ret = false;/*Mendatory field*/ }
	if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.a")))
	{
		strncpy(token->audience,  np_treeval_to_str(tmp->val, NULL), 255);
	}
	if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.p")))
	{
		memcpy(token->public_key, tmp->val.value.bin, crypto_sign_PUBLICKEYBYTES);
	}
	else { ret = false;/*Mendatory field*/ }

	if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.ex")))
	{
		token->expires_at = tmp->val.value.d;
	}
	else { ret = false;/*Mendatory field*/ }
	if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.ia")))
	{
		token->issued_at = tmp->val.value.d;
	}
	if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.nb")))
	{
		token->not_before = tmp->val.value.d;
	}

	if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.si")))
	{
		memcpy(token->signature, tmp->val.value.bin, crypto_sign_BYTES);
		token->is_signature_verified = false;
	}
	else { ret = false;/*Mendatory field*/ }

	// decode extensions
	if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.e")))
	{
		ASSERT(tmp->val.type == np_treeval_type_jrb_tree, 
			"token (%s) type is %"PRIu32" instead of np_treeval_type_jrb_tree(%"PRIu32")",
			token->uuid, tmp->val.type, np_treeval_type_jrb_tree
		);

		if (token->extensions == token->extensions_local) {
			token->extensions_local = np_tree_clone( tmp->val.value.tree);
			token->extensions_local->attr.immutable = false;
		}
		else {
			np_tree_copy(tmp->val.value.tree, token->extensions_local);
		}
		np_tree_clear( token->extensions);
		np_tree_copy( tmp->val.value.tree, token->extensions);


		if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.signature_extensions")))
		{
			memcpy(token->signature_extensions, tmp->val.value.bin, fmin(tmp->val.size, crypto_sign_BYTES));
			token->is_signature_extensions_verified = false;
		}
		else { ret = false;/*Mendatory field if extensions provided*/ }
	}

	_np_aaatoken_update_type_and_scope(token);

	return ret;
}

void _np_aaatoken_update_type_and_scope(np_aaatoken_t* self) {

	if(self->private_key_is_set){
		self->scope = np_aaatoken_scope_private;
	} else {
		self->scope = np_aaatoken_scope_public;
	}
	self->type = np_aaatoken_type_undefined;

	if (strncmp( _NP_URN_IDENTITY_PREFIX, self->subject, strlen( _NP_URN_IDENTITY_PREFIX)) == 0) {
		self->type |= np_aaatoken_type_identity;
	}
	else if (strncmp( _NP_URN_NODE_PREFIX, self->subject, strlen( _NP_URN_NODE_PREFIX)) == 0) {
		if (np_tree_find_str(self->extensions, _NP_MSG_EXTENSIONS_SESSION) == NULL) {
			self->type |= np_aaatoken_type_node;
		}
		else {
			self->type |= np_aaatoken_type_handshake;
		}
	}
	else //if (strncmp( _NP_URN_MSG_PREFIX, self->subject, strlen( _NP_URN_MSG_PREFIX)) == 0)
	{
		self->type |= np_aaatoken_type_message_intent;
	}

//	if (strncmp("", self->issuer, 1) == 0) {
//		self->type |= np_aaatoken_type_identity;
//	}
}

np_dhkey_t np_aaatoken_get_fingerprint(np_aaatoken_t* self)
{
	np_ctx_memory(self);
	np_dhkey_t ret;

	// if (FLAG_CMP(self->type, np_aaatoken_type_handshake)) {
	// 	np_str2id( self->issuer, &ret);
	// }else{

		// build a hash to find a place in the dhkey table, not for signing !
		unsigned char* hash_attributes = _np_aaatoken_get_hash(self);
		ASSERT(hash_attributes != NULL, "cannot sign NULL hash");

		unsigned char hash[crypto_generichash_BYTES] = { 0 };
		crypto_generichash_state gh_state;
		crypto_generichash_init(&gh_state, NULL, 0, crypto_generichash_BYTES);
		crypto_generichash_update(&gh_state, hash_attributes, crypto_generichash_BYTES);
		crypto_generichash_update(&gh_state, self->signature, crypto_sign_BYTES);
		crypto_generichash_final(&gh_state, hash, crypto_generichash_BYTES);

		char key[crypto_generichash_BYTES * 2 + 1];
		sodium_bin2hex(key, crypto_generichash_BYTES * 2 + 1, hash, crypto_generichash_BYTES);
		ret = np_dhkey_create_from_hash(key);

		free(hash_attributes);
	// }
	return ret;
}

bool _np_aaatoken_is_valid(np_aaatoken_t* token, enum np_aaatoken_type expected_type)
{
	log_trace_msg(LOG_TRACE | LOG_AAATOKEN, "start: bool _np_aaatoken_is_valid(np_aaatoken_t* token){");
	if (NULL == token) return false;
	np_state_t* context = np_ctx_by_memory(token);

	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "checking token (%s) validity for token of type %"PRIu32" and scope %"PRIu32, token->uuid, token->type, token->scope);


	if (FLAG_CMP(token->type, expected_type) == false)
	{
		log_msg(LOG_AAATOKEN | LOG_WARN, "token (%s) for subject \"%s\": is not from correct type (%"PRIu32" != (expected:=)%"PRIu32"). verification failed",
			token->uuid, token->subject, token->type, expected_type);
#ifdef DEBUG
		ASSERT(false, "token (%s) for subject \"%s\": is not from correct type (%"PRIu32" != (expected:=)%"PRIu32"). verification failed",
			token->uuid, token->subject, token->type, expected_type);
#endif // DEBUG

		token->state &= AAA_INVALID;
		log_trace_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
		return (false);
	}
	else {
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token has expected type");
	}


	// check timestamp
	double now = np_time_now();
	if (now > (token->expires_at))
	{
		log_msg(LOG_AAATOKEN | LOG_WARN, "token (%s) for subject \"%s\": expired (%f). verification failed", token->uuid, token->subject, token->expires_at - now);
		token->state &= AAA_INVALID;
		log_trace_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
		return (false);
	}
	else {
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token has not expired");
	}

	if (token->scope > np_aaatoken_scope_private_available)
	{
		if (token->is_signature_verified == false) {
			unsigned char* hash = _np_aaatoken_get_hash(token);

			// verify inserted signature first
			unsigned char* signature = token->signature;

			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "try to check signature checksum");
			int ret = crypto_sign_verify_detached((unsigned char*)signature, hash, crypto_generichash_BYTES, token->public_key);

#ifdef DEBUG
			if (ret != 0)// || (FLAG_CMP(token->type, np_aaatoken_type_message_intent) && ( strcmp(token->subject[strlen("urn:np:msg:")], "_NP.SYSINFO.REPLY") == 0 || strcmp(token->subject[strlen("urn:np:msg:")], "_NP.SYSINFO.REQUEST") == 0 )))
			{				
				char signature_hex[crypto_sign_BYTES * 2 + 1] = { 0 };
				sodium_bin2hex(signature_hex, crypto_sign_BYTES * 2 + 1,
					signature, crypto_sign_BYTES);
				
				char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1] = { 0 };
				sodium_bin2hex(pk_hex, crypto_sign_PUBLICKEYBYTES * 2 + 1,
					token->public_key, crypto_sign_PUBLICKEYBYTES);

				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "(token: %p) signature: is_valid (pk: %s) %s = %"PRId32, token, pk_hex, signature_hex, ret);				
			}
#endif

			free(hash);
			if (ret < 0)
			{
				log_msg(LOG_AAATOKEN | LOG_WARN, "token (%s) for subject \"%s\": checksum verification failed", token->uuid, token->subject);
				log_trace_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
				token->state &= AAA_INVALID;
				return (false);
			}
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token (%s) for subject \"%s\": checksum verification success", token->uuid, token->subject);
			token->is_signature_verified = true;
		}

		if (token->is_signature_extensions_verified == false) {
			unsigned char* hash = __np_aaatoken_get_extensions_hash(token);

			// verify inserted signature first
			unsigned char* signature = token->signature_extensions;

			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "try to check extension signature checksum");
			int ret = crypto_sign_verify_detached((unsigned char*)signature, hash, crypto_generichash_BYTES, token->public_key);

#ifdef DEBUG
			if (ret != 0)
			{
				char hash_hex[crypto_generichash_BYTES * 2 + 1] = { 0 };
				sodium_bin2hex(hash_hex, crypto_generichash_BYTES * 2 + 1, 
					hash, crypto_generichash_BYTES);

				char signature_hex[crypto_sign_BYTES * 2 + 1] = { 0 };
				sodium_bin2hex(signature_hex, crypto_sign_BYTES * 2 + 1,
					signature, crypto_sign_BYTES);

				char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1] = { 0 };
				sodium_bin2hex(pk_hex, crypto_sign_PUBLICKEYBYTES * 2 + 1,
					token->public_key, crypto_sign_PUBLICKEYBYTES);

				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "(token: %s) extension signature: is_valid (hash: %s) (pk: %s) %s = %"PRId32, token->uuid, hash_hex, pk_hex, signature_hex, ret);
			}
#endif
			free(hash);
			if (ret < 0)
			{
				log_msg(LOG_AAATOKEN | LOG_WARN, "token (%s) for subject \"%s\": extension signature checksum verification failed", token->uuid, token->subject);
				log_trace_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
				token->state &= AAA_INVALID;
				
				return (false);
			}
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token (%s) for subject \"%s\": extension signature checksum verification success", token->uuid, token->subject);
			token->is_signature_extensions_verified = true;
		}
	}
	/*
		If we received a full token we may already got a handshake token,
		if so we need to validate the new tokens signature against the already received token sig
		and an successfully verifying the new tokens identity is the same as the handshaketokens
	*/
	if (FLAG_CMP(token ->type, np_aaatoken_type_node)) {

		// check for already received handshaketoken
		np_dhkey_t handshake_token_dhkey = np_aaatoken_get_fingerprint(token);

		np_key_t* handshake_token_key = _np_keycache_find(context, handshake_token_dhkey);
		if (handshake_token_key != NULL && handshake_token_key->aaa_token != NULL && handshake_token_key->aaa_token != token /*reference compare!*/ &&
			FLAG_CMP(handshake_token_key->aaa_token->type, np_aaatoken_type_handshake) /*&& _np_aaatoken_is_valid(handshake_token_key ->aaa_token)*/) {

			//FIXME: Change to signature check with other tokens pub key
			if (memcmp(handshake_token_key->aaa_token->public_key, token->public_key, crypto_sign_PUBLICKEYBYTES *(sizeof(unsigned char))) != 0) {

				np_unref_obj(np_key_t, handshake_token_key, "_np_keycache_find");
				log_msg(LOG_WARN, "Someone tried to impersonate a token (%s). verification failed", token->uuid);
				return (false);
			}

		}
		np_unref_obj(np_key_t, handshake_token_key, "_np_keycache_find");
	}

	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token checksum verification completed");

	// TODO: only if this is a message token
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "try to find max/msg threshold ");
	np_tree_elem_t* max_threshold = np_tree_find_str(token->extensions_local, "max_threshold");
	np_tree_elem_t* msg_threshold = np_tree_find_str(token->extensions_local, "msg_threshold");
	if ( max_threshold && msg_threshold)
	{
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "found max/msg threshold");
		uint16_t token_max_threshold = max_threshold->val.value.ui;
		uint16_t token_msg_threshold = msg_threshold->val.value.ui;

		if (0                   <= token_msg_threshold &&
			token_msg_threshold <= token_max_threshold)
		{
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token for subject \"%s\": %s can be used for %d msgs", token->subject, token->issuer, token_max_threshold-token_msg_threshold);
		}
		else
		{
			log_msg(LOG_AAATOKEN | LOG_WARN, "verification failed. token (%s) for subject \"%s\": %s was already used, 0<=%"PRIu16"<%"PRIu16, token->uuid, token->subject, token->issuer, token_msg_threshold, token_max_threshold);
			log_trace_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
			token->state &= AAA_INVALID;
			return (false);
		}
	}
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token (%s) validity for subject \"%s\": verification valid", token->uuid, token->subject);
	token->state |= AAA_VALID;
	return (true);
}

static int8_t _np_aaatoken_cmp (np_aaatoken_ptr first, np_aaatoken_ptr second)
{
	int8_t ret_check = 0;

	if (first == second) return (0);

	if (first == NULL || second == NULL ) return (-1);

	ret_check = strncmp(first->issuer, second->issuer, strnlen(first->issuer,64));
	if (0 != ret_check )
	{
		return (ret_check);
	}

	ret_check = strncmp(first->subject, second->subject, (strnlen(first->subject,255)));
	if (0 != ret_check )
	{
		return (ret_check);
	}

	ret_check = strncmp(first->realm, second->realm, strlen(first->realm));
	if (0 != ret_check )
	{
		return (ret_check);
	}

	return (0);
}

static int8_t _np_aaatoken_cmp_exact (np_aaatoken_ptr first, np_aaatoken_ptr second)
{
	int8_t ret_check = 0;

	if (first == second) return (0);

	if (first == NULL || second == NULL ) return (-1);

	ret_check = sodium_memcmp(first->public_key, second->public_key, crypto_sign_PUBLICKEYBYTES);
	if (0 != ret_check )
	{
		return (ret_check);
	}

	ret_check = strncmp(first->uuid, second->uuid, NP_UUID_BYTES);
	if (0 != ret_check )
	{
		return (ret_check);
	}

	return _np_aaatoken_cmp(first,second);
}

void _np_aaatoken_create_ledger(np_key_t* subject_key, const char* const subject)
{
	assert(NULL != subject_key);
	np_state_t* context = np_ctx_by_memory(subject_key);

	np_msgproperty_t* prop = NULL;
	bool create_new_prop = false;
	
	_LOCK_MODULE(np_aaatoken_t)
	{

		if (NULL == subject_key->recv_tokens)
			pll_init(np_aaatoken_ptr, subject_key->recv_tokens);

		if (NULL == subject_key->send_tokens)
			pll_init(np_aaatoken_ptr, subject_key->send_tokens);


		np_msgproperty_t* send_prop = np_msgproperty_get(context, OUTBOUND, subject);
		if (NULL != send_prop)
		{
			if(NULL == subject_key->send_property)
			{
				_np_key_set_send_property(subject_key, send_prop);
			}
		}
		else
		{
			create_new_prop |= true;
		}

		np_msgproperty_t* recv_prop = np_msgproperty_get(context, INBOUND, subject);
		if (NULL != recv_prop)
		{
			if(NULL == subject_key->recv_property)
			{
				_np_key_set_recv_property(subject_key, recv_prop);
			}
		}
		else
		{
			create_new_prop |= true;
		}

		if (true == create_new_prop && (NULL == subject_key->send_property || NULL == subject_key->recv_property))
		{
			log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "creating ledger property for %s", subject);

			if(send_prop != NULL) {
				prop = send_prop;
			} else {
				if(recv_prop != NULL) {
					prop = recv_prop;
				} else {
					np_new_obj(np_msgproperty_t, prop);
					prop->msg_subject = strndup(subject, 255);
					prop->mode_type |= OUTBOUND | INBOUND;
				}
			}

			if (NULL == subject_key->send_property) {
				_np_key_set_send_property(subject_key, prop);
			}
			if (NULL == subject_key->recv_property) {
				_np_key_set_recv_property(subject_key, prop);
			}
		}
	}
}

// update internal structure and return a interest if a matching pair has been found
np_aaatoken_t * _np_aaatoken_add_sender(char* subject, np_aaatoken_t *token)
{
	assert(token != NULL);
	np_state_t* context = np_ctx_by_memory(token);
	np_aaatoken_t * ret = NULL;
	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport( subject, "0");

	subject_key = _np_keycache_find_or_create(context, search_key);
	_np_aaatoken_create_ledger(subject_key, subject);

	// should never happen
	if (NULL == subject_key) return ret;

	log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "update on global sender msg token structures ... %p (size %d)",
							 subject_key->send_property,
							 pll_size(subject_key->send_tokens) );

	// insert new token
	_LOCK_ACCESS(&subject_key->send_property->lock)
	{
		// update #2 subject specific data
		subject_key->send_property->mep_type |= (np_tree_find_str(token->extensions, "mep_type")->val.value.ul & SENDER_MASK);
		subject_key->send_property->ack_mode = np_tree_find_str(token->extensions, "ack_mode")->val.value.ush;
		subject_key->send_property->last_update = np_time_now();

		uint16_t max_threshold = np_tree_find_str(token->extensions_local, "max_threshold")->val.value.ui;

		if (max_threshold > 0)
		{
			np_msg_mep_type sender_mep_type = subject_key->send_property->mep_type & SENDER_MASK;

			np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_add     = _np_aaatoken_cmp;
			np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_replace = _np_aaatoken_cmp_exact;
			bool allow_dups = true;

			if (SINGLE_SENDER == (SINGLE_SENDER & sender_mep_type))
			{
				cmp_aaatoken_replace   = _np_aaatoken_cmp;
				allow_dups = false;
			}

			// update #1 key specific data
			np_ref_obj(np_aaatoken_t, token,"send_tokens");
			ret = pll_replace(np_aaatoken_ptr, subject_key->send_tokens, token, cmp_aaatoken_replace);
			if (NULL == ret)
			{
				pll_insert(np_aaatoken_ptr, subject_key->send_tokens, token, allow_dups, cmp_aaatoken_add);
			}
			else
			{
				token->state = ret->state;
				np_ref_obj(np_aaatoken_t, ret, FUNC);
				np_unref_obj(np_aaatoken_t, ret,"send_tokens");
			}
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "added new single sender token for message hash %s",
					_np_key_as_str(subject_key) );
		}
	}

	// check for outdated token
	_LOCK_ACCESS(&subject_key->send_property->lock)
	{
		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->send_tokens);
		while (NULL != iter)
		{
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "checking sender msg tokens %p/%p", iter, iter->val);
			np_aaatoken_t* tmp_token = iter->val;
			pll_next(iter);

			if (NULL  != tmp_token &&
				false == _np_aaatoken_is_valid(tmp_token, np_aaatoken_type_message_intent))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "deleting old / invalid sender msg tokens %p", tmp_token);
				pll_remove(np_aaatoken_ptr, subject_key->send_tokens, tmp_token, _np_aaatoken_cmp_exact);
				np_unref_obj(np_aaatoken_t, tmp_token,"send_tokens");
				break;
			}
		}
		log_debug_msg(LOG_DEBUG, ".step3._np_aaatoken_add_sender %d", pll_size(subject_key->send_tokens));
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");

	return ret;
}

/** np_get_sender_token
 ** retrieve a list of valid sender tokens from the cache
 ** TODO extend this function with a key and an amount of messages
 ** TODO use a different function for mitm and leaf nodes ?
 **/
sll_return(np_aaatoken_ptr) _np_aaatoken_get_all_sender(np_state_t* context, const char* const subject, const char* const audience)
{
	np_sll_t(np_aaatoken_ptr, return_list) = NULL;
	sll_init(np_aaatoken_ptr, return_list);

	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport( subject, "0");

	subject_key = _np_keycache_find_or_create(context, search_key);
	// look up target structures or create them
	_np_aaatoken_create_ledger(subject_key, subject);

	// log_debug_msg(LOG_DEBUG, "available %hd interests %hd", subject_key->send_property->max_threshold, subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists

	// should never happen
	if (NULL == subject_key) return (return_list);

	pll_iterator(np_aaatoken_ptr) tmp = NULL;

	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
			"lookup in global sender msg token structures (%p)...",
			subject_key->send_property);

	_LOCK_ACCESS(&(subject_key->send_property->lock))
	{
		log_debug_msg(LOG_DEBUG, ".step1._np_aaatoken_get_all_sender %d / %s", pll_size(subject_key->send_tokens), subject);
		tmp = pll_first(subject_key->send_tokens);
		while (NULL != tmp)
		{
			if (false == _np_aaatoken_is_valid(tmp->val, np_aaatoken_type_message_intent))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid sender token for issuer %s", tmp->val->issuer);
			}
			else
			{
				bool include_token = true;
				if (audience != NULL && strlen(audience) > 0) {
					include_token =
							(strncmp(audience, tmp->val->issuer, strlen(tmp->val->issuer)) == 0) |
							(strncmp(audience, tmp->val->realm, strlen(tmp->val->realm)) == 0) ;
				}

				if (include_token==true) {
					log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "found valid sender token (%s)", tmp->val->issuer );
					// only pick key from a list if the subject msg_treshold is bigger than zero
					// and the sending threshold is bigger than zero as well
					// and we actually have a receiver node in the list
					np_ref_obj(np_aaatoken_t, tmp->val);
					sll_append(np_aaatoken_ptr, return_list, tmp->val);
				}
			}
			pll_next(tmp);
		}
		log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_get_all_sender %d", pll_size(subject_key->send_tokens));
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");

	return (return_list);
}

np_dhkey_t _np_aaatoken_get_issuer(np_aaatoken_t* self){
	np_dhkey_t ret =
		np_dhkey_create_from_hash(self->issuer);
	return ret;
}

np_aaatoken_t* _np_aaatoken_get_sender_token(np_state_t* context, const char* const subject, const np_dhkey_t* const sender_dhkey)
{
	log_trace_msg(LOG_TRACE | LOG_AAATOKEN, "start: np_aaatoken_t* _np_aaatoken_get_sender_token(char* subject, char* sender){");
	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport( subject, "0");

	subject_key = _np_keycache_find_or_create(context, search_key);
	// look up target structures or create them
	_np_aaatoken_create_ledger(subject_key, subject);

	// should never happen
	if (NULL == subject_key) return (NULL);

	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
			"lookup in global sender msg token structures (%p)...",
			subject_key->send_property);

//	log_debug_msg(LOG_DEBUG, "available %hd interests %hd",
//						subject_key->send_property->max_threshold,
//						subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists
	np_aaatoken_t* return_token = NULL;
	bool found_return_token = false;

	_LOCK_ACCESS(&subject_key->send_property->lock)
	{
#ifdef DEBUG
		char sender_dhkey_as_str[65];
		np_id2str((np_id*)sender_dhkey, sender_dhkey_as_str);
#endif

		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, ".step1._np_aaatoken_get_sender_token %d / %s", pll_size(subject_key->send_tokens), subject);
		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->send_tokens);
		while (NULL != iter &&
			   false == found_return_token)
		{
			return_token = iter->val;
			if (false == _np_aaatoken_is_valid(return_token, np_aaatoken_type_message_intent))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid sender token for issuer %s", return_token->issuer);
				return_token = NULL;
				pll_next(iter);
				continue;
			}

			np_dhkey_t return_token_dhkey = { 0 };
			np_tree_elem_t* target_node_elem = np_tree_find_str(return_token->extensions, "target_node");
			if (target_node_elem != NULL)
			{
				return_token_dhkey = np_dhkey_create_from_hash(target_node_elem->val.value.s);
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
							  "comparing sender token (%s) for %s with send_dhkey: %s (target node match)",
							  return_token->uuid, target_node_elem->val.value.s, sender_dhkey_as_str);
			}
			else
			{
				return_token_dhkey = np_dhkey_create_from_hash(return_token->issuer);
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
							  "comparing sender token (%s) for %s with send_dhkey: %s (issuer match)",
							  return_token->uuid, return_token->issuer, sender_dhkey_as_str);
			}

			// only pick key from a list if the subject msg_treshold is bigger than zero
			// and we actually have the correct sender node in the list
			if (false == _np_dhkey_equal(&return_token_dhkey, sender_dhkey))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
							  "ignoring sender token for issuer %s / send_hk: %s (issuer does not match)",
							  return_token->issuer, sender_dhkey_as_str);
				return_token = NULL;
				pll_next(iter);
				continue;
			}

			if (! (IS_AUTHENTICATED(return_token->state)) )
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
							  "ignoring sender token for issuer %s / send_hk: %s as it is not authenticated",
							  return_token->issuer, sender_dhkey_as_str);
				return_token = NULL;
				pll_next(iter);
				continue;
			}
			if (! (IS_AUTHORIZED(return_token->state)))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
							  "ignoring sender token for issuer %s / send_hk: %s as it is not authorized",
							  return_token->issuer, sender_dhkey_as_str);
				return_token = NULL;
				pll_next(iter);
				continue;
			}

			found_return_token = true;
			np_ref_obj(np_aaatoken_t, return_token);
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "found valid sender token (%s)", return_token->issuer);
		}
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, ".step2._np_aaatoken_get_sender_token %d", pll_size(subject_key->send_tokens));
	}

	np_unref_obj(np_key_t, subject_key, "_np_keycache_find_or_create");
	return (return_token);
}

// update internal structure and clean invalid tokens
np_aaatoken_t *_np_aaatoken_add_receiver(char* subject, np_aaatoken_t *token)
{
	assert(token != NULL);
	np_state_t* context = np_ctx_by_memory(token);

	np_aaatoken_t* ret = NULL;	

	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport( subject, "0");

	subject_key = _np_keycache_find_or_create(context, search_key);
	_np_aaatoken_create_ledger(subject_key, subject);

	// should never happen
	if (NULL == subject_key) return ret;

	log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "update on global receiving msg token structures ... %p (size %d)",
							 subject_key->recv_property,
							 pll_size(subject_key->recv_tokens) );

	// insert new token
	_LOCK_ACCESS(&subject_key->recv_property->lock)
	{
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, ".step1._np_aaatoken_add_receiver %d / %s", pll_size(subject_key->recv_tokens), subject);
		// update #2 subject specific data
//		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "receiver token %03x mask %03x",
//										  subject_key->recv_property->mep_type, (RECEIVER_MASK | FILTER_MASK) );

		subject_key->recv_property->mep_type |= (np_tree_find_str(token->extensions, "mep_type")->val.value.ul & RECEIVER_MASK);

//		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "receiver token %03x %03x",
//				                          subject_key->recv_property->mep_type, np_tree_find_str(token->extensions, "mep_type")->val.value.ul );

		// subject_key->recv_property->ack_mode = np_tree_find_str(token->extensions, "ack_mode")->val.value.ush;
		subject_key->recv_property->last_update = np_time_now();

		uint16_t max_threshold = np_tree_find_str(token->extensions_local, "max_threshold")->val.value.ui;

		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "adding receiver token %p threshold %d", token, max_threshold );

		if (max_threshold > 0)
		{	// only add if there are messages to receive
			np_msg_mep_type receiver_mep_type = (subject_key->recv_property->mep_type & RECEIVER_MASK);
			

			np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_add     = _np_aaatoken_cmp;
			np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_replace = _np_aaatoken_cmp_exact;
			bool allow_dups = true;

			if (SINGLE_RECEIVER == (SINGLE_RECEIVER & receiver_mep_type))
			{
				cmp_aaatoken_replace   = _np_aaatoken_cmp;
				allow_dups = false;
			}

			// update #1 key specific data
			np_ref_obj(np_aaatoken_t, token,"recv_tokens");
			ret = pll_replace(np_aaatoken_ptr, subject_key->recv_tokens, token, cmp_aaatoken_replace);
			if (NULL == ret)
			{
				pll_insert(np_aaatoken_ptr, subject_key->recv_tokens, token, allow_dups, cmp_aaatoken_add);
			}
			else
			{
				token->state = ret->state;
				np_ref_obj(np_aaatoken_t, ret, FUNC);
				np_unref_obj(np_aaatoken_t, ret,"recv_tokens");
			}
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "added new single sender token for message hash %s",
					_np_key_as_str(subject_key) );
		}
	}

	// check for outdated token
	_LOCK_ACCESS(&subject_key->recv_property->lock)
	{
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, ".step2._np_aaatoken_add_receiver %d", pll_size(subject_key->recv_tokens));

		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
		while (NULL != iter)
		{
			np_aaatoken_t* tmp_token = iter->val;
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "checking receiver msg tokens %p/%p", iter, iter->val);

			pll_next(iter);

			if (NULL  != tmp_token &&
				false == _np_aaatoken_is_valid(tmp_token, np_aaatoken_type_message_intent) )
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "deleting old / invalid receiver msg tokens %p", tmp_token);
				pll_remove(np_aaatoken_ptr, subject_key->recv_tokens, tmp_token, _np_aaatoken_cmp_exact);
				np_unref_obj(np_aaatoken_t, tmp_token,"recv_tokens");
				break;
			}
		}
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, ".step3._np_aaatoken_add_receiver %d", pll_size(subject_key->recv_tokens));
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	log_trace_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .np_add_receiver_token");

	return ret;
}

np_aaatoken_t* _np_aaatoken_get_receiver(np_state_t* context, const char* const subject, np_dhkey_t* target)
{
	log_trace_msg(LOG_TRACE | LOG_AAATOKEN, "start: np_aaatoken_t* _np_aaatoken_get_receiver(char* subject, np_dhkey_t* target){");
	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport( subject, "0");

	subject_key = _np_keycache_find_or_create(context, search_key);
	_np_aaatoken_create_ledger(subject_key, subject);

	// should never happen
	if (NULL == subject_key) return (NULL);

	// log_debug_msg(LOG_DEBUG, "available %hd interests %hd",
	// subject_key->send_property->max_threshold, subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists
	np_aaatoken_t* return_token = NULL;
	bool found_return_token = false;

	_LOCK_ACCESS(&subject_key->recv_property->lock)
	{

#ifdef DEBUG
		if(NULL != target) {
			char targetnode_str[65];
			np_id2str((np_id*)target, targetnode_str);
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "searching token for %s ", targetnode_str);
		}
#endif

		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
		while (NULL != iter &&
			   false == found_return_token)
		{
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "checking receiver msg tokens %p/%p", iter, iter->val);
			return_token = iter->val;

			if (false == _np_aaatoken_is_valid(return_token, np_aaatoken_type_message_intent))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid receiver msg tokens %p", return_token );
				pll_next(iter);
				return_token = NULL;
				continue;
			}

			np_dhkey_t recvtoken_issuer_key = np_dhkey_create_from_hash(return_token->issuer);

			if (_np_dhkey_equal(&recvtoken_issuer_key, &context->my_node_key->dhkey))
			{
				// only use the token if it is not from ourself (in case of IN/OUTBOUND on same subject)
				pll_next(iter);
				return_token = NULL;
				continue;
			}
			
			if(NULL != target) {
				if (!_np_dhkey_equal(&recvtoken_issuer_key, target)) {
					log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring %s receiver token for others nodes", return_token->issuer);
					pll_next(iter);
					return_token = NULL;
					continue;
				}
			}
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
					"found valid receiver token (%s)", return_token->issuer );

			// only pick key from a list if the subject msg_treshold is bigger than zero
			// and the sending threshold is bigger than zero as well
			// and we actually have a receiver node in the list
			// sll_append(np_aaatoken_t, return_list, tmp);
			if (IS_AUTHORIZED(return_token->state) && IS_AUTHENTICATED(return_token->state))
			{
				found_return_token = true;
				np_ref_obj(np_aaatoken_t, return_token);
				break;
			}
		}
	}

	if(NULL == return_token ) {
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "found no valid receiver token" );
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	return (return_token);
}

sll_return(np_aaatoken_ptr) _np_aaatoken_get_all_receiver(np_state_t* context, const char* const subject, const char* const audience)
{
	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport( subject, "0");

	subject_key = _np_keycache_find_or_create(context, search_key);
	_np_aaatoken_create_ledger(subject_key, subject);

//	log_debug_msg(LOG_DEBUG, "available %hd interests %hd",
//			subject_key->send_property->max_threshold, subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists	
	sll_init_full(np_aaatoken_ptr, return_list);

	// should never happen
	if (NULL == subject_key) return (return_list);

	pll_iterator(np_aaatoken_ptr) tmp = NULL;

	_LOCK_ACCESS(&subject_key->recv_property->lock)
	{
		tmp = pll_first(subject_key->recv_tokens);
		while (NULL != tmp)
		{
			if (false == _np_aaatoken_is_valid(tmp->val, np_aaatoken_type_message_intent))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid receiver msg token" );
			}
			else
			{
				bool include_token = true;
				if (audience != NULL && strlen(audience) > 0) {
					include_token =
							(strncmp(audience, tmp->val->issuer, strlen(tmp->val->issuer)) == 0) |
							(strncmp(audience, tmp->val->realm, strlen(tmp->val->realm)) == 0) ;
				}

				if (include_token==true) {
					log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "found valid receiver token (%s)", tmp->val->issuer );
					np_ref_obj(np_aaatoken_t, tmp->val);
					// only pick key from a list if the subject msg_treshold is bigger than zero
					// and the sending threshold is bigger than zero as well
					// and we actually have a receiver node in the list
					sll_append(np_aaatoken_ptr, return_list, tmp->val);
				}
			}
			pll_next(tmp);
			// tmp = pll_head(np_aaatoken_ptr, subject_key->recv_tokens);
		}
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	return (return_list);
}

unsigned char* _np_aaatoken_get_hash(np_aaatoken_t* self) {

	assert(self != NULL);// "cannot get token hash of NULL
	np_ctx_memory(self);
	unsigned char* ret = calloc(1, crypto_generichash_BYTES);
	crypto_generichash_state gh_state;
	crypto_generichash_init(&gh_state, NULL, 0, crypto_generichash_BYTES);

	ASSERT(self->uuid != NULL, "cannot get token hash of uuid NULL");
	crypto_generichash_update(&gh_state, (unsigned char*)self->uuid, strnlen(self->uuid, NP_UUID_BYTES));
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting uuid      : %s", self->uuid);

	crypto_generichash_update(&gh_state, (unsigned char*)self->realm, strnlen(self->realm, 255));
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting realm     : %s", self->realm);

	crypto_generichash_update(&gh_state, (unsigned char*)self->issuer, strnlen(self->issuer, 65));
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting issuer    : %s", self->issuer);

	crypto_generichash_update(&gh_state, (unsigned char*)self->subject, strnlen(self->subject, 255));
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting subject   : %s", self->subject);

	crypto_generichash_update(&gh_state, (unsigned char*)self->audience, strnlen(self->audience, 255));
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting audience  : %s", self->audience);

	crypto_generichash_update(&gh_state, (unsigned char*)self->public_key, crypto_sign_PUBLICKEYBYTES);

#ifdef DEBUG
	char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
	sodium_bin2hex(pk_hex, crypto_sign_PUBLICKEYBYTES * 2 + 1,
		self->public_key, crypto_sign_PUBLICKEYBYTES);
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting public_key: %s", pk_hex);
#else
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting public_key: <...>");
#endif

	// if(FLAG_CMP(self->type, np_aaatoken_type_handshake) == false) {
	// TODO: expires_at in handshake?
	crypto_generichash_update(&gh_state, (unsigned char*)&(self->expires_at), sizeof(double));
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting expiration: %f", self->expires_at);
	crypto_generichash_update(&gh_state, (unsigned char*)&(self->issued_at), sizeof(double));
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting issued_at : %f", self->issued_at);
	crypto_generichash_update(&gh_state, (unsigned char*)&(self->not_before), sizeof(double));
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting not_before: %f", self->not_before);
	// }
	crypto_generichash_final(&gh_state, ret, crypto_generichash_BYTES);

#ifdef DEBUG
	char hash_str[crypto_generichash_BYTES * 2 + 1];
	sodium_bin2hex(hash_str, crypto_generichash_BYTES * 2 + 1, ret, crypto_generichash_BYTES);
	log_debug_msg(LOG_DEBUG| LOG_AAATOKEN, "token hash for %s is %s", self->uuid, hash_str);
#endif
	ASSERT(ret != NULL, "generated hash cannot be NULL");
	return ret;
}

int __np_aaatoken_generate_signature(np_state_t* context, unsigned char* hash, unsigned char* private_key, unsigned char* save_to) {

	unsigned long long signature_len = 0;

#ifdef DEBUG
	char hash_hex[crypto_generichash_BYTES * 2 + 1];
	sodium_bin2hex(hash_hex, crypto_generichash_BYTES * 2 + 1, hash,
		crypto_generichash_BYTES);
	log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "token hash key fingerprint: %s",
		hash_hex);
#endif

#ifdef DEBUG
	char sk_hex[crypto_sign_SECRETKEYBYTES * 2 + 1];
	sodium_bin2hex(sk_hex, crypto_sign_SECRETKEYBYTES * 2 + 1, private_key, crypto_sign_SECRETKEYBYTES);
	log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "token signature private key: %s", sk_hex);
#endif

	int ret = crypto_sign_detached(save_to, NULL,
				(const unsigned char*)hash, crypto_generichash_BYTES, private_key);

	ASSERT(ret == 0,  "checksum creation for token failed, using unsigned token");
	return ret;
}

np_aaatoken_t* _np_aaatoken_get_local_mx(np_state_t* context, const char* const subject)
{
	log_trace_msg(LOG_TRACE | LOG_AAATOKEN, "start: np_aaatoken_t* _np_aaatoken_get_local_mx(char* subject){");

	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport( subject, "0");

	subject_key = _np_keycache_find_or_create(context, search_key);
	// look up target structures or create them
	_np_aaatoken_create_ledger(subject_key, subject);

	// should never happen
	if (NULL == subject_key) return (NULL);

	if (NULL == subject_key->local_mx_tokens)
		pll_init(np_aaatoken_ptr, subject_key->local_mx_tokens);

	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
			"lookup in local mx token structures (%p)...",
			subject_key->local_mx_tokens);

	// look up sources to see whether a sender already exists
	np_aaatoken_t* return_token = NULL;
	bool found_return_token = false;

	_LOCK_ACCESS(&subject_key->send_property->lock)
	{
		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->local_mx_tokens);
		while (NULL != iter &&
			   false == found_return_token)
		{
			return_token = iter->val;
			if (false == _np_aaatoken_is_valid(return_token, np_aaatoken_type_message_intent))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid local mx token for subject %s", return_token->subject);
				pll_next(iter);
				return_token = NULL;
				continue;
			}
			found_return_token = true;
			np_ref_obj(np_aaatoken_t, return_token);
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "found valid local mx token (%s)", return_token->issuer);
		}
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	return (return_token);
}

// update internal structure and return a interest if a matching pair has been found
void _np_aaatoken_add_local_mx(char* subject, np_aaatoken_t *token)
{
	np_ctx_memory(token);
	assert(token != NULL);	

	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport( subject, "0");

	subject_key = _np_keycache_find_or_create(context, search_key);
	_np_aaatoken_create_ledger(subject_key, subject);

	// should never happen
	if (NULL == subject_key) return;

	if (NULL == subject_key->local_mx_tokens)
		pll_init(np_aaatoken_ptr, subject_key->local_mx_tokens);

	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
			"update in local mx token structures (%p)...",
			subject_key->local_mx_tokens);

	// insert new token
	_LOCK_ACCESS(&subject_key->send_property->lock)
	{
		np_aaatoken_t *tmp_token = NULL;

		// update #1 key specific data
		np_ref_obj(np_aaatoken_t, token,"local_mx_tokens");
		tmp_token = pll_replace(np_aaatoken_ptr, subject_key->local_mx_tokens, token, _np_aaatoken_cmp);
		if (NULL == tmp_token)
		{
			pll_insert(np_aaatoken_ptr, subject_key->local_mx_tokens, token, false, _np_aaatoken_cmp);
		}
		else
		{
			np_unref_obj(np_aaatoken_t, tmp_token,"local_mx_tokens");
		}
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "added new single mx token for message hash %s",
				_np_key_as_str(subject_key) );
	}

	// check for outdated token
	_LOCK_ACCESS(&subject_key->send_property->lock)
	{
		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->local_mx_tokens);
		while (NULL != iter)
		{
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "checking mx msg tokens %p/%p", iter, iter->val);
			np_aaatoken_t* tmp_token = iter->val;
			pll_next(iter);

			if (NULL  != tmp_token &&
				false == _np_aaatoken_is_valid(tmp_token, np_aaatoken_type_message_intent) )
			{
				log_msg(LOG_INFO, "deleting old / invalid mx msg token %p", tmp_token);
				pll_remove(np_aaatoken_ptr, subject_key->local_mx_tokens, tmp_token, _np_aaatoken_cmp_exact);
				np_unref_obj(np_aaatoken_t, tmp_token,"local_mx_tokens");
				break;
			}
		}
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	log_trace_msg(LOG_AAATOKEN | LOG_TRACE, ".end  ._np_add_local_mx_token");
}


void np_aaatoken_set_partner_fp(np_aaatoken_t*self, np_dhkey_t partner_fp) {
	assert(self != NULL);
	np_state_t* context = np_ctx_by_memory(self);

	np_tree_replace_str( self->extensions, "_np.partner_fp", np_treeval_new_dhkey(partner_fp));
}

np_dhkey_t np_aaatoken_get_partner_fp(np_aaatoken_t* self) {
	assert(self != NULL);
	np_state_t* context = np_ctx_by_memory(self);
	
	np_dhkey_t ret = { 0 };

	np_tree_elem_t* ele = np_tree_find_str(self->extensions, "_np.partner_fp");
	if (ele != NULL) {
		ret = ele->val.value.dhkey;
	}
	else {
		np_str2id( self->issuer, (np_id*)&ret);
	}

	return ret;
}

void _np_aaatoken_set_signature(np_aaatoken_t* self, np_aaatoken_t* signee) {
	assert(self != NULL);
	np_state_t* context = np_ctx_by_memory(self);

	// update public key and issuer fingerprint with data take from signee
	memcpy((char*)self->public_key, (char*)signee->public_key, crypto_sign_PUBLICKEYBYTES);

	if (self != signee) {
		// prevent fingerprint recursion
		char my_token_fp_s[65];
		np_dhkey_t my_token_fp = np_aaatoken_get_fingerprint(signee);
		np_id2str((np_id*)&my_token_fp, my_token_fp_s);
		strncpy(self->issuer, my_token_fp_s, 65);
		self->issuer_token = signee;
	}
	else {
		self->issuer_token = self;
	}

	// create the hash of the core token data
	unsigned char* hash = _np_aaatoken_get_hash(self);
	// sign the core token
	int ret = __np_aaatoken_generate_signature(context, hash, signee->private_key, self->signature);

	free(hash);

#ifdef DEBUG
	char sign_hex[crypto_sign_BYTES * 2 + 1];
	sodium_bin2hex(sign_hex, crypto_sign_BYTES * 2 + 1, self->signature, crypto_sign_BYTES);
	log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "signature hash for %s is %s", self->uuid, sign_hex);
#endif

	ASSERT(ret == 0, "Error in token signature creation");
}

void _np_aaatoken_update_extensions_signature(np_aaatoken_t* self, np_aaatoken_t* signee) {

	np_ctx_memory(self);
	ASSERT(signee != NULL, "Cannot sign extensions with empty signee");

	unsigned char* hash = __np_aaatoken_get_extensions_hash(self);
	int ret = __np_aaatoken_generate_signature(context, hash, signee->private_key, self->signature_extensions);
#ifdef DEBUG
	char sign_hex[crypto_sign_BYTES * 2 + 1];
	sodium_bin2hex(sign_hex, crypto_sign_BYTES * 2 + 1, self->signature_extensions, crypto_sign_BYTES);
	log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "extension signature hash for %s is %s", self->uuid, sign_hex);
#endif
	ASSERT(ret == 0, "Error in extended token signature creation");
	free(hash);
}

unsigned char* __np_aaatoken_get_extensions_hash(np_aaatoken_t* self) {
	assert(self != NULL);
	np_state_t* context = np_ctx_by_memory(self);

	unsigned char* ret = calloc(1, crypto_generichash_BYTES);

	crypto_generichash_state gh_state;
	crypto_generichash_init(&gh_state, NULL, 0, crypto_generichash_BYTES);

	unsigned char* hash = np_tree_get_hash(self->extensions);
	ASSERT(hash != NULL, "cannot sign NULL hash");

	crypto_generichash_update(&gh_state, hash, crypto_generichash_BYTES);
	crypto_generichash_update(&gh_state, self->signature, crypto_sign_BYTES);

	crypto_generichash_final(&gh_state, ret, crypto_generichash_BYTES);

	free(hash);

	return ret;
}

void np_aaatoken_ref_list(np_sll_t(np_aaatoken_ptr, sll_list), const char* reason, const char* reason_desc)
{
	np_state_t* context = NULL;

	sll_iterator(np_aaatoken_ptr) iter = sll_first(sll_list);
	while (NULL != iter)
	{
		if (context == NULL && iter->val != NULL) context = np_ctx_by_memory(iter->val);
		np_ref_obj(np_aaatoken_t, (iter->val), reason, reason_desc);
		sll_next(iter);
	}
}
 
void np_aaatoken_unref_list(np_sll_t(np_aaatoken_ptr, sll_list), const char* reason)
{	
	np_state_t* context = NULL;

	sll_iterator(np_aaatoken_ptr) iter = sll_first(sll_list);
	while (NULL != iter)
	{
		if (context == NULL && iter->val!=NULL) context = np_ctx_by_memory(iter->val);
		np_unref_obj(np_aaatoken_t, (iter->val), reason);
		sll_next(iter);
	}
}


#ifdef DEBUG
void _np_aaatoken_trace_info(char* desc, np_aaatoken_t* self) {
	assert(self != NULL);
	np_ctx_memory(self);


	char* info_str = NULL;
	info_str = np_str_concatAndFree(info_str, "AAATokenTrace_%s", desc);

	np_tree_t* data = np_tree_create();
	_np_aaatoken_encode(data, self, false);
	np_tree_elem_t* tmp = NULL;
	bool free_key, free_value;
	char *key, *value;
	
	info_str = np_str_concatAndFree(info_str, " ");
	RB_FOREACH(tmp, np_tree_s, (data))
	{
		key = np_treeval_to_str(tmp->key, &free_key);
		value = np_treeval_to_str(tmp->val, &free_value);
		info_str = np_str_concatAndFree(info_str, "%s:%s |", key, value);
		if (free_value) free(value);
		if (free_key) free(key);
	}	
	np_tree_free( data);
	info_str = np_str_concatAndFree(info_str, ": %s", info_str, self->uuid);

	log_msg(LOG_AAATOKEN | LOG_INFO, "%s", info_str);
	free(info_str);
}
#endif

struct np_token* np_aaatoken4user(struct np_token* dest, np_aaatoken_t* src) {

	assert(src != NULL);
	assert(dest!= NULL);
	np_ctx_memory(src);

	
	dest->expires_at = src->expires_at;
	dest->issued_at	 = src->issued_at;
	dest->not_before = src->not_before;

	strncpy(dest->uuid, src->uuid, NP_UUID_BYTES);

	//TODO: convert to np_id
	strncpy(dest->issuer, src->issuer, 65);
	strncpy(dest->realm, src->realm, 255);
	strncpy(dest->audience, src->audience, 255);
	strncpy(dest->subject, src->subject, 255);

	memcpy(dest->public_key, src->public_key, NP_PUBLIC_KEY_BYTES);
	memcpy(dest->secret_key, src->private_key, NP_SECRET_KEY_BYTES);
	
	// TODO: warning/error if NP_EXTENSION_BYTES < src->extensions->byte_size 
	cmp_ctx_t cmp;
	_np_obj_buffer_container_t buffer_container;
	buffer_container.buffer = dest->extensions;
	buffer_container.bufferCount = 0;
	buffer_container.bufferMaxCount = NP_EXTENSION_BYTES;
	buffer_container.obj = src;
	cmp_init(&cmp, &buffer_container, _np_buffer_container_reader, _np_buffer_container_skipper, _np_buffer_container_writer);
	np_tree_serialize(context, src->extensions, &cmp);
	dest->extension_length = src->extensions->byte_size;

	return dest;
}

np_aaatoken_t* np_user4aaatoken(np_aaatoken_t* dest, struct np_token* src) {
	assert(src != NULL);
	assert(dest != NULL);
	np_ctx_memory(dest);

	dest->expires_at = src->expires_at;
	dest->issued_at = src->issued_at;
	dest->not_before = src->not_before;

	strncpy(dest->uuid, src->uuid, NP_UUID_BYTES);

	//TODO: convert to np_id
	strncpy(dest->issuer, src->issuer, 65);
	strncpy(dest->realm, src->realm, 255);
	strncpy(dest->audience, src->audience, 255);
	strncpy(dest->subject, src->subject, 255);

	memcpy(dest->public_key, src->public_key, NP_PUBLIC_KEY_BYTES);	
	uint8_t null_secret_key[NP_SECRET_KEY_BYTES] = { 0 };
	if (memcmp(src->secret_key, null_secret_key, NP_SECRET_KEY_BYTES) != 0) {
		memcpy(dest->private_key, src->secret_key, NP_SECRET_KEY_BYTES);
		dest->private_key_is_set = true;
	}
	strncpy(dest->subject, src->subject, 255);

	cmp_ctx_t cmp;
	_np_obj_buffer_container_t buffer_container;
	buffer_container.buffer = src->extensions;
	buffer_container.bufferCount = 0;
	buffer_container.bufferMaxCount = NP_EXTENSION_BYTES;
	buffer_container.obj = dest;
	cmp_init(&cmp, &buffer_container, _np_buffer_container_reader, _np_buffer_container_skipper, _np_buffer_container_writer);
	np_tree_deserialize(context, dest->extensions, &cmp);

	return dest;
}