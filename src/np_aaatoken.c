//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "event/ev.h"
#include "sodium.h"

#include "np_aaatoken.h"

#include "dtime.h"
#include "np_log.h"
#include "neuropil.h"
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


_NP_GENERATE_MEMORY_IMPLEMENTATION(np_aaatoken_t);

NP_SLL_GENERATE_IMPLEMENTATION(np_aaatoken_ptr);

NP_PLL_GENERATE_IMPLEMENTATION(np_aaatoken_ptr);

void _np_aaatoken_t_new(void* token)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: void _np_aaatoken_t_new(void* token){");
	np_aaatoken_t* aaa_token = (np_aaatoken_t*) token;

	aaa_token->realm[0]      = '\0';

	// aaa_token->issuer;
	memset(aaa_token->issuer, '\0', 65);

	aaa_token->subject[0]    = '\0';
	aaa_token->audience[0]   = '\0';

	aaa_token->private_key_is_set = FALSE;

	aaa_token->public_key[0] = '\0';

	memset(aaa_token->signature, '\0', crypto_sign_BYTES*(sizeof(unsigned char)));	
	aaa_token->signed_hash = NULL;	
	aaa_token->is_signature_verified = FALSE;
	
	aaa_token->is_core_token = FALSE;

	aaa_token->uuid = np_uuid_create("generic_aaatoken", 0);

	aaa_token->issued_at = np_time_now();
	aaa_token->not_before = aaa_token->issued_at;

	int expire_sec =  ((int)randombytes_uniform(20)+10);

	aaa_token->expires_at = aaa_token->not_before + expire_sec;
	log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "aaatoken expires in %d sec", expire_sec);

	aaa_token->extensions = np_tree_create();
	aaa_token->state |= AAA_INVALID;
}

void _np_aaatoken_t_del (void* token)
{
	np_aaatoken_t* aaa_token = (np_aaatoken_t*) token;

	free(aaa_token->signed_hash);
	//aaa_token->signed_hash = NULL;

	// clean up extensions
	if (NULL != aaa_token->extensions)
	{
		np_tree_free(aaa_token->extensions);
	}
	if (NULL != aaa_token->uuid)
	{
		free(aaa_token->uuid);
	//	aaa_token->uuid= NULL;
	}
}

void _np_aaatoken_mark_as_core_token(np_aaatoken_t* token) {
	token->is_core_token = TRUE;
	// unsigned long long sig_len = 0;
	// set token->signature to signature of full token
	// if (token->private_key_is_set){
	//	_np_aaatoken_add_signature(token);
	// }
}

void _np_aaatoken_mark_as_full_token(np_aaatoken_t* token) {
	token->is_core_token = FALSE;
	// unsigned long long sig_len = 0;
	// set token->signature to signature of full token
	// if (token->private_key_is_set){
	//_np_aaatoken_add_signature(token);
	// }
}

np_bool _np_aaatoken_is_core_token(np_aaatoken_t* token) {	
	return token->is_core_token;
}

void _np_aaatoken_upgrade_core_token(np_key_t* key_with_core_token, np_aaatoken_t* full_token)
{
	if (NULL == key_with_core_token->aaa_token) {
		np_ref_obj(np_aaatoken_t, full_token, ref_key_aaa_token);
		key_with_core_token->aaa_token = full_token;
	}
	else if (_np_aaatoken_is_core_token(key_with_core_token->aaa_token))
	{
		log_debug_msg(LOG_AAATOKEN |LOG_DEBUG, "signature: upgrade token %p with data from %p", key_with_core_token->aaa_token,full_token);

		np_tree_t* container = np_tree_create();
		np_aaatoken_encode(container, full_token);
		np_tree_del_str(container, "np.t.p");
		np_tree_replace_str(container, "np.t.si", np_treeval_new_bin(key_with_core_token->aaa_token->signature, crypto_sign_BYTES));
		np_aaatoken_decode(container, key_with_core_token->aaa_token);
		np_tree_free(container);

		key_with_core_token->aaa_token->is_signature_verified = FALSE;
	}
}

void np_aaatoken_core_encode(np_tree_t* data, np_aaatoken_t* token, np_bool standalone)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: void np_aaatoken_encode(np_tree_t* data, np_aaatoken_t* token){");	
	if (standalone == TRUE) {
		if (!_np_aaatoken_is_core_token(token)) {
			_np_aaatoken_mark_as_core_token(token);
		}
	}
	np_tree_insert_str(data, "np.t.c", np_treeval_new_sh(_np_aaatoken_is_core_token(token)));
	np_tree_insert_str(data, "np.t.s", np_treeval_new_s(token->subject));
	np_tree_insert_str(data, "np.t.u", np_treeval_new_s(token->uuid));
	np_tree_insert_str(data, "np.t.i", np_treeval_new_s(token->issuer));
	np_tree_insert_str(data, "np.t.ex", np_treeval_new_d(token->expires_at));
	np_tree_insert_str(data, "np.t.p", np_treeval_new_bin(token->public_key, crypto_sign_PUBLICKEYBYTES));
	
	if (token->private_key_is_set == TRUE) {
		_np_aaatoken_add_signature(token);
	}
	np_tree_insert_str(data, "np.t.si", np_treeval_new_bin(token->signature, crypto_sign_BYTES));
}

void np_aaatoken_encode(np_tree_t* data, np_aaatoken_t* token)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: void np_aaatoken_encode(np_tree_t* data, np_aaatoken_t* token){");
	// add e2e encryption details for sender

	np_tree_insert_str(data, "np.t.ia", np_treeval_new_d(token->issued_at));
	np_tree_insert_str(data, "np.t.nb", np_treeval_new_d(token->not_before));

	np_tree_insert_str(data, "np.t.r", np_treeval_new_s(token->realm));
	np_tree_insert_str(data, "np.t.a", np_treeval_new_s(token->audience));
	np_tree_insert_str(data, "np.t.e", np_treeval_new_tree(token->extensions));

	np_aaatoken_core_encode(data, token, FALSE);
}

void np_aaatoken_decode(np_tree_t* data, np_aaatoken_t* token)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: void np_aaatoken_decode(np_tree_t* data, np_aaatoken_t* token){");
	assert (NULL != data);
	assert (NULL != token);
	// get e2e encryption details of sending entity

	np_tree_elem_t* tmp;	
	if (NULL != (tmp = np_tree_find_str(data, "np.t.c")))
	{
		if (TRUE == tmp->val.value.sh) {
			_np_aaatoken_mark_as_core_token(token);
		}
		else {
			_np_aaatoken_mark_as_full_token(token);
		}
	}
	if (NULL != (tmp = np_tree_find_str(data, "np.t.r")))
	{
		strncpy(token->realm,  np_treeval_to_str(tmp->val, NULL), 255);
	} 
	if (NULL != (tmp = np_tree_find_str(data, "np.t.s")))
	{
		strncpy(token->subject,  np_treeval_to_str(tmp->val, NULL), 255);
	}
	if (NULL != (tmp = np_tree_find_str(data, "np.t.i")))
	{
		strncpy(token->issuer,  np_treeval_to_str(tmp->val, NULL), 64);
	}
	if (NULL != (tmp = np_tree_find_str(data, "np.t.a")))
	{
		strncpy(token->audience,  np_treeval_to_str(tmp->val, NULL), 255);
	}
	if (NULL !=(tmp = np_tree_find_str(data, "np.t.u")))
	{
		free(token->uuid);
		token->uuid = strndup( np_treeval_to_str(tmp->val, NULL), UUID_SIZE);
	}
	if (NULL != (tmp = np_tree_find_str(data, "np.t.nb")))
	{
		token->not_before = tmp->val.value.d;
	}
	if (NULL != (tmp = np_tree_find_str(data, "np.t.ex")))
	{
		token->expires_at = tmp->val.value.d;
	}
	if (NULL != (tmp = np_tree_find_str(data, "np.t.ia")))
	{
		token->issued_at = tmp->val.value.d;
	}
	if (NULL != (tmp = np_tree_find_str(data, "np.t.p")))
	{
		memcpy(token->public_key, tmp->val.value.bin, min(tmp->val.size, crypto_sign_PUBLICKEYBYTES));
		
	}
	if (NULL != (tmp = np_tree_find_str(data, "np.t.si")))
	{
		memcpy(token->signature, tmp->val.value.bin, min(tmp->val.size, crypto_sign_BYTES));
	} 
	// decode extensions
	if (NULL != (tmp = np_tree_find_str(data, "np.t.e")))
	{		
		ASSERT(tmp->val.type == jrb_tree_type, "type is %"PRIu8" instead of jrb_tree_type(%"PRIu8")", tmp->val.type, jrb_tree_type);

		np_tree_clear(token->extensions);
		np_tree_copy(tmp->val.value.tree, token->extensions);
	}

//	log_debug_msg(LOG_DEBUG, "realm             : %s", token->realm);
//	log_debug_msg(LOG_DEBUG, "issuer            : %s", token->issuer);
//	log_debug_msg(LOG_DEBUG, "subject           : %s", token->subject);
//	log_debug_msg(LOG_DEBUG, "audience          : %s", token->audience);
//	log_debug_msg(LOG_DEBUG, "uuid              : %s", token->uuid);

//	struct timeval token_time;
//	struct tm token_ts;
//	char time_entry[27];
//	token_time.tv_sec = (long) token->issued_at;
//	token_time.tv_usec = (long) ((token->issued_at - (double) token_time.tv_sec) * 1000000.0);
//	localtime_r(&token_time.tv_sec, &token_ts);
//	strftime(time_entry,    19, "%Y-%m-%d %H:%M:%S", &token_ts);
//	snprintf(time_entry+19,  6, ".%6d", token_time.tv_usec);
//	log_debug_msg(LOG_DEBUG, "issued date       : %s", time_entry);
//
//	token_time.tv_sec = (long) token->expires_at;
//	token_time.tv_usec = (long) ((token->expires_at - (double) token_time.tv_sec) * 1000000.0);
//	localtime_r(&token_time.tv_sec, &token_ts);
//	strftime(time_entry, 19, "%Y-%m-%d %H:%M:%S", &token_ts);
//	snprintf(time_entry+19, 6, ".%6d", token_time.tv_usec);
//	log_debug_msg(LOG_DEBUG, "expires_at        : %s", time_entry);
//
//	char pub_key[2*crypto_sign_PUBLICKEYBYTES+1];
//	sodium_bin2hex(pub_key, 2*crypto_sign_PUBLICKEYBYTES+1, token->public_key, crypto_sign_PUBLICKEYBYTES);
//	log_debug_msg(LOG_DEBUG, "public_key        : %s", pub_key);

	// log_debug_msg(LOG_DEBUG, "extensions        : %s");
}

np_dhkey_t _np_aaatoken_create_dhkey(np_aaatoken_t* identity)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: np_dhkey_t _np_aaatoken_create_dhkey(np_aaatoken_t* identity){");
	// build a hash to find a place in the dhkey table, not for signing !
	unsigned char* hash = _np_aaatoken_get_fingerprint(identity, FALSE);	
	char key[crypto_generichash_BYTES * 2 + 1];
	sodium_bin2hex(key, crypto_generichash_BYTES*2+1, hash, crypto_generichash_BYTES);
	np_dhkey_t search_key = np_dhkey_create_from_hash(key);
	free(hash);
	return (search_key);
}

np_bool _np_aaatoken_is_valid(np_aaatoken_t* token)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: np_bool _np_aaatoken_is_valid(np_aaatoken_t* token){");
	assert (NULL != token);

	log_msg(LOG_AAATOKEN | LOG_TRACE, ".start.token_is_valid");

	np_bool is_full_token = FALSE == _np_aaatoken_is_core_token(token);

	// check timestamp
	double now = np_time_now();
	if (now > (token->expires_at))
	{
		log_msg(LOG_AAATOKEN | LOG_WARN, "token for subject \"%s\": expired. verification failed", token->subject);
		token->state &= AAA_INVALID;
		log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
		return (FALSE);
	}
	else {
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token has not expired");
	}

	if (token->private_key_is_set == FALSE &&
		token->is_signature_verified == FALSE)
	{
		unsigned char* hash = _np_aaatoken_get_fingerprint(token, is_full_token);

		char hash_hex[crypto_generichash_BYTES * 2 + 1] = { 0 };
		sodium_bin2hex(hash_hex, crypto_generichash_BYTES * 2 + 1, hash, crypto_generichash_BYTES);
		log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "token hash key fingerprint: %s", hash_hex);

		// verify inserted signature first
		unsigned char* signature = token->signature;

		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "try to check signature checksum");
		int ret = crypto_sign_verify_detached((unsigned char*)signature, hash, crypto_generichash_BYTES, token->public_key);

#ifdef DEBUG
		if (ret != 0 || strcmp(token->subject, "_NP.SYSINFO.REPLY") == 0 || strcmp(token->subject, "_NP.SYSINFO.REQUEST") == 0 ) {
			unsigned long long signature_len = crypto_sign_BYTES;
			char* signature_hex = calloc(1, signature_len * 2 + 1);
			sodium_bin2hex(signature_hex, signature_len * 2 + 1,
				signature, signature_len);

			unsigned long long pk_len = crypto_sign_PUBLICKEYBYTES;
			char* pk_hex = calloc(1, pk_len * 2 + 1);
			sodium_bin2hex(pk_hex, pk_len * 2 + 1,
				token->public_key, pk_len);

			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "(token: %p) signature: is_valid (payload: %s) (pk: %s) %s = %"PRId32, token, hash_hex, pk_hex, signature_hex, ret);
			free(signature_hex);
			free(pk_hex);
		}
#endif

		free(hash);
		if (ret < 0)
		{
			log_msg(LOG_AAATOKEN | LOG_WARN, "token for subject \"%s\": checksum verification failed", token->subject);
			log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
			token->state &= AAA_INVALID;			
			return (FALSE);
		}
		token->is_signature_verified = TRUE;
	}
	
	/*
		If we received a full token we may already got a core token,
		if so we need to validate the new tokens signature against the already received token sig
		and an successfully verifying the new tokens identity is the same as the core tokens 
	*/
	if (is_full_token == TRUE) {

		// check for already received core token
		np_dhkey_t core_token_dhkey = _np_aaatoken_create_dhkey(token);

		np_key_t* core_token_key = _np_keycache_find(core_token_dhkey);
		if (core_token_key != NULL){				

			if (memcmp(core_token_key->aaa_token->signature, token->signature, crypto_sign_BYTES*(sizeof(unsigned char))) != 0) {

				np_unref_obj(np_key_t, core_token_key, "_np_keycache_find");
				log_msg(LOG_WARN, "Someone tried to impersonate a token. verification failed");
				return (FALSE);
			}
		}
		np_unref_obj(np_key_t, core_token_key, "_np_keycache_find");
	}

	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token checksum verification completed");	

	// TODO: only if this is a message token
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "try to find max/msg threshold ");
	np_tree_elem_t* max_threshold = np_tree_find_str(token->extensions, "max_threshold");
	np_tree_elem_t* msg_threshold = np_tree_find_str(token->extensions, "msg_threshold");
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
			log_msg(LOG_WARN, "verification failed. token for subject \"%s\": %s was already used, 0<=%"PRIu16"<%"PRIu16, token->subject, token->issuer, token_msg_threshold, token_max_threshold);
			log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
			token->state &= AAA_INVALID;
			return (FALSE);
		}
	}
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token for subject \"%s\": verification valid", token->subject);
	token->state |= AAA_VALID;
	return (TRUE);
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

	ret_check = strncmp(first->uuid, second->uuid, UUID_SIZE);
	if (0 != ret_check )
	{
		return (ret_check);
	}

	return _np_aaatoken_cmp(first,second);
}

void _np_aaatoken_create_ledger(np_key_t* subject_key, char* subject)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: void _np_aaatoken_create_ledger(np_key_t* subject_key, char* subject){");
	np_msgproperty_t* prop = NULL;
	np_bool create_new_prop = FALSE;

	_LOCK_MODULE(np_aaatoken_t)
	{

		if (NULL == subject_key->recv_tokens)
			pll_init(np_aaatoken_ptr, subject_key->recv_tokens);

		if (NULL == subject_key->send_tokens)
			pll_init(np_aaatoken_ptr, subject_key->send_tokens);


		np_msgproperty_t* send_prop = np_msgproperty_get(OUTBOUND, subject);
		if (NULL != send_prop)
		{
			if(NULL == subject_key->send_property)
			{
				np_ref_obj(np_msgproperty_t, send_prop, ref_key_send_property);
				subject_key->send_property = send_prop;
			}
		}
		else
		{
			create_new_prop |= TRUE;
		}

		np_msgproperty_t* recv_prop = np_msgproperty_get(INBOUND, subject);
		if (NULL != recv_prop)
		{
			if(NULL == subject_key->recv_property)
			{
				np_ref_obj(np_msgproperty_t, recv_prop, ref_key_recv_property);
				subject_key->recv_property = recv_prop;
			}
		}
		else
		{
			create_new_prop |= TRUE;
		}

		if (TRUE == create_new_prop && (NULL == subject_key->send_property || NULL == subject_key->recv_property))
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
				np_ref_obj(np_msgproperty_t, prop, ref_key_send_property);
				subject_key->send_property = prop;
			}
			if (NULL == subject_key->recv_property) {
				np_ref_obj(np_msgproperty_t, prop,ref_key_recv_property);
				subject_key->recv_property = prop;
			}
		}
	}
}

// update internal structure and return a interest if a matching pair has been found
void _np_aaatoken_add_sender(char* subject, np_aaatoken_t *token)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: void _np_aaatoken_add_sender(char* subject, np_aaatoken_t *token){");
	log_msg(LOG_AAATOKEN | LOG_TRACE, ".start.np_add_sender_token");

	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport(subject, "0");

	subject_key = _np_keycache_find_or_create(search_key);
	_np_aaatoken_create_ledger(subject_key, subject);

	// should never happen
	if (NULL == subject_key) return;

	log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "update on global sender msg token structures ... %p (size %d)",
							 subject_key->send_property,
							 pll_size(subject_key->send_tokens) );

	// insert new token
	_LOCK_ACCESS(&subject_key->send_property->lock)
	{
		log_debug_msg(LOG_DEBUG, ".step1._np_aaatoken_add_sender %d / %s", pll_size(subject_key->send_tokens), subject);
		// update #2 subject specific data
		subject_key->send_property->mep_type |= (np_tree_find_str(token->extensions, "mep_type")->val.value.ul & SENDER_MASK);
		subject_key->send_property->ack_mode = np_tree_find_str(token->extensions, "ack_mode")->val.value.ush;
		subject_key->send_property->last_update = np_time_now();

		uint16_t max_threshold = np_tree_find_str(token->extensions, "max_threshold")->val.value.ui;
		np_aaatoken_t *tmp_token = NULL;

		if (max_threshold > 0)
		{
			np_msg_mep_type sender_mep_type = subject_key->send_property->mep_type & SENDER_MASK;

			np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_add     = _np_aaatoken_cmp;
			np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_replace = _np_aaatoken_cmp_exact;
			np_bool allow_dups = TRUE;

			if (SINGLE_SENDER == (SINGLE_SENDER & sender_mep_type))
			{
				cmp_aaatoken_replace   = _np_aaatoken_cmp;
				allow_dups = FALSE;
			}

			// update #1 key specific data
			np_ref_obj(np_aaatoken_t, token,"send_tokens");
			tmp_token = pll_replace(np_aaatoken_ptr, subject_key->send_tokens, token, cmp_aaatoken_replace);
			if (NULL == tmp_token)
			{
				pll_insert(np_aaatoken_ptr, subject_key->send_tokens, token, allow_dups, cmp_aaatoken_add);
			}
			else
			{
				token->state = tmp_token->state;
				np_unref_obj(np_aaatoken_t, tmp_token,"send_tokens");
			}
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "added new single sender token for message hash %s",
					_np_key_as_str(subject_key) );
		}
	}

	// check for outdated token
	_LOCK_ACCESS(&subject_key->send_property->lock)
	{
		log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_add_sender %d", pll_size(subject_key->send_tokens));
		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->send_tokens);
		while (NULL != iter)
		{
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "checking sender msg tokens %p/%p", iter, iter->val);
			np_aaatoken_t* tmp_token = iter->val;
			pll_next(iter);

			if (NULL  != tmp_token &&
				FALSE == _np_aaatoken_is_valid(tmp_token) )
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

	log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .np_add_sender_token");
}

/** np_get_sender_token
 ** retrieve a list of valid sender tokens from the cache
 ** TODO extend this function with a key and an amount of messages
 ** TODO use a different function for mitm and leaf nodes ?
 **/
sll_return(np_aaatoken_ptr) _np_aaatoken_get_all_sender(char* subject)
{
	np_sll_t(np_aaatoken_ptr, return_list) = NULL;
	sll_init(np_aaatoken_ptr, return_list);

	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport(subject, "0");

	subject_key = _np_keycache_find_or_create(search_key);
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
			if (FALSE == _np_aaatoken_is_valid(tmp->val))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid sender token for issuer %s", tmp->val->issuer);
			}
			else
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "found valid sender token (%s)", tmp->val->issuer );
				// only pick key from a list if the subject msg_treshold is bigger than zero
				// and the sending threshold is bigger than zero as well
				// and we actually have a receiver node in the list
				np_ref_obj(np_aaatoken_t, tmp->val);
				sll_append(np_aaatoken_ptr, return_list, tmp->val);
			}
			pll_next(tmp);
		}
		log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_get_all_sender %d", pll_size(subject_key->send_tokens));
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");

	return (return_list);
}

np_aaatoken_t* _np_aaatoken_get_sender(char* subject, char* sender)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: np_aaatoken_t* _np_aaatoken_get_sender(char* subject, char* sender){");
	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport(subject, "0");

	subject_key = _np_keycache_find_or_create(search_key);
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
	np_bool found_return_token = FALSE;

	_LOCK_ACCESS(&subject_key->send_property->lock)
	{
		log_debug_msg(LOG_DEBUG, ".step1._np_aaatoken_get_sender %d / %s", pll_size(subject_key->send_tokens), subject);
		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->send_tokens);
		while (NULL != iter &&
			   FALSE == found_return_token)
		{
			return_token = iter->val;
			if (FALSE == _np_aaatoken_is_valid(return_token))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid sender token for issuer %s", return_token->issuer);
				pll_next(iter);
				return_token = NULL;
				continue;
			}

			// only pick key from a list if the subject msg_treshold is bigger than zero
			// and we actually have the correct sender node in the list
			if (0 != strncmp(return_token->issuer, sender, 64))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring sender token for issuer %s / send_hk: %s",
						return_token->issuer, sender);
				pll_next(iter);
				return_token = NULL;
				continue;
			}
			if (! (IS_AUTHORIZED(return_token->state)))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring sender token for issuer %s / send_hk: %s as it is not authorized",
						return_token->issuer, sender);
				pll_next(iter);
				return_token = NULL;
				continue;
			}
			if (! (IS_AUTHENTICATED(return_token->state)) )
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring sender token for issuer %s / send_hk: %s as it is not authenticated",
						return_token->issuer, sender);
				pll_next(iter);
				return_token = NULL;
				continue;
			}

			found_return_token = TRUE;
			np_ref_obj(np_aaatoken_t, return_token);
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "found valid sender token (%s)", return_token->issuer);
		}
		log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_get_sender %d", pll_size(subject_key->send_tokens));
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	return (return_token);
}

// update internal structure and clean invalid tokens
void _np_aaatoken_add_receiver(char* subject, np_aaatoken_t *token)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: void _np_aaatoken_add_receiver(char* subject, np_aaatoken_t *token){");

	assert(token != NULL);
	log_msg(LOG_AAATOKEN | LOG_TRACE, ".start.np_add_receiver_token");

	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport(subject, "0");

	subject_key = _np_keycache_find_or_create(search_key);
	_np_aaatoken_create_ledger(subject_key, subject);

	// should never happen
	if (NULL == subject_key) return;

	log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "update on global receiving msg token structures ... %p (size %d)",
							 subject_key->recv_property,
							 pll_size(subject_key->recv_tokens) );

	// insert new token
	_LOCK_ACCESS(&subject_key->recv_property->lock)
	{
		log_debug_msg(LOG_DEBUG, ".step1._np_aaatoken_add_receiver %d / %s", pll_size(subject_key->recv_tokens), subject);
		// update #2 subject specific data
//		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "receiver token %03x mask %03x",
//										  subject_key->recv_property->mep_type, (RECEIVER_MASK | FILTER_MASK) );

		subject_key->recv_property->mep_type |= (np_tree_find_str(token->extensions, "mep_type")->val.value.ul & RECEIVER_MASK);

//		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "receiver token %03x %03x",
//				                          subject_key->recv_property->mep_type, np_tree_find_str(token->extensions, "mep_type")->val.value.ul );

		// subject_key->recv_property->ack_mode = np_tree_find_str(token->extensions, "ack_mode")->val.value.ush;
		subject_key->recv_property->last_update = np_time_now();

		uint16_t max_threshold = np_tree_find_str(token->extensions, "max_threshold")->val.value.ui;

		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "adding receiver token %p threshold %d", token, max_threshold );

		if (max_threshold > 0)
		{	// only add if there are messages to receive
			np_msg_mep_type receiver_mep_type = (subject_key->recv_property->mep_type & RECEIVER_MASK);
			np_aaatoken_t* tmp_token = NULL;

			np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_add     = _np_aaatoken_cmp;
			np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_replace = _np_aaatoken_cmp_exact;
			np_bool allow_dups = TRUE;

			if (SINGLE_RECEIVER == (SINGLE_RECEIVER & receiver_mep_type))
			{
				cmp_aaatoken_replace   = _np_aaatoken_cmp;
				allow_dups = FALSE;
			}

			// update #1 key specific data
			np_ref_obj(np_aaatoken_t, token,"recv_tokens");
			tmp_token = pll_replace(np_aaatoken_ptr, subject_key->recv_tokens, token, cmp_aaatoken_replace);
			if (NULL == tmp_token)
			{
				pll_insert(np_aaatoken_ptr, subject_key->recv_tokens, token, allow_dups, cmp_aaatoken_add);
			}
			else
			{
				token->state = tmp_token->state;
				np_unref_obj(np_aaatoken_t, tmp_token,"recv_tokens");
			}
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "added new single sender token for message hash %s",
					_np_key_as_str(subject_key) );
		}
	}

	// check for outdated token
	_LOCK_ACCESS(&subject_key->recv_property->lock)
	{
		log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_add_receiver %d", pll_size(subject_key->recv_tokens));

		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
		while (NULL != iter)
		{
			np_aaatoken_t* tmp_token = iter->val;
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "checking receiver msg tokens %p/%p", iter, iter->val);

			pll_next(iter);

			if (NULL  != tmp_token &&
				FALSE == _np_aaatoken_is_valid(tmp_token) )
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "deleting old / invalid receiver msg tokens %p", tmp_token);
				pll_remove(np_aaatoken_ptr, subject_key->recv_tokens, tmp_token, _np_aaatoken_cmp_exact);
				np_unref_obj(np_aaatoken_t, tmp_token,"recv_tokens");
				break;
			}
		}
		log_debug_msg(LOG_DEBUG, ".step3._np_aaatoken_add_receiver %d", pll_size(subject_key->recv_tokens));
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .np_add_receiver_token");
}

np_aaatoken_t* _np_aaatoken_get_receiver(char* subject, np_dhkey_t* target)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: np_aaatoken_t* _np_aaatoken_get_receiver(char* subject, np_dhkey_t* target){");
	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport(subject, "0");

	subject_key = _np_keycache_find_or_create(search_key);
	_np_aaatoken_create_ledger(subject_key, subject);

	// should never happen
	if (NULL == subject_key) return (NULL);

	// log_debug_msg(LOG_DEBUG, "available %hd interests %hd",
	// subject_key->send_property->max_threshold, subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists
	np_aaatoken_t* return_token = NULL;
	np_bool found_return_token = FALSE;

	_LOCK_ACCESS(&subject_key->recv_property->lock)
	{
		log_debug_msg(LOG_DEBUG, ".step1._np_aaatoken_get_receiver %d / %s", pll_size(subject_key->recv_tokens), subject);
		if(NULL != target) {
			char targetnode_str[65];
			_np_dhkey_to_str(target, targetnode_str);
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "searching token for %s ", targetnode_str);
		}

		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
		while (NULL != iter &&
			   FALSE == found_return_token)
		{
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "checking receiver msg tokens %p/%p", iter, iter->val);
			return_token = iter->val;

			if (FALSE == _np_aaatoken_is_valid(return_token))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid receiver msg tokens %p", return_token );
				pll_next(iter);
				return_token = NULL;
				continue;
			}

			np_dhkey_t recvtoken_issuer_key = np_dhkey_create_from_hash(return_token->issuer);
			if (_np_dhkey_equal(&recvtoken_issuer_key, &_np_state()->my_node_key->dhkey))
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
				found_return_token = TRUE;
				np_ref_obj(np_aaatoken_t, return_token);
				break;
			}
		}
		log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_get_receiver %d", pll_size(subject_key->recv_tokens));
	}

	if(NULL == return_token ) {
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "found no valid receiver token" );
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	return (return_token);
}

sll_return(np_aaatoken_ptr) _np_aaatoken_get_all_receiver(char* subject)
{
	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport(subject, "0");

	subject_key = _np_keycache_find_or_create(search_key);
	_np_aaatoken_create_ledger(subject_key, subject);

//	log_debug_msg(LOG_DEBUG, "available %hd interests %hd",
//			subject_key->send_property->max_threshold, subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists
	np_sll_t(np_aaatoken_ptr, return_list) = NULL;
	sll_init(np_aaatoken_ptr, return_list);

	// should never happen
	if (NULL == subject_key) return (return_list);

	pll_iterator(np_aaatoken_ptr) tmp = NULL;

	_LOCK_ACCESS(&subject_key->recv_property->lock)
	{
		log_debug_msg(LOG_DEBUG, ".step1._np_aaatoken_get_all_receiver %d / %s", pll_size(subject_key->recv_tokens), subject);
		tmp = pll_first(subject_key->recv_tokens);
		while (NULL != tmp)
		{
			if (FALSE == _np_aaatoken_is_valid(tmp->val))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid receiver msg token" );
			}
			else
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
						"found valid receiver token (%s)", tmp->val->issuer );
				np_ref_obj(np_aaatoken_t, tmp->val);

				// only pick key from a list if the subject msg_treshold is bigger than zero
				// and the sending threshold is bigger than zero as well
				// and we actually have a receiver node in the list
				sll_append(np_aaatoken_ptr, return_list, tmp->val);
			}
			pll_next(tmp);
			// tmp = pll_head(np_aaatoken_ptr, subject_key->recv_tokens);
		}
		log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_get_all_receiver %d", pll_size(subject_key->recv_tokens));
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	return (return_list);
}

unsigned char* _np_aaatoken_get_fingerprint(np_aaatoken_t* msg_token, np_bool full) {
	int sizeof_hash = crypto_generichash_BYTES * sizeof(unsigned char);
	unsigned char* hash = calloc(1, sizeof_hash);
	crypto_generichash_state gh_state;
	crypto_generichash_init(&gh_state, NULL, 0, crypto_generichash_BYTES);
	
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprint: use full: %s", full ? "yes":"no");

	// only use fields available in core tokens and during the initial node setup

	crypto_generichash_update(&gh_state, (unsigned char*)msg_token->issuer, strnlen(msg_token->issuer, 65));
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprint: issuer: %s", msg_token->issuer);

	crypto_generichash_update(&gh_state, (unsigned char*)msg_token->subject, strnlen(msg_token->subject, 255));
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprint: subject: %s", msg_token->subject);

	crypto_generichash_update(&gh_state, (unsigned char*)msg_token->uuid, strnlen(msg_token->uuid, UUID_SIZE));
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprint: uuid: %s", msg_token->uuid);

	crypto_generichash_update(&gh_state, (unsigned char*)msg_token->public_key, crypto_sign_PUBLICKEYBYTES);



	if(full == TRUE) {
		// may contain all other fields

		crypto_generichash_update(&gh_state, (unsigned char*)&(msg_token->expires_at), sizeof(double));
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprint: expiration: %f", msg_token->expires_at);

		crypto_generichash_update(&gh_state, (unsigned char*)&(msg_token->issued_at), sizeof(double));
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprint: issued_at: %f", msg_token->issued_at);

		crypto_generichash_update(&gh_state, (unsigned char*)&(msg_token->not_before), sizeof(double));
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprint: not_before: %f", msg_token->not_before);

		
		crypto_generichash_update(&gh_state, (unsigned char*)msg_token->audience, strnlen(msg_token->audience, 255));
		crypto_generichash_update(&gh_state, (unsigned char*)msg_token->realm, strnlen(msg_token->realm,255));

		/* FIXME: seems to interrupt the signature later on
		if (msg_token->extensions != NULL) {

			cmp_ctx_t cmp;
			unsigned char extensions_payload[NP_AAATOKEN_MAX_SIZE_EXTENSIONS] = { 0 };
			void* extensions_buf_ptr = extensions_payload;

			cmp_init(&cmp, extensions_buf_ptr, _np_buffer_reader, _np_buffer_writer);
			_np_tree_serialize(msg_token->extensions, &cmp);
			
			crypto_generichash_update(&gh_state, (unsigned char*)extensions_buf_ptr,
				min(msg_token->extensions->byte_size, NP_AAATOKEN_MAX_SIZE_EXTENSIONS)
			;
		}
		*/
	}
	crypto_generichash_final(&gh_state, hash, crypto_generichash_BYTES);
	
#ifdef DEBUG
	char hash_str[crypto_generichash_BYTES * 2 + 1];
	sodium_bin2hex(hash_str, crypto_generichash_BYTES * 2 + 1, hash, crypto_generichash_BYTES);
	log_debug_msg(LOG_DEBUG, "fingerprint: result: %s", hash_str);
#endif

	return hash;
}
void _np_aaatoken_add_signature(np_aaatoken_t* msg_token)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: void _np_aaatoken_add_signature(np_aaatoken_t* msg_token){");
		unsigned long long signature_len = 0;
				
		unsigned char* hash = _np_aaatoken_get_fingerprint(msg_token, FALSE == _np_aaatoken_is_core_token(msg_token));

		if (msg_token->signed_hash == NULL || memcmp(hash, msg_token->signed_hash, crypto_generichash_BYTES * sizeof(unsigned char)) != 0) {
			free(msg_token->signed_hash);
			msg_token->signed_hash = NULL;

			char hash_hex[crypto_generichash_BYTES * 2 + 1];
			sodium_bin2hex(hash_hex, crypto_generichash_BYTES * 2 + 1, hash,
				crypto_generichash_BYTES);
			log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "token hash key fingerprint: %s",
				hash_hex);

			int ret = crypto_sign_detached((unsigned char*)msg_token->signature, &signature_len,
				(const unsigned char*)hash, crypto_generichash_BYTES,
				msg_token->private_key);
			if (ret < 0)
			{
				log_msg(LOG_WARN,
					"checksum creation for token failed, using unsigned token");
				free(hash);
			}
			else
			{
				msg_token->signed_hash = hash;
#ifdef DEBUG
				if (strcmp(msg_token->subject, "_NP.SYSINFO.REPLY") == 0) {
					log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "signature has %"PRIu64" bytes", signature_len);
					char* signature_hex = calloc(1, signature_len * 2 + 1);
					sodium_bin2hex(signature_hex, signature_len * 2 + 1,
						msg_token->signature, signature_len);

					unsigned long long pk_len = crypto_sign_PUBLICKEYBYTES;
					char* pk_hex = calloc(1, pk_len * 2 + 1);
					sodium_bin2hex(pk_hex, pk_len * 2 + 1,
						msg_token->public_key, pk_len);

					log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "signature: generate (payload hash: %s) (pk: %s) %s", hash_hex, pk_hex, signature_hex);

					free(pk_hex);
					free(signature_hex);
				}
#endif
			}
		}
		else {
			free(hash);
		}
}


np_aaatoken_t* _np_aaatoken_get_local_mx(char* subject)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: np_aaatoken_t* _np_aaatoken_get_local_mx(char* subject){");
	log_msg(LOG_AAATOKEN | LOG_TRACE, ".start._np_get_local_mx_token");
	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport(subject, "0");

	subject_key = _np_keycache_find_or_create(search_key);
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
	np_bool found_return_token = FALSE;

	_LOCK_ACCESS(&subject_key->send_property->lock)
	{
		log_debug_msg(LOG_DEBUG, ".step1._np_aaatoken_get_local_mx %d / %s", pll_size(subject_key->local_mx_tokens), subject);
		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->local_mx_tokens);
		while (NULL != iter &&
			   FALSE == found_return_token)
		{
			return_token = iter->val;
			if (FALSE == _np_aaatoken_is_valid(return_token))
			{
				log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid local mx token for subject %s", return_token->subject);
				pll_next(iter);
				return_token = NULL;
				continue;
			}
			found_return_token = TRUE;
			np_ref_obj(np_aaatoken_t, return_token);
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "found valid local mx token (%s)", return_token->issuer);
		}
		log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_get_local_mx %d", pll_size(subject_key->local_mx_tokens));
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  ._np_get_local_mx_token");
	return (return_token);
}

// update internal structure and return a interest if a matching pair has been found
void _np_aaatoken_add_local_mx(char* subject, np_aaatoken_t *token)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, "start: void _np_aaatoken_add_local_mx(char* subject, np_aaatoken_t *token){");
	log_msg(LOG_AAATOKEN | LOG_TRACE, ".start._np_add_local_mx_token");

	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = np_dhkey_create_from_hostport(subject, "0");

	subject_key = _np_keycache_find_or_create(search_key);
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
		log_debug_msg(LOG_DEBUG, ".step1._np_aaatoken_add_local_mx %d / %s", pll_size(subject_key->local_mx_tokens), subject);
		np_aaatoken_t *tmp_token = NULL;

		// update #1 key specific data
		np_ref_obj(np_aaatoken_t, token,"local_mx_tokens");
		tmp_token = pll_replace(np_aaatoken_ptr, subject_key->local_mx_tokens, token, _np_aaatoken_cmp);
		if (NULL == tmp_token)
		{
			pll_insert(np_aaatoken_ptr, subject_key->local_mx_tokens, token, FALSE, _np_aaatoken_cmp);
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
		log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_add_local_mx %d", pll_size(subject_key->local_mx_tokens));
		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->local_mx_tokens);
		while (NULL != iter)
		{
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "checking mx msg tokens %p/%p", iter, iter->val);
			np_aaatoken_t* tmp_token = iter->val;
			pll_next(iter);

			if (NULL  != tmp_token &&
				FALSE == _np_aaatoken_is_valid(tmp_token) )
			{
				log_msg(LOG_INFO, "deleting old / invalid mx msg token %p", tmp_token);
				pll_remove(np_aaatoken_ptr, subject_key->local_mx_tokens, tmp_token, _np_aaatoken_cmp_exact);
				np_unref_obj(np_aaatoken_t, tmp_token,"local_mx_tokens");
				break;
			}
		}
		log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_add_local_mx %d", pll_size(subject_key->local_mx_tokens));
	}

	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  ._np_add_local_mx_token");
}
