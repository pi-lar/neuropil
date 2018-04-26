//
// neuropil is copyright 2016-2018 by pi-lar GmbH
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
#include "np_network.h"
#include "np_treeval.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_threads.h"
#include "np_settings.h"
#include "np_util.h"
#include "np_constants.h"
#include "np_token_factory.h"
#include "np_memory.h"
#include "np_memory_v2.h"

np_aaatoken_t* __np_token_factory_derive(np_aaatoken_t* source, enum np_aaatoken_scope scope)
{
	np_aaatoken_t* ret = NULL;

	/// contract begin
	ASSERT(source != NULL, "source token cannot be NULL");

	switch (scope)
	{
	case np_aaatoken_scope_private:
		ASSERT(source->scope == np_aaatoken_scope_private, "Can only derive a private token from another private token. current token scope: %"PRIu8,source->scope);
		ASSERT(
			FLAG_CMP(source->type, np_aaatoken_type_identity) && FLAG_CMP(source->type, np_aaatoken_type_node),
			"Can only derive a private token from a node or identity token.");
		break;
	case np_aaatoken_scope_public:
		ASSERT(source->scope <= np_aaatoken_scope_public, "Can only derive a public token from a private or public token. current token scope: %"PRIu8, source->scope);
		break;
	default:
		log_msg(LOG_ERROR, "scope to derive token to is unknown. scope: %"PRIu8, scope);
		abort();
		break;
	}
	/// end of contract

	// create token
	np_new_obj(np_aaatoken_t, ret, __func__);

	strncpy(ret->realm, source->realm, 255);
	strncpy(ret->issuer, source->issuer, 65);
	strncpy(ret->subject, source->subject, 255);
	strncpy(ret->audience, source->audience, 255);

	ret->not_before = source->not_before;
	ret->expires_at = source->expires_at;
	ret->issued_at  = source->issued_at;
	ret->version = source->version;
	ret->state = source->state;

	memcpy(ret->public_key, source->public_key, crypto_sign_PUBLICKEYBYTES);

	if(scope != np_aaatoken_scope_private) {
		memset(ret->private_key, 0, crypto_sign_SECRETKEYBYTES );
		ret->private_key_is_set = FALSE;
	}
	else
	{
		memcpy(ret->private_key, source->private_key, crypto_sign_SECRETKEYBYTES);
		ret->private_key_is_set = TRUE;
	}
	np_tree_copy(source->extensions, ret->extensions);

	// np_tree_t* copy = np_tree_create();
	// np_aaatoken_encode_with_secrets(copy, source);
	// np_aaatoken_decode_with_secrets(copy, ret);
	// }
	// else {
	// np_aaatoken_encode(copy, source);
	// np_aaatoken_decode(copy, ret);
	// }
	ret->scope = scope;

	return (ret);
}

np_ident_public_token_t* np_token_factory_get_public_ident_token(np_aaatoken_t* source) {
	np_ident_public_token_t* ret = NULL;

	ASSERT(FLAG_CMP(source->type, np_aaatoken_type_identity), "Can only directly derive ident token from ident token. current token type: %"PRIu8, source->type);

	ret = __np_token_factory_derive(source, np_aaatoken_scope_public);
	ret->type = np_aaatoken_type_identity;

	ref_replace_reason(np_aaatoken_t, ret, "__np_token_factory_derive", __func__);
	return ret;
}

np_node_public_token_t* np_token_factory_get_public_node_token(np_aaatoken_t* source) {
	np_node_public_token_t* ret = NULL;

	ASSERT(FLAG_CMP(source->type , np_aaatoken_type_node), "Can only directly derive node token from node token. current token type: %"PRIu8, source->type);

	ret = __np_token_factory_derive(source, np_aaatoken_scope_public);
	ret->type = np_aaatoken_type_node;

	ref_replace_reason(np_aaatoken_t, ret, "__np_token_factory_derive", __func__);
	return ret;
}

np_aaatoken_t* __np_token_factory_new(char issuer[64], char node_subject[255], double expires_at)
{
	np_aaatoken_t* ret = NULL;
	np_new_obj(np_aaatoken_t, ret, __func__);

	np_state_t* state = np_state();

	// create token
	if (NULL != state->realm_name)
	{
		strncpy(ret->realm, state->realm_name, 255);
	}
	strncpy(ret->issuer, issuer, 64);
	strncpy(ret->subject, node_subject, 254);
	// strncpy(ret->audience, (char*) _np_key_as_str(state->my_identity->aaa_token->realm), 255);

	ret->not_before = np_time_now();
	ret->expires_at = expires_at;

	crypto_sign_keypair(ret->public_key, ret->private_key);   // ed25519
	ret->scope = np_aaatoken_scope_private;

	return ret;
}

np_message_intent_public_token_t* _np_token_factory_new_message_intent_token(np_msgproperty_t* msg_request) {
	log_trace_msg(LOG_TRACE, "start: np_aaatoken_t* _np_token_factory_new_message_intent_token(np_msgproperty_t* msg_request){");
	np_message_intent_public_token_t* ret = NULL;

	ASSERT(msg_request != NULL, "source messageproperty cannot be NULL");

	np_state_t* state = np_state();
	np_new_obj(np_aaatoken_t, ret, __func__);

	char msg_id_subject[255];
	snprintf(msg_id_subject, 255, _NP_URN_MSG_PREFIX"%s", msg_request->msg_subject);

	np_waitref_obj(np_key_t, state->my_identity, my_identity, "np_waitref_obj");
	np_waitref_obj(np_key_t, state->my_node_key, my_node_key, "np_waitref_obj");

	// create token
	strncpy(ret->realm, my_identity->aaa_token->realm, 255);
	strncpy(ret->issuer, (char*)_np_key_as_str(my_identity), 64);
	strncpy(ret->subject, msg_id_subject, 255);
	if (NULL != msg_request->msg_audience)
	{
		strncpy(ret->audience, (char*)msg_request->msg_audience, 255);
	}

	// TODO: how to allow the possible transmit jitter ?
	ret->not_before = np_time_now();
	int expire_sec = ((int)randombytes_uniform(msg_request->token_max_ttl - msg_request->token_min_ttl) + msg_request->token_min_ttl);
	ret->expires_at = ret->not_before + expire_sec;

	log_debug_msg(LOG_MESSAGE | LOG_AAATOKEN | LOG_DEBUG, "setting msg token EXPIRY to: %f (now: %f diff: %f)", ret->expires_at, np_time_now(), ret->expires_at - np_time_now());

	if (my_identity->aaa_token->expires_at < ret->expires_at) {
		ret->expires_at = my_identity->aaa_token->expires_at;
	}

	// add e2e encryption details for sender
	memcpy((char*)ret->public_key,
		(char*)my_identity->aaa_token->public_key,
		crypto_sign_PUBLICKEYBYTES);

	// private key is only required for signing later, will not be send over the wire
	// memcpy((char*)ret->private_key,
	//	(char*)my_identity->aaa_token->private_key,
	//	crypto_sign_SECRETKEYBYTES);
	//ret->scope = np_aaatoken_scope_private;
	ret->scope = np_aaatoken_scope_private_available;

	np_tree_replace_str(ret->extensions, "mep_type",
		np_treeval_new_ul(msg_request->mep_type));
	np_tree_replace_str(ret->extensions, "ack_mode",
		np_treeval_new_ush(msg_request->ack_mode));
	np_tree_replace_str(ret->extensions, "max_threshold",
		np_treeval_new_ui(msg_request->max_threshold));
	np_tree_replace_str(ret->extensions, "msg_threshold",
		np_treeval_new_ui(0)); //TODO: correct ?

	// TODO: insert value based on msg properties / respect (sticky) reply
	np_tree_replace_str(ret->extensions,  "target_node",
		np_treeval_new_s((char*)_np_key_as_str(my_node_key)));

	ret->state = AAA_AUTHORIZED | AAA_AUTHENTICATED | AAA_VALID;

	ret->type = np_aaatoken_type_message_intent;

	// fingerprinting and signing the token
	_np_aaatoken_set_signature(ret, my_identity->aaa_token);

	np_unref_obj(np_key_t, my_identity, "np_waitref_obj");
	np_unref_obj(np_key_t, my_node_key, "np_waitref_obj");

	_np_aaatoken_trace_info("build_intent", ret);

	return (ret);
}

np_handshake_token_t* _np_token_factory_new_handshake_token() {

	np_handshake_token_t* ret = NULL;

	np_waitref_obj(np_key_t, np_state()->my_node_key, my_node_key);
	np_waitref_obj(np_aaatoken_t, my_node_key->aaa_token, my_node_token);

	ASSERT(FLAG_CMP(my_node_token->type, np_aaatoken_type_node), "Can only derive handshake token from node token. current token type: %"PRIu8, my_node_token->type);
	ASSERT(my_node_token->scope == np_aaatoken_scope_private, "Can only derive handshake token from private token. current token scope: %"PRIu8, my_node_token->scope);

	ret = __np_token_factory_derive(my_node_token, np_aaatoken_scope_private);
	ret->type = np_aaatoken_type_handshake;

#ifdef DEBUG
	char sk_hex[crypto_sign_SECRETKEYBYTES * 2 + 1];
	sodium_bin2hex(sk_hex, crypto_sign_SECRETKEYBYTES * 2 + 1, ret->private_key, crypto_sign_SECRETKEYBYTES);
	log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "hst_token signature private key: %s", sk_hex);
#endif

	np_dhkey_t node_dhkey = np_aaatoken_get_fingerprint(my_node_token);
	_np_dhkey_to_str(&node_dhkey, ret->issuer);

	// create and handshake session data
	// convert to curve key
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	// TODO: handle crypto result
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_node_token->private_key);
	// calculate session key for dh key exchange
	unsigned char my_dh_sessionkey[crypto_scalarmult_BYTES] = { 0 };
	crypto_scalarmult_base(my_dh_sessionkey, curve25519_sk);

	np_tree_clear(ret->extensions);
	np_tree_insert_str(ret->extensions, "_np.session", np_treeval_new_bin(my_dh_sessionkey, crypto_scalarmult_BYTES));

	_np_aaatoken_set_signature(ret, my_node_key->aaa_token);

#ifdef DEBUG
	char my_token_fp_s[255] = { 0 };
	np_dhkey_t my_token_fp = np_aaatoken_get_fingerprint(ret);
	_np_dhkey_to_str(&my_token_fp, my_token_fp_s);
	log_debug_msg(LOG_DEBUG, "new handshake token fp: %s from node: %s", my_token_fp_s, _np_key_as_str(my_node_key));
	// ASSERT(strcmp(my_token_fp_s, _np_key_as_str(my_node_key)) == 0, "Node key and handshake partner key has to be the same");
#endif // DEBUG

	// if (!_np_aaatoken_is_valid(ret, np_aaatoken_type_handshake)) exit(0);

	np_unref_obj(np_aaatoken_t, my_node_token, __func__);
	np_unref_obj(np_key_t, my_node_key, __func__);
	ref_replace_reason(np_aaatoken_t, ret, "__np_token_factory_derive", __func__);

	_np_aaatoken_trace_info("build_handshake", ret);

	return ret;
}

np_node_private_token_t* _np_token_factory_new_node_token(np_node_t* source_node)
{
	log_trace_msg(LOG_TRACE, "start: np_aaatoken_t* _np_token_factory_new_node_token(np_node_t* source_node){");


	int rand_interval = ((int)randombytes_uniform(NODE_MAX_TTL_SEC - NODE_MIN_TTL_SEC) + NODE_MIN_TTL_SEC);
	double expires_at = np_time_now() + rand_interval;

	char issuer[64] = { 0 };
	char node_subject[255];
	snprintf(node_subject, 255,  _NP_URN_NODE_PREFIX "%s:%s:%s",
		_np_network_get_protocol_string(source_node->protocol), source_node->dns_name, source_node->port);

	np_node_private_token_t* ret = __np_token_factory_new(issuer, node_subject, expires_at);

	if (np_state() != NULL && np_state()->my_identity != NULL) {
		np_aaatoken_set_partner_fp(ret, np_aaatoken_get_fingerprint(np_state()->my_identity->aaa_token));
	}
	ret->type = np_aaatoken_type_node;
	ret->scope = np_aaatoken_scope_private;

	_np_aaatoken_set_signature(ret, ret);
	_np_aaatoken_update_extensions_signature(ret, ret);

	ref_replace_reason(np_aaatoken_t, ret, "__np_token_factory_new", __func__);

	#ifdef DEBUG
	char sk_hex[crypto_sign_SECRETKEYBYTES * 2 + 1];
	sodium_bin2hex(sk_hex, crypto_sign_SECRETKEYBYTES * 2 + 1, ret->private_key, crypto_sign_SECRETKEYBYTES);
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG , "n_token signature private key: %s", sk_hex);
#endif

	_np_aaatoken_trace_info("build_node", ret);
	return (ret);
}

np_ident_private_token_t* np_token_factory_new_identity_token(double expires_at)
{
	char issuer[64] = { 0 };
	char node_subject[255];
	snprintf(node_subject, 255,  _NP_URN_IDENTITY_PREFIX"%s", np_uuid_create("gererated identy", 0));


	np_aaatoken_t* ret = __np_token_factory_new(issuer, node_subject, expires_at);
	ret->type = np_aaatoken_type_identity;
	ret->scope = np_aaatoken_scope_private;

	np_aaatoken_set_partner_fp(ret, np_aaatoken_get_fingerprint(np_state()->my_node_key->aaa_token));

	_np_aaatoken_set_signature(ret, ret);
	_np_aaatoken_update_extensions_signature(ret, ret);

	ref_replace_reason(np_aaatoken_t, ret, "__np_token_factory_new", __func__);

	_np_aaatoken_trace_info("build_ident", ret);

	return ret;
}

np_aaatoken_t* np_token_factory_read_from_tree(np_tree_t* tree) {
	np_aaatoken_t* ret = NULL;
	np_bool ok = FALSE;
	np_new_obj(np_aaatoken_t, ret, __func__);
	if (np_aaatoken_decode(tree, ret)) {
		log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "imported token %s (type: %"PRIu8") from tree %p", ret->uuid, ret->type, tree);

		if (_np_aaatoken_is_valid(ret, np_aaatoken_type_undefined)) {
			
			ASSERT(strlen(ret->subject) > 1, "tokens (%s) subject string (\"%s\") has incorrect size", ret->uuid, ret->subject);
			ok = TRUE;
		}
	}
	if (ok) {
		_np_aaatoken_trace_info("in_OK", ret);
	}else{
		_np_aaatoken_trace_info("in_NOK", ret);
		np_unref_obj(np_aaatoken_t, ret, __func__);
		ret = NULL;
	}
	return ret;
}