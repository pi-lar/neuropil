//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "inttypes.h"

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
#include "np_token_factory.h"


np_aaatoken_t* __np_token_factory_derive(np_aaatoken_t* source, enum np_aaatoken_scope scope)
{
	np_aaatoken_t* ret = NULL;
	/// contract begin
	ASSERT(source != NULL, "source token cannot be NULL");	

	switch (scope)
	{
	case np_aaatoken_scope_private:
		ASSERT(source->scope == np_aaatoken_scope_private, "Can only derive a private token from another private token.");
		ASSERT(
			FLAG_CMP(source->type, np_aaatoken_type_identity) && FLAG_CMP(source->type, np_aaatoken_type_node),
			"Can only derive a private token from a node or identity token.");
		break;
	case np_aaatoken_scope_public:
		ASSERT(source->scope <= np_aaatoken_scope_public, "Can only derive a public token from a private or public token.");
		break;
	default:
		log_msg(LOG_ERROR, "scope to derive token to is unknown.");
		abort();
		break;
	}
	// end of contract

	np_new_obj(np_aaatoken_t, ret, __func__);

	np_tree_t* copy = np_tree_create();		
	if(scope == np_aaatoken_scope_private){
		np_aaatoken_decode_with_secrets(copy, source);
	}
	else {
		np_aaatoken_decode(copy, source);
	}
	np_aaatoken_encode(copy, ret);		

	ret->scope = scope;
	free(ret->uuid);
	ret->uuid = np_uuid_create("new token", 0);
	

	return ret;
}

np_ident_public_token_t* np_token_factory_get_public_ident_token(np_aaatoken_t* source) {
	np_ident_public_token_t* ret = NULL;

	ASSERT(FLAG_CMP(source->type, np_aaatoken_type_identity), "Can only directly derive ident token from ident token");

	ret = __np_token_factory_derive(source, np_aaatoken_scope_public);
	ret->type = np_aaatoken_type_identity;
	
	return ret;
}

np_node_public_token_t* np_token_factory_get_public_node_token(np_aaatoken_t* source) {
	np_node_public_token_t* ret = NULL;

	ASSERT(FLAG_CMP(source->type , np_aaatoken_type_node), "Can only directly derive node token from node token");

	ret = __np_token_factory_derive(source, np_aaatoken_scope_public);
	ret->type = np_aaatoken_type_node;

	return ret;
}

np_message_intent_public_token_t* np_token_factory_get_message_intent_token(np_aaatoken_t* source, np_msgproperty_t* source_prop) {
	np_message_intent_public_token_t* ret = NULL;

	ASSERT(FLAG_CMP(source->type, np_aaatoken_type_identity), "Can only derive message intent token from ident token");
	ASSERT(source_prop != NULL, "source messageproperty cannot be NULL");

	ret = __np_token_factory_derive(source, np_aaatoken_scope_public);
	ret->type = np_aaatoken_type_message_intent;

	_np_token_factory_new_node_token

	return ret;
}


np_aaatoken_t* __np_token_factory_new(char issuer[64], char node_subject[255], double expires_at)
{
	np_aaatoken_t* ret = NULL;
	np_new_obj(np_aaatoken_t, ret);

	np_state_t* state = np_state();

	// create token
	if (NULL != state->realm_name)
	{
		strncpy(ret->realm, state->realm_name, 255);
	}
	strncpy(ret->issuer, issuer, 64);
	strncpy(ret->subject, node_subject, 255);
	// strncpy(ret->audience, (char*) _np_key_as_str(state->my_identity->aaa_token->realm), 255);

	ret->not_before = np_time_now();

	ret->expires_at = expires_at;

	crypto_sign_keypair(ret->public_key, ret->private_key);   // ed25519
	ret->private_key_is_set = TRUE;
	ret->scope = np_aaatoken_scope_private;

	return ret;
}


np_aaatoken_t* _np_token_factory_new_node_token(np_node_t* source_node)
{
	log_msg(LOG_TRACE, "start: np_aaatoken_t* _np_token_factory_new_node_token(np_node_t* source_node){");

	int rand_interval = ((int)randombytes_uniform(NODE_MAX_TTL_SEC - NODE_MIN_TTL_SEC) + NODE_MIN_TTL_SEC);
	double expires_at = np_time_now() + rand_interval;

	char node_subject[255];
	snprintf(node_subject, 255, "urn:np:node:%s:%s:%s",
		_np_network_get_protocol_string(source_node->protocol), source_node->dns_name, source_node->port);

	char issuer[64] = { 0 };
	if (np_state() != NULL && np_state()->my_identity != NULL &&
		_np_node_cmp(np_state()->my_identity->node, source_node) != 0) {

		strncpy(issuer, _np_key_as_str(np_state()->my_identity), 64);
	}
	else {
		strncpy(issuer, node_subject, 64);
	}

	np_aaatoken_t* ret = __np_token_factory_new(issuer, node_subject, expires_at);

	return (ret);
}

np_aaatoken_t* np_token_factory_new_identity_token(double expires_at)
{
	char node_subject[255];
	snprintf(node_subject, 255, "urn:np:identity:%s", np_uuid_create("urn:np:identity", 0));

	char issuer[64] = { 0 };

	np_aaatoken_t* ret = __np_token_factory_new(issuer, node_subject, expires_at);


	return ret;
}