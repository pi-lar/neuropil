/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sodium.h"
#include "event/ev.h"

#include "neuropil.h"

#include "dtime.h"
#include "np_log.h"
#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_dendrit.h"
#include "np_glia.h"
#include "np_http.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_route.h"

const char* np_major  = "0";
const char* np_minor  = "1";
const char* np_bugfix = "0";
const char* NP_VERSION = "0.1.0";

static np_state_t* __global_state = NULL;

np_state_t* _np_state ()
{
	return (__global_state);
}

np_bool _np_default_authorizefunc (np_aaatoken_t* token )
{
	log_msg(LOG_WARN, "using default handler to authorize %s", token->subject );
	log_msg(LOG_WARN, "do you really want the default authorize handler (allow all) ???");

	return (TRUE);
}

np_bool _np_aaa_authorizefunc (np_aaatoken_t* token )
{
	np_key_t* aaa_target;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->aaa_token = token;

//	log_msg(LOG_DEBUG, "realm             : %s", token->realm);
//	log_msg(LOG_DEBUG, "issuer            : %s", token->issuer);
//	log_msg(LOG_DEBUG, "subject           : %s", token->subject);
//	log_msg(LOG_DEBUG, "audience          : %s", token->audience);
//	log_msg(LOG_DEBUG, "uuid              : %s", token->uuid);
	log_msg(LOG_DEBUG, "realm authorization request for subject: %s", token->subject);

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHORIZATION_REQUEST);
	_np_job_submit_transform_event(0.0, aaa_props, aaa_target, NULL);

	np_free_obj(np_key_t, aaa_target);

	return (FALSE);
}

np_bool _np_default_authenticatefunc (np_aaatoken_t* token )
{
	log_msg(LOG_WARN, "using default handler to authenticate %s", token->subject);
	log_msg(LOG_WARN, "do you really want the default authenticate handler (trust all) ???");

	return (TRUE);
}

np_bool _np_aaa_authenticatefunc (np_aaatoken_t* token)
{
	np_key_t* aaa_target;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->aaa_token = token;

//	log_msg(LOG_DEBUG, "realm             : %s", token->realm);
//	log_msg(LOG_DEBUG, "issuer            : %s", token->issuer);
//	log_msg(LOG_DEBUG, "subject           : %s", token->subject);
//	log_msg(LOG_DEBUG, "audience          : %s", token->audience);
//	log_msg(LOG_DEBUG, "uuid              : %s", token->uuid);
	log_msg(LOG_DEBUG, "realm authentication request for subject: %s", token->subject);

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHENTICATION_REQUEST);
	_np_job_submit_transform_event(0.0, aaa_props, aaa_target, NULL);

	np_free_obj(np_key_t, aaa_target);

	return (FALSE);
}

np_bool _np_default_accountingfunc (np_aaatoken_t* token )
{
	log_msg(LOG_WARN, "using default handler to account for %s", token->subject );
	log_msg(LOG_WARN, "do you really want the default accounting handler (account nothing) ???");

	return (TRUE);
}

np_bool _np_aaa_accountingfunc (np_aaatoken_t* token)
{
	np_key_t* aaa_target;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->aaa_token = token;

//	log_msg(LOG_DEBUG, "realm             : %s", token->realm);
//	log_msg(LOG_DEBUG, "issuer            : %s", token->issuer);
//	log_msg(LOG_DEBUG, "subject           : %s", token->subject);
//	log_msg(LOG_DEBUG, "audience          : %s", token->audience);
//	log_msg(LOG_DEBUG, "uuid              : %s", token->uuid);

	log_msg(LOG_DEBUG, "realm accounting request for subject: %s", token->subject);

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_ACCOUNTING_REQUEST);
	_np_job_submit_transform_event(0.0, aaa_props, aaa_target, NULL);

	np_free_obj(np_key_t, aaa_target);
	return (FALSE);
}

void np_setauthorizing_cb(np_aaa_func_t aaaFunc)
{
	log_msg(LOG_INFO, "setting user defined authorization handler, that's good ...");
	__global_state->authorize_func = aaaFunc;
}

void np_setauthenticate_cb(np_aaa_func_t aaaFunc)
{
	log_msg(LOG_INFO, "setting user defined authentication handler, that's good ...");
	__global_state->authenticate_func = aaaFunc;
}

void np_setaccounting_cb(np_aaa_func_t aaaFunc)
{
	log_msg(LOG_INFO, "setting user defined accounting handler, that's good ...");
	__global_state->accounting_func = aaaFunc;
}

void np_send_join(const char* node_string)
{
	np_state_t* state = _np_state();
	np_key_t* node_key = NULL;

	_LOCK_MODULE(np_keycache_t)
	{
		node_key = _np_node_decode_from_str(node_string);
	}

	np_message_t* msg_out;

	np_tree_t* jrb_me = make_jtree();
	np_encode_aaatoken(jrb_me, state->my_identity->aaa_token);

	np_new_obj(np_message_t, msg_out);
	np_message_create(msg_out, node_key, state->my_node_key, _NP_MSG_JOIN_REQUEST, jrb_me);

	log_msg(LOG_DEBUG, "submitting join request to target key %s", _key_as_str(node_key));
	np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _NP_MSG_JOIN_REQUEST);
	_np_job_submit_msgout_event(0.0, prop, node_key, msg_out);

	np_free_obj(np_message_t, msg_out);
}

void np_set_realm_name(const char* realm_name)
{
	__global_state->realm_name = strndup(realm_name, 255);

	// create a new token
    np_aaatoken_t* auth_token = _np_create_node_token(__global_state->my_node_key->node);
    auth_token->state = AAA_VALID | AAA_AUTHENTICATED | AAA_AUTHORIZED;

	np_dhkey_t my_dhkey = _np_create_dhkey_for_token(auth_token); // dhkey_create_from_hostport(my_node->dns_name, my_node->port);
	np_key_t* new_node_key = _np_key_find_create(my_dhkey);

	// TODO: use ref/unref
	new_node_key->network = __global_state->my_node_key->network;
	__global_state->my_node_key->network = NULL;
	new_node_key->network->watcher.data = new_node_key;

	new_node_key->node = __global_state->my_node_key->node;
	__global_state->my_node_key->node = NULL;

	new_node_key->aaa_token = auth_token;

	// re-initialize routing table
    _np_route_set_key (new_node_key);

	// set and ref additional identity
    if (__global_state->my_identity == __global_state->my_node_key)
    {
        np_unref_obj(np_key_t, __global_state->my_identity);
        __global_state->my_identity = new_node_key;
        np_ref_obj(np_key_t, __global_state->my_identity);
    }
    else
    {
        // set target node string for correct routing
    	tree_replace_str(__global_state->my_identity->aaa_token->extensions, "target_node", new_val_s(_key_as_str(new_node_key)) );
    }
    __global_state->my_node_key = new_node_key;

	log_msg(LOG_INFO, "neuropil realm successfully set, node hash now: %s", _key_as_str(__global_state->my_node_key));
}

void np_enable_realm_slave()
{
    __global_state->authorize_func    = _np_aaa_authorizefunc;
    __global_state->authenticate_func = _np_aaa_authenticatefunc;
    __global_state->accounting_func   = _np_aaa_accountingfunc;

    __global_state->enable_realm_master = FALSE;
	__global_state->enable_realm_slave = TRUE;
}

void np_enable_realm_master()
{
	if (NULL == __global_state->realm_name)
	{
		return;
	}

	np_msgproperty_t* prop = NULL;

	// turn msg handlers for aaa to inbound msg as well
	prop = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHENTICATION_REQUEST);
	prop->mode_type |= INBOUND;
	sll_init(np_message_t, prop->msg_cache);

	prop = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHORIZATION_REQUEST);
	prop->mode_type |= INBOUND;
	sll_init(np_message_t, prop->msg_cache);
	if (NULL == prop->msg_audience)
	{
		prop->msg_audience = strndup(__global_state->realm_name, 255);
	}

	prop = np_msgproperty_get(OUTBOUND, _NP_MSG_ACCOUNTING_REQUEST);
	sll_init(np_message_t, prop->msg_cache);
	prop->mode_type |= INBOUND;
	if (NULL == prop->msg_audience)
	{
		prop->msg_audience = strndup(__global_state->realm_name, 255);
	}

	__global_state->enable_realm_master = TRUE;
	__global_state->enable_realm_slave = FALSE;
}

void np_waitforjoin()
{
	np_state_t* state = _np_state();
	while (FALSE == state->my_node_key->node->joined_network)
	{
		ev_sleep(0.31415);
	}
}

void np_set_listener (np_usercallback_t msg_handler, char* subject)
{
	// check whether an handler already exists
	np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, subject);

	if (NULL == msg_prop)
	{
		// create a default set of properties for listening to messages
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->mode_type = INBOUND;
		msg_prop->clb_inbound = _np_callback_wrapper;
		msg_prop->user_clb = msg_handler;
		np_msgproperty_register(msg_prop);
	}

	// update informations somewhere in the network
	_np_send_msg_interest(subject);
}

void np_set_identity(np_aaatoken_t* identity)
{
	np_state_t* state = _np_state();
    np_key_t* my_identity_key = NULL;

    // build a hash to find a place in the dhkey table, not for signing !
	np_dhkey_t search_key = _np_create_dhkey_for_token(identity);
	_LOCK_MODULE(np_keycache_t)
	{
		my_identity_key = _np_key_find_create(search_key);
	}

	if (NULL != state->my_identity)
	{
		// delete old identity
		np_unref_obj(np_key_t, state->my_identity);
	}

	if (NULL != my_identity_key)
	{
		// cannot be null, but otherwise checker complains
		state->my_identity = my_identity_key;
		state->my_identity->aaa_token = identity;
		np_ref_obj(np_aaatoken_t, identity);
	}

	// set target node string for correct routing
	tree_insert_str(identity->extensions, "target_node", new_val_s(_key_as_str(state->my_node_key)) );

    // create encryption parameter
	crypto_sign_keypair(identity->public_key, identity->private_key);
	_np_aaatoken_add_signature(identity);

}

void np_set_mx_property(char* subject, const char* key, np_val_t value)
{
	np_msgproperty_t* msg_prop = np_msgproperty_get(OUTBOUND, subject);
	if (NULL == msg_prop)
	{
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->clb_outbound = _np_out_send;

		np_msgproperty_register(msg_prop);
	}

	if (0 == strncmp(key, mode_type_str, strlen(mode_type_str)))
	{
		_np_msgproperty_t_set_mode_type(msg_prop, value.value.ush);
	}
	if (0 == strncmp(key, mep_type_str, strlen(mep_type_str)))
	{
		_np_msgproperty_t_set_mep_type(msg_prop, value.value.ush);
	}
	if (0 == strncmp(key, ack_mode_str, strlen(ack_mode_str)))
	{
		_np_msgproperty_t_set_ack_mode(msg_prop, value.value.ush);
	}
	if (0 == strncmp(key, ttl_str, strlen(ttl_str)))
	{
		_np_msgproperty_t_set_ttl(msg_prop, value.value.d);
	}
	if (0 == strncmp(key, retry_str, strlen(retry_str)))
	{
		_np_msgproperty_t_set_retry(msg_prop, value.value.ush);
	}
	if (0 == strncmp(key, max_threshold_str, strlen(max_threshold_str)))
	{
		_np_msgproperty_t_set_max_threshold(msg_prop, value.value.ui);
	}
	if (0 == strncmp(key, partner_key_str, strlen(partner_key_str)))
	{
		_np_msgproperty_t_set_partner_key(msg_prop, value.value.key);
	}
}

void np_rem_mx_property(char* subject, const char* key)
{
	np_msgproperty_t* msg_prop = np_msgproperty_get(OUTBOUND, subject);
	if (NULL == msg_prop)
	{
		return;
	}

	if (0 == strncmp(key, partner_key_str, strlen(partner_key_str)))
	{
		// _np_msgproperty_t_set_partner_key(msg_prop, 0);
	}
	else
	{
		log_msg(LOG_WARN, "cannot unset property %s", key);
	}
}

void np_send_msg (char* subject, np_tree_t *properties, np_tree_t *body)
{
	np_msgproperty_t* msg_prop = np_msgproperty_get(OUTBOUND, subject);
	if (NULL == msg_prop)
	{
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->mep_type = ANY_TO_ANY;
		msg_prop->mode_type = OUTBOUND;
		msg_prop->clb_outbound = _np_out_send;

		np_msgproperty_register(msg_prop);
	}

	np_message_t* msg = NULL;
	np_new_obj(np_message_t, msg);

	tree_insert_str(msg->header, NP_MSG_HEADER_SUBJECT, new_val_s((char*) subject));
	tree_insert_str(msg->header, NP_MSG_HEADER_FROM, new_val_s((char*) _key_as_str(_np_state()->my_node_key)));

	np_message_setbody(msg, body);
	np_message_setproperties(msg, properties);

	// msg_prop->msg_threshold++;
	_np_send_msg_availability(subject);

	_np_send_msg(subject, msg, msg_prop);

	np_free_obj(np_message_t, msg);
}

void np_send_text (char* subject, char *data, uint32_t seqnum)
{
	np_state_t* state = _np_state();

	np_msgproperty_t* msg_prop = np_msgproperty_get(OUTBOUND, subject);
	if (NULL == msg_prop)
	{
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->mep_type = ANY_TO_ANY;
		msg_prop->mode_type = OUTBOUND;
		msg_prop->clb_outbound = _np_out_send;

		np_msgproperty_register(msg_prop);
	}

	np_message_t* msg = NULL;
	np_new_obj(np_message_t, msg);

	tree_insert_str(msg->header, NP_MSG_HEADER_SUBJECT, new_val_s(subject));
	tree_insert_str(msg->header, NP_MSG_HEADER_FROM, new_val_s(_key_as_str(state->my_node_key)));
	tree_insert_str(msg->body,   NP_MSG_BODY_TEXT, new_val_s(data));

	tree_insert_str(msg->properties, NP_MSG_INST_SEQ, new_val_ul(seqnum));

	// msg_prop->msg_threshold++;
	_np_send_msg_availability(subject);

	_np_send_msg(subject, msg, msg_prop);

	np_free_obj(np_message_t, msg);
}

uint32_t np_receive_msg (char* subject, np_tree_t* properties, np_tree_t* body)
{
	// send out that we want to receive messages
	np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, subject);
	if (NULL == msg_prop)
	{
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->mep_type = ANY_TO_ANY;
		msg_prop->mode_type = INBOUND;
		msg_prop->clb_inbound = _np_signal;
		// when creating, set to zero because callback function is not used
		msg_prop->max_threshold = 0;

		// register the handler so that message can be received
		np_msgproperty_register(msg_prop);
	}
	msg_prop->max_threshold++;

	_np_send_msg_interest(subject);

	np_aaatoken_t* sender_token = NULL;
	np_message_t* msg = NULL;
	char* sender_id = NULL;
	np_bool msg_received = FALSE;

	do
	{	// first check or wait for available messages
		if (0 == sll_size(msg_prop->msg_cache))
		{
			LOCK_CACHE(msg_prop)
			{
				log_msg(LOG_DEBUG, "waiting for signal that a new message arrived %p", msg_prop);
				pthread_cond_wait(&msg_prop->msg_received, &msg_prop->lock);
				log_msg(LOG_DEBUG, "received signal that a new message arrived %p", msg_prop);
			}
		}
		msg = sll_first(msg_prop->msg_cache)->val;

		// next check or wait for valid sender tokens
		sender_id = tree_find_str(msg->header, NP_MSG_HEADER_FROM)->val.value.s;
		sender_token = _np_get_sender_token(subject, sender_id);
		if (NULL == sender_token)
		{
			// sleep for a while, token may need some time to arrive
			ev_sleep(0.31415);
			// dsleep(0.31415);
			continue;
		}

		msg_received = TRUE;

	} while (FALSE == msg_received);

	tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui--;
	msg_prop->msg_threshold--;

	// in receive function, we can only receive one message per call, different for callback function
	log_msg(LOG_DEBUG, "received message from cache %p ( cache-size: %d)", msg_prop, sll_size(msg_prop->msg_cache));
	msg = sll_head(np_message_t, msg_prop->msg_cache);

	log_msg(LOG_DEBUG, "decrypting message ...");
	np_bool decrypt_ok = np_message_decrypt_payload(msg, sender_token);

	if (FALSE == decrypt_ok)
	{
		log_msg(LOG_DEBUG, "decryption of message failed, deleting message");

		np_unref_obj(np_message_t, msg);
		np_unref_obj(np_aaatoken_t, sender_token);
		msg_prop->max_threshold--;

		return (FALSE);
	}

	// copy properties
	np_tree_elem_t* tmp = NULL;
	RB_FOREACH(tmp, np_tree_s, msg->properties)
	{
		if (tmp->key.type == char_ptr_type)      tree_insert_str(properties, tmp->key.value.s, tmp->val);
		if (tmp->key.type == int_type)           tree_insert_int(properties, tmp->key.value.i, tmp->val);
		if (tmp->key.type == double_type)        tree_insert_dbl(properties, tmp->key.value.d, tmp->val);
		if (tmp->key.type == unsigned_long_type) tree_insert_ulong(properties, tmp->key.value.ul, tmp->val);
	}

	// copy body
	tmp = NULL;
	RB_FOREACH(tmp, np_tree_s, msg->body)
	{
		if (tmp->key.type == char_ptr_type)      tree_insert_str(body, tmp->key.value.s, tmp->val);
		if (tmp->key.type == int_type)           tree_insert_int(body, tmp->key.value.i, tmp->val);
		if (tmp->key.type == double_type)        tree_insert_dbl(body, tmp->key.value.d, tmp->val);
		if (tmp->key.type == unsigned_long_type) tree_insert_ulong(body, tmp->key.value.ul, tmp->val);
	}

	uint8_t ack_mode = tree_find_str(msg->instructions, NP_MSG_INST_ACK)->val.value.ush;
	if (0 < (ack_mode & ACK_DESTINATION))
	{
		_np_send_ack(msg);
	}

	np_unref_obj(np_message_t, msg);
	np_unref_obj(np_aaatoken_t, sender_token);

	msg_prop->max_threshold--;

	return (TRUE);
}

uint32_t np_receive_text (char* subject, char **data)
{
	// send out that we want to receive messages
	np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, subject);
	if (NULL == msg_prop)
	{
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->mep_type = ANY_TO_ANY;
		msg_prop->mode_type = INBOUND;
		msg_prop->clb_inbound = _np_signal;
		// when creating, set to zero because callback function is not used
		msg_prop->max_threshold = 0;

		// register the handler so that message can be received
		np_msgproperty_register(msg_prop);
	}
	msg_prop->max_threshold++;

	_np_send_msg_interest(subject);

	np_aaatoken_t* sender_token = NULL;
	np_message_t* msg = NULL;
	char* sender_id = NULL;
	np_bool msg_received = FALSE;

	do
	{	// first check or wait for available messages
		if (0 == sll_size(msg_prop->msg_cache))
		{
			LOCK_CACHE(msg_prop)
			{
				log_msg(LOG_DEBUG, "waiting for signal that a new message arrived %p", msg_prop);
				pthread_cond_wait(&msg_prop->msg_received, &msg_prop->lock);
				log_msg(LOG_DEBUG, "received signal that a new message arrived %p", msg_prop);
			}
		}
		msg = sll_first(msg_prop->msg_cache)->val;

		// next check or wait for valid sender tokens
		sender_id = tree_find_str(msg->header, NP_MSG_HEADER_FROM)->val.value.s;
		sender_token = _np_get_sender_token(subject, sender_id);
		if (NULL == sender_token)
		{
			// sleep for a while, token may need some time to arrive
			ev_sleep(0.31415);
			// dsleep(0.31415);
			continue;
		}

		msg_received = TRUE;

	} while (FALSE == msg_received);

	tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui--;
	msg_prop->msg_threshold--;

	// in receive function, we can only receive one message per call, different for callback function
	log_msg(LOG_DEBUG, "received message from cache %p ( cache-size: %d)", msg_prop, sll_size(msg_prop->msg_cache));
	msg = sll_head(np_message_t, msg_prop->msg_cache);

	log_msg(LOG_DEBUG, "decrypting message ...");
	np_bool decrypt_ok = np_message_decrypt_payload(msg, sender_token);

	if (FALSE == decrypt_ok)
	{
		log_msg(LOG_DEBUG, "decryption of message failed, deleting message");

		np_unref_obj(np_message_t, msg);
		np_unref_obj(np_aaatoken_t, sender_token);
		msg_prop->max_threshold--;

		return (0);
	}

	uint32_t received = tree_find_str(msg->properties, NP_MSG_INST_SEQ)->val.value.ul;
	np_tree_elem_t* reply_data = tree_find_str(msg->body, NP_MSG_BODY_TEXT);
	*data = strndup(reply_data->val.value.s, strlen(reply_data->val.value.s));

	uint8_t ack_mode = tree_find_str(msg->instructions, NP_MSG_INST_ACK)->val.value.ush;
	if (0 < (ack_mode & ACK_DESTINATION))
	{
		_np_send_ack(msg);
	}

	np_unref_obj(np_message_t, msg);
	np_unref_obj(np_aaatoken_t, sender_token);
	msg_prop->max_threshold--;

	log_msg(LOG_INFO, "someone sending us messages %s !!!", *data);

	return (received);
}

void _np_send_ack(np_message_t* in_msg)
{
	np_state_t* state = _np_state();

	// uint8_t ack = ACK_NONE;
	uint32_t seq = 0;
	char* uuid = NULL;

	// np_message_t* in_msg = args->msg;

	if (NULL != tree_find_str(in_msg->header, NP_MSG_INST_ACK_TO))
	{
		// extract data from incoming message
		seq = tree_find_str(in_msg->instructions, NP_MSG_INST_SEQ)->val.value.ul;
		// ack = tree_find_str(in_msg->instructions, NP_MSG_INST_ACK)->val.value.ush;
		uuid = tree_find_str(in_msg->instructions, NP_MSG_INST_UUID)->val.value.s;

		// create new ack message & handlers
		np_dhkey_t ack_key = dhkey_create_from_hash(
				tree_find_str(in_msg->header, NP_MSG_INST_ACK_TO)->val.value.s);

		// TODO: find in keycache, must be present
		np_key_t* ack_target;
		np_new_obj(np_key_t, ack_target);
		ack_target->dhkey = ack_key;

		np_message_t* ack_msg = NULL;
		np_new_obj(np_message_t, ack_msg);

		np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _NP_MSG_ACK);

		np_message_create(ack_msg, ack_target, state->my_node_key, _NP_MSG_ACK, NULL);
		tree_insert_str(ack_msg->instructions, NP_MSG_INST_ACK, new_val_ush(prop->ack_mode));
		tree_insert_str(ack_msg->instructions, NP_MSG_INST_ACKUUID, new_val_s(uuid));
		tree_insert_str(ack_msg->instructions, NP_MSG_INST_SEQ, new_val_ul(seq));
		// send the ack out
		_np_job_submit_route_event(0.0, prop, ack_target, ack_msg);

		np_free_obj(np_message_t, ack_msg);
	}
}

/**
 ** np_ping:
 ** sends a PING message to another node. The message is acknowledged in network layer.
 **/
void _np_ping (np_key_t* key)
{
	np_state_t* state = _np_state();
	/* weired: assume failure of the node now, will be reset with ping reply later */
	if (NULL != key->node)
	{
		key->node->failuretime = ev_time();
		np_node_update_stat(key->node, 0);
	}

    np_message_t* out_msg = NULL;
    np_new_obj(np_message_t, out_msg);

    np_message_create (out_msg, key, state->my_node_key, _NP_MSG_PING_REQUEST, NULL);
    log_msg(LOG_DEBUG, "ping request to: %s", _key_as_str(key));

    np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _NP_MSG_PING_REQUEST);
	_np_job_submit_msgout_event(0.0, prop, key, out_msg);

	np_free_obj(np_message_t, out_msg);
}

/**
 ** np_destroy:
 ** destroys the neuropil data structures and cleans memory that has been used
 **/
void np_destroy()
{

}

/**
 ** np_init:
 ** initializes neuropil on specified port and returns the const np_state_t* which
 ** contains global state of different neuropil modules.
 **/
np_state_t* np_init(char* proto, char* port, np_bool start_http)
{
    // encryption and memory protection
    sodium_init();
    // memory pool
	np_mem_init();

	// initialize key min max ranges
    _dhkey_init();

    // global neuropil structure
    np_state_t *state = (np_state_t *) malloc (sizeof (np_state_t));
    if (state == NULL)
	{
    	log_msg(LOG_ERROR, "neuropil_init: state module not created: %s", strerror (errno));
	    exit(1);
	}
    memset(state, 0, sizeof(np_state_t));
    __global_state = state;

    // splay tree initializing
	_np_keycache_init();

    //
    // TODO: read my own identity from file, if a e.g. a password is given
    //
    // set default aaa functions
    state->authorize_func    = _np_default_authorizefunc;
    state->authenticate_func = _np_default_authenticatefunc;
    state->accounting_func   = _np_default_accountingfunc;

    state->enable_realm_slave = FALSE;
    state->enable_realm_master = FALSE;

	char* np_service = "3141";
	uint8_t np_proto = UDP | IPv6;

	if (NULL != port)
	{
		np_service = port;
	}
	if (NULL != proto)
	{
		np_proto = np_parse_protocol_string(proto);
		log_msg(LOG_DEBUG, "now initializing networking for %s:%s", proto, np_service);
	}
	else
	{
		log_msg(LOG_DEBUG, "now initializing networking for udp6://%s", np_service);
	}

	np_node_t* my_node = NULL;
    np_new_obj(np_node_t, my_node);

    np_network_t* my_network = NULL;
    np_new_obj(np_network_t, my_network);

    // listen on all network interfaces
    char hostname[255];
    gethostname(hostname, 255);
	network_init(my_network, TRUE, np_proto, hostname, np_service);
	if (FALSE == my_network->initialized)
	{
    	log_msg(LOG_ERROR, "neuropil_init: network_init failed, see log for details");
	    exit(1);
	}

	np_node_update(my_node, np_proto, hostname, np_service);

	log_msg(LOG_DEBUG, "neuropil_init: network_init for %s:%s:%s",
			           np_get_protocol_string(my_node->protocol), my_node->dns_name, my_node->port);

    // create a new token for encryption each time neuropil starts
    np_aaatoken_t* auth_token = _np_create_node_token(my_node);
    auth_token->state = AAA_VALID | AAA_AUTHENTICATED | AAA_AUTHORIZED;

	np_dhkey_t my_dhkey = _np_create_dhkey_for_token(auth_token); // dhkey_create_from_hostport(my_node->dns_name, my_node->port);
    state->my_node_key = _np_key_find_create(my_dhkey);

    my_network->watcher.data = state->my_node_key;
    // log_msg(LOG_WARN, "node_key %p", state->my_node_key);

    state->my_node_key->node = my_node;
    state->my_node_key->network = my_network;
    state->my_node_key->aaa_token = auth_token;

    // set and ref additional identity
    state->my_identity = state->my_node_key;
    np_ref_obj(np_key_t, state->my_identity);

    // initialize routing table
    if (FALSE == _np_route_init (state->my_node_key) )
    {
		log_msg(LOG_ERROR, "neuropil_init: route_init failed: %s", strerror (errno));
	    exit(1);
	}
    // initialize job queue
    if (FALSE == _np_job_queue_create())
	{
    	log_msg(LOG_ERROR, "neuropil_init: job_queue_create failed: %s", strerror (errno));
	    exit(1);
	}
    // initialize message handling system
    if (FALSE == _np_msgproperty_init())
	{
    	log_msg(LOG_ERROR, "neuropil_init: job_queue_create failed: %s", strerror (errno));
	    exit(1);
	}

    state->msg_tokens = make_jtree();
    state->msg_part_cache = make_jtree();

    if (TRUE == start_http)
    {
    	if (FALSE == _np_http_init())
    	{
        	log_msg(LOG_WARN, "neuropil_init: initialization of http interface failed");
    	}
    }

    // initialize real network layer last
    np_job_submit_event(0.0, _np_cleanup_ack);
	np_job_submit_event(0.0, _np_cleanup_keycache);
    // start leafset checking jobs
    np_job_submit_event(0.0, _np_check_leafset);

#ifdef SKIP_EVLOOP
    // intialize log file writing
    np_job_submit_event(0.0, _np_write_log);
    // np_job_submit_event(0.0, _np_events_read);
#endif

    // initialize retransmission of tokens
    np_job_submit_event(0.0, _np_retransmit_tokens);
    // initialize network/io reading and writing
    np_job_submit_event(0.0, _np_events_read);

	log_msg(LOG_INFO, "neuropil successfully initialized: %s", _key_as_str(state->my_node_key));
	_np_log_fflush();

	return (state);
}

void np_start_job_queue(uint8_t pool_size)
{
	if (pthread_attr_init (&__global_state->attr) != 0)
	{
	    log_msg (LOG_ERROR, "pthread_attr_init: %s", strerror (errno));
	    return;
	}

    if (pthread_attr_setscope (&__global_state->attr, PTHREAD_SCOPE_SYSTEM) != 0)
	{
	    log_msg (LOG_ERROR, "pthread_attr_setscope: %s", strerror (errno));
	    return;
	}

    if (pthread_attr_setdetachstate (&__global_state->attr, PTHREAD_CREATE_DETACHED) != 0)
	{
    	log_msg (LOG_ERROR, "pthread_attr_setdetachstate: %s", strerror (errno));
	    return;
	}

    __global_state->thread_ids = (pthread_t *) malloc (sizeof (pthread_t) * pool_size);

    /* create the thread pool */
    for (uint8_t i = 0; i < pool_size; i++)
    {
        pthread_create (&__global_state->thread_ids[i], &__global_state->attr, _job_exec, (void *) __global_state);
    	log_msg(LOG_DEBUG, "neuropil worker thread started: %p", __global_state->thread_ids[i]);
   	}
	log_msg(LOG_DEBUG, "neuropil (version %s) event loop with %d threads started", NP_VERSION, pool_size);

	fprintf(stdout, "\n");
	fprintf(stdout, "neuropil (version %s) initializiation successful\n", NP_VERSION);
	fprintf(stdout, "neuropil (version %s) event loop with %d worker threads started\n", NP_VERSION, pool_size);
	fprintf(stdout, "your neuropil node will be addressable as:\n");
	fprintf(stdout, "\t%s:%s:%s:%s\n",
					_key_as_str(__global_state->my_node_key),
					np_get_protocol_string(__global_state->my_node_key->node->protocol),
					__global_state->my_node_key->node->dns_name,
					__global_state->my_node_key->node->port);
	fprintf(stdout, "\n");
	fflush(stdout);
}

