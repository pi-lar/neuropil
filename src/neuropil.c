//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
 
#include "sodium.h"
#include "event/ev.h"

#include "neuropil.h"

#include "np_log.h"
#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_dendrit.h"
#include "np_glia.h"
#include "np_http.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_route.h"
#include "np_event.h"
#include "np_types.h"
#include "np_settings.h"
#include "np_sysinfo.h"
#include "np_constants.h"

NP_SLL_GENERATE_IMPLEMENTATION(np_usercallback_t);


/**
 * Gets a np_key_t or a NULL pointer for the given hash value.
 * Generates warnings and aborts the process if a misschief configuration is found.
 * @param targetDhkey hash value of a node
 * @return
 */
np_key_t* _np_get_key_by_key_hash(char* targetDhkey) ;

static np_state_t* __global_state = NULL;
/**
 * The current state/context variable for the whole neuropil process
 * @return
 */
np_state_t* _np_state ()
{
	return (__global_state);
}
/**
 * The default authorize function, allows all authorizations and generates warnings
 * @param token
 * @return
 */
np_bool _np_default_authorizefunc (np_aaatoken_t* token )
{
#ifndef DEBUG
	log_msg(LOG_WARN, "using default handler (authorize all) to authorize %s", token->subject );
	// log_msg(LOG_WARN, "do you really want the default authorize handler (allow all) ???");
#endif
	return (TRUE);
}
/**
 * The default realm slave authorize function. Forwards the authorization request to the realm master
 * @param token
 * @return
 */
np_bool _np_aaa_authorizefunc (np_aaatoken_t* token )
{
	np_key_t* aaa_target = NULL;
	np_new_obj(np_key_t, aaa_target);
	np_ref_obj(np_aaatoken_t, token, ref_key_aaa_token);
	aaa_target->aaa_token = token;

//	log_debug_msg(LOG_DEBUG, "realm             : %s", token->realm);
//	log_debug_msg(LOG_DEBUG, "issuer            : %s", token->issuer);
//	log_debug_msg(LOG_DEBUG, "subject           : %s", token->subject);
//	log_debug_msg(LOG_DEBUG, "audience          : %s", token->audience);
//	log_debug_msg(LOG_DEBUG, "uuid              : %s", token->uuid);
	log_debug_msg(LOG_DEBUG, "realm authorization request for subject: %s", token->subject);

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHORIZATION_REQUEST);
	_np_job_submit_transform_event(0.0, aaa_props, aaa_target, NULL);

	np_unref_obj(np_key_t, aaa_target, ref_obj_creation);

	return (FALSE);
}

/**
 * The default authenticate function, allows all authorizations and generates warnings
 * @param token
 * @return
 */
np_bool _np_default_authenticatefunc (np_aaatoken_t* token )
{
#ifndef DEBUG
	log_msg(LOG_WARN, "using default handler (auth all) to authenticate %s", token->subject);
	// log_msg(LOG_WARN, "do you really want the default authenticate handler (trust all) ???");
#endif
	return (TRUE);
}

/**
 * The default realm slave authenticate function. Forwards the authenticate request to the realm master
 * @param token
 * @return
 */
np_bool _np_aaa_authenticatefunc (np_aaatoken_t* token)
{
	np_key_t* aaa_target = NULL;
	np_new_obj(np_key_t, aaa_target);
	np_ref_obj(np_aaatoken_t, token, ref_key_aaa_token);
	aaa_target->aaa_token = token;

//	log_debug_msg(LOG_DEBUG, "realm             : %s", token->realm);
//	log_debug_msg(LOG_DEBUG, "issuer            : %s", token->issuer);
//	log_debug_msg(LOG_DEBUG, "subject           : %s", token->subject);
//	log_debug_msg(LOG_DEBUG, "audience          : %s", token->audience);
//	log_debug_msg(LOG_DEBUG, "uuid              : %s", token->uuid);
	log_debug_msg(LOG_DEBUG, "realm authentication request for subject: %s", token->subject);

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHENTICATION_REQUEST);
	_np_job_submit_transform_event(0.0, aaa_props, aaa_target, NULL);

	np_unref_obj(np_key_t, aaa_target, ref_obj_creation);

	return (FALSE);
}
/**
 * The default accounting function, allows all authorizations and generates warnings
 * @param token
 * @return
 */
np_bool _np_default_accountingfunc (np_aaatoken_t* token )
{
#ifndef DEBUG
	log_msg(LOG_WARN, "using default handler to account for %s", token->subject );
	// log_msg(LOG_WARN, "do you really want the default accounting handler (account nothing) ???");
#endif
	return (TRUE);
}

/**
 * The default realm slave accounting function. Forwards the accounting request to the realm master
 * @param token
 * @return
 */
np_bool _np_aaa_accountingfunc (np_aaatoken_t* token)
{
	np_key_t* aaa_target = NULL;
	np_new_obj(np_key_t, aaa_target);
	np_ref_obj(np_aaatoken_t, token, ref_key_aaa_token);
	aaa_target->aaa_token = token;

//	log_debug_msg(LOG_DEBUG, "realm             : %s", token->realm);
//	log_debug_msg(LOG_DEBUG, "issuer            : %s", token->issuer);
//	log_debug_msg(LOG_DEBUG, "subject           : %s", token->subject);
//	log_debug_msg(LOG_DEBUG, "audience          : %s", token->audience);
//	log_debug_msg(LOG_DEBUG, "uuid              : %s", token->uuid);

	log_debug_msg(LOG_DEBUG, "realm accounting request for subject: %s", token->subject);

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_ACCOUNTING_REQUEST);
	_np_job_submit_transform_event(0.0, aaa_props, aaa_target, NULL);

	np_unref_obj(np_key_t, aaa_target, ref_obj_creation);
	return (FALSE);
}
/**
 * Sets the callback for authorization requests against this node
 * @param aaaFunc
 */
void np_setauthorizing_cb(np_aaa_func_t aaaFunc)
{
	log_msg(LOG_TRACE, "start: void np_setauthorizing_cb(np_aaa_func_t aaaFunc){");
	log_msg(LOG_INFO, "setting user defined authorization handler, that's good ...");
	_np_state()->authorize_func = aaaFunc;
}
/**
 * Sets the callback for authentication requests against this node
 * @param aaaFunc
 */
void np_setauthenticate_cb(np_aaa_func_t aaaFunc)
{
	log_msg(LOG_TRACE, "start: void np_setauthenticate_cb(np_aaa_func_t aaaFunc){");
	log_msg(LOG_INFO, "setting user defined authentication handler, that's good ...");
	_np_state()->authenticate_func = aaaFunc;
}
/**
 * Sets the callback for accounting requests against this node
 * @param aaaFunc
 */
void np_setaccounting_cb(np_aaa_func_t aaaFunc)
{
	log_msg(LOG_TRACE, "start: void np_setaccounting_cb(np_aaa_func_t aaaFunc){");
	log_msg(LOG_INFO, "setting user defined accounting handler, that's good ...");
	_np_state()->accounting_func = aaaFunc;
}
/**
 * Sends a JOIN request to the given node string.
 * Please see @np_get_connection_string() for the node_string definition
 * @param node_string
 */
void np_send_join(const char* node_string)
{
	log_msg(LOG_TRACE, "start: void np_send_join(const char* node_string){");

	if(node_string[0] == '*') {
		const char* node_string_2 = node_string + 2;
		log_msg(LOG_INFO, "Assumed wildcard join for \"%s\"", node_string);
		// node_string2 += 2;
		np_send_wildcard_join(node_string_2);

	} else {
		np_key_t* node_key = NULL;

		node_key = _np_node_decode_from_str(node_string);
		_np_send_simple_invoke_request(node_key, _NP_MSG_JOIN_REQUEST);

		np_route_set_bootstrap_key(node_key);

		np_unref_obj(np_key_t, node_key,"_np_node_decode_from_str"); // _np_node_decode_from_str
	}
}

/**
 * Takes a node connection string and tries to connect to any node available on the other end.
 * node_string should not contain a hash value (nor the trailing: character).
 * Example: np_send_wildcard_join("udp4:example.com:1234");
 */
void np_send_wildcard_join(const char* node_string)
{
	log_msg(LOG_TRACE, "start: void np_send_wildcard_join(const char* node_string){");
	/**
	 * Wir erzeugen einen festen hash key der als wildcard fungiert.
	 * Anschließend wird diesem der node_string mit allen anderen informationen (dns/port/etc) hinzugefügt.
	 * Beim handshake wird festgestellt das es für diese Zusatzinformationen (dns/port) einen wildcard key bereits gibt.
	 * Der wildcard key wird dann mit den tatsächlichen dhkey informationen angereichert.
	 * So wird aus dem wildcard key ein vollwertiger key eintrag in der routing Tabelle.
	 */

	char* wildcard_node_str = NULL;
	np_key_t* wildcard_node_key = NULL;

	//START Build our wildcard connection string
	np_dhkey_t wildcard_dhkey = np_dhkey_create_from_hostport("*", node_string);
	char wildcard_dhkey_str[65];
	_np_dhkey_to_str(&wildcard_dhkey, wildcard_dhkey_str);
	asprintf(&wildcard_node_str, "%s:%s", wildcard_dhkey_str, node_string);
	//END Build our wildcard connection string

	wildcard_node_key = _np_node_decode_from_str(wildcard_node_str);
	free(wildcard_node_str);

	// proposal: only invoke handshake ?
    _np_network_send_handshake(wildcard_node_key);

	np_route_set_bootstrap_key(wildcard_node_key);
	np_unref_obj(np_key_t, wildcard_node_key, "_np_node_decode_from_str");
}

/**
 * Sets the realm name of the node.
 * RECONFIGURES THE NODE HASH! The old node hash will be forgotten.
 * @param realm_name
 */
void np_set_realm_name(const char* realm_name)
{
	log_msg(LOG_TRACE, "start: void np_set_realm_name(const char* realm_name){");
	_np_state()->realm_name = strndup(realm_name, 255);

	// create a new token
	np_aaatoken_t* auth_token = _np_node_create_token(_np_state()->my_node_key->node);
	auth_token->state = AAA_VALID | AAA_AUTHENTICATED | AAA_AUTHORIZED;

	np_dhkey_t my_dhkey = _np_aaatoken_create_dhkey(auth_token); // np_dhkey_create_from_hostport(my_node->dns_name, my_node->port);
	np_key_t* new_node_key = _np_keycache_find_or_create(my_dhkey);

	new_node_key->network = _np_state()->my_node_key->network;
	np_ref_obj(np_network_t, new_node_key->network, ref_key_network);

	_np_state()->my_node_key->network = NULL;

	np_ref_obj(np_key_t, new_node_key,ref_network_watcher);
	new_node_key->network->watcher.data = new_node_key;

	new_node_key->node = _np_state()->my_node_key->node;
	np_ref_obj(np_node_t, new_node_key->node, ref_key_node);

	_np_state()->my_node_key->node = NULL;

	np_ref_obj(np_aaatoken_t, auth_token, ref_key_aaa_token);
	new_node_key->aaa_token = auth_token;

	// re-initialize routing table
	_np_route_set_key (new_node_key);

	// set and ref additional identity
	//TODO: use np_set_identity
	if (_np_state()->my_identity == _np_state()->my_node_key)
	{
		np_ref_switch(np_key_t, _np_state()->my_identity, ref_state_identity, new_node_key);
	}
	else
	{
		// set target node string for correct routing
		np_tree_replace_str(_np_state()->my_identity->aaa_token->extensions, "target_node", np_treeval_new_s(_np_key_as_str(new_node_key)) );
	}
	_np_state()->my_node_key = new_node_key;

	log_msg(LOG_INFO, "neuropil realm successfully set, node hash now: %s", _np_key_as_str(_np_state()->my_node_key));

	np_unref_obj(np_key_t, new_node_key,"_np_keycache_find_or_create");
}
/**
 * Enables this node as realm slave.
 * The node will forward all aaa requests to the realm master
 */
void np_enable_realm_slave()
{
	log_msg(LOG_TRACE, "start: void np_enable_realm_slave(){");
	_np_state()->authorize_func    = _np_aaa_authorizefunc;
	_np_state()->authenticate_func = _np_aaa_authenticatefunc;
	_np_state()->accounting_func   = _np_aaa_accountingfunc;

	_np_state()->enable_realm_master = FALSE;
	_np_state()->enable_realm_slave = TRUE;
}
/**
 * Enables this node as realm master.
 */
void np_enable_realm_master()
{
	log_msg(LOG_TRACE, "start: void np_enable_realm_master(){");
	if (NULL == _np_state()->realm_name)
	{
		return;
	}

	np_msgproperty_t* prop = NULL;

	// turn msg handlers for aaa to inbound msg as well
	prop = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHENTICATION_REQUEST);
	if (NULL == prop->msg_audience)
	{
		prop->msg_audience = strndup(_np_state()->realm_name, 255);
	}

	prop = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHORIZATION_REQUEST);
	if (NULL == prop->msg_audience)
	{
		prop->msg_audience = strndup(_np_state()->realm_name, 255);
	}

	prop = np_msgproperty_get(OUTBOUND, _NP_MSG_ACCOUNTING_REQUEST);
	if (NULL == prop->msg_audience)
	{
		prop->msg_audience = strndup(_np_state()->realm_name, 255);
	}

	_np_state()->enable_realm_master = TRUE;
	_np_state()->enable_realm_slave = FALSE;
}

/**
 * Waits till this node is connected to a network.
 * WARNING! Blocks the current thread and does not have a timeout!
 */
void np_waitforjoin()
{
	log_msg(LOG_TRACE, "start: void np_waitforjoin(){");
	np_state_t* state = _np_state();
	while (FALSE == state->my_node_key->node->joined_network)
	{
		ev_sleep(0.31415/2);
	}
}

/**
* Sets a callback for a given msg subject.
* Each msg for the given subject may invoke this handler.
* @param msg_handler
* @param subject
*/
void np_add_receive_listener(np_usercallback_t msg_handler, char* subject)
{
	// check whether an handler already exists
	np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, subject);

	if (NULL == msg_prop)
	{
		// create a default set of properties for listening to messages
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->mode_type = INBOUND;
		np_msgproperty_register(msg_prop);		
	}
	
	msg_prop->clb_inbound = _np_in_callback_wrapper;

	sll_append(np_usercallback_t, msg_prop->user_receive_clb, msg_handler);

	// update informations somewhere in the network
	_np_send_subject_discovery_messages(INBOUND, subject);
}

/**
* Sets a callback for a given msg subject.
* Each msg for the given subject may invoke this handler.
* @param msg_handler
* @param subject
*/
void np_add_send_listener(np_usercallback_t msg_handler, char* subject)
{
	// check whether an handler already exists
	np_msgproperty_t* msg_prop = np_msgproperty_get(OUTBOUND, subject);

	if (NULL == msg_prop)
	{
		// create a default set of properties for listening to messages
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->mode_type = OUTBOUND;
		np_msgproperty_register(msg_prop);
	}

	sll_append(np_usercallback_t, msg_prop->user_send_clb, msg_handler);
}

/**
 * Sets the identity of the node.
 * @param identity
 */
void np_set_identity(np_aaatoken_t* identity)
{
	log_msg(LOG_TRACE, "start: void np_set_identity(np_aaatoken_t* identity){");
	np_state_t* state = _np_state();

	// build a hash to find a place in the dhkey table, not for signing !
	np_dhkey_t search_key = _np_aaatoken_create_dhkey(identity);
	np_key_t* my_identity_key = _np_keycache_find_or_create(search_key);

	if (NULL != state->my_identity)
	{
		np_ref_switch(np_key_t, state->my_identity, ref_state_identity, my_identity_key);
	}
	else
	{
		// cannot be null, but otherwise checker complains
		np_ref_obj(np_key_t, my_identity_key, ref_state_identity); 
		state->my_identity = my_identity_key;		

		np_aaatoken_t* old_aaatoken = state->my_identity->aaa_token;		
		np_ref_obj(np_aaatoken_t, identity, ref_key_aaa_token); 
		state->my_identity->aaa_token = identity;

		if (old_aaatoken != NULL) {
			np_unref_obj(np_aaatoken_t, old_aaatoken, ref_key_aaa_token);
		}
	}
	// set target node string for correct routing
	np_tree_insert_str(identity->extensions, "target_node", np_treeval_new_s(_np_key_as_str(state->my_node_key)) );

	// create encryption parameter
	crypto_sign_keypair(identity->public_key, identity->private_key);
    identity->private_key_is_set = TRUE;
    // _np_aaatoken_add_signature(identity);
	np_unref_obj(np_key_t, my_identity_key,"_np_keycache_find_or_create");

}


/**
 * Sets the property key for the subject np_msgproperty_t to a given value.
 * If the subject does not have a np_msgproperty_t a new one will be created and registered.
 * All primitive types properties can be edited.
 * @param subject
 * @param key
 * @param value
 */
void np_set_mx_property(char* subject, const char* key, np_treeval_t value)
{
	log_msg(LOG_TRACE, "start: void np_set_mx_property(char* subject, const char* key, np_treeval_t value){");
	// TODO: rework key from char to enum
	np_msgproperty_t* msg_prop = np_msgproperty_get(OUTBOUND, subject);
	if (NULL == msg_prop)
	{
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->clb_outbound = _np_send;

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
	if (0 == strncmp(key, msg_ttl_str, strlen(msg_ttl_str)))
	{
		_np_msgproperty_t_set_msg_ttl(msg_prop, value.value.d);
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
	log_msg(LOG_TRACE, "start: void np_rem_mx_property(char* subject, const char* key){");
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

void np_send_msg (char* subject, np_tree_t *properties, np_tree_t *body, np_dhkey_t* target_key )
{
	np_msgproperty_t* msg_prop = np_msgproperty_get(OUTBOUND, subject);
	if (NULL == msg_prop)
	{
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->mep_type = ANY_TO_ANY;
		msg_prop->mode_type |= OUTBOUND;

		np_msgproperty_register(msg_prop);
	}
	msg_prop->clb_outbound = _np_send;

	np_message_t* msg = NULL;
	np_new_obj(np_message_t, msg);

	np_tree_insert_str(msg->header, _NP_MSG_HEADER_SUBJECT, np_treeval_new_s((char*) subject));
	np_tree_insert_str(msg->header, _NP_MSG_HEADER_FROM, np_treeval_new_s((char*) _np_key_as_str(_np_state()->my_node_key)));

	_np_message_setbody(msg, body);
	_np_message_setproperties(msg, properties);

	// msg_prop->msg_threshold++;
	// _np_send_msg_availability(subject);
	_np_send_subject_discovery_messages(OUTBOUND, subject);

	// char tmp_dhkey_hash[65];
	// _np_dhkey_to_str(target_key,tmp_dhkey_hash);
	// np_key_t* target = _np_get_key_by_key_hash(tmp_dhkey_hash);

	_np_send_msg(subject, msg, msg_prop, target_key);

	np_unref_obj(np_message_t, msg, ref_obj_creation);
}

np_key_t* _np_get_key_by_key_hash(char* targetDhkey)
{
	log_msg(LOG_TRACE, "start: np_key_t* _np_get_key_by_key_hash(char* targetDhkey){");
	np_key_t* target = NULL;

	if (NULL != targetDhkey) {

		target = _np_keycache_find_by_details(targetDhkey, FALSE, TRUE, TRUE, TRUE, FALSE, FALSE, TRUE);

		if (NULL == target) {
			log_msg(LOG_WARN,
					"could not find the specific target %s for message. broadcasting msg", targetDhkey);
		} else {
			log_debug_msg(LOG_DEBUG, "could find the specific target %s for message.", targetDhkey);
		}

		if (NULL != target && strcmp(_np_key_as_str(target), targetDhkey) != 0) {
			log_msg(LOG_ERROR,
					"Found target key (%s) does not match requested target key (%s)! Aborting",
					_np_key_as_str(target), targetDhkey);
			exit(EXIT_FAILURE);
		}
	}
	return target;
}

void np_send_text (char* subject, char *data, uint32_t seqnum, char* targetDhkey)
{
	np_state_t* state = _np_state();

	np_msgproperty_t* msg_prop = np_msgproperty_get(OUTBOUND, subject);
	if (NULL == msg_prop)
	{
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->mep_type = ANY_TO_ANY;
		msg_prop->mode_type = OUTBOUND;

		np_msgproperty_register(msg_prop);
	}
	msg_prop->clb_outbound = _np_send;

	np_message_t* msg = NULL;
	np_new_obj(np_message_t, msg);

	np_tree_insert_str(msg->header, _NP_MSG_HEADER_SUBJECT, np_treeval_new_s(subject));
	np_tree_insert_str(msg->header, _NP_MSG_HEADER_FROM, np_treeval_new_s(_np_key_as_str(state->my_node_key)));
	np_tree_insert_str(msg->body,   NP_MSG_BODY_TEXT, np_treeval_new_s(data));

	np_tree_insert_str(msg->properties, _NP_MSG_INST_SEQ, np_treeval_new_ul(seqnum));

	_np_send_subject_discovery_messages(OUTBOUND, subject);

	np_key_t* target = _np_get_key_by_key_hash(targetDhkey);

	_np_send_msg(subject, msg, msg_prop, NULL == target ? NULL: &target->dhkey);

	np_unref_obj(np_message_t, msg, ref_obj_creation);
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
		msg_prop->clb_inbound = _np_in_signal_np_receive;
		// when creating, set to zero because callback function is not used
		msg_prop->max_threshold = 0;

		// register the handler so that message can be received
		np_msgproperty_register(msg_prop);
	}
	msg_prop->max_threshold++;

	// _np_send_msg_interest(subject);
	_np_send_subject_discovery_messages(INBOUND, subject);

	np_aaatoken_t* sender_token = NULL;
	np_message_t* msg = NULL;
	char* sender_id = NULL;
	np_bool msg_received = FALSE;

	do
	{	// first check or wait for available messages
		if (0 == sll_size(msg_prop->msg_cache_in))
		{
			_LOCK_ACCESS(&msg_prop->lock)
			{
				log_debug_msg(LOG_DEBUG, "waiting for signal that a new message arrived %p", msg_prop);
				_np_threads_condition_wait(&msg_prop->msg_received, &msg_prop->lock);
				log_debug_msg(LOG_DEBUG, "received signal that a new message arrived %p", msg_prop);
			}
		}
		msg = sll_first(msg_prop->msg_cache_in)->val;

		// next check or wait for valid sender tokens
		sender_id = np_tree_find_str(msg->header, _NP_MSG_HEADER_FROM)->val.value.s;
		sender_token = _np_aaatoken_get_sender(subject, sender_id);
		if (NULL == sender_token)
		{
			// sleep for a while, token may need some time to arrive
			ev_sleep(0.31415);
			// dsleep(0.31415);
			continue;
		}

		msg_received = TRUE;
		np_tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;

	} while (FALSE == msg_received);

	// in receive function, we can only receive one message per call, different for callback function
	log_debug_msg(LOG_DEBUG, "received message from cache %p ( cache-size: %d)", msg_prop, sll_size(msg_prop->msg_cache_in));
	msg = sll_head(np_message_ptr, msg_prop->msg_cache_in);

	log_debug_msg(LOG_DEBUG, "decrypting message ...");
	np_bool decrypt_ok = _np_message_decrypt_payload(msg, sender_token);

	if (FALSE == decrypt_ok)
	{
		log_debug_msg(LOG_DEBUG, "decryption of message failed, deleting message");
		np_tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui--;
		msg_prop->max_threshold--;

		np_unref_obj(np_message_t, msg,"?");
		np_unref_obj(np_aaatoken_t, sender_token,"?");
		return (FALSE);
	}

	// copy properties
	np_tree_elem_t* tmp = NULL;
	RB_FOREACH(tmp, np_tree_s, msg->properties)
	{
		if (tmp->key.type == char_ptr_type)      np_tree_insert_str(properties, tmp->key.value.s, tmp->val);
		if (tmp->key.type == int_type)           np_tree_insert_int(properties, tmp->key.value.i, tmp->val);
		if (tmp->key.type == double_type)        np_tree_insert_dbl(properties, tmp->key.value.d, tmp->val);
		if (tmp->key.type == unsigned_long_type) np_tree_insert_ulong(properties, tmp->key.value.ul, tmp->val);
	}

	// copy body
	tmp = NULL;
	RB_FOREACH(tmp, np_tree_s, msg->body)
	{
		if (tmp->key.type == char_ptr_type)      np_tree_insert_str(body, tmp->key.value.s, tmp->val);
		if (tmp->key.type == int_type)           np_tree_insert_int(body, tmp->key.value.i, tmp->val);
		if (tmp->key.type == double_type)        np_tree_insert_dbl(body, tmp->key.value.d, tmp->val);
		if (tmp->key.type == unsigned_long_type) np_tree_insert_ulong(body, tmp->key.value.ul, tmp->val);
	}

	uint8_t ack_mode = np_tree_find_str(msg->instructions, _NP_MSG_INST_ACK)->val.value.ush;
	if (0 < (ack_mode & ACK_DESTINATION))
	{
		_np_send_ack(msg);
	}

	// decrease threshold counter
	msg_prop->msg_threshold--;
	msg_prop->max_threshold--;

	np_unref_obj(np_message_t, msg, "?");
	np_unref_obj(np_aaatoken_t, sender_token,"?");

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
		msg_prop->clb_inbound = _np_in_signal_np_receive;
		// when creating, set to zero because callback function is not used
		msg_prop->max_threshold = 0;

		// register the handler so that message can be received
		np_msgproperty_register(msg_prop);
	}
	msg_prop->max_threshold++;

	_np_send_subject_discovery_messages(INBOUND, subject);

	np_aaatoken_t* sender_token = NULL;
	np_message_t* msg = NULL;
	char* sender_id = NULL;
	np_bool msg_received = FALSE;

	do
	{	// first check or wait for available messages
		if (0 == sll_size(msg_prop->msg_cache_in))
		{
			_LOCK_ACCESS(&msg_prop->lock)
			{
				log_debug_msg(LOG_DEBUG, "waiting for signal that a new message arrived %p", msg_prop);
				_np_threads_condition_wait(&msg_prop->msg_received, &msg_prop->lock);
				log_debug_msg(LOG_DEBUG, "received signal that a new message arrived %p", msg_prop);
			}
		}
		msg = sll_first(msg_prop->msg_cache_in)->val;

		// next check or wait for valid sender tokens
		sender_id = np_tree_find_str(msg->header, _NP_MSG_HEADER_FROM)->val.value.s;
		sender_token = _np_aaatoken_get_sender(subject, sender_id);
		if (NULL == sender_token)
		{
			// sleep for a while, token may need some time to arrive
			ev_sleep(0.31415);
			// dsleep(0.31415);
			continue;
		}

		np_tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;
		msg_received = TRUE;

	} while (FALSE == msg_received);

	// in receive function, we can only receive one message per call, different for callback function
	log_debug_msg(LOG_DEBUG, "received message from cache %p ( cache-size: %d)", msg_prop, sll_size(msg_prop->msg_cache_in));
	msg = sll_head(np_message_ptr, msg_prop->msg_cache_in);

	log_debug_msg(LOG_DEBUG, "decrypting message ...");
	np_bool decrypt_ok = _np_message_decrypt_payload(msg, sender_token);

	if (FALSE == decrypt_ok)
	{
		log_debug_msg(LOG_DEBUG, "decryption of message failed, deleting message");
		np_tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui--;
		msg_prop->max_threshold--;

		np_unref_obj(np_message_t, msg, "unknown");
		np_unref_obj(np_aaatoken_t, sender_token, "unknown");
		return (0);
	}

	uint32_t received = np_tree_find_str(msg->properties, _NP_MSG_INST_SEQ)->val.value.ul;
	np_tree_elem_t* reply_data = np_tree_find_str(msg->body, NP_MSG_BODY_TEXT);
	*data = strndup(reply_data->val.value.s, strlen(reply_data->val.value.s));

	uint8_t ack_mode = np_tree_find_str(msg->instructions, _NP_MSG_INST_ACK)->val.value.ush;
	if (0 < (ack_mode & ACK_DESTINATION))
	{
		_np_send_ack(msg);
	}

	np_tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;
	msg_prop->msg_threshold--;
	msg_prop->max_threshold--;

	np_unref_obj(np_message_t, msg, "unknown");
	np_unref_obj(np_aaatoken_t, sender_token, "unknown");

	log_msg(LOG_INFO, "someone sending us messages %s !!!", *data);

	return (received);
}
/**
 * Sends a ACK msg for the given message.
 * @param in_msg
 */
void _np_send_ack(np_message_t* in_msg)
{
	log_msg(LOG_TRACE, "start: void _np_send_ack(np_message_t* in_msg){");
	np_state_t* state = _np_state();

	// uint8_t ack = ACK_NONE;
	uint32_t seq = 0;
	char* uuid = NULL;

	// np_message_t* in_msg = args->msg;

	if (NULL != np_tree_find_str(in_msg->header, _NP_MSG_INST_ACK_TO))
	{
		// extract data from incoming message
		seq = np_tree_find_str(in_msg->instructions, _NP_MSG_INST_SEQ)->val.value.ul;
		// ack = np_tree_find_str(in_msg->instructions, NP_MSG_INST_ACK)->val.value.ush;
		uuid = np_tree_find_str(in_msg->instructions, _NP_MSG_INST_UUID)->val.value.s;

		// create new ack message & handlers
		np_dhkey_t ack_key = np_dhkey_create_from_hash(
				np_tree_find_str(in_msg->header, _NP_MSG_INST_ACK_TO)->val.value.s);

		np_key_t* ack_target = _np_keycache_find(ack_key);

		np_message_t* ack_msg = NULL;
		np_new_obj(np_message_t, ack_msg);

		np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _NP_MSG_ACK);

		_np_message_create(ack_msg, ack_target, state->my_node_key, _NP_MSG_ACK, NULL);
		np_tree_insert_str(ack_msg->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop->ack_mode));
		np_tree_insert_str(ack_msg->instructions, _NP_MSG_INST_ACKUUID, np_treeval_new_s(uuid));
		np_tree_insert_str(ack_msg->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(seq));
		// send the ack out
		_np_job_submit_route_event(0.0, prop, ack_target, ack_msg);

		np_unref_obj(np_key_t, ack_target,"_np_keycache_find");
		np_unref_obj(np_message_t, ack_msg,ref_obj_creation);
	}
}

/**
 ** _np_ping:
 ** sends a PING message to another node. The message is acknowledged in network layer.
 **/
void _np_ping (np_key_t* key)
{
	np_state_t* state = _np_state();

	np_message_t* out_msg = NULL;
	np_new_obj(np_message_t, out_msg);

	_np_message_create (out_msg, key, state->my_node_key, _NP_MSG_PING_REQUEST, NULL);
	log_debug_msg(LOG_DEBUG, "ping request to: %s", _np_key_as_str(key));

	/* weired: assume failure of the node now, will be reset with ping reply later */
	if (NULL != key->node)
	{
		key->node->failuretime = ev_time();
		_np_node_update_stat(key->node, 0);
	}
	np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _NP_MSG_PING_REQUEST);
	_np_job_submit_msgout_event(0.0, prop, key, out_msg);

	np_unref_obj(np_message_t, out_msg, ref_obj_creation);
}

/**
 ** np_destroy:
 ** destroys the neuropil data structures and cleans memory that has been used
 **/
void np_destroy()
{
	log_msg(LOG_TRACE, "start: void np_destroy(){");
	// TODO: implement me ...
}

/**
 ** np_init:
 ** initializes neuropil on specified port and returns the const np_state_t* which
 ** contains global state of different neuropil modules.
 **/
np_state_t* np_init(char* proto, char* port, char* hostname)
{
	log_msg(LOG_TRACE, "start: np_state_t* np_init(char* proto, char* port, np_bool start_http, char* hostname){");
	log_debug_msg(LOG_DEBUG, "neuropil_init");
	
	 if(_np_threads_init() == FALSE){
		log_msg(LOG_ERROR, "neuropil_init: could not init threding mutexes");
		exit(EXIT_FAILURE);
	}
	// encryption and memory protection
	if(sodium_init() == -1){
		log_msg(LOG_ERROR, "neuropil_init: could not init crypto library");
		exit(EXIT_FAILURE);
	}
	
	// memory pool
	np_mem_init();

	// initialize key min max ranges
	_np_dhkey_init();
	
	// global neuropil structure
	np_state_t *state = (np_state_t *) calloc (1,sizeof (np_state_t));
	CHECK_MALLOC(state);
	if (state == NULL)
	{
		log_msg(LOG_ERROR, "neuropil_init: state module not created: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	sll_init(np_thread_ptr, state->threads);

	np_thread_t * new_main_thread;
	np_new_obj(np_thread_t, new_main_thread);
	new_main_thread->id = (unsigned long)getpid();
	sll_append(np_thread_ptr, state->threads, new_main_thread);

	
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
		np_proto = _np_network_parse_protocol_string(proto);
		log_debug_msg(LOG_DEBUG, "now initializing networking for %s:%s", proto, np_service);
	}
	else
	{
		log_debug_msg(LOG_DEBUG, "now initializing networking for udp6://%s", np_service);
	}
	
	log_debug_msg(LOG_DEBUG, "building node base structure");
	np_node_t* my_node = NULL;
	np_new_obj(np_node_t, my_node);

	log_debug_msg(LOG_DEBUG, "building network base structure");
	np_network_t* my_network = NULL;
	np_new_obj(np_network_t, my_network);
	
	// get public / local network interface id
	if(NULL == hostname){
		hostname = calloc(1,sizeof(char) * 255);
		CHECK_MALLOC(hostname);
		log_msg(LOG_INFO, "neuropil_init: resolve hostname");

		if(_np_get_local_ip(hostname, 255) == FALSE) {
			if( 0 != gethostname(hostname, 255)){
				free(hostname);
				hostname = strdup("localhost");
			}
		}
	}
	//--
	log_debug_msg(LOG_DEBUG, "initialise network");
	_LOCK_MODULE(np_network_t)
	{
		_np_network_init(my_network, TRUE, np_proto, hostname, np_service);
		_np_network_stop(my_network);
	}
	log_debug_msg(LOG_DEBUG, "check for initialised network");
	if (FALSE == my_network->initialized)
	{
		log_msg(LOG_ERROR, "neuropil_init: network_init failed, see log for details");
		exit(EXIT_FAILURE);
	}
	
	log_debug_msg(LOG_DEBUG, "update my node data");
	_np_node_update(my_node, np_proto, hostname, np_service);
	
	log_debug_msg(LOG_DEBUG, "neuropil_init: network_init for %s:%s:%s",
					   _np_network_get_protocol_string(my_node->protocol), my_node->dns_name, my_node->port);
	// create a new token for encryption each time neuropil starts
	np_aaatoken_t* auth_token = _np_node_create_token(my_node);
	auth_token->state = AAA_VALID | AAA_AUTHENTICATED | AAA_AUTHORIZED;

	np_dhkey_t my_dhkey = _np_aaatoken_create_dhkey(auth_token); // np_dhkey_create_from_hostport(my_node->dns_name, my_node->port);
	state->my_node_key = _np_keycache_find_or_create(my_dhkey);


	np_ref_obj(np_key_t, state->my_node_key, ref_network_watcher);
	my_network->watcher.data = state->my_node_key;
	_np_network_start(my_network);

	// log_msg(LOG_WARN, "node_key %p", state->my_node_key);

	np_ref_obj(np_node_t, my_node, ref_key_node);
	state->my_node_key->node = my_node;
	np_ref_obj(np_network_t, my_network, ref_key_network);
	state->my_node_key->network = my_network;
	np_ref_obj(np_aaatoken_t, auth_token, ref_key_aaa_token);
	state->my_node_key->aaa_token = auth_token;

	//TODO: via np_setIdentity
	// set and ref additional identity
	state->my_identity = state->my_node_key;
	np_ref_obj(np_key_t, state->my_identity, ref_state_identity);
	
	// initialize routing table
	if (FALSE == _np_route_init (state->my_node_key) )
	{
		log_msg(LOG_ERROR, "neuropil_init: route_init failed: %s", strerror (errno));
		exit(EXIT_FAILURE);
	}
	// initialize job queue
	if (FALSE == _np_job_queue_create())
	{
		log_msg(LOG_ERROR, "neuropil_init: job_queue_create failed: %s", strerror (errno));
		exit(EXIT_FAILURE);
	}
	// initialize message handling system
	if (FALSE == _np_msgproperty_init())
	{
		log_msg(LOG_ERROR, "neuropil_init: job_queue_create failed: %s", strerror (errno));
		exit(EXIT_FAILURE);
	}

	state->msg_tokens = np_tree_create();
	state->msg_part_cache = np_tree_create();


	// initialize cleanup layer last
	np_job_submit_event(0.0, _np_cleanup_ack_jobexec);
	np_job_submit_event(0.0, _np_cleanup_keycache_jobexec);
	np_job_submit_event(0.0, _np_event_cleanup_msgpart_cache);

	// start leafset checking jobs
	np_job_submit_event(0.0, _np_route_check_leafset_jobexec);


#ifdef SKIP_EVLOOP
	// intialize log file writing
	np_job_submit_event(0.0, _np_write_log);
	// np_job_submit_event(0.0, _np_events_read);
#endif

	// initialize retransmission of tokens
	np_job_submit_event(0.0, _np_retransmit_message_tokens_jobexec);
	// initialize node token renewal
	np_job_submit_event(0.0, _np_renew_node_token_jobexec);
	// initialize network/io reading and writing
	np_job_submit_event(0.0, _np_events_read);


	np_unref_obj(np_key_t, state->my_node_key, "_np_keycache_find_or_create");
	np_unref_obj(np_node_t, my_node, ref_obj_creation);
	np_unref_obj(np_network_t, my_network, ref_obj_creation);
	np_unref_obj(np_aaatoken_t, auth_token, ref_obj_creation);

	log_msg(LOG_INFO, "neuropil successfully initialized: %s", _np_key_as_str(state->my_node_key));
	_np_log_fflush(TRUE);

	return (state);
}

void np_start_job_queue(uint8_t pool_size)
{
	log_msg(LOG_TRACE, "start: void np_start_job_queue(uint8_t pool_size){");
	if (pthread_attr_init (&_np_state()->attr) != 0)
	{
		log_msg (LOG_ERROR, "pthread_attr_init: %s", strerror (errno));
		return;
	}

	if (pthread_attr_setscope (&_np_state()->attr, PTHREAD_SCOPE_SYSTEM) != 0)
	{
		log_msg (LOG_ERROR, "pthread_attr_setscope: %s", strerror (errno));
		return;
	}

	if (pthread_attr_setdetachstate (&_np_state()->attr, PTHREAD_CREATE_DETACHED) != 0)
	{
		log_msg (LOG_ERROR, "pthread_attr_setdetachstate: %s", strerror (errno));
		return;
	}

	_np_state()->thread_count = pool_size;
	_np_state()->thread_ids = (pthread_t *) malloc (sizeof (pthread_t) * pool_size);

	CHECK_MALLOC(_np_state()->thread_ids);

	/* create the thread pool */
	for (uint8_t i = 0; i < pool_size; i++)
	{
		pthread_create (&_np_state()->thread_ids[i], &_np_state()->attr, _job_exec, (void *) _np_state());
		np_thread_t * new_thread;
		np_new_obj(np_thread_t, new_thread);
		new_thread->id  = (unsigned long)_np_state()->thread_ids[i];
		sll_append(np_thread_ptr, _np_state()->threads, new_thread);

		log_debug_msg(LOG_DEBUG, "neuropil worker thread started: %p", _np_state()->thread_ids[i]);
	}
	log_debug_msg(LOG_DEBUG, "%s event loop with %d threads started", NEUROPIL_RELEASE, pool_size);
	log_msg(LOG_INFO, "%s", NEUROPIL_COPYRIGHT);
	log_msg(LOG_INFO, "%s", NEUROPIL_TRADEMARK);

	fprintf(stdout, "\n");
	fprintf(stdout, "%s initializiation successful\n", NEUROPIL_RELEASE);
	fprintf(stdout, "%s event loop with %d worker threads started\n", NEUROPIL_RELEASE, pool_size);
	fprintf(stdout, "your neuropil node will be addressable as:\n");
	fprintf(stdout, "\n");

	char* connection_str = np_get_connection_string();
	fprintf(stdout, "\t%s\n",connection_str);
	free(connection_str);

	fprintf(stdout, "\n");
	fprintf(stdout, "%s\n", NEUROPIL_COPYRIGHT);
	fprintf(stdout, "%s\n", NEUROPIL_TRADEMARK);
	fprintf(stdout, "\n");
	fflush(stdout);
}

char* np_get_connection_string(){
	log_msg(LOG_TRACE, "start: char* np_get_connection_string(){");
	
	return np_get_connection_string_from(_np_state()->my_node_key, TRUE);
}

char* np_get_connection_string_from(np_key_t* node_key, np_bool includeHash) {
	log_msg(LOG_TRACE, "start: char* np_get_connection_string_from(np_key_t* node_key, np_bool includeHash){");
	
	return _np_build_connection_string(
		includeHash == TRUE ? _np_key_as_str(node_key) : NULL,
		_np_network_get_protocol_string(node_key->node->protocol),
		node_key->node->dns_name,
		node_key->node->port,
		includeHash
	);
}
char* _np_build_connection_string(char* hash, char* protocol, char*dns_name,char* port, np_bool includeHash) {
	log_msg(LOG_TRACE, "start: char* np_get_connection_string_from(np_key_t* node_key, np_bool includeHash){");
	char* connection_str;
	
	if (TRUE == includeHash) {
		asprintf(&connection_str, "%s:%s:%s:%s",
			hash,
			protocol,
			dns_name,
			port);
	}
	else {
		asprintf(&connection_str, "%s:%s:%s",
			protocol,
			dns_name,
			port);
	}

	return connection_str;
}
