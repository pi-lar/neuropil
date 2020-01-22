//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <float.h>
#include <string.h>

#include <inttypes.h>
#include <sys/types.h>

#include "sodium.h"
#include "event/ev.h"

#include "neuropil.h"
#include "np_legacy.h"

#include "np_types.h"
#include "dtime.h"
#include "np_log.h"
#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_dendrit.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_keycache.h"
#include "np_memory.h"

#include "np_message.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"
#include "np_network.h"
#include "np_token_factory.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_route.h"
#include "np_event.h"
#include "np_statistics.h"
#include "np_list.h"
#include "np_util.h"
#include "np_shutdown.h"
#include "np_bootstrap.h"
#include "np_tree.h"

#include "np_settings.h"
#include "np_constants.h"

NP_SLL_GENERATE_IMPLEMENTATION(np_usercallback_ptr);

NP_SLL_GENERATE_IMPLEMENTATION(np_evt_callback_t);

/**
 * The default authorize function, allows no authorizations and generates warnings
 * @param token
 * @return
 */
bool _np_default_authorizefunc (np_context* ac, struct np_token* token )
{
    np_ctx_cast(ac);
    log_msg(LOG_WARN, "using default handler (authorize none) to reject authorization for: %s", token->subject );
    // log_msg(LOG_WARN, "do you really want the default authorize handler (allow all) ???");

    return (false);
}
/**
 * The default realm client authorize function. Forwards the authorization request to the realm server
 * @param token
 * @return
 */
bool _np_aaa_authorizefunc (np_context* ac, struct np_token* token )
{
    np_ctx_cast(ac);

//	log_debug_msg(LOG_DEBUG, "realm             : %s", token->realm);
//	log_debug_msg(LOG_DEBUG, "issuer            : %s", token->issuer);
//	log_debug_msg(LOG_DEBUG, "subject           : %s", token->subject);
//	log_debug_msg(LOG_DEBUG, "audience          : %s", token->audience);
//	log_debug_msg(LOG_DEBUG, "uuid              : %s", token->uuid);
    log_debug_msg(LOG_DEBUG, "realm authorization request for subject: %s", token->subject);

    return (false);
}

/**
 * The default authenticate function, allows all authorizations and generates warnings
 * @param token
 * @return
 */
bool _np_default_authenticatefunc (np_context* ac, struct np_token* token )
{
    np_ctx_cast(ac);
    log_msg(LOG_WARN, "using default handler (authn all) to authenticate %s", token->subject);
    // log_msg(LOG_WARN, "do you really want the default authenticate handler (trust all) ???");

    return (true);
}

/**
 * The default realm client authenticate function. Forwards the authenticate request to the realm server
 * @param token
 * @return
 */
bool _np_aaa_authenticatefunc (np_context*ac, struct np_token* token)
{
    np_ctx_cast(ac);

//	log_debug_msg(LOG_DEBUG, "realm             : %s", token->realm);
//	log_debug_msg(LOG_DEBUG, "issuer            : %s", token->issuer);
//	log_debug_msg(LOG_DEBUG, "subject           : %s", token->subject);
//	log_debug_msg(LOG_DEBUG, "audience          : %s", token->audience);
//	log_debug_msg(LOG_DEBUG, "uuid              : %s", token->uuid);
    log_debug_msg(LOG_DEBUG, "realm authentication request for subject: %s", token->subject);

    return (false);
}

/**
 * The default accounting function, allows no authorizations and generates warnings
 * @param token
 * @return
 */
bool _np_default_accountingfunc (np_context* ac, struct np_token* token )
{
    np_ctx_cast(ac);
    log_msg(LOG_WARN, "using default handler to deny accounting for: %s", token->subject );
    // log_msg(LOG_WARN, "do you really want the default accounting handler (account nothing) ???");

    return (false);
}

/**
 * The default realm client accounting function. Forwards the accounting request to the realm server
 * @param token
 * @return
 */
bool _np_aaa_accountingfunc (np_context*ac, struct  np_token* token)
{
    np_ctx_cast(ac);

//	log_debug_msg(LOG_DEBUG, "realm             : %s", token->realm);
//	log_debug_msg(LOG_DEBUG, "issuer            : %s", token->issuer);
//	log_debug_msg(LOG_DEBUG, "subject           : %s", token->subject);
//	log_debug_msg(LOG_DEBUG, "audience          : %s", token->audience);
//	log_debug_msg(LOG_DEBUG, "uuid              : %s", token->uuid);
    log_debug_msg(LOG_DEBUG, "realm accounting request for subject: %s", token->subject);
    return (false);
}

/**
 * Sets the realm name of the node.
 * RECONFIGURES THE NODE HASH! The old node hash will be forgotten.
 * @param realm_name
 */
void np_set_realm_name(np_context*ac, const char* realm_name)
{
    np_ctx_cast(ac);
    log_trace_msg(LOG_TRACE, "start: void np_set_realm_name(const char* realm_name){");
    context->realm_name = strndup(realm_name, 255);
    
    /*    
    // create a new token
    np_dhkey_t my_dhkey = np_aaatoken_get_fingerprint(auth_token, false); // np_dhkey_create_from_hostport( my_node->dns_name, my_node->port);
    np_key_t* new_node_key = _np_keycache_find_or_create(context, my_dhkey);

    new_node_key->network = context->my_node_key->network;
    np_ref_obj(np_network_t, new_node_key->network, ref_key_network);

    context->my_node_key->network = NULL;

    _np_network_set_key(new_node_key->network, new_node_key);

    new_node_key->node = context->my_node_key->node;
    np_ref_obj(np_node_t, new_node_key->node, ref_key_node);

    context->my_node_key->node = NULL;

    np_ref_switch(np_aaatoken_t, new_node_key->aaa_token, ref_key_aaa_token, auth_token);

    // re-initialize routing table
    _np_route_set_key (new_node_key);

    // set and ref additional identity
    // TODO: use _np_set_identity
    if (_np_key_cmp(context->my_identity, context->my_node_key) == 0)
    {
        np_ref_switch(np_key_t, context->my_identity, ref_state_identitykey, new_node_key);
    }

    // context->my_identity->aaa_token->type = np_aaatoken_type_identity;
    context->my_node_key = new_node_key;

    log_msg(LOG_INFO, "neuropil realm successfully set, node hash now: %s", _np_key_as_str(context->my_node_key));

    np_unref_obj(np_key_t, new_node_key,"_np_keycache_find_or_create");
    */
}
/**
 * Enables this node as realm client.
 * The node will forward all aaa requests to the realm server
 */
void np_enable_realm_client(np_context*ac)
{
    np_ctx_cast(ac);

    np_set_authorize_cb(ac, _np_aaa_authorizefunc);
    np_set_authenticate_cb(ac, _np_aaa_authenticatefunc);
    np_set_accounting_cb(ac, _np_aaa_accountingfunc);

    context->enable_realm_server = false;
    context->enable_realm_client = true;
}

/**
 * Enables this node as realm server.
 */
void np_enable_realm_server(np_context*ac )
{
    np_ctx_cast(ac);
    if (NULL == context->realm_name)
    {
        return;
    }

    np_msgproperty_t* prop = NULL;

    // turn msg handlers for aaa to inbound msg as well
    prop = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHENTICATION_REQUEST);
    if (NULL == prop->msg_audience)
    {
        prop->msg_audience = strndup(context->realm_name, 255);
    }

    prop = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHORIZATION_REQUEST);
    if (NULL == prop->msg_audience)
    {
        prop->msg_audience = strndup(context->realm_name, 255);
    }

    prop = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_ACCOUNTING_REQUEST);
    if (NULL == prop->msg_audience)
    {
        prop->msg_audience = strndup(context->realm_name, 255);
    }

    context->enable_realm_server = true;
    context->enable_realm_client = false;
}

/**
 * Waits till this node is connected to a network.
 * WARNING! Blocks the current thread and does not have a timeout!
 */
void np_waitforjoin(np_context*ac)
{
    np_ctx_cast(ac);
    log_trace_msg(LOG_TRACE, "start: void np_waitforjoin(){");
    while (false == _np_route_my_key_has_connection(context))
    {
        np_time_sleep(0.0);
    }
}

/**
* Sets a callback for a given msg subject.
* Each msg for the given subject may invoke this handler.
* @param msg_handler
* @param subject
*/
void np_add_receive_listener(np_context*ac, np_usercallbackfunction_t msg_handler_fn, void* msg_handler_localdata, const char* subject)
{
    np_ctx_cast(ac);
    // check whether an handler already exists
    np_msgproperty_t* msg_prop = _np_msgproperty_get_or_create(context, INBOUND, subject);
    
    log_debug(LOG_INFO, "adding receive listener on subject %s / property %p", subject, msg_prop);
    
    np_usercallback_t * msg_handler = malloc(sizeof(np_usercallback_t));
    msg_handler->data = msg_handler_localdata;
    msg_handler->fn = msg_handler_fn;

    if (msg_prop != NULL && msg_prop->is_internal == false) 
    {
        if (false == sll_contains(np_evt_callback_t, msg_prop->clb_inbound, _np_in_callback_wrapper, np_evt_callback_t_sll_compare_type)) 
        {   // decrypt or cache the message
            sll_append(np_evt_callback_t, msg_prop->clb_inbound, _np_in_callback_wrapper);
        }
        if (false == sll_contains(np_evt_callback_t, msg_prop->clb_inbound, _check_and_send_destination_ack, np_evt_callback_t_sll_compare_type)) 
        {   // potentially send an ack for a message
            sll_append(np_evt_callback_t, msg_prop->clb_inbound, _check_and_send_destination_ack);
        }
        // hand it over to the userspace
        sll_append(np_usercallback_ptr, msg_prop->user_receive_clb, msg_handler);
    }
}
/**
* Sets a callback for a given msg subject.
* Each msg for the given subject may invoke this handler.
* @param msg_handler
* @param subject
*/
void np_add_send_listener(np_context*ac, np_usercallbackfunction_t msg_handler_fn, void * msg_handler_localdata, const char* subject)
{
    np_ctx_cast(ac);
    // check whether an handler already exists
    np_msgproperty_t* msg_prop = _np_msgproperty_get_or_create(context, OUTBOUND, subject);

    np_usercallback_t * msg_handler = malloc(sizeof(np_usercallback_t));
    msg_handler->data = msg_handler_localdata;
    msg_handler->fn   = msg_handler_fn;

    sll_append(np_usercallback_ptr, msg_prop->user_send_clb, msg_handler);
}

/**
 * Sets the identity of the node.
 * @param identity
 */
void _np_set_identity(np_context*ac, np_aaatoken_t* identity)
{    
    np_ctx_cast(ac);

    np_dhkey_t search_key = np_aaatoken_get_fingerprint(identity, false);
    np_key_t* my_identity_key = _np_keycache_find_or_create(context, search_key);

    np_util_event_t ev = { .type=(evt_internal|evt_token), .context=ac, .user_data=identity, .target_dhkey=search_key };
    _np_key_handle_event(my_identity_key, ev, false);

    np_unref_obj(np_key_t, my_identity_key,"_np_keycache_find_or_create");
}

void np_send_response_msg(np_context*ac, np_message_t* original, np_tree_t *body)
{
    // np_ctx_cast(ac);
    // np_dhkey_t* sender = _np_message_get_sender(original);
    /* 
    np_message_t* msg = _np_prepare_msg(context, original->msg_property->rep_subject, body, sender);

    np_tree_replace_str( msg->instructions, _NP_MSG_INST_RESPONSE_UUID, np_treeval_new_s(original->uuid));

    _np_send_msg(msg->msg_property->msg_subject, msg, msg->msg_property, sender);

    np_unref_obj(np_message_t, msg, ref_obj_creation);
    */
}

char* np_get_connection_string(np_context*ac) 
{
    np_ctx_cast(ac);
    log_trace_msg(LOG_TRACE, "start: char* np_get_connection_string(){");

    return np_get_connection_string_from(context->my_node_key, true);
}

char* np_get_connection_string_from(np_key_t* node_key, bool includeHash) 
{
    np_ctx_memory(node_key);
    log_trace_msg(LOG_TRACE, "start: char* np_get_connection_string_from(np_key_t* node_key, bool includeHash){");

    assert (FLAG_CMP(node_key->type, np_key_type_node) || FLAG_CMP(node_key->type, np_key_type_wildcard) );

    np_node_t* node_data = _np_key_get_node(node_key);
    if (node_data) 
    {
        return (np_build_connection_string(
                        includeHash == true ? _np_key_as_str(node_key) : NULL,
                        _np_network_get_protocol_string(context, node_data->protocol),
                        node_data->dns_name,
                        node_data->port,
                        includeHash)
            );
    }

    return NULL;
}

char* np_build_connection_string(char* hash, char* protocol, char*dns_name,char* port, bool includeHash)
{
    log_trace_msg(LOG_TRACE, "start: char* np_get_connection_string_from(np_key_t* node_key, bool includeHash){");
    char* connection_str;
    if (true == includeHash) {
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

/**
 * Sends a JOIN request to the given node string.
 * Please see @np_get_connection_string() for the node_string definition
 * @param node_string
    @deprecated
 */
void np_send_join(np_context*ac, const char* node_string)
{
    np_ctx_cast(ac);	

    np_node_t* new_node = _np_node_decode_from_str(context, node_string);

    // TODO: use sscanf !
    // int n = sscanf("string", "%64s%*[:]%4s%*[:]%s%*[:]%d", hash_str, proto, dns/ip, port); // n == 4
    // int n = sscanf("string", "%*[*]%*[:]%4s%*[:]%s%*[:]%d", proto, dns/ip, port); // n == 3
    
    np_dhkey_t search_key = {0};
    if (node_string[0] == '*') 
    {
        search_key = np_dhkey_create_from_hostport( "*", node_string+2);
    } 
    else
    {
        search_key = np_dhkey_create_from_hash(node_string);
    }
    np_key_t* node_key = _np_keycache_find_or_create(context, search_key);

    np_util_event_t new_node_evt = { .type=(evt_internal), .context=context, 
                                     .user_data=new_node, .target_dhkey=search_key };
    _np_keycache_handle_event(context, search_key, new_node_evt, false);

    np_unref_obj(np_key_t, node_key, "_np_keycache_find_or_create");    
    np_bootstrap_add(context, node_string);
}

