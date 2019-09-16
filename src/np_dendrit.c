//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "sodium.h"
#include "event/ev.h"
#include "msgpack/cmp.h"

#include "np_dendrit.h"

#include "np_statistics.h"
#include "np_axon.h"
#include "np_log.h"
#include "np_legacy.h"
#include "np_aaatoken.h"
#include "np_token_factory.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_message.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_intent.h"
#include "core/np_comp_node.h"
#include "np_network.h"
#include "np_node.h"
#include "np_memory.h"
#include "np_list.h"
#include "np_route.h"
#include "np_util.h"
#include "np_types.h"
#include "np_threads.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "np_axon.h"
#include "np_event.h"
#include "np_constants.h"
#include "np_responsecontainer.h"
#include "np_serialization.h"
#include "np_bootstrap.h"
#include "neuropil.h"


bool _np_in_ping(np_state_t* context, np_util_event_t msg_event)
{
    log_trace_msg(LOG_TRACE, "start: bool _np_in_ping(...) {");

    NP_CAST(msg_event.user_data, np_message_t, msg);
    log_debug_msg(LOG_DEBUG, "_np_in_ping for message uuid %s", msg->uuid);

    // initiate ack for ping messages
    // TODO: do this in a np_evt_callback_t function
    np_dhkey_t ack_dhkey   = _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_ACK);
    np_dhkey_t target = np_tree_find_str(msg->header, _NP_MSG_HEADER_FROM)->val.value.dhkey;

    np_tree_t* msg_body = np_tree_create();
    np_tree_insert_str(msg_body, _NP_MSG_INST_RESPONSE_UUID, np_treeval_new_s(msg->uuid) );

    np_message_t* msg_out;
    np_new_obj(np_message_t, msg_out, ref_obj_creation);
    _np_message_create(msg_out, target, context->my_node_key->dhkey, _NP_MSG_ACK, msg_body);

    np_util_event_t ack_event = { .context=context, .type=evt_message|evt_internal, .target_dhkey=target, .user_data=msg_out };
    _np_keycache_handle_event(context, ack_dhkey, ack_event, false);
    // nothing more to do. work is done only on the sending end (ack handling)

    return true;
}

/**
 ** neuropil_piggy_message:
 ** This function is responsible to add the piggy backing node information that is sent along with
 ** other ctrl messages or separately to the routing table. the PIGGY message type is a separate
 ** message type.
 **/
bool _np_in_piggy(np_state_t* context, np_util_event_t msg_event)
{
    log_trace_msg(LOG_TRACE, "start: bool _np_in_piggy(...) {");

    NP_CAST(msg_event.user_data, np_message_t, msg);

    np_node_t* node_entry = NULL;
    np_sll_t(np_node_ptr, o_piggy_list) = NULL;

    o_piggy_list = _np_node_decode_multiple_from_jrb(context, msg->body);

    log_info(LOG_DEBUG, "received piggy msg (%"PRIu32" nodes)", sll_size(o_piggy_list));

    while (NULL != (node_entry = sll_head(np_node_ptr, o_piggy_list)))
    {
        np_dhkey_t search_key = {0};
        _np_str_dhkey(node_entry->host_key, &search_key);
        // add entries in the message to our routing table
        // routing table is responsible to handle possible double entries
        // TODO: those new entries in the piggy message must be authenticated before sending join requests
        np_key_t* piggy_key = _np_keycache_find(context, search_key);
        if (piggy_key == NULL)
        {   // unkown key, just send a join request 
            char* connect_str = np_build_connection_string(NULL, 
                                                        _np_network_get_protocol_string(context, node_entry->protocol), 
                                                        node_entry->dns_name, 
                                                        node_entry->port, 
                                                        false);
            np_dhkey_t search_key = np_dhkey_create_from_hostport( "*", connect_str);
            piggy_key = _np_keycache_find_or_create(context, search_key);
            
            np_util_event_t new_node_evt = { .type=(evt_internal), .context=context, .user_data=node_entry };
            _np_key_handle_event(piggy_key, new_node_evt, false);

            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "node %s is qualified for a piggy join.", _np_key_as_str(piggy_key));
            np_unref_obj(np_key_t, piggy_key,"_np_keycache_find_or_create");
            free(connect_str);
        }
        else if (_np_key_get_node(piggy_key)->joined_network                                           &&
                 _np_key_get_node(piggy_key)->success_avg > BAD_LINK                                   &&
                (np_time_now() - piggy_key->created_at) >= BAD_LINK_REMOVE_GRACETIME ) 
        {
            // let's try to fill up our leafset, routing table is filled by internal state
            // TODO: realize this via an event, otherwiese locking of the piggy key is not in place
            __np_node_add_to_leafset(&piggy_key->sm, msg_event);
            np_unref_obj(np_key_t, piggy_key,"_np_keycache_find");

        } else {
            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "node %s is not qualified for a further piggy actions. (%s)",
                                                   _np_key_as_str(piggy_key), 
                                                   _np_key_get_node(piggy_key)->joined_network ? "J":"NJ");
            np_unref_obj(np_key_t, piggy_key,"_np_keycache_find");
        }        
        np_unref_obj(np_node_t, node_entry,"_np_node_decode_from_jrb");
        // free(connect_str);
    }
    sll_free(np_node_ptr, o_piggy_list);

    log_trace_msg(LOG_TRACE, "end  : bool _np_in_piggy(...) }");
    return true;
}

/** _np_in_callback_wrapper
 ** _np_in_callback_wrapper is used when a callback function is used to receive messages
 ** The purpose is automated acknowledge handling in case of ACK_CLIENT message subjects
 ** the user defined callback has to return true in case the ack can be send, or false
 ** if e.g. validation of the message has failed.
 **/
bool _np_in_callback_wrapper(np_state_t* context, np_util_event_t msg_event)
{
    log_trace_msg(LOG_TRACE, "start: bool _np_in_callback_wrapper(np_jobargs_t* args){");
    
    NP_CAST(msg_event.user_data, np_message_t, msg_in);

    log_debug(LOG_MESSAGE, "(msg: %s) start callback wrapper",msg_in->uuid);

    bool ret = true;
    bool free_msg_subject = false;

    CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_SUBJECT, msg_subject_ele);    
    CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_from);

    char* msg_subject = np_treeval_to_str(msg_subject_ele, &free_msg_subject);
    
    np_dhkey_t prop_dhkey = _np_msgproperty_dhkey(INBOUND, msg_subject);
    np_key_t* prop_key    = _np_keycache_find(context, prop_dhkey);
    np_msgproperty_t* msg_prop = _np_msgproperty_get(context, INBOUND, msg_subject);
    
    np_aaatoken_t* sender_token = _np_intent_get_sender_token(prop_key, msg_from.value.dhkey);

    if (_np_messsage_threshold_breached(msg_prop) || NULL == sender_token )
    {
        // cleanup of msgs in property receiver msg cache
        _np_msgproperty_add_msg_to_recv_cache(msg_prop, msg_in);
        if (sender_token == NULL)
        {
            log_msg(LOG_INFO,"no token to decrypt msg (%s). Retrying later", msg_in->uuid);
        }
        else
        {
            log_msg(LOG_INFO,"possible message processing overload - retrying later", msg_in->uuid);
        }
        ret = false;
    } 
    else
    {
        _np_msgproperty_threshold_increase(msg_prop);
        log_debug_msg(LOG_DEBUG, "decrypting message(%s) from sender %s", msg_in->uuid, sender_token->issuer);
        ret = _np_message_decrypt_payload(msg_in, sender_token);
        _np_msgproperty_threshold_decrease(msg_prop);
        np_unref_obj(np_aaatoken_t, sender_token,"_np_intent_get_sender_token"); // _np_aaatoken_get_sender_token
    }
    np_unref_obj(np_key_t, prop_key, "_np_keycache_find");

    __np_cleanup__:
    if (free_msg_subject) free(msg_subject);

    return ret;
}

/** _np_in_leave_req:
 ** internal function that is called at the destination of a LEAVE message. This
 ** call encodes the leaf set of the current host and sends it to the joiner.
 **/
bool _np_in_leave(np_state_t* context, np_util_event_t msg_event)
{
    log_debug_msg(LOG_TRACE, "start: bool _np_in_leave(...){");

    NP_CAST(msg_event.user_data, np_message_t, msg);
        
    np_tree_elem_t* node_token_ele = np_tree_find_str(msg->body, _NP_URN_NODE_PREFIX);
    if (node_token_ele != NULL) 
    {
        np_aaatoken_t* node_token = np_token_factory_read_from_tree(context, node_token_ele->val.value.tree);
        if (node_token != NULL) {

            np_dhkey_t search_key   = np_aaatoken_get_fingerprint(node_token, false);
            np_util_event_t shutdown_event = { .context=context, .type=evt_shutdown|evt_internal, .target_dhkey=search_key, .user_data=node_token };

            _np_keycache_handle_event(context, search_key, shutdown_event, false);

            np_unref_obj(np_aaatoken_t, node_token, "np_token_factory_read_from_tree");
        }
    }
    return true;
}


/** _np_in_join_req:
 ** internal function that is called at the destination of a JOIN message. This
 ** call encodes the leaf set of the current host and sends it to the joiner.
 **/
bool _np_in_join(np_state_t* context, np_util_event_t msg_event)
{
    log_debug_msg(LOG_TRACE, "start: bool _np_in_join(...){");

    NP_CAST(msg_event.user_data, np_message_t, msg);

    np_key_t*  join_node_key = NULL;
    np_dhkey_t join_node_dhkey = { 0 };
    np_node_public_token_t* join_node_token = NULL;

    np_dhkey_t join_ident_dhkey = { 0 };
    np_ident_public_token_t* join_ident_token = NULL;

    np_util_event_t authn_event = { .context=context, .type=evt_authn|evt_external|evt_token };
    
    np_tree_elem_t* node_token_ele = np_tree_find_str(msg->body, _NP_URN_NODE_PREFIX);
    if (node_token_ele == NULL) 
    {
        // silently exit join protocol for invalid msg syntax
        log_debug_msg(LOG_TRACE, "JOIN request: bad msg syntax");
        goto __np_cleanup__;
    }

    join_node_token = np_token_factory_read_from_tree(context, node_token_ele->val.value.tree);
    if (join_node_token == NULL ) {
        // silently exit join protocol for unknown node tokens
        log_debug_msg(LOG_TRACE, "JOIN request: missing node token");
        goto __np_cleanup__;
    }

    if (!_np_aaatoken_is_valid(join_node_token, np_aaatoken_type_node)) {
        // silently exit join protocol for invalid token type
        log_debug_msg(LOG_WARN, "JOIN request: invalid node token");
        goto __np_cleanup__;
    }

    log_debug_msg(LOG_AAATOKEN | LOG_ROUTING , "node token is valid");
    // build a hash to find a place in the dhkey table, not for signing !
    join_node_dhkey = np_aaatoken_get_fingerprint(join_node_token, false);

    np_tree_elem_t* ident_token_ele = np_tree_find_str(msg->body, _NP_URN_IDENTITY_PREFIX);	

    if (ident_token_ele != NULL)
    {    
    	join_ident_token = np_token_factory_read_from_tree(context, ident_token_ele->val.value.tree);
        if (NULL == join_ident_token || 
            false == _np_aaatoken_is_valid(join_ident_token, np_aaatoken_type_identity)) 
        {
            // silently exit join protocol for invalid identity token
            log_debug_msg(LOG_TRACE, "JOIN request: invalid identity token");
            goto __np_cleanup__;
        }
        log_debug_msg(LOG_AAATOKEN | LOG_ROUTING, "join token is valid");
        // build a hash to find a place in the dhkey table, not for signing !
        join_ident_dhkey = np_aaatoken_get_fingerprint(join_ident_token, false);

        np_dhkey_t zero_dhkey = { 0 };
        np_dhkey_t partner_of_ident_dhkey = np_aaatoken_get_partner_fp(join_ident_token);
        if (_np_dhkey_equal(&zero_dhkey,      &partner_of_ident_dhkey) == true ||
        	_np_dhkey_equal(&join_node_dhkey, &partner_of_ident_dhkey) == false)  
        {
            char fp_n[65], fp_p[65];
            _np_dhkey_str(&join_node_dhkey, fp_n);
            _np_dhkey_str(&partner_of_ident_dhkey, fp_p);
            log_msg(LOG_WARN,
                "JOIN request: node fingerprint must match partner fingerprint in identity token. (node: %s / partner: %s)",
                fp_n, fp_p
            );
            goto __np_cleanup__;
        }

        np_dhkey_t partner_of_node_dhkey = np_aaatoken_get_partner_fp(join_node_token);
        if (_np_dhkey_equal(&zero_dhkey,       &partner_of_node_dhkey) == true ||
        	_np_dhkey_equal(&join_ident_dhkey, &partner_of_node_dhkey) == false) 
        {
            char fp_i[65], fp_p[65];
            _np_dhkey_str(&join_ident_dhkey, fp_i);
            _np_dhkey_str(&partner_of_node_dhkey, fp_p);
            log_msg(LOG_WARN,
                "JOIN request: identity fingerprint must match partner fingerprint in node token. (identity: %s / partner: %s)",
                fp_i, fp_p
            );
            goto __np_cleanup__;
        }

        log_debug_msg(LOG_DEBUG, "JOIN request: identity %s would like to join", _np_key_as_str(join_node_key));
        // everything is fine and we can continue        
        authn_event.target_dhkey = join_ident_dhkey;
        authn_event.user_data = join_ident_token;
    }
    
    join_node_key = _np_keycache_find(context, join_node_dhkey);
    if (join_node_key == NULL) 
    {
        // no handshake before join ? exit join protocol ...
        log_debug_msg(LOG_DEBUG, "JOIN request: no corresponding node key found");
        goto __np_cleanup__;
    } 
    else if (join_node_key != NULL && join_ident_token == NULL)
    {   // pure node join without additional identity :-(
        log_debug_msg(LOG_DEBUG, "JOIN request: node     %s would like to join", _np_key_as_str(join_node_key));
        authn_event.target_dhkey = msg_event.target_dhkey;
        authn_event.user_data = join_node_token;

        _np_key_handle_event(context->my_identity, authn_event, false);
    }
    else if(join_node_key != NULL && join_ident_token != NULL)
    {   // update node token and wait for identity authentication
        log_debug_msg(LOG_DEBUG, "JOIN request: node     %s would like to join", _np_key_as_str(join_node_key));
        np_util_event_t token_event = { .context=context, .type=evt_token|evt_external };
        token_event.target_dhkey = join_node_dhkey;
        token_event.user_data = join_node_token;
        // update node token
        _np_key_handle_event(join_node_key, token_event, false);
        // identity authn
        _np_key_handle_event(context->my_identity, authn_event, false);
    }
    else
    {   // silently exit join protocol as we already joined this key
        log_debug_msg(LOG_DEBUG, "JOIN request: no corresponding identity key found");
    }
    
    // authenticate identity key
    
    __np_cleanup__:
        if (join_ident_token != NULL) {
            np_unref_obj(np_aaatoken_t, join_ident_token, "np_token_factory_read_from_tree");
            // np_unref_obj(np_key_t, join_ident_key, "_np_keycache_find_or_create");
        }
        np_unref_obj(np_aaatoken_t, join_node_token, "np_token_factory_read_from_tree");
        np_unref_obj(np_key_t, join_node_key, "_np_keycache_find");

    return true;
}

bool _np_in_ack(np_state_t* context, np_util_event_t msg_event)
{
    log_debug_msg(LOG_TRACE, "start: bool __np_in_ack(...){");

    NP_CAST(msg_event.user_data, np_message_t, msg);

    np_dhkey_t ack_in_dhkey = _np_msgproperty_dhkey(INBOUND, _NP_MSG_ACK);
    np_key_t* ack_key = _np_keycache_find(context, ack_in_dhkey);
    NP_CAST(sll_first(ack_key->entities)->val, np_msgproperty_t, property);

    CHECK_STR_FIELD(msg->body, _NP_MSG_INST_RESPONSE_UUID, ack_uuid);
    
    np_tree_elem_t* response_entry = np_tree_find_str(property->response_handler, ack_uuid.value.s);
    if(response_entry != NULL)
    {   // just an acknowledgement of own messages send out earlier
        NP_CAST(response_entry->val.value.v, np_responsecontainer_t, response);
        log_debug_msg(LOG_DEBUG, "msg (%s) is acknowledgment of uuid=%s", msg->uuid, np_treeval_to_str(ack_uuid, NULL) );
        response->received_at = np_time_now();
    }
    else 
    {
        log_debug_msg(LOG_DEBUG, "msg (%s) is acknowledgment of uuid=%s but we do not know of this msg",
                                msg->uuid, np_treeval_to_str(ack_uuid, NULL) );
    }
 
    __np_cleanup__:
    np_unref_obj(np_key_t, ack_key, "_np_keycache_find");

    return true;
}

// TODO: write a function that handles path discovery
// TODO: if this is not the target node, add my own address to the update message
// TODO: if this is the target node, change target to sending instance and send again
// receive information about new nodes in the network and try to contact new nodes
bool _np_in_update(np_state_t* context, np_util_event_t msg_event)
{
    log_debug_msg(LOG_DEBUG, "start: bool _np_in_update(np_jobargs_t* args){");

    NP_CAST(msg_event.user_data, np_message_t, msg);

    np_tree_t* update_tree = np_tree_find_str(msg->body, _NP_URN_NODE_PREFIX)->val.value.tree;

    np_aaatoken_t* update_token = NULL;
    np_new_obj(np_aaatoken_t, update_token);

    np_aaatoken_decode(update_tree, update_token);

    if (false == _np_aaatoken_is_valid(update_token, np_aaatoken_type_node))
    {
        goto __np_cleanup__;
    }

    np_dhkey_t update_dhkey = np_aaatoken_get_fingerprint(update_token, false);
    np_key_t* update_key = _np_keycache_find(context, update_dhkey);

    if (NULL == update_key)
    {   // potentially join the new node
        update_key = _np_keycache_find_or_create(context, update_dhkey);
        np_util_event_t update_event = { .type=(evt_external|evt_token), .context=context, .user_data=update_token, .target_dhkey=update_dhkey};
        _np_keycache_handle_event(context, update_dhkey, update_event, false);
        np_unref_obj(np_key_t, update_key,"_np_keycache_find_or_create");

        // and forward the token to another hop
        np_dhkey_t update_prop_dhkey = _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_UPDATE_REQUEST);
        update_event.type = (evt_message|evt_internal);
        update_event.user_data = msg;
        update_event.target_dhkey = update_prop_dhkey;
        np_ref_obj(np_message_t, msg, ref_obj_creation);

        _np_keycache_handle_event(context, update_prop_dhkey, update_event, false);
    }
    else
    {
        np_unref_obj(np_key_t, update_key, "_np_keycache_find");
    }

    __np_cleanup__:
    np_unref_obj(np_aaatoken_t, update_token, ref_obj_creation);

    return true;
}

bool _np_in_discover_sender(np_state_t* context, np_util_event_t msg_event)
{
    log_debug_msg(LOG_TRACE, "start: bool _np_in_discover_sender(...){");

    NP_CAST(msg_event.user_data, np_message_t, discover_msg_in);
    np_aaatoken_t* msg_token = NULL;

    CHECK_STR_FIELD(discover_msg_in->header, _NP_MSG_HEADER_SUBJECT, msg_subject); // dicover sender or receiver
    CHECK_STR_FIELD(discover_msg_in->header, _NP_MSG_HEADER_TO, msg_to); // note: this is the hash of the real message subject

    // extract e2e encryption details for sender
    msg_token = np_token_factory_read_from_tree(context, discover_msg_in->body);
    if (msg_token)
    {
        np_key_t* subject_key = _np_keycache_find_or_create(context, msg_to.value.dhkey);
        np_dhkey_t discovery_sender = np_dhkey_create_from_hostport(msg_subject.value.s, "0");

        np_util_event_t discover_event = { .type=(evt_token|evt_external), .context=context, .user_data=msg_token, .target_dhkey=discovery_sender };
        _np_keycache_handle_event(context, msg_to.value.dhkey, discover_event, false);

        np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
        np_unref_obj(np_aaatoken_t, msg_token, "np_token_factory_read_from_tree");
    }

    __np_cleanup__: {}

    return true;
}

bool _np_in_available_sender(np_state_t* context, np_util_event_t msg_event)
{
    log_trace_msg(LOG_TRACE, "start: bool _np_in_available_sender(...){");

    NP_CAST(msg_event.user_data, np_message_t, available_msg_in);

    // extract e2e encryption details for sender
    np_message_intent_public_token_t* msg_token = NULL;

    msg_token = np_token_factory_read_from_tree(context, available_msg_in->body);
    if (msg_token)
    {
        np_dhkey_t available_msg_type = _np_msgproperty_dhkey(INBOUND, msg_token->subject);
        
        np_util_event_t authz_event = { .type=(evt_token|evt_external|evt_authz), .context=context, .user_data=msg_token, .target_dhkey=available_msg_type };
        _np_keycache_handle_event(context, context->my_identity->dhkey, authz_event, false);
    }
    return true;
}

bool _np_in_discover_receiver(np_state_t* context, np_util_event_t msg_event)
{
    log_debug_msg(LOG_TRACE, "start: bool _np_in_discover_receiver(...){");

    NP_CAST(msg_event.user_data, np_message_t, discover_msg_in);
    np_aaatoken_t* msg_token = NULL;

    CHECK_STR_FIELD(discover_msg_in->header, _NP_MSG_HEADER_SUBJECT, msg_subject);
    CHECK_STR_FIELD(discover_msg_in->header, _NP_MSG_HEADER_TO, msg_to); // note: this is the hash of the real message subject

    // extract e2e encryption details for sender
    msg_token = np_token_factory_read_from_tree(context, discover_msg_in->body); 
    if (msg_token)
    {
        np_key_t* subject_key = _np_keycache_find_or_create(context, msg_to.value.dhkey);
        np_dhkey_t discovery_receiver = np_dhkey_create_from_hostport(msg_subject.value.s, "0");    

        np_util_event_t discover_event = { .type=(evt_token|evt_external), .context=context, .user_data=msg_token, .target_dhkey=discovery_receiver };
        _np_keycache_handle_event(context, msg_to.value.dhkey, discover_event, false);

        np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
        np_unref_obj(np_aaatoken_t, msg_token, "np_token_factory_read_from_tree");
    }
    
    __np_cleanup__: {}

    return true;
}

bool _np_in_available_receiver(np_state_t* context, np_util_event_t msg_event)
{
    log_trace_msg(LOG_TRACE, "start: bool _np_in_available_receiver(...){");

    NP_CAST(msg_event.user_data, np_message_t, available_msg_in);

    // extract e2e encryption details for sender
    np_message_intent_public_token_t* msg_token = NULL;

    msg_token = np_token_factory_read_from_tree(context, available_msg_in->body);
    if (msg_token)
    {
        np_dhkey_t available_msg_type = _np_msgproperty_dhkey(OUTBOUND, msg_token->subject);    
        np_util_event_t authz_event = { .type=(evt_token|evt_external|evt_authz), .context=context, .user_data=msg_token, .target_dhkey=available_msg_type };
        _np_keycache_handle_event(context, context->my_identity->dhkey, authz_event, false);
    }
    return true;
}

bool _np_in_authenticate(np_state_t* context, np_util_event_t msg_event)
{/*
    log_trace_msg(LOG_TRACE, "start: bool _np_in_authenticate(np_jobargs_t* args){");
    np_aaatoken_t* sender_token = NULL;
    np_aaatoken_t* authentication_token = NULL;
    np_message_t *msg_in = args.msg;

    _np_msgproperty_threshold_increase(args.properties);

    CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_from);
    np_dhkey_t reply_to_key = msg_from.value.dhkey;
#ifdef DEBUG
        char reply_to_dhkey_as_str[65];
        _np_dhkey_str(&reply_to_key, reply_to_dhkey_as_str);
#endif
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "reply key: %s", reply_to_dhkey_as_str );

    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "reply key: %s", reply_to_dhkey_as_str );

    sender_token = _np_aaatoken_get_sender_token(context, (char*) _NP_MSG_AUTHENTICATION_REQUEST,  &msg_from.value.dhkey);
    if (NULL == sender_token)
    {
        goto __np_cleanup__;
    }

    bool decrypt_ok = _np_message_decrypt_payload(msg_in, sender_token);
    if (false == decrypt_ok)
    {
        goto __np_cleanup__;
    }
    np_tree_find_str(sender_token->extensions_local, "msg_threshold")->val.value.ui++;

    // extract e2e encryption details for sender
    authentication_token = np_token_factory_read_from_tree(context, msg_in->body);

    // always?: just store the available messages in memory and update if new data arrives
    if (false == _np_aaatoken_is_valid(authentication_token, np_aaatoken_type_message_intent))
    {
        goto __np_cleanup__;
    }

    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now checking (remote) authentication of token");
    struct  np_token tmp;
    bool authenticate = context->authenticate_func(context, np_aaatoken4user(&tmp, authentication_token));
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "authentication of token: %"PRIu8, authenticate);
    if (authenticate)
    {
        authentication_token->state |= AAA_AUTHENTICATED;
    }

    if (IS_AUTHENTICATED(authentication_token->state) )
    {

        np_aaatoken_t* old_token = _np_aaatoken_add_receiver(_NP_MSG_AUTHENTICATION_REPLY, sender_token);
        np_unref_obj(np_aaatoken_t, old_token, "_np_aaatoken_add_receiver");
        np_tree_t* token_data = np_tree_create();

        np_aaatoken_encode(token_data, authentication_token);
        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out);
        _np_message_create(msg_out, reply_to_key, context->my_node_key->dhkey, _NP_MSG_AUTHENTICATION_REPLY, token_data);
        np_msgproperty_t* prop_route = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHENTICATION_REPLY);

        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending back authenticated data to %s", reply_to_dhkey_as_str);
        _np_job_submit_route_event(context, 0.0, prop_route, NULL, msg_out);
        np_unref_obj(np_message_t, msg_out,ref_obj_creation);
    }
    else
    {
        log_msg(LOG_WARN, "unknown security token received for authentication, dropping token");
        log_msg(LOG_WARN, "i:%s s:%s", authentication_token->issuer, authentication_token->subject);
    }

    __np_cleanup__:
    np_unref_obj(np_aaatoken_t, sender_token,"_np_aaatoken_get_sender_token");
    np_unref_obj(np_aaatoken_t, authentication_token, "np_token_factory_read_from_tree");

    // __np_return__:
    _np_msgproperty_threshold_decrease(args.properties);
    return;*/
}

bool _np_in_authenticate_reply(np_state_t* context, np_util_event_t msg_event)
{/*
    log_trace_msg(LOG_TRACE, "start: bool _np_in_authenticate_reply(np_jobargs_t* args){");
    np_aaatoken_t* authentication_token = NULL;
    np_aaatoken_t* sender_token = NULL;
    np_key_t* subject_key = NULL;

    // args.properties->msg_threshold++;

    CHECK_STR_FIELD(args.msg->header, _NP_MSG_HEADER_FROM, msg_from);

    sender_token = _np_aaatoken_get_sender_token(context, (char*) _NP_MSG_AUTHENTICATION_REPLY,  &msg_from.value.dhkey);
    if (NULL == sender_token)
    {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "no sender token for authentication reply found");
        goto __np_cleanup__;
    }

    // TODO: the following should not be required/possible, because it invalidates the token
    bool decrypt_ok = _np_message_decrypt_payload(args.msg, sender_token);
    if (false == decrypt_ok)
    {
        log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "decryption of authentication reply failed");
        goto __np_cleanup__;
    }
    np_tree_find_str(sender_token->extensions_local, "msg_threshold")->val.value.ui++;

    // extract e2e encryption details for sender
    authentication_token = np_token_factory_read_from_tree(context, args.msg->body);

    if (authentication_token != NULL) {
        np_dhkey_t search_key = { 0 };
        // TODO: validate token technically again
        if (0 == strncmp(authentication_token->subject, _NP_URN_NODE_PREFIX, 12))
        {
            search_key = np_dhkey_create_from_hash(authentication_token->issuer);
            // TODO: trigger JOIN request again if node has not joined ?

        } // TODO: add a token type to identify msg exchanges, nodes and real persons
        else // if (0 == strncmp(authentication_token->subject, "urn:np:msg:", 11))
        {
            search_key = np_dhkey_create_from_hostport( authentication_token->subject, "0");
        }

        subject_key = _np_keycache_find_or_create(context, search_key);

        if (0 == strncmp(authentication_token->subject, _NP_URN_NODE_PREFIX, 12))
        {
            subject_key->aaa_token->state |= AAA_AUTHENTICATED;
        }
        else // if (0 == strncmp(authentication_token->subject, "urn:np:msg:", 11))
        {
            pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
            while (NULL != iter)
            {
                np_aaatoken_t* tmp_token = iter->val;
                if (0 == strncmp(tmp_token->uuid, authentication_token->uuid, 255))
                {
                    tmp_token->state |= AAA_AUTHENTICATED;
                    // _np_msgproperty_check_receiver_msgcache(subject_key->recv_property,_np_aaatoken_get_issuer(tmp_token));
                    break;
                }
                // TODO: move to msgcache.h and change parameter
                pll_next(iter);
            }

            iter = pll_first(subject_key->send_tokens);
            while (NULL != iter)
            {
                np_aaatoken_t* tmp_token = iter->val;
                if (0 == strncmp(tmp_token->uuid, authentication_token->uuid, 255))
                {
                    tmp_token->state |= AAA_AUTHENTICATED;
                    // _np_msgproperty_check_sender_msgcache(subject_key->send_property);
                    break;
                }
                // TODO: move to msgcache.h and change parameter
                pll_next(iter);
            }
        }
    }
    __np_cleanup__:
    np_unref_obj(np_aaatoken_t, authentication_token, "np_token_factory_read_from_tree");
    np_unref_obj(np_aaatoken_t, sender_token,"_np_aaatoken_get_sender_token");

    // __np_return__:
    // args.properties->msg_threshold--;
    np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
    return; */
}

bool _np_in_authorize(np_state_t* context, np_util_event_t msg_event)
{/*
    log_trace_msg(LOG_TRACE, "start: bool _np_in_authorize(np_jobargs_t* args){");

    np_aaatoken_t* sender_token = NULL;
    np_aaatoken_t* authorization_token = NULL;

    np_message_t *msg_in = args.msg;

    _np_msgproperty_threshold_increase(args.properties);

    CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_from);
    np_dhkey_t reply_to_key = msg_from.value.dhkey;
#ifdef DEBUG
        char reply_to_dhkey_as_str[65];
        _np_dhkey_str(&reply_to_key, reply_to_dhkey_as_str);
#endif
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "reply key: %s", reply_to_dhkey_as_str );

    sender_token = _np_aaatoken_get_sender_token(context, (char*) _NP_MSG_AUTHORIZATION_REQUEST,  &msg_from.value.dhkey);
    if (NULL == sender_token)
    {
        goto __np_cleanup__;
    }

    bool decrypt_ok = _np_message_decrypt_payload(msg_in, sender_token);
    if (false == decrypt_ok)
    {
        goto __np_cleanup__;
    }

    np_tree_find_str(sender_token->extensions_local, "msg_threshold")->val.value.ui++;
    // extract e2e encryption details for sender
    authorization_token = np_token_factory_read_from_tree(context, msg_in->body);

    // always?: just store the available messages in memory and update if new data arrives
    if (false == _np_aaatoken_is_valid(authorization_token, np_aaatoken_type_message_intent))
    {
        goto __np_cleanup__;
    }

    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now checking (remote) authorization of token");
    struct np_token tmp;
    bool authorize = context->authorize_func(context, np_aaatoken4user(&tmp, authorization_token));
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "authorize of token: %"PRIu8, authorize);
    if (authorize)
    {
        authorization_token->state |= AAA_AUTHORIZED;
    }

    if (IS_AUTHORIZED(authorization_token->state) )
    {
        np_aaatoken_t* old_token = _np_aaatoken_add_receiver(_NP_MSG_AUTHORIZATION_REPLY, sender_token);
        np_unref_obj(np_aaatoken_t, old_token, "_np_aaatoken_add_receiver");

        np_tree_t* token_data = np_tree_create();
        np_aaatoken_encode(token_data, authorization_token);

        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out);
        _np_message_create(msg_out, reply_to_key, context->my_node_key->dhkey, _NP_MSG_AUTHORIZATION_REPLY, token_data);
        np_msgproperty_t* prop_route = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHORIZATION_REPLY);

        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending back authorized data to %s", reply_to_dhkey_as_str);
        _np_job_submit_route_event(context, 0.0, prop_route, NULL, msg_out);
        np_unref_obj(np_message_t, msg_out,ref_obj_creation);
    }
    else
    {
        log_msg(LOG_WARN, "unknown security token received for authorization, dropping token");
        log_msg(LOG_WARN, "i:%s s:%s", authorization_token->issuer, authorization_token->subject);
    }

    __np_cleanup__:
    np_unref_obj(np_aaatoken_t, sender_token, "_np_aaatoken_get_sender_token");
    np_unref_obj(np_aaatoken_t, authorization_token, "np_token_factory_read_from_tree");

    // __np_return__:
    _np_msgproperty_threshold_decrease(args.properties);
    return;*/
}

bool _np_in_authorize_reply(np_state_t* context, np_util_event_t msg_event)
{/*
    log_trace_msg(LOG_TRACE, "start: bool _np_in_authorize_reply(np_jobargs_t* args){");
    np_aaatoken_t* authorization_token = NULL;
    np_aaatoken_t* sender_token = NULL;

    // args.properties->msg_threshold++;
    np_key_t* subject_key = NULL;

    CHECK_STR_FIELD(args.msg->header, _NP_MSG_HEADER_FROM, msg_from);

    sender_token = _np_aaatoken_get_sender_token(context, (char*) _NP_MSG_AUTHORIZATION_REPLY,  &msg_from.value.dhkey);
    if (NULL == sender_token)
    {
        goto __np_cleanup__;
    }

    bool decrypt_ok = _np_message_decrypt_payload(args.msg, sender_token);
    if (false == decrypt_ok)
    {
        goto __np_cleanup__;
    }

     np_tree_find_str(sender_token->extensions_local, "msg_threshold")->val.value.ui++;

    // extract e2e encryption details for sender
    authorization_token = np_token_factory_read_from_tree(context, args.msg->body);

    if (authorization_token != NULL) {
        np_dhkey_t search_key = { 0 };

        // TODO: validate token technically again
        if (0 == strncmp(authorization_token->subject, _NP_URN_NODE_PREFIX, 12))
        {
            search_key = np_dhkey_create_from_hash(authorization_token->issuer);
        }
        else // if (0 == strncmp(authorization_token->subject, "urn:np:msg:", 11))
        {
            search_key = np_dhkey_create_from_hostport( authorization_token->subject, "0");
        }

        subject_key = _np_keycache_find_or_create(context, search_key);

        if (0 == strncmp(authorization_token->subject, _NP_URN_NODE_PREFIX, 12))
        {
            subject_key->aaa_token->state |= AAA_AUTHORIZED;
        }
        else // if (0 == strncmp(authorization_token->subject, "urn:np:msg:", 11))
        {
            pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
            while (NULL != iter)
            {
                np_aaatoken_t* tmp_token = iter->val;
                if (0 == strncmp(tmp_token->uuid, authorization_token->uuid, 255))
                {
                    tmp_token->state |= AAA_AUTHORIZED;
                    // _np_msgproperty_check_receiver_msgcache(subject_key->recv_property,_np_aaatoken_get_issuer(tmp_token));
                    break;
                }
                // TODO: move to msgcache.h and change parameter
                pll_next(iter);
            }

            iter = pll_first(subject_key->send_tokens);
            while (NULL != iter)
            {
                np_aaatoken_t* tmp_token = iter->val;
                if (0 == strncmp(tmp_token->uuid, authorization_token->uuid, 255))
                {
                    tmp_token->state |= AAA_AUTHORIZED;
                    // _np_msgproperty_check_sender_msgcache(subject_key->send_property);
                    break;
                }
                pll_next(iter);
            }
        }
    }
    __np_cleanup__:
    np_unref_obj(np_aaatoken_t, authorization_token, "np_token_factory_read_from_tree");
    np_unref_obj(np_aaatoken_t, sender_token,"_np_aaatoken_get_sender_token");

    // __np_return__:
    // args.properties->msg_threshold--;
    np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
    return;*/
}

bool _np_in_account(np_state_t* context, np_util_event_t msg_event)
{/*
    log_trace_msg(LOG_TRACE, "start: bool _np_in_account(np_jobargs_t* args){");
    np_aaatoken_t* sender_token = NULL;
    np_aaatoken_t* accounting_token = NULL;

    _np_msgproperty_threshold_increase(args.properties);

    CHECK_STR_FIELD(args.msg->header, _NP_MSG_HEADER_FROM, msg_from);

    sender_token = _np_aaatoken_get_sender_token(context, (char*) _NP_MSG_ACCOUNTING_REQUEST,  &msg_from.value.dhkey);
    if (NULL == sender_token)
    {
        goto __np_cleanup__;
    }

    np_tree_find_str(sender_token->extensions_local, "msg_threshold")->val.value.ui++;
    bool decrypt_ok = _np_message_decrypt_payload(args.msg, sender_token);
    if (false == decrypt_ok)
    {
        goto __np_cleanup__;
    }

    accounting_token  = np_token_factory_read_from_tree(context, args.msg->body);
    if (accounting_token != NULL) {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now checking (remote) accounting of token");
        struct np_token tmp;
        bool accounting = context->accounting_func(context, np_aaatoken4user(&tmp, accounting_token));
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "accounting of token: %"PRIu8, accounting);

    }
    __np_cleanup__:
    np_unref_obj(np_aaatoken_t, accounting_token, "np_token_factory_read_from_tree");
    np_unref_obj(np_aaatoken_t, sender_token, "_np_aaatoken_get_sender_token");

    // __np_return__:
    _np_msgproperty_threshold_decrease(args.properties);
    return;*/
}

bool _np_in_handshake(np_state_t* context, np_util_event_t msg_event)
{
    log_trace_msg(LOG_TRACE, "start: bool _np_msgin_handshake(np_message_t* msg) {");

    log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 2");
    NP_CAST(msg_event.user_data, np_message_t, msg);

    np_handshake_token_t* handshake_token = NULL;
    np_key_t* msg_source_key = NULL;
    np_key_t* hs_wildcard_key = NULL;
    np_key_t* hs_alias_key = NULL;   
    
    handshake_token = np_token_factory_read_from_tree(context, msg->body);

    if (handshake_token == NULL || !_np_aaatoken_is_valid(handshake_token, np_aaatoken_type_handshake)) 
    {
        log_msg(LOG_ERROR, "incorrect handshake signature in message");
        goto __np_cleanup__;
    }
    else
    {
        log_debug_msg(LOG_DEBUG,
                    "decoding of handshake message from %s / %s (i:%f/e:%f) complete",
                    handshake_token->subject, handshake_token->issuer, handshake_token->issued_at, handshake_token->expires_at);
    }    
    // store the handshake data in the node cache,
    np_dhkey_t search_key = { 0 };
    _np_str_dhkey(handshake_token->issuer, &search_key);

    msg_source_key = _np_keycache_find_or_create(context, search_key);
    if (NULL == msg_source_key)
    {   // should never happen
        log_msg(LOG_ERROR, "Handshake key is NULL!");
        goto __np_cleanup__;
    }
    // setup sending encryption
    np_util_event_t hs_event = msg_event;
    hs_event.user_data = handshake_token;
    hs_event.type = (evt_external | evt_token);
    _np_keycache_handle_event(context, search_key, hs_event, false);
    
    log_msg(LOG_DEBUG, "Update msg source done! %p", msg_source_key);

    // TODO: passive check, then don't setup alias key, but alias_key == node_key
    // if ((msg_source_key->node->protocol & PASSIVE) == PASSIVE && alias_key->network == NULL) {

    // setup inbound decryption session with the alias key
    hs_alias_key = _np_keycache_find_or_create(context, msg_event.target_dhkey);
    hs_event.type = (evt_internal | evt_token);
    _np_key_handle_event(hs_alias_key, hs_event, false);
    np_unref_obj(np_key_t, hs_alias_key, "_np_keycache_find_or_create");

    log_debug_msg(LOG_TRACE, "Update alias done! %p", hs_alias_key);

    // finally delete possible wildcard key
    char* tmp_connection_str = np_get_connection_string_from(msg_source_key, false);
    np_dhkey_t wildcard_dhkey = np_dhkey_create_from_hostport("*", tmp_connection_str);
    hs_wildcard_key = _np_keycache_find(context, wildcard_dhkey);
    if (NULL != hs_wildcard_key)
    {
        np_util_event_t hs_event = msg_event;
        hs_event.type = (evt_external | evt_token);
        hs_event.user_data = handshake_token;
        _np_key_handle_event(hs_wildcard_key, hs_event, false);
        log_debug_msg(LOG_TRACE, "Update wildcard done!");
        np_unref_obj(np_key_t, hs_wildcard_key, "_np_keycache_find");
    } 
    free(tmp_connection_str);

    __np_cleanup__:
        np_unref_obj(np_aaatoken_t, handshake_token, "np_token_factory_read_from_tree");
        np_unref_obj(np_key_t, msg_source_key, "_np_keycache_find_or_create");

    return true;
}

/*
bool _np_in_handshake(np_state_t* context, np_util_event_t msg_event)
{
    log_trace_msg(LOG_TRACE, "start: bool _np_in_handshake(np_jobargs_t* args){");

    log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 1");
    _LOCK_MODULE(np_handshake_t) 
    {
        log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 2");
        np_node_t* tokens_node = NULL;
        np_handshake_token_t* handshake_token = NULL;
        np_key_t* msg_source_key = NULL;
        
        np_key_t* hs_wildcard_key = NULL;
        np_key_t* alias_key = args.target;		
        
        _np_message_deserialize_chunked(args.msg);

        // TODO: check if the complete buffer was read (byte count match)
        handshake_token = np_token_factory_read_from_tree(context, args.msg->body);

        if (handshake_token == NULL || !_np_aaatoken_is_valid(handshake_token, np_aaatoken_type_handshake)) {
            log_msg(LOG_ERROR, "incorrect handshake signature in message");
            goto __np_cleanup__;
        }

        // store the handshake data in the node cache,
        np_dhkey_t search_key = { 0 };
        _np_str_dhkey(handshake_token->issuer, &search_key);

        if (_np_dhkey_cmp(&context->my_node_key->dhkey, &search_key) == 0) {
            log_msg(LOG_ERROR, "Cannot perform a handshake with myself!");
            goto __np_cleanup__;
        }
        msg_source_key = _np_keycache_find_or_create(context, search_key);

        log_debug_msg(LOG_HANDSHAKE | LOG_DEBUG,
            "decoding of handshake message from %s (i:%f/e:%f) complete",
            handshake_token->subject, handshake_token->issued_at, handshake_token->expires_at);

        // should never happen
        if (NULL == msg_source_key)
        {
            log_msg(LOG_ERROR, "Handshake key is NULL!");
            goto __np_cleanup__;
        }

        // extract node data from handshake messages
        tokens_node = _np_node_from_token(handshake_token, np_aaatoken_type_handshake);
        if (NULL == tokens_node) {
            log_msg(LOG_ERROR, "Handshake token data is NULL!");
            _np_keycache_remove(context, search_key);
            goto __np_cleanup__;
        }

        log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE| LOG_DEBUG, "handshake for %s", _np_key_as_str(msg_source_key));
        msg_source_key->type |= np_key_type_node;

        double now = np_time_now();
        np_msgproperty_t* msg_prop_handshake = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_HANDSHAKE);

        if (msg_source_key->node == NULL || msg_source_key->node->_handshake_status == np_handshake_status_Connected) {            		
            if (msg_source_key->node != NULL && 
                msg_source_key->node->_handshake_status == np_handshake_status_Connected &&
                now < (msg_source_key->node->handshake_send_at + msg_prop_handshake->msg_ttl)) {
                log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE | LOG_DEBUG,
                    "handshake for alias %s received, but alias in state %s and not ready to reconnect",
                    _np_key_as_str(alias_key),
                    np_handshake_status_str[msg_source_key->node->_handshake_status]
                );
                goto __np_cleanup__;
            }
            // recover handshake_send_at attribute
            if(msg_source_key->node != NULL) tokens_node->handshake_send_at = msg_source_key->node->handshake_send_at;

            np_ref_switch(np_node_t, msg_source_key->node, ref_key_node, tokens_node);
            np_node_set_handshake(msg_source_key->node, np_handshake_status_RemoteInitiated);
        }
        else if (
            msg_source_key->node->_handshake_status == np_handshake_status_Disconnected ||
            msg_source_key->node->_handshake_status == np_handshake_status_SelfInitiated
            )
        {
            tokens_node->handshake_send_at = msg_source_key->node->handshake_send_at;
            np_node_set_handshake(tokens_node, msg_source_key->node->_handshake_status);
            tokens_node->joined_network |= msg_source_key->node->joined_network;
            np_ref_switch(np_node_t, msg_source_key->node, ref_key_node, tokens_node);
        }
        else {
            log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE| LOG_DEBUG,
                "handshake for alias %s received, but alias in state %s", 
                _np_key_as_str(alias_key),
               np_handshake_status_str[msg_source_key->node->_handshake_status]
            );
            goto __np_cleanup__;
        }

        if (msg_source_key->node == NULL) {
            log_msg(LOG_ERROR, "Handshake message does not contain necessary node data");
            goto __np_cleanup__;
        }

        // detect keys node info by wildcard if necessary 
        if (msg_source_key->node->joined_network == false) {
            char* tmp_connection_str = np_get_connection_string_from(msg_source_key, false);
            np_dhkey_t wildcard_dhkey = np_dhkey_create_from_hostport("*", tmp_connection_str);
            free(tmp_connection_str);

            log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 3");
            _LOCK_MODULE(np_network_t)
            {
                log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 4");

                hs_wildcard_key = _np_keycache_find(context, wildcard_dhkey);
                if (NULL != hs_wildcard_key && NULL != hs_wildcard_key->network &&
                    (hs_wildcard_key->node == NULL || !hs_wildcard_key->node->joined_network)
                    )
                {
                    np_network_t* old_network = hs_wildcard_key->network;
                    np_ref_obj(np_network_t, old_network, "usage_of_old_network");

                    log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 5");
                    _LOCK_ACCESS(&old_network->access_lock)
                    {
                        log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 6");
                        // _np_network_stop(old_network);
                        // Updating handshake key with already existing network
                        // structure of the wildcard key
                        log_debug_msg(LOG_ROUTING | LOG_DEBUG,
                            "Updating wildcard key %s to %s",
                            _np_key_as_str(hs_wildcard_key),
                            _np_key_as_str(msg_source_key));
                        
                        np_node_set_handshake(msg_source_key->node, hs_wildcard_key->node->_handshake_status);
                        
                        // msg_source_key->aaa_token = hs_wildcard_key->aaa_token;
                        hs_wildcard_key->aaa_token = NULL;

                        if (msg_source_key->parent_key == NULL) {
                            msg_source_key->parent_key = hs_wildcard_key->parent_key;
                            hs_wildcard_key->parent_key = NULL;
                        }
                        _np_network_remap_network(msg_source_key, hs_wildcard_key);
                    }
                    np_unref_obj(np_network_t, old_network, "usage_of_old_network");					
                    np_ref_switch(np_key_t, hs_wildcard_key->parent_key, ref_key_parent, msg_source_key);
                }
                np_unref_obj(np_key_t, hs_wildcard_key, "_np_keycache_find");
            }
        }
        bool process_handshake = true;
        log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 7");

        _LOCK_ACCESS(&msg_source_key->node->lock) {
            log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 8");
            _LOCK_MODULE(np_network_t)
            {
                log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 9");

                if (NULL == msg_source_key->network)//|| (msg_source_key->network->last_received_date + 30) < np_time_now())
                {
                    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "handshake: init alias (%s) network", _np_key_as_str(alias_key));

                    if ((msg_source_key->node->protocol & PASSIVE) == PASSIVE && alias_key->network == NULL) {
                        char tmp[255];
                        log_msg(LOG_ERROR, "could not initiate passive network to alias key for %s. network missing",
                            np_network_get_desc(msg_source_key,tmp)
                        );
                        process_handshake = false;
                    }
                    else {
                        np_network_t * new_msg_source_key_network;
                        np_new_obj(np_network_t, new_msg_source_key_network);

                        _np_network_init(
                            new_msg_source_key_network,
                            false,
                            msg_source_key->node->protocol,
                            msg_source_key->node->dns_name,
                            msg_source_key->node->port,
                            ((msg_source_key->node->protocol & PASSIVE) == PASSIVE ?
                                alias_key->network->socket :
                                -1//msg_source_key->network->socket
                                )
                            , ((msg_source_key->node->protocol & PASSIVE) == PASSIVE ?
                            (context->my_node_key->network->socket_type & MASK_PROTOCOLL)
                                : UNKNOWN_PROTO)
                        );

                        if (true == new_msg_source_key_network->initialized)
                        {
                            _np_network_set_key(new_msg_source_key_network, msg_source_key);
                            _np_key_set_network(msg_source_key, new_msg_source_key_network);
                        }
                        else
                        {
                            log_msg(LOG_ERROR, "could not initiate network to alias key for %s:%s",
                                new_msg_source_key_network->ip, new_msg_source_key_network->port
                            );
                            process_handshake = false;
                        }
                        np_unref_obj(np_network_t, new_msg_source_key_network, ref_obj_creation);
                    }
                }
            }

            // Resolve handshake resend in too short timeframe
            if (process_handshake) {
                if (alias_key->node != NULL && alias_key->node->_handshake_status == np_handshake_status_Connected) {
                    process_handshake = now > (alias_key->node->handshake_send_at + msg_prop_handshake->msg_ttl);
                    if (!process_handshake) {
                        log_debug_msg(LOG_HANDSHAKE,
                            "Stopping handshake %s as the last handshake may still be valid.",
                            args.msg->uuid
                        );
                    }
                }
            }

            // Resolve handshake on both nodes in same timeframe (SI <-> SI)
            if (process_handshake) {
                // Stop the infinity handshake resend on contradicting handshake sends
                // Maybe even verify the Response UUID and the send UUID match. 

                np_tree_elem_t* response_uuid = np_tree_find_str(args.msg->instructions, _NP_MSG_INST_RESPONSE_UUID);
                np_tree_elem_t* remote_hs_prio = np_tree_find_str(args.msg->header, NP_HS_PRIO);

                if (response_uuid != NULL && alias_key->node != NULL && alias_key->node->_handshake_status == np_handshake_status_SelfInitiated) 
                {
                    if (remote_hs_prio->val.value.ul < context->my_node_key->node->handshake_priority)
                    {
                        process_handshake = false;
                        log_debug_msg(LOG_HANDSHAKE,
                            "Handshake status contradiction. Handshake cannot be processed further. Remote-Prio: %"PRIu32" My-Prio: %"PRIu32" ",
                            remote_hs_prio->val.value.ul, context->my_node_key->node->handshake_priority
                        );
                    } 
                    else
                    {
                        np_node_set_handshake(alias_key->node, np_handshake_status_RemoteInitiated);                        
                        log_debug_msg(LOG_HANDSHAKE,
                            "Handshake status contradiction. Resetting node to remote initiated. Remote-Prio: %"PRIu32" My-Prio: %"PRIu32" ",
                            remote_hs_prio->val.value.ul, context->my_node_key->node->handshake_priority
                        );
                    }
                }
            }

            if (process_handshake) 
            {
                np_state_t* state = context;
                np_waitref_obj(np_aaatoken_t, state->my_node_key->aaa_token, my_node_token, "np_waitref_my_node_key->aaa_token");
                
                np_unref_obj(np_aaatoken_t, my_node_token, "np_waitref_my_node_key->aaa_token");

                //np_aaatoken_t* old_token = NULL;
                if (
                    NULL != msg_source_key->aaa_token &&
                    IS_VALID(msg_source_key->aaa_token->state)
                    )
                {
                    // print warning if overwrite happens
                    log_msg(LOG_WARN,
                        "found valid authentication token for node %s (%s), overwriting...",
                        _np_key_as_str(msg_source_key), np_memory_get_id(msg_source_key->node));
                    //old_token = msg_source_key->aaa_token;
                    // msg_source_key->node->joined_network = false;
                }

                // handle alias key, also in case a new connection has been established
                log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE | LOG_DEBUG,
                    "processing handshake (msg: %s) for alias %s",
                    args.msg->uuid,
                    _np_key_as_str(alias_key));

                np_ref_switch(np_aaatoken_t, alias_key->aaa_token, ref_key_aaa_token, handshake_token);
                np_ref_switch(np_aaatoken_t, msg_source_key->aaa_token, ref_key_aaa_token, handshake_token);

                if (alias_key->node != NULL && msg_source_key->node != NULL) 
                {
                    alias_key->node->handshake_send_at = msg_source_key->node->handshake_send_at;
                }
                np_ref_switch(np_node_t, alias_key->node, ref_key_node, msg_source_key->node);

                // copy over session key
                log_debug_msg(LOG_DEBUG | LOG_HANDSHAKE, "HANDSHAKE SECRET: setting shared secret on %s and alias %s on system %s",
                    _np_key_as_str(msg_source_key), _np_key_as_str(alias_key), _np_key_as_str(context->my_node_key));

                msg_source_key->node->session_key_is_set = 0 == 
                    np_crypto_session(
                        context,
                        &my_node_token->crypto,
                        &msg_source_key->node->session,
                        &msg_source_key->aaa_token->crypto,
                        alias_key->node->_handshake_status != np_handshake_status_SelfInitiated
                    );
                // Implicit: as both keys share the same node the session is exchanged between alias and sending key


                // mark as valid to identify existing connections
                msg_source_key->aaa_token->state |= AAA_VALID;

                bool succ_registerd = false;
                if (alias_key->node->_handshake_status == np_handshake_status_SelfInitiated) 
                {
                    np_node_set_handshake(alias_key->node, np_handshake_status_Connected);
                    succ_registerd = true;
                }
                else if (alias_key->node->_handshake_status == np_handshake_status_RemoteInitiated) 
                {
                    if (_np_network_send_handshake(context, msg_source_key, true, args.msg->uuid))
                    {
                        if (context->settings->n_threads > 1) np_time_sleep(0.05);
                        np_node_set_handshake(alias_key->node, np_handshake_status_Connected);
                        succ_registerd = true;
                    }
                }
                else if (alias_key->node->_handshake_status == np_handshake_status_Disconnected)
                {
                    np_node_set_handshake(alias_key->node, np_handshake_status_RemoteInitiated);
                    if (_np_network_send_handshake(context, msg_source_key, true, args.msg->uuid)) 
                    { 
                        np_node_set_handshake(alias_key->node, np_handshake_status_Connected);
                        succ_registerd = true;
                    }
                }

                if (succ_registerd) {
                    log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE | LOG_DEBUG, "handshake data successfully registered for node %s (alias %s)",
                        _np_key_as_str(msg_source_key), _np_key_as_str(alias_key)
                    );
                }

                if (alias_key->node->_handshake_status == np_handshake_status_Connected) {
                    char tmp[255];
                    log_msg(LOG_INFO, "Connection established to node %s (alias %s / %s)",
                        _np_key_as_str(msg_source_key), _np_key_as_str(alias_key), np_network_get_desc(alias_key, tmp));
                }
            }
        }

    __np_cleanup__:
        np_unref_obj(np_node_t, tokens_node, "_np_node_from_token");
        np_unref_obj(np_aaatoken_t, handshake_token, "np_token_factory_read_from_tree");
        np_unref_obj(np_key_t, msg_source_key, "_np_keycache_find_or_create");
    }
    
}
*/