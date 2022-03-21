//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that a node can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include <inttypes.h>
#include "core/np_comp_node.h"

#include "np_axon.h"
#include "np_aaatoken.h"
#include "np_evloop.h"
#include "util/np_event.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_responsecontainer.h"
#include "np_route.h"

#include "np_eventqueue.h"
#include "util/np_statemachine.h"

// IN_SETUP -> IN_USE transition condition / action #1
bool __is_node_handshake_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_node_handshake_token(...) {");
    NP_CAST(statemachine->_user_data, np_key_t, key);

    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_token) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
    if ( ret) {
        NP_CAST(event.user_data, np_aaatoken_t, hs_token);
        ret &= FLAG_CMP(hs_token->type, np_aaatoken_type_handshake);
        ret &= _np_aaatoken_is_valid(context, hs_token, hs_token->type);
    }
    return ret;
}

bool __is_shutdown_event(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_shutdown_event(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, key);

    bool ret = false;
    
    if (!ret) ret = FLAG_CMP(event.type, evt_shutdown);

    if (ret && FLAG_CMP(event.type, evt_external)) 
    {   
        NP_CAST(event.user_data, np_aaatoken_t, remote_token);

        np_aaatoken_t* local_token = _np_key_get_token(key);

        ret &= _np_aaatoken_is_valid(context, remote_token, np_aaatoken_type_node);
        if (NULL != local_token && ret) ret &= (0 == memcmp(remote_token->crypto.ed25519_public_key, local_token->crypto.ed25519_public_key, crypto_sign_ed25519_PUBLICKEYBYTES) );
    }

    if (ret && FLAG_CMP(event.type, evt_internal)) 
    {
        ret &= _np_dhkey_equal(&key->dhkey, &event.target_dhkey);
    }

    // if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);

    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

bool __is_node_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_node_token(...) {");

    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_token) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
    if ( ret) {
        NP_CAST(event.user_data, np_aaatoken_t, token);
        ret &= FLAG_CMP(token->type, np_aaatoken_type_node);
        ret &= !token->private_key_is_set;
        ret &= _np_aaatoken_is_valid(context, token, token->type);
    }

    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

// IN_USE -> IN_DESTROY transition condition / action #1
bool __is_node_invalid(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_node_invalid(...) {");

    bool ret = false;
    
    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    log_debug_msg(LOG_MISC, "__is_node_invalid(...) { [0]:%p [1]:%p [2]:%p [3]:%p }", 
                  node_key->entity_array[0], node_key->entity_array[1], node_key->entity_array[2], node_key->entity_array[3]);

    if (!ret) ret = FLAG_CMP(node_key->type, np_key_type_unknown);

    if (!ret) ret = (_np_key_get_node(node_key) == NULL);

    double now = np_time_now();

    if (!ret && 
        (node_key->created_at + BAD_LINK_REMOVE_GRACETIME) > now){
        return false;
    }
    np_node_t* node = _np_key_get_node(node_key);

    if (!ret) ret &= (node->connection_attempts > 15);

    if (!ret) // check for not in routing / leafset table anymore
    {    
        ret = (!node->is_in_leafset) && (!node->is_in_routing_table);
        if(ret){log_info(LOG_EXPERIMENT, "bad node [no routing]: %s , is_in_leafset: %d, is_in_routing_table: %d", _np_key_as_str(node_key), node->is_in_leafset, node->is_in_routing_table);}

        log_trace_msg(LOG_TRACE, "end  : bool __is_node_invalid(...) { %d (%d / %d / %f < %f)", 
                        ret, node->is_in_leafset, node->is_in_routing_table, (node_key->created_at + BAD_LINK_REMOVE_GRACETIME), np_time_now());
    }

    if (!ret) // bad node connectivity
    {
        ret  = (node->success_avg < BAD_LINK);
        if(ret){
        log_info(LOG_EXPERIMENT, "bad node [connectivity]: %s success_avg: %f ", _np_key_as_str(node_key), node->success_avg);}
        log_trace_msg(LOG_TRACE, "end  : bool __is_node_invalid(...) { %d (%d / %d / %f < %f)", 
                        ret, node->is_in_leafset, node->is_in_routing_table, (node_key->created_at + BAD_LINK_REMOVE_GRACETIME), np_time_now());
    }

    if (!ret) // token expired
    {
        np_aaatoken_t* node_token = _np_key_get_token(node_key);
        ret = (node_token == NULL);
        if (!ret) {
            ret  = !_np_aaatoken_is_valid(context, node_token, node_token->type);
        }
        if(ret){log_info(LOG_EXPERIMENT, "bad node [token expired]: %s", _np_key_as_str(node_key));}
        log_trace_msg(LOG_TRACE, "end  : bool __is_node_invalid(...) { %d (%d / %d / %f < %f)", 
                        ret, node->is_in_leafset, node->is_in_routing_table, (node_key->created_at + BAD_LINK_REMOVE_GRACETIME), np_time_now());
    }

    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

bool __is_wildcard_key(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_wildcard_key(...) {");

    bool ret = false;

    if (!ret) ret  = FLAG_CMP(event.type, evt_internal);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_node_t);
    if ( ret){
        NP_CAST(event.user_data, np_node_t, node);
        ret &= _np_node_check_address_validity(node);
        ret &= node->host_key[0] == '*';
    }
    

    return ret;
}

bool __is_node_info(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_wildcard_key(...) {");

    bool ret = false;
    
    // NP_CAST(statemachine->_user_data, np_key_t, node_key);
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_internal);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_node_t);
    if ( ret){
        NP_CAST(event.user_data, np_node_t, node);
        ret &= _np_node_check_address_validity(node);
        ret &= node->host_key[0] != '*';
    }

    return ret;
}

void __np_node_set_node(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_set_node(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_node_t, node);

    if(!FLAG_CMP(node_key->type ,np_key_type_node)) {
        np_ref_obj(np_key_t, node_key, "__np_node_set");
        node_key->type |= np_key_type_node;
    }
    log_trace_msg(LOG_TRACE, "start: void __np_node_set_node(...) { %s:%s", node->dns_name, node->port);

    if (node_key->entity_array[2] == NULL) 
    {
        node_key->entity_array[2] = node;
        np_ref_obj(np_node_t, node, "__np_node_set");
    } else {
        log_trace_msg(LOG_TRACE, "start: void __np_node_set_node(...) { %s:%s", ((np_node_t*)node_key->entity_array[2])->dns_name, ((np_node_t*)node_key->entity_array[2])->port);
    }
}

bool __is_node_authn(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    // { .type=(evt_internal|evt_token), .user_data=authn_token, .target_dhkey=event.target_dhkey};
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_node_authn(...) {");

    bool ret = false;
    
    // NP_CAST(statemachine->_user_data, np_key_t, node_key);
    //NP_CAST(event.user_data, np_node_t, my_node);

    if (!ret) ret  = (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_token) );
    if ( ret) ret &=  FLAG_CMP(event.type, evt_authn);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_aaatoken_t);

    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

bool __is_node_identity_authn(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    // { .type=(evt_internal|evt_token), .user_data=authn_token, .target_dhkey=event.target_dhkey};
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_node_authn(...) {");

    bool ret = false;

    // NP_CAST(statemachine->_user_data, np_key_t, node_key);

    if (!ret) ret  = (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_token) );
    if ( ret) ret &=  FLAG_CMP(event.type, evt_authn);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_aaatoken_t);

    if ( ret){ 
        NP_CAST(event.user_data, np_aaatoken_t, token);
        ret &= FLAG_CMP(token->type, np_aaatoken_type_identity);
        if ( ret) {
            np_dhkey_t partner_fp = np_aaatoken_get_partner_fp(token);
            NP_CAST(statemachine->_user_data, np_key_t, node_key);
            ret &= _np_dhkey_equal(&partner_fp, &node_key->dhkey);
        }
    }

    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

void __np_node_set(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_set(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_aaatoken_t, node_token);

    if(!FLAG_CMP(node_key->type ,np_key_type_node)) {
        np_ref_obj(np_key_t, node_key, "__np_node_set");
        node_key->type |= np_key_type_node;
    }

    if (node_token->type == np_aaatoken_type_handshake) 
        node_key->entity_array[0] = node_token;
    if (node_token->type == np_aaatoken_type_node)      
        node_key->entity_array[1] = node_token;

    np_ref_obj(np_aaatoken_t, node_token, "__np_node_set");
    node_token->state = AAA_VALID;
    
    np_node_t* node = _np_node_from_token(node_token, node_token->type);
    if (FLAG_CMP(node->protocol, PASSIVE)) 
    {
        np_key_t* alias_key = _np_keycache_find(context, event.target_dhkey);
        if (NULL != alias_key) {
            // if this node is not null, then a passive node contacted us first
            np_node_t* alias_node = _np_key_get_node(alias_key);
            if (NULL != alias_node) 
            {
                log_warn(LOG_NETWORK, "connecting passive node, check dns name %s / ip %s combination", node->dns_name, alias_node->dns_name);
                node_key->entity_array[2] = alias_node;
                alias_node->protocol |= node->protocol;

                log_debug_msg(LOG_ROUTING, "node_status: %d:%s:%s", alias_node->protocol, alias_node->dns_name, alias_node->port);
                log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE, "node_status: %d %f",    alias_node->_handshake_status, alias_node->handshake_send_at);

                np_ref_obj(np_node_t, alias_node, "_np_node_from_token");
                np_unref_obj(np_node_t, node, "_np_node_from_token");

                node = alias_node;
            }else{
                log_debug(LOG_NETWORK|LOG_ERROR, "try to connect passive node, but found no alias node");
            }
            np_unref_obj(np_key_t, alias_key, "_np_keycache_find");
        }else{
            log_debug(LOG_NETWORK|LOG_ERROR, "try to connect passive node, but found no alias key");
        }
    }

    if (NULL != node) 
    {       
        if(_np_node_cmp(node, node_key->entity_array[2]) != 0) {
            //np_memory_debug_obj(context, node_key->entity_array[2]);
            ASSERT(node_key->entity_array[2]==NULL,"elment needs to be dereferenced first.");
            node_key->entity_array[2] = node;
        }
        np_ref_obj(np_node_t, node_key->entity_array[2], "__np_node_set");

        // handle handshake token after wildcard join
        char* tmp_connection_str = np_get_connection_string_from(node_key, false);
        np_dhkey_t wildcard_dhkey = np_dhkey_create_from_hostport("*", tmp_connection_str);
    
        np_key_t* hs_wildcard_key = _np_keycache_find(context, wildcard_dhkey);
        if (NULL != hs_wildcard_key)
        {
            np_node_t* wc_node = _np_key_get_node(hs_wildcard_key);
            node->handshake_send_at = wc_node->handshake_send_at;
            node->_handshake_status = wc_node->_handshake_status;
        
            np_unref_obj(np_key_t, hs_wildcard_key, "_np_keycache_find");
        }
        log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE, "node_status: %d %f", node->_handshake_status, node->handshake_send_at);
        free(tmp_connection_str);
        np_unref_obj(np_node_t, node, "_np_node_from_token");
    }
    else 
    {
        log_msg(LOG_ERROR, "start: void __np_node_set(...) {");
        ABORT("start: void __np_node_set(...) {");
    }
}

void __np_wildcard_set(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_wildcard_set(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, wildcard_key);
    NP_CAST(event.user_data, np_node_t, node);

    np_ref_obj(np_key_t, wildcard_key, "__np_wildcard_set");
    wildcard_key->type |= np_key_type_wildcard;

    if (wildcard_key->entity_array[2] == NULL) 
    {
        wildcard_key->entity_array[2] = node;   
        np_ref_obj(np_node_t, node, "__np_wildcard_set");
    }
    else
        log_trace_msg(LOG_TRACE, "start: void __np_wildcard_set(...) {");
}

void __np_filter_remove_passive_nodes(np_state_t* context, np_sll_t(np_key_ptr, sll_of_keys), const char* ref_source)
{
    np_sll_t(np_key_ptr, to_remove_keys);
    sll_init(np_key_ptr, to_remove_keys);

    sll_iterator(np_key_ptr) iter = sll_first(sll_of_keys);
    while (iter != NULL)
    {
        np_node_t * node = _np_key_get_node(iter->val);
        if (node != NULL &&
            FLAG_CMP(node->protocol, PASSIVE) )
        {
            sll_append(np_key_ptr,to_remove_keys, iter->val);
        }
        sll_next(iter);
    }
    iter = sll_first(to_remove_keys);
    while (iter != NULL)
    {
        np_key_ptr current = iter->val;
        sll_remove(np_key_ptr, sll_of_keys, current, np_key_ptr_sll_compare_type);
        np_unref_obj(np_key_t, current, ref_source);
        sll_next(iter);
    }
    sll_free(np_key_ptr, to_remove_keys)
}

void __np_node_update(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_update(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    np_node_t* node = _np_key_get_node(node_key);
    float total = 0.0;
    
    float old = node->success_avg;
    for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
    {
        total += node->success_win[i];
    }
    node->success_avg = total / NP_NODE_SUCCESS_WINDOW;
    if (node->success_avg != old)
    {
        log_info(LOG_MISC, "connection status to node %.15s:%.6s success rate now: %1.2f (idx:%2u / val:%2u)", 
                node->dns_name, node->port, node->success_avg, node->success_win_index, node->success_win[node->success_win_index]);
    }

    total = 0.0; 
    old = node->latency;
    for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
    {
        total += node->latency_win[i];
    }
    node->latency = total / NP_NODE_SUCCESS_WINDOW;
    if (node->latency != old)
    {
        log_info(LOG_MISC, "connection status to node %.15s:%.6s latency      now: %1.6f (update with: %1.6fsec)",
                node->dns_name, node->port, node->latency, node->latency_win[node->latency_win_index]);                
    }
    if(node->is_in_routing_table || node->is_in_leafset)
        log_info(LOG_EXPERIMENT, "connection to node %.15s:%.6s success rate now: %1.2f latency now: %1.6f", node->dns_name, node->port,node->success_avg, node->latency);

    // insert into the routing table after a specific time period
    // reason: routing is based on latency, therefore we need a stable connection before inserting
    if ( node->is_in_routing_table == false && 
        (node_key->created_at + MISC_SEND_PINGS_MAX_EVERY_X_SEC) < np_time_now() &&
        !FLAG_CMP(node->protocol, PASSIVE) ) 
    {
        np_key_t* added = NULL, *deleted = NULL;
        np_node_t* node_1 = NULL;
        
        _np_route_update(node_key, true, &deleted, &added);

        if (added != NULL) 
        {
            node_1 = _np_key_get_node(added);
            node_1->is_in_routing_table = true;
        }

        if (deleted != NULL) 
        {
            node_1 = _np_key_get_node(deleted);
            node_1->is_in_routing_table = false;
            // log_info(LOG_EXPERIMENT, "deleted from table  : %s:%s:%s / %f / %1.2f / %1.2f",
            //     _np_key_as_str(deleted),
            //     node_1->dns_name, node_1->port,
            //     node_1->last_success,
            //     node_1->success_avg,
            //     node_1->latency
            //     );
            // TODO: issue leave event and delete node, respect leafset table
        }
    }

    // follow up actions
    if ( 
        (  node->success_avg                                             > BAD_LINK)     &&
        ( (node->last_success + MISC_SEND_PINGS_SEC*node->success_avg)  <= np_time_now()  )
       )
    {
        np_dhkey_t ping_dhkey = {0};
        np_generate_subject(&ping_dhkey, _NP_MSG_PING_REQUEST, strnlen(_NP_MSG_PING_REQUEST, 256));

        // issue ping messages
        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out, FUNC);
        _np_message_create(msg_out, node_key->dhkey, context->my_node_key->dhkey, ping_dhkey, NULL);
        
        log_info(LOG_ROUTING,"(msg: %s) Sending internal ping event", msg_out->uuid);
        
        np_dhkey_t ping_out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, ping_dhkey);
        np_util_event_t ping_event = { .type=(evt_internal|evt_message), .target_dhkey=node_key->dhkey, .user_data=msg_out};
        _np_event_runtime_add_event(context, event.current_run, ping_out_dhkey, ping_event);

        log_debug_msg(LOG_ROUTING, "submitted ping to target key %s / %p", _np_key_as_str(node_key), node_key);
        np_unref_obj(np_message_t, msg_out, FUNC);
    }

    if (
        ( node->success_avg               > BAD_LINK)     &&
        ( node->next_routing_table_update < np_time_now() ) 
       )
    {   
        /* send one row of our routing table back to joiner #host# */    
        np_sll_t(np_key_ptr, sll_of_keys) = NULL;
        sll_of_keys = _np_route_row_lookup(context, node_key->dhkey);
        char* source_sll_of_keys = "_np_route_row_lookup";
        
        if (sll_size(sll_of_keys) < 1)
        {   // nothing found, send leafset to exchange some data at least
            // prevents small clusters from not exchanging all data
            np_key_unref_list(sll_of_keys, source_sll_of_keys); // only for completion
            sll_free(np_key_ptr, sll_of_keys);
            sll_of_keys = _np_route_neighbors(context);
            source_sll_of_keys = "_np_route_neighbors";
        }
        if (sll_size(sll_of_keys) < 4){
            // if the set is still too low we may return on all-we-know base
            np_key_unref_list(sll_of_keys, source_sll_of_keys);
            sll_free(np_key_ptr, sll_of_keys);
            sll_of_keys = _np_route_neighbour_lookup(context, node_key->dhkey);
            source_sll_of_keys = "_np_route_neighbour_lookup";
        }
        // filter out potential passive nodes from neighbour list
        __np_filter_remove_passive_nodes(context, sll_of_keys, source_sll_of_keys);

        if (sll_size(sll_of_keys) > 0)
        {
            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "job submit piggyinfo to %s:%s!", node->dns_name, node->port);

            np_dhkey_t piggy_dhkey = {0};
            np_generate_subject(&piggy_dhkey, _NP_MSG_PIGGY_REQUEST, strnlen(_NP_MSG_PIGGY_REQUEST, 256));

            np_tree_t* msg_body = np_tree_create();
            _np_node_encode_multiple_to_jrb(msg_body, sll_of_keys, false);

            np_message_t* msg_out = NULL;
            np_new_obj(np_message_t, msg_out); // ref_obj_creation
            _np_message_create(msg_out, node_key->dhkey, context->my_node_key->dhkey, piggy_dhkey, msg_body);

            log_info(LOG_ROUTING,"(msg: %s) Sending internal piggy event", msg_out->uuid);

            np_dhkey_t piggy_out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, piggy_dhkey);
            np_util_event_t piggy_event = { .type=(evt_internal|evt_message), .target_dhkey=node_key->dhkey, .user_data=msg_out };
            _np_event_runtime_add_event(context, event.current_run, piggy_out_dhkey, piggy_event);
            np_unref_obj(np_message_t, msg_out, ref_obj_creation);
        }
        np_key_unref_list(sll_of_keys, source_sll_of_keys);
        sll_free(np_key_ptr, sll_of_keys);

        node->next_routing_table_update = np_time_now() + MISC_SEND_PIGGY_REQUESTS_SEC;
    }
}

void __np_node_add_to_leafset(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_add_to_leafset(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    if (trinity.node->is_in_leafset == false)
    {
        np_key_t *added = NULL, *deleted = NULL;
        _np_route_leafset_update(node_key, true, &deleted, &added);

        if (added != NULL) {
            trinity.node->is_in_leafset = true;
            log_info(LOG_EXPERIMENT, "[routing disturbance] added to leafset: %s:%s:%s / %f / %1.2f",
                _np_key_as_str(added),
                trinity.node->dns_name, trinity.node->port,
                trinity.node->last_success,
                trinity.node->success_avg);
        }
        if (deleted != NULL) {
            _np_key_get_node(deleted)->is_in_leafset = false;
            log_info(LOG_EXPERIMENT, "[routing disturbance] deleted from leafset (due to update): %s:%s:%s / last_success: %f (diff: %f) / success_avg: %1.2f",
                _np_key_as_str(deleted),
                _np_key_get_node(deleted)->dns_name, _np_key_get_node(deleted)->port,
                _np_key_get_node(deleted)->last_success, np_time_now()-_np_key_get_node(deleted)->last_success,
                _np_key_get_node(deleted)->success_avg);
        }
        // TODO: trigger re-fill of leafset? see piggy messages
    }
}

void __np_node_remove_from_routing(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_remove_from_routing(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    if (trinity.node->is_in_leafset == true) 
    {
        np_key_t *added = NULL, *deleted = NULL;
        _np_route_leafset_update(node_key, false, &deleted, &added);
        ASSERT(added == NULL,"Cannot add to leafset here");
        if (deleted != NULL) {
            _np_key_get_node(deleted)->is_in_leafset = false;
            log_info(LOG_EXPERIMENT, "[routing disturbance] deleted from leafset: %s:%s:%s / last_success: %f (diff: %f) / success_avg: %1.2f",
                _np_key_as_str(deleted),
                _np_key_get_node(deleted)->dns_name, _np_key_get_node(deleted)->port,
                _np_key_get_node(deleted)->last_success, np_time_now()-_np_key_get_node(deleted)->last_success,
                _np_key_get_node(deleted)->success_avg);
        } else {
            log_error("deletion from leafset unsuccesful, reason unknown !!!");
        }
    }

    if (trinity.node->is_in_routing_table == true) 
    {
        np_key_t *added = NULL, *deleted = NULL;
        _np_route_update(node_key, false, &deleted, &added);

        if (deleted != NULL) {
            _np_key_get_node(deleted)->is_in_routing_table = false;
            log_info(LOG_EXPERIMENT, "[routing disturbance] deleted from routing table: %s:%s:%s / %f / %1.2f",
                _np_key_as_str(deleted),
                _np_key_get_node(deleted)->dns_name, _np_key_get_node(deleted)->port,
                _np_key_get_node(deleted)->last_success,
                _np_key_get_node(deleted)->success_avg);
        } else {
            log_error("deletion from routing table unsuccesful, reason unknown !!!");
        }
    }
}


void __np_node_handle_completion_cleanup(void * context, np_util_event_t ev){
    np_unref_obj(np_message_t, ev.user_data, "__np_node_handle_completion");
}
void __np_node_handle_completion(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_handle_completion(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    double now = np_time_now();

    np_dhkey_t hs_dhkey   = _np_msgproperty_dhkey(WIRE_FORMAT, _NP_MSG_HANDSHAKE);
    // np_generate_subject((np_subject*) &hs_dhkey, _NP_MSG_HANDSHAKE, 13);
    np_dhkey_t join_dhkey = {0};
    np_generate_subject((np_subject*) &join_dhkey, _NP_MSG_JOIN_REQUEST, strnlen(_NP_MSG_JOIN_REQUEST, 256));
    char hex[65];
    // log_msg(LOG_INFO, "hand %s\n", sodium_bin2hex(hex, 65, &hs_dhkey, 32));
    // log_msg(LOG_INFO, "join %s\n", sodium_bin2hex(hex, 65, &join_dhkey, 32));

    np_msgproperty_conf_t* hs_prop   = _np_msgproperty_conf_get(context, OUTBOUND, hs_dhkey);
    np_msgproperty_conf_t* join_prop = _np_msgproperty_conf_get(context, OUTBOUND, join_dhkey);

    log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE, "node handshake status: %d %f // %p", trinity.node->_handshake_status, trinity.node->handshake_send_at, hs_prop);
    log_debug_msg(LOG_ROUTING, "node join      status: %d %f // %p", trinity.node->_joined_status,    trinity.node->join_send_at, join_prop);

    np_message_t* msg_out = NULL;
    TSP_GET(bool, trinity.node->session_key_is_set,session_key_is_set);
    if ( trinity.node->_handshake_status < np_node_status_Connected && 
         (trinity.node->handshake_send_at + hs_prop->msg_ttl) < now )
    {
        np_new_obj(np_message_t, msg_out, FUNC);
        _np_message_create(msg_out, node_key->dhkey, context->my_node_key->dhkey, hs_dhkey, NULL);
    
        enum np_node_status old_e = trinity.node->_handshake_status;
        trinity.node->_handshake_status = np_node_status_Initiated;
        log_info(LOG_HANDSHAKE,"set %s %s _handshake_status: %"PRIu8" -> %"PRIu8,
            FUNC, trinity.node->dns_name, old_e , trinity.node->_handshake_status
        );

        trinity.node->handshake_send_at = now;
        trinity.node->connection_attempts++;
        
        log_info(LOG_ROUTING,"(msg: %s) Sending internal handshake event", msg_out->uuid);
        np_util_event_t handshake_event = { .type=(evt_internal|evt_message), .user_data=msg_out, .target_dhkey=node_key->dhkey,
                                            .cleanup=__np_node_handle_completion_cleanup };
        _np_event_runtime_add_event(context, event.current_run, _np_msgproperty_tweaked_dhkey(OUTBOUND, hs_dhkey), handshake_event);

        log_trace_msg(LOG_TRACE, "start: __np_node_handle_completion(...) { node now (hand)    : %p / %p %d", node_key, trinity.node, trinity.node->_handshake_status);
    }
    else if ( session_key_is_set == true &&  trinity.node->_joined_status < np_node_status_Connected && 
            (trinity.node->join_send_at + join_prop->msg_ttl) < now ) 
    {
        np_new_obj(np_message_t, msg_out, FUNC);
        _np_message_create(msg_out, node_key->dhkey, context->my_node_key->dhkey, join_dhkey, NULL);

        trinity.node->_joined_status = np_node_status_Initiated;
        trinity.node->join_send_at = now;
        trinity.node->connection_attempts++;

        log_info(LOG_ROUTING,"(msg: %s) Sending internal join event", msg_out->uuid);

        np_util_event_t join_event = {  .type=(evt_internal|evt_message), .user_data=msg_out, .target_dhkey=node_key->dhkey,
                                        .cleanup=__np_node_handle_completion_cleanup };
        _np_event_runtime_add_event(context, event.current_run, _np_msgproperty_tweaked_dhkey(OUTBOUND, join_dhkey), join_event);

        log_trace_msg(LOG_TRACE, "start: __np_node_handle_completion(...) { node now (join)    : %p / %p %d", node_key, trinity.node, trinity.node->_joined_status);
    }
}

void __np_node_identity_upgrade(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_identity_upgrade(...) { %p", statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, alias_or_node_key);
    NP_CAST(event.user_data, np_aaatoken_t, token);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(alias_or_node_key, &trinity);

    __np_node_handle_completion(&alias_or_node_key->sm, event);

    if (FLAG_CMP(trinity.token->type, np_aaatoken_type_node))
    {
        trinity.token->state |= AAA_AUTHENTICATED;
        trinity.node->_joined_status = np_node_status_Connected;
    }
}

void __np_node_upgrade(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_upgrade(...) { %p", statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, alias_or_node_key);
    NP_CAST(event.user_data, np_aaatoken_t, token);

    // if this is an alias, trigger the state transition of the correpsonding node key
    if (FLAG_CMP(alias_or_node_key->type, np_key_type_alias)) 
    {
        log_debug_msg(LOG_ROUTING, "update alias with full token -> state change");
        if (alias_or_node_key->entity_array[1] == NULL) 
        {
            alias_or_node_key->entity_array[1] = token;
            np_ref_obj(np_aaatoken_t, token, "__np_alias_set");
        }
        // np_dhkey_t node_token_fp = alias_or_node_key->parent_dhkey;
        // _np_event_runtime_add_event(context, event.current_run, node_token_fp, event);

    } else {
        // node key and alias key share the same data structures, updating once counts for both
        struct __np_node_trinity trinity = {0};
        __np_key_to_trinity(alias_or_node_key, &trinity);

        // eventually send out our own data for mtls
        __np_node_handle_completion(&alias_or_node_key->sm, event);

        if (alias_or_node_key->entity_array[1] == NULL) 
        {
            log_debug_msg(LOG_MISC, "setting full token");
            alias_or_node_key->entity_array[1] = token;
            np_ref_obj(np_aaatoken_t, token, "__np_node_set");

            __np_key_to_trinity(alias_or_node_key, &trinity);
        }
        
        trinity.token->state |= AAA_AUTHENTICATED;    
        trinity.node->_joined_status = np_node_status_Connected;
        
        if (!FLAG_CMP(trinity.node->protocol, PASSIVE)) 
        {
            log_debug_msg(LOG_ROUTING, "sending np.update.request to peers in the network");
            np_tree_t* jrb_token = np_tree_create();
            np_tree_t* jrb_data  = np_tree_create();
            // send out update request to other nodes that are hashwise "nearer"
            np_aaatoken_encode(jrb_token, token);
            np_tree_insert_str(jrb_data, _NP_URN_NODE_PREFIX, np_treeval_new_tree(jrb_token));
            np_dhkey_t update_dhkey = {0};
            np_generate_subject(&update_dhkey, _NP_MSG_UPDATE_REQUEST, strnlen(_NP_MSG_UPDATE_REQUEST, 256));

            np_message_t* msg_out = NULL;
            np_new_obj(np_message_t, msg_out, FUNC);
            _np_message_create(msg_out, event.target_dhkey, context->my_node_key->dhkey, update_dhkey, jrb_data);
    
            log_info(LOG_ROUTING,"(msg: %s) Sending internal node update event", msg_out->uuid);
            // send update messages to nodes near to this fingerprint        
            np_util_event_t update_event = {.type=(evt_message|evt_internal), .user_data=msg_out, .target_dhkey=np_aaatoken_get_fingerprint(token, false)};
            _np_event_runtime_add_event(context, event.current_run, _np_msgproperty_tweaked_dhkey(OUTBOUND, update_dhkey), update_event);
            np_unref_obj(np_message_t, msg_out, FUNC);

            np_tree_free(jrb_token);
        }
    }
}

void __np_node_update_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_update_token(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_aaatoken_t, node_token);

    if (node_key->entity_array[1] == NULL) 
    {
        node_key->entity_array[1] = node_token;
        np_ref_obj(np_aaatoken_t, node_token, "__np_node_set");
    }
    // TODO: add uuid check whether the two token match
    node_token->state = AAA_VALID;

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);
    TSP_GET(bool, trinity.node->session_key_is_set,session_key_is_set);

    if (session_key_is_set == true && trinity.node->_joined_status < np_node_status_Connected) 
    {
        // send out our own join message, as we have just received the join request from the peer
        np_dhkey_t join_dhkey   = _np_msgproperty_dhkey(WIRE_FORMAT, _NP_MSG_JOIN_REQUEST);
        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out, FUNC);
        _np_message_create(msg_out, node_key->dhkey, context->my_node_key->dhkey, join_dhkey, NULL);

        log_info(LOG_ROUTING,"(msg: %s) Sending internal join event", msg_out->uuid);

        trinity.node->_joined_status = np_node_status_Connected;
        trinity.node->join_send_at = np_time_now();

        np_util_event_t join_event = { .type=(evt_internal|evt_message), .user_data=msg_out, .target_dhkey=node_key->dhkey };
        _np_event_runtime_add_event(context, event.current_run, _np_msgproperty_tweaked_dhkey(OUTBOUND, join_dhkey), join_event);
        np_unref_obj(np_message_t, msg_out, FUNC);

        log_trace_msg(LOG_TRACE, "start: __np_node_update_token(...) { node now (join)    : %p / %p %d", node_key, trinity.node, trinity.node->_joined_status);
    }
}

void __np_node_destroy(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_destroy(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    _np_network_disable(trinity.network);

    if (node_key->entity_array[3] != NULL) np_unref_obj(np_network_t, node_key->entity_array[3], "__np_create_client_network");
    if (node_key->entity_array[2] != NULL){
        np_unref_obj(np_node_t, node_key->entity_array[2], "__np_node_set");
    }
    if (node_key->entity_array[1] != NULL) np_unref_obj(np_aaatoken_t, node_key->entity_array[1], "__np_node_set");
    if (node_key->entity_array[0] != NULL) np_unref_obj(np_aaatoken_t, node_key->entity_array[0], "__np_node_set");

    np_unref_obj(np_key_t, node_key, "__np_node_set");
}

void __np_node_send_shutdown(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_send_shutdown(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    
    if (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_shutdown)) {
        // 1: create leave message
        np_tree_t* jrb_data     = np_tree_create();
        np_tree_t* jrb_my_node  = np_tree_create();
        np_aaatoken_encode(jrb_my_node, _np_key_get_token(context->my_node_key));
        np_tree_insert_str(jrb_data, _NP_URN_NODE_PREFIX, np_treeval_new_tree(jrb_my_node));

        np_dhkey_t leave_dhkey = {0};
        np_generate_subject(&leave_dhkey, _NP_MSG_LEAVE_REQUEST, strnlen(_NP_MSG_LEAVE_REQUEST, 256));

        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out, FUNC);
        _np_message_create(msg_out, node_key->dhkey, context->my_node_key->dhkey, leave_dhkey, jrb_data);

        np_util_event_t leave_evt = { .type=(evt_internal|evt_message), .user_data=msg_out, .target_dhkey=node_key->dhkey };
        _np_event_runtime_add_event(context, event.current_run, _np_msgproperty_tweaked_dhkey(OUTBOUND, leave_dhkey), leave_evt);
        np_unref_obj(np_message_t, msg_out, FUNC);

        np_tree_free(jrb_my_node);
    }
    __np_node_remove_from_routing(statemachine, event);
    log_info(LOG_KEY, "shutdown node key %s 1", _np_key_as_str(node_key));
    node_key->type = np_key_type_unknown;
}

void __np_create_client_network (np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_create_client_network(...) { %p", statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity node_trinity = {0};
    __np_key_to_trinity(node_key, &node_trinity);

    log_debug_msg(LOG_NETWORK, "__np_create_client_network key %p (type: %d)", node_key, node_key->type);

    // lookup wildcard to extract existing np_network_t structure
    char* tmp_connection_str  = np_get_connection_string_from(node_key, false);
    if (tmp_connection_str)
    {
        np_dhkey_t wildcard_dhkey = np_dhkey_create_from_hostport("*", tmp_connection_str);
        np_key_t*  wildcard_key   = _np_keycache_find(context, wildcard_dhkey);

        // take over existing wildcard network if it exists
        if (NULL != wildcard_key && wildcard_key != node_key)
        {
            struct __np_node_trinity wildcard_trinity = {0};
            __np_key_to_trinity(wildcard_key, &wildcard_trinity);
            if (NULL != wildcard_trinity.network) 
            {
                log_info(LOG_NETWORK, "_np_network_stop %s", FUNC);
                _np_network_stop(wildcard_trinity.network, true);
                _np_network_set_key(wildcard_trinity.network, node_key->dhkey);

                np_ref_obj(np_network_t, wildcard_trinity.network, "__np_create_client_network");
                node_key->entity_array[3] = wildcard_trinity.network;

                __np_key_to_trinity(node_key, &node_trinity);

                _np_network_start(wildcard_trinity.network, true);
            }
            np_unref_obj(np_key_t, wildcard_key, "_np_keycache_find");
        }
        else if (wildcard_key == node_key) 
        {
            np_unref_obj(np_key_t, wildcard_key, "_np_keycache_find");
        }
        free(tmp_connection_str);
    }

    // we nee our own node info now
    np_node_t* my_node = _np_key_get_node(context->my_node_key);

    // look out for alias network after tcp accept
    np_key_t*  alias_key   = _np_keycache_find(context, event.target_dhkey);

    if (NULL != alias_key)    
        np_unref_obj(np_key_t, alias_key, "_np_keycache_find");

    if (NULL == node_trinity.network && NULL != node_trinity.node)
    {   // create outgoing network
        np_network_t* new_network = NULL;
        np_new_obj(np_network_t, new_network);

        log_debug_msg(LOG_NETWORK, "node_info: %"PRIu8":%s:%s", node_trinity.node->protocol, node_trinity.node->dns_name, node_trinity.node->port);
        if (FLAG_CMP(node_trinity.node->protocol, PASSIVE))
        {
            if(FLAG_CMP(my_node->protocol, UDP))
            {
                np_network_t* my_network = _np_key_get_network(context->my_node_key);
                // send messages from own socket
                if (_np_network_init(new_network, false, my_node->protocol, node_trinity.node->dns_name, node_trinity.node->port, my_network->socket, PASSIVE))
                {
                    node_key->entity_array[3] = new_network;
                    ref_replace_reason(np_network_t, new_network, ref_obj_creation, "__np_create_client_network");
                    log_debug_msg(LOG_NETWORK, "connected to passive node: %"PRIu8":%s:%s", 
                        node_trinity.node->protocol, 
                        node_trinity.node->dns_name, 
                        node_trinity.node->port
                    );
                }
                _np_network_enable(new_network);
            } 
            else if(FLAG_CMP(my_node->protocol, TCP)) 
            {
                // on passive TCP add read network

                struct __np_node_trinity alias_trinity = {0};
                __np_key_to_trinity(alias_key, &alias_trinity);

                log_debug_msg(LOG_NETWORK, "connecting passive node: %"PRIu8":%s:%s for alias %s",
                    node_trinity.node->protocol, 
                    node_trinity.node->dns_name, 
                    node_trinity.node->port,
                    _np_key_as_str(alias_key)
                );

                if (_np_network_init(new_network, false, my_node->protocol, alias_trinity.node->dns_name, alias_trinity.node->port, alias_trinity.network->socket, PASSIVE))
                {
                    np_ref_obj(np_network_t, new_network,"__np_create_client_network");
                    node_key->entity_array[3] = new_network;
                    
                    log_debug_msg(LOG_NETWORK, "connected to passive node: %"PRIu8":%s:%s", 
                        node_trinity.node->protocol, 
                        node_trinity.node->dns_name, 
                        node_trinity.node->port
                    );
                }
                //_np_network_set_key(new_network, context->my_identity->dhkey);
            }
        }
        else
        {
            if (_np_network_init(new_network, false, node_trinity.node->protocol, node_trinity.node->dns_name, node_trinity.node->port, -1, UNKNOWN_PROTO))
            {
                if (FLAG_CMP(my_node->protocol, PASSIVE)) {
                    log_debug_msg(LOG_NETWORK, "connected as passive node to: %d:%s:%s", node_trinity.node->protocol, node_trinity.node->dns_name, node_trinity.node->port);
                    // set our identity key because of tcp passive network connection (this node is passive)
                    _np_network_init(new_network, true, node_trinity.node->protocol, node_trinity.node->dns_name, node_trinity.node->port, new_network->socket, UNKNOWN_PROTO);
                    _np_network_set_key(new_network, context->my_identity->dhkey);
                }
                else
                {
                    // or use our node dhkey for other types of network connections
                    _np_network_set_key(new_network, node_key->dhkey);
                }
                node_key->entity_array[3] = new_network;
                ref_replace_reason(np_network_t, new_network, ref_obj_creation, "__np_create_client_network");

                _np_network_enable(new_network);
            }
            else 
            {
                log_msg(LOG_WARNING, "creation of client network failed, invalidating key %s (type: %d)", _np_key_as_str(node_key), node_key->type);
                node_key->type = np_key_type_unknown;
            }
        }
    }
}

bool __is_wildcard_invalid(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_wildcard_invalid(...) {");

    bool ret = false;

    NP_CAST(statemachine->_user_data, np_key_t, wildcard_key); 

    if (!ret) ret  = FLAG_CMP(wildcard_key->type, np_key_type_wildcard);
    if ( ret) ret &= ( (wildcard_key->created_at + 10.0) < np_time_now() );

    return ret;
}

void __np_wildcard_destroy(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_wildcard_destroy(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, wildcard_key); 
    
    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(wildcard_key, &trinity);
    if (NULL != trinity.network) 
    {
        log_info(LOG_NETWORK, "_np_network_stop %s", FUNC);
        _np_network_stop(trinity.network, false);
        np_unref_obj(np_network_t, trinity.network, "__np_create_client_network");
    }

    if (NULL != trinity.node) 
    {
        np_unref_obj(np_node_t, trinity.node, "__np_wildcard_set");
    }

    np_unref_obj(np_key_t, wildcard_key, "__np_wildcard_set");

    wildcard_key->type &= ~np_key_type_wildcard;
}

void __np_node_send_direct(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_send_direct(...) { %p", statemachine->_user_data);
    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_messagepart_t, hs_messagepart);

    _np_messagepart_trace_info("MSGPART_OUT_DIRECT", hs_messagepart);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    if (trinity.network == NULL) return;
    
    char* packet;
    np_new_obj(BLOB_1024, packet, ref_obj_creation);

    memcpy(packet, hs_messagepart->msg_part, MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40);

    log_info(LOG_MESSAGE,"sending msg %s / %p part: %"PRIu32,hs_messagepart->uuid, packet, hs_messagepart->part);

    _LOCK_ACCESS(&trinity.network->access_lock)  
    {
        // ret =_np_network_send_data(context, trinity.network, packet);
        
        sll_append(
            void_ptr,
            trinity.network->out_events,
            (void*)packet
        );
       
        log_trace_msg(LOG_TRACE, "start: void __np_node_send_direct(...) { %d", sll_size(trinity.network->out_events));
    }
    //np_unref_obj(BLOB_1024, packet, ref_obj_creation);
    
    _np_network_start(trinity.network, false);
    _np_event_invoke_out(context); 

    np_unref_obj(np_messagepart_t, hs_messagepart, "_np_out_handshake");
}

void __np_node_split_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    NP_CAST(event.user_data, np_message_t, default_msg);
    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    _LOCK_ACCESS(&default_msg->msg_chunks_lock)
    {
        pll_iterator(np_messagepart_ptr) part_iter = pll_first(default_msg->msg_chunks);
        while (NULL != part_iter) 
        {
            memcpy(part_iter->val->uuid, default_msg->uuid, NP_UUID_BYTES);

            char _buf[65]={0};
            log_debug(LOG_ROUTING, "sending    message (%s) part %"PRIu32" to hop %s",
                default_msg->uuid, part_iter->val->part, np_id_str(_buf, _np_key_as_str(node_key))
            );

            np_util_event_t send_event = event;
            send_event.user_data=part_iter->val;
            //_np_event_runtime_add_event(context, event.current_run, node_key->dhkey, send_event);       
            // run in same lock context
            _np_event_runtime_start_with_event(context, node_key->dhkey, send_event);       
        
            pll_next(part_iter);
        }
    }
}

void __np_node_send_encrypted(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_send_encrypted(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_messagepart_t, part);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    np_crypto_session_t crypto_session = _np_key_get_node(node_key)->session;
    if (!crypto_session.session_key_to_write_is_set)  return; // TODO: this is happening ... Check if we could prevent this
    else { log_debug_msg(LOG_ROUTING, "fetched crypto session to %p", node_key);}

    if (trinity.network == NULL) return;

    unsigned char * enc_msg;//[MSG_CHUNK_SIZE_1024]={0};
    np_new_obj(BLOB_1024, enc_msg, ref_obj_creation);

    int encryption = -1;
    _LOCK_ACCESS(&part->work_lock)
    {
        // replace with our onw local sequence number for next hop
        np_tree_replace_str(part->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(trinity.network->seqend++));
        // increase resend counter for hop measurement
        np_tree_elem_t* jrb_send_counter = np_tree_find_str(part->instructions, _NP_MSG_INST_SEND_COUNTER);
        jrb_send_counter->val.value.ush++;

        _np_messagepart_trace_info("MSGPART_OUT_ENCRYPTED", part);

        // add protection from replay attacks ...
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        // TODO: move nonce to np_node_t and re-use it with increments ?
        randombytes_buf(nonce, sizeof(nonce));

        memcpy(enc_msg, nonce, crypto_secretbox_NONCEBYTES);
        encryption = crypto_secretbox_easy(enc_msg+crypto_secretbox_NONCEBYTES,
            part->msg_part,
            MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40,
            nonce,
            crypto_session.session_key_to_write
        );
    }
    log_debug_msg(LOG_HANDSHAKE,
        "HANDSHAKE SECRET: using shared secret from target %s on system %s to encrypt data (msg: %s)",
        _np_key_as_str(node_key), _np_key_as_str(context->my_node_key), part->uuid);

    if (encryption != 0)
    {
        log_msg(LOG_ERROR,
            "incorrect encryption of message (%s) (not sending to %s:%s)",
            part->uuid, trinity.node->dns_name, trinity.node->port);
    } 
    else
    {
        /* send data */
        if (NULL != trinity.network->out_events) 
        {   
/*        
#ifdef DEBUG
            char tmp_hex[MSG_CHUNK_SIZE_1024*2+1] = { 0 };
            sodium_bin2hex(tmp_hex, MSG_CHUNK_SIZE_1024*2+1, enc_buffer, MSG_CHUNK_SIZE_1024);
            log_debug(LOG_MESSAGE,
                "(msg: %s) appending to eventqueue (part: %"PRIu16"/%p) %p (%d bytes) to queue for %s:%s, hex: 0x%.5s...%s",
                part->uuid, part->part+1, part, enc_buffer, MSG_CHUNK_SIZE_1024, trinity.node->dns_name, trinity.node->port,tmp_hex, tmp_hex + strlen(tmp_hex) -5
            );
#endif // DEBUG
*/
            log_debug(LOG_ROUTING,
                "(msg: %s) sending message part: %"PRIu32" / %p to %s:%s / %s",
                part->uuid,
                part->part,
                enc_msg,
                trinity.network->ip,
                trinity.network->port,
                _np_key_as_str(node_key)
            );
            _LOCK_ACCESS(&trinity.network->access_lock) 
            {
                //ret = _np_network_send_data(context, trinity.network, enc_msg);

                sll_append(void_ptr,
                    trinity.network->out_events,
                    (void*)enc_msg
                );
            }
            //np_unref_obj(BLOB_1024, packet, ref_obj_creation);

            _np_network_start(trinity.network, false);
            _np_event_invoke_out(context); 

        }
        else 
        {
            log_info(LOG_MESSAGE, "Dropping part of msg %s due to uninitialized network", part->uuid);
        }
    }
}

void __np_node_discard_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_node_discard_message(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_messagepart_t, part);

    log_msg(LOG_WARNING,
        "discarding message %s, node %s not in desired state. peer could be responding too slow", part->uuid, _np_key_as_str(node_key) );
    // np_memory_free(context, part);
}

bool __is_np_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_np_message(...) {");

    bool ret = false;

    if (!ret) ret  = (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_message));

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    if ( ret) ret &= FLAG_CMP(node_key->type, np_key_type_node);
    if ( ret) ret &= (event.user_data != NULL);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);
    return ret;
}

bool __is_np_messagepart(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_np_message(...) {");

    bool ret = false;

    if (!ret) ret  = (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_message));

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    if ( ret) ret &= FLAG_CMP(node_key->type, np_key_type_node);
    if ( ret) ret &= (event.user_data != NULL);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_messagepart_t);
    if ( ret) {
        // NP_CAST(event.user_data, np_messagepart_t, out_message);
        // TODO: add bloom filter ?
    }
    return ret;
}

bool __is_handshake_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_handshake_message(...) {");

    bool ret = false;
    
    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    if (!ret) ret  = (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_message));
    if ( ret) ret &= FLAG_CMP(node_key->type, np_key_type_wildcard) || FLAG_CMP(node_key->type, np_key_type_node);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_messagepart_t);
    if ( ret) {
        NP_CAST(event.user_data, np_messagepart_t, hs_messagepart);
        /* TODO: make it working and better! */
        CHECK_STR_FIELD_BOOL(hs_messagepart->header, _NP_MSG_HEADER_SUBJECT, msg_subject_elem, "NO SUBJECT IN MESSAGE") 
        {
            np_dhkey_t handshake_dhkey = {0};
            np_generate_subject(&handshake_dhkey, _NP_MSG_HANDSHAKE, strnlen(_NP_MSG_HANDSHAKE, 256));

            ret &= _np_dhkey_equal(&msg_subject_elem->val.value.dhkey, &handshake_dhkey);
            goto __np_return__;
        }
        ret = false;
    }
    __np_return__:
    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

bool __is_invalid_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_invalid_message(...) {");

    bool ret = false;

    if (!ret) ret  = ( FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_internal) );
    if ( ret) ret &= (event.user_data != NULL);

    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_messagepart_t);

    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

bool __is_join_out_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_join_out_message(...) {");

    bool ret = false;

    if (!ret) ret  = ( FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_internal) );
    if ( ret) ret &= (event.user_data != NULL);

    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_messagepart_t);
    if ( ret) {
        NP_CAST(event.user_data, np_messagepart_t, out_message);
        /* TODO: make it working and better! */
        CHECK_STR_FIELD_BOOL(out_message->header, _NP_MSG_HEADER_SUBJECT, msg_subject_elem, "NO SUBJECT IN MESSAGE") {
            np_dhkey_t join_dhkey = {0};
            np_generate_subject(&join_dhkey, _NP_MSG_JOIN_REQUEST, strnlen(_NP_MSG_JOIN_REQUEST, 256));
            np_dhkey_t leave_dhkey = {0};
            np_generate_subject(&leave_dhkey, _NP_MSG_LEAVE_REQUEST, strnlen(_NP_MSG_LEAVE_REQUEST, 256));
            ret &= ( _np_dhkey_equal(&msg_subject_elem->val.value.dhkey, &join_dhkey)  ||
                     _np_dhkey_equal(&msg_subject_elem->val.value.dhkey, &leave_dhkey) );
            goto __np_return__;
        }
        ret = false;
    }
    __np_return__:
    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

void __np_node_handle_response(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __np_node_handle_response(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    np_node_t* node = _np_key_get_node(node_key);

    node->success_win_index++;
    if (node->success_win_index == NP_NODE_SUCCESS_WINDOW)
        node->success_win_index = 0;

    node->latency_win_index++;
    if (node->latency_win_index == NP_NODE_SUCCESS_WINDOW)
        node->latency_win_index = 0;

    NP_CAST(event.user_data, np_responsecontainer_t, response);

     if (FLAG_CMP(event.type, evt_timeout) )
    {
        node->success_win[node->success_win_index % NP_NODE_SUCCESS_WINDOW] =   0;
        node->latency_win[node->latency_win_index % NP_NODE_SUCCESS_WINDOW] = (response->expires_at - response->send_at);
    } 
    else if (FLAG_CMP(event.type, evt_response) )
    {
        node->last_success = np_time_now();
        node->success_win[node->success_win_index % NP_NODE_SUCCESS_WINDOW] = 1;
        if(node->latency == -1) {
            for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
            {
                node->latency_win[i] = (response->received_at - response->send_at);
            }
        }else{
            node->latency_win[node->latency_win_index % NP_NODE_SUCCESS_WINDOW] = (response->received_at - response->send_at);
        }
    }
    else 
    {
        log_msg(LOG_INFO, "unknown responsehandler called, not doing any action ...");
    }
}
