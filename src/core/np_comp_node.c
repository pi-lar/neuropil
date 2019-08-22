//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that a node can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include "np_axon.h"
#include "np_aaatoken.h"
#include "np_event.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_message.h"
#include "np_responsecontainer.h"
#include "np_route.h"

#include "util/np_event.h"
#include "util/np_statemachine.h"

struct __np_node_trinity {
    np_aaatoken_t  *token;
    np_node_t      *node;
    np_network_t   *network;
};

void __np_key_to_trinity(np_key_t* key, struct __np_node_trinity *trinity) 
{
    sll_iterator(void_ptr) iter = sll_first(key->entities);

    while (iter != NULL) {

        if (_np_memory_rtti_check(iter->val, np_memory_types_np_node_t))     trinity->node    = iter->val;
        if (_np_memory_rtti_check(iter->val, np_memory_types_np_aaatoken_t)) trinity->token   = iter->val;
        if (_np_memory_rtti_check(iter->val, np_memory_types_np_network_t))  trinity->network = iter->val;

        sll_next(iter);
    }
}

np_network_t* _np_key_get_network(np_key_t* key) 
{
    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(key, &trinity);

    return trinity.network;
}

np_node_t* _np_key_get_node(np_key_t* key) 
{
    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(key, &trinity);

    return trinity.node;
}

np_aaatoken_t* _np_key_get_token(np_key_t* key) 
{
    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(key, &trinity);

    return trinity.token;
}

// IN_SETUP -> IN_USE transition condition / action #1
bool __is_node_handshake_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_node_handshake_token(...) {");
    
    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_token) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
    if ( ret) {
        NP_CAST(event.user_data, np_aaatoken_t, hs_token);
        ret &= (hs_token->type == np_aaatoken_type_handshake);
        ret &= _np_aaatoken_is_valid(hs_token, hs_token->type);
    }
    return ret;
}

bool __is_shutdown_event(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_node_handshake_token(...) {");
    
    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_shutdown) && FLAG_CMP(event.type, evt_internal);
    // if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
    return ret;
}

bool __is_node_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_node_token(...) {");

    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_token) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
    if ( ret) {
        NP_CAST(event.user_data, np_aaatoken_t, node);
        ret &= (node->type == np_aaatoken_type_node);
        ret &= !node->private_key_is_set;
        ret &= _np_aaatoken_is_valid(node, node->type);
    }
    return ret;
}

bool __is_node_complete(np_util_statemachine_t* statemachine, const np_util_event_t event)
{ 
    return false;
}

// IN_USE -> IN_DESTROY transition condition / action #1
bool __is_node_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_node_invalid(...) {");

    bool ret = false;
    
    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    if (!ret) ret  = (node_key->type == np_key_type_node);
    if ( ret) ret &= (_np_key_get_token(node_key) != NULL);
    if ( ret) {
        np_aaatoken_t* node_token = _np_key_get_token(node_key);
        ret &= !_np_aaatoken_is_valid(node_token, node_token->type);
    }
    return ret;
}

bool __is_wildcard_key(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_wildcard_key(...) {");

    bool ret = false;
    
    // NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_node_t, my_node);

    if (!ret) ret  = FLAG_CMP(event.type, evt_internal);
    if ( ret) ret &= _np_memory_rtti_check(my_node, np_memory_types_np_node_t);
    if ( ret) ret &= _np_node_check_address_validity(my_node);

    return ret;
}

bool __is_node_authn(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    // { .type=(evt_internal|evt_token), .context=context, .user_data=authn_token, .target_dhkey=event.target_dhkey};
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_node_authn(...) {");

    bool ret = false;
    
    // NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_node_t, my_node);

    if (!ret) ret  = (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_token) );
    if ( ret) ret &=  FLAG_CMP(event.type, evt_authn);
    if ( ret) ret &= _np_memory_rtti_check(my_node, np_memory_types_np_aaatoken_t);

    return ret;
}

void __np_node_set(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_node_set(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    NP_CAST(event.user_data, np_aaatoken_t, node_token);
    sll_append(void_ptr, node_key->entities, node_token);
    np_ref_obj(np_aaatoken_t, node_token, "__np_node_set");

    np_node_t* my_node = _np_node_from_token(node_token, node_token->type);
    sll_append(void_ptr, node_key->entities, my_node);
    np_ref_obj(np_node_t, my_node, "__np_node_set");

    node_key->type |= np_key_type_node;
    node_token->state = AAA_VALID;

    // handle handshake token after wildcard join
    char* tmp_connection_str = np_get_connection_string_from(node_key, false);
    np_dhkey_t wildcard_dhkey = np_dhkey_create_from_hostport("*", tmp_connection_str);
    np_key_t* hs_wildcard_key = _np_keycache_find(context, wildcard_dhkey);
    if (NULL != hs_wildcard_key)
    {
        np_node_t* wc_node = _np_key_get_node(hs_wildcard_key);
        my_node->handshake_send_at = wc_node->handshake_send_at;
        my_node->_handshake_status = wc_node->_handshake_status;
    
        np_unref_obj(np_key_t, hs_wildcard_key, "np_keycache_find");
    }    
    log_debug_msg(LOG_DEBUG, "node_status: %d %f", my_node->_handshake_status, my_node->handshake_send_at);
    free(tmp_connection_str);
}

void __np_wildcard_set(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_wildcard_set(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_node_t, node);

    node_key->type |= np_key_type_wildcard;
    node_key->is_in_keycache = true;

    // _np_keycache_add(node_key);
    sll_append(void_ptr, node_key->entities, node);   
    np_ref_obj(np_node_t, node, "__np_wildcard_set");
}

void __np_node_update(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_node_update(...) {");

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
        log_msg(LOG_INFO, "connection to node %s:%s success rate now: %1.2f (%2u / %2u)", 
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
        log_msg(LOG_INFO, "connection to node %s:%s latency      now: %1.3f (update with: %1.3f)",
                node->dns_name, node->port, node->latency, node->latency_win[node->latency_win_index]);                
    }

    // insert into the routing table after a specific time period
    // reason: routing is also based on latency, therefore we need a stable connection before inserting
    if ( node->is_in_routing_table == false && 
        (node_key->created_at + MISC_SEND_PINGS_MAX_EVERY_X_SEC*2) < np_time_now() ) 
    {
        np_key_t* added = NULL, *deleted = NULL;
        np_node_t* node = NULL;
        
        _np_route_update(node_key, true, &deleted, &added);

        if (added != NULL) 
        {
            node = _np_key_get_node(added);
            node->is_in_routing_table = true;
            log_debug_msg(LOG_INFO, "added   to   table  : %s:%s:%s / %f / %1.2f",
                _np_key_as_str(added),
                node->dns_name, node->port,
                node->last_success,
                node->success_avg);
        }

        if (deleted != NULL) 
        {
            node = _np_key_get_node(deleted);
            node->is_in_routing_table = false;
            log_debug_msg(LOG_INFO, "deleted from table  : %s:%s:%s / %f / %1.2f",
                _np_key_as_str(deleted),
                node->dns_name, node->port,
                node->last_success,
                node->success_avg);
            // TODO: issue leave event and delete node, respect leafset table
        }
    }

    // follow up actions
    if ( 
        (  node->success_avg                                                         > BAD_LINK)     &&
        ( (node->last_success + MISC_SEND_PINGS_MAX_EVERY_X_SEC*node->success_avg)  <= np_time_now()  )
       )
    {
        // issue ping messages
        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out);
        _np_message_create(msg_out, node_key->dhkey, context->my_node_key->dhkey, _NP_MSG_PING_REQUEST, NULL);

        np_dhkey_t ping_dhkey = _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_PING_REQUEST);
        np_util_event_t ping_event = { .type=(evt_internal|evt_message), .target_dhkey=node_key->dhkey, .user_data=msg_out, .context=context };
        _np_keycache_handle_event(context, ping_dhkey, ping_event, false);

        log_debug_msg(LOG_DEBUG, "submitted ping to target key %s / %p", _np_key_as_str(node_key), node_key);
    }

    if (
        ( node->success_avg               > BAD_LINK)     &&
        ( node->next_routing_table_update < np_time_now() ) 
       )
    {   
        /* send one row of our routing table back to joiner #host# */    
        np_sll_t(np_key_ptr, sll_of_keys) = NULL;
        sll_of_keys = _np_route_row_lookup(node_key);
        char* source_sll_of_keys = "_np_route_row_lookup";
        
        if (sll_size(sll_of_keys) <= 5)
        {   // nothing found, send leafset to exchange some data at least
            // prevents small clusters from not exchanging all data
            np_key_unref_list(sll_of_keys, source_sll_of_keys); // only for completion
            sll_free(np_key_ptr, sll_of_keys);
            sll_of_keys = _np_route_neighbors(context);
            source_sll_of_keys = "_np_route_neighbors";
        }
        
        if (sll_size(sll_of_keys) > 0)
        {
            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "job submit piggyinfo to %s:%s!", node->dns_name, node->port);

            np_tree_t* msg_body = np_tree_create();
            _np_node_encode_multiple_to_jrb(msg_body, sll_of_keys, false);

            np_message_t* msg_out = NULL;
            np_new_obj(np_message_t, msg_out);
            _np_message_create(msg_out, node_key->dhkey, context->my_node_key->dhkey, _NP_MSG_PIGGY_REQUEST, msg_body);

            np_dhkey_t piggy_dhkey = _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_PIGGY_REQUEST);
            np_util_event_t piggy_event = { .type=(evt_internal|evt_message), .target_dhkey=node_key->dhkey, .user_data=msg_out, .context=context };
            _np_keycache_handle_event(context, piggy_dhkey, piggy_event, false);

        }
        np_key_unref_list(sll_of_keys, source_sll_of_keys);
        sll_free(np_key_ptr, sll_of_keys);

        node->next_routing_table_update = np_time_now() + MISC_SEND_PIGGY_REQUESTS_SEC;
    }
}

void __np_node_add_to_leafset(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_node_add_to_leafset(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    if (trinity.node->is_in_leafset == false)
    {
        np_key_t *added = NULL, *deleted = NULL;
        _np_route_leafset_update(node_key, true, &deleted, &added);

        if (added != NULL) {
            trinity.node->is_in_leafset = true;
            log_debug_msg(LOG_INFO, "added   to   leafset: %s:%s:%s / %f / %1.2f",
                _np_key_as_str(added),
                trinity.node->dns_name, trinity.node->port,
                trinity.node->last_success,
                trinity.node->success_avg);
        }
        if (deleted != NULL) {
            _np_key_get_node(deleted)->is_in_leafset = false;
            log_debug_msg(LOG_INFO, "deleted from leafset: %s:%s:%s / %f / %1.2f",
                _np_key_as_str(deleted),
                _np_key_get_node(deleted)->dns_name, _np_key_get_node(deleted)->port,
                _np_key_get_node(deleted)->last_success,
                _np_key_get_node(deleted)->success_avg);
        }
        // TODO: trigger re-fill of leafset? see piggy messages
    }
}

void __np_node_remove_from_routing(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_node_remove_from_routing(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    if (trinity.node->is_in_leafset == true) 
    {
        np_key_t *added = NULL, *deleted = NULL;
        _np_route_leafset_update(node_key, false, &deleted, &added);

        if (deleted != NULL) {
            _np_key_get_node(deleted)->is_in_leafset = false;
            log_debug_msg(LOG_INFO, "deleted from leafset: %s:%s:%s / %f / %1.2f",
                _np_key_as_str(deleted),
                _np_key_get_node(deleted)->dns_name, _np_key_get_node(deleted)->port,
                _np_key_get_node(deleted)->last_success,
                _np_key_get_node(deleted)->success_avg);
        } else {
            log_msg(LOG_WARN, "deletion from leafset unsuccesful, reason unknown !!!");
        }
    }

    if (trinity.node->is_in_routing_table == true) 
    {
        np_key_t *added = NULL, *deleted = NULL;
        _np_route_update(node_key, false, &deleted, &added);

        if (deleted != NULL) {
            _np_key_get_node(deleted)->is_in_leafset = false;
            log_debug_msg(LOG_INFO, "deleted from leafset: %s:%s:%s / %f / %1.2f",
                _np_key_as_str(deleted),
                _np_key_get_node(deleted)->dns_name, _np_key_get_node(deleted)->port,
                _np_key_get_node(deleted)->last_success,
                _np_key_get_node(deleted)->success_avg);
        } else {
            log_msg(LOG_WARN, "deletion from routing table unsuccesful, reason unknown !!!");
        }
    }
}

void __np_node_handle_completion(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{ 
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_node_handle_completion(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    double now = np_time_now();

    np_dhkey_t hs_dhkey = _np_msgproperty_dhkey( OUTBOUND, _NP_MSG_HANDSHAKE);
    np_dhkey_t join_dhkey = _np_msgproperty_dhkey( OUTBOUND, _NP_MSG_JOIN_REQUEST);

    np_msgproperty_t* hs_prop = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_HANDSHAKE);
    np_msgproperty_t* join_prop = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_JOIN_REQUEST);

    log_debug_msg(LOG_DEBUG, "node_status: %d %f", trinity.node->_handshake_status, trinity.node->handshake_send_at);

    np_message_t* msg_out = NULL;

    if ( trinity.node->_handshake_status < np_status_Connected && 
         (trinity.node->handshake_send_at + hs_prop->msg_ttl) < now )
    {
        np_new_obj(np_message_t, msg_out, FUNC);
        _np_message_create(msg_out, node_key->dhkey, context->my_node_key->dhkey, _NP_MSG_HANDSHAKE, NULL);

        np_util_event_t handshake_event = { .type=(evt_internal|evt_message), .context=context, .user_data=msg_out, .target_dhkey=node_key->dhkey };
        _np_keycache_handle_event(context, hs_dhkey, handshake_event, false);

        trinity.node->_handshake_status++;
        trinity.node->handshake_send_at = np_time_now();
        
        log_debug_msg(LOG_DEBUG, "start: __np_node_handle_completion(...) { node now         : %p / %p %d", node_key, trinity.node, trinity.node->_handshake_status);
    }
    else if (trinity.node->session_key_is_set == true &&  trinity.node->_joined_status < np_status_Connected && 
            (trinity.node->join_send_at + join_prop->msg_ttl) < now ) 
    {
        np_new_obj(np_message_t, msg_out, FUNC);
        _np_message_create(msg_out, node_key->dhkey, context->my_node_key->dhkey, _NP_MSG_JOIN_REQUEST, NULL);

        np_util_event_t join_event = { .type=(evt_internal|evt_message), .context=context, .user_data=msg_out, .target_dhkey=node_key->dhkey };
        _np_keycache_handle_event(context, join_dhkey, join_event, false);

        trinity.node->join_send_at = np_time_now();
        trinity.node->_joined_status++;
    }
}

void __np_node_upgrade(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_node_upgrade(...) { %p", statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, alias_or_node_key);
    NP_CAST(event.user_data, np_aaatoken_t, token);

    np_dhkey_t token_fp = np_aaatoken_get_fingerprint(token, false);

    // if this is an alias, trigger the state transition of the correpsonding node key
    if (FLAG_CMP(alias_or_node_key->type, np_key_type_alias)) 
    {
        _np_keycache_handle_event(context, token_fp, event, false);

    } else {
        // node key and alias key share the same data structures, updating once counts for both
        struct __np_node_trinity trinity = {0};
        __np_key_to_trinity(alias_or_node_key, &trinity);

        // eventually send out our own data for mtls
        __np_node_handle_completion(&alias_or_node_key->sm, event);

        if (FLAG_CMP(trinity.token->type, np_aaatoken_type_node) ) 
        {
            trinity.token->state |= AAA_AUTHENTICATED;    
            trinity.node->_joined_status++;
        }
        else if (FLAG_CMP(trinity.token->type, np_aaatoken_type_handshake)) 
        {
            np_unref_obj(np_aaatoken_t, trinity.token, "__np_node_set");
            
            sll_append(void_ptr, alias_or_node_key->entities, token);
            np_ref_obj(np_aaatoken_t, token, "__np_node_upgrade");

            token->state |= AAA_AUTHENTICATED;
            trinity.node->_joined_status++;
        } 

        np_tree_t* jrb_token = np_tree_create();
        np_tree_t* jrb_data  = np_tree_create();

        // send out update request to other nodes that are hashwise "nearer"
        np_aaatoken_encode(jrb_token, token);
        np_tree_insert_str(jrb_data, _NP_URN_NODE_PREFIX, np_treeval_new_tree(jrb_token));

        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out, FUNC);
        _np_message_create(msg_out, event.target_dhkey, context->my_node_key->dhkey, _NP_MSG_UPDATE_REQUEST, np_tree_clone(jrb_data));

        // send update messages to nodes near to this fingerprint        
        np_dhkey_t update_key = _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_UPDATE_REQUEST);
        np_util_event_t update_event = {.type=(evt_message|evt_internal), .context=context, .user_data=msg_out, .target_dhkey=token_fp};
        _np_keycache_handle_event(context, update_key, update_event, false);

        np_tree_free(jrb_data);
        np_tree_free(jrb_token);
    }
}

void __np_node_update_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    // comapare new and old node token, take over changes
}

void __np_wildcard_finalize(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_wildcard_finalize(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, wildcard_key);

    // we do not need this key anymore
    wildcard_key->type = np_key_type_unknown;
}

void __np_node_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{    
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_node_destroy(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    _np_network_stop(trinity.network, true);    
    sll_clear(void_ptr, node_key->entities);

    _np_keycache_remove(context, node_key->dhkey);
    node_key->is_in_keycache = false;
    node_key->type = np_key_type_unknown;
}

void __np_node_shutdown(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_node_shutdown(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    np_dhkey_t leave_prop_dhkey = _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_LEAVE_REQUEST);
    np_key_t* leave_prop_key = _np_keycache_find(context, leave_prop_dhkey);
    
    np_util_event_t leave_evt = { .type=(evt_internal|evt_message), .context=context, .user_data=node_key, .target_dhkey=node_key->dhkey };

    _np_key_handle_event(leave_prop_key, leave_evt, false);
    np_unref_obj(np_aaatoken_t, leave_prop_key, "_np_keycache_find");

    // __np_node_destroy(statemachine, event);
}

void __np_create_client_network (np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_create_client_network(...) { %p", statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    log_msg(LOG_ERROR, "__np_create_client_network %p (%d)", node_key, node_key->type);

    // lookup wildcard to extract existing np_network_t structure
    char* tmp_connection_str  = np_get_connection_string_from(node_key, false);
    np_dhkey_t wildcard_dhkey = np_dhkey_create_from_hostport("*", tmp_connection_str);
    np_key_t* wildcard_key    = _np_keycache_find(context, wildcard_dhkey);

    // take over existing wildcard network if it exists
    if (NULL != wildcard_key && wildcard_key != node_key)
    {
        struct __np_node_trinity wildcard_trinity = {0};
          
        __np_key_to_trinity(wildcard_key, &wildcard_trinity);
        sll_append(void_ptr, node_key->entities, _np_key_get_network(wildcard_key) );
        np_ref_obj(np_network_t, wildcard_trinity.network);

        __np_key_to_trinity(node_key, &trinity);
        
        np_unref_obj(np_aaatoken_t, wildcard_key, "_np_keycache_find");
    } 
    free(tmp_connection_str);


    if (NULL == trinity.network && NULL != trinity.node) 
    {   // create outgoing network
        np_network_t* my_network = NULL;
        np_new_obj(np_network_t, my_network);
        _np_network_init(my_network, false, trinity.node->protocol, trinity.node->dns_name, trinity.node->port, -1, UNKNOWN_PROTO);
        np_ref_obj(np_network_t, my_network, "__np_create_client_network");

        _np_network_set_key(my_network, node_key);
        
        sll_append(void_ptr, node_key->entities, my_network);
        np_ref_obj(np_network_t, my_network);

        log_debug_msg(LOG_DEBUG | LOG_NETWORK, "Network %s is the main receiving network", np_memory_get_id(my_network));

        _np_network_enable(my_network);
    }

    node_key->last_update = np_time_now();
}

bool __is_wildcard_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_wildcard_invalid(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key); 

    if ( (node_key->created_at + 60) < np_time_now() ) return true;

    return false;
}

void __np_wildcard_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{

}

void __np_node_send_direct(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_node_send_direct(...) { %p", statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_messagepart_t, hs_messagepart);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    char* packet = np_memory_new(context, np_memory_types_BLOB_1024);
    memcpy(packet, hs_messagepart->msg_part, 984);
    
    _LOCK_ACCESS(&trinity.network->out_events_lock)  
    {
        sll_append(
            void_ptr,
            trinity.network->out_events,
            (void*)packet);
    }
    _np_event_invoke_out(context); 

    log_debug_msg(LOG_TRACE, "start: void __np_node_send_direct(...) { %d", sll_size(trinity.network->out_events));
}

void __np_node_send_encrypted(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_node_send_encrypted(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_messagepart_t, part);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    struct __np_node_trinity my_trinity = {0};
    __np_key_to_trinity(context->my_node_key, &my_trinity);

    // replace with our onw local sequence number for next hop
    np_tree_replace_str(part->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(my_trinity.network->seqend++));
    // increase resend counter for hop measurement
    np_tree_elem_t* jrb_send_counter = np_tree_find_str(part->instructions, _NP_MSG_INST_SEND_COUNTER);
    jrb_send_counter->val.value.ush++;
    
    // add protection from replay attacks ...
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    // TODO: move nonce to np_node_t and re-use it with increments ?
    randombytes_buf(nonce, sizeof(nonce));

    unsigned char enc_msg[MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES];
    int encryption = crypto_secretbox_easy(enc_msg,
        part->msg_part,
        MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40,
        nonce,
        trinity.node->session.session_key_to_write
    );

    log_debug_msg(LOG_DEBUG | LOG_HANDSHAKE,
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
        unsigned char* enc_buffer = np_memory_new(context, np_memory_types_BLOB_1024);
        
        uint32_t enc_buffer_len = MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES;
        memcpy(enc_buffer, nonce, crypto_secretbox_NONCEBYTES);
        memcpy(enc_buffer + crypto_secretbox_NONCEBYTES, enc_msg, enc_buffer_len);

        /* send data */
        if (NULL != trinity.network->out_events) {
            log_debug_msg(LOG_NETWORK | LOG_DEBUG, "appending message (%s part: %d) %p (%d bytes) to queue for %s:%s", part->uuid, part, enc_buffer, MSG_CHUNK_SIZE_1024, trinity.node->dns_name, trinity.node->port);
            char tmp_hex[MSG_CHUNK_SIZE_1024*2+1] = { 0 };

            log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                "(msg: %s) %s",
                part->uuid, sodium_bin2hex(tmp_hex, MSG_CHUNK_SIZE_1024*2+1, enc_buffer, MSG_CHUNK_SIZE_1024));
            
            _LOCK_ACCESS(&trinity.network->out_events_lock) 
            {
                sll_append(void_ptr, trinity.network->out_events, (void*)enc_buffer);
            }
            _np_event_invoke_out(context); 
#ifdef DEBUG
            if(!trinity.network->is_running){
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "msg (%s) cannot be send (now) as network is not running", part->uuid);
            }
#endif
        } else {
            log_debug_msg(LOG_INFO, "Dropping data package for msg %s due to not initialized out_events", part->uuid);
            np_memory_free(context, enc_buffer);
        }
    }
    free(part->uuid);
}

bool __is_np_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_np_message(...) {");

    bool ret = false;

    if (!ret) ret  = (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_message));

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    if ( ret) ret &= node_key->type == np_key_type_node;

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
    log_debug_msg(LOG_TRACE, "start: bool __is_handshake_message(...) {");

    bool ret = false;
    
    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    if (!ret) ret  = (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_message));
    if ( ret) ret &= (node_key->type == np_key_type_wildcard || node_key->type == np_key_type_node);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_messagepart_t);
    if ( ret) {
        NP_CAST(event.user_data, np_messagepart_t, hs_messagepart);
        /* TODO: make it working and better! */
        CHECK_STR_FIELD_BOOL(hs_messagepart->header, _NP_MSG_HEADER_SUBJECT, str_msg_subject, "NO SUBJECT IN MESSAGE") {
            ret &= (0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_HANDSHAKE, strlen(_NP_MSG_HANDSHAKE)) );
            goto __np_return__;
        }
        ret = false;
    }
    __np_return__:
        return ret;
}

bool __is_join_out_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_join_out_message(...) {");

    bool ret = false;

    if (!ret) ret  = ( FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_internal) );
    if ( ret) ret &= (event.user_data != NULL);

    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_messagepart_t);
    if ( ret) {
        NP_CAST(event.user_data, np_messagepart_t, out_message);
        /* TODO: make it working and better! */
        CHECK_STR_FIELD_BOOL(out_message->header, _NP_MSG_HEADER_SUBJECT, str_msg_subject, "NO SUBJECT IN MESSAGE") {
            ret &= ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_JOIN_REQUEST,  strlen(_NP_MSG_JOIN_REQUEST))  ) ||
                   ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_LEAVE_REQUEST, strlen(_NP_MSG_LEAVE_REQUEST)) );
            goto __np_return__;
        }
        ret = false;
    }
    __np_return__:
        return ret;
}

void __np_node_handle_response(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __np_node_handle_response(...) {");

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
        node->latency_win[node->latency_win_index % NP_NODE_SUCCESS_WINDOW] = 1.0;
    } 
    else if (FLAG_CMP(event.type, evt_response) )
    {
        node->last_success = np_time_now();
        node->success_win[node->success_win_index % NP_NODE_SUCCESS_WINDOW] = 1;
        node->latency_win[node->latency_win_index % NP_NODE_SUCCESS_WINDOW] = (response->received_at - response->send_at);
    }
    else 
    {
        log_msg(LOG_INFO, "unknown responsehandler called, not doing any action ...");
    }
}