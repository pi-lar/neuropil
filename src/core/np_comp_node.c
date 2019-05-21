//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that a node can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include "np_aaatoken.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_message.h"

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

        iter = sll_next(iter);
    }
}

// IN_SETUP -> IN_USE transition condition / action #1
bool __is_node_handshake_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    
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
bool __is_node_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
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

}
bool __is_node_join_nack(np_util_statemachine_t* statemachine, const np_util_event_t event) { }
bool __is_node_leave_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
    if ( ret) {
        NP_CAST(event.user_data, np_aaatoken_t, node);
        ret &= (node->type == np_aaatoken_type_node);
        ret &= _np_aaatoken_is_valid(node, node->type);
    }
    return ret;
}
// IN_USE -> IN_DESTROY transition condition / action #1
bool __is_node_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);

    bool ret = false;
    
    NP_CAST(statemachine->_user_data, np_key_t, my_node_key);

    if (!ret) ret = (my_node_key->aaa_token != NULL);
    if ( ret) {
        NP_CAST(my_node_key->aaa_token, np_aaatoken_t, node);
        ret &= (my_node_key->type == np_aaatoken_type_node);
        ret &= !_np_aaatoken_is_valid(node, np_aaatoken_type_node);
    }
    return ret;
}
void __np_node_set(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void _np_set_node(np_aaatoken_t* node){");

    NP_CAST(event.user_data, np_aaatoken_t, node);
    NP_CAST(statemachine->_user_data, np_key_t, my_node_key);

    // _np_keycache_add(my_node_key);

    sll_append(void_ptr, my_node_key->entities, node                                             );
    sll_append(void_ptr, my_node_key->entities, _np_node_from_token(node, np_aaatoken_type_node) );
    // sll_append(void_ptr, my_node_key->entities, NULL                                             );

    my_node_key->type |= np_key_type_node;
    node->state = AAA_VALID;
    
    __add_transitions_for(my_node_key, np_key_type_node);
}
void __np_node_update(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    // handle leave event

    // handle ping reply

    // send ping request

}
void __np_node_handle_completion(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{ 
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void _np_node_update(...) {");

    NP_CAST(event.user_data, np_aaatoken_t, token);
    NP_CAST(statemachine->_user_data, np_key_t, my_node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(my_node_key, &trinity);

    if ( FLAG_CMP(event.type,evt_internal) )
    {   // self triggered event to handle node completion
        if (trinity.node->_handshake_status != np_handshake_status_Connected) 
        {
            _np_network_send_handshake(context, my_node_key, false, NULL);
        } 
        else if (trinity.node->joined_network != true) 
        {
            np_send_join(context, "");
        }
    }

    if ( FLAG_CMP(event.type, evt_token) )
    {   // external event received to complete the node configuration (join / join_ack)

        // np_key_t *added = NULL, *deleted = NULL;
        // _np_route_leafset_update(my_node_key, true, added, deleted);
        // TODO: error handling
        // _np_route_update(my_node_key, true, added, deleted);
        // TODO: error handling
    }
}
void __np_node_handle_leave(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{ }
void __np_node_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{    
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, my_node_key);

    np_aaatoken_t* node_token = (np_aaatoken_t*) sll_head(void_ptr, my_node_key->entities);
    np_node_t* node_struct = (np_node_t*) sll_head(void_ptr, my_node_key->entities);
    np_network_t* node_network = (np_network_t*) sll_head(void_ptr, my_node_key->entities);
    
    // np_unref_obj(np_aaatoken_t, sll_first(my_node_key->entities), ref_key_aaa_token);
    // np_unref_obj(np_node_t, sll_second(my_node_key->entities), ref_key_aaa_token);
    // np_unref_obj(np_network_t, sll_last(my_node_key->entities), ref_key_aaa_token);

    _np_keycache_remove(context, my_node_key->dhkey);
    my_node_key->is_in_keycache = false;

    sll_clear(void_ptr, my_node_key->entities);

    my_node_key->type = np_key_type_unknown;
}
