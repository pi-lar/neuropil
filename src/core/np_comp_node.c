//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that a node can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include "np_axon.h"
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

bool __is_node_join_nack(np_util_statemachine_t* statemachine, const np_util_event_t event)
{

}

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
    
    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    if (!ret) ret = (node_key->aaa_token != NULL);
    if ( ret) {
        NP_CAST(node_key->aaa_token, np_aaatoken_t, node);
        ret &= (node_key->type == np_aaatoken_type_node);
        ret &= !_np_aaatoken_is_valid(node, np_aaatoken_type_node);
    }
    return ret;
}

bool __is_wildcard_key(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);

    bool ret = false;
    
    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_node_t, my_node);

    if (!ret) ret  = (node_key->type == np_key_type_wildcard);
    if ( ret) ret &= _np_memory_rtti_check(my_node, np_memory_types_np_node_t);
    if ( ret) ret &= _np_node_check_address_validity(my_node);

    return ret;
}

bool __is_node_authn(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{

}

void __np_node_set(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void _np_set_node(np_aaatoken_t* node){");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_aaatoken_t, node_token);

    np_node_t* my_node = _np_node_from_token(node_token, node_token->type);
    if (node_token->type == np_aaatoken_type_handshake) 
    {
        my_node->_handshake_status++;
    }

    sll_append(void_ptr, node_key->entities, node_token);
    sll_append(void_ptr, node_key->entities, my_node);

    node_key->type |= np_key_type_node;
    node_token->state = AAA_VALID;
}

void __np_wildcard_set(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void _np_set_node(np_aaatoken_t* node){");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_node_t, node);

    // _np_keycache_add(node_key);
    sll_append(void_ptr, node_key->entities, node);   
}

void __np_node_update(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    // issue ping / piggy messages
}

void __np_node_upgrade(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   

}

void __np_node_update_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    // comapare new and old node token, take over changes
}

void __np_node_handle_completion(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{ 
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void _np_node_update(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_aaatoken_t, node_token);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    if ( FLAG_CMP(event.type,evt_internal) )
    {   // self triggered event to handle node completion
        if (trinity.node->_handshake_status != np_handshake_status_Connected) 
        {
            _np_network_send_handshake(context, node_key, false, NULL);
        } 
        else if (trinity.node->joined_network != true) 
        {
            np_send_join(context, "");
        }
    }

    if ( FLAG_CMP(event.type, evt_token) && FLAG_CMP(event.type, evt_external) )
    {   // external token received to complete the node configuration (join / join_ack)

    }
}

void __np_wildcard_finalize(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, wildcard_key);
    NP_CAST(event.user_data, np_aaatoken_t, wildcard_token);

    np_dhkey_t search_key = np_aaatoken_get_fingerprint(wildcard_token, false);
    np_key_t* node_key = _np_keycache_find_or_create(context, search_key);

    np_util_event_t ev = { .type=(evt_external|evt_token), .context=context, .user_data=wildcard_token };
    np_util_statemachine_invoke_auto_transition(&node_key->sm, ev);

    // we do not need this key anymore
    wildcard_key->type = np_key_type_unknown;
}

bool __is_node_join(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    // join request or join ack
}

void __np_node_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{    
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    _np_keycache_remove(context, node_key->dhkey);
    node_key->is_in_keycache = false;

    // TODO unref and clean trinity data structures
    sll_clear(void_ptr, node_key->entities);

    node_key->type = np_key_type_unknown;
}

void __np_create_client_network (np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    if (NULL == trinity.network && NULL != trinity.node) 
    {
        // create outgoing network
        np_network_t* my_network = NULL;
        np_new_obj(np_network_t, my_network);
        _np_network_init(my_network, false, trinity.node->protocol, trinity.node->dns_name, trinity.node->port, -1, UNKNOWN_PROTO);
        _np_network_set_key(my_network, node_key);

        sll_append(void_ptr, node_key->entities, my_network);

        log_debug_msg(LOG_DEBUG | LOG_NETWORK, "Network %s is the main receiving network", np_memory_get_id(my_network));

        _np_network_enable(my_network);
        _np_network_start(my_network, true);
    }

    // send out handshake (reply or new)
    np_jobargs_t args = { .target=node_key };

    if (trinity.token->type == np_aaatoken_type_handshake) 
    {
        // add identitfcation for reply handshake
        args.custom_data = strndup(trinity.token->uuid, NP_UUID_BYTES);

        // create cryptio session key
        np_aaatoken_t* my_token = sll_first(context->my_node_key->entities)->val;
        trinity.node->session_key_is_set = 
                    (0 == np_crypto_session(context, 
                                            &my_token->crypto,
                                            &trinity.node->session,
                                            &trinity.token->crypto,
                                            false ) 
                    );
    }

    _np_out_handshake(context, args);

    trinity.node->handshake_send_at = np_time_now();
    trinity.node->_handshake_status++;
    node_key->last_update = np_time_now();
}

bool __is_wildcard_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    NP_CAST(statemachine->_user_data, np_key_t, node_key); 

    if ( (node_key->created_at + 60) < np_time_now() ) return true;

    return false;
}

void __np_wildcard_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{

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
