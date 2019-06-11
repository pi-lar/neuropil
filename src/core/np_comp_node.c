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

bool __is_node_join_nack(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    return false;
}

bool __is_node_leave_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_node_leave_message(...) {");

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
    log_debug_msg(LOG_TRACE, "start: bool __is_node_invalid(...) {");

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
    log_debug_msg(LOG_TRACE, "start: bool __is_wildcard_key(...) {");

    bool ret = false;
    
    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_node_t, my_node);

    if (!ret) ret  = FLAG_CMP(event.type, evt_internal);
    if ( ret) ret &= _np_memory_rtti_check(my_node, np_memory_types_np_node_t);
    if ( ret) ret &= _np_node_check_address_validity(my_node);

    return ret;
}

bool __is_node_authn(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    return false;
}

void __np_node_set(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void __np_node_set(...) {");

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
    }    
    log_debug_msg(LOG_DEBUG, "node_status: %d %f", my_node->_handshake_status, my_node->handshake_send_at);
}

void __np_wildcard_set(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void __np_wildcard_set(...) {");

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
    log_debug_msg(LOG_DEBUG, "start: void __np_node_handle_completion(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    double now = np_time_now();

    np_dhkey_t hs_dhkey = _np_msgproperty_dhkey( OUTBOUND, _NP_MSG_HANDSHAKE);
    np_dhkey_t join_dhkey = _np_msgproperty_dhkey( OUTBOUND, _NP_MSG_JOIN_REQUEST);

    np_msgproperty_t* hs_prop = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_HANDSHAKE);
    np_msgproperty_t* join_prop = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_JOIN_REQUEST);

    log_debug_msg(LOG_DEBUG, "node_status: %d %f", trinity.node->_handshake_status, trinity.node->handshake_send_at);

    if ( trinity.node->_handshake_status < np_handshake_status_Connected && 
         (trinity.node->handshake_send_at + hs_prop->msg_ttl) < now       )
    {
        np_key_t* hs_key = _np_keycache_find(context, hs_dhkey);
        np_util_event_t handshake_event = { .type=(evt_internal|evt_message), .context=context, .user_data=NULL, .target_dhkey=node_key->dhkey };
        np_util_statemachine_invoke_auto_transition(&hs_key->sm, handshake_event);

        trinity.node->handshake_send_at = np_time_now();
        trinity.node->_handshake_status++;
        
        log_debug_msg(LOG_DEBUG, "start: __np_node_handle_completion(...) { node now         : %p / %p %d", node_key, trinity.node, trinity.node->_handshake_status);
    } 
    else if (trinity.node->joined_network == false && 
            (trinity.node->join_send_at + join_prop->msg_ttl) < now ) 
    {
        np_key_t* join_key = _np_keycache_find(context, join_dhkey);
        np_util_event_t handshake_event = { .type=(evt_internal|evt_message), .context=context, .user_data=NULL, .target_dhkey=node_key->dhkey };
        np_util_statemachine_invoke_auto_transition(&join_key->sm, handshake_event);

        trinity.node->join_send_at = np_time_now();
    }
}

void __np_wildcard_finalize(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_wildcard_finalize(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, wildcard_key);

    // we do not need this key anymore
    wildcard_key->type = np_key_type_unknown;
}

bool __is_node_join(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_node_join(...) {");
    return false;
    // join request or join ack
}

void __np_node_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{    
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_node_destroy(...) {");

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
        _np_network_start(my_network, true);
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
    NP_CAST(event.user_data, np_message_t, hs_message);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    char* packet = np_memory_new(context, np_memory_types_BLOB_1024);

    memcpy(packet, pll_first(hs_message->msg_chunks)->val->msg_part, 984);
    
    sll_append(
        void_ptr,
        trinity.network->out_events,
        (void*)packet);

    log_debug_msg(LOG_TRACE, "start: void __np_node_send_direct(...) { %d", sll_size(trinity.network->out_events));

    _np_network_start(trinity.network, true);
    _np_message_trace_info("out", hs_message);
}

void __np_node_send_encrypted(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_node_send_encrypted(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_message_t, message);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(node_key, &trinity);

    int part = 0;
    pll_iterator(np_messagepart_ptr) iter = pll_first(message->msg_chunks);
    while (NULL != iter )
    {
        part++;

        // add protection from replay attacks ...
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        // TODO: move nonce to np_node_t and re-use it with increments ?
        randombytes_buf(nonce, sizeof(nonce));

        unsigned char enc_msg[MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES];
        int encryption = crypto_secretbox_easy(enc_msg,
            (const unsigned char*)iter->val,
            MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40,
            nonce,
            trinity.node->session.session_key_to_write
        );

        log_debug_msg(LOG_DEBUG | LOG_HANDSHAKE,
            "HANDSHAKE SECRET: using shared secret from target %s on system %s to encrypt data (msg: %s)",
            _np_key_as_str(node_key), _np_key_as_str(context->my_node_key), message->uuid);

        if (encryption != 0)
        {
            log_msg(LOG_ERROR,
                "incorrect encryption of message (%s) (not sending to %s:%s)",
                message->uuid, trinity.node->dns_name, trinity.node->port);
        } 
        else
        {
            unsigned char* enc_buffer = np_memory_new(context, np_memory_types_BLOB_1024);
            
            uint32_t enc_buffer_len = MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES;
            memcpy(enc_buffer, nonce, crypto_secretbox_NONCEBYTES);
            memcpy(enc_buffer + crypto_secretbox_NONCEBYTES, enc_msg, enc_buffer_len);

            /* send data */
            if (NULL != trinity.network->out_events) {
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "appending message (%s part: %d) %p (%d bytes) to queue for %s:%s", message->uuid, part, enc_buffer, MSG_CHUNK_SIZE_1024, trinity.node->dns_name, trinity.node->port);
                char tmp_hex[MSG_CHUNK_SIZE_1024*2+1] = { 0 };

                log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                    "(msg: %s) %s",
                    message->uuid, sodium_bin2hex(tmp_hex, MSG_CHUNK_SIZE_1024*2+1, enc_buffer, MSG_CHUNK_SIZE_1024));
                
                sll_append(void_ptr, trinity.network->out_events, (void*)enc_buffer);                                    
                _np_network_start(trinity.network, false);
#ifdef DEBUG
                if(!trinity.network->is_running){
                    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "msg (%s) cannot be send (now) as network is not running", message->uuid);
                }
#endif
            } else {
                log_debug_msg(LOG_INFO, "Dropping data package for msg %s due to not initialized out_events", message->uuid);
                np_memory_free(context, enc_buffer);
            }
        }
        pll_next(iter);
    }
}

bool __is_np_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_np_message(...) {");

    bool ret = false;
    
    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_message_t, hs_message);

    if (!ret) ret  = (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_message));
    if ( ret) ret &= node_key->type == np_key_type_node;
    if ( ret) ret &= _np_memory_rtti_check(hs_message, np_memory_types_np_message_t);
    return ret;
}

bool __is_handshake_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_handshake_message(...) {");

    bool ret = false;
    
    NP_CAST(statemachine->_user_data, np_key_t, node_key);
    NP_CAST(event.user_data, np_message_t, hs_message);

    if (!ret) ret  = (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_message));
    if ( ret) ret &= (node_key->type == np_key_type_wildcard || node_key->type == np_key_type_node);
    if ( ret) ret &= _np_memory_rtti_check(hs_message, np_memory_types_np_message_t);
    if ( ret) {
        /* TODO: make it working and better! 
        char str_msg_subject[65];
        CHECK_STR_FIELD_BOOL(hs_message->header, _NP_MSG_HEADER_SUBJECT, str_msg_subject, "NO SUBJECT IN MESSAGE") {
            ret &= (0 == strncmp(str_msg_subject, _NP_MSG_HANDSHAKE, strlen(_NP_MSG_HANDSHAKE)) );
        }
        */
    }
    return ret;
}

bool __is_join_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_join_message(...) {");

    bool ret = false;
    
    NP_CAST(event.user_data, np_message_t, hs_message);

    if (!ret) ret  = FLAG_CMP(event.type, evt_message);
    if ( ret) ret &= (FLAG_CMP(event.type, evt_internal) || FLAG_CMP(event.type, evt_external));
    if ( ret) ret &= _np_memory_rtti_check(hs_message, np_memory_types_np_message_t);
    if ( ret) {
        /* TODO: make it working and better! 
        char str_msg_subject[65];
        CHECK_STR_FIELD_BOOL(hs_message->header, _NP_MSG_HEADER_SUBJECT, str_msg_subject, "NO SUBJECT IN MESSAGE") {
            ret &= (0 == strncmp(str_msg_subject, _NP_MSG_JOIN, strlen(_NP_MSG_HANDSHAKE)) );
        }
        */
    }
    return ret;
}
