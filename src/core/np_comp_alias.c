//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that an identity can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include "stdio.h"
#include "inttypes.h"

#include "core/np_comp_alias.h"
#include "core/np_comp_node.h"

#include "neuropil.h"
#include "np_aaatoken.h"
#include "util/np_bloom.h"
#include "np_key.h"
#include "np_legacy.h"
#include "neuropil_log.h"
#include "np_log.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_pheromones.h"
#include "np_route.h"
#include "np_statistics.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"
#include "util/np_tree.h"
#include "neuropil_data.h"

np_message_t* _np_alias_check_msgpart_cache(np_state_t* context, np_message_t* msg_to_check)
{
    log_trace_msg(LOG_TRACE, "start: np_message_t* _np_alias_check_msgpart_cache(...){");

    np_message_t* ret= NULL;

#ifdef DEBUG
    np_tree_elem_t*  ele = np_tree_find_str(msg_to_check->header, _NP_MSG_HEADER_SUBJECT);
    assert(ele!=NULL);
    char subject[100]={0};
    strncpy(subject, np_treeval_to_str(ele->val, NULL), 99);
#endif

    // Detect from instructions if this msg was orginally chunked
    char msg_uuid[NP_UUID_BYTES+1]={0};
    strncpy(msg_uuid, np_treeval_to_str(np_tree_find_str(msg_to_check->instructions, _NP_MSG_INST_UUID)->val, NULL), NP_UUID_BYTES);
    np_dhkey_t uuid_dhkey = np_dhkey_create_from_hostport(msg_uuid, "0");

    bool _seen_before = true;
    _LOCK_MODULE(np_message_part_cache_t)
    {
        _seen_before = context->msg_part_filter->op.check_cb(context->msg_part_filter, uuid_dhkey);
    }

    bool is_expired = _np_message_is_expired(msg_to_check);

    uint16_t expected_msg_chunks = np_tree_find_str(msg_to_check->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[0];
    if (!is_expired && !_seen_before && 1 < expected_msg_chunks)
    {
        _LOCK_MODULE(np_message_part_cache_t)
        {
            // If there exists multiple chunks, check if we already have one in cache
            np_tree_elem_t* tmp = np_tree_find_str(context->msg_part_cache, msg_uuid);
            if (NULL != tmp)
            {
                // there exists a msg(part) in our msgcache for this msg uuid
                // lets add our msgpart to this msg
                np_message_t* msg_in_cache = tmp->val.value.v;

                np_messagepart_ptr to_add = NULL;
                _LOCK_ACCESS(&msg_to_check->msg_chunks_lock) {
                    to_add = pll_first(msg_to_check->msg_chunks)->val; // get the messagepart we received
                }
                log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
                        "message (%s) %p / %p / %p", msg_uuid, msg_in_cache, msg_in_cache->msg_chunks, to_add);

                uint32_t current_count_of_chunks = 0;
                _LOCK_ACCESS(&msg_in_cache->msg_chunks_lock)
                {
                    // try to add the new received messagepart to the msg in cache
                    if(true == pll_insert(np_messagepart_ptr, msg_in_cache->msg_chunks, to_add, false, _np_messagepart_cmp)) {
                        // new entry is added (was not present)
                        pll_head(np_messagepart_ptr, msg_to_check->msg_chunks);
                    }
                    // we saved the chunk, but the message capsule can go now
                    np_unref_obj(np_message_t, msg_to_check, ref_message_in_send_system);
                    // now we check if all chunks are complete for this msg
                    current_count_of_chunks = pll_size(msg_in_cache->msg_chunks);
                }

                if (current_count_of_chunks < expected_msg_chunks)
                {
                    log_debug(LOG_MESSAGE,
                        "message %s (%s) not complete yet (%"PRIu32" of %"PRIu16"), waiting for missing parts",
                        subject, msg_uuid, current_count_of_chunks, expected_msg_chunks);
                    // nothing to return as we still wait for chunks
                }
                else
                {

                    log_debug(LOG_MESSAGE,
                        "message %s (%s) is complete now  (%"PRIu32" of %"PRIu16")",
                        subject, msg_uuid, current_count_of_chunks, expected_msg_chunks);

                    ret = msg_in_cache;
                    // removing the message from the cache system
                    np_ref_obj(np_message_t, msg_in_cache, ref_message_in_send_system);
                    //msg_uuid = np_treeval_to_str(np_tree_find_str(msg_in_cache->instructions, _NP_MSG_INST_UUID)->val, NULL);
                    np_tree_del_str(context->msg_part_cache, msg_uuid);
                    np_unref_obj(np_message_t, msg_in_cache, ref_msgpartcache);

                    context->msg_part_filter->op.add_cb(context->msg_part_filter, uuid_dhkey);
                }
            }
            else
            {
                // there exists no msg(part) in our msgcache for this msg uuid
                // TODO: limit msg_part_cache size

                // there is no chunk for this msg in cache,
                // so we insert this message into out cache
                // as a structure to accumulate further chunks into
                np_ref_obj(np_message_t, msg_to_check, ref_msgpartcache); // we need to unref this after we finish the handeling of this msg
                np_tree_insert_str(context->msg_part_cache, msg_uuid, np_treeval_new_v(msg_to_check));
                np_unref_obj(np_message_t, msg_to_check, ref_message_in_send_system);
            }
        }
    }
    else if (!is_expired && !_seen_before)
    {
        // If this is the only chunk, then return it as is
        log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "message %s (%s) is unchunked", subject, msg_uuid);
        ret = msg_to_check;
        _LOCK_MODULE(np_message_part_cache_t)
        {
            context->msg_part_filter->op.add_cb(context->msg_part_filter, uuid_dhkey);
        }
    }
    else 
    {
        log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "discarding message %s (%s) because it was handled before or is too old", subject, msg_uuid);
        np_unref_obj(np_message_t, msg_to_check, ref_message_in_send_system);
        ret = NULL;
    }
    return ret;
}

void _np_alias_cleanup_msgpart_cache(np_state_t* context)
{
    np_sll_t(np_message_ptr, to_del);
    sll_init(np_message_ptr, to_del);
    
    _LOCK_MODULE(np_message_part_cache_t)
    {
        if (context->msg_part_cache->size > 0) 
        {
            log_debug_msg(LOG_DEBUG, "MSG_PART_TABLE checking (left-over) message parts (size: %d)", context->msg_part_cache->size);
            np_tree_elem_t* tmp = NULL;
            RB_FOREACH(tmp, np_tree_s, context->msg_part_cache)
            {
                np_message_t* msg = tmp->val.value.v;
                if (true == _np_message_is_expired(msg)) {
                    sll_append(np_message_ptr, to_del, msg);
                }
            }
        }
        _np_decaying_bloom_decay(context->msg_part_filter);
    }

    sll_iterator(np_message_ptr) iter = sll_first(to_del);
    while (NULL != iter)
    {
        log_debug_msg(LOG_DEBUG, "MSG_PART_TABLE removing (left-over) message part for uuid: %s", iter->val->uuid);
        _LOCK_MODULE(np_message_part_cache_t)
        {
            np_tree_del_str(context->msg_part_cache, iter->val->uuid);
        }
        np_unref_obj(np_message_t, iter->val, ref_msgpartcache);
        sll_next(iter);
    }
    sll_free(np_message_ptr, to_del);  

    uint16_t _peer_nodes   = _np_route_my_key_count_routes(context); /* + 
                             _np_route_my_key_count_neighbors(context, NULL, NULL); */
    uint8_t _size_modifier = floor(cbrt(_peer_nodes));

    _LOCK_MODULE(np_message_part_cache_t) 
    {
        log_debug_msg(LOG_DEBUG, "MSG_PART_TABLE duplicate check has currently space for: %d items (s: %d / p: %d)", 
                          context->msg_part_filter->_free_items, context->msg_part_filter->_size, context->msg_part_filter->_p);

        size_t                  _size_adjustment  = 1024;
        if (_size_modifier > 0) _size_adjustment  = _size_modifier*1024;
        if (context->msg_part_filter->_size != _size_adjustment)
        {
            free(context->msg_part_filter->_bitset);
            context->msg_part_filter->_size = _size_adjustment;
            _np_standard_bloom_clear(context->msg_part_filter);
            log_debug_msg(LOG_DEBUG, "MSG_PART_TABLE duplicate check adjusted, now using size: %d", _size_adjustment);
        }

        uint8_t _prune_adjustment = 1;
        if (_size_modifier > 1) _prune_adjustment = _size_modifier;
        if (context->msg_part_filter->_p != _prune_adjustment)
        {
            context->msg_part_filter->_p = _prune_adjustment;
            log_debug_msg(LOG_DEBUG, "MSG_PART_TABLE duplicate check adjusted, now using bit-pruning: %d)", _prune_adjustment);
        }
    }
}

bool __is_alias_handshake_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_alias_handshake_token(...) {");
    
    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_token) && FLAG_CMP(event.type, evt_internal);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_aaatoken_t);
    if ( ret) {
        NP_CAST(event.user_data, np_aaatoken_t, hs_token);
        ret &= (hs_token->type == np_aaatoken_type_handshake);
        ret &= _np_aaatoken_is_valid(hs_token, hs_token->type);
    }
    return ret;
}

void __np_alias_set(np_util_statemachine_t* statemachine, const np_util_event_t event)
{   // handle internal received handsjake token
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_alias_set(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);
    NP_CAST(event.user_data, np_aaatoken_t, handshake_token);

    if (!FLAG_CMP(alias_key->type, np_key_type_alias))
    {
        alias_key->type |= np_key_type_alias;
        np_ref_obj(np_key_t, alias_key, "__np_alias_set");
    }

    // fix TCP setup and set correct key
    np_network_t* alias_network = _np_key_get_network(alias_key);
    if (alias_network != NULL) {
        _np_network_stop(alias_network, true);
        ref_replace_reason(np_network_t, alias_network, ref_obj_creation, "__np_alias_set");
        _np_network_set_key(alias_network, alias_key->dhkey);
        _np_network_start(alias_network, true);
    }

    alias_key->entity_array[0] = handshake_token;
    np_ref_obj(np_aaatoken_t, handshake_token, "__np_alias_set");

    np_dhkey_t search_key = {0};
    _np_str_dhkey(handshake_token->issuer, &search_key);

    np_node_t* alias_node = NULL;
    np_key_t* node_key = _np_keycache_find(context, search_key);
    if (NULL == node_key) 
    {
        // TODO: check if this code gets executed ever ...
        alias_node = alias_key->entity_array[2];
        if (alias_node == NULL) {
        alias_node = _np_node_from_token(handshake_token, handshake_token->type);
            alias_key->entity_array[2] = alias_node;
        ref_replace_reason(np_node_t, alias_node, "_np_node_from_token", "__np_alias_set");
        }
        alias_node->_handshake_status++;
    }
    else
    if (NULL != node_key)
    {
        alias_node = alias_key->entity_array[2];
        if (NULL != alias_node && alias_node != _np_key_get_node(node_key))
        {
            np_unref_obj(np_node_t, alias_node, "__np_alias_set");
            alias_node = _np_key_get_node(node_key);
            alias_key->entity_array[2] = alias_node;
            np_ref_obj(np_node_t, alias_node, "__np_alias_set");
        }
        else
        if (NULL == alias_node) 
        {
            alias_node = _np_key_get_node(node_key);
            alias_key->entity_array[2] = alias_node;
            np_ref_obj(np_node_t, alias_node, "__np_alias_set");
        }
        log_debug_msg(LOG_DEBUG, "start: void __np_alias_set(...) %p / %p {", node_key, alias_node);
    }

    np_node_t*  _my_node = _np_key_get_node(context->my_node_key);
    // check node key for passive network connection (partner or own node is passive)
    if (NULL != node_key && 
        NULL != _my_node && 
        (
            FLAG_CMP(alias_node->protocol, PASSIVE) ||
            FLAG_CMP(_my_node->protocol, PASSIVE) 
        )
       )
    {
        // take over existing network if partner is passive
        log_debug_msg(LOG_NETWORK, "try to take over existing network (passive mode)");
        struct __np_node_trinity node_trinity = {0};
        __np_key_to_trinity(node_key, &node_trinity);
        if (NULL != node_trinity.network) 
        {
            log_debug_msg(LOG_NETWORK, "take over existing network (passive mode)");
            _np_network_stop(node_trinity.network, true);
            np_ref_obj(np_network_t, node_trinity.network, "__np_alias_set");
            alias_key->entity_array[3] = node_trinity.network;
            // set our key to receive and decrypt messages
            _np_network_set_key(node_trinity.network, alias_key->dhkey);
            _np_network_start(node_trinity.network, true);
        }
    }

    if (NULL != node_key)
        np_unref_obj(np_key_t, node_key, "_np_keycache_find");

    handshake_token->state = AAA_VALID;
}

bool __is_alias_node_info(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_alias_node_info(...) {");

    bool ret = false;    
    NP_CAST(event.user_data, np_node_t, my_node);

    if (!ret) ret  = FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= _np_memory_rtti_check(my_node, np_memory_types_np_node_t);
    if ( ret) ret &= _np_node_check_address_validity(my_node);

    return ret;
}

void __np_alias_set_node(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_alias_set_node(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);
    NP_CAST(event.user_data, np_node_t, node);

    log_debug_msg(LOG_DEBUG, "start: void __np_alias_set_node(...) { %s:%s", node->dns_name, node->port);

    if (alias_key->entity_array[2] == NULL) 
    {
        np_ref_obj(np_key_t, alias_key, "__np_alias_set");
        alias_key->type |= np_key_type_alias;

        log_debug_msg(LOG_INFO, "created new alias structure %s / %s", node->dns_name, node->port);    

        alias_key->entity_array[2] = node;   
        ref_replace_reason(np_node_t, node, "_np_network_read", "__np_alias_set");
    }
    else 
    {
        np_unref_obj(np_node_t, node, "_np_network_read");
    }
}

void __np_create_session(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event)
{   // create crypto session and "steal" node sructure
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_create_session(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);

    np_aaatoken_t* handshake_token = alias_key->entity_array[0];
    np_node_t*     alias_node      = alias_key->entity_array[2];
    
    np_aaatoken_t* my_token = _np_key_get_token(context->my_node_key);
    np_node_t* my_node = _np_key_get_node(context->my_node_key);

    // HAS TO BE be there
    struct np_data_conf cfg;
    np_data_value remote_hs_prio = {0};

    if (np_get_data(handshake_token->attributes, NP_HS_PRIO, &cfg, &remote_hs_prio) != np_ok ){
        log_error("Structual error in token. Missing %s key", NP_HS_PRIO);
    }
    // COULD be there
    // np_tree_elem_t* response_uuid = np_tree_find_str(handshake_token->extensions, _NP_MSG_INST_RESPONSE_UUID);

    if (/* response_uuid == NULL ||*/
        remote_hs_prio.unsigned_integer < my_node->handshake_priority)
    {
        log_debug_msg(LOG_DEBUG,
            "handshake session created in server mode. remote-prio: %"PRIu32" local-prio: %"PRIu32" ",
                remote_hs_prio.unsigned_integer, my_node->handshake_priority
            );
        np_crypto_session(context,
                &my_token->crypto,
                &alias_node->session,
                &handshake_token->crypto,
                false
            );
    } else {
        log_debug_msg(LOG_DEBUG,
            "handshake session created in client mode. remote-prio: %"PRIu32" local-prio: %"PRIu32" ",
                remote_hs_prio.unsigned_integer, my_node->handshake_priority
            );
        np_crypto_session(context,
                &my_token->crypto,
                &alias_node->session,
                &handshake_token->crypto,
                true
            );
    }

    alias_node->_handshake_status++;
    alias_node->session_key_is_set = true;

    log_debug_msg(LOG_DEBUG, "start: __np_create_session(...) { node now complete: %p / %p %d", alias_key, alias_node, alias_node->_handshake_status);
}

bool __is_crypted_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_crypted_message(...) {");

    bool ret = false;

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);
    if (!ret) ret  = FLAG_CMP(alias_key->type, np_key_type_alias);
    if ( ret) ret &= FLAG_CMP(event.type, evt_message);
    if ( ret) ret &= (FLAG_CMP(event.type, evt_external) );
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_BLOB_1024);
    // if ( ret) ret &= 
    // TODO: check crypto signature of incomming message
    // TODO: check increasing counter of partner node
    
    return ret;
}

void __np_alias_decrypt(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   // decrypt transport encryption
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __np_alias_decrypt(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);

    log_debug_msg(LOG_DEBUG, "/start decrypting message with alias %s", _np_key_as_str(alias_key));

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    // unsigned char dec_msg[MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES];
    unsigned char* dec_msg = np_memory_new(context, np_memory_types_BLOB_984_RANDOMIZED);
    memcpy(nonce, event.user_data, crypto_secretbox_NONCEBYTES);                

    #ifdef DEBUG
        char msg_hex[2*MSG_CHUNK_SIZE_1024+1];
        sodium_bin2hex(msg_hex, 2*MSG_CHUNK_SIZE_1024+1, event.user_data, MSG_CHUNK_SIZE_1024);                
        log_debug(LOG_MESSAGE, "Try to decrypt data. 0x%.5s...%s", msg_hex, msg_hex + strlen(msg_hex) - 5);
    #endif

    int crypto_result = 
        crypto_secretbox_open_easy(
            dec_msg,
            (const unsigned char *)event.user_data + crypto_secretbox_NONCEBYTES,
            MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES,
            nonce,
            _np_key_get_node(alias_key)->session.session_key_to_read
    );
                    
    log_debug_msg(LOG_DEBUG,
        "HANDSHAKE SECRET: using shared secret from %s (mem id: %s) = %"PRIi32" to decrypt data",
        _np_key_as_str(alias_key), np_memory_get_id(alias_key), crypto_result
    );

    if (crypto_result == 0)
    {
        log_debug_msg(LOG_DEBUG, "correct decryption of message send from %s", _np_key_as_str(alias_key));

        // memset(event.user_data, 0, MSG_CHUNK_SIZE_1024);
        // memcpy(event.user_data, dec_msg, MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);

        np_message_t* msg_in = NULL;
        np_new_obj(np_message_t, msg_in, ref_message_in_send_system);
        if (!_np_message_deserialize_header_and_instructions(msg_in, dec_msg) )
        {
            log_debug_msg(LOG_DEBUG, "incorrect header deserialization of message send from %s", _np_key_as_str(alias_key));
            np_memory_unref_obj(context, event.user_data, "_np_network_read");
            np_memory_free(context, dec_msg);
            np_unref_obj(np_message_t, msg_in, ref_message_in_send_system);
            return;
        }
        log_debug_msg(LOG_SERIALIZATION, "(msg: %s) correct header deserialization of message", msg_in->uuid);

        _np_message_trace_info("MSG_IN", msg_in);
        np_util_event_t in_message_evt = { .type=(evt_external|evt_message), .context=context,
                                           .user_data=msg_in, .target_dhkey=alias_key->dhkey};
        _np_keycache_handle_event(context, alias_key->dhkey, in_message_evt, false);
        // _np_keycache_handle_event(context, alias_key->dhkey, in_message_evt, false);

    } else {
        // np_memory_unref_obj(context, event.user_data, "_np_network_read");
        np_memory_free(context, dec_msg);

        log_msg(LOG_WARN,
            "error on decryption of message (source: %s:%s)", _np_key_get_node(alias_key)->dns_name, _np_key_get_node(alias_key)->port);
    }
    void* raw_message = event.user_data;
    np_unref_obj(BLOB_1024, raw_message, "_np_network_read");
    // np_memory_unref_obj(context, event.user_data, "_np_network_read");
} 

bool __is_join_in_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_join_in_message(...) {");

    bool ret = false;

    NP_CAST(statemachine->_user_data, np_key_t, alias_key); 
    if (!ret) ret  = FLAG_CMP(alias_key->type, np_key_type_alias);
    if ( ret) ret &= (FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external) );
    if ( ret) ret &= (event.user_data != NULL);

    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);
    if ( ret) {
        NP_CAST(event.user_data, np_message_t, join_message);
        /* TODO: make it working and better! */
        np_dhkey_t join_dhkey = {0};
        np_generate_subject(&join_dhkey, _NP_MSG_JOIN_REQUEST, strnlen(_NP_MSG_JOIN_REQUEST, 256));
        np_dhkey_t leave_dhkey = {0};
        np_generate_subject(&leave_dhkey, _NP_MSG_LEAVE_REQUEST, strnlen(_NP_MSG_LEAVE_REQUEST, 256));
        CHECK_STR_FIELD_BOOL(join_message->header, _NP_MSG_HEADER_SUBJECT, msg_subject_elem, "NO SUBJECT IN MESSAGE") {
            ret &= ( _np_dhkey_equal(&msg_subject_elem->val.value.dhkey, &join_dhkey)  ) ||
                   ( _np_dhkey_equal(&msg_subject_elem->val.value.dhkey, &leave_dhkey ) );
            return ret;
        }
        ret = false;
    }
    return ret;
}

bool __is_forward_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_forward_message(...) {");

    bool ret = false;

    NP_CAST(statemachine->_user_data, np_key_t, alias_key); 
    if (!ret) ret  = FLAG_CMP(alias_key->type, np_key_type_alias);
    if ( ret) ret &= FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= (event.user_data != NULL);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);

    if ( ret) {
        NP_CAST(event.user_data, np_message_t, discovery_message);
        /* TODO: use the bloom, luke */
        CHECK_STR_FIELD_BOOL(discovery_message->header, _NP_MSG_HEADER_TO, str_msg_to, "NO TO IN MESSAGE") 
        {
            // messagepart is not addressed to our node --> forward
            ret &= !_np_dhkey_equal(&context->my_node_key->dhkey, &str_msg_to->val.value.dhkey);
        }
    }
    return ret;
}

bool __is_discovery_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_discovery_message(...) {");

    bool ret = __is_forward_message(statemachine, event);
    if  (ret) 
    {
        NP_CAST(event.user_data, np_message_t, discovery_message);
        /* TODO: use the bloom, luke */
        NP_PERFORMANCE_POINT_START(is_discovery_message);
        CHECK_STR_FIELD_BOOL(discovery_message->header, _NP_MSG_HEADER_SUBJECT, msg_subject_elem, "NO SUBJECT IN MESSAGE")
        {
            np_dhkey_t avail_recv_dhkey = {0};
            np_generate_subject( (np_subject*) &avail_recv_dhkey, _NP_MSG_AVAILABLE_RECEIVER, strnlen(_NP_MSG_AVAILABLE_RECEIVER, 256) );
            np_dhkey_t avail_send_dhkey = {0};
            np_generate_subject( (np_subject*) &avail_send_dhkey, _NP_MSG_AVAILABLE_SENDER, strnlen(_NP_MSG_AVAILABLE_SENDER, 256) );
            // use the bloom to exclude other message types
            ret &= ( _np_dhkey_equal(&msg_subject_elem->val.value.dhkey, &avail_recv_dhkey) ) ||
                   ( _np_dhkey_equal(&msg_subject_elem->val.value.dhkey, &avail_send_dhkey) ) ;
        }
        NP_PERFORMANCE_POINT_END(is_discovery_message);
    }
    return ret;
}

bool __is_pheromone_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_pheromone_message(...) {");

    bool ret = false;

    NP_CAST(statemachine->_user_data, np_key_t, alias_key); 
    if (!ret) ret  = FLAG_CMP(alias_key->type, np_key_type_alias);
    if ( ret) ret &= FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= (event.user_data != NULL);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);

    if ( ret) 
    {
        NP_CAST(event.user_data, np_message_t, pheromone_message);
        CHECK_STR_FIELD_BOOL(pheromone_message->header, _NP_MSG_HEADER_SUBJECT, msg_subject_ele, "NO SUBJECT IN MESSAGE")
        {
            np_dhkey_t pheromone_dhkey = {0};
            np_generate_subject( (np_subject*) &pheromone_dhkey, _NP_MSG_PHEROMONE_UPDATE, strnlen(_NP_MSG_PHEROMONE_UPDATE, 256));
            ret &= (_np_dhkey_equal(&msg_subject_ele->val.value.dhkey, &pheromone_dhkey) );
        }
    }

    return ret;
}

bool __is_dht_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_dht_message(...) {");

    bool ret = false;

    NP_CAST(statemachine->_user_data, np_key_t, alias_key); 
    if (!ret) ret  = FLAG_CMP(alias_key->type, np_key_type_alias);
    if ( ret) ret &= FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= (event.user_data != NULL);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);

    if ( ret) 
    {
        NP_CAST(event.user_data, np_message_t, dht_message);
        /* TODO: use the bloom, luke */
        CHECK_STR_FIELD_BOOL(dht_message->header, _NP_MSG_HEADER_SUBJECT, msg_subject_elem, "NO SUBJECT IN MESSAGE")
        {
            NP_PERFORMANCE_POINT_START(is_dht_message);
            np_dhkey_t ack_dhkey = {0};
            np_generate_subject( (np_subject*) &ack_dhkey, _NP_MSG_ACK, strnlen(_NP_MSG_ACK, 256));
            np_dhkey_t ping_dhkey = {0};
            np_generate_subject( (np_subject*) &ping_dhkey, _NP_MSG_PING_REQUEST, strnlen(_NP_MSG_PING_REQUEST, 256));
            np_dhkey_t piggy_dhkey = {0};
            np_generate_subject( (np_subject*) &piggy_dhkey, _NP_MSG_PIGGY_REQUEST, strnlen(_NP_MSG_PIGGY_REQUEST, 256));
            np_dhkey_t update_dhkey = {0};
            np_generate_subject( (np_subject*) &update_dhkey, _NP_MSG_UPDATE_REQUEST, strnlen(_NP_MSG_UPDATE_REQUEST, 256));
            np_dhkey_t leave_dhkey = {0};
            np_generate_subject( (np_subject*) &leave_dhkey, _NP_MSG_LEAVE_REQUEST, strnlen(_NP_MSG_LEAVE_REQUEST, 256));

            // if (ret) {
                ret &=  ( _np_dhkey_equal(&msg_subject_elem->val.value.dhkey, &ack_dhkey            ) ||
                          _np_dhkey_equal(&msg_subject_elem->val.value.dhkey, &ping_dhkey           ) ||
                          _np_dhkey_equal(&msg_subject_elem->val.value.dhkey, &piggy_dhkey          ) ||
                          _np_dhkey_equal(&msg_subject_elem->val.value.dhkey, &update_dhkey         ) ||
                          _np_dhkey_equal(&msg_subject_elem->val.value.dhkey, &leave_dhkey          ) );
            // }
            NP_PERFORMANCE_POINT_END(is_dht_message);
        }

        if (ret) {
            CHECK_STR_FIELD_BOOL(dht_message->header, _NP_MSG_HEADER_TO, str_msg_to, "NO TO IN MESSAGE") 
            {
                // messagepart is not addressed to our node --> forward
                ret &= _np_dhkey_equal(&context->my_node_key->dhkey, &str_msg_to->val.value.dhkey);
            }
        }
        log_debug(LOG_MESSAGE,"(msg:%s) is %s DHT msg.",dht_message->uuid, (ret?"a ":"no"));        
    }
    return ret;
}

bool __is_usr_in_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_usr_in_message(...) {");

    bool ret = false;

    NP_CAST(statemachine->_user_data, np_key_t, alias_key); 
    if (!ret) ret  = FLAG_CMP(alias_key->type, np_key_type_alias);
    if ( ret) ret &= FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= (event.user_data != NULL);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);

    
    if ( ret) {
        NP_CAST(event.user_data, np_message_t, usr_message);
        /* TODO: use the bloom, luke */
        CHECK_STR_FIELD_BOOL(usr_message->header, _NP_MSG_HEADER_SUBJECT, msg_subject_elem, "NO SUBJECT IN MESSAGE")
        {
            NP_PERFORMANCE_POINT_START(is_usr_in_message);

            np_msgproperty_conf_t* user_prop = _np_msgproperty_conf_get(context, INBOUND, msg_subject_elem->val.value.dhkey);
            ret &= (NULL != user_prop);
            if (ret) ret &= !user_prop->is_internal;
            if (ret) ret &= (user_prop->audience_type != NP_MX_AUD_VIRTUAL);

            NP_PERFORMANCE_POINT_END(is_usr_in_message);
        }
/*
        if (ret) 
        {
            CHECK_STR_FIELD_BOOL(usr_message->header, _NP_MSG_HEADER_TO, str_msg_to, "NO TO IN MESSAGE") 
            {
                ret &= _np_dhkey_equal(&context->my_node_key->dhkey, &str_msg_to->val.value.dhkey);
            }
        }
*/

    }
    return ret;
}

void __np_handle(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   // handle ght messages (ping, piggy, ...)
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __np_handle(...) {");

    NP_CAST(event.user_data, np_message_t, message);

    // TODO: message part cache should be a component on its own, but for now just use it
    np_message_t* msg_to_use = _np_alias_check_msgpart_cache(context, message);

    if (msg_to_use != NULL)
    {
        if(_np_message_deserialize_chunked(msg_to_use) )
        {
            CHECK_STR_FIELD_BOOL(msg_to_use->header, _NP_MSG_HEADER_SUBJECT, msg_subject_elem, "NO SUBJECT IN MESSAGE")
            {
                np_dhkey_t subject_dhkey_in = _np_msgproperty_tweaked_dhkey(INBOUND, msg_subject_elem->val.value.dhkey);
                np_util_event_t msg_event = event;
                msg_event.user_data = msg_to_use;
                log_msg(LOG_INFO, "handling   message (%s) for subject: %08"PRIx32":%08"PRIx32, msg_to_use->uuid, msg_subject_elem->val.value.dhkey.t[0], msg_subject_elem->val.value.dhkey.t[1]);
                _np_keycache_handle_event(context, subject_dhkey_in, msg_event, false);
            }
        } else {
            log_warn(LOG_MESSAGE, "message (%s) has invalid data structure.", msg_to_use->uuid);
            np_unref_obj(np_message_t, msg_to_use, ref_message_in_send_system);
        }
    }
} 

void __np_handle_np_discovery(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   // handle discovery messages (ping, piggy, ...)
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __np_handle_np_discovery(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);
    NP_CAST(event.user_data, np_message_t, message);

    CHECK_STR_FIELD(message->header, _NP_MSG_HEADER_TO, msg_to);
    CHECK_STR_FIELD(message->header, _NP_MSG_HEADER_SUBJECT, msg_subj);

    // the value "event.target_dhkey" is set to an alias key when the request has been forwarded 
    // from another node.
    np_dhkey_t last_hop = alias_key->parent_key->dhkey;
    np_util_event_t available_event = event;
    available_event.target_dhkey = last_hop;

    // increase our pheromone trail by adding a stronger scent
    // TODO: move to np_dendrit.c and handle reply field as well
    np_dhkey_t avail_recv_dhkey = {0};
    np_dhkey_t avail_send_dhkey = {0};
    np_generate_subject( (np_subject*) &avail_recv_dhkey, _NP_MSG_AVAILABLE_RECEIVER, strnlen(_NP_MSG_AVAILABLE_RECEIVER, 256));
    np_generate_subject( (np_subject*) &avail_send_dhkey, _NP_MSG_AVAILABLE_SENDER, strnlen(_NP_MSG_AVAILABLE_SENDER, 256));
    bool find_receiver = _np_dhkey_equal(&avail_send_dhkey, &msg_subj.value.dhkey );
    bool find_sender   = _np_dhkey_equal(&avail_recv_dhkey, &msg_subj.value.dhkey );

    np_bloom_t* _scent = _np_neuropil_bloom_create();
    _np_neuropil_bloom_add(_scent, msg_to.value.dhkey);
    np_pheromone_t _pheromone = { 0 };
    if (find_receiver) {
        _pheromone._subj_bloom = _scent;
        _pheromone._sender     = last_hop;
        _pheromone._pos        = - ((msg_to.value.dhkey.t[0]%257)+1);
    }
    if (find_sender) {
        _pheromone._subj_bloom = _scent;
        _pheromone._receiver   = last_hop;
        _pheromone._pos        =   ((msg_to.value.dhkey.t[0]%257)+1);
    }
    bool _forward_discovery_msg = _np_pheromone_inhale(context, _pheromone);
    _np_bloom_free(_scent);

    if (_forward_discovery_msg) {
        log_debug_msg(LOG_TRACE, "forwarding message token, (subject %08"PRIx32":%08"PRIx32") to other nodes", msg_to.value.dhkey.t[0], msg_to.value.dhkey.t[1]);
        np_dhkey_t discover_out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, msg_subj.value.dhkey);
        np_util_event_t discover_event = event;
        discover_event.target_dhkey = last_hop;
        discover_event.type=(evt_internal|evt_message); 

        np_ref_obj(np_message_t, message, ref_message_in_send_system);
        _np_keycache_handle_event(context, discover_out_dhkey, discover_event, false);
    }

    // np_dhkey_t target_subject_dhkey = _np_msgproperty_tweaked_dhkey(INBOUND, msg_subj.value.dhkey);
    np_dhkey_t lookup_key = {0}; // check whether this node is interested in this kind of message
    if (find_receiver) 
    {
        log_debug_msg(LOG_DEBUG, "lookup receiver for message token, subject %08"PRIx32":%08"PRIx32" found in keycache", msg_to.value.dhkey.t[0], msg_to.value.dhkey.t[1]);
        lookup_key = _np_msgproperty_tweaked_dhkey(INBOUND, msg_to.value.dhkey);
    }
    if (find_sender) 
    {
        log_debug_msg(LOG_DEBUG, "lookup sender for message token, subject %08"PRIx32":%08"PRIx32" found in keycache", msg_to.value.dhkey.t[0], msg_to.value.dhkey.t[1]);
        lookup_key = _np_msgproperty_tweaked_dhkey(OUTBOUND, msg_to.value.dhkey);
    }

    np_key_t* subject_key = _np_keycache_find(context, lookup_key);
    if (NULL != subject_key) 
    {
        log_debug_msg(LOG_TRACE, "handling message token, subject %08"PRIx32":%08"PRIx32" found in keycache", lookup_key.t[0], lookup_key.t[1]);
        __np_handle(statemachine, available_event);
        np_unref_obj(np_key_t, subject_key, "_np_keycache_find");
    }
    else 
    {
        np_unref_obj(np_message_t, message, ref_message_in_send_system);
    }

    __np_cleanup__: {}
}

void __np_handle_pheromone(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    // handle ght messages (ping, piggy, ...)
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __np_handle_pheromone_message(...) {");

    bool ret = false;

    // check whether node and alias are in the correct state
    NP_CAST(statemachine->_user_data, np_key_t, alias_key);
    NP_CAST(event.user_data, np_message_t, pheromone_message);

    if (!ret) ret  = _np_dhkey_equal(&alias_key->dhkey, &event.target_dhkey);
    if ( ret) ret &= (NULL != alias_key->parent_key);
    if ( ret) ret &= FLAG_CMP(alias_key->parent_key->type, np_key_type_node);

    if ( ret) 
    {
        np_node_t* node = _np_key_get_node(alias_key);
        ret &= (node != NULL);
        ret &= (node->is_in_leafset || node->is_in_routing_table);
    }

    if (ret) 
    {
        np_util_event_t pheromone_evt = event;
        pheromone_evt.target_dhkey = alias_key->parent_key->dhkey;
        __np_handle(statemachine, pheromone_evt);
    }
    else 
    {
        np_unref_obj(np_message_t, pheromone_message, ref_message_in_send_system);
    }
} 

void __np_handle_np_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    // handle ght messages (ping, piggy, ...)
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __np_handle_np_message(...) {");

    __np_handle(statemachine, event);
} 

void __np_handle_np_forward(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   // handle other messages
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __np_handle_np_forward(...) {");

    NP_CAST(event.user_data, np_message_t, message_in);

    CHECK_STR_FIELD(message_in->header, _NP_MSG_HEADER_SUBJECT, msg_subject_elem);
    CHECK_STR_FIELD(message_in->header, _NP_MSG_HEADER_TO, str_msg_to);

    np_dhkey_t subj_dhkey    = msg_subject_elem.value.dhkey;

    np_dhkey_t ack_dhkey     = {0};
    np_generate_subject(&ack_dhkey, _NP_MSG_ACK, strnlen(_NP_MSG_ACK, 256));
    np_dhkey_t forward_dhkey = {0};
    np_generate_subject(&forward_dhkey, _FORWARD, strnlen(_FORWARD, 256));
    
    // np_dhkey_t subj_in_dhkey     = _np_msgproperty_tweaked_dhkey(INBOUND,  subj_dhkey);
    np_dhkey_t forward_out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, forward_dhkey);
    np_dhkey_t ack_out_dhkey     = _np_msgproperty_tweaked_dhkey(OUTBOUND, ack_dhkey);

    log_msg(LOG_INFO, "forwarding message (%s) for subject: %08"PRIx32":%08"PRIx32, message_in->uuid, msg_subject_elem.value.dhkey.t[0], msg_subject_elem.value.dhkey.t[1]);

    np_dhkey_t msg_handler = {0};
    if (_np_dhkey_equal(&ack_dhkey, &subj_dhkey) )
        _np_dhkey_assign(&msg_handler, &ack_out_dhkey);
    else
        _np_dhkey_assign(&msg_handler, &forward_out_dhkey);

    np_util_event_t forward_event = event;
    forward_event.type = (evt_internal | evt_message);
    _np_keycache_handle_event(context, msg_handler, forward_event, false);

    _np_increment_forwarding_counter(msg_subject_elem.value.dhkey);

    __np_cleanup__: {}
}

void __np_handle_usr_msg(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __np_handle_usr_msg(...) {");

    NP_CAST(event.user_data, np_message_t, usr_message); 

    CHECK_STR_FIELD(usr_message->header, _NP_MSG_HEADER_FROM, msg_from);

    np_util_event_t usr_event = event;
    _np_dhkey_assign(&usr_event.target_dhkey, &msg_from.value.dhkey);

    __np_handle(statemachine, usr_event);

    __np_cleanup__: {}
}

bool __is_alias_invalid(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_alias_invalid(...) {");

    bool ret = false;

    NP_CAST(statemachine->_user_data, np_key_t, alias_key); 

    log_debug_msg(LOG_INFO, "__is_alias_invalid(...) { [0]:%p [1]:%p [2]:%p [3]:%p }", 
                  alias_key->entity_array[0], alias_key->entity_array[1], alias_key->entity_array[2], alias_key->entity_array[3]);

    if (!ret) ret = FLAG_CMP(alias_key->type, np_key_type_unknown);

    if (!ret && 
        (alias_key->created_at + BAD_LINK_REMOVE_GRACETIME) > np_time_now() ) 
        return false;

    // check for activity on the alias key. the last_update field receives updates whenever an event has been handled, except for noop events.
    // alias keys only receive events when there is activity on the network layer. no in activity -> no alias needed -> shutdown input channel
    if (!ret && 
        (alias_key->last_update + BAD_LINK_REMOVE_GRACETIME) < np_time_now() )
        return true;

    np_node_t* alias_node = _np_key_get_node(alias_key);
    if (!ret) // check for not in routing / leafset table anymore
    {    
        ret = (!alias_node->is_in_leafset) && (!alias_node->is_in_routing_table);
        log_debug_msg(LOG_INFO, "end  : bool __is_alias_invalid(...) { %d (%d / %d / %f < %f)", 
                        ret, alias_node->is_in_leafset, alias_node->is_in_routing_table, (alias_key->created_at + BAD_LINK_REMOVE_GRACETIME), np_time_now());
    }

    if (!ret) // bad node connectivity
    {
        ret  = (alias_node->success_avg < BAD_LINK);
        log_debug_msg(LOG_INFO, "end  : bool __is_alias_invalid(...) { %d (%d / %d / %f < %f)", 
                        ret, alias_node->is_in_leafset, alias_node->is_in_routing_table, (alias_key->created_at + BAD_LINK_REMOVE_GRACETIME), np_time_now());
    }

    if (!ret) // token expired
    {
        np_aaatoken_t* alias_token = _np_key_get_token(alias_key);
        ret = (alias_token == NULL);
        if (!ret) {
            ret  = !_np_aaatoken_is_valid(alias_token, alias_token->type);
        }
        log_debug_msg(LOG_INFO, "end %p: bool __is_alias_invalid(...) { %d (%d / %d / %f < %f)", 
                        alias_token, ret, alias_node->is_in_leafset, alias_node->is_in_routing_table, (alias_key->created_at + BAD_LINK_REMOVE_GRACETIME), np_time_now());
    }

    return ret;    
}

void __np_alias_shutdown(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_alias_shutdown(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);

    alias_key->parent_key = NULL;
    alias_key->type = np_key_type_unknown;
}

void __np_alias_destroy(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_INFO, "start: bool __np_alias_destroy(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);

    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(alias_key, &trinity);

    if (trinity.token) np_unref_obj(np_aaatoken_t, trinity.token, "__np_alias_set");
    if (trinity.node)  np_unref_obj(np_node_t, trinity.node, "__np_alias_set");
    if (trinity.network) 
    {
        _np_network_disable(trinity.network);
        np_unref_obj(np_network_t, trinity.network, "__np_alias_set");
    }
    if (alias_key->entity_array[0]) np_unref_obj(np_aaatoken_t, alias_key->entity_array[0], "__np_alias_set");

    // memset(alias_key->entity_array, 0, 8*sizeof(void_ptr));

    alias_key->type = np_key_type_unknown;
    np_unref_obj(np_key_t, alias_key, "__np_alias_set");
    // ref_replace_reason(np_key_t, alias_key, "__np_alias_set", "_np_keycache_finalize" );
}

void __np_alias_update(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __np_alias_update(...) {");

    _np_alias_cleanup_msgpart_cache(context);

    if (event.user_data != NULL) {
        log_msg(LOG_WARN, "unexpected datatype %u attached to event", np_memory_get_type(event.user_data));        
    }
}
