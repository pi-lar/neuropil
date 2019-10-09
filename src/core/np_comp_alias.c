//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
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
#include "np_key.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_route.h"
#include "np_statistics.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"
#include "np_tree.h"

np_message_t* _np_alias_check_msgpart_cache(np_state_t* context, np_message_t* msg_to_check)
{
    log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: np_message_t* _np_message_check_chunks_complete(np_message_t* msg_to_check){");

    np_message_t* ret= NULL;

#ifdef DEBUG
    char* subject = np_treeval_to_str(np_tree_find_str(msg_to_check->header, _NP_MSG_HEADER_SUBJECT)->val, NULL);
#endif
    // Detect from instructions if this msg was orginally chunked
    char* msg_uuid = np_treeval_to_str(np_tree_find_str(msg_to_check->instructions, _NP_MSG_INST_UUID)->val, NULL);
    uint16_t expected_msg_chunks = np_tree_find_str(msg_to_check->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[0];

    if (1 < expected_msg_chunks)
    {
        _LOCK_MODULE(np_message_part_cache_t)
        {
            // If there exists multiple chunks, check if we already have one in cache
            np_tree_elem_t* tmp = np_tree_find_str(context->msg_part_cache, msg_uuid);
            if (NULL != tmp)
            {
                // there exists a msg(part) in our msgcache for this msg uuid
                // lets add our msgpart to this msg
                np_message_t* msg_in_cache = msg_in_cache = tmp->val.value.v;

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
                    np_unref_obj(np_message_t, msg_to_check, ref_obj_creation);
                    // now we check if all chunks are complete for this msg
                    current_count_of_chunks = pll_size(msg_in_cache->msg_chunks);
                }

                if (current_count_of_chunks < expected_msg_chunks)
                {
                    log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
                        "message %s (%s) not complete yet (%d of %d), waiting for missing parts",
                        subject, msg_uuid, current_count_of_chunks, expected_msg_chunks);
                    // nothing to return as we still wait for chunks
                }
                else
                {
                    ret = msg_in_cache;
                    // removing the message from the cache system
                    msg_uuid = np_treeval_to_str(np_tree_find_str(msg_in_cache->instructions, _NP_MSG_INST_UUID)->val, NULL);
                    np_tree_del_str(context->msg_part_cache, msg_uuid);
                    np_unref_obj(np_message_t, msg_in_cache, ref_msgpartcache);

                    log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
                        "message %s (%s) is complete now  (%d of %d)",
                        subject, msg_uuid, current_count_of_chunks, expected_msg_chunks);
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
            }
        }
    }
    else
    {
        // If this is the only chunk, then return it as is
        log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
                "message %s (%s) is unchunked  ", subject, msg_uuid);
        ret = msg_to_check;
    }
    return ret;
}

// TODO: move to glia
void _np_alias_cleanup_msgpart_cache(np_state_t* context)
{
    np_sll_t(np_message_ptr, to_del);
    sll_init(np_message_ptr, to_del);
    
    _LOCK_MODULE(np_message_part_cache_t)
    {
        if (context->msg_part_cache->size > 0) {
            log_debug_msg(LOG_INFO, "MSG_PART_TABLE removing (left-over) message parts (size: %d)", context->msg_part_cache->size);

            np_tree_elem_t* tmp = NULL;
            RB_FOREACH(tmp, np_tree_s, context->msg_part_cache)
            {
                np_message_t* msg = tmp->val.value.v;
                if (true == _np_message_is_expired(msg)) {
                    sll_append(np_message_ptr, to_del, msg);
                }
            }
        }
    }

    sll_iterator(np_message_ptr) iter = sll_first(to_del);
    while (NULL != iter)
    {
        log_debug_msg(LOG_INFO, "MSG_PART_TABLE removing (left-over) message part for uuid: %s", iter->val->uuid);
        _LOCK_MODULE(np_message_part_cache_t)
        {
            np_tree_del_str(context->msg_part_cache, iter->val->uuid);
        }
        np_unref_obj(np_message_t, iter->val, ref_msgpartcache);
        sll_next(iter);
    }
    sll_free(np_message_ptr, to_del);  
}

bool __is_alias_handshake_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_alias_handshake_token(...) {");
    
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
    log_debug_msg(LOG_TRACE, "start: void __np_alias_set(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);
    NP_CAST(event.user_data, np_aaatoken_t, handshake_token);

    alias_key->type |= np_key_type_alias;
    // ref_replace_reason(np_key_t, alias_key, ref_obj_creation, "__np_alias_set");
    np_ref_obj(np_key_t, alias_key, "__np_alias_set");

    // fix TCP setup and set correct key
    np_network_t* alias_network = _np_key_get_network(alias_key);
    if (alias_network != NULL) {
        _np_network_stop(alias_network, true);
        ref_replace_reason(np_network_t, alias_network, ref_obj_creation, "__np_alias_set");
        _np_network_set_key(alias_network, alias_key);
        _np_network_start(alias_network, true);
    }

    sll_append(void_ptr, alias_key->entities, handshake_token);

    np_dhkey_t search_key = {0};
    _np_str_dhkey(handshake_token->issuer, &search_key);

    np_node_t* alias_node = NULL;
    np_key_t* node_key = _np_keycache_find(context, search_key);
    if (node_key == NULL) 
    {
        alias_node = _np_node_from_token(handshake_token, handshake_token->type);
        // ref_replace_reason(np_key_t, alias_key, "_np_node_from_token", "__np_alias_set");
        alias_node->_handshake_status++;
    }
    else
    {
        alias_node = _np_key_get_node(node_key);
        log_debug_msg(LOG_DEBUG, "start: void __np_alias_set(...) %p / %p {", node_key, alias_node);
        np_unref_obj(np_key_t, node_key, "_np_keycache_find");
    }

    sll_append(void_ptr, alias_key->entities, alias_node);
    np_ref_obj(np_node_t, alias_node, "__np_alias_set");

    handshake_token->state = AAA_VALID;
}

void __np_create_session(np_util_statemachine_t* statemachine, const np_util_event_t event)
{   // create crypto session and "steal" node sructure
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_create_session(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);

    np_aaatoken_t* handshake_token = _np_key_get_token(alias_key);
    np_node_t*     alias_node      = _np_key_get_node(alias_key);
    
    np_aaatoken_t* my_token = _np_key_get_token(context->my_node_key);
    np_node_t* my_node = _np_key_get_node(context->my_node_key);

    // MUST be there
    np_tree_elem_t* remote_hs_prio = np_tree_find_str(handshake_token->extensions, NP_HS_PRIO);
    // COULD be there
    // np_tree_elem_t* response_uuid = np_tree_find_str(handshake_token->extensions, _NP_MSG_INST_RESPONSE_UUID);
    
    if (/* response_uuid == NULL ||*/
        remote_hs_prio->val.value.ul < my_node->handshake_priority)
    {
        log_debug_msg(LOG_DEBUG,
            "handshake session created in server mode. remote-prio: %"PRIu32" local-prio: %"PRIu32" ",
                remote_hs_prio->val.value.ul, my_node->handshake_priority
            );
        np_crypto_session(context,
                &my_token->crypto,
                &alias_node->session,
                &handshake_token->crypto,
                false
            );
    }
    else 
    {
        log_debug_msg(LOG_DEBUG,
            "handshake session created in client mode. remote-prio: %"PRIu32" local-prio: %"PRIu32" ",
                remote_hs_prio->val.value.ul, my_node->handshake_priority
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
    log_debug_msg(LOG_TRACE, "start: bool __is_crypted_message(...) {");

    bool ret = false;

    if (!ret) ret  = FLAG_CMP(event.type, evt_message);
    if ( ret) ret &= (FLAG_CMP(event.type, evt_external) );
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_BLOB_1024);
    // if ( ret) ret &= 
    // TODO: check crypto signature of incomming message
    // TODO: check increasing counter of partner node
    
    return ret;
}

void __np_alias_decrypt(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{ // decrypt transport encryption
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __np_alias_decrypt(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);

    bool ret = false;
    log_debug_msg(LOG_DEBUG, "/start decrypting message with alias %s", _np_key_as_str(alias_key));

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char dec_msg[MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES];

    memcpy(nonce, event.user_data, crypto_secretbox_NONCEBYTES);                

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
        ret = true;
        log_debug_msg(LOG_DEBUG, "correct decryption of message send from %s", _np_key_as_str(alias_key));
        
        memset(event.user_data, 0, MSG_CHUNK_SIZE_1024);
        memcpy(event.user_data, dec_msg, MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);

        np_message_t* msg_in = NULL;
        np_new_obj(np_message_t, msg_in, ref_obj_creation);
        if (!_np_message_deserialize_header_and_instructions(msg_in, event.user_data) )
        {
            np_memory_free(context, event.user_data);
            // np_unref_obj(msg_in, msg_in, ref_obj_creation);
            return;
        }

        np_util_event_t in_message_evt = { .type=(evt_external|evt_message), .context=context, 
                                           .user_data=msg_in, .target_dhkey=alias_key->dhkey};
        _np_keycache_handle_event(context, alias_key->dhkey, in_message_evt, false);
        // _np_keycache_handle_event(context, alias_key->dhkey, in_message_evt, false);

    } else {
        np_memory_free(context, event.user_data);
        char tmp[255];

        log_msg(LOG_WARN,
            "error on decryption of message (source: %s:%s)", _np_key_get_node(alias_key)->dns_name, _np_key_get_node(alias_key)->port);
    }
    alias_key->last_update = np_time_now();
} 

bool __is_join_in_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_join_in_message(...) {");

    bool ret = false;

    if (!ret) ret  = (FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external) );
    if ( ret) ret &= (event.user_data != NULL);

    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);
    if ( ret) {
        NP_CAST(event.user_data, np_message_t, join_message);
        /* TODO: make it working and better! */
        CHECK_STR_FIELD_BOOL(join_message->header, _NP_MSG_HEADER_SUBJECT, str_msg_subject, "NO SUBJECT IN MESSAGE") {
            ret &= ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_JOIN_REQUEST,  strlen(_NP_MSG_JOIN_REQUEST))  ) ||
                   ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_LEAVE_REQUEST, strlen(_NP_MSG_LEAVE_REQUEST)) );
            return ret;
        }
        ret = false;
    }
    return ret;
}

bool __is_forward_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_forward_message(...) {");

    bool ret = false;

    if (!ret) ret  = FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
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
    log_debug_msg(LOG_TRACE, "start: bool __is_discovery_message(...) {");

    bool ret = __is_forward_message(statemachine, event);
    if  (ret) {
        NP_CAST(event.user_data, np_message_t, discovery_message);
        /* TODO: use the bloom, luke */
        CHECK_STR_FIELD_BOOL(discovery_message->header, _NP_MSG_HEADER_SUBJECT, str_msg_subject, "NO SUBJECT IN MESSAGE")
        {
            // use the bloom to exclude other message types
            ret &= ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_DISCOVER_RECEIVER,  strlen(_NP_MSG_DISCOVER_RECEIVER))  ) ||
                   ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_DISCOVER_SENDER,    strlen(_NP_MSG_DISCOVER_SENDER))    );
        }
    
        CHECK_STR_FIELD_BOOL(discovery_message->header, _NP_MSG_HEADER_TO, str_msg_to, "NO TO IN MESSAGE") 
        {
            // perform a route lookup
            np_sll_t(np_key_ptr, tmp) = NULL;    
            // zero as "consider this node as final target"
            tmp = _np_route_lookup(context, str_msg_to->val.value.dhkey, 0);
            if (0 < sll_size(tmp)) {
                log_debug_msg(LOG_DEBUG,
                    "msg (%s) route_lookup result 1 = %s",
                    discovery_message->uuid, _np_key_as_str(sll_first(tmp)->val)
                );
            }
            /* forward the message if
                b) we do have a list of possible forwards
                c) we are not the best possible forward
            */
            if (NULL != tmp && sll_size(tmp) > 0 )
            {
                ret &= _np_dhkey_equal(&sll_first(tmp)->val->dhkey, &context->my_node_key->dhkey);
            }

            np_key_unref_list(tmp, "_np_route_lookup");
            sll_free(np_key_ptr, tmp);
        }
    }
    return ret;
}

bool __is_dht_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_dht_message(...) {");

    bool ret = false;

    if (!ret) ret  = FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= (event.user_data != NULL);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);

    if ( ret) {
        NP_CAST(event.user_data, np_message_t, dht_message);
        /* TODO: use the bloom, luke */
        CHECK_STR_FIELD_BOOL(dht_message->header, _NP_MSG_HEADER_SUBJECT, str_msg_subject, "NO SUBJECT IN MESSAGE")
        {
            ret &= ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_ACK,                strlen(_NP_MSG_ACK))                ) ||
                   ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_PING_REQUEST,       strlen(_NP_MSG_PING_REQUEST))       ) ||
                   ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_PIGGY_REQUEST,      strlen(_NP_MSG_PIGGY_REQUEST))      ) ||
                   ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_UPDATE_REQUEST,     strlen(_NP_MSG_UPDATE_REQUEST))     ) ||
                   ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_LEAVE_REQUEST,      strlen(_NP_MSG_LEAVE_REQUEST))      ) ||
                   ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_AVAILABLE_RECEIVER, strlen(_NP_MSG_AVAILABLE_RECEIVER)) ) ||
                   ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_AVAILABLE_SENDER,   strlen(_NP_MSG_AVAILABLE_SENDER))   );
        }

        CHECK_STR_FIELD_BOOL(dht_message->header, _NP_MSG_HEADER_TO, str_msg_to, "NO TO IN MESSAGE") 
        {
            // messagepart is not addressed to our node --> forward
            ret &= _np_dhkey_equal(&context->my_node_key->dhkey, &str_msg_to->val.value.dhkey);
        }
    }
    return ret;
}

bool __is_usr_in_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_usr_in_message(...) {");

    bool ret = false;

    if (!ret) ret  = FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= (event.user_data != NULL);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);

    if ( ret) {
        NP_CAST(event.user_data, np_message_t, usr_message);
        /* TODO: use the bloom, luke */
        CHECK_STR_FIELD_BOOL(usr_message->header, _NP_MSG_HEADER_SUBJECT, str_msg_subject, "NO SUBJECT IN MESSAGE")
        {
            np_dhkey_t subject_dhkey = _np_msgproperty_dhkey(INBOUND, str_msg_subject->val.value.s);
            np_key_t* subject_key = _np_keycache_find(context, subject_dhkey);

            ret &= (NULL != subject_key);

            np_unref_obj(np_key_t, subject_key, "_np_keycache_find");
        }

        CHECK_STR_FIELD_BOOL(usr_message->header, _NP_MSG_HEADER_TO, str_msg_to, "NO TO IN MESSAGE") 
        {
            ret &= _np_dhkey_equal(&context->my_node_key->dhkey, &str_msg_to->val.value.dhkey);
        }

        np_msgproperty_t* user_prop = _np_msgproperty_get(context, INBOUND, str_msg_subject->val.value.s);
        ret &= (false == user_prop->is_internal);
    }
    return ret;
}

void __np_handle_np_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   // handle ght messages (ping, piggy, ...)
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __np_handle_np_message(...) {");

    NP_CAST(event.user_data, np_message_t, message);

    // TODO: messag part cache should be a component on its own, but for now just use it
    np_message_t* msg_to_use = _np_alias_check_msgpart_cache(context, message);

    if (msg_to_use != NULL && _np_message_deserialize_chunked(msg_to_use) )
    {
        CHECK_STR_FIELD_BOOL(msg_to_use->header, _NP_MSG_HEADER_SUBJECT, str_msg_subject, "NO SUBJECT IN MESSAGE") 
        {
            np_dhkey_t subject_dhkey = _np_msgproperty_dhkey(INBOUND, str_msg_subject->val.value.s);
            np_util_event_t msg_event = event;
            msg_event.user_data = msg_to_use;
            log_msg(LOG_INFO, "handling   message (%s) for subject: %s", msg_to_use->uuid, str_msg_subject->val.value.s);
            _np_keycache_handle_event(context, subject_dhkey, msg_event, false);
        }
    } 
} 

void __np_handle_np_forward(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{   // handle other messages
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __np_handle_np_forward(...) {");

    NP_CAST(event.user_data, np_message_t, message_in);

    CHECK_STR_FIELD(message_in->header, _NP_MSG_HEADER_SUBJECT, str_msg_subject);
    CHECK_STR_FIELD(message_in->header, _NP_MSG_HEADER_TO, str_msg_to);

    log_msg(LOG_INFO, "forwarding message (%s) for subject: %s", message_in->uuid, str_msg_subject.value.s);

    np_dhkey_t msg_handler = _np_msgproperty_dhkey(OUTBOUND, _FORWARD);

    np_util_event_t forward_event = event;
    forward_event.target_dhkey = str_msg_to.value.dhkey;
    forward_event.type = (evt_internal | evt_message);
    _np_keycache_handle_event(context, msg_handler, forward_event, false);

    _np_increment_forwarding_counter(str_msg_subject.value.s);

    __np_cleanup__: {}
} 

bool __is_usr_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_usr_message(...) {");

    bool ret = false;

    if (!ret) ret  = FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_userspace);
    if ( ret) ret &= (event.user_data != NULL);

    return ret;
}

void __np_handle_usr_msg(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __np_handle_usr_msg(...) {");

    NP_CAST(event.user_data, np_message_t, message);

    // TODO: messag part cache should be a component on its own, but for now just use it
    np_message_t* msg_to_use = _np_alias_check_msgpart_cache(context, message);

    if (msg_to_use != NULL) 
    {
        if (_np_message_deserialize_chunked(msg_to_use) ) 
        {
            CHECK_STR_FIELD_BOOL(msg_to_use->header, _NP_MSG_HEADER_SUBJECT, str_msg_subject, "NO SUBJECT IN MESSAGE") 
            {
                np_dhkey_t subject_dhkey = _np_msgproperty_dhkey(INBOUND, str_msg_subject->val.value.s);
                np_util_event_t msg_event = event;
                msg_event.user_data = msg_to_use;
                log_msg(LOG_INFO, "handling   message (%s) for subject: %s", msg_to_use->uuid, str_msg_subject->val.value.s);
                _np_keycache_handle_event(context, subject_dhkey, msg_event, false);
            }
        }
    }
} 

bool __is_alias_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_alias_invalid(...) {");

    bool ret = false;

    NP_CAST(statemachine->_user_data, np_key_t, alias_key); 

    if (!ret) ret = ( (alias_key->last_update + MISC_SEND_PINGS_MAX_EVERY_X_SEC) < np_time_now() );

    np_dhkey_t search_key = {0};
    _np_str_dhkey(_np_key_get_token(alias_key)->issuer, &search_key);
    np_key_t* node_key = _np_keycache_find(context, search_key);

    if      (ret && node_key == NULL) { ret = true; }
    else if (ret && node_key != NULL) {
        ret = false; 
    }
    np_unref_obj(np_key_t, node_key, "_np_keycache_find");
    return ret;    
}

void __np_alias_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __np_alias_destroy(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);

    sll_iterator(void_ptr) iter = sll_first(alias_key->entities);
    while (iter != NULL) 
    {
        if (_np_memory_rtti_check(iter->val, np_memory_types_np_node_t))     np_unref_obj(np_node_t,     iter->val, "__np_alias_set");
        // if (_np_memory_rtti_check(iter->val, np_memory_types_np_aaatoken_t)) np_unref_obj(np_aaatoken_t, iter->val, "__np_alias_set");
        if (_np_memory_rtti_check(iter->val, np_memory_types_np_network_t))  {
            _np_network_stop(iter->val, true);
            np_unref_obj(np_network_t,  iter->val, "__np_alias_set");
        }
        sll_next(iter);
    }

    sll_clear(void_ptr, alias_key->entities);

    alias_key->type = np_key_type_unknown;
    ref_replace_reason(np_key_t, alias_key, "__np_alias_set", "_np_keycache_finalize" );
}

void __np_alias_update(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __np_alias_update(...) {");

    NP_CAST(event.user_data, np_message_t, message);

    _np_alias_cleanup_msgpart_cache(context);
}
