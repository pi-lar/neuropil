//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/select.h>

#include "np_axon.h"

#include "msgpack/cmp.h"
#include "event/ev.h"
#include "sodium.h"

#include "core/np_comp_intent.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"

#include "np_aaatoken.h"
#include "np_bloom.h" 
#include "np_constants.h"
#include "np_dhkey.h"
#include "np_event.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_list.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_node.h"
#include "np_pheromones.h"
#include "np_responsecontainer.h"
#include "np_route.h"
#include "np_serialization.h"
#include "np_settings.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_token_factory.h"
#include "np_tree.h"
#include "np_types.h"
#include "np_util.h"


/** message split up maths
 ** message size = 1b (common header) + 40b (encryption) +
 **                msg (header + instructions) + msg (properties + body) + msg (footer)
 ** if (size > MSG_CHUNK_SIZE_1024)
 **     fixed_size = 1b + 40b + msg (header + instructions)
 **     payload_size = msg (properties) + msg(body) + msg(footer)
 **     #_of_chunks = int(payload_size / (MSG_CHUNK_SIZE_1024 - fixed_size)) + 1
 **     chunk_size = payload_size / #_of_chunks
 **     garbage_size = #_of_chunks * (fixed_size + chunk_size) % MSG_CHUNK_SIZE_1024 // spezial behandlung garbage_size < 3
 **     add garbage
 ** else
 ** 	add garbage
 **/


bool _np_out_callback_wrapper(np_state_t* context, const np_util_event_t event) 
{
    log_trace_msg(LOG_TRACE, "start: void __np_out_callback_wrapper(...){");

    NP_CAST(event.user_data, np_message_t, message);
    
    np_dhkey_t prop_dhkey = _np_msgproperty_dhkey(OUTBOUND, _np_message_get_subject(message) );
    np_key_t*  prop_key   = _np_keycache_find(context, prop_dhkey);
    NP_CAST(sll_first(prop_key->entities)->val, np_msgproperty_t, my_property);

    bool ret = false;

    np_message_intent_public_token_t* tmp_token = _np_intent_get_receiver(prop_key, event.target_dhkey);

    // TODO: refactor breach check as single callback
    if (_np_msgproperty_threshold_breached(my_property) || NULL == tmp_token )
    {
        _np_msgproperty_add_msg_to_send_cache(my_property, message);
        if (tmp_token == NULL)
        {
            log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "(msg: %s) for subject \"%s\" has NO valid token / %p", message->uuid, my_property->msg_subject, my_property);
        }
        else
        {
            log_msg(LOG_INFO, "(msg: %s) for subject \"%s\" treshold breached!", message->uuid, my_property->msg_subject);
            np_unref_obj(np_aaatoken_t, tmp_token,"_np_intent_get_receiver");
        }
        ret = false;
    }
    else 
    {
        log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "(msg: %s) for subject \"%s\" has valid token", message->uuid, my_property->msg_subject);

        np_dhkey_t receiver_dhkey = np_aaatoken_get_partner_fp(tmp_token);

        if (_np_dhkey_equal(&context->my_node_key->dhkey, &receiver_dhkey))
        {
            np_dhkey_t in_handler = _np_msgproperty_dhkey(INBOUND, my_property->msg_subject);
            np_util_event_t msg_in_event = { .type=(evt_external|evt_message), .context=context, .target_dhkey=receiver_dhkey, .user_data=message };
            _np_keycache_handle_event(context, in_handler, msg_in_event, false);
        }
        else
        {
            uint16_t recv_threshold = np_tree_find_str(tmp_token->extensions_local, "max_threshold")->val.value.ui;
            if (recv_threshold < my_property->max_threshold) {
                log_debug_msg(LOG_WARN, "reduce max threshold for subject (%s/%u) because receiver %s has lower, otherwise MESSAGE LOSS IS GUARANTEED!", my_property->msg_subject, recv_threshold, tmp_token->issuer);
            }

            log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "encrypting message (%s/%s) with receiver token %s %s...", my_property->msg_subject, message->uuid, tmp_token->uuid, tmp_token->issuer);
            // encrypt the relevant message part itself
            np_tree_replace_str(message->header, _NP_MSG_HEADER_TO, np_treeval_new_dhkey(receiver_dhkey));

            _np_message_encrypt_payload(message, tmp_token);

            if (FLAG_CMP(my_property->ack_mode, ACK_DESTINATION))
            {
                np_dhkey_t redeliver_dhkey = _np_msgproperty_dhkey(OUTBOUND, my_property->msg_subject);
                np_util_event_t redeliver_event = { .type=(evt_redeliver|evt_internal|evt_message), .context=context, .target_dhkey=redeliver_dhkey, .user_data=message };
                _np_keycache_handle_event(context, redeliver_dhkey, redeliver_event, false);
                _np_message_add_msg_response_handler(message);
            }
        }
        // decrease threshold counters
        np_unref_obj(np_aaatoken_t, tmp_token, "_np_intent_get_receiver");
        ret = true;
    }
    np_unref_obj(np_key_t, prop_key, "_np_keycache_find");

    return ret;
}

bool _np_out_forward(np_state_t* context, np_util_event_t event)
{
    log_debug_msg(LOG_DEBUG, "start: bool _np_out_forward(...){");

    NP_CAST(event.user_data, np_message_t, forward_msg);

    CHECK_STR_FIELD(forward_msg->header, _NP_MSG_HEADER_FROM, msg_from);
    CHECK_STR_FIELD(forward_msg->header, _NP_MSG_HEADER_TO, msg_to);
    CHECK_STR_FIELD(forward_msg->header, _NP_MSG_HEADER_SUBJECT, msg_subj);

    if (!_np_route_my_key_has_connection(context))
    {
        log_msg(LOG_INFO, "--- request for forward message out, but no connections left ...");
        return false;
    }

    float target_age = 1.0;
    np_sll_t(np_dhkey_t, tmp) = NULL;
    sll_init(np_dhkey_t, tmp);

    char* ref_reason = "_np_pheromone_snuffle";
    np_dhkey_t recv_dhkey = _np_msgproperty_dhkey(INBOUND,  msg_subj.value.s);
    uint8_t i = 0;
    while (sll_size(tmp) == 0 && i < 8)
    {
        _np_pheromone_snuffle_receiver(context, tmp, recv_dhkey, &target_age);
        i++;
        target_age -= 0.1;
    };
    
    if (sll_size(tmp) == 0) 
    {   // find next hop based on fingerprint of the message
        CHECK_STR_FIELD(forward_msg->header, _NP_MSG_HEADER_TO, msg_to_ele);    
        np_sll_t(np_key_ptr, route_tmp) = NULL;
        uint8_t i = 1;
        do {
            route_tmp = _np_route_lookup(context, msg_to_ele.value.dhkey, i);
            i++;
        } while (sll_size(route_tmp) == 0 && i < 5);

        sll_iterator(np_key_ptr) iter = sll_first(route_tmp);
        while (NULL != iter) {
            sll_append(np_dhkey_t, tmp, iter->val->dhkey);
            sll_next(iter);
        }
        np_key_unref_list(route_tmp, "_np_route_lookup");
        sll_free(np_key_ptr, route_tmp);
    } else {
        // routing based on pheromones, exhale ...
        _np_pheromone_exhale(context);
    }

    if (sll_size(tmp) == 0)
    {
        log_msg(LOG_WARN, "--- request for default message out, but no routing found ...");
        sll_free(np_dhkey_t, tmp);
        return false;
    }

    // 2: chunk the message if required
    // TODO: send two separate messages?
    if (forward_msg->is_single_part == false) {
        _np_message_calculate_chunking(forward_msg);
        _np_message_serialize_chunked(forward_msg);
    }
    
    // 3: send over the message parts
    log_msg(LOG_INFO, "sending    message (%s) to next %d hops", forward_msg->uuid, sll_size(tmp));
    pll_iterator(np_messagepart_ptr) part_iter = pll_first(forward_msg->msg_chunks);
    while (NULL != part_iter) 
    {
        sll_iterator(np_dhkey_t) key_iter = sll_first(tmp);
        while (key_iter != NULL) 
        {
            if (!_np_dhkey_equal(&key_iter->val, &msg_from.value.dhkey) &&
                !_np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey))
            {
                memcpy(part_iter->val->uuid, forward_msg->uuid, NP_UUID_BYTES);

                np_util_event_t send_event = { .type=(evt_internal|evt_message), .context=context, .user_data=part_iter->val, .target_dhkey=msg_to.value.dhkey};
                _np_keycache_handle_event(context, key_iter->val, send_event, false);
            }
            sll_next(key_iter);
        }
        pll_next(part_iter);
    }

    // 4 cleanup
    sll_free(np_dhkey_t, tmp);

    __np_cleanup__: {}

    return true;
}

bool _np_out_default(np_state_t* context, np_util_event_t event)
{
    log_debug_msg(LOG_DEBUG, "start: bool _np_out_default(...){");

    NP_CAST(event.user_data, np_message_t, default_msg);

    CHECK_STR_FIELD(default_msg->header, _NP_MSG_HEADER_FROM, msg_from);
    CHECK_STR_FIELD(default_msg->header, _NP_MSG_HEADER_TO, msg_to);
    CHECK_STR_FIELD(default_msg->header, _NP_MSG_HEADER_SUBJECT, msg_subj);

    if (!_np_route_my_key_has_connection(context))
    {
        log_msg(LOG_INFO, "--- request for forward message out, but no connections left ...");
        return false;
    }

    float target_age = 1.0;
    np_sll_t(np_dhkey_t, tmp) = NULL;
    sll_init(np_dhkey_t, tmp);

    np_dhkey_t recv_dhkey = _np_msgproperty_dhkey(INBOUND,  msg_subj.value.s);
    uint8_t i = 0;
    while (sll_size(tmp) == 0 && i < 8)
    {
        _np_pheromone_snuffle_receiver(context, tmp, recv_dhkey, &target_age);
        i++;
        target_age -= 0.1;
    };
    
    if (sll_size(tmp) == 0)
    {
        log_msg(LOG_WARN, "--- request for default message out, but no routing found ...");
        sll_free(np_dhkey_t, tmp);
        return false;
    }

    // 2: chunk the message if required
    // TODO: send two separate messages?
    _np_message_calculate_chunking(default_msg);
    _np_message_serialize_chunked(default_msg);
    
    // 3: send over the message parts
    log_msg(LOG_INFO, "sending    message (%s) to next %d hops", default_msg->uuid, sll_size(tmp));
    pll_iterator(np_messagepart_ptr) part_iter = pll_first(default_msg->msg_chunks);
    while (NULL != part_iter) 
    {
        sll_iterator(np_dhkey_t) key_iter = sll_first(tmp);
        while (key_iter != NULL) 
        {
            if (!_np_dhkey_equal(&key_iter->val, &msg_from.value.dhkey) &&
                !_np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey))
            {
                memcpy(part_iter->val->uuid, default_msg->uuid, NP_UUID_BYTES);

                np_util_event_t send_event = { .type=(evt_internal|evt_message), .context=context, .user_data=part_iter->val, .target_dhkey=msg_to.value.dhkey};
                _np_keycache_handle_event(context, key_iter->val, send_event, false);
            }
            sll_next(key_iter);
        }
        pll_next(part_iter);
    }

    // 4 cleanup
    sll_free(np_dhkey_t, tmp);

    __np_cleanup__: {}

    _np_pheromone_exhale(context);

    return true;
}

bool _np_out_available_messages(np_state_t* context, np_util_event_t event)
{    
    log_debug_msg(LOG_DEBUG, "start: bool _np_out_available_messages(...){");

    NP_CAST(event.user_data, np_message_t, available_msg);

    CHECK_STR_FIELD(available_msg->header, _NP_MSG_HEADER_TO, msg_to);
    CHECK_STR_FIELD(available_msg->header, _NP_MSG_HEADER_FROM, msg_from);
    CHECK_STR_FIELD(available_msg->header, _NP_MSG_HEADER_SUBJECT, msg_subj);

    log_debug_msg(LOG_DEBUG, "handling available request {%s}", available_msg->uuid );

    if (!_np_route_my_key_has_connection(context))
    {
        log_msg(LOG_WARN, "--- request for available message out, but no connections left ...");
        return false;
    }

    float target_age = 1.0;
    np_sll_t(np_dhkey_t, tmp) = NULL;
    sll_init(np_dhkey_t, tmp);

    bool find_receiver = (0 == strncmp(_NP_MSG_AVAILABLE_SENDER,   msg_subj.value.s, strlen(_NP_MSG_AVAILABLE_SENDER  )) );
    bool find_sender   = (0 == strncmp(_NP_MSG_AVAILABLE_RECEIVER, msg_subj.value.s, strlen(_NP_MSG_AVAILABLE_RECEIVER)) );

    uint8_t i = 0;
    while (sll_size(tmp) == 0 && i < 9)
    {
        if (find_receiver) 
            _np_pheromone_snuffle_receiver(context, tmp, msg_to.value.dhkey, &target_age);
        else 
        if (find_sender) 
            _np_pheromone_snuffle_sender(context, tmp, msg_to.value.dhkey, &target_age);
        log_debug_msg(LOG_DEBUG, "--- request for available message out %s: %f", msg_subj.value.s, target_age);
        i++;
        target_age -= 0.1;
    };
    
    if (sll_size(tmp) == 0) 
    {
        log_msg(LOG_WARN, "--- request for available message (%s) out, but no routing found ...", msg_subj.value.s);
        sll_free(np_dhkey_t, tmp);
        return false;
    }

    if (available_msg->is_single_part == false) {
        // 2: chunk the message if required
        _np_message_calculate_chunking(available_msg);
        _np_message_serialize_chunked(available_msg);
    }

    np_dhkey_t last_hop = event.target_dhkey;

    // 3: send over the message parts
    pll_iterator(np_messagepart_ptr) part_iter = pll_first(available_msg->msg_chunks);
    while (NULL != part_iter) 
    {
        sll_iterator(np_dhkey_t) key_iter = sll_first(tmp);
        while (key_iter != NULL) 
        {
            if (!_np_dhkey_equal(&key_iter->val, &msg_from.value.dhkey)        &&
                !_np_dhkey_equal(&key_iter->val, &last_hop)                    &&
                !_np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey) )
            {
                memcpy(part_iter->val->uuid, available_msg->uuid, NP_UUID_BYTES);
                np_util_event_t send_event = { .type=(evt_internal|evt_message), .context=context, .user_data=part_iter->val, .target_dhkey=msg_to.value.dhkey};
                _np_keycache_handle_event(context, key_iter->val, send_event, false);
            }
            sll_next(key_iter);
        }
        pll_next(part_iter);
    }

    _np_pheromone_exhale(context);

    // 4 cleanup
    __np_cleanup__: {}

    sll_free(np_dhkey_t, tmp);

    return true;
}

bool _np_out_pheromone(np_state_t* context, np_util_event_t msg_event)
{
    log_debug_msg(LOG_DEBUG, "start: bool _np_out_pheromone(...) {");

    if (!_np_route_my_key_has_connection(context))
    {
        log_msg(LOG_WARN, "--- request for pheromone update message out, but no connections left ...");
        return false;
    }

    NP_CAST(msg_event.user_data, np_message_t, pheromone_msg_out);
    CHECK_STR_FIELD(pheromone_msg_out->header, _NP_MSG_HEADER_FROM, msg_from);

    // 1: find next hop based on fingerprint of the token
    np_sll_t(np_key_ptr, tmp) = NULL;
    tmp = _np_route_row_lookup(context, msg_event.target_dhkey);
    char* source_sll_of_keys = "_np_route_row_lookup";
    
    if (sll_size(tmp) < 1)
    {   // nothing found, send leafset to exchange some data at least
        // prevents small clusters from not exchanging all data
        np_key_unref_list(tmp, source_sll_of_keys); // only for completion
        sll_free(np_key_ptr, tmp);
        tmp = _np_route_neighbors(context);
        source_sll_of_keys = "_np_route_neighbors";
    }

    uint8_t send_counter = 0;
    sll_iterator(np_key_ptr) target_iter = sll_first(tmp);
    while(NULL != target_iter && send_counter < NP_ROUTE_LEAFSET_SIZE/2)
    {
        if (_np_dhkey_equal(&target_iter->val->dhkey, &msg_from.value.dhkey) ||
            _np_dhkey_equal(&target_iter->val->dhkey, &context->my_node_key->dhkey) )
        {
            sll_next(target_iter);
            continue;
        }

        np_key_t* target = target_iter->val;
        // np_tree_replace_str(pheromone_msg_out->header, _NP_MSG_HEADER_FROM, np_treeval_new_dhkey(context->my_node_key->dhkey) );        
        // 2: chunk the message if required
        // TODO: send two separate messages?
        _np_message_calculate_chunking(pheromone_msg_out);
        _np_message_serialize_chunked(pheromone_msg_out);

        // 3: send over the message parts
        pll_iterator(np_messagepart_ptr) part_iter = pll_first(pheromone_msg_out->msg_chunks);
        while (NULL != part_iter) 
        {
            memcpy(part_iter->val->uuid, pheromone_msg_out->uuid, NP_UUID_BYTES);
            log_debug_msg(LOG_DEBUG, "submitting pheromone request to next hop %s", _np_key_as_str(target));
            np_util_event_t send_event = { .type=(evt_internal|evt_message), .context=context, .user_data=part_iter->val, .target_dhkey=msg_event.target_dhkey};
            _np_keycache_handle_event(context, target->dhkey, send_event, false);
            pll_next(part_iter);
        }

        if (_np_dhkey_equal(&target_iter->val->dhkey, &msg_event.target_dhkey) )
        {   // if the target key was set to a real node, then do not send to further nodes 
            break;
        }
        else 
        {
            sll_next(target_iter);
            send_counter++;
        }
    }

    _np_pheromone_exhale(context);

    // 4 cleanup
    np_key_unref_list(tmp, source_sll_of_keys);
    sll_free(np_key_ptr, tmp);    

    __np_cleanup__:{}
    
    return true;
}


/**
 ** _np_network_append_msg_to_out_queue: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
bool _np_out_ack(np_state_t* context, np_util_event_t msg_event)
{
    log_trace_msg(LOG_TRACE, "start: bool _np_send_ack(np_state_t* context, np_util_event_t msg_event){");

    NP_CAST(msg_event.user_data, np_message_t, ack_msg);

    CHECK_STR_FIELD(ack_msg->header, _NP_MSG_HEADER_FROM, msg_from); // dhkey of original msg subject
    CHECK_STR_FIELD(ack_msg->header, _NP_MSG_HEADER_TO, msg_to); // dhkey of a node
    CHECK_STR_FIELD(ack_msg->header, _NP_MSG_HEADER_SUBJECT, msg_subj); // "ack" msg subject

    if (!_np_route_my_key_has_connection(context))
    {
        log_msg(LOG_INFO, "--- request for forward message out, but no connections left ...");
        return false;
    }

    float target_age = 1.0;
    np_sll_t(np_dhkey_t, tmp) = NULL;
    sll_init(np_dhkey_t, tmp);

    np_dhkey_t ack_subj_dhkey = msg_from.value.dhkey; // (INBOUND,  msg_subj.value.s);
    np_dhkey_t ack_to_dhkey   = msg_to.value.dhkey;

    // 1a. check if the ack is for a direct neighbour
    np_key_t* target_key = _np_keycache_find(context, ack_to_dhkey);
    if (NULL == target_key)
    {
        // no --> 1b. lookup based on original msg subject, but snuffle for sender
        uint8_t i = 0;
        while (sll_size(tmp) == 0 && i < 8)
        {
            _np_pheromone_snuffle_sender(context, tmp, ack_subj_dhkey, &target_age);
            i++;
            target_age -= 0.1;
        };
        // routing based on pheromones, exhale ...
        _np_pheromone_exhale(context);
    }
    else
    {
        // yes --> 1a. append to result list
        sll_append(np_dhkey_t, tmp, target_key->dhkey);
        np_unref_obj(np_key_t, target_key, "_np_keycache_find");
    }

    if (sll_size(tmp) == 0)
    {   // exit early if no routing has been found
        log_msg(LOG_WARN, "--- request for ack message out, but no routing found ...");
        sll_free(np_dhkey_t, tmp);
        return false;
    }

    // chunking for 1024 bit message size
    _np_message_calculate_chunking(ack_msg);
    _np_message_serialize_chunked(ack_msg);

    // 2: send over the message parts
    pll_iterator(np_messagepart_ptr) part_iter = pll_first(ack_msg->msg_chunks);
    while (NULL != part_iter) 
    {
        sll_iterator(np_dhkey_t) key_iter = sll_first(tmp);
        while (key_iter != NULL) 
        {
            if (!_np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey))
            {
                #ifdef DEBUG
                np_key_t* target_key = _np_keycache_find(context, key_iter->val);
                if (NULL != target_key) {
                    log_debug_msg(LOG_DEBUG, "submitting ack to target key %s / %p", _np_key_as_str(target_key), target_key);
                    np_unref_obj(np_key_t, target_key, "_np_keycache_find");
                }
                #endif // DEBUG
                memcpy(part_iter->val->uuid, ack_msg->uuid, NP_UUID_BYTES);

                np_util_event_t ack_event = { .type=(evt_internal|evt_message), .context=context, .user_data=part_iter->val, .target_dhkey=msg_to.value.dhkey};
                _np_keycache_handle_event(context, key_iter->val, ack_event, false);
            }
            sll_next(key_iter);
        }
        pll_next(part_iter);
    }

    __np_cleanup__: {}

    sll_free(np_dhkey_t, tmp);

    return true;
}

bool _np_out_ping(np_state_t* context, const np_util_event_t event) 
{  
    log_trace_msg(LOG_TRACE, "start: bool _np_out_ping(...) {");

    NP_CAST(event.user_data, np_message_t, ping_msg);
    log_debug_msg(LOG_DEBUG, "_np_out_ping for message uuid %s", ping_msg->uuid);

    // 2: chunk the message if required
    _np_message_calculate_chunking(ping_msg);
    _np_message_serialize_chunked(ping_msg);

    _np_message_add_key_response_handler(ping_msg);

    // 3: send over the message parts
    pll_iterator(np_messagepart_ptr) iter = pll_first(ping_msg->msg_chunks);
    while (NULL != iter) 
    {
        memcpy(iter->val->uuid, ping_msg->uuid, NP_UUID_BYTES);
        np_util_event_t ping_event = { .type=(evt_internal|evt_message), .context=context, .user_data=iter->val, .target_dhkey=event.target_dhkey};
        _np_keycache_handle_event(context, ping_event.target_dhkey, ping_event, false);

        pll_next(iter);
    }

    return true;
}

bool _np_out_piggy(np_state_t* context, const np_util_event_t event) 
{
    log_trace_msg(LOG_TRACE, "start: bool _np_out_piggy(...) {");

    NP_CAST(event.user_data, np_message_t, piggy_msg);
    
    // 2: chunk the message if required
    _np_message_calculate_chunking(piggy_msg);
    _np_message_serialize_chunked(piggy_msg);

    // 3: send over the message parts
    pll_iterator(np_messagepart_ptr) iter = pll_first(piggy_msg->msg_chunks);
    while (NULL != iter) 
    {
#ifdef DEBUG
        np_key_t* target_key = _np_keycache_find(context, event.target_dhkey);
        log_debug_msg(LOG_DEBUG, "submitting piggy to target key %s / %p", _np_key_as_str(target_key), target_key);
        np_unref_obj(np_key_t, target_key, "_np_keycache_find");
#endif // DEBUG
        memcpy(iter->val->uuid, piggy_msg->uuid, NP_UUID_BYTES);
        np_util_event_t piggy_event = { .type=(evt_internal|evt_message), .context=context, .user_data=iter->val, .target_dhkey=event.target_dhkey};
        _np_keycache_handle_event(context, event.target_dhkey, piggy_event, false);

        pll_next(iter);
    }

    return true;
}

bool _np_out_update(np_state_t* context, const np_util_event_t event) 
{
    log_debug_msg(LOG_DEBUG, "start: bool _np_out_update(...) {");

    if (!_np_route_my_key_has_connection(context))
    {
        log_msg(LOG_WARN, "--- request for update message out, but no connections left ...");
        return false;
    }

    NP_CAST(event.user_data, np_message_t, update_msg);

    // 3: find next hop based on fingerprint of the token
    np_sll_t(np_key_ptr, tmp) = NULL;
    uint8_t i = 1;
    do {
        tmp = _np_route_lookup(context, event.target_dhkey, i);
        i++;
    } while (sll_size(tmp) == 0 && i < 5);

    if(tmp == NULL){
        log_msg(LOG_WARN, "--- request for update message out, but no connections left (2) ...");
        return false;
    }
    np_key_t* target = sll_first(tmp)->val;

    if (_np_dhkey_equal(&target->dhkey, &context->my_node_key->dhkey)) {
        log_msg(LOG_WARN, "--- request for update message out, but this is already the nearest node ...");
        np_key_unref_list(tmp, "_np_route_lookup");
        sll_free(np_key_ptr, tmp);
        return false;
    }

    _np_message_set_to(update_msg, target->dhkey);

    // 4: chunk the message if required
    // TODO: send two separate messages?
    _np_message_calculate_chunking(update_msg);
    _np_message_serialize_chunked(update_msg);

    // 5: send over the message parts
    pll_iterator(np_messagepart_ptr) iter = pll_first(update_msg->msg_chunks);
    while (NULL != iter) 
    {
        log_debug_msg(LOG_DEBUG, "submitting update request to target key %s / %p", _np_key_as_str(target), target);
        memcpy(iter->val->uuid, update_msg->uuid, NP_UUID_BYTES);
        np_util_event_t update_event = { .type=(evt_internal|evt_message), .context=context, .user_data=iter->val, .target_dhkey=event.target_dhkey};
        _np_keycache_handle_event(context, target->dhkey, update_event, false);
        pll_next(iter);
    }

    // 5 cleanup
    np_key_unref_list(tmp, "_np_route_lookup");
    sll_free(np_key_ptr, tmp);

    return true;
}

bool _np_out_leave(np_state_t* context, const np_util_event_t event) 
{
    log_trace_msg(LOG_TRACE, "start: bool _np_out_leave(...) {");

    NP_CAST(event.user_data, np_message_t, leave_msg);

    // 2: chunk the message if required
    _np_message_calculate_chunking(leave_msg);
    _np_message_serialize_chunked(leave_msg);

    // 3: send over the message parts
    pll_iterator(np_messagepart_ptr) iter = pll_first(leave_msg->msg_chunks);

    while (NULL != iter) 
    {
#ifdef DEBUG
        np_key_t* target_key = _np_keycache_find(context, event.target_dhkey);
        if (target_key!= NULL)
        {
            log_debug_msg(LOG_DEBUG, "submitting leave to target key %s / %p", _np_key_as_str(target_key), target_key);
            np_unref_obj(np_key_t, target_key, "_np_keycache_find");
        }
#endif // DEBUG
        memcpy(iter->val->uuid, leave_msg->uuid, NP_UUID_BYTES);
        np_util_event_t leave_event = { .type=(evt_internal|evt_message), .context=context, .user_data=iter->val, .target_dhkey=event.target_dhkey};
        _np_keycache_handle_event(context, event.target_dhkey, leave_event, false);

        pll_next(iter);
    }

    // 5 cleanup
    return true;
}

bool _np_out_join(np_state_t* context, const np_util_event_t event)
{
    log_trace_msg(LOG_TRACE, "start: bool _np_out_join_req(...) {");

    NP_CAST(event.user_data, np_message_t, join_msg);

    np_tree_t* jrb_data     = np_tree_create();
    np_tree_t* jrb_my_node  = np_tree_create();
    np_tree_t* jrb_my_ident = NULL;

    // 1: create join payload
    np_aaatoken_encode(jrb_my_node, _np_key_get_token(context->my_node_key));
    np_tree_insert_str(jrb_data, _NP_URN_NODE_PREFIX, np_treeval_new_tree(jrb_my_node));

    if(_np_key_cmp(context->my_identity, context->my_node_key) != 0) {
        jrb_my_ident = np_tree_create();
        np_aaatoken_encode(jrb_my_ident, _np_key_get_token(context->my_identity));
        np_tree_insert_str(jrb_data, _NP_URN_IDENTITY_PREFIX, np_treeval_new_tree(jrb_my_ident));
    }
    // 2. set it as body of message
    _np_message_setbody(join_msg, jrb_data);

    // 3: chunk the message if required
    // TODO: send two separate messages?
    _np_message_calculate_chunking(join_msg);
    _np_message_serialize_chunked(join_msg);

    // 4: send over the message parts
    pll_iterator(np_messagepart_ptr) iter = pll_first(join_msg->msg_chunks);
    while (NULL != iter) {
#ifdef DEBUG
        np_key_t* target = _np_keycache_find(context, event.target_dhkey);
        log_debug(LOG_ROUTING, "submitting join request to target key %s / %p", _np_key_as_str(target), target);
        np_unref_obj(np_key_t, target, "_np_keycache_find");
#endif // DEBUG
        memcpy(iter->val->uuid, join_msg->uuid, NP_UUID_BYTES);
        np_util_event_t join_event = { .type=(evt_internal|evt_message), .context=context, .user_data=iter->val, .target_dhkey=event.target_dhkey};
        _np_keycache_handle_event(context, event.target_dhkey, join_event, false);
        pll_next(iter);
    }

    // 5 cleanup
    np_tree_free(jrb_my_node);
    if (NULL != jrb_my_ident) np_tree_free(jrb_my_ident);

    return true;
}

bool _np_out_handshake(np_state_t* context, const np_util_event_t event)
{
    log_trace_msg(LOG_TRACE, "start: bool _np_out_handshake(...) {");

    NP_CAST(event.user_data, np_message_t, hs_message);

    np_key_t* target_key = _np_keycache_find(context, event.target_dhkey);
    
    np_node_t* target_node = _np_key_get_node(target_key);
    np_node_t* my_node = _np_key_get_node(context->my_node_key);

    NP_PERFORMANCE_POINT_START(handshake_out);
    if (_np_node_check_address_validity(target_node))
    {
        np_tree_t* jrb_body = np_tree_create();
        // get our node identity from the cache			
        np_handshake_token_t* my_token = _np_token_factory_new_handshake_token(context);

        np_tree_insert_str(my_token->extensions, NP_HS_PRIO, np_treeval_new_ul(my_node->handshake_priority));
        _np_aaatoken_update_extensions_signature(my_token);
        
        np_aaatoken_encode(jrb_body, my_token);
        _np_message_setbody(hs_message, jrb_body);

        np_unref_obj(np_aaatoken_t, my_token, "_np_token_factory_new_handshake_token");

        _np_message_calculate_chunking(hs_message);

        bool serialize_ok = _np_message_serialize_chunked(hs_message);

        if (hs_message->no_of_chunks != 1 || serialize_ok == false) 
        {
            log_msg(LOG_ERROR, "HANDSHAKE MESSAGE IS NOT 1024 BYTES IN SIZE! Message will not be send");
        }
        else
        {   
            /* send data if handshake status is still just initialized or less */
            log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE | LOG_DEBUG,
                "sending handshake message %s to %s", // (%s:%s)",
                hs_message->uuid, _np_key_as_str(target_key)/*, hs_node->dns_name, hs_node->port*/);

            pll_iterator(np_messagepart_ptr) iter = pll_first(hs_message->msg_chunks);
            np_ref_obj(np_messagepart_t, iter->val, FUNC);
            np_util_event_t handshake_send_evt = { .type=(evt_internal|evt_message), .user_data=iter->val, .context=context, .target_dhkey=event.target_dhkey };
            _np_keycache_handle_event(context, event.target_dhkey, handshake_send_evt, false);
        }
    }
    else
    {
            log_msg(LOG_ERROR, "target node is not valid");
    }
    NP_PERFORMANCE_POINT_END(handshake_out);

    np_unref_obj(np_key_t, target_key, "_np_keycache_find");

    return true;
}
