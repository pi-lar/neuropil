//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "msgpack/cmp.h"
#include "event/ev.h"
#include "sodium.h"

#include "core/np_comp_intent.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"

#include "np_aaatoken.h"
#include "util/np_bloom.h" 
#include "np_constants.h"
#include "np_dhkey.h"
#include "np_event.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "neuropil_log.h"
#include "np_log.h"
#include "util/np_list.h"
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
#include "util/np_tree.h"
#include "np_types.h"
#include "np_util.h"
#include "neuropil_data.h"


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
    
    np_dhkey_t prop_out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, *(_np_message_get_subject(message)) );
    np_key_t*  prop_out_key   = _np_keycache_find(context, prop_out_dhkey);

    NP_CAST(prop_out_key->entity_array[0], np_msgproperty_conf_t, my_property_conf);
    NP_CAST(prop_out_key->entity_array[1], np_msgproperty_run_t, my_property_run);

    bool ret = false;

    np_sll_t(np_aaatoken_ptr, tmp_token_list);
    sll_init(np_aaatoken_ptr, tmp_token_list);

    _np_intent_get_all_receiver(prop_out_key, event.target_dhkey, &tmp_token_list);
    log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "(msg: %s) for subject \"%s\" has valid token", message->uuid, my_property_conf->msg_subject);

    if (FLAG_CMP(my_property_conf->ack_mode, ACK_DESTINATION))
    {
        // TODO: create a copy in case of re-delivery for un-acked messages
        np_message_t* redeliver_copy = NULL;
        np_new_obj(np_message_t, redeliver_copy);

        np_message_clone(redeliver_copy, message);
        _np_message_add_msg_response_handler(redeliver_copy);

        np_util_event_t redeliver_event = { .type=(evt_redeliver|evt_internal|evt_message), .context=context, .target_dhkey=event.target_dhkey, .user_data=redeliver_copy };
        _np_keycache_handle_event(context, prop_out_dhkey, redeliver_event, false);
    }

    np_dhkey_t _computed_to = {0};
    sll_iterator(np_aaatoken_ptr) iter = tmp_token_list->first;
    while (NULL != iter) 
    {
        struct np_data_conf cfg;
        np_data_value recv_threshold;
        if (np_get_data(iter->val->attributes, "max_threshold", &cfg, &recv_threshold) == np_ok) 
        {
            if (recv_threshold.unsigned_integer < my_property_conf->max_threshold) 
            {
                log_msg(LOG_WARN, "reduce max threshold for subject (%s/%u) because receiver %s has lower, otherwise MESSAGE LOSS IS GUARANTEED!", my_property_conf->msg_subject, recv_threshold, iter->val->issuer);
            }
        }
        np_dhkey_t _issuer_dhkey = np_dhkey_create_from_hash(iter->val->issuer);
        _np_dhkey_add(&_computed_to, &_computed_to, &_issuer_dhkey);
        sll_next(iter);
    }
    np_tree_replace_str(message->header, _NP_MSG_HEADER_TO, np_treeval_new_dhkey(_computed_to));

    // encrypt the relevant message part itself
    _np_message_encrypt_payload(message, tmp_token_list);

    np_aaatoken_unref_list(tmp_token_list, "_np_intent_get_all_receiver");
    ret = true;

    np_unref_obj(np_key_t, prop_out_key, "_np_keycache_find");
    sll_free(np_aaatoken_ptr, tmp_token_list);
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

    // np_dhkey_t recv_dhkey = _np_msgproperty_tweaked_dhkey(INBOUND,  msg_subj.value.dhkey);
    uint8_t i = 0;
    while (sll_size(tmp) == 0 && i < 8)
    {
        _np_pheromone_snuffle_receiver(context, tmp, msg_subj.value.dhkey, &target_age);
        i++;
        target_age -= 0.1;
    };
    
    if (sll_size(tmp) == 0) 
    {   // find next hop based on fingerprint of the message
        log_debug_msg(LOG_DEBUG, "pheromone lookup failed, looking up routing table", forward_msg->uuid, sll_size(tmp));
        CHECK_STR_FIELD(forward_msg->header, _NP_MSG_HEADER_TO, msg_to_ele);    
        np_sll_t(np_key_ptr, route_tmp) = NULL;
        i = 1;
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
            if (!_np_dhkey_equal(&key_iter->val, &msg_from.value.dhkey)        &&
                !_np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey) &&
                _np_keycache_contains(context, key_iter->val) )
            {
                memcpy(part_iter->val->uuid, forward_msg->uuid, NP_UUID_BYTES);
                log_debug_msg(LOG_DEBUG, "sending    message (%s) to next hop", forward_msg->uuid, key_iter->val);

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
        log_msg(LOG_INFO, "--- request for default message out, but no connections left ...");
        return false;
    }

    float target_age = 1.0;
    np_sll_t(np_dhkey_t, tmp) = NULL;
    sll_init(np_dhkey_t, tmp);

    // np_dhkey_t recv_dhkey = _np_msgproperty_dhkey(INBOUND,  msg_subj.value.dhkey);
    uint8_t i = 0;
    while (sll_size(tmp) == 0 && i < 8)
    {
        _np_pheromone_snuffle_receiver(context, tmp, msg_subj.value.dhkey, &target_age);
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
                !_np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey) &&
                _np_keycache_contains(context, key_iter->val) )
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

    np_dhkey_t sender_dhkey = {0};
    np_dhkey_t receiver_dhkey = {0};
    np_generate_subject(&sender_dhkey, _NP_MSG_AVAILABLE_SENDER, strnlen(_NP_MSG_AVAILABLE_SENDER, 256));
    np_generate_subject(&receiver_dhkey, _NP_MSG_AVAILABLE_RECEIVER, strnlen(_NP_MSG_AVAILABLE_RECEIVER, 256));

    bool find_receiver = _np_dhkey_equal(&msg_subj.value.dhkey, &sender_dhkey);
    bool find_sender = _np_dhkey_equal(&msg_subj.value.dhkey, &receiver_dhkey);

    uint8_t i = 0;
    while (sll_size(tmp) == 0 && i < 9)
    {
        if (find_receiver){
            _np_pheromone_snuffle_receiver(context, tmp, msg_to.value.dhkey, &target_age);
        } else {
        if (find_sender)
            _np_pheromone_snuffle_sender(context, tmp, msg_to.value.dhkey, &target_age);
        }
        log_debug_msg(LOG_DEBUG, "--- request for available message out %08"PRIx32":08"PRIx32": %f", msg_subj.value.dhkey.t[0], msg_subj.value.dhkey.t[1], target_age);
        i++;
        target_age -= 0.1;
    };

    if (sll_size(tmp) == 0)
    {
        log_msg(LOG_WARN, "--- request for available message (%08"PRIx32":08"PRIx32") out, but no routing found ...", msg_subj.value.dhkey.t[0], msg_subj.value.dhkey.t[1]);
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
            if (!_np_dhkey_equal(&key_iter->val, &last_hop)                    &&
                !_np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey)  &&
                _np_keycache_contains(context, key_iter->val) )
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

    sll_free(np_dhkey_t, tmp);

    // 4 cleanup
    __np_cleanup__: {}

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
    tmp = _np_route_lookup(context, msg_event.target_dhkey, 1);
    char* source_sll_of_keys = "_np_route_lookup";
    
    if (sll_size(tmp) < 1)
    {   // nothing found, send leafset to exchange some data at least
        // prevents small clusters from not exchanging all data
        np_key_unref_list(tmp, source_sll_of_keys); // only for completion
        sll_free(np_key_ptr, tmp);
        tmp = _np_route_neighbors(context);
        // tmp = _np_route_row_lookup(context, msg_event.target_dhkey);
        source_sll_of_keys = "_np_route_neighbors";
    }

    uint8_t send_counter = 0;
    sll_iterator(np_key_ptr) target_iter = sll_first(tmp);
    while(NULL != target_iter && send_counter < NP_PI_INT)
    {
        if (_np_dhkey_equal(&target_iter->val->dhkey, &msg_from.value.dhkey) ||
            _np_dhkey_equal(&target_iter->val->dhkey, &context->my_node_key->dhkey) )
        {
            log_debug_msg(LOG_DEBUG, "discarding pheromone request to next hop %s", _np_key_as_str(target_iter->val));
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
bool _np_out_ack(np_state_t* context, np_util_event_t ack_event)
{
    log_trace_msg(LOG_TRACE, "start: bool _np_send_ack(np_state_t* context, np_util_event_t msg_event){");

    NP_CAST(ack_event.user_data, np_message_t, ack_msg);

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

    np_dhkey_t ack_to_dhkey   = msg_to.value.dhkey;

    // 1a. check if the ack is for a direct neighbour
    np_key_t* target_key = _np_keycache_find(context, ack_to_dhkey);
    if (NULL == target_key)
    {
        // otherwise follow the ack trail of the "from" + "ack" dhkey path
        np_generate_subject(&ack_to_dhkey, _NP_MSG_ACK, strnlen(_NP_MSG_ACK, 256));
        // _np_msgproperty_dhkey(INBOUND,  _NP_MSG_ACK);
        // _np_dhkey_add(&ack_to_dhkey, &ack_to_dhkey, &ack_subj_dhkey);
        // no --> 1b. lookup based on original msg subject, but snuffle for sender
        uint8_t i = 0;
        while (sll_size(tmp) == 0 && i < 8)
        {
            _np_pheromone_snuffle_receiver(context, tmp, ack_to_dhkey, &target_age);
            i++;
            target_age -= 0.1;
        };
        // routing based on pheromones, exhale ...
        _np_pheromone_exhale(context);
    }
    else
    {
        // yes --> 1a. append to result list
        sll_append(np_dhkey_t, tmp, ack_to_dhkey);
        np_unref_obj(np_key_t, target_key, "_np_keycache_find");
    }

    if (sll_size(tmp) == 0)
    {   // exit early if no routing has been found
        log_msg(LOG_WARN, "--- request for ack message out, but no routing found ...");
        sll_free(np_dhkey_t, tmp);
        return false;
    }

    // chunking for 1024 bit message size
    if (ack_msg->is_single_part == false) // indicates the forwarding of the message, no additional chunking needed
    {
        _np_message_calculate_chunking(ack_msg);
        _np_message_serialize_chunked(ack_msg);
    }
    // 2: send over the message parts
    pll_iterator(np_messagepart_ptr) part_iter = pll_first(ack_msg->msg_chunks);
    while (NULL != part_iter) 
    {
        sll_iterator(np_dhkey_t) key_iter = sll_first(tmp);
        while (key_iter != NULL) 
        {
            if (!_np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey) &&
                !_np_dhkey_equal(&key_iter->val, &ack_event.target_dhkey)      &&
                _np_keycache_contains(context, key_iter->val) )
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

    sll_free(np_dhkey_t, tmp);

    __np_cleanup__: {}

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
        if (target_key!= NULL)
        {
            log_debug_msg(LOG_DEBUG, "submitting piggy to target key %s / %p", _np_key_as_str(target_key), target_key);
            np_unref_obj(np_key_t, target_key, "_np_keycache_find");
        }
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

    if(tmp == NULL || sll_size(tmp) == 0) {
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

    np_tree_replace_str(update_msg->header, _NP_MSG_HEADER_TO,  np_treeval_new_dhkey(target->dhkey));
    _np_message_trace_info("MSG_OUT_UPDATE", update_msg);


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
        _np_keycache_handle_event(context, event.target_dhkey, leave_event, true);

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
        np_aaatoken_encode(jrb_my_ident, np_token_factory_get_public_ident_token(_np_key_get_token(context->my_identity)));
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
        np_key_t* target_key = _np_keycache_find(context, event.target_dhkey);
        if (target_key!= NULL)
        {
            log_debug(LOG_ROUTING, "submitting join request to target key %s / %p", _np_key_as_str(target_key), target_key);
            np_unref_obj(np_key_t, target_key, "_np_keycache_find");
        }
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

        np_aaatoken_encode(jrb_body, my_token);
        _np_message_setbody(hs_message, jrb_body);

        np_unref_obj(np_aaatoken_t, my_token, "_np_token_factory_new_handshake_token");

        _np_message_calculate_chunking(hs_message);

        bool serialize_ok = _np_message_serialize_chunked(hs_message);

        if (hs_message->no_of_chunks != 1 || serialize_ok == false)
        {
            log_msg(LOG_ERROR, "HANDSHAKE MESSAGE IS NOT 1024 BYTES IN SIZE! Message will not be send");
            log_debug(LOG_HANDSHAKE, "HANDSHAKE MESSAGE: no_of_chunks:%"PRIu32", serialize: %"PRIu8, hs_message->no_of_chunks, serialize_ok);
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
