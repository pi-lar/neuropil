//
// neuropil is copyright 2016-2019 by pi-lar GmbH
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

#include "msgpack/cmp.h"
#include "event/ev.h"
#include "sodium.h"

#include "np_constants.h"

#include "np_axon.h"

#include "np_log.h"
#include "np_legacy.h"
#include "np_aaatoken.h"
#include "np_event.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_message.h"

#include "core/np_comp_intent.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"

#include "np_memory.h"
#include "np_network.h"
#include "np_node.h"
#include "np_util.h"
#include "np_threads.h"
#include "np_route.h"
#include "np_settings.h"
#include "np_types.h"
#include "np_token_factory.h"
#include "np_list.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_dhkey.h"
#include "np_util.h"
#include "np_responsecontainer.h"
#include "np_serialization.h"
#include "np_statistics.h"


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


/**
 ** _np_network_append_msg_to_out_queue: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
bool _np_out(np_state_t* context, np_util_event_t msg_event)
{
/*    log_trace_msg(LOG_TRACE, "start: bool _np_out(np_state_t* context, np_util_event_t msg_event){");

    uint32_t seq = 0;
    np_message_t* msg_out = args.msg;

    bool is_resend = args.is_resend;
    bool is_forward = msg_out->is_single_part;
    bool ack_to_is_me = false;
    bool ack_mode_from_msg = false;

    uint8_t ack_mode = ACK_NONE;
    char* uuid = NULL;

    np_msgproperty_t* prop = args.properties;
    
    assert(msg_out != NULL && "A message is needed to send a msg out");
    assert(prop != NULL && "A property is needed to send a msg out");

    // set msgproperty of msg
    if (msg_out != NULL && prop != NULL) {
        np_ref_switch(np_msgproperty_t, msg_out->msg_property, ref_message_msg_property, prop);
    }
    np_key_t* target = args.target;
    if (target->type == np_key_type_wildcard && target->parent_key != NULL) {
        log_debug_msg(LOG_ROUTING,
            "reroute wildcard msg (%s) from %s to %s",
            args.msg->uuid,
            _np_key_as_str(target),
            _np_key_as_str(target->parent_key)
        );
        target = target->parent_key;
        np_tree_replace_str(msg_out->header, _NP_MSG_HEADER_TO, np_treeval_new_dhkey(target->dhkey));
    }
    
    // sanity check
    if (!_np_node_check_address_validity(target->node) &&
        target->node->joined_network)
    {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "attempt to send to an invalid node (key: %s)",
            _np_key_as_str(target));
        return;
    }
    np_ref_obj(np_key_t, target, FUNC); // usage ref


    // log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_out 2");
    // now we can try to send the msg
    np_waitref_obj(np_key_t, context->my_node_key, my_key,"np_waitref_key");
    {
        // log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_out 3");
        np_waitref_obj(np_network_t, my_key->network, my_network,"np_waitref_network");
        {
            // log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_out 4");
            uuid = msg_out->uuid;

            // check ack indicator if this is a resend of a message
            if (true == is_resend && prop->ack_mode != ACK_NONE)
            {
                bool skip = false;
                // log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_out 5");
                _LOCK_ACCESS(&my_network->waiting_lock)
                {
                    // log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_out 6");
                    // first find the uuid
                    np_tree_elem_t* uuid_ele = np_tree_find_str(my_network->waiting, uuid);
                    if (NULL == uuid_ele)
                    {
                        // has been deleted already
                        log_debug_msg(LOG_DEBUG, "ACK_HANDLING message %s (%s) assumed acknowledged, not resending ...", prop->msg_subject, uuid);
                        skip = true;
                    }
                    else {
                        TSP_GET(bool, ((np_responsecontainer_t*)uuid_ele->val.value.v)->msg->is_acked, is_acked);

                        if (true == is_acked)
                        {
                            // uuid has been acked
                            log_debug_msg(LOG_DEBUG, "ACK_HANDLING message %s (%s) acknowledged (ACK), not resending ...", prop->msg_subject, uuid);
                            skip = true;
                        }
                        else
                        {
                            // ack indicator still there ! initiate resend ...
                            np_responsecontainer_t* entry = uuid_ele->val.value.v;
                            if (_np_dhkey_cmp(&entry->dest_key->dhkey, &args.target->dhkey) != 0) {
                                // switch dest_key if routing is now pointing to a different key
                                np_ref_switch(np_key_t, entry->dest_key, ref_ack_key, args.target);
                                entry->dest_key = args.target;
                            }
                            log_msg(LOG_INFO, "ACK_HANDLING message %s (%s) not acknowledged, resending ...", prop->msg_subject, uuid);
                        }
                    }
                }
                // TODO: ref counting on ack may differ (ref_message_ack) / key may not be the same more
                if (true == skip) {
                    np_unref_obj(np_key_t, target, FUNC);
                    np_unref_obj(np_network_t, my_network, "np_waitref_network");
                    np_unref_obj(np_key_t, my_key, "np_waitref_key");
                    return;
                }
                
                uint8_t msg_resendcounter = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_SEND_COUNTER)->val.value.ush;
                
                if (msg_resendcounter > 31)
                {
                    log_debug_msg(LOG_ROUTING | LOG_MESSAGE | LOG_DEBUG, "resend message %s (%s) sendcounter too high, not resending ...", prop->msg_subject, uuid);

                    np_unref_obj(np_key_t, target, FUNC);
                    np_unref_obj(np_network_t, my_network, "np_waitref_network");
                    np_unref_obj(np_key_t, my_key, "np_waitref_key");
                    return;
                }

                if (_np_message_is_expired(msg_out))
                {
                    log_debug_msg(LOG_ROUTING | LOG_MESSAGE | LOG_DEBUG, "resend message %s (%s) expired, not resending ...", prop->msg_subject, uuid);

                    np_unref_obj(np_key_t, target, FUNC);
                    np_unref_obj(np_network_t, my_network, "np_waitref_network");
                    np_unref_obj(np_key_t, my_key, "np_waitref_key");
                    return;
                }
                // only redeliver if ack_to has been initialized correctly, so this must be true for a resend
                ack_to_is_me = true;
            }
            log_debug_msg(LOG_ROUTING | LOG_MESSAGE | LOG_DEBUG, "setting instructions to out msg %s ", uuid);

            // find correct ack_mode, inspect message first because of forwarding
            if (NULL == np_tree_find_str(msg_out->instructions, _NP_MSG_INST_ACK))
            {
                ack_mode = prop->ack_mode;
            }
            else
            {
                ack_mode = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_ACK)->val.value.ush;
                ack_mode_from_msg = true;
            }
            np_tree_insert_str( msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop->ack_mode));

            char* ack_to_str = _np_key_as_str(my_key);

            if (FLAG_CMP(ack_mode, ACK_DESTINATION) || FLAG_CMP(ack_mode, ACK_CLIENT))
            {
                // only set ack_to for these two ack mode values if not yet set !
                np_tree_insert_str( msg_out->instructions, _NP_MSG_INST_ACK_TO, np_treeval_new_s(ack_to_str));
                if (false == ack_mode_from_msg) ack_to_is_me = true;
            }
            else
            {
                ack_to_is_me = false;
            }

            np_tree_insert_str( msg_out->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(0));
            if (!is_resend)
            {
                // log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_out 7");
                _LOCK_ACCESS(&my_network->access_lock)
                {
                    // log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_out 8");
                    // get/set sequence number to keep increasing sequence numbers per node
                    seq = my_network->seqend;
                    np_tree_replace_str( msg_out->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(seq));
                    my_network->seqend++;
                }
            }

            // insert a uuid if not yet present
            np_tree_insert_str( msg_out->instructions, _NP_MSG_INST_UUID, np_treeval_new_s(msg_out->uuid));

            // set re-send count to zero if not yet present
            np_tree_insert_str( msg_out->instructions, _NP_MSG_INST_SEND_COUNTER, np_treeval_new_ush(0));
            // and increase resend count by one
            // TODO: forwarding of message will also increase re-send counter, ok ?
            np_tree_elem_t* jrb_send_counter = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_SEND_COUNTER);
            jrb_send_counter->val.value.ush++;
            // TODO: insert resend count check

            // insert timestamp and time-to-live
            double now = np_time_now();
            np_tree_insert_str( msg_out->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d(now));
            double ttl_of_msg_via_property = now + args.properties->msg_ttl;
            np_tree_insert_str( msg_out->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(args.properties->msg_ttl));
            // calculate ttl or take the one already present if it expieres earlier
            np_tree_elem_t *tmp1, *tmp2;
            if ((tmp1 = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_TTL)) == NULL ||
                (tmp2 = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_TSTAMP)) == NULL ||
                ((tmp1->val.value.d + tmp2->val.value.d) > ttl_of_msg_via_property)
            ) {
                np_tree_replace_str(msg_out->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d(now));
                np_tree_replace_str(msg_out->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(args.properties->msg_ttl));
            }

            np_tree_insert_str( msg_out->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(1, 1));
            if (false == msg_out->is_single_part)
            {
                _np_message_calculate_chunking(msg_out);
            }

            bool reschedule_msg_transmission = false;

            if (true == ack_to_is_me || (!is_forward && sll_size(msg_out->on_reply) > 0))
            {
                if (false == is_resend && false == is_forward)
                {
                    uuid = np_treeval_to_str(np_tree_find_str(msg_out->instructions, _NP_MSG_INST_UUID)->val, NULL);

                    np_responsecontainer_t *responsecontainer = NULL;
                    // get/set sequence number to initialize acknowledgement indicator correctly
                    np_new_obj(np_responsecontainer_t, responsecontainer, ref_ack_obj);

                    responsecontainer->send_at = np_time_now();
                    responsecontainer->expires_at = responsecontainer->send_at + args.properties->msg_ttl + _np_msgproperty_get(context, INBOUND, _NP_MSG_ACK)->msg_ttl;
                    responsecontainer->dest_key = target;
                    np_ref_obj(np_key_t, responsecontainer->dest_key, ref_ack_key);

                    responsecontainer->msg = args.msg;
                    np_ref_obj(np_message_t, responsecontainer->msg, ref_ack_msg);

                    // responsecontainer->expected_ack = 1; // msg_out->no_of_chunks ?
                    log_debug_msg(LOG_DEBUG, "initial   sending of message (%s/%s) with response",
                                             args.properties->msg_subject, args.msg->uuid);

#ifdef DEBUG					
                    CHECK_STR_FIELD(args.msg->header, _NP_MSG_HEADER_TO, msg_to);
                    {
                        bool freeable = false;
                        char* dhkey_to = np_treeval_to_str(msg_to, &freeable);

                        log_debug_msg(LOG_DEBUG, "RESPONSE_HANDLING                   message (%s/%s) %s < - > %s / %"PRIu8":%s:%s",
                                uuid, args.properties->msg_subject,
                                 _np_key_as_str(target), dhkey_to,
                            target->node->joined_network, target->node->dns_name, target->node->port);

                        if (freeable) free(dhkey_to);
                    }
                    __np_cleanup__:
                        {}
#endif
                    // log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_out 9");
                    _LOCK_ACCESS(&my_network->waiting_lock)
                    {
                        // log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_out 10");
                        np_tree_insert_str( my_network->waiting, uuid, np_treeval_new_v(responsecontainer));
                    }
                    // log_msg(LOG_ERROR, "ACK_HANDLING ack handling requested for msg uuid: %s/%s", uuid, args.properties->msg_subject);
                    log_debug_msg(LOG_ROUTING | LOG_MESSAGE | LOG_DEBUG, "response handling (%p) requested for msg uuid: %s", my_network->waiting, uuid);
                }
                reschedule_msg_transmission = true;
            }

            np_jobargs_t chunk_args = { .msg = msg_out };

            if (true == is_forward)
            {
                _np_message_serialize_header_and_instructions(context, chunk_args);
            }
            else
            {
                _np_message_serialize_chunked(msg_out);
            }

            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "Try sending message for subject \"%s\" (msg id: %s chunks: %"PRIu32") to %s", prop->msg_subject, msg_out->uuid, msg_out->no_of_chunks, _np_key_as_str(args.target));

            //TODO: DOCUMENT FEATURE RESEND
            //TODO: DOCUMENT FEATURE ACKing
            if(msg_out->send_at ==0) msg_out->send_at = np_time_now();
            bool send_completed = _np_network_append_msg_to_out_queue(target, msg_out);

            if(send_completed) {
                _np_increment_send_msgs_counter(msg_out->msg_property->msg_subject);
                if(is_forward == false){
                    __np_axon_invoke_on_user_send_callbacks(msg_out, msg_out->msg_property);
                }
            }

            if (send_completed == false || (args.properties->retry > 0 && reschedule_msg_transmission == true) ) {
                double retransmit_interval = args.properties->msg_ttl / (args.properties->retry + 1);
                // np_msgproperty_t* out_prop = _np_msgproperty_get(context, OUTBOUND, args.properties->msg_subject);
                if (send_completed == false &&
                    reschedule_msg_transmission == false && 
                    (np_time_now() - msg_out->send_at) > retransmit_interval*args.properties->retry
                    ) {
                    log_msg(LOG_WARN, "np_network returned error, and no re-sending of message (%s) has been scheduled", args.msg->uuid);
                }
                else {								
                    if (args.msg->submit_type == np_message_submit_type_DIRECT) {
                        _np_job_resubmit_msgout_event(context, retransmit_interval, args.properties, target, args.msg);
                    }
                    else {
                        _np_job_resubmit_route_event(context, retransmit_interval, args.properties, target, args.msg);
                    }
                    log_debug_msg(LOG_DEBUG, "ACK_HANDLING re-sending of message (%s) scheduled", args.msg->uuid);
                }
            }

            np_unref_obj(np_network_t, my_network, "np_waitref_network");
        }
        np_unref_obj(np_key_t, target, FUNC);
        np_unref_obj(np_key_t, my_key, "np_waitref_key");		
    }
    // log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_out 11");
    */
    return true;
}

bool _np_out_callback_wrapper(np_state_t* context, const np_util_event_t event) 
{
    log_debug_msg(LOG_TRACE, "start: void __np_out_callback_wrapper(...){");

    NP_CAST(event.user_data, np_message_t, message);

    np_dhkey_t prop_dhkey = _np_msgproperty_dhkey(OUTBOUND, _np_message_get_subject(message) );
    np_key_t*  prop_key   = _np_keycache_find(context, prop_dhkey);
    NP_CAST(sll_first(prop_key->entities)->val, np_msgproperty_t, my_property);

    bool ret = false;

    np_message_intent_public_token_t* tmp_token = _np_intent_get_receiver(prop_key, event.target_dhkey);
    if (NULL != tmp_token)
    {
        _np_msgproperty_threshold_increase(my_property);
        log_msg(LOG_INFO, "(msg: %s) for subject \"%s\" has valid token", message->uuid, my_property->msg_subject);

        np_dhkey_t receiver_dhkey = np_aaatoken_get_partner_fp(tmp_token);

        if (_np_dhkey_equal(&context->my_node_key->dhkey, &receiver_dhkey))
        {
            np_dhkey_t in_handler = _np_msgproperty_dhkey(INBOUND, my_property->msg_subject);
            np_util_event_t msg_in_event = { .type=(evt_external|evt_message), .context=context, .target_dhkey=receiver_dhkey, .user_data=message };
            _np_keycache_handle_event(context, in_handler, msg_in_event, false);
        }
        else
        {
            // TODO: instead of token threshold a local copy of the value should be increased
            if (np_tree_find_str(tmp_token->extensions_local, "msg_threshold"))
                np_tree_find_str(tmp_token->extensions_local, "msg_threshold")->val.value.ui++;

            log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "encrypting message (%s) with receiver token %s %s...", message->uuid, tmp_token->uuid, tmp_token->issuer);
            // encrypt the relevant message part itself
            _np_message_encrypt_payload(message, tmp_token);

            np_tree_replace_str(message->header, _NP_MSG_HEADER_TO, np_treeval_new_dhkey(receiver_dhkey));
        }
        // decrease threshold counters
        _np_msgproperty_threshold_decrease(my_property);
        np_unref_obj(np_aaatoken_t, tmp_token, "_np_intent_get_receiver");
        ret = true;
    }
    else
    {
        log_msg(LOG_INFO, "(msg: %s) for subject \"%s\" has NO valid token / %p", message->uuid, my_property->msg_subject, my_property);
        _np_msgproperty_add_msg_to_send_cache(my_property, message);
    }
    np_unref_obj(np_key_t, prop_key, "_np_keycache_find");

    return ret;
}

bool _np_out_forward(np_state_t* context, np_util_event_t event)
{
    log_debug_msg(LOG_DEBUG, "start: bool _np_out_default(np_state_t* context, np_util_event_t msg_event){");
    np_message_intent_public_token_t* msg_token = NULL;

    NP_CAST(event.user_data, np_message_t, forward_msg);

    if (!_np_route_my_key_has_connection(context))
    {
        log_msg(LOG_WARN, "--- request for forward message out, but no connections left ...");
        return false;
    }

    // 1: find next hop based on fingerprint of the token
    CHECK_STR_FIELD(forward_msg->header, _NP_MSG_HEADER_TO, msg_to_ele);    
    
    np_sll_t(np_key_ptr, tmp) = NULL;
    uint8_t i = 0;
    do {
        tmp = _np_route_lookup(context, msg_to_ele.value.dhkey, i);
        i++;
    } while (sll_size(tmp) == 0 && i < 5);

    np_key_t* target = sll_first(tmp)->val;

    if (_np_dhkey_equal(&target->dhkey, &context->my_node_key->dhkey))
    {
        np_key_unref_list(tmp, "_np_route_lookup");
        return false;
    }

    log_msg(LOG_INFO, "sending    message (%s) to: %s (%d)", forward_msg->uuid, _np_key_as_str(target), sll_size(tmp));
    
    // 3: send over the message parts
    pll_iterator(np_messagepart_ptr) iter = pll_first(forward_msg->msg_chunks);
    while (NULL != iter) 
    {
        iter->val->uuid = strndup(forward_msg->uuid, NP_UUID_BYTES);
        log_debug_msg(LOG_DEBUG, "submitting request to target key %s / %p", _np_key_as_str(target), target);
        np_util_event_t send_event = { .type=(evt_internal|evt_message), .context=context, .user_data=iter->val, .target_dhkey=event.target_dhkey};
        _np_keycache_handle_event(context, target->dhkey, send_event, false);
        pll_next(iter);
    }
    // 4 cleanup
    np_key_unref_list(tmp, "_np_route_lookup");
    sll_free(np_key_ptr, tmp);

    __np_cleanup__: {}

    return true;
}

bool _np_out_default(np_state_t* context, np_util_event_t event)
{
    log_debug_msg(LOG_DEBUG, "start: bool _np_out_default(np_state_t* context, np_util_event_t msg_event){");
    np_message_intent_public_token_t* msg_token = NULL;

    NP_CAST(event.user_data, np_message_t, forward_msg);

    if (!_np_route_my_key_has_connection(context))
    {
        log_msg(LOG_WARN, "--- request for forward message out, but no connections left ...");
        return false;
    }

    // 1: find next hop based on fingerprint of the token
    CHECK_STR_FIELD(forward_msg->header, _NP_MSG_HEADER_TO, msg_to_ele);    
    
    np_sll_t(np_key_ptr, tmp) = NULL;
    uint8_t i = 1;
    do {
        tmp = _np_route_lookup(context, msg_to_ele.value.dhkey, i);
        i++;
    } while (sll_size(tmp) == 0 && i < 5);

    np_key_t* target = sll_first(tmp)->val;

    if (_np_dhkey_equal(&target->dhkey, &context->my_node_key->dhkey))
    {
        np_key_unref_list(tmp, "_np_route_lookup");
        return false;
    }

    log_msg(LOG_INFO, "sending    message (%s) to: %s (%d)", forward_msg->uuid, _np_key_as_str(target), sll_size(tmp));

    // 2: chunk the message if required
    // TODO: send two separate messages?
    if (forward_msg->is_single_part == false) {
        _np_message_calculate_chunking(forward_msg);
        _np_message_serialize_chunked(forward_msg);
    }
    
    // 3: send over the message parts
    pll_iterator(np_messagepart_ptr) iter = pll_first(forward_msg->msg_chunks);
    while (NULL != iter) 
    {
        iter->val->uuid = strndup(forward_msg->uuid, NP_UUID_BYTES);
        log_debug_msg(LOG_DEBUG, "submitting request to target key %s / %p", _np_key_as_str(target), target);
        np_util_event_t send_event = { .type=(evt_internal|evt_message), .context=context, .user_data=iter->val, .target_dhkey=event.target_dhkey};
        _np_keycache_handle_event(context, target->dhkey, send_event, false);
        pll_next(iter);
    }
    // 4 cleanup
    np_key_unref_list(tmp, "_np_route_lookup");
    sll_free(np_key_ptr, tmp);

    __np_cleanup__: {}

    return true;
}

bool _np_out_available_messages(np_state_t* context, np_util_event_t event)
{    
    log_debug_msg(LOG_DEBUG, "start: bool _np_out_available_messages(...){");
    np_message_intent_public_token_t* msg_token = NULL;

    NP_CAST(event.user_data, np_message_t, available_msg);

    if (!_np_route_my_key_has_connection(context))
    {
        log_msg(LOG_WARN, "--- request for discovery message out, but no connections left ...");
        return false;
    }

    // 1: find next hop based on fingerprint of the token
    np_sll_t(np_key_ptr, tmp) = NULL;
    uint8_t i = 1;
    do {
        tmp = _np_route_lookup(context, event.target_dhkey, i);
        i++;
    } while (sll_size(tmp) == 0 && i < 5);

    np_key_t* target = sll_first(tmp)->val;

    // 2: chunk the message if required
    // TODO: send two separate messages?
    _np_message_calculate_chunking(available_msg);
    _np_message_serialize_chunked(available_msg);

    // 3: send over the message parts
    pll_iterator(np_messagepart_ptr) iter = pll_first(available_msg->msg_chunks);
    while (NULL != iter) 
    {
        iter->val->uuid = strndup(available_msg->uuid, NP_UUID_BYTES);
        log_debug_msg(LOG_DEBUG, "submitting discovery request to target key %s / %p", _np_key_as_str(target), target);
        np_util_event_t send_event = { .type=(evt_internal|evt_message), .context=context, .user_data=iter->val, .target_dhkey=event.target_dhkey};
        _np_keycache_handle_event(context, target->dhkey, send_event, false);
        pll_next(iter);
    }

    // 4 cleanup
    np_key_unref_list(tmp, "_np_route_lookup");
    sll_free(np_key_ptr, tmp);

    return true;
}

bool _np_out_discovery_messages(np_state_t* context, np_util_event_t event)
{    
    log_debug_msg(LOG_DEBUG, "start: bool _np_out_discovery_messages(np_state_t* context, np_util_event_t msg_event){");
    np_message_intent_public_token_t* msg_token = NULL;

    NP_CAST(event.user_data, np_message_t, discover_msg);

    if (!_np_route_my_key_has_connection(context))
    {
        log_msg(LOG_WARN, "--- request for discovery message out, but no connections left ...");
        return false;
    }

    NP_PERFORMANCE_POINT_START(msg_discovery_out);

    // 1: find next hop based on fingerprint of the token
    np_sll_t(np_key_ptr, tmp) = NULL;
    uint8_t i = 1;
    do {
        tmp = _np_route_lookup(context, event.target_dhkey, i);
        i++;
    } while (sll_size(tmp) == 0 && i < 5);

    np_key_t* target = sll_first(tmp)->val;

    // 2: chunk the message if required
    // TODO: send two separate messages?
    _np_message_calculate_chunking(discover_msg);
    _np_message_serialize_chunked(discover_msg);

    // 3: send over the message parts
    pll_iterator(np_messagepart_ptr) iter = pll_first(discover_msg->msg_chunks);
    while (NULL != iter) 
    {
        iter->val->uuid = strndup(discover_msg->uuid, NP_UUID_BYTES);
        log_debug_msg(LOG_DEBUG, "submitting discovery request to target key %s / %p", _np_key_as_str(target), target);
        np_util_event_t send_event = { .type=(evt_internal|evt_message), .context=context, .user_data=iter->val, .target_dhkey=event.target_dhkey};
        _np_keycache_handle_event(context, target->dhkey, send_event, false);
        pll_next(iter);
    }
    NP_PERFORMANCE_POINT_END(msg_discovery_out);

    // 4 cleanup
    np_key_unref_list(tmp, "_np_route_lookup");
    sll_free(np_key_ptr, tmp);

    return true;
}

bool _np_out_authentication_request(np_state_t* context, np_util_event_t msg_event)
{
 /*   
    log_trace_msg(LOG_TRACE, "start: bool _np_out_authentication_request(np_state_t* context, np_util_event_t msg_event){");

    np_dhkey_t target_dhkey = { 0 };

    if (0 < strlen(args.target->aaa_token->realm))
    {
        _np_str_dhkey( args.target->aaa_token->realm, &target_dhkey);
    }
    else if (0 < strlen(context->my_identity->aaa_token->realm) )
    {
        // TODO: this is wrong, it should be the token issuer which we ask for authentication        
        _np_str_dhkey( context->my_identity->aaa_token->realm, &target_dhkey);
    }
    else
    {
        return;
    }

    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding and sending authentication token");

    np_key_t* aaa_target = NULL;
    np_new_obj(np_key_t, aaa_target);
    aaa_target->dhkey = target_dhkey;

    np_msgproperty_t* aaa_props = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHENTICATION_REQUEST);

    // create and send authentication request
    np_message_t* msg_out = NULL;
    np_new_obj(np_message_t, msg_out);

    np_tree_t* auth_data = np_tree_create();
    np_aaatoken_encode(auth_data, args.target->aaa_token);

//	log_debug_msg(LOG_DEBUG, "realm             : %s", args.target->aaa_token->realm);
//	log_debug_msg(LOG_DEBUG, "issuer            : %s", args.target->aaa_token->issuer);
//	log_debug_msg(LOG_DEBUG, "subject           : %s", args.target->aaa_token->subject);
//	log_debug_msg(LOG_DEBUG, "audience          : %s", args.target->aaa_token->audience);
//	log_debug_msg(LOG_DEBUG, "uuid              : %s", args.target->aaa_token->uuid);

    _np_message_create(msg_out, target_dhkey, context->my_node_key->dhkey, _NP_MSG_AUTHENTICATION_REQUEST, auth_data);
    if (false == _np_send_msg(_NP_MSG_AUTHENTICATION_REQUEST, msg_out, aaa_props, NULL))
    {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending authentication discovery");
        np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
        _np_out_receiver_discovery(context, jargs);
    }
    np_unref_obj(np_message_t, msg_out,ref_obj_creation);

    np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
    */
    return true;
}

bool _np_out_authentication_reply(np_state_t* context, np_util_event_t msg_event)
{
    /*
    log_trace_msg(LOG_TRACE, "start: bool _np_out_authentication_reply(np_state_t* context, np_util_event_t msg_event){");

    np_dhkey_t target_dhkey;

    np_msg_mep_type mep_reply_sticky = np_tree_find_str(args.target->aaa_token->extensions, "mep_type")->val.value.ul & STICKY_REPLY;

    if (STICKY_REPLY != mep_reply_sticky &&
        0 < strlen(args.target->aaa_token->realm) )
    {
        target_dhkey = np_dhkey_create_from_hostport( args.target->aaa_token->realm, "0");
    }
    else
    {
        target_dhkey = np_dhkey_create_from_hash(args.target->aaa_token->issuer);
    }

    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding and sending authentication reply");

    np_key_t* aaa_target = NULL;
    np_new_obj(np_key_t, aaa_target);
    aaa_target->dhkey = target_dhkey;

    np_msgproperty_t* aaa_props = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHENTICATION_REPLY);

    // create and send authentication reply
    if (false == _np_send_msg(_NP_MSG_AUTHENTICATION_REPLY, args.msg, aaa_props, NULL))
    {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending authentication reply discovery");
        np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
        _np_out_receiver_discovery(context, jargs);
    }
    np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
    */
    return true;
}

bool _np_out_authorization_request(np_state_t* context, np_util_event_t msg_event)
{
     /*
    log_trace_msg(LOG_TRACE, "start: bool _np_out_authorization_request(np_state_t* context, np_util_event_t msg_event){");

    np_dhkey_t target_dhkey = { 0 };

    if (0 < strlen(context->my_identity->aaa_token->realm) )
    {
        _np_str_dhkey( context->my_identity->aaa_token->realm, &target_dhkey);
    }
    else
    {
        return;
    }

    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding and sending authorization token");
    np_key_t* aaa_target = NULL;
    np_new_obj(np_key_t, aaa_target);
    aaa_target->dhkey = target_dhkey;

    np_msgproperty_t* aaa_props = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHORIZATION_REQUEST);

    // create and and send authorization request
    np_message_t* msg_out = NULL;
    np_new_obj(np_message_t, msg_out);
    np_tree_t* auth_data = np_tree_create();
    np_aaatoken_encode(auth_data, args.target->aaa_token);

    _np_message_create(msg_out, target_dhkey, context->my_node_key->dhkey, _NP_MSG_AUTHORIZATION_REQUEST, auth_data);
    if (false == _np_send_msg(_NP_MSG_AUTHORIZATION_REQUEST, msg_out, aaa_props, NULL))
    {
        np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
        _np_out_receiver_discovery(context, jargs);
    }
    np_unref_obj(np_message_t, msg_out,ref_obj_creation);
    np_unref_obj(np_key_t, aaa_target, ref_obj_creation);
    */
    return true;
}

bool _np_out_authorization_reply(np_state_t* context, np_util_event_t msg_event)
{/*
    np_dhkey_t target_dhkey = { 0 };

    np_msg_mep_type mep_reply_sticky = np_tree_find_str(args.target->aaa_token->extensions, "mep_type")->val.value.ul & STICKY_REPLY;

    if (STICKY_REPLY != mep_reply_sticky &&
        0 < strlen(args.target->aaa_token->realm) )
    {
        _np_str_dhkey( args.target->aaa_token->realm, &target_dhkey);
    }
    else
    {
        _np_str_dhkey( args.target->aaa_token->issuer, &target_dhkey);
    }

    log_debug_msg(LOG_SERIALIZATION| LOG_DEBUG, "encoding and sending authorization reply");

    np_key_t* aaa_target = NULL;
    np_new_obj(np_key_t, aaa_target);
    aaa_target->dhkey = target_dhkey;

    np_msgproperty_t* aaa_props = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHORIZATION_REPLY);

    // create and send authentication reply
    if (false == _np_send_msg(_NP_MSG_AUTHORIZATION_REPLY, args.msg, aaa_props, NULL))
    {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending authorization reply discovery");
        np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
        _np_out_receiver_discovery(context, jargs);
    }
    np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
*/
    return true;
}

bool _np_out_accounting_request(np_state_t* context, np_util_event_t msg_event)
{
   /* 
    np_dhkey_t target_dhkey = { 0 };

    if (0 < strlen(context->my_identity->aaa_token->realm) )
    {
        _np_str_dhkey( context->my_identity->aaa_token->realm, &target_dhkey);
    }
    else
    {
        return;
    }

    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding and sending accounting token");
    np_msgproperty_t* aaa_props = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_ACCOUNTING_REQUEST);

    np_key_t* aaa_target = NULL;
    np_new_obj(np_key_t, aaa_target);
    aaa_target->dhkey = target_dhkey;

    // create and and send authentication request
    np_message_t* msg_out = NULL;
    np_new_obj(np_message_t, msg_out);

    np_tree_t* auth_data = np_tree_create();
    np_aaatoken_encode(auth_data, args.target->aaa_token);
    _np_message_create(msg_out, target_dhkey, context->my_node_key->dhkey, _NP_MSG_ACCOUNTING_REQUEST, auth_data);

    if (false == _np_send_msg(_NP_MSG_ACCOUNTING_REQUEST, msg_out, aaa_props, NULL))
    {
        np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
        _np_out_receiver_discovery(context, jargs);
    }
    np_unref_obj(np_message_t, msg_out,ref_obj_creation);

    np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
    */
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

    // chunking for 1024 bit message size
    _np_message_calculate_chunking(ack_msg);
    _np_message_serialize_chunked(ack_msg);

    // 3: send over the message parts
    pll_iterator(np_messagepart_ptr) iter = pll_first(ack_msg->msg_chunks);
    while (NULL != iter) 
    {
#ifdef DEBUG
        np_key_t* target_key = _np_keycache_find(context, msg_event.target_dhkey);
        if (NULL != target_key) {
            log_debug_msg(LOG_DEBUG, "submitting ack to target key %s / %p", _np_key_as_str(target_key), target_key);
            np_unref_obj(np_key_t, target_key, "_np_keycache_find");
        }
#endif // DEBUG
        iter->val->uuid = strndup(ack_msg->uuid, NP_UUID_BYTES);
        np_util_event_t ack_event = { .type=(evt_internal|evt_message), .context=context, .user_data=iter->val, .target_dhkey=msg_event.target_dhkey};
        _np_keycache_handle_event(context, msg_event.target_dhkey, ack_event, false);

        pll_next(iter);
    }

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
        iter->val->uuid = strndup(ping_msg->uuid, NP_UUID_BYTES);
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
        iter->val->uuid = strndup(piggy_msg->uuid, NP_UUID_BYTES);
#ifdef DEBUG
        np_key_t* target_key = _np_keycache_find(context, event.target_dhkey);
        log_debug_msg(LOG_DEBUG, "submitting piggy to target key %s / %p", _np_key_as_str(target_key), target_key);
        np_unref_obj(np_key_t, target_key, "_np_keycache_find");
#endif // DEBUG
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
        iter->val->uuid = strndup(update_msg->uuid, NP_UUID_BYTES);
        log_debug_msg(LOG_DEBUG, "submitting update request to target key %s / %p", _np_key_as_str(target), target);
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
        iter->val->uuid = strndup(leave_msg->uuid, NP_UUID_BYTES);
#ifdef DEBUG
        np_key_t* target_key = _np_keycache_find(context, event.target_dhkey);
        log_debug_msg(LOG_DEBUG, "submitting leave to target key %s / %p", _np_key_as_str(target_key), target_key);
        np_unref_obj(np_key_t, target_key, "_np_keycache_find");
#endif // DEBUG
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
        iter->val->uuid = strndup(join_msg->uuid, NP_UUID_BYTES);
#ifdef DEBUG
        np_key_t* target = _np_keycache_find(context, event.target_dhkey);
        log_debug_msg(LOG_DEBUG, "submitting join request to target key %s / %p", _np_key_as_str(target), target);
        np_unref_obj(np_key_t, target, "_np_keycache_find");
#endif // DEBUG
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
    log_debug_msg(LOG_TRACE, "start: bool _np_out_handshake(...) {");

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
