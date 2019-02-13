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

#include "np_msgproperty.h"
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


void __np_axon_invoke_on_user_send_callbacks(np_message_t* msg_out, np_msgproperty_t* prop)
{
    assert(msg_out != NULL);
    np_state_t* context = np_ctx_by_memory(msg_out);

    if (msg_out->msg_property == NULL) {
        np_ref_obj(np_msgproperty_t, prop, ref_message_msg_property);
        msg_out->msg_property = prop;
    }
    // Call user handler for send msgs
    sll_iterator(np_usercallback_ptr) iter_usercallbacks = sll_first(prop->user_send_clb);
    while (iter_usercallbacks != NULL)
    {
        iter_usercallbacks->val->fn(context, msg_out, (msg_out == NULL ? NULL : msg_out->body), iter_usercallbacks->val->data);
        sll_next(iter_usercallbacks);
    }
}

/**
 ** _np_network_append_msg_to_out_queue: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void _np_out_ack(np_state_t* context, np_jobargs_t args)
{
    

    log_trace_msg(LOG_TRACE, "start: void _np_send_ack(np_state_t* context, np_jobargs_t args){");
    np_waitref_obj(np_key_t, context->my_node_key, my_key,"np_waitref_key");
    np_waitref_obj(np_network_t, my_key->network, my_network,"np_waitref_network");

    uint32_t seq = 0;
    _LOCK_ACCESS(&my_network->access_lock)
    {
        /* get/set sequence number to keep increasing sequence numbers per node */
        seq = my_network->seqend;
        np_tree_replace_str(args.msg->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(seq));
        my_network->seqend++;
    }
    double now = np_time_now();
    np_tree_insert_str( args.msg->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(args.properties->ack_mode));
    np_tree_insert_str( args.msg->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(args.properties->msg_ttl));
    np_tree_insert_str( args.msg->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d(now));

    np_tree_insert_str(args.msg->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(args.properties->ack_mode));
    np_tree_insert_str( args.msg->instructions, _NP_MSG_INST_UUID, np_treeval_new_s(args.msg->uuid));
    np_tree_insert_str( args.msg->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(1, 1));
    np_tree_insert_str( args.msg->instructions, _NP_MSG_INST_SEND_COUNTER, np_treeval_new_ush(0));
    np_tree_elem_t* jrb_send_counter = np_tree_find_str(args.msg->instructions, _NP_MSG_INST_SEND_COUNTER);
    jrb_send_counter->val.value.ush++;

    // chunking for 1024 bit message size
    _np_message_calculate_chunking(args.msg);
    _np_message_serialize_chunked(args.msg);
    bool send_ok = _np_network_append_msg_to_out_queue(args.target, args.msg);
    if(send_ok) {
        __np_axon_invoke_on_user_send_callbacks(args.msg, np_msgproperty_get(context, OUTBOUND, _NP_MSG_ACK));
    } else {
        np_tree_elem_t* target_uuid = np_tree_find_str(args.msg->instructions, _NP_MSG_INST_RESPONSE_UUID);
        log_msg(LOG_ERROR, "msg (%s) ACK_HANDLING sending of ack message (%s) to %s:%s failed",
                args.msg->uuid,
                target_uuid->val.value.s,
                args.target->node->dns_name, args.target->node->port);
    }
    np_unref_obj(np_key_t, my_key,"np_waitref_key");
    np_unref_obj(np_network_t, my_network,"np_waitref_network");
}

/**
 ** _np_network_append_msg_to_out_queue: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void _np_out(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_out(np_state_t* context, np_jobargs_t args){");
    // log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_out 1");

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
                    /* get/set sequence number to keep increasing sequence numbers per node */
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
                ((tmp1->val.value.d + tmp2->val.value.d) > ttl_of_msg_via_property/*compare expiers_at values*/)
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
                    responsecontainer->expires_at = responsecontainer->send_at + args.properties->msg_ttl + np_msgproperty_get(context, INBOUND, _NP_MSG_ACK)->msg_ttl;
                    responsecontainer->dest_key = target;
                    np_ref_obj(np_key_t, responsecontainer->dest_key, ref_ack_key);

                    responsecontainer->msg = args.msg;
                    np_ref_obj(np_message_t, responsecontainer->msg, ref_ack_msg);

                    // responsecontainer->expected_ack = 1; // msg_out->no_of_chunks ?
                    log_debug_msg(LOG_DEBUG, "initial sending of message (%s/%s) with response",
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

            if(is_forward == false && send_completed == true) {
                __np_axon_invoke_on_user_send_callbacks(msg_out, msg_out->msg_property);
            }

            if (send_completed == false || (args.properties->retry > 0 && reschedule_msg_transmission == true) ) {
                double retransmit_interval = args.properties->msg_ttl / (args.properties->retry + 1);
                // np_msgproperty_t* out_prop = np_msgproperty_get(context, OUTBOUND, args.properties->msg_subject);
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
}

void _np_out_handshake(np_state_t* context, np_jobargs_t args)
{
    NP_PERFORMANCE_POINT_START(handshake_out);
    NP_PERFORMANCE_POINT_START(handshake_out_lock);
    _LOCK_MODULE(np_handshake_t)
    {
        NP_PERFORMANCE_POINT_END(handshake_out_lock);
        if (_np_node_check_address_validity(args.target->node))
        {
            // get our node identity from the cache			
            np_handshake_token_t* my_token = _np_token_factory_new_handshake_token(context);

            // create real handshake message ...
            np_message_t* hs_message = NULL;
            np_msgproperty_t* hs_prop = np_msgproperty_get(context, OUTBOUND, _NP_MSG_HANDSHAKE);
            np_new_obj(np_message_t, hs_message);

            np_tree_insert_str( hs_message->header, _NP_MSG_HEADER_SUBJECT, np_treeval_new_s(_NP_MSG_HANDSHAKE));
            np_tree_insert_str( hs_message->header, _NP_MSG_HEADER_FROM, np_treeval_new_dhkey(context->my_node_key->dhkey) );
            np_tree_insert_str( hs_message->header, NP_HS_PRIO, np_treeval_new_ul(context->my_node_key->node->handshake_priority));
            
            np_tree_insert_str( hs_message->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(1, 1));
            np_tree_insert_str( hs_message->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(hs_prop->ack_mode));
            np_tree_insert_str( hs_message->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(hs_prop->token_max_ttl + 0.0));
            np_tree_insert_str( hs_message->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d((double)np_time_now()));
            if (args.custom_data != NULL) {
                np_tree_insert_str(hs_message->instructions, _NP_MSG_INST_RESPONSE_UUID, np_treeval_new_s(args.custom_data));
                free(args.custom_data);
            }

            np_aaatoken_encode(hs_message->body, my_token);
            np_unref_obj(np_aaatoken_t, my_token, "_np_token_factory_new_handshake_token");

            _np_message_calculate_chunking(hs_message);

            bool serialize_ok = _np_message_serialize_chunked(hs_message);

            if (hs_message->no_of_chunks != 1) {
                log_msg(LOG_ERROR, "HANDSHAKE MESSAGE IS NOT 1024 BYTES IN SIZE! Message will not be send");
                np_unref_obj(np_message_t, hs_message, ref_obj_creation);                
            }
            else {
                if (true == serialize_ok)
                {
                    bool network_error = false;
                    NP_PERFORMANCE_POINT_START(handshake_out_network);
                    _LOCK_MODULE(np_network_t)
                    {
                        NP_PERFORMANCE_POINT_END(handshake_out_network);
                        if (NULL == args.target->network)
                        {
                            log_debug_msg(LOG_NETWORK | LOG_DEBUG, "handshake: init client network");
                            // initialize network
                            np_new_obj(np_network_t, args.target->network, ref_key_network);
                            _np_network_init(args.target->network,
                                false,
                                args.target->node->protocol,
                                args.target->node->dns_name,
                                args.target->node->port,
                                -1,
                                UNKNOWN_PROTO
                            );
                            if (false == args.target->network->initialized)
                            {
                                np_unref_obj(np_network_t, args.target->network, ref_key_network);
                                args.target->network = NULL;
                                network_error = true;
                            }
                            else {
                                _np_network_set_key(args.target->network, args.target);
                                _np_network_enable(args.target->network);
                            }
                        }
                    }
                    
                    if (!network_error) {
                        // construct target address and send it out
                        // np_node_t* hs_node = args.target->node;

                        /* send data if handshake status is still just initialized or less */
                        log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE | LOG_DEBUG,
                            "sending handshake message %s to %s",// (%s:%s)",
                            hs_message->uuid, _np_key_as_str(args.target)/*, hs_node->dns_name, hs_node->port*/);

                        char* packet = np_memory_new(context, np_memory_types_BLOB_1024);

                        NP_PERFORMANCE_POINT_START(handshake_out_msg_chunks_lock);
                        _LOCK_ACCESS(&hs_message->msg_chunks_lock) {
                            NP_PERFORMANCE_POINT_END(handshake_out_msg_chunks_lock);
                            memcpy(packet, pll_first(hs_message->msg_chunks)->val->msg_part, 984);
                        }
                        
                        NP_PERFORMANCE_POINT_START(handshake_out_events_lock);
                        _LOCK_ACCESS(&args.target->network->out_events_lock)
                        {
                            NP_PERFORMANCE_POINT_END(handshake_out_events_lock);

                            if (NULL != args.target->network->out_events) {
                                sll_append(
                                    void_ptr,
                                    args.target->network->out_events,
                                    (void*)packet);
                                _np_network_start(args.target->network, true);
                            }
                            else {
                                log_msg(LOG_ERROR, "Dropping data package due to not initialized out_events");
                                np_memory_free(context, packet);
                            }
                        }
                        _np_message_trace_info("out", hs_message);
                        __np_axon_invoke_on_user_send_callbacks(hs_message, hs_prop);
                    }
                }
                np_unref_obj(np_message_t, hs_message, ref_obj_creation);
            }
        }
    }
    NP_PERFORMANCE_POINT_END(handshake_out);
}

void _np_out_discovery_messages(np_state_t* context, np_jobargs_t args)
{
    
    log_trace_msg(LOG_TRACE, "start: void _np_out_discovery_messages(np_state_t* context, np_jobargs_t args){");
    np_message_intent_public_token_t* msg_token = NULL;

    if (_np_route_my_key_has_connection(context))
    {
        // cleanup of msgs in property receiver msg cache
        _np_msgproperty_cleanup_receiver_cache(args.properties);
        // upsert message intent token
        msg_token = _np_msgproperty_upsert_token(args.properties);

        _TRYLOCK_ACCESS(&args.properties->send_discovery_msgs_lock) {			
            NP_PERFORMANCE_POINT_START(msg_discovery_out);

            // args.target == Key of subject
            np_dhkey_t target_dhkey = np_dhkey_create_from_hostport( args.properties->msg_subject, "0");

            if (FLAG_CMP(args.properties->mode_type, INBOUND))
            {
                log_msg(LOG_INFO, "refresh of inbound  subject token, subject: %25s uuid: %s", args.properties->msg_subject, msg_token->uuid);
                //if (args.properties->current_receive_token != msg_token) 
                {
                    np_ref_switch(np_aaatoken_t, args.properties->current_receive_token, ref_msgproperty_current_recieve_token, msg_token);
                    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding token for subject %p / %s", msg_token, msg_token->uuid);
                    np_tree_t* _data = np_tree_create();
                    np_aaatoken_encode(_data, msg_token);

                    np_message_t* msg_out = NULL;
                    np_new_obj(np_message_t, msg_out);
                    _np_message_create(
                        msg_out,
                        target_dhkey,
                        context->my_node_key->dhkey,
                        _NP_MSG_DISCOVER_SENDER,
                        _data
                    );
                    double now = np_time_now(); 
                    np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d(now));
                    np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(msg_token->expires_at-now));

                    // send message availability
                    np_msgproperty_t* prop_route = np_msgproperty_get(context, OUTBOUND, _NP_MSG_DISCOVER_SENDER);
                    np_tree_insert_str( msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop_route->ack_mode));
#ifdef DEBUG
                    np_tree_insert_str( msg_out->header, "_np.debug.discovery.subj", np_treeval_new_s(args.properties->msg_subject));
#endif
                    _np_job_submit_route_event(context, 0.0, prop_route, NULL, msg_out);

                    np_unref_obj(np_message_t, msg_out, ref_obj_creation);
                }
            }

            if (FLAG_CMP(args.properties->mode_type, OUTBOUND) )
            {
                log_msg(LOG_INFO, "refresh of outbound subject token, subject: %25s uuid: %s", args.properties->msg_subject, msg_token->uuid);
                //if (args.properties->current_sender_token != msg_token) 
                {
                    np_ref_switch(np_aaatoken_t, args.properties->current_sender_token, ref_msgproperty_current_sender_token, msg_token);

                    np_tree_find_str(msg_token->extensions, "msg_threshold")->val.value.ui = args.properties->msg_threshold;

                    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding token for subject %p / %s", msg_token, msg_token->uuid);

                    np_tree_t* _data = np_tree_create();
                    np_aaatoken_encode(_data, msg_token);

                    np_message_t* msg_out = NULL;
                    np_new_obj(np_message_t, msg_out);

                    _np_message_create(
                        msg_out,
                        target_dhkey,
                        context->my_node_key->dhkey,
                        _NP_MSG_DISCOVER_RECEIVER,
                        _data
                    );
                    // send message availability
                    np_msgproperty_t* prop_route =
                        np_msgproperty_get(context, 
                            OUTBOUND,
                            _NP_MSG_DISCOVER_RECEIVER
                        );
                    double now = np_time_now();
                    np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d(now));
                    np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(msg_token->expires_at - now));
                    
                    np_tree_insert_str( msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop_route->ack_mode));
#ifdef DEBUG
                    np_tree_insert_str( msg_out->header, "_np.debug.discovery.subj", np_treeval_new_s(args.properties->msg_subject));
#endif
                    _np_job_submit_route_event(context, 0.0, prop_route, NULL, msg_out);
                    np_unref_obj(np_message_t, msg_out, ref_obj_creation);
                }
            }

            NP_PERFORMANCE_POINT_END(msg_discovery_out);
        }

        np_unref_obj(np_aaatoken_t, msg_token, "_np_msgproperty_upsert_token");
    } else {
        log_msg(LOG_AAATOKEN | LOG_DEBUG, "--- cont refresh: but no connections left ...");
    }
}

// deprecated
void _np_out_receiver_discovery(np_state_t* context, np_jobargs_t args)
{    
    log_trace_msg(LOG_TRACE, "start: void _np_out_receiver_discovery(np_state_t* context, np_jobargs_t args){");
    // create message interest in authentication request
    np_aaatoken_t* msg_token = NULL;

    msg_token = _np_aaatoken_get_sender_token(context, args.properties->msg_subject,
                                        &context->my_node_key->dhkey);

    if (NULL == msg_token)
    {
        log_debug_msg(LOG_ROUTING | LOG_AAATOKEN | LOG_DEBUG, "creating new sender token for subject %s", args.properties->msg_subject);
        np_aaatoken_t* msg_token_new = _np_token_factory_new_message_intent_token(args.properties);
        np_ref_obj(np_aaatoken_t, msg_token_new); // usage ref
        msg_token  = _np_aaatoken_add_sender(msg_token_new->subject, msg_token_new);
        np_unref_obj(np_aaatoken_t, msg_token, "_np_aaatoken_add_sender");
        msg_token = msg_token_new;
        ref_replace_reason(np_aaatoken_t, msg_token, ref_obj_creation,"_np_aaatoken_get_sender_token")
    }

    np_tree_t* _data = np_tree_create();
    np_aaatoken_encode(_data, msg_token);

    np_message_t* msg_out = NULL;
    np_new_obj(np_message_t, msg_out);

    np_msgproperty_t* prop_route = np_msgproperty_get(context, OUTBOUND, _NP_MSG_DISCOVER_RECEIVER);
    _np_message_create(msg_out, args.target->dhkey, context->my_node_key->dhkey, _NP_MSG_DISCOVER_RECEIVER, _data);
    np_tree_insert_str( msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop_route->ack_mode));

    // send message availability
    _np_job_submit_route_event(context, 0.0, prop_route, args.target, msg_out);
    np_unref_obj(np_message_t, msg_out,ref_obj_creation);

    np_unref_obj(np_aaatoken_t, msg_token,"_np_aaatoken_get_sender_token");
}

// deprecated
void _np_out_sender_discovery(np_state_t* context, np_jobargs_t args)
{
    
    log_trace_msg(LOG_TRACE, "start: void _np_out_sender_discovery(np_state_t* context, np_jobargs_t args){");
    // create message interest in authentication request
    np_aaatoken_t* msg_token = NULL;

    msg_token = _np_aaatoken_get_receiver(context, args.properties->msg_subject, NULL);

    if (NULL == msg_token)
    {
        log_debug_msg(LOG_ROUTING | LOG_AAATOKEN | LOG_DEBUG, "creating new receiver token for subject %s", args.properties->msg_subject);
        np_aaatoken_t* msg_token_new = _np_token_factory_new_message_intent_token(args.properties);
        np_ref_obj(np_aaatoken_t, msg_token_new); // usage ref
        msg_token = _np_aaatoken_add_receiver(msg_token_new->subject, msg_token_new);
        np_unref_obj(np_aaatoken_t, msg_token_new, "_np_aaatoken_add_receiver");
        msg_token = msg_token_new;
    }

    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding receiver token for subject %p / %s", msg_token, msg_token->uuid);
    np_tree_t* _data = np_tree_create();
    np_aaatoken_encode(_data, msg_token);

    np_message_t* msg_out = NULL;
    np_new_obj(np_message_t, msg_out);
    _np_message_create(msg_out, args.target->dhkey, context->my_node_key->dhkey, _NP_MSG_DISCOVER_SENDER, _data);
    np_msgproperty_t* prop_route = np_msgproperty_get(context, OUTBOUND, _NP_MSG_DISCOVER_SENDER);
    np_tree_insert_str( msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop_route->ack_mode));

    // send message availability
    _np_job_submit_route_event(context, 0.0, prop_route, args.target, msg_out);

    np_unref_obj(np_message_t, msg_out,ref_obj_creation);

    np_unref_obj(np_aaatoken_t, msg_token, "_np_aaatoken_get_receiver");
}

void _np_out_authentication_request(np_state_t* context, np_jobargs_t args)
{
    
    log_trace_msg(LOG_TRACE, "start: void _np_out_authentication_request(np_state_t* context, np_jobargs_t args){");

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

    np_msgproperty_t* aaa_props = np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHENTICATION_REQUEST);

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
}

void _np_out_authentication_reply(np_state_t* context, np_jobargs_t args)
{
    
    log_trace_msg(LOG_TRACE, "start: void _np_out_authentication_reply(np_state_t* context, np_jobargs_t args){");

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

    np_msgproperty_t* aaa_props = np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHENTICATION_REPLY);

    // create and send authentication reply
    if (false == _np_send_msg(_NP_MSG_AUTHENTICATION_REPLY, args.msg, aaa_props, NULL))
    {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending authentication reply discovery");
        np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
        _np_out_receiver_discovery(context, jargs);
    }
    np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
}

void _np_out_authorization_request(np_state_t* context, np_jobargs_t args)
{
     
    log_trace_msg(LOG_TRACE, "start: void _np_out_authorization_request(np_state_t* context, np_jobargs_t args){");

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

    np_msgproperty_t* aaa_props = np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHORIZATION_REQUEST);

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
}

void _np_out_authorization_reply(np_state_t* context, np_jobargs_t args)
{
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

    np_msgproperty_t* aaa_props = np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHORIZATION_REPLY);

    // create and send authentication reply
    if (false == _np_send_msg(_NP_MSG_AUTHORIZATION_REPLY, args.msg, aaa_props, NULL))
    {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending authorization reply discovery");
        np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
        _np_out_receiver_discovery(context, jargs);
    }
    np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
}

void _np_out_accounting_request(np_state_t* context, np_jobargs_t args)
{
    
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
    np_msgproperty_t* aaa_props = np_msgproperty_get(context, OUTBOUND, _NP_MSG_ACCOUNTING_REQUEST);

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
}
