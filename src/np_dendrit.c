//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "sodium.h"
#include "event/ev.h"
#include "msgpack/cmp.h"

#include "np_dendrit.h"

#include "np_statistics.h"
#include "np_axon.h"
#include "np_log.h"
#include "np_legacy.h"
#include "np_aaatoken.h"
#include "np_token_factory.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_memory.h"
#include "np_list.h"
#include "np_route.h"
#include "np_util.h"
#include "np_types.h"
#include "np_threads.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "np_axon.h"
#include "np_event.h"
#include "np_constants.h"
#include "np_responsecontainer.h"
#include "np_serialization.h"
#include "np_bootstrap.h"
#include "neuropil.h"

/*
will always call all handlers, but will return false if any of the handlers returns false
*/
bool _np_in_invoke_user_receive_callbacks(np_message_t * msg_in, np_msgproperty_t* msg_prop) {
    bool ret = true;
    np_ctx_memory(msg_in);

    ASSERT(msg_prop != NULL, "msg property cannot be null");

    // set msg property if not already set
    if (msg_in->msg_property == NULL) {
        np_ref_obj(np_msgproperty_t, msg_prop, ref_message_msg_property);
        msg_in->msg_property = msg_prop;
    }

    log_debug(LOG_MESSAGE, "(msg: %s) Invoking user callbacks", msg_in->uuid);
    // call user callbacks
    sll_iterator(np_usercallback_ptr) iter_usercallbacks = sll_first(msg_prop->user_receive_clb);
    while (iter_usercallbacks != NULL)
    {
        ret = iter_usercallbacks->val->fn(context, msg_in, msg_in->body, iter_usercallbacks->val->data) && ret;
        sll_next(iter_usercallbacks);
    }
    log_debug(LOG_MESSAGE | LOG_VERBOSE, "(msg: %s) Invoked user callbacks", msg_in->uuid);

    // call msg on_reply if applyable
    np_tree_elem_t* response_uuid = np_tree_find_str(msg_in->instructions, _NP_MSG_INST_RESPONSE_UUID);
    if(response_uuid != NULL) {
        // is response to
        np_responsecontainer_t *entry = _np_responsecontainers_get_by_uuid(context, np_treeval_to_str(response_uuid->val, NULL));

        /* just an acknowledgement of own messages send out earlier */
        //TODO: add msgpropery cmp function to replace strcmp
        if (entry != NULL && entry->msg != NULL && entry->msg->msg_property->rep_subject != NULL && strcmp(msg_prop->msg_subject, entry->msg->msg_property->rep_subject) == 0)
        {
            _np_responsecontainer_received_response(entry, msg_in);
            log_debug_msg(LOG_ROUTING | LOG_MESSAGE | LOG_DEBUG, "received response of uuid=%s", np_treeval_to_str(response_uuid->val, NULL));
        }
        np_unref_obj(np_responsecontainer_t, entry, "_np_responsecontainers_get_by_uuid");
    }

    return ret;
}



bool _np_in_received_decrypt(np_state_t* context, np_key_t* alias_key, void* raw_msg){

    bool ret = false;
    

     if (NULL != alias_key &&
        NULL != alias_key->aaa_token &&
        IS_VALID (alias_key->aaa_token->state) &&
        alias_key->node->session_key_is_set == true
        )
    {
        log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
            "/start decrypting message with alias %s",
            _np_key_as_str(alias_key)
        );

        unsigned char nonce[crypto_secretbox_NONCEBYTES];

        unsigned char dec_msg[MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES];
        memcpy(nonce, raw_msg, crypto_secretbox_NONCEBYTES);                

        int crypto_result = crypto_secretbox_open_easy(dec_msg,
                (const unsigned char *)raw_msg + crypto_secretbox_NONCEBYTES,
                MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES,
                nonce,
                alias_key->node->session.session_key_to_read
        );
                        
        log_debug_msg(LOG_DEBUG | LOG_HANDSHAKE,
            "HANDSHAKE SECRET: using shared secret from %s (mem id: %s) = %"PRIi32" to decrypt data",
            _np_key_as_str(alias_key), 
            np_memory_get_id(alias_key), 
            crypto_result
        );

        if (crypto_result == 0)
        {					
            ret = true;
            log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
                    "correct decryption of message send from %s", _np_key_as_str(alias_key));
            memset(raw_msg, 0, MSG_CHUNK_SIZE_1024);
            memcpy(raw_msg, dec_msg, MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);
        } else {
            char tmp[255];
            log_msg(LOG_WARN,
                "error on decryption of message (source: \"%s\")",
                np_network_get_desc(alias_key,tmp));
        }
    }
    else {
        log_debug_msg(LOG_DEBUG | LOG_HANDSHAKE,
            "HANDSHAKE SECRET: using no shared secret (%s) used alias: %s",
                NULL == alias_key ? "no alias key is provided":
                NULL == alias_key->aaa_token ? "alias key has no aaatoken" :
                !(IS_VALID(alias_key->aaa_token->state)) ? "alias key token is not valid" :
                alias_key->node->session_key_is_set != true ? "alias key node has no session key" :
                "no reason available",
            alias_key == NULL ?"NULL":_np_key_as_str(alias_key)
        );
    }
    return ret;
}


bool _np_in_received_forwarding(
    np_state_t* context, np_msgproperty_t* handler, 
    np_key_t* my_key,np_key_t* alias_key, 
    np_dhkey_t target_dhkey, bool is_direct_msg, 
    np_message_t* msg_in, char* str_msg_subject, 
    bool *forwarded_msg
    ){    

    bool ret = true;
    *forwarded_msg = false;

    // forward the message if
    // a) msg is not for my dhkey
    if (_np_dhkey_cmp(&target_dhkey, &my_key->dhkey) != 0)// || handler == NULL)
    {
        // perform a route lookup
        np_sll_t(np_key_ptr, tmp) = NULL;
        // zero as "consider this node as final target"
        tmp = _np_route_lookup(context, target_dhkey, 0);
        if (0 < sll_size(tmp))
            log_debug_msg(LOG_ROUTING | LOG_DEBUG,
                "msg (%s) route_lookup result 1 = %s",
                msg_in->uuid, _np_key_as_str(sll_first(tmp)->val)
            );

        /* forward the message if
            b) we do have a list of possible forwards
            c) we are not the best possible forward
        */
        if (NULL != tmp &&
            sll_size(tmp) > 0 &&
            (false == _np_dhkey_equal(&sll_first(tmp)->val->dhkey, &my_key->dhkey)))
        {
            *forwarded_msg = true;
        }
        /* try forwarding the message if
        d) it is a direct message (ack / join / ...)
        e) we do have a handler (but we are not the target!)
        */
        if (handler != NULL && is_direct_msg)
        {
            *forwarded_msg = true;
        }

        if (*forwarded_msg)
        {
            log_msg(LOG_INFO, "forwarding message (%s) for subject: %s", msg_in->uuid, str_msg_subject);

            np_msgproperty_t* prop = np_msgproperty_get(context, OUTBOUND, str_msg_subject);
            if (NULL == prop) {
                prop = np_msgproperty_get(context, OUTBOUND, _DEFAULT);
            }
            // TODO: is it necessary to forward with a small penalty to prevent infinite loops?
            _np_job_submit_route_event(context, NP_PI/1000, prop, alias_key, msg_in);
            _np_increment_forwarding_counter();

            np_key_unref_list(tmp, "_np_route_lookup");
            sll_free(np_key_ptr, tmp);

            // if we do not have a handler or the handler has no receive tokens and no send tokens
            // we may cancel further handling
            // FIXME: Only further work on this msg if we are one of the (few) nodes handling this type of msg            
            if (handler == NULL ||
                (
                ( /*msg->subj*/handler->recv_key == NULL || pll_size(handler->recv_key->recv_tokens) <= 0)
                &&
                (handler->send_key == NULL || pll_size(handler->send_key->send_tokens) <= 0)
                )
            )
            {
                ret = false;
            }
        } else {
            np_key_unref_list(tmp, "_np_route_lookup");
            if (NULL != tmp) sll_free(np_key_ptr, tmp);
            log_debug_msg(LOG_ROUTING | LOG_DEBUG,
                        "msg (%s) self handling message for subject '%s'",
                        msg_in->uuid, str_msg_subject);
        }
    }
    return ret;
}

/**
 ** message_received:
 ** is called by network_activate and will be passed received data and size from socket
 */
void _np_in_received(np_state_t* context,np_key_t* alias_key, void* raw_msg)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_received(np_jobargs_t* args){");
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "received msg");
    char* str_msg_subject;
    char str_msg_to[65];
    char str_msg_from[65];

    np_state_t* state = context;
    if (raw_msg != NULL) {            
        np_waitref_obj(np_key_t, state->my_node_key, my_key,"np_waitref_key");
        {
            np_waitref_obj(np_network_t, my_key->network, my_network,"np_waitref_network");
            {
                np_message_t* msg_in = NULL;

                np_new_obj(np_message_t, msg_in);
                _np_message_mark_as_incomming(msg_in);

                log_debug_msg(LOG_MESSAGE, "incomming msg alias_key %s", _np_key_as_str(alias_key));

                bool is_decryption_successful = _np_in_received_decrypt(context, alias_key, raw_msg);                

                bool is_deserialization_successful = _np_message_deserialize_header_and_instructions(msg_in, raw_msg);

                char tmp[255]={0};
                if (is_deserialization_successful == false) {				
                    if(is_decryption_successful == true) {
                        log_msg(LOG_ERROR,
                            "error deserializing message %s after   successful decryption (source: \"%s\")",
                            msg_in->uuid, np_network_get_desc(alias_key,tmp));
                    } else {
                        log_msg(LOG_WARN,
                            "error deserializing message %s after unsuccessful decryption (source: \"%s\")",
                            msg_in->uuid, np_network_get_desc(alias_key,tmp));

                        #ifdef DEBUG
                            char tmp_hex[MSG_CHUNK_SIZE_1024*2+1] = { 0 };
                            log_debug(LOG_VERBOSE | LOG_NETWORK,
                                "(msg: %s) %s",
                                msg_in->uuid, sodium_bin2hex(tmp_hex, MSG_CHUNK_SIZE_1024*2+1, raw_msg, MSG_CHUNK_SIZE_1024)
                            );
                        #endif

                    }
                    np_memory_free(context, raw_msg);
                    
                } else {

                    log_debug_msg(LOG_SERIALIZATION | LOG_MESSAGE | LOG_DEBUG,
                        "deserialized message %s (source: \"%s\")",
                        msg_in->uuid, np_network_get_desc(alias_key,tmp));

                    _np_message_trace_info("in", msg_in);

                    // now read decrypted (or handshake plain text) message
                    CHECK_STR_FIELD_BOOL(msg_in->header, _NP_MSG_HEADER_SUBJECT, msg_subject, "NO SUBJECT IN MESSAGE (%s)", msg_in->uuid) {
                        CHECK_STR_FIELD_BOOL(msg_in->header, _NP_MSG_HEADER_FROM, msg_from,"NO FROM IN MESSAGE (%s)", msg_in->uuid) 
                        {

                            _np_dhkey2str(&msg_from->val.value.dhkey, str_msg_from);
                            str_msg_subject = msg_subject->val.value.s;

                            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "(msg: %s) received msg", msg_in->uuid);

                            bool is_handshake_msg = 0 == strncmp(
                                str_msg_subject,
                                _NP_URN_MSG_PREFIX _NP_MSG_HANDSHAKE,
                                strlen(_NP_URN_MSG_PREFIX _NP_MSG_HANDSHAKE)
                            );

                            bool is_direct_msg =
                                    ( 0 == strncmp(str_msg_subject, _NP_MSG_ACK, strlen(_NP_MSG_ACK)) ||
                                    0 == strncmp(str_msg_subject, _NP_MSG_JOIN, strlen(_NP_MSG_JOIN)) ||
                                    0 == strncmp(str_msg_subject, _NP_MSG_JOIN_REQUEST, strlen(_NP_MSG_LEAVE_REQUEST))
                                    );

                            np_msgproperty_t* handshake_prop = np_msgproperty_get(context, INBOUND, _NP_MSG_HANDSHAKE);

                            if (is_handshake_msg && _np_msgproperty_check_msg_uniquety(handshake_prop, msg_in))
                            {
                                _np_job_submit_msgin_event(0.0, handshake_prop, alias_key, msg_in, NULL);
                            }
                            else if (is_decryption_successful == false) {
                                char tmp[255];
                                log_msg(LOG_WARN,
                                    "(msg: %s) incorrect decryption of message (received via alias %s / %s) (send from %s)",
                                    msg_in->uuid,
                                    _np_key_as_str(alias_key),
                                    np_network_get_desc(alias_key, tmp),
                                    str_msg_from
                                );
                            }
                            else if(alias_key->node->joined_network || is_direct_msg)
                            {
                                /* real receive part */
                                CHECK_STR_FIELD_BOOL(msg_in->header, _NP_MSG_HEADER_TO, msg_to, "NO TO IN MESSAGE (%s)", msg_in->uuid) {
                                    CHECK_STR_FIELD_BOOL(msg_in->instructions, _NP_MSG_INST_TTL, msg_ttl, "NO TTL IN MESSAGE (%s)", msg_in->uuid) {
                                        CHECK_STR_FIELD_BOOL(msg_in->instructions, _NP_MSG_INST_TSTAMP, msg_tstamp, "NO TSTAMP IN MESSAGE (%s)", msg_in->uuid) {
                                            CHECK_STR_FIELD_BOOL(msg_in->instructions, _NP_MSG_INST_SEND_COUNTER, msg_resendcounter, "NO SEND_COUNTER IN MESSAGE (%s)", msg_in->uuid) 
                                            {
                                                _np_dhkey2str(&msg_to->val.value.dhkey, str_msg_to);

                                                log_debug(LOG_ROUTING,
                                                    "msg (%s) target of message for subject: %s from: %s is: %s",
                                                    msg_in->uuid, str_msg_subject, str_msg_from, str_msg_to);

                                                // check time-to-live for message and expiry if neccessary
                                                if (true == _np_message_is_expired(msg_in))
                                                {
                                                    log_msg(LOG_INFO,
                                                        "msg (%s) ttl expired, dropping message (part) %s target: %s",
                                                        msg_in->uuid, str_msg_subject, str_msg_to);
                                                }
                                                else if (msg_resendcounter->val.value.ush > 31) {
                                                    log_msg(LOG_WARN,
                                                        "msg (%s) resend count (%d) too high, dropping message (part) %s target: %s",
                                                        msg_in->uuid, msg_resendcounter->val.value.ush, str_msg_subject, str_msg_to);
                                                }
                                                else {
                                                    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "msg (%s) message ttl not expired", msg_in->uuid);

                                                    np_dhkey_t target_dhkey = msg_to->val.value.dhkey;
                                                    /*
                                                        log_debug_msg(LOG_ROUTING | LOG_DEBUG,
                                                            "target of msg (%s) is %s i am %s",
                                                            msg_in->uuid, msg_to, _np_key_as_str(context->my_node_key)
                                                        );
                                                    */

                                                    // check if inbound subject handler exists
                                                    np_msgproperty_t* handler = np_msgproperty_get(context, INBOUND, str_msg_subject);
                                                    bool forwarded_msg;

                                                    bool forwarded = _np_in_received_forwarding(context, handler, my_key,alias_key, target_dhkey, is_direct_msg, msg_in, str_msg_subject, &forwarded_msg);
                                                    if(forwarded) 
                                                    {
                                                        // we know now: this node is the node nearest to the dhkey

                                                        // if this message really has to be handled by this node, does a handler exists ?
                                                        if (NULL == handler)
                                                        {
                                                            log_msg(LOG_WARN,
                                                                "msg (%s) no incoming callback function was found for type %s, dropping message",
                                                                msg_in->uuid, str_msg_subject);
                                                        } else {
                                                            // sum up message parts if the message is for this node
                                                            np_message_t* msg_to_submit = _np_message_check_chunks_complete(msg_in);
                                                            if (NULL != msg_to_submit)
                                                            {
                                                                log_debug_msg(LOG_ROUTING | LOG_DEBUG, "msg (%s) is now complete", msg_in->uuid);
                                                                _np_in_new_msg_received(msg_to_submit, handler, !forwarded_msg);
                                                                np_unref_obj(np_message_t, msg_to_submit, "_np_message_check_chunks_complete");
                                                            }
                                                            else {
                                                                log_debug_msg(LOG_ROUTING | LOG_DEBUG,
                                                                    "msg (%s) is not complete and waits for other chunks",
                                                                    msg_in->uuid
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }                
                np_unref_obj(np_message_t, msg_in, ref_obj_creation);
            }
            np_unref_obj(np_network_t,my_network,"np_waitref_network");
        }
        np_unref_obj(np_key_t, my_key,"np_waitref_key");
    }
    // __np_return__:
    return;
}

void _np_in_new_msg_received(np_message_t* msg_to_submit, np_msgproperty_t* handler, bool allow_destination_ack) {

    np_ctx_memory(msg_to_submit);

    np_waitref_obj(np_key_t, context->my_node_key, my_key, FUNC);

    CHECK_STR_FIELD(msg_to_submit->instructions, _NP_MSG_INST_ACK, msg_ack);

    if (_np_message_deserialize_chunked(msg_to_submit) == false) {
        log_msg(LOG_WARN,
            "msg (%s) could not deserialize chunked msg", msg_to_submit->uuid);

    } else {

        if (_np_msgproperty_check_msg_uniquety(handler, msg_to_submit)) {             
            
            if(!_np_job_submit_msgin_event(0, handler, my_key, msg_to_submit, NULL)) {
                _np_msgproperty_remove_msg_from_uniquety_list(handler, msg_to_submit);
            } else
            
            {
                log_debug(LOG_MESSAGE, "handling   message (%s) for subject: %s (%d) with function %p",
                        msg_to_submit->uuid, handler->msg_subject, allow_destination_ack, handler->clb_inbound);

                _np_message_trace_info("accepted", msg_to_submit);

                if (allow_destination_ack)
                {
                    _np_send_ack(msg_to_submit, ACK_DESTINATION);
                }            
            }
            //np_job_submit_msgin_event_sync(handler, my_key, msg_to_submit, NULL);
        } else {
            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "msg (%s) is already known", msg_to_submit->uuid);
        }
    }

    __np_cleanup__:
        np_unref_obj(np_key_t, my_key, FUNC);
}

/**
 ** neuropil_piggy_message:
 ** This function is responsible to add the piggy backing node information that is sent along with
 ** other ctrl messages or separately to the routing table. the PIGGY message type is a separate
 ** message type.
 **/
void _np_in_piggy(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_piggy(np_jobargs_t* args) {");
    np_state_t* state = context;
    np_key_t* node_entry = NULL;
    // double tmp_ft;
    np_sll_t(np_key_ptr, o_piggy_list) = NULL;

    o_piggy_list = _np_node_decode_multiple_from_jrb(context, args.msg->body);

    np_waitref_obj(np_key_t, state->my_node_key, my_key, "np_waitref_key");

    log_info(LOG_ROUTING, "received piggy msg (%"PRIu32" nodes)", sll_size(o_piggy_list));

    while (NULL != (node_entry = sll_head(np_key_ptr, o_piggy_list)))
    {
        // add entries in the message to our routing table
        // routing table is responsible to handle possible double entries
        // tmp_ft = node_entry->node->failuretime;

        // TODO: those new entries in the piggy message must be authenticated before sending join requests
        if (false == _np_dhkey_equal(&node_entry->dhkey, &my_key->dhkey) &&
            !FLAG_CMP(node_entry->node->protocol, PASSIVE) &&
            !node_entry->node->joined_network)
        {
            // just record nodes in the network or send an join request as well ?
            // answer: only send join request !
            // if (GRACEPERIOD > (np_time_now() - tmp_ft))
            // {
            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "node %s is qualified for a piggy join.", _np_key_as_str(node_entry));
            _np_send_simple_invoke_request(node_entry, _NP_MSG_JOIN_REQUEST);
        }
        else if (node_entry->node->joined_network &&
                node_entry->node->success_avg > BAD_LINK &&
                (np_time_now() - node_entry->node->last_success) <= BAD_LINK_REMOVE_GRACETIME) {

            // udpate and leafset, as nodes could have left the network and we need to fill up entries
            np_key_t *added = NULL, *deleted = NULL;
            _np_route_leafset_update(node_entry, true, &deleted, &added);

#ifdef DEBUG
            if (added != NULL && deleted != NULL) {
                log_msg(LOG_ROUTING | LOG_INFO, "STABILITY replaced in   leafset: %s:%s:%s / %f / %1.2f replaced %s:%s:%s / %f / %1.2f",
                            _np_key_as_str(added),
                            added->node->dns_name, deleted->node->port,
                            added->node->last_success,
                            added->node->success_avg,

                            _np_key_as_str(deleted),
                            deleted->node->dns_name, deleted->node->port,
                            deleted->node->last_success,
                            deleted->node->success_avg
                );
            }
            else if (added != NULL) {
                log_msg(LOG_ROUTING | LOG_INFO, "STABILITY added    to   leafset: %s:%s:%s / %f / %1.2f",
                            _np_key_as_str(added),
                            added->node->dns_name, added->node->port,
                            added->node->last_success,
                            added->node->success_avg);
            }
            else  if (deleted !=NULL){
                log_msg(LOG_ROUTING | LOG_INFO, "STABILITY deleted  from leafset: %s:%s:%s / %f / %1.2f",
                            _np_key_as_str(deleted),
                            deleted->node->dns_name, deleted->node->port,
                            deleted->node->last_success,
                            deleted->node->success_avg);
            }
#endif

            added = NULL, deleted = NULL;
//          DEACTIVATED due to a missing gracetime during the route network initialisation
// 			_np_route_update(node_entry, true, &deleted, &added);
#ifdef DEBUG
            if (added != NULL && deleted != NULL) {
                log_msg(LOG_ROUTING | LOG_INFO, "STABILITY replaced in   table  : %s:%s:%s / %f / %1.2f replaced %s:%s:%s / %f / %1.2f",
                            _np_key_as_str(added),
                            added->node->dns_name, deleted->node->port,
                            added->node->last_success,
                            added->node->success_avg,

                            _np_key_as_str(deleted),
                            deleted->node->dns_name, deleted->node->port,
                            deleted->node->last_success,
                            deleted->node->success_avg
                    );
            }else  if (added !=NULL){
                log_msg(LOG_ROUTING | LOG_INFO, "STABILITY added    to   table  : %s:%s:%s / %f / %1.2f",
                            _np_key_as_str(added),
                            added->node->dns_name, added->node->port,
                            added->node->last_success,
                            added->node->success_avg);
            } else if (deleted !=NULL){
                log_msg(LOG_ROUTING | LOG_INFO, "STABILITY deleted  from table  : %s:%s:%s / %f / %1.2f",
                            _np_key_as_str(deleted),
                            deleted->node->dns_name, deleted->node->port,
                            deleted->node->last_success,
                            deleted->node->success_avg);
            }
#endif
        } else {
            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "node %s is not qualified for a piggy join. (%s)", _np_key_as_str(node_entry), node_entry->node->joined_network ? "J":"NJ");
        }
        np_unref_obj(np_key_t, node_entry,"_np_node_decode_multiple_from_jrb");
    }
    np_unref_obj(np_key_t, my_key, "np_waitref_key");
    sll_free(np_key_ptr, o_piggy_list);

    // __np_cleanup__:
    // nothing to do
    // __np_return__:
    log_trace_msg(LOG_TRACE, "end  : void _np_in_piggy(np_jobargs_t* args) }");
    return;
}

/** _np_in_signal_np_receive
 ** _np_in_signal_np_receive registered when np_receive function is used to receive message.
 ** it is invoked after a message has been send from the sender of messages and sends a signal to the
 ** np_receive function
 **/
void _np_in_signal_np_receive (np_state_t* context, np_jobargs_t args)
{
    np_message_t* msg_in = args.msg;

    CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_SUBJECT, msg_subject);
    CHECK_STR_FIELD(msg_in->instructions, _NP_MSG_INST_ACK, msg_ack_mode);

    np_msgproperty_t* real_prop = np_msgproperty_get(context, INBOUND, np_treeval_to_str(msg_subject, NULL));

    _np_msgproperty_add_msg_to_recv_cache(real_prop, msg_in);
    _np_threads_condition_signal(context, &real_prop->msg_received);

    // log_debug_msg(LOG_DEBUG, "pushing message into cache %p", real_prop);
    // _LOCK_MODULE(np_msgproperty_t)
    // {
    //		sll_append(np_message_t, real_prop->msg_cache_in, args.msg);
    //		np_ref_obj(np_message_t, args.msg);
    //		// signal the np_receive function that the message has arrived
    //		log_debug_msg(LOG_DEBUG, "signaling via available %p", real_prop);
    // }

    __np_cleanup__:
    // nothing to do
    // __np_return__:
    return;
}

/** _np_in_callback_wrapper
 ** _np_in_callback_wrapper is used when a callback function is used to receive messages
 ** The purpose is automated acknowledge handling in case of ACK_CLIENT message subjects
 ** the user defined callback has to return true in case the ack can be send, or false
 ** if e.g. validation of the message has failed.
 **/
void _np_in_callback_wrapper(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_callback_wrapper(np_jobargs_t* args){");

    np_aaatoken_t* sender_token = NULL;
    np_message_t* msg_in = args.msg;
    bool free_msg_subject = false;
    char* msg_subject;
    log_debug(LOG_MESSAGE, "(msg: %s) start callback wrapper",msg_in->uuid);
    if (args.properties != NULL && args.properties->is_internal)
    {
        log_debug(LOG_VERBOSE|LOG_MESSAGE, "(msg: %s) handeling internal msg",msg_in->uuid);
        _np_in_invoke_user_receive_callbacks(msg_in, args.properties);
        goto __np_cleanup__;
    }

    if(NULL == msg_in)
    {
        log_msg(LOG_ERROR, "message object null but in use! %s",
            ((args.properties == NULL)? "" : args.properties->msg_subject)
        );

        goto __np_cleanup__;
    }

    CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_SUBJECT, msg_subject_ele);    
    CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_from);

    msg_subject = np_treeval_to_str(msg_subject_ele, &free_msg_subject);
    np_msgproperty_t* msg_prop = np_msgproperty_get(context, INBOUND, msg_subject);

    if (true == _np_message_is_expired(msg_in))
    {
        log_debug_msg(LOG_DEBUG,
                      "discarding expired message %s / %s ...",
                      msg_prop->msg_subject, msg_in->uuid);

    } else if (_np_messsage_threshold_breached(msg_prop)) {
        // cleanup of msgs in property receiver msg cache
        _np_msgproperty_add_msg_to_recv_cache(msg_prop, msg_in);
        log_msg(LOG_INFO,"possible message processing overload - retrying later", msg_in->uuid);

        _np_msgproperty_cleanup_receiver_cache(msg_prop);

    } else
    {
        _np_msgproperty_threshold_increase(msg_prop);
        sender_token = _np_aaatoken_get_sender_token(context, (char*)msg_subject,  &msg_from.value.dhkey);
        if (NULL == sender_token)
        {
            _np_msgproperty_add_msg_to_recv_cache(msg_prop, msg_in);
            log_msg(LOG_INFO,"no token to decrypt msg (%s). Retrying later", msg_in->uuid);
        }
        else
        {
            log_debug_msg(LOG_DEBUG, "decrypting message(%s) from sender %s", msg_in->uuid, sender_token->issuer);

            // np_tree_find_str(sender_token->extensions_local, "msg_threshold")->val.value.ui--;

            bool decrypt_ok = _np_message_decrypt_payload(msg_in, sender_token);
            if (true == decrypt_ok) {
                // np_tree_find_str(sender_token->extensions_local, "msg_threshold")->val.value.ui++;

                bool user_result = _np_in_invoke_user_receive_callbacks(msg_in, msg_prop);

                if(user_result)
                {
                    _np_send_ack(args.msg, ACK_CLIENT);
                }
            }
        }
        _np_msgproperty_threshold_decrease(msg_prop);
    }

__np_cleanup__:
    if (free_msg_subject)free(msg_subject);
    np_unref_obj(np_aaatoken_t, sender_token,"_np_aaatoken_get_sender_token"); // _np_aaatoken_get_sender_token

    return;
}

/** _np_in_leave_req:
 ** internal function that is called at the destination of a LEAVE message. This
 ** call encodes the leaf set of the current host and sends it to the joiner.
 **/
void _np_in_leave_req(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_leave_req(np_jobargs_t* args){");
    // np_key_t* leave_req_key = NULL;

    np_tree_elem_t* node_token_ele = np_tree_find_str(args.msg->body, "_np.token.node");
    if (node_token_ele != NULL) {
        np_aaatoken_t* node_token = np_token_factory_read_from_tree(context, node_token_ele->val.value.tree);

        if (node_token != NULL) {
            np_dhkey_t search_key   = np_aaatoken_get_fingerprint(node_token, false);
            np_key_t* leave_req_key = _np_keycache_find(context, search_key);

            np_unref_obj(np_aaatoken_t, node_token, "np_token_factory_read_from_tree");

            if (_np_key_cmp(context->my_node_key, leave_req_key) != 0 &&
                _np_key_cmp(context->my_identity, leave_req_key) != 0 )
            {
                // update node flags
                leave_req_key->node->joined_network = false;
                np_node_set_handshake(leave_req_key->node, np_handshake_status_Disconnected);
                leave_req_key->node->session_key_is_set = false;

                log_debug_msg(LOG_KEY | LOG_DEBUG, "destroy key %s due to leave msg (%s) ", _np_key_as_str(leave_req_key), args.msg->uuid);
                _np_key_destroy(leave_req_key);
            }
            np_unref_obj(np_key_t, leave_req_key, "_np_keycache_find");
        }

    }
    return;
}

/** _np_in_join_req:
 ** internal function that is called at the destination of a JOIN message. This
 ** call encodes the leaf set of the current host and sends it to the joiner.
 **/

void _np_in_join_req(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_join_req(np_jobargs_t* args){");

    np_message_t* msg_out = NULL;

    np_key_t* join_ident_key = NULL;
    np_key_t* join_node_key = NULL;

    np_dhkey_t join_node_dhkey = { 0 };
    np_node_public_token_t* join_node_token = NULL;
    np_dhkey_t join_ident_dhkey = { 0 };
    np_ident_public_token_t* join_ident_token = NULL;

    log_debug_msg(LOG_AAATOKEN | LOG_ROUTING , "check if node token is valid");
    np_tree_elem_t* node_token_ele = np_tree_find_str(args.msg->body, "_np.token.node");
    if (node_token_ele == NULL) {
        // silently exit join protocol for invalid msg syntax
        log_debug_msg(LOG_ROUTING | LOG_VERBOSE , "JOIN request: msg syntax");
        goto __np_cleanup__;
    }

    join_node_token = np_token_factory_read_from_tree(context, node_token_ele->val.value.tree);
    if (join_node_token == NULL ) {
        // silently exit join protocol for unknown node tokens
        log_debug_msg(LOG_ROUTING | LOG_VERBOSE, "JOIN request: missing node token");
        goto __np_cleanup__;
    }
    if (!_np_aaatoken_is_valid(join_node_token, np_aaatoken_type_node)) {
        // silently exit join protocol for invalid token type
        log_debug_msg(LOG_ROUTING | LOG_VERBOSE, "JOIN request: invalid node token");
        goto __np_cleanup__;
    }
    log_debug_msg(LOG_AAATOKEN | LOG_ROUTING , "node token is valid");
    // build a hash to find a place in the dhkey table, not for signing !
    join_node_dhkey = np_aaatoken_get_fingerprint(join_node_token, false);

    np_tree_elem_t* ident_token_ele = np_tree_find_str(args.msg->body, "_np.token.ident");	

    if (ident_token_ele != NULL) { // if not selfsigned

    		join_ident_token = np_token_factory_read_from_tree(context, ident_token_ele->val.value.tree);
        if (false == _np_aaatoken_is_valid(join_ident_token, np_aaatoken_type_identity)) {
            // silently exit join protocol for invalid identity token
            log_debug_msg(LOG_ROUTING | LOG_VERBOSE, "JOIN request: invalid identity token");
            goto __np_cleanup__;
        }
        log_debug_msg(LOG_AAATOKEN | LOG_ROUTING, "join token is valid");
        // build a hash to find a place in the dhkey table, not for signing !
        join_ident_dhkey = np_aaatoken_get_fingerprint(join_ident_token, false);

        np_dhkey_t zero_dhkey = { 0 };
        np_dhkey_t partner_of_ident_dhkey = np_aaatoken_get_partner_fp(join_ident_token);
        if (_np_dhkey_equal(&zero_dhkey,      &partner_of_ident_dhkey) == true ||
        		_np_dhkey_equal(&join_node_dhkey, &partner_of_ident_dhkey) == false)  {
            char fp_n[65], fp_p[65];
            _np_dhkey2str(&join_node_dhkey, fp_n);
            _np_dhkey2str(&partner_of_ident_dhkey, fp_p);
            log_msg(LOG_WARN,
                "JOIN request: node fingerprint must match partner fingerprint in identity token. (node: %s / partner: %s)",
                fp_n, fp_p
            );
            goto __np_cleanup__;
        }

        np_dhkey_t partner_of_node_dhkey = np_aaatoken_get_partner_fp(join_node_token);
        if (_np_dhkey_equal(&zero_dhkey,       &partner_of_node_dhkey) == true ||
        		_np_dhkey_equal(&join_ident_dhkey, &partner_of_node_dhkey) == false)  {
            char fp_i[65], fp_p[65];
            _np_dhkey2str(&join_ident_dhkey, fp_i);
            _np_dhkey2str(&partner_of_node_dhkey, fp_p);
            log_msg(LOG_WARN,
                "JOIN request: identity fingerprint must match partner fingerprint in node token. (identity: %s / partner: %s)",
                fp_i, fp_p
            );
            goto __np_cleanup__;
        }
        // everything is fine and we can continue
        join_ident_key = _np_keycache_find(context, join_ident_dhkey);
        if (join_ident_key == NULL) {
            join_ident_key = _np_keycache_find_or_create(context, join_ident_dhkey);
        		np_ref_obj(np_aaatoken_t, join_ident_token, ref_key_aaa_token);
        		join_ident_key->aaa_token = join_ident_token;
        }
    }
    join_node_key = _np_keycache_find(context, join_node_dhkey);
    if (join_node_key == NULL) {
        // no handshake before join ? exit join protocol ...
        goto __np_cleanup__;
    }
    else if (
        join_node_key->node != NULL &&
        join_node_key->node->joined_network == true)
    {
        // silently exit join protocol as we already joined this key
        log_debug_msg(LOG_ROUTING | LOG_VERBOSE | LOG_DEBUG, "JOIN request: key already joined %s", _np_key_as_str(join_node_key));
        goto __np_cleanup__;
    }

    _np_aaatoken_upgrade_handshake_token(join_node_key, join_node_token);

    // check for allowance of token by user defined function
    bool send_reply = false;
    if (join_ident_key != NULL)
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "JOIN request: ident key %s", _np_key_as_str(join_ident_key));
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "JOIN request:  node key %s", _np_key_as_str(join_node_key));


    struct np_token tmp_user_token = { 0 };
    if (NULL != join_ident_key && IS_NOT_AUTHENTICATED(join_ident_key->aaa_token->state) )
    {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now checking (join/ident) authentication of token");
        bool join_allowed = context->authenticate_func == NULL ? false : context->authenticate_func(context, np_aaatoken4user(&tmp_user_token, join_ident_key->aaa_token));
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "authentication of token: %"PRIu8, join_allowed);

        if (false == context->enable_realm_client &&
            true == join_allowed)
        {
            join_ident_key->aaa_token->state |= AAA_AUTHENTICATED;
            join_node_key->aaa_token->state |= AAA_AUTHENTICATED;
        }
    } else {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now checking (join/node) authentication of token");
        bool join_allowed = false;
		if (IS_AUTHENTICATED(join_node_key->aaa_token->state))
			join_allowed = true;
		else
			join_allowed = context->authenticate_func == NULL ? false : context->authenticate_func(context, np_aaatoken4user(&tmp_user_token, join_node_key->aaa_token));
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "authentication of token: %"PRIu8, join_allowed);
        if (false == context->enable_realm_client &&
            true == join_allowed)
        {
            join_node_key->aaa_token->state |= AAA_AUTHENTICATED;
        }
    }

    CHECK_STR_FIELD(args.msg->instructions, _NP_MSG_INST_UUID, in_uuid);

    //	log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) reset uuid to %s", args.msg->uuid,  np_treeval_to_str(in_uuid, NULL));
    //	free(args.msg->uuid );
    //	args.msg->uuid = strdup( np_treeval_to_str(in_uuid, NULL));

    np_msgproperty_t *msg_prop = NULL;
    np_new_obj(np_message_t, msg_out);

    np_waitref_obj(np_key_t, context->my_node_key, my_key, "np_waitref_key");

    if (IS_AUTHENTICATED(join_node_key->aaa_token->state))
    {
        np_tree_t* jrb_me = np_tree_create();
        np_aaatoken_encode(jrb_me, context->my_node_key->aaa_token);

        _np_message_create(msg_out, join_node_key->dhkey, my_key->dhkey, _NP_MSG_JOIN_ACK, jrb_me);
        np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_RESPONSE_UUID, in_uuid);

        log_msg(LOG_ROUTING | LOG_INFO,
            "JOIN request approved, sending back join acknowledge (%s) for key %s",
            msg_out->uuid, _np_key_as_str(join_node_key));

        msg_prop = np_msgproperty_get(context, OUTBOUND, _NP_MSG_JOIN_ACK);
        my_key->node->joined_network = true;
        join_node_key->node->joined_network = true;

        send_reply = true;
    }

    if (false == context->enable_realm_client &&
        IS_NOT_AUTHENTICATED(join_node_key->aaa_token->state))
    {
        log_msg(LOG_ROUTING | LOG_INFO,
            "JOIN request denied by user implementation, rejected key %s",
            _np_key_as_str(join_node_key));

        _np_message_create(msg_out, join_node_key->dhkey, my_key->dhkey, _NP_MSG_JOIN_NACK, NULL);
        np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_RESPONSE_UUID, in_uuid);

        msg_prop = np_msgproperty_get(context, OUTBOUND, _NP_MSG_JOIN_NACK);
        send_reply = true;
    }
    np_unref_obj(np_key_t, my_key, "np_waitref_key");

    // TODO: chicken egg problem, we have to insert the entry into the table to be able to send back the JOIN.NACK
    np_key_t *added = NULL, *deleted = NULL;
    _np_route_leafset_update(join_node_key, true, &deleted, &added);

#ifdef DEBUG
    if (added != NULL)
        log_debug_msg(LOG_INFO, "added   to   leafset: %s:%s:%s / %f / %1.2f",
            _np_key_as_str(added),
            added->node->dns_name, added->node->port,
            added->node->last_success,
            added->node->success_avg);
    if (deleted != NULL)
        log_debug_msg(LOG_INFO, "deleted from leafset: %s:%s:%s / %f / %1.2f",
            _np_key_as_str(deleted),
            deleted->node->dns_name, deleted->node->port,
            deleted->node->last_success,
            deleted->node->success_avg);
#endif

    added = NULL, deleted = NULL;
    _np_route_update(join_node_key, true, &deleted, &added);

#ifdef DEBUG
    if (added != NULL)
        log_debug_msg(LOG_INFO, "added   to   table  : %s:%s:%s / %f / %1.2f",
            _np_key_as_str(added),
            added->node->dns_name, added->node->port,
            added->node->last_success,
            added->node->success_avg);
    if (deleted != NULL)
        log_debug_msg(LOG_INFO, "deleted from table  : %s:%s:%s / %f / %1.2f",
            _np_key_as_str(deleted),
            deleted->node->dns_name, deleted->node->port,
            deleted->node->last_success,
            deleted->node->success_avg);
#endif

    // TODO: what happens if node is not added to leafset or routing table ?
    if (true == send_reply)
    {
        _np_job_submit_msgout_event(context, 0.0, msg_prop, join_node_key, msg_out);
        if (IS_AUTHENTICATED(join_node_key->aaa_token->state)) {
            np_msgproperty_t* piggy_prop = np_msgproperty_get(context, TRANSFORM, _NP_MSG_PIGGY_REQUEST);
            // add a small delay to prevent the arrival of the piggy message before the join ack
            _np_job_submit_transform_event(context, NP_PI/500, piggy_prop, join_node_key, NULL);
        }
    }

    if (deleted != NULL) {
        _np_send_simple_invoke_request_msg(deleted, _NP_MSG_LEAVE_REQUEST);
    }

__np_cleanup__:
    if (join_ident_key != NULL) {
        np_unref_obj(np_aaatoken_t, join_ident_token, "np_token_factory_read_from_tree");
        np_unref_obj(np_key_t, join_ident_key, "_np_keycache_find_or_create");
    }
    np_unref_obj(np_aaatoken_t, join_node_token, "np_token_factory_read_from_tree");
    np_unref_obj(np_key_t, join_node_key, "_np_keycache_find");

    np_unref_obj(np_message_t, msg_out, ref_obj_creation);
    return;
}

/** _np_in_join_ack:
 ** called when the current node is joining the network and has just received
 ** its leaf set. This function sends an update message to all nodes in its
 ** new leaf set to announce its arrival.
 **/
void _np_in_join_ack(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_join_ack(np_jobargs_t* args){");

    np_state_t* state = context;
    np_waitref_obj(np_key_t, state->my_node_key, my_key);

    np_message_t* msg_out = NULL;
    np_key_t* join_key = NULL;
    np_key_t* routing_key = NULL;

    np_msgproperty_t* out_props = NULL;
    np_node_public_token_t* join_token = np_token_factory_read_from_tree(context, args.msg->body);

    if (false == _np_aaatoken_is_valid(join_token, np_aaatoken_type_node))
    {
        // silently exit join protocol for invalid tokens
        goto __np_cleanup__;
    }

    np_dhkey_t search_key = np_aaatoken_get_fingerprint(join_token, false);
    join_key = _np_keycache_find(context, search_key);

    if (NULL != join_key )
    {
        _np_aaatoken_upgrade_handshake_token(join_key, join_token);
        // if a join ack is received here, then this node has send the join request
        join_key->aaa_token->state |= AAA_AUTHENTICATED;
    }

    if (NULL == join_key)
    {
        goto __np_cleanup__;
    }

    if (NULL != np_tree_find_str(join_token->extensions,  "target_node"))
    {
        np_dhkey_t search_key = np_dhkey_create_from_hash(np_treeval_to_str(np_tree_find_str(join_token->extensions,  "target_node")->val, NULL));
        routing_key = _np_keycache_find(context, search_key);
        routing_key->aaa_token->state |= AAA_AUTHENTICATED;
    }
    else
    {
        routing_key = join_key;
    }

    // should never happen
    if (NULL == routing_key || NULL == routing_key->node)
    {
        goto __np_cleanup__;
    }

    if (NULL != routing_key->node)
    {
        // node cannot be NULL, but checker complains otherwise
        log_msg(LOG_ROUTING | LOG_INFO,
                "received join acknowledgement from node key %s", _np_key_as_str(routing_key));
    }

    /* forward arrival of new node to the nodes with similar hash keys */
    // TODO: check for protected node neighbours ?
    np_sll_t(np_key_ptr, node_keys) = NULL;
    node_keys = _np_route_lookup(context, join_key->dhkey, 2);

    np_key_t* elem = NULL;
    int i = 0;

    while ( NULL != (elem = sll_head(np_key_ptr, node_keys)))
    {
        if(!_np_dhkey_equal(_np_message_get_sender(args.msg), &elem->dhkey)) {
            np_new_obj(np_message_t, msg_out);

            // encode informations -> has to be done for each update message new
            // otherwise there is a crash when deleting the message
            np_tree_t* jrb_join_node = np_tree_create();
            np_aaatoken_encode(jrb_join_node, join_token);

            _np_message_create(msg_out, elem->dhkey, my_key->dhkey, _NP_MSG_UPDATE_REQUEST, jrb_join_node);
            out_props = np_msgproperty_get(context, OUTBOUND, _NP_MSG_UPDATE_REQUEST);
            _np_job_submit_route_event(context, i*NP_PI/500, out_props, elem, msg_out);

            np_unref_obj(np_message_t, msg_out,ref_obj_creation);
        }

        np_unref_obj(np_key_t, elem,"_np_route_lookup");
    }
    np_key_unref_list(node_keys, "_np_route_lookup");
    sll_free(np_key_ptr, node_keys);

    // remember key for routing table update
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "join acknowledged and updates to other nodes send");

    // update table
    np_key_t* added = NULL;
    np_key_t* deleted = NULL;
    _np_route_update(routing_key, true, &deleted, &added);
#ifdef DEBUG
    if (added !=NULL)
        log_debug_msg(LOG_INFO, "added   to   table  : %s:%s:%s / %f / %1.2f",
                        _np_key_as_str(added),
                        added->node->dns_name, added->node->port,
                        added->node->last_success,
                        added->node->success_avg);
    if (deleted !=NULL)
        log_debug_msg(LOG_INFO, "deleted from table: %s:%s:%s / %f / %1.2f",
                        _np_key_as_str(deleted),
                        deleted->node->dns_name, deleted->node->port,
                        deleted->node->last_success,
                        deleted->node->success_avg);
#endif

    // update leafset
    added = NULL, deleted = NULL;
    _np_route_leafset_update(routing_key, true, &deleted, &added);
#ifdef DEBUG
    if (added !=NULL)
        log_debug_msg(LOG_INFO, "added   to   leafset: %s:%s:%s / %f / %1.2f",
                        _np_key_as_str(added),
                        added->node->dns_name, added->node->port,
                        added->node->last_success,
                        added->node->success_avg);
    if (deleted !=NULL)
        log_debug_msg(LOG_INFO, "deleted from leafset: %s:%s:%s / %f / %1.2f",
                        _np_key_as_str(deleted),
                        deleted->node->dns_name, deleted->node->port,
                        deleted->node->last_success,
                        deleted->node->success_avg);
#endif

    _np_send_ack(args.msg, ACK_CLIENT);

    // send an initial piggy message to the new node in our routing table
    np_msgproperty_t* piggy_prop = np_msgproperty_get(context, TRANSFORM, _NP_MSG_PIGGY_REQUEST);
    _np_job_submit_transform_event(context, 0.0, piggy_prop, routing_key, NULL);

    routing_key->node->joined_network = true;
    // just in case it has not been set until now
    my_key->node->joined_network = true;
    _np_bootstrap_confirm(context, join_key);

    __np_cleanup__:
    np_unref_obj(np_key_t, my_key, FUNC);
    np_unref_obj(np_aaatoken_t, join_token, "np_token_factory_read_from_tree");

    // __np_return__:
    if (routing_key != join_key)
        np_unref_obj(np_key_t, routing_key,"_np_keycache_find");
    np_unref_obj(np_key_t, join_key,"_np_keycache_find");

    return;
}

/**
 ** hnd_msg_join_nack
 ** internal function that is called when the sender of a JOIN message receives
 ** the JOIN_NACK message type which is join denial from the current key root
 ** in the network.
 **/
void _np_in_join_nack(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_join_nack(np_jobargs_t* args){");

    np_state_t* state = context;
    np_waitref_obj(np_key_t, state->my_node_key, my_key,"np_waitref_key");

    // np_network_t* ng = my_key->network;
    np_key_t* nack_key = NULL;

    CHECK_STR_FIELD(args.msg->header, _NP_MSG_HEADER_FROM, msg_from);
    CHECK_STR_FIELD(args.msg->instructions, _NP_MSG_INST_RESPONSE_UUID, ack_uuid);

    np_dhkey_t search_key = msg_from.value.dhkey;
    nack_key = _np_keycache_find(context, search_key);

    /*
    //FIXME: Mixing of Transport ACK and BL ACK
    _LOCK_ACCESS(&ng->send_data_lock)
    {
        np_tree_elem_t *jrb_node = np_tree_find_str(ng->waiting,  np_treeval_to_str(ack_uuid));
        if (jrb_node != NULL)
        {
            np_responsecontainer_t *entry = (np_responsecontainer_t *) jrb_node->val.value.v;
            entry->has_received_nack = true;
            entry->received_at = np_time_now();
            //todo handle ack
            log_debug_msg(LOG_DEBUG, "received not-acknowledgment of JOIN uuid=%s",  np_treeval_to_str(ack_uuid));
        }
    }
    */

    // should never happen
    if (NULL == nack_key || NULL == nack_key->node)
    {
        return;
    }

    log_msg(LOG_ROUTING | LOG_INFO, "JOIN request rejected from key %s !", _np_key_as_str(nack_key));

    // update table
    np_key_t* added = NULL;
    np_key_t* deleted = NULL;
    _np_route_update(nack_key, false, &deleted, &added);
#ifdef DEBUG
    if (deleted !=NULL)
        log_debug_msg(LOG_INFO, "deleted from table  : %s:%s:%s / %f / %1.2f",
                        _np_key_as_str(deleted),
                        deleted->node->dns_name, deleted->node->port,
                        deleted->node->last_success,
                        deleted->node->success_avg);
#endif

    // update leafset
    added = NULL, deleted = NULL;
    _np_route_leafset_update(nack_key, false, &deleted, &added);
#ifdef DEBUG
    if (deleted !=NULL)
        log_debug_msg(LOG_INFO, "deleted from leafset: %s:%s:%s / %f / %1.2f",
                        _np_key_as_str(deleted),
                        deleted->node->dns_name, deleted->node->port,
                        deleted->node->last_success,
                        deleted->node->success_avg);
#endif

    nack_key->aaa_token->state &= (~AAA_AUTHENTICATED);
    nack_key->node->joined_network = false;
    np_node_set_handshake(nack_key->node, np_handshake_status_Disconnected);

    __np_cleanup__:
    // nothing to do
    // __np_return__:

    np_unref_obj(np_key_t, nack_key,"_np_keycache_find");
    np_unref_obj(np_key_t, my_key,"np_waitref_key");
    return;
}

void __np_in_ack_handle(np_message_t * msg)
{
    np_ctx_memory(msg);
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "msg (%s) handling acknowledgment", msg->uuid);

    np_waitref_obj(np_key_t, context->my_node_key, my_key);
    np_waitref_obj(np_network_t, my_key->network, my_network);

    CHECK_STR_FIELD(msg->instructions, _NP_MSG_INST_RESPONSE_UUID, ack_uuid);
    np_responsecontainer_t *entry = _np_responsecontainers_get_by_uuid(context, ack_uuid.value.s);

    /* just an acknowledgement of own messages send out earlier */
    if(entry != NULL)
    {
        log_debug_msg(LOG_ROUTING | LOG_MESSAGE | LOG_DEBUG, "msg (%s) is acknowledgment of uuid=%s",
                                                              msg->uuid, np_treeval_to_str(ack_uuid, NULL));
        _np_responsecontainer_received_ack(entry);
    }
    else {
        log_debug_msg(LOG_ROUTING | LOG_MESSAGE | LOG_DEBUG, "msg (%s) is acknowledgment of uuid=%s but we do not know of this msg",
                                                              msg->uuid, np_treeval_to_str(ack_uuid, NULL));
    }
    np_unref_obj(np_responsecontainer_t, entry, "_np_responsecontainers_get_by_uuid");

    __np_cleanup__:
    np_unref_obj(np_network_t, my_network,FUNC);
    np_unref_obj(np_key_t, my_key, FUNC);
}

void _np_in_ack(NP_UNUSED  np_state_t* context, np_jobargs_t args)
{
    __np_in_ack_handle(args.msg);
}

// TODO: write a function that handles path discovery
// TODO: if this is not the target node, add my own address to the update message
// TODO: if this is the target node, change target to sending instance and send again

// receive information about new nodes in the network and try to contact new nodes
void _np_in_update(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_update(np_jobargs_t* args){");

    np_key_t *update_key = NULL;
    np_aaatoken_t* update_token = np_token_factory_read_from_tree(context, args.msg->body);

    if (false == _np_aaatoken_is_valid(update_token, np_aaatoken_type_node))
    {
        goto __np_cleanup__;
    }

    _LOCK_MODULE(np_keycache_t)
    {
        update_key = _np_key_create_from_token(update_token);
    }

    if (NULL == update_key->aaa_token)
    {
        np_ref_switch(np_aaatoken_t, update_key->aaa_token, ref_key_aaa_token, update_token);
    }

    if (NULL != update_key &&
        NULL != update_key->node &&
        !FLAG_CMP(update_key->node->protocol, PASSIVE) &&
        false == update_key->node->joined_network)
    {
        // do not join myself
        if(0 != _np_key_cmp(update_key, context->my_identity)
        && 0 != _np_key_cmp(update_key, context->my_node_key))
        {
            /*
            char* connection_str = np_get_connection_string_from(
                    update_key,false);
            np_key_t* old_key = _np_keycache_find_by_details(
                    connection_str, false, false,false,
                    false, true, true, false);
            free(connection_str);

            if(NULL != old_key)
            {
                log_msg(LOG_ROUTING | LOG_INFO,
                    "Node %s replaces itself with node %s",
                    _np_key_as_str(args.target),
                    _np_key_as_str(update_key)
                    );

                if(old_key->network != NULL)
                {
                    _np_network_remap_network(update_key, old_key);
                }
                np_unref_obj(np_key_t, old_key,"_np_keycache_find_by_details");
            }
            */
            log_debug_msg(LOG_ROUTING | LOG_DEBUG,
            "Sending join %s:%s",
            // np_network_get_ip(update_key), np_network_get_port(update_key);
                args.target->node->dns_name, update_key->node->port);
            _np_send_simple_invoke_request(update_key, _NP_MSG_JOIN_REQUEST);
        }
    } else {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "Sending no join");
    }

    // TODO: forward update token to other neighbours
    __np_cleanup__:
    np_unref_obj(np_key_t, update_key,"_np_key_create_from_token");
    np_unref_obj(np_aaatoken_t, update_token, "np_token_factory_read_from_tree");

    // nothing to do
    // __np_return__:
    return;
}

void _np_dendrit_propagate_receivers(np_dhkey_t target_to_receive_tokens, np_message_intent_public_token_t* sender_msg_token, NP_UNUSED bool inform_counterparts) {
    np_ctx_memory(sender_msg_token);
    np_sll_t(np_aaatoken_ptr, available_list) =
        _np_aaatoken_get_all_receiver(context, sender_msg_token->subject, sender_msg_token->audience);

    np_msgproperty_t* prop_route =
        np_msgproperty_get(context,
            OUTBOUND,
            _NP_MSG_AVAILABLE_RECEIVER);

    _np_dendrit_propagate_list(prop_route, target_to_receive_tokens, available_list);
    np_aaatoken_unref_list(available_list, "_np_aaatoken_get_all_receiver");
    sll_free(np_aaatoken_ptr, available_list);

    // TODO: deprecated
    // reason: any system should not be able to inflict traffic on peer nodes by sending message intents.
    // message intents already bear a danger of being misused for flooding the network
    // by just returning data to the sender the main conflict will be caused at the initiator of the traffic
    /*
    if(inform_counterparts){
        available_list = _np_aaatoken_get_all_sender(context, sender_msg_token->subject, sender_msg_token->audience);

        sll_iterator(np_aaatoken_ptr) iter_sender_tokens = sll_first(available_list);
        while (iter_sender_tokens != NULL)
        {
            np_tree_elem_t* target_ele = np_tree_find_str(iter_sender_tokens->val->extensions, "target_node");

            np_dhkey_t target_key;
            if (target_ele != NULL) {
                target_key = np_dhkey_create_from_hash(np_treeval_to_str(target_ele->val, NULL));
            }
            else {
                target_key = _np_aaatoken_get_issuer(iter_sender_tokens->val);
            }

            _np_dendrit_propagate_senders(target_key, sender_msg_token, false);
            sll_next(iter_sender_tokens);
        }

        np_aaatoken_unref_list(available_list, "_np_aaatoken_get_all_sender");
        sll_free(np_aaatoken_ptr, available_list);
    }
    */
}

void _np_dendrit_propagate_senders(np_dhkey_t target_to_receive_tokens, np_message_intent_public_token_t* receiver_msg_token, NP_UNUSED bool inform_counterparts) {

    np_ctx_memory(receiver_msg_token);
    np_sll_t(np_aaatoken_ptr, available_list) =
        _np_aaatoken_get_all_sender(context, receiver_msg_token->subject, receiver_msg_token->audience);

    np_msgproperty_t* prop_route =
        np_msgproperty_get(context,
            OUTBOUND,
            _NP_MSG_AVAILABLE_SENDER);

    _np_dendrit_propagate_list(prop_route, target_to_receive_tokens, available_list);
    np_aaatoken_unref_list(available_list, "_np_aaatoken_get_all_sender");
    sll_free(np_aaatoken_ptr, available_list);

    // TODO: deprecated
    // reason: any system should not be able to inflict traffic on peer nodes by sending message intents.
    // message intents already bear a danger of being misused for flooding the network
    // by just returning data to the sender the main conflict will be caused at the initiator of the traffic
    /*
    if (inform_counterparts) {
        available_list = _np_aaatoken_get_all_receiver(context, receiver_msg_token->subject, receiver_msg_token->audience);

        sll_iterator(np_aaatoken_ptr) iter_receiver_tokens = sll_first(available_list);
        while (iter_receiver_tokens != NULL)
        {

            np_tree_elem_t* target_ele = np_tree_find_str(iter_receiver_tokens->val->extensions, "target_node");

            np_dhkey_t target_key;
            if (target_ele != NULL) {
                target_key = np_dhkey_create_from_hash(np_treeval_to_str(target_ele->val, NULL));
            }
            else {
                target_key = _np_aaatoken_get_issuer(iter_receiver_tokens->val);
            }
            _np_dendrit_propagate_receivers(target_key, receiver_msg_token, false);
            sll_next(iter_receiver_tokens);
        }

        np_aaatoken_unref_list(available_list, "_np_aaatoken_get_all_receiver");
        sll_free(np_aaatoken_ptr, available_list);
    }
    */
}

void _np_dendrit_propagate_list(np_msgproperty_t* subject_property, np_dhkey_t target, np_sll_t(np_aaatoken_ptr, list_to_send)) {
    np_ctx_memory(subject_property);
    np_aaatoken_t * tmp_token;
    np_tree_t * available_data;
    np_message_t * msg_out = NULL;
    np_dhkey_t tmp_token_issuer;

    sll_iterator(np_aaatoken_ptr) iter_list_to_send = sll_first(list_to_send);

    while (iter_list_to_send != NULL)
    {
        tmp_token = iter_list_to_send->val;
        sll_next(iter_list_to_send);

        tmp_token_issuer = _np_aaatoken_get_issuer(tmp_token);

        // do not send the msgtoken to its own issuer (remove clutter)
        if (_np_dhkey_cmp(&target, &tmp_token_issuer) != 0)
        {
            available_data = np_tree_create();
            np_aaatoken_encode(available_data, tmp_token);

            np_new_obj(np_message_t, msg_out);
            _np_message_create(
                msg_out,
                target,
                context->my_node_key->dhkey,
                subject_property->msg_subject,
                available_data
            );

            np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(subject_property->ack_mode));


            log_debug_msg(LOG_ROUTING | LOG_DEBUG,
                "discovery success: sending back message (%s) %s token %s ...",
                msg_out->uuid, subject_property->msg_subject, tmp_token->uuid
            );

            _np_job_submit_route_event(context, 0.0, subject_property, NULL, msg_out);

            np_unref_obj(np_message_t, msg_out, ref_obj_creation);
        }
    }
}

void _np_in_discover_sender(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_discover_sender(np_jobargs_t* args){");
    np_dhkey_t reply_to_key = { 0 };

    assert(args.msg != NULL);
    assert(args.msg->header != NULL);

    np_aaatoken_t* msg_token = NULL;
    CHECK_STR_FIELD(args.msg->header, _NP_MSG_HEADER_FROM, msg_reply_to);
    reply_to_key = msg_reply_to.value.dhkey;

    // extract e2e encryption details for sender
    msg_token = np_token_factory_read_from_tree(context, args.msg->body);

    if (_np_aaatoken_is_valid(msg_token, np_aaatoken_type_message_intent))
    {
        // just store the available tokens in memory and update them if new data arrives
        log_debug_msg(LOG_ROUTING | LOG_AAATOKEN | LOG_DEBUG, "discovery: received new receiver token %s for %s",msg_token->uuid, msg_token->subject);

        np_aaatoken_t* old_token = _np_aaatoken_add_receiver(msg_token->subject, msg_token);

        // this node is the man in the middle - inform receiver of sender token
        _np_dendrit_propagate_senders(reply_to_key, msg_token, false);
        // _np_dendrit_propagate_senders(reply_to_key, msg_token, old_token == NULL || strncmp(msg_token->uuid, old_token->uuid, UUID_SIZE)!=0);
        np_unref_obj(np_aaatoken_t, old_token, "_np_aaatoken_add_receiver");

    }
    else if(msg_token!=NULL) {
        log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token %s will not receive the available senders.", msg_token->uuid);
    }

    __np_cleanup__:
        np_unref_obj(np_aaatoken_t, msg_token, "np_token_factory_read_from_tree");

    // __np_return__:
    return;
}

void _np_in_available_sender(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_available_sender(np_jobargs_t* args){");

    np_message_t *msg_in = args.msg;

    // extract e2e encryption details for sender
    np_message_intent_public_token_t* msg_token = NULL;
    CHECK_STR_FIELD(args.msg->header, _NP_MSG_HEADER_TO, msg_to);

    msg_token = np_token_factory_read_from_tree(context, msg_in->body);

    // always?: just store the available tokens in memory and update them if new data arrives
    if (false == _np_aaatoken_is_valid(msg_token, np_aaatoken_type_message_intent))
    {
        if(msg_token != NULL){
            log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token %s will not be added to the available senders.", msg_token->uuid);
        }
        goto __np_cleanup__;
    }

    np_state_t* state = context;

    np_dhkey_t sendtoken_issuer_key = np_dhkey_create_from_hash(msg_token->issuer);
    if (_np_dhkey_equal(&sendtoken_issuer_key, &state->my_node_key->dhkey) )
    {
        // only add the token if it is not from ourself (in case of IN/OUTBOUND on same subject)
        // TODO CHECK IF NESSECARY
        // goto __np_cleanup__;
    }
    np_aaatoken_t* old_token = _np_aaatoken_add_sender(msg_token->subject, msg_token);
    np_unref_obj(np_aaatoken_t, old_token, "_np_aaatoken_add_sender");

    np_dhkey_t to_key = msg_to.value.dhkey;
    if (old_token &&
    		memcmp(old_token->uuid, msg_token->uuid, NP_UUID_BYTES) == 0 )
    {
		msg_token->state = old_token->state;
    }

    if ( _np_dhkey_equal(&to_key, &state->my_node_key->dhkey) )
    {        
		struct np_token tmp;
    		if (!IS_AUTHENTICATED(msg_token->state)) {
    			log_debug(LOG_ROUTING | LOG_AAATOKEN, "now checking (available sender) authentication of token");
    			bool authenticated = state->authenticate_func(context, np_aaatoken4user(&tmp, msg_token));
    			log_debug(LOG_ROUTING | LOG_AAATOKEN, "result of token authentication: %"PRIu8, authenticated);

    			if (authenticated) {
    				msg_token->state |= AAA_AUTHENTICATED;
    			}
    		}

    		if (!IS_AUTHORIZED(msg_token->state)) {
            log_debug(LOG_ROUTING | LOG_AAATOKEN, "now checking (available sender) authorization of token");
            bool authorized = state->authorize_func(context, np_aaatoken4user(&tmp, msg_token));
            log_debug(LOG_ROUTING | LOG_AAATOKEN, "result of token authorization: %"PRIu8, authorized);
            if (authorized) {
                msg_token->state |= AAA_AUTHORIZED;
            }
        }
    }

    // check if some messages are left in the cache
    np_msgproperty_t* real_prop = np_msgproperty_get(context, INBOUND, msg_token->subject);
    // check if we are (one of the) receiving node(s) of this kind of message
    if ( NULL != real_prop)
    {
        _np_msgproperty_check_receiver_msgcache(real_prop, _np_aaatoken_get_issuer(msg_token));
    }

    __np_cleanup__:
        np_unref_obj(np_aaatoken_t, msg_token, "np_token_factory_read_from_tree");

    // __np_return__:
    return;
}

void _np_in_discover_receiver(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_discover_receiver(np_jobargs_t* args){");

    np_message_intent_public_token_t* msg_token = NULL;
    np_message_t *msg_in = args.msg;

        CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_reply_to);
        np_dhkey_t reply_to_key = msg_reply_to.value.dhkey;
#ifdef DEBUG
        char reply_to_dhkey_as_str[65];
        _np_dhkey2str(&reply_to_key, reply_to_dhkey_as_str);
#endif
        log_debug_msg(LOG_ROUTING, "reply key: %s", reply_to_dhkey_as_str );

        // extract e2e encryption details for sender
        msg_token = np_token_factory_read_from_tree(context, msg_in->body);

        // always?: just store the available messages in memory and update if new data arrives
        if (false == _np_aaatoken_is_valid(msg_token, np_aaatoken_type_message_intent))
        {
            if(msg_token != NULL){
                log_debug_msg(LOG_ROUTING | LOG_AAATOKEN | LOG_DEBUG, "token %s will not receive the available receivers.", msg_token->uuid);
            }else{
                log_warn(LOG_ROUTING | LOG_AAATOKEN, "DISCOVER.RECEIVER msg does not contain token");
            }
            goto __np_cleanup__;
        }

        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "discovery: received new sender token %s for %s",msg_token->uuid, msg_token->subject);

        np_aaatoken_t* old_token = _np_aaatoken_add_sender(msg_token->subject, msg_token);

        _np_dendrit_propagate_receivers(reply_to_key, msg_token, false);
        // _np_dendrit_propagate_receivers(reply_to_key, msg_token, old_token == NULL || strncmp(msg_token->uuid,old_token->uuid,UUID_SIZE) != 0);
        np_unref_obj(np_aaatoken_t, old_token, "_np_aaatoken_add_sender");

    __np_cleanup__:
        np_unref_obj(np_aaatoken_t, msg_token, "np_token_factory_read_from_tree");
    
    // __np_return__:
    return;
}

void _np_in_available_receiver(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_available_receiver(np_jobargs_t* args){");

    np_state_t* state = context;
    np_waitref_obj(np_key_t, state->my_node_key, my_key,"np_waitref_key");
    np_waitref_obj(np_key_t, state->my_identity, my_identity,"np_waitref_identity");

    // extract e2e encryption details for sender

    np_aaatoken_t* msg_token = NULL;
    CHECK_STR_FIELD(args.msg->header, _NP_MSG_HEADER_TO, msg_to);
    np_dhkey_t to_key = msg_to.value.dhkey;

    msg_token = np_token_factory_read_from_tree(context, args.msg->body);

    if (false == _np_aaatoken_is_valid(msg_token, np_aaatoken_type_message_intent))
    {
        if(msg_token != NULL){
            log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token %s will not be added to the available receivers.", msg_token->uuid);
        }
        goto __np_cleanup__;
    }

    np_dhkey_t recvtoken_issuer_key = np_dhkey_create_from_hash(msg_token->issuer);
    if (_np_dhkey_equal(&recvtoken_issuer_key, &my_identity->dhkey) )
    {
        // only add the token if it is not from ourself (in case of IN/OUTBOUND on same subject)
        // TODO CHECK IF NESSECARY
        // goto __np_cleanup__;
    }

    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now handling message interest");
    np_aaatoken_t* old_token = _np_aaatoken_add_receiver(msg_token->subject, msg_token);
    np_unref_obj(np_aaatoken_t, old_token, "_np_aaatoken_add_receiver");

    // check if we are (one of the) sending node(s) of this kind of message
    if ( _np_dhkey_equal(&to_key, &my_key->dhkey) )
    {
        struct  np_token tmp;
        if (true == state->authenticate_func(context, np_aaatoken4user(&tmp, msg_token)))
            msg_token->state |= AAA_AUTHENTICATED;

        if (true == state->authorize_func(context, np_aaatoken4user(&tmp, msg_token)))
            msg_token->state |= AAA_AUTHORIZED;
    }

    // check if we are (one of the) sending node(s) of this kind of message
    // should not return NULL
    np_msgproperty_t* real_prop = np_msgproperty_get(context, OUTBOUND, msg_token->subject);
    if ( NULL != real_prop)
    {
        _np_msgproperty_check_sender_msgcache(real_prop);
    }

    __np_cleanup__:
    np_unref_obj(np_aaatoken_t, msg_token, "np_token_factory_read_from_tree");
    np_unref_obj(np_key_t, my_key,"np_waitref_key");
    np_unref_obj(np_key_t, my_identity,"np_waitref_identity");

    // __np_return__:
    return;
}

void _np_in_authenticate(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_authenticate(np_jobargs_t* args){");
    np_aaatoken_t* sender_token = NULL;
    np_aaatoken_t* authentication_token = NULL;
    np_message_t *msg_in = args.msg;

    _np_msgproperty_threshold_increase(args.properties);

    CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_from);
    np_dhkey_t reply_to_key = msg_from.value.dhkey;
#ifdef DEBUG
        char reply_to_dhkey_as_str[65];
        _np_dhkey2str(&reply_to_key, reply_to_dhkey_as_str);
#endif
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "reply key: %s", reply_to_dhkey_as_str );

    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "reply key: %s", reply_to_dhkey_as_str );

    sender_token = _np_aaatoken_get_sender_token(context, (char*) _NP_MSG_AUTHENTICATION_REQUEST,  &msg_from.value.dhkey);
    if (NULL == sender_token)
    {
        goto __np_cleanup__;
    }

    bool decrypt_ok = _np_message_decrypt_payload(msg_in, sender_token);
    if (false == decrypt_ok)
    {
        goto __np_cleanup__;
    }
    np_tree_find_str(sender_token->extensions_local, "msg_threshold")->val.value.ui++;

    // extract e2e encryption details for sender
    authentication_token = np_token_factory_read_from_tree(context, msg_in->body);

    // always?: just store the available messages in memory and update if new data arrives
    if (false == _np_aaatoken_is_valid(authentication_token, np_aaatoken_type_message_intent))
    {
        goto __np_cleanup__;
    }

    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now checking (remote) authentication of token");
    struct  np_token tmp;
    bool authenticate = context->authenticate_func(context, np_aaatoken4user(&tmp, authentication_token));
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "authentication of token: %"PRIu8, authenticate);
    if (authenticate)
    {
        authentication_token->state |= AAA_AUTHENTICATED;
    }

    if (IS_AUTHENTICATED(authentication_token->state) )
    {

        np_aaatoken_t* old_token = _np_aaatoken_add_receiver(_NP_MSG_AUTHENTICATION_REPLY, sender_token);
        np_unref_obj(np_aaatoken_t, old_token, "_np_aaatoken_add_receiver");
        np_tree_t* token_data = np_tree_create();

        np_aaatoken_encode(token_data, authentication_token);
        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out);
        _np_message_create(msg_out, reply_to_key, context->my_node_key->dhkey, _NP_MSG_AUTHENTICATION_REPLY, token_data);
        np_msgproperty_t* prop_route = np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHENTICATION_REPLY);

        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending back authenticated data to %s", reply_to_dhkey_as_str);
        _np_job_submit_route_event(context, 0.0, prop_route, NULL, msg_out);
        np_unref_obj(np_message_t, msg_out,ref_obj_creation);
    }
    else
    {
        log_msg(LOG_WARN, "unknown security token received for authentication, dropping token");
        log_msg(LOG_WARN, "i:%s s:%s", authentication_token->issuer, authentication_token->subject);
    }

    __np_cleanup__:
    np_unref_obj(np_aaatoken_t, sender_token,"_np_aaatoken_get_sender_token");
    np_unref_obj(np_aaatoken_t, authentication_token, "np_token_factory_read_from_tree");

    // __np_return__:
    _np_msgproperty_threshold_decrease(args.properties);
    return;
}

void _np_in_authenticate_reply(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_authenticate_reply(np_jobargs_t* args){");
    np_aaatoken_t* authentication_token = NULL;
    np_aaatoken_t* sender_token = NULL;
    np_key_t* subject_key = NULL;

    // args.properties->msg_threshold++;

    CHECK_STR_FIELD(args.msg->header, _NP_MSG_HEADER_FROM, msg_from);

    sender_token = _np_aaatoken_get_sender_token(context, (char*) _NP_MSG_AUTHENTICATION_REPLY,  &msg_from.value.dhkey);
    if (NULL == sender_token)
    {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "no sender token for authentication reply found");
        goto __np_cleanup__;
    }

    // TODO: the following should not be required/possible, because it invalidates the token
    bool decrypt_ok = _np_message_decrypt_payload(args.msg, sender_token);
    if (false == decrypt_ok)
    {
        log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "decryption of authentication reply failed");
        goto __np_cleanup__;
    }
     np_tree_find_str(sender_token->extensions_local, "msg_threshold")->val.value.ui++;

    // extract e2e encryption details for sender
     authentication_token = np_token_factory_read_from_tree(context, args.msg->body);

     if (authentication_token != NULL) {
         np_dhkey_t search_key = { 0 };
         // TODO: validate token technically again
         if (0 == strncmp(authentication_token->subject, _NP_URN_NODE_PREFIX, 12))
         {
             search_key = np_dhkey_create_from_hash(authentication_token->issuer);
             // TODO: trigger JOIN request again if node has not joined ?

         } // TODO: add a token type to identify msg exchanges, nodes and real persons
         else /* if (0 == strncmp(authentication_token->subject, "urn:np:msg:", 11)) */
         {
             search_key = np_dhkey_create_from_hostport( authentication_token->subject, "0");
         }

         subject_key = _np_keycache_find_or_create(context, search_key);

         if (0 == strncmp(authentication_token->subject, _NP_URN_NODE_PREFIX, 12))
         {
             subject_key->aaa_token->state |= AAA_AUTHENTICATED;
         }
         else /* if (0 == strncmp(authentication_token->subject, "urn:np:msg:", 11)) */
         {
             _LOCK_ACCESS(&subject_key->recv_property->lock)
             {
                 pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
                 while (NULL != iter)
                 {
                     np_aaatoken_t* tmp_token = iter->val;
                     if (0 == strncmp(tmp_token->uuid, authentication_token->uuid, 255))
                     {
                         tmp_token->state |= AAA_AUTHENTICATED;
                         _np_msgproperty_check_receiver_msgcache(subject_key->recv_property,_np_aaatoken_get_issuer(tmp_token));
                         break;
                     }
                     // TODO: move to msgcache.h and change parameter
                     pll_next(iter);
                 }
             }

             _LOCK_ACCESS(&subject_key->send_property->lock)
             {
                 pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->send_tokens);
                 while (NULL != iter)
                 {
                     np_aaatoken_t* tmp_token = iter->val;
                     if (0 == strncmp(tmp_token->uuid, authentication_token->uuid, 255))
                     {
                         tmp_token->state |= AAA_AUTHENTICATED;
                         _np_msgproperty_check_sender_msgcache(subject_key->send_property);
                         break;
                     }
                     // TODO: move to msgcache.h and change parameter
                     pll_next(iter);
                 }
             }
         }
     }
    __np_cleanup__:
    np_unref_obj(np_aaatoken_t, authentication_token, "np_token_factory_read_from_tree");
    np_unref_obj(np_aaatoken_t, sender_token,"_np_aaatoken_get_sender_token");

    // __np_return__:
    // args.properties->msg_threshold--;
    np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
    return;
}

void _np_in_authorize(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_authorize(np_jobargs_t* args){");

    np_aaatoken_t* sender_token = NULL;
    np_aaatoken_t* authorization_token = NULL;

    np_message_t *msg_in = args.msg;

    _np_msgproperty_threshold_increase(args.properties);

    CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_from);
    np_dhkey_t reply_to_key = msg_from.value.dhkey;
#ifdef DEBUG
        char reply_to_dhkey_as_str[65];
        _np_dhkey2str(&reply_to_key, reply_to_dhkey_as_str);
#endif
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "reply key: %s", reply_to_dhkey_as_str );

    sender_token = _np_aaatoken_get_sender_token(context, (char*) _NP_MSG_AUTHORIZATION_REQUEST,  &msg_from.value.dhkey);
    if (NULL == sender_token)
    {
        goto __np_cleanup__;
    }

    bool decrypt_ok = _np_message_decrypt_payload(msg_in, sender_token);
    if (false == decrypt_ok)
    {
        goto __np_cleanup__;
    }

    np_tree_find_str(sender_token->extensions_local, "msg_threshold")->val.value.ui++;
    // extract e2e encryption details for sender
    authorization_token = np_token_factory_read_from_tree(context, msg_in->body);

    // always?: just store the available messages in memory and update if new data arrives
    if (false == _np_aaatoken_is_valid(authorization_token, np_aaatoken_type_message_intent))
    {
        goto __np_cleanup__;
    }

    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now checking (remote) authorization of token");
    struct np_token tmp;
    bool authorize = context->authorize_func(context, np_aaatoken4user(&tmp, authorization_token));
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "authorize of token: %"PRIu8, authorize);
    if (authorize)
    {
        authorization_token->state |= AAA_AUTHORIZED;
    }

    if (IS_AUTHORIZED(authorization_token->state) )
    {

        np_aaatoken_t* old_token = _np_aaatoken_add_receiver(_NP_MSG_AUTHORIZATION_REPLY, sender_token);
        np_unref_obj(np_aaatoken_t, old_token, "_np_aaatoken_add_receiver");

        np_tree_t* token_data = np_tree_create();
        np_aaatoken_encode(token_data, authorization_token);

        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out);
        _np_message_create(msg_out, reply_to_key, context->my_node_key->dhkey, _NP_MSG_AUTHORIZATION_REPLY, token_data);
        np_msgproperty_t* prop_route = np_msgproperty_get(context, OUTBOUND, _NP_MSG_AUTHORIZATION_REPLY);

        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending back authorized data to %s", reply_to_dhkey_as_str);
        _np_job_submit_route_event(context, 0.0, prop_route, NULL, msg_out);
        np_unref_obj(np_message_t, msg_out,ref_obj_creation);
    }
    else
    {
        log_msg(LOG_WARN, "unknown security token received for authorization, dropping token");
        log_msg(LOG_WARN, "i:%s s:%s", authorization_token->issuer, authorization_token->subject);
    }

    __np_cleanup__:
    np_unref_obj(np_aaatoken_t, sender_token, "_np_aaatoken_get_sender_token");
    np_unref_obj(np_aaatoken_t, authorization_token, "np_token_factory_read_from_tree");

    // __np_return__:
    _np_msgproperty_threshold_decrease(args.properties);
    return;
}

void _np_in_authorize_reply(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_authorize_reply(np_jobargs_t* args){");
    np_aaatoken_t* authorization_token = NULL;
    np_aaatoken_t* sender_token = NULL;

    // args.properties->msg_threshold++;
    np_key_t* subject_key = NULL;

    CHECK_STR_FIELD(args.msg->header, _NP_MSG_HEADER_FROM, msg_from);

    sender_token = _np_aaatoken_get_sender_token(context, (char*) _NP_MSG_AUTHORIZATION_REPLY,  &msg_from.value.dhkey);
    if (NULL == sender_token)
    {
        goto __np_cleanup__;
    }

    bool decrypt_ok = _np_message_decrypt_payload(args.msg, sender_token);
    if (false == decrypt_ok)
    {
        goto __np_cleanup__;
    }

     np_tree_find_str(sender_token->extensions_local, "msg_threshold")->val.value.ui++;

    // extract e2e encryption details for sender
    authorization_token = np_token_factory_read_from_tree(context, args.msg->body);

    if (authorization_token != NULL) {
        np_dhkey_t search_key = { 0 };

        // TODO: validate token technically again
        if (0 == strncmp(authorization_token->subject, _NP_URN_NODE_PREFIX, 12))
        {
            search_key = np_dhkey_create_from_hash(authorization_token->issuer);
        }
        else /* if (0 == strncmp(authorization_token->subject, "urn:np:msg:", 11)) */
        {
            search_key = np_dhkey_create_from_hostport( authorization_token->subject, "0");
        }

        subject_key = _np_keycache_find_or_create(context, search_key);

        if (0 == strncmp(authorization_token->subject, _NP_URN_NODE_PREFIX, 12))
        {
            subject_key->aaa_token->state |= AAA_AUTHORIZED;
        }
        else /* if (0 == strncmp(authorization_token->subject, "urn:np:msg:", 11)) */
        {
            _LOCK_ACCESS(&subject_key->recv_property->lock)
            {
                pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
                while (NULL != iter)
                {
                    np_aaatoken_t* tmp_token = iter->val;
                    if (0 == strncmp(tmp_token->uuid, authorization_token->uuid, 255))
                    {
                        tmp_token->state |= AAA_AUTHORIZED;
                        _np_msgproperty_check_receiver_msgcache(subject_key->recv_property,_np_aaatoken_get_issuer(tmp_token));
                        break;
                    }
                    // TODO: move to msgcache.h and change parameter
                    pll_next(iter);
                }
            }

            _LOCK_ACCESS(&subject_key->send_property->lock)
            {
                pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->send_tokens);
                while (NULL != iter)
                {
                    np_aaatoken_t* tmp_token = iter->val;
                    if (0 == strncmp(tmp_token->uuid, authorization_token->uuid, 255))
                    {
                        tmp_token->state |= AAA_AUTHORIZED;
                        _np_msgproperty_check_sender_msgcache(subject_key->send_property);
                        break;
                    }
                    pll_next(iter);
                }
            }
        }
    }
    __np_cleanup__:
    np_unref_obj(np_aaatoken_t, authorization_token, "np_token_factory_read_from_tree");
    np_unref_obj(np_aaatoken_t, sender_token,"_np_aaatoken_get_sender_token");

    // __np_return__:
    // args.properties->msg_threshold--;
    np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
    return;
}

void _np_in_account(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_account(np_jobargs_t* args){");
    np_aaatoken_t* sender_token = NULL;
    np_aaatoken_t* accounting_token = NULL;

    _np_msgproperty_threshold_increase(args.properties);

    CHECK_STR_FIELD(args.msg->header, _NP_MSG_HEADER_FROM, msg_from);

    sender_token = _np_aaatoken_get_sender_token(context, (char*) _NP_MSG_ACCOUNTING_REQUEST,  &msg_from.value.dhkey);
    if (NULL == sender_token)
    {
        goto __np_cleanup__;
    }

    np_tree_find_str(sender_token->extensions_local, "msg_threshold")->val.value.ui++;
    bool decrypt_ok = _np_message_decrypt_payload(args.msg, sender_token);
    if (false == decrypt_ok)
    {
        goto __np_cleanup__;
    }

    accounting_token  = np_token_factory_read_from_tree(context, args.msg->body);
    if (accounting_token != NULL) {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now checking (remote) accounting of token");
        struct np_token tmp;
        bool accounting = context->accounting_func(context, np_aaatoken4user(&tmp, accounting_token));
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "accounting of token: %"PRIu8, accounting);

    }
    __np_cleanup__:
    np_unref_obj(np_aaatoken_t, accounting_token, "np_token_factory_read_from_tree");
    np_unref_obj(np_aaatoken_t, sender_token, "_np_aaatoken_get_sender_token");

    // __np_return__:
    _np_msgproperty_threshold_decrease(args.properties);
    return;
}

void _np_in_handshake(np_state_t* context, np_jobargs_t args)
{
    log_trace_msg(LOG_TRACE, "start: void _np_in_handshake(np_jobargs_t* args){");

    log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 1");
    _LOCK_MODULE(np_handshake_t) {
        log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 2");
        np_node_t* tokens_node = NULL;
        np_handshake_token_t* handshake_token = NULL;
        np_key_t* msg_source_key = NULL;
        
        np_key_t* hs_wildcard_key = NULL;
        np_key_t* alias_key = args.target;		
        
        _np_message_deserialize_chunked(args.msg);

        // TODO: check if the complete buffer was read (byte count match)
        handshake_token = np_token_factory_read_from_tree(context, args.msg->body);

        if (handshake_token == NULL || !_np_aaatoken_is_valid(handshake_token, np_aaatoken_type_handshake)) {
            log_msg(LOG_ERROR, "incorrect handshake signature in message");
            goto __np_cleanup__;
        }

        // store the handshake data in the node cache,
        np_dhkey_t search_key = { 0 };
        _np_str2dhkey(handshake_token->issuer, &search_key);

        if (_np_dhkey_cmp(&context->my_node_key->dhkey, &search_key) == 0) {
            log_msg(LOG_ERROR, "Cannot perform a handshake with myself!");
            goto __np_cleanup__;
        }
        msg_source_key = _np_keycache_find_or_create(context, search_key);

        log_debug_msg(LOG_HANDSHAKE | LOG_DEBUG,
            "decoding of handshake message from %s (i:%f/e:%f) complete",
            handshake_token->subject, handshake_token->issued_at, handshake_token->expires_at);

        // should never happen
        if (NULL == msg_source_key)
        {
            log_msg(LOG_ERROR, "Handshake key is NULL!");
            goto __np_cleanup__;
        }

        // extract node data from handshake messages
        tokens_node = _np_node_from_token(handshake_token, np_aaatoken_type_handshake);
        if (NULL == tokens_node) {
            log_msg(LOG_ERROR, "Handshake token data is NULL!");
            _np_keycache_remove(context, search_key);
            goto __np_cleanup__;
        }

        log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE| LOG_DEBUG, "handshake for %s", _np_key_as_str(msg_source_key));
        msg_source_key->type |= np_key_type_node;

        /*
            Handshake/Join worklfow:
                1. 1Node initiates the workflow with a Handshake msg
                    Handshake msg contains a subset of the aaatoken data
                    (named "core_token", data required for a cryptographic safe connection)
                    and the node data to answer back as well as the session key
                    and the signature of the full token
                2. 2Node receives Handshake msg and saves it into a key.
                    2.Node now sends 1.Node his own Handshake msg
                3. Join msg is send from 1.Node to 2.Node
                    Join msg contains the full token data of 1.Node
                4. 2.Node receives Join msg
                    The new tokens signature will be matched with the signature of the core token
                    If it does match the new token will replace the old one
                    the appropiate aaa callbacks will be called
                    and the Join ACK msg will contain the full token data of 2.Node
                5. 1.Node receives Join ACK msg and replaces the old token with the new one

            We are now in step 2.

            Stop the Handshake workflow now if
            the handshake data is already received (prevent handshake spamming)
        */
        /*
        if (msg_source_key->node != NULL &&  msg_source_key->node->is_handshake_received == true) {
            log_msg(LOG_ROUTING | LOG_INFO, "Handshake message already completed");
            np_unref_obj(np_node_t, tokens_node, "_np_node_from_token");
            goto __np_cleanup__;
        }
        */
        double now = np_time_now();
        np_msgproperty_t* msg_prop_handshake = np_msgproperty_get(context, OUTBOUND, _NP_MSG_HANDSHAKE);

        if (msg_source_key->node == NULL || msg_source_key->node->_handshake_status == np_handshake_status_Connected) {            		
            if (msg_source_key->node != NULL && 
                msg_source_key->node->_handshake_status == np_handshake_status_Connected &&
                now < (msg_source_key->node->handshake_send_at + msg_prop_handshake->msg_ttl)) {
                log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE | LOG_DEBUG,
                    "handshake for alias %s received, but alias in state %s and not ready to reconnect",
                    _np_key_as_str(alias_key),
                    np_handshake_status_str[msg_source_key->node->_handshake_status]
                );
                goto __np_cleanup__;
            }
            // recover handshake_send_at attribute
            if(msg_source_key->node != NULL) tokens_node->handshake_send_at = msg_source_key->node->handshake_send_at;

            np_ref_switch(np_node_t, msg_source_key->node, ref_key_node, tokens_node);
            np_node_set_handshake(msg_source_key->node, np_handshake_status_RemoteInitiated);
        }
        else if (
            msg_source_key->node->_handshake_status == np_handshake_status_Disconnected ||
            msg_source_key->node->_handshake_status == np_handshake_status_SelfInitiated
            )
        {
            tokens_node->handshake_send_at = msg_source_key->node->handshake_send_at;
            np_node_set_handshake(tokens_node, msg_source_key->node->_handshake_status);
            tokens_node->joined_network |= msg_source_key->node->joined_network;
            np_ref_switch(np_node_t, msg_source_key->node, ref_key_node, tokens_node);
        }
        else {
            log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE| LOG_DEBUG,
                "handshake for alias %s received, but alias in state %s", 
                _np_key_as_str(alias_key),
               np_handshake_status_str[msg_source_key->node->_handshake_status]
            );
            goto __np_cleanup__;
        }

        if (msg_source_key->node == NULL) {
            log_msg(LOG_ERROR, "Handshake message does not contain necessary node data");
            goto __np_cleanup__;
        }


        // detect keys node info by wildcard if necessary 
        if (msg_source_key->node->joined_network == false) {
            char* tmp_connection_str = np_get_connection_string_from(msg_source_key, false);
            np_dhkey_t wildcard_dhkey = np_dhkey_create_from_hostport("*", tmp_connection_str);
            free(tmp_connection_str);

            log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 3");
            _LOCK_MODULE(np_network_t)
            {
                log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 4");

                hs_wildcard_key = _np_keycache_find(context, wildcard_dhkey);
                if (NULL != hs_wildcard_key && NULL != hs_wildcard_key->network &&
                    (hs_wildcard_key->node == NULL || !hs_wildcard_key->node->joined_network/*Already joined key is ignored*/)
                    )
                {
                    np_network_t* old_network = hs_wildcard_key->network;
                    np_ref_obj(np_network_t, old_network, "usage_of_old_network");

                    log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 5");
                    _LOCK_ACCESS(&old_network->access_lock)
                    {
                        log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 6");
                        // _np_network_stop(old_network);
                        // Updating handshake key with already existing network
                        // structure of the wildcard key
                        log_debug_msg(LOG_ROUTING | LOG_DEBUG,
                            "Updating wildcard key %s to %s",
                            _np_key_as_str(hs_wildcard_key),
                            _np_key_as_str(msg_source_key));

                        
                        np_node_set_handshake(msg_source_key->node, hs_wildcard_key->node->_handshake_status);
                        
                        // msg_source_key->aaa_token = hs_wildcard_key->aaa_token;
                        hs_wildcard_key->aaa_token = NULL;

                        if (msg_source_key->parent_key == NULL) {
                            msg_source_key->parent_key = hs_wildcard_key->parent_key;
                            hs_wildcard_key->parent_key = NULL;
                        }
                        _np_network_remap_network(msg_source_key, hs_wildcard_key);
                    }
                    np_unref_obj(np_network_t, old_network, "usage_of_old_network");					
                    np_ref_switch(np_key_t, hs_wildcard_key->parent_key, ref_key_parent, msg_source_key);
                }
                np_unref_obj(np_key_t, hs_wildcard_key, "_np_keycache_find");
            }
        }
        bool process_handshake = true;
        log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 7");

        _LOCK_ACCESS(&msg_source_key->node->lock) {
            log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 8");
            _LOCK_MODULE(np_network_t)
            {
                log_debug_msg(LOG_TRACE | LOG_VERBOSE, "logpoint handshake 9");

                if (NULL == msg_source_key->network)//|| (msg_source_key->network->last_received_date + 30) < np_time_now())
                {
                    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "handshake: init alias (%s) network", _np_key_as_str(alias_key));

                    if ((msg_source_key->node->protocol & PASSIVE) == PASSIVE && alias_key->network == NULL) {
                        char tmp[255];
                        log_msg(LOG_ERROR, "could not initiate passive network to alias key for %s. network missing",
                            np_network_get_desc(msg_source_key,tmp)
                        );
                        process_handshake = false;
                    }
                    else {
                        np_network_t * new_msg_source_key_network;
                        np_new_obj(np_network_t, new_msg_source_key_network);

                        _np_network_init(
                            new_msg_source_key_network,
                            false,
                            msg_source_key->node->protocol,
                            msg_source_key->node->dns_name,
                            msg_source_key->node->port,
                            ((msg_source_key->node->protocol & PASSIVE) == PASSIVE ?
                                alias_key->network->socket :
                                -1//msg_source_key->network->socket
                                )
                            , ((msg_source_key->node->protocol & PASSIVE) == PASSIVE ?
                            (context->my_node_key->network->socket_type & MASK_PROTOCOLL)
                                : UNKNOWN_PROTO)
                        );

                        if (true == new_msg_source_key_network->initialized)
                        {
                            _np_network_set_key(new_msg_source_key_network, msg_source_key);
                            _np_key_set_network(msg_source_key, new_msg_source_key_network);
                        }
                        else
                        {
                            log_msg(LOG_ERROR, "could not initiate network to alias key for %s:%s",
                                new_msg_source_key_network->ip, new_msg_source_key_network->port
                            );
                            process_handshake = false;
                        }
                        np_unref_obj(np_network_t, new_msg_source_key_network, ref_obj_creation);
                    }
                }
            }

            // Resolve handshake resend in too short timeframe
            if (process_handshake) {
                if (alias_key->node != NULL && alias_key->node->_handshake_status == np_handshake_status_Connected) {
                    process_handshake = now > (alias_key->node->handshake_send_at + msg_prop_handshake->msg_ttl);
                    if (!process_handshake) {
                        log_debug_msg(LOG_HANDSHAKE,
                            "Stopping handshake %s as the last handshake may still be valid.",
                            args.msg->uuid
                        );
                    }
                }
            }

            // Resolve handshake on both nodes in same timeframe (SI <-> SI)
            if (process_handshake) {
                // Stop the infinity handshake resend on contradicting handshake sends
                // Maybe even verify the Response UUID and the send UUID match. 

                np_tree_elem_t* response_uuid = np_tree_find_str(args.msg->instructions, _NP_MSG_INST_RESPONSE_UUID);
                np_tree_elem_t* remote_hs_prio = np_tree_find_str(args.msg->header, NP_HS_PRIO);

                if (response_uuid != NULL && alias_key->node != NULL && alias_key->node->_handshake_status == np_handshake_status_SelfInitiated) {
                    if (remote_hs_prio->val.value.ul < context->my_node_key->node->handshake_priority)
                    {
                        process_handshake = false;
                        log_debug_msg(LOG_HANDSHAKE,
                            "Handshake status contradiction. Handshake cannot be processed further. Remote-Prio: %"PRIu32" My-Prio: %"PRIu32" ",
                            remote_hs_prio->val.value.ul, context->my_node_key->node->handshake_priority
                        );
                    }
                    else {
                        np_node_set_handshake(alias_key->node, np_handshake_status_RemoteInitiated);                        
                        log_debug_msg(LOG_HANDSHAKE,
                            "Handshake status contradiction. Resetting node to remote initiated. Remote-Prio: %"PRIu32" My-Prio: %"PRIu32" ",
                            remote_hs_prio->val.value.ul, context->my_node_key->node->handshake_priority
                        );
                    }
                }
            }

            if (process_handshake) {
                np_state_t* state = context;
                np_waitref_obj(np_aaatoken_t, state->my_node_key->aaa_token, my_node_token, "np_waitref_my_node_key->aaa_token");
                
                np_unref_obj(np_aaatoken_t, my_node_token, "np_waitref_my_node_key->aaa_token");

                //np_aaatoken_t* old_token = NULL;
                if (
                    NULL != msg_source_key->aaa_token &&
                    IS_VALID(msg_source_key->aaa_token->state)
                    )
                {
                    // print warning if overwrite happens
                    log_msg(LOG_WARN,
                        "found valid authentication token for node %s (%s), overwriting...",
                        _np_key_as_str(msg_source_key), np_memory_get_id(msg_source_key->node));
                    //old_token = msg_source_key->aaa_token;
                    // msg_source_key->node->joined_network = false;
                }

                // handle alias key, also in case a new connection has been established
                log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE | LOG_DEBUG,
                    "processing handshake (msg: %s) for alias %s",
                    args.msg->uuid,
                    _np_key_as_str(alias_key));

                np_ref_switch(np_aaatoken_t, alias_key->aaa_token, ref_key_aaa_token, handshake_token);
                np_ref_switch(np_aaatoken_t, msg_source_key->aaa_token, ref_key_aaa_token, handshake_token);

                if (alias_key->node != NULL && msg_source_key->node != NULL) {
                    alias_key->node->handshake_send_at = msg_source_key->node->handshake_send_at;
                }
                np_ref_switch(np_node_t, alias_key->node, ref_key_node, msg_source_key->node);

                // copy over session key
                log_debug_msg(LOG_DEBUG | LOG_HANDSHAKE, "HANDSHAKE SECRET: setting shared secret on %s and alias %s on system %s",
                    _np_key_as_str(msg_source_key), _np_key_as_str(alias_key), _np_key_as_str(context->my_node_key));

                msg_source_key->node->session_key_is_set = 0 == 
                    np_crypto_session(
                        context,
                        &my_node_token->crypto,
                        &msg_source_key->node->session,
                        &msg_source_key->aaa_token->crypto,
                        alias_key->node->_handshake_status != np_handshake_status_SelfInitiated
                    );
                // Implicit: as both keys share the same node the session is exchanged between alias and sending key


                // mark as valid to identify existing connections
                msg_source_key->aaa_token->state |= AAA_VALID;

                bool succ_registerd = false;
                if (alias_key->node->_handshake_status == np_handshake_status_SelfInitiated) {
                    np_node_set_handshake(alias_key->node, np_handshake_status_Connected);
                    succ_registerd = true;
                }
                else if (alias_key->node->_handshake_status == np_handshake_status_RemoteInitiated) {
                    if (_np_network_send_handshake(context, msg_source_key, true, args.msg->uuid)) {
                        if (context->settings->n_threads > 1) np_time_sleep(0.05);
                        np_node_set_handshake(alias_key->node, np_handshake_status_Connected);
                        succ_registerd = true;
                    }
                }
                else if (alias_key->node->_handshake_status == np_handshake_status_Disconnected) {
                    np_node_set_handshake(alias_key->node, np_handshake_status_RemoteInitiated);
                    if (_np_network_send_handshake(context, msg_source_key, true, args.msg->uuid)) {                        
                        np_node_set_handshake(alias_key->node, np_handshake_status_Connected);
                        succ_registerd = true;
                    }
                }

                if (succ_registerd) {
                    log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE | LOG_DEBUG, "handshake data successfully registered for node %s (alias %s)",
                        _np_key_as_str(msg_source_key), _np_key_as_str(alias_key)
                    );
                }

                if (alias_key->node->_handshake_status == np_handshake_status_Connected) {
                    char tmp[255];
                    log_msg(LOG_INFO, "Connection established to node %s (alias %s / %s)",
                        _np_key_as_str(msg_source_key), _np_key_as_str(alias_key), np_network_get_desc(alias_key, tmp));
                }
            }
        }

    __np_cleanup__:
        np_unref_obj(np_node_t, tokens_node, "_np_node_from_token");
        np_unref_obj(np_aaatoken_t, handshake_token, "np_token_factory_read_from_tree");
        np_unref_obj(np_key_t, msg_source_key, "_np_keycache_find_or_create");
    }
    
}
