//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netdb.h>
#include <inttypes.h>

#include "sodium.h"
#include "event/ev.h"
#include "tree/tree.h"

#include "np_glia.h"

#include "np_legacy.h"

#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_dendrit.h"
#include "np_dhkey.h"
#include "np_event.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_list.h"
#include "np_log.h"
#include "np_message.h"
#include "np_memory.h"

#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_route.h"
#include "np_threads.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "np_types.h"
#include "np_util.h"
#include "np_settings.h"
#include "np_constants.h"
#include "np_responsecontainer.h"

// TODO: make these configurable (via struct np_config)

/**
 ** np_route:
 ** routes a message one step closer to its destination key. Delivers
 ** the message to its destination if it is the current host through the
 ** deliver upcall, otherwise it makes the route upcall
 **/
void _np_glia_route_lookup(np_state_t* context, np_jobargs_t args)
{
    
    np_waitref_obj(np_key_t, context->my_node_key, my_key, "np_waitref_obj");
    
    np_sll_t(np_key_ptr, tmp) = NULL;
    np_key_t* target_key = NULL;
    np_message_t* msg_in = args.msg;

    CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_TO, msg_target);

    char* msg_subject;
    bool free_msg_subject = false;
    np_tree_elem_t* ele_subject = np_tree_find_str(msg_in->header, _NP_MSG_HEADER_SUBJECT);
    if(ele_subject != NULL){
        msg_subject = np_treeval_to_str(ele_subject->val, &free_msg_subject);
    }
    else if(args.properties != NULL){
        msg_subject = args.properties->msg_subject;
    }
    else {
        ASSERT(false, "A msg subject to route for is required");
    }
    
    bool is_a_join_request = false;
    if (0 == strncmp(msg_subject, _NP_MSG_JOIN_REQUEST, strlen(_NP_MSG_JOIN_REQUEST)) )
    {
        is_a_join_request = true;
    }
    np_dhkey_t search_key = msg_target.value.dhkey;

    // 1 means: always send out message to another node first, even if it returns
    tmp = _np_route_lookup(context, search_key, 1);
    if ( 0 < sll_size(tmp) )
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "msg (%s) route_lookup result 1 = %s", msg_in->uuid, _np_key_as_str(sll_first(tmp)->val));


    if ( NULL != tmp                &&
         0    < sll_size(tmp)       &&
         false == is_a_join_request &&
         (_np_dhkey_equal(&sll_first(tmp)->val->dhkey, &my_key->dhkey)) )
    {
        // the result returned the sending node, try again with a higher count parameter
        np_key_unref_list(tmp, "_np_route_lookup");
        sll_free(np_key_ptr, tmp);

        tmp = _np_route_lookup(context, search_key, 2);
        if (0 < sll_size(tmp))
            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "msg (%s) route_lookup result 2 = %s", msg_in->uuid, _np_key_as_str(sll_first(tmp)->val));

        // TODO: increase count parameter again ?
    }

    if (NULL  != tmp           &&
        0     <  sll_size(tmp) &&
        false == _np_dhkey_equal(&sll_first(tmp)->val->dhkey, &my_key->dhkey))
    {
        target_key = sll_first(tmp)->val;
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "msg (%s) route_lookup result   = %s", msg_in->uuid, _np_key_as_str(target_key));
    }
    else {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "msg (%s) route_lookup result   = myself (listsize: %"PRIu32")", msg_in->uuid, (NULL == tmp ?0 : sll_size(tmp)));
    }
    
    /* if I am the only host or the closest host is me, deliver the message */
    if (NULL == target_key && false == is_a_join_request)
    {
        // the message has to be handled by this node (e.g. msg interest messages)
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "msg (%s) internal routing for subject '%s'", msg_in->uuid, msg_subject);
                
        np_msgproperty_t* prop = np_msgproperty_get(context, INBOUND, msg_subject);
        if(prop != NULL) {
            _np_job_submit_msgin_event(0.0, prop, my_key, args.msg, NULL);
        }
    } else {
        /* hand it over to the np_axon sending unit */
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "msg (%s) forward routing for subject '%s'", msg_in->uuid, msg_subject);

        if (NULL == target_key || true == is_a_join_request)
        {
            target_key = args.target;
        }

        np_msgproperty_t* prop = np_msgproperty_get(context, OUTBOUND, msg_subject);
        if (NULL == prop) {
            prop = np_msgproperty_get(context, OUTBOUND, _DEFAULT);
        }

        if (args.is_resend == true) {
            _np_job_resubmit_msgout_event(context, 0.0, prop, target_key, args.msg);
        } else {
            _np_job_submit_msgout_event(context, 0.0, prop, target_key, args.msg);
        }
    }
    np_key_unref_list(tmp, "_np_route_lookup");
    sll_free(np_key_ptr, tmp);	
    if (free_msg_subject) free(msg_subject);	

    __np_cleanup__:
        np_unref_obj(np_key_t, my_key, "np_waitref_obj");
}

void __np_glia_check_connections(np_sll_t(np_key_ptr, connections), __np_glia_check_connections_handler fn) {

    np_key_t *tmp_node_key = NULL;
    
    sll_iterator(np_key_ptr) iter_keys = sll_first(connections);
    np_ctx_decl(NULL); // WARNING: context is NULL!
    while (iter_keys != NULL)
    {
        tmp_node_key = iter_keys->val;		
        
        // check for bad link nodes
        if (NULL != tmp_node_key->node &&
            tmp_node_key->node->success_avg < BAD_LINK &&
            (np_time_now() - tmp_node_key->node->last_success) >= BAD_LINK_REMOVE_GRACETIME  &&
            tmp_node_key->node->_handshake_status == np_handshake_status_Connected
            )
        {			
            if(context == NULL) context = np_ctx_by_memory(tmp_node_key);

            log_msg(LOG_INFO, "deleted from table/leafset: %s:%s:%s / %f / %1.2f",
                                _np_key_as_str(tmp_node_key),
                                tmp_node_key->node->dns_name, tmp_node_key->node->port,
                                tmp_node_key->node->last_success,
                                tmp_node_key->node->success_avg);

            np_key_t *added = NULL, *deleted = NULL;
            fn(tmp_node_key, false, &deleted, &added);
            if (deleted != tmp_node_key)
            {
                log_msg(LOG_ROUTING | LOG_WARN, "deleting from table returned different key");
            }
        }

        sll_next(iter_keys);
    }
}

/** _np_route_check_leafset_jobexec:
 ** sends a PING message to each member of the leafset and routing table frequently and
 ** sends the leafset to other members of its leafset periodically.
 ** uses _np_job_yield between pings to different nodes
 ** _np_route_check_leafset_jobexec frequency is LEAFSET_CHECK_PERIOD.
 **/
void _np_glia_check_neighbours(np_state_t* context, NP_UNUSED  np_jobargs_t args) {
    
    np_sll_t(np_key_ptr, table) = NULL;
    table = _np_route_neighbors(context);
    __np_glia_check_connections(table, _np_route_leafset_update);
    np_key_unref_list(table, "_np_route_neighbors");
    sll_free(np_key_ptr, table);
}

void _np_glia_check_routes(np_state_t* context, NP_UNUSED  np_jobargs_t args) {
    
    np_sll_t(np_key_ptr, table) = NULL;
    table = _np_route_get_table(context);
    __np_glia_check_connections(table, _np_route_update);
    np_key_unref_list(table, "_np_route_get_table");
    sll_free(np_key_ptr, table);
}

void _np_glia_send_pings(np_state_t* context, NP_UNUSED  np_jobargs_t args) {
    // TODO: do a dynamic selection of keys
    np_sll_t(np_key_ptr, routing_keys) = _np_route_get_table(context);
    np_sll_t(np_key_ptr, neighbour_keys) = _np_route_neighbors(context);

    np_sll_t(np_key_ptr, keys) = sll_merge(np_key_ptr, neighbour_keys, routing_keys, _np_key_cmp);

    sll_iterator(np_key_ptr) iter = sll_first(keys);

    double now = np_time_now();
    while (iter != NULL) {

        if(iter->val != context->my_node_key){
            np_tryref_obj(np_node_t, iter->val->node, node_exists, node);
            if(node_exists) {
                if (
                    node->joined_network                 
                    && (node->last_success + MISC_SEND_PINGS_MAX_EVERY_X_SEC) <= now
                ) {
                    _np_ping_send(context, iter->val);                
                }
                np_unref_obj(np_node_t, node, FUNC);
            }
        }
        sll_next(iter);
    }
    sll_free(np_key_ptr, keys); // no ref
    np_key_unref_list(routing_keys, "_np_route_get_table");
    sll_free(np_key_ptr, routing_keys);
    np_key_unref_list(neighbour_keys, "_np_route_neighbors");
    sll_free(np_key_ptr, neighbour_keys);
}

void _np_glia_log_flush(np_state_t* context, NP_UNUSED  np_jobargs_t args) {
    
    _np_log_fflush(context, false);
}

void _np_glia_send_piggy_requests(np_state_t* context, NP_UNUSED  np_jobargs_t args) {
    

    /* send leafset exchange data every 3 times that pings the leafset */
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "leafset exchange for neighbours started");

    np_sll_t(np_key_ptr, routing_keys) = _np_route_get_table(context);
    np_sll_t(np_key_ptr, neighbour_keys) = _np_route_neighbors(context);
    np_sll_t(np_key_ptr, keys_merged) = sll_merge(np_key_ptr, routing_keys, neighbour_keys, _np_key_cmp);

    int i = 0;
    sll_iterator(np_key_ptr) iter_keys = sll_first(keys_merged);
    while (iter_keys != NULL)
    {
        // send a piggy message to the the nodes in our routing table
        np_msgproperty_t* piggy_prop = np_msgproperty_get(context, TRANSFORM, _NP_MSG_PIGGY_REQUEST);
        _np_job_submit_transform_event(context, 0.0, piggy_prop, iter_keys->val, NULL);

        i++;
        sll_next(iter_keys);
    }

    sll_free(np_key_ptr, keys_merged);
    np_key_unref_list(routing_keys, "_np_route_get_table");
    sll_free(np_key_ptr, routing_keys);
    np_key_unref_list(neighbour_keys, "_np_route_neighbors");
    sll_free(np_key_ptr, neighbour_keys);
}

/**
 ** np_retransmit_tokens
 ** retransmit tokens on a regular interval
 ** default ttl value for message exchange tokens is ten seconds, afterwards they will be invalid
 ** and a new token is required. this also ensures that the correct encryption key will be transmitted
 **/
void _np_retransmit_message_tokens_jobexec(np_state_t* context, NP_UNUSED  np_jobargs_t args)
{
    if (_np_route_my_key_has_connection(context)) {		

        np_tree_elem_t *iter = NULL;
        np_msgproperty_t* msg_prop = NULL;
        _LOCK_MODULE(np_state_message_tokens_t) {
            RB_FOREACH(iter, np_tree_s, context->msg_tokens)
            {
                // bool free_subject;
                const char* subject = iter->key.value.s;
                
                np_dhkey_t target_dhkey = np_dhkey_create_from_hostport( subject, "0");
                np_key_t* target = NULL;
                target = _np_keycache_find_or_create(context, target_dhkey);

                msg_prop = np_msgproperty_get(context, TRANSFORM, subject);

                if (NULL != msg_prop)
                {
                    _np_job_submit_transform_event(context, 0.0, msg_prop, target, NULL);
                    np_unref_obj(np_key_t, target, "_np_keycache_find_or_create");
                }
                else
                {
                    // deleted = RB_REMOVE(np_tree_s, context->msg_tokens, iter);
                    // free( np_treeval_to_str(deleted->key));
                    // free(deleted);
                    np_unref_obj(np_key_t, target, "_np_keycache_find_or_create");
                    // break;
                }
            }
        }

        if (true == context->enable_realm_server)
        {
            np_msgproperty_t* msg_prop = NULL;

            np_dhkey_t target_dhkey = { 0 };
            _np_str_dhkey( context->my_identity->aaa_token->realm, &target_dhkey);

            np_key_t* target = NULL;
            target = _np_keycache_find_or_create(context, target_dhkey);

            msg_prop = np_msgproperty_get(context, INBOUND, _NP_MSG_AUTHENTICATION_REQUEST);
            if (false == sll_contains(np_callback_t, msg_prop->clb_transform, _np_out_sender_discovery, np_callback_t_sll_compare_type)) {
                sll_append(np_callback_t, msg_prop->clb_transform, _np_out_sender_discovery);
            }
            // _np_out_sender_discovery(0.0, msg_prop, target, NULL);
            _np_job_submit_transform_event(context, 0.0, msg_prop, target, NULL);

            msg_prop = np_msgproperty_get(context, INBOUND, _NP_MSG_AUTHORIZATION_REQUEST);
            if (false == sll_contains(np_callback_t, msg_prop->clb_transform, _np_out_sender_discovery, np_callback_t_sll_compare_type)) {
                sll_append(np_callback_t, msg_prop->clb_transform, _np_out_sender_discovery);
            }
            _np_job_submit_transform_event(context, 0.0, msg_prop, target, NULL);

            msg_prop = np_msgproperty_get(context, INBOUND, _NP_MSG_ACCOUNTING_REQUEST);
            if (false == sll_contains(np_callback_t, msg_prop->clb_transform, _np_out_sender_discovery, np_callback_t_sll_compare_type)) {
                sll_append(np_callback_t, msg_prop->clb_transform, _np_out_sender_discovery);
            }
            _np_job_submit_transform_event(context, 0.0, msg_prop, target, NULL);

            np_unref_obj(np_key_t, target, "_np_keycache_find_or_create");
        }
    }
}

/**
 ** _np_cleanup
 ** general resend mechanism. all message which have an acknowledge indicator set are stored in
 ** memory. If the acknowledge has not been send in time, we try to redeliver the message, otherwise
 ** the message gets deleted or dropped (if max redelivery has been reached)
 ** redelivery has two aspects -> simple resend or reroute because of bad link nodes in the routing table
 **/
void _np_cleanup_ack_jobexec(np_state_t* context, NP_UNUSED  np_jobargs_t args)
{
    np_waitref_obj(np_key_t, context->my_node_key, my_key);
    np_waitref_obj(np_network_t, my_key->network, my_network);	

    np_tree_elem_t *jrb_ack_node = NULL;

    // wake up and check for acknowledged messages

    np_tree_elem_t* iter = NULL;
    int c = 0;

    sll_init_full(char_ptr, to_remove);

    _LOCK_ACCESS(&my_network->waiting_lock)
    {
        iter = RB_MIN(np_tree_s, my_network->waiting);
        double now =  np_time_now();
        while (iter != NULL) {
            jrb_ack_node = iter;
            iter = RB_NEXT(np_tree_s, my_network->waiting, iter);

            np_responsecontainer_t *responsecontainer = (np_responsecontainer_t *)jrb_ack_node->val.value.v;
            if (responsecontainer != NULL) {
                bool is_fully_acked = _np_responsecontainer_is_fully_acked(responsecontainer);

                if (is_fully_acked || now > responsecontainer->expires_at) {
                    if (!is_fully_acked) {
                        _np_responsecontainer_set_timeout(responsecontainer);
                        log_msg(LOG_WARN, "ACK_HANDLING timeout (table size: %3d) message (%s / %s) not acknowledged (IN TIME %f/%f)",
                            my_network->waiting->size,
                            jrb_ack_node->key.value.s, responsecontainer->msg->msg_property->msg_subject,
                            now, responsecontainer->expires_at
                        );
                    }
                    sll_append(char_ptr, to_remove, jrb_ack_node->key.value.s);
                }
            }
            else {
                log_debug_msg(LOG_DEBUG, "ACK_HANDLING (table size: %3d) message (%s) not found",
                    my_network->waiting->size,
                    jrb_ack_node->key.value.s);
            }
            c++;
        };
    }

    if (sll_size(to_remove) > 0) {
        sll_iterator(char_ptr) iter_to_rm = sll_first(to_remove);
        log_debug_msg(LOG_WARN, "ACK_HANDLING removing %"PRIu32" (of %d) from ack table", sll_size(to_remove), c);
        while (iter_to_rm != NULL)
        {
            np_responsecontainer_t *responsecontainer = _np_responsecontainers_get_by_uuid(context, iter_to_rm->val);
            _LOCK_ACCESS(&my_network->waiting_lock) {
                np_tree_del_str(my_network->waiting, iter_to_rm->val);
            }
            np_unref_obj(np_responsecontainer_t, responsecontainer, "_np_responsecontainers_get_by_uuid");
            np_unref_obj(np_responsecontainer_t, responsecontainer, ref_ack_obj);

            sll_next(iter_to_rm);
        }
    }
    sll_free(char_ptr, to_remove);

    np_unref_obj(np_key_t, my_key, FUNC);
    np_unref_obj(np_network_t, my_network, FUNC);
}

void _np_cleanup_keycache_jobexec(np_state_t* context, NP_UNUSED  np_jobargs_t args)
{
    

    np_key_t* old = NULL;
    double now = np_time_now();

    old = _np_keycache_find_deprecated(context);

    if (NULL != old)
    {
        log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup check started for key : %p -> %s", old, _np_key_as_str(old));
        bool delete_key = true;

        if (NULL != old->node)
        {
            // found a node key, check last_success value
            if ((np_time_now() - old->node->last_success) < 60. )
            {
                // 60 sec no success full msg received
                log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key cancelled because of valid node last_success value: %s", _np_key_as_str(old));
                delete_key &= false;
            }
        }

        np_tryref_obj(np_aaatoken_t, old->aaa_token, tokenExists,  aaa_token, "np_tryref_old->aaa_token");
        if(tokenExists) {
            if (true == _np_aaatoken_is_valid(aaa_token, np_aaatoken_type_undefined))
            {
                log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key cancelled because of valid aaa_token structure: %s", _np_key_as_str(old));
                delete_key &= false;
            }
            np_unref_obj(np_aaatoken_t, aaa_token,"np_tryref_old->aaa_token");
        }

        if (NULL != old->recv_tokens)
        {
            _LOCK_ACCESS(&old->recv_property->lock)
            {
                // check old receiver token structure
                pll_iterator(np_aaatoken_ptr) iter = pll_first(old->recv_tokens);
                while (NULL != iter)
                {
                    np_aaatoken_t* tmp_token = iter->val;
                    if (true == _np_aaatoken_is_valid(tmp_token, np_aaatoken_type_message_intent))
                    {
                        log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key cancelled because of valid receiver tokens: %s", _np_key_as_str(old));
                        delete_key &= false;
                        break;
                    }
                    pll_next(iter);
                }
            }
        }

        if (NULL != old->send_tokens)
        {
            _LOCK_ACCESS(&old->send_property->lock)
            {
                // check old sender token structure
                pll_iterator(np_aaatoken_ptr) iter = pll_first(old->send_tokens);
                while (NULL != iter)
                {
                    np_aaatoken_t* tmp_token = iter->val;
                    if (true == _np_aaatoken_is_valid(tmp_token, np_aaatoken_type_message_intent))
                    {
                        log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key cancelled because of valid sender tokens: %s", _np_key_as_str(old));
                        delete_key &= false;
                        break;
                    }
                    pll_next(iter);
                }
            }
        }

        // last sanity check if we should delete
        if (true == delete_key &&
            now > old->last_update)
        {
            _np_key_destroy(old);
        }
        else
        {
            // update timestamp so that the same key cannot be evaluated twice
            old->last_update = np_time_now();
        }
        np_unref_obj(np_key_t, old, "_np_keycache_find_deprecated");
    }
}

/**
 ** np_send_rowinfo:
 ** sends matching row of its table to the target node
 **/
void _np_send_rowinfo_jobexec(np_state_t* context, np_jobargs_t args)
{
    
    np_key_t* target_key = args.target;

    // check for correct target
    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "job submit route row info to %s:%s!",
            target_key->node->dns_name, target_key->node->port);

    np_sll_t(np_key_ptr, sll_of_keys) = NULL;
    /* send one row of our routing table back to joiner #host# */
    
    char* source_sll_of_keys;
    sll_of_keys = _np_route_row_lookup(target_key);
    source_sll_of_keys = "_np_route_row_lookup";
    //sll_of_keys = _np_route_get_table(context);
    //source_sll_of_keys = "_np_route_get_table";
    
    
    if (sll_size(sll_of_keys) <= 5)
    {
        // nothing found, send leafset to exchange some data at least
        // prevents small clusters from not exchanging all data
        np_key_unref_list(sll_of_keys, source_sll_of_keys); // only for completion
        sll_free(np_key_ptr, sll_of_keys);
        sll_of_keys = _np_route_neighbors(context);
        source_sll_of_keys = "_np_route_neighbors";
    }
    
    if (sll_size(sll_of_keys) > 0)
    {
        np_tree_t* msg_body = np_tree_create();
        _np_node_encode_multiple_to_jrb(msg_body, sll_of_keys, false);
        np_msgproperty_t* outprop = np_msgproperty_get(context, OUTBOUND, _NP_MSG_PIGGY_REQUEST);
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending piggy msg (%"PRIu32" nodes) to %s", sll_size(sll_of_keys), _np_key_as_str(target_key));

        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out);
        _np_message_create(msg_out, target_key->dhkey, context->my_node_key->dhkey, _NP_MSG_PIGGY_REQUEST, msg_body);
        _np_job_submit_msgout_event(context, NP_PI/500, outprop, target_key, msg_out);
        np_unref_obj(np_message_t, msg_out, ref_obj_creation);
    }

    np_key_unref_list(sll_of_keys, source_sll_of_keys);
    sll_free(np_key_ptr, sll_of_keys);
}

void _np_send_subject_discovery_messages(np_state_t* context , np_msg_mode_type mode_type, const char* subject)
{
    // TODO: msg_tokens for either
    // insert into msg token token renewal queue
    _LOCK_MODULE(np_state_message_tokens_t) {
        if (NULL == np_tree_find_str(context->msg_tokens, subject))
        {
            np_tree_insert_str( context->msg_tokens, subject, np_treeval_new_v(NULL));

            np_msgproperty_t* msg_prop = np_msgproperty_get(context, mode_type, subject);
            assert(msg_prop!=NULL);
            msg_prop->mode_type |= TRANSFORM;
            if (false == sll_contains(np_callback_t, msg_prop->clb_transform, _np_out_discovery_messages, np_callback_t_sll_compare_type)) {
                sll_append(np_callback_t, msg_prop->clb_transform, _np_out_discovery_messages);
            }

            np_dhkey_t target_dhkey = np_dhkey_create_from_hostport( subject, "0");
            np_key_t* target = NULL;
            target = _np_keycache_find_or_create(context, target_dhkey);

            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "registering for message discovery token handling (%s)", subject);
            _np_job_submit_transform_event(context, 0.0, msg_prop, target, NULL);
            np_unref_obj(np_key_t, target, "_np_keycache_find_or_create");
        }
    }
}

// TODO: add a wrapper function which can be scheduled via jobargs
bool _np_send_msg (char* subject, np_message_t* msg, np_msgproperty_t* msg_prop, np_dhkey_t* target)
{
    assert(msg != NULL);
    np_state_t* context = np_ctx_by_memory(msg);
    // np_aaatoken_t* tmp_token = _np_aaatoken_get_receiver(subject, &target_key);
    np_message_intent_public_token_t* tmp_token = _np_aaatoken_get_receiver(context, subject, target);
    if (NULL != tmp_token)
    {
        _np_msgproperty_threshold_increase(msg_prop);
        log_msg(LOG_INFO | LOG_ROUTING, "(msg: %s) for subject \"%s\" has valid token", msg->uuid, subject);

        // TODO: instead of token threshold a local copy of the value should be increased
        np_tree_find_str(tmp_token->extensions_local, "msg_threshold")->val.value.ui++;

        np_dhkey_t empty_check = { 0 };
        np_dhkey_t receiver_dhkey = np_aaatoken_get_partner_fp(tmp_token);
        if (_np_dhkey_equal(&empty_check, &receiver_dhkey))
        {
            _np_str_dhkey(tmp_token->issuer, &receiver_dhkey);
        }

        if (_np_dhkey_equal(&context->my_node_key->dhkey, &receiver_dhkey))
        {
            np_msgproperty_t* handler = np_msgproperty_get(context, INBOUND, msg->msg_property->msg_subject);
            if (handler != NULL)
            {
                _np_in_new_msg_received(msg, handler, true);
            }
        }
        else
        {
            log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "encrypting message (%s) with receiver token %s %s...", msg->uuid, tmp_token->uuid, tmp_token->issuer);

            // encrypt the relevant message part itself
            _np_message_encrypt_payload(msg, tmp_token);

/*            char receiver_key_str[65];
            receiver_key_str[64] = '\0';
            _np_dhkey_str(&receiver_dhkey, receiver_key_str);
            char * ctx = np_get_userdata(context);
            fprintf(stdout, "     (%s): encrypted message (%s) for %s / node: %s\n", ctx, msg->uuid, tmp_token->issuer, receiver_key_str); fflush(stdout);
*/
            np_tree_replace_str(msg->header, _NP_MSG_HEADER_TO, np_treeval_new_dhkey(receiver_dhkey));

            np_msgproperty_t* out_prop = np_msgproperty_get(context, OUTBOUND, subject);
            _np_job_submit_route_event(context, 0.0, out_prop, NULL, msg);

            if (NULL != msg_prop->rep_subject &&
                FLAG_CMP(msg_prop->mep_type, STICKY_REPLY))
            {

                np_aaatoken_t* old_token = _np_aaatoken_add_sender(msg_prop->rep_subject, tmp_token);
                np_unref_obj(np_aaatoken_t, old_token, "_np_aaatoken_add_sender");
            }

            // decrease threshold counters
            _np_msgproperty_threshold_decrease(msg_prop);

            np_unref_obj(np_aaatoken_t, tmp_token, "_np_aaatoken_get_receiver");
            return (true);
        }
    }
    else
    {
        log_msg(LOG_INFO, "(msg: %s) for subject \"%s\" has NO valid token", msg->uuid, subject);
        _np_msgproperty_add_msg_to_send_cache(msg_prop, msg);
    }
    
    return (false);
}
