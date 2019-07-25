//
// neuropil is copyright 2016-2019 by pi-lar GmbH
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

#include "core/np_comp_msgproperty.h"
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
    else
    {
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "msg (%s) route_lookup result   = myself (listsize: %"PRIu32")", msg_in->uuid, (NULL == tmp ?0 : sll_size(tmp)));
    }
    
    /* if I am the only host or the closest host is me, deliver the message */
    if (NULL == target_key && false == is_a_join_request)
    {
        // the message has to be handled by this node (e.g. msg interest messages)
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "msg (%s) internal routing for subject '%s'", msg_in->uuid, msg_subject);
                
        np_msgproperty_t* prop = _np_msgproperty_get(context, INBOUND, msg_subject);
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

        np_msgproperty_t* prop = _np_msgproperty_get(context, OUTBOUND, msg_subject);
        if (NULL == prop) {
            prop = _np_msgproperty_get(context, OUTBOUND, _DEFAULT);
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

void _np_glia_log_flush(np_state_t* context, NP_UNUSED  np_jobargs_t args) 
{    
    _np_log_fflush(context, false);
}

/**
 ** _np_cleanup
 ** general resend mechanism. all message which have an acknowledge indicator set are stored in
 ** memory. If the acknowledge has not been send in time, we try to redeliver the message, otherwise
 ** the message gets deleted or dropped (if max redelivery has been reached)
 ** redelivery has two aspects -> simple resend or reroute because of bad link nodes in the routing table
 **/
/* 
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
            else 
            {
                log_debug_msg(LOG_DEBUG, "ACK_HANDLING (table size: %3d) message (%s) not found",
                                         my_network->waiting->size, jrb_ack_node->key.value.s);
            }
            c++;
        };
    }

    if (sll_size(to_remove) > 0) 
    {
        sll_iterator(char_ptr) iter_to_rm = sll_first(to_remove);
        log_debug_msg(LOG_WARN, "ACK_HANDLING removing %"PRIu32" (of %d) from ack table", sll_size(to_remove), c);
        while (iter_to_rm != NULL)
        {
            np_responsecontainer_t *responsecontainer = _np_responsecontainers_get_by_uuid(context, iter_to_rm->val);
            _LOCK_ACCESS(&my_network->waiting_lock)
            {
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
*/

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
        if(tokenExists) 
        {
            if (true == _np_aaatoken_is_valid(aaa_token, np_aaatoken_type_undefined))
            {
                log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key cancelled because of valid aaa_token structure: %s", _np_key_as_str(old));
                delete_key &= false;
            }
            np_unref_obj(np_aaatoken_t, aaa_token,"np_tryref_old->aaa_token");
        }

        if (NULL != old->recv_tokens)
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

        if (NULL != old->send_tokens)
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

