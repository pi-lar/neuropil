//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>

#include "sodium.h"
#include "msgpack/cmp.h"

#include "np_msgproperty.h"

#include "np_legacy.h"

#include "dtime.h"
#include "np_log.h"
#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_dendrit.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_memory.h"

#include "np_message.h"
#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_treeval.h"
#include "np_settings.h"
#include "np_constants.h"
#include "np_list.h"
#include "np_types.h"
#include "np_token_factory.h"


#define NR_OF_ELEMS(x)  (sizeof(x) / sizeof(x[0]))

NP_SLL_GENERATE_IMPLEMENTATION(np_msgproperty_ptr);

#include "np_msgproperty_init.c"

// required to properly link inline in debug mode
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, mode_type, np_msg_mode_type);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, mep_type, np_msg_mep_type);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, ack_mode, np_msg_ack_type);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, msg_ttl, double);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, retry, uint8_t);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, max_threshold, uint16_t);

_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, partner_key, np_dhkey_t);

RB_HEAD(rbt_msgproperty, np_msgproperty_s);
// RB_PROTOTYPE(rbt_msgproperty, np_msgproperty_s, link, property_comp);
RB_GENERATE(rbt_msgproperty, np_msgproperty_s, link, _np_msgproperty_comp);

typedef struct rbt_msgproperty rbt_msgproperty_t;

np_module_struct(msgproperties) {
    np_state_t * context;
    rbt_msgproperty_t* __msgproperty_table;
};

/**
 ** _np_msgproperty_init
 ** Initialize message property subsystem.
 **/
bool _np_msgproperty_init (np_state_t* context)
{
    if (!np_module_initiated(msgproperties)) {
        np_module_malloc(msgproperties);
        _module->__msgproperty_table = (rbt_msgproperty_t*)malloc(sizeof(rbt_msgproperty_t));
        CHECK_MALLOC(_module->__msgproperty_table);

        if (NULL == _module->__msgproperty_table) return false;

        RB_INIT(_module->__msgproperty_table);

        // NEUROPIL_INTERN_MESSAGES

        np_sll_t(np_msgproperty_ptr, msgproperties);
        msgproperties = default_msgproperties(context);
        sll_iterator(np_msgproperty_ptr) __np_internal_messages = sll_first(msgproperties);

        while (__np_internal_messages != NULL)
        {
            np_msgproperty_t* property = __np_internal_messages->val;
            property->is_internal = true;

            if (strlen(property->msg_subject) > 0)
            {
                log_debug_msg(LOG_DEBUG, "register handler: %s", property->msg_subject);
                RB_INSERT(rbt_msgproperty, _module->__msgproperty_table, property);
            }

            sll_next(__np_internal_messages);
        }

        sll_free(np_msgproperty_ptr, msgproperties);
    }
    return true;
}
void _np_msgproperty_destroy (np_state_t* context)
{
    if (np_module_initiated(msgproperties)) {
        np_module_var(msgproperties);
        
        
        np_msgproperty_t* iter_prop = RB_MIN(rbt_msgproperty, np_module(msgproperties)->__msgproperty_table);        
        while(iter_prop != NULL){            
            RB_REMOVE(rbt_msgproperty, np_module(msgproperties)->__msgproperty_table,iter_prop);

            sll_iterator(np_message_ptr) iter_prop_msg_cache_in = sll_first(iter_prop->msg_cache_in);
            while (iter_prop_msg_cache_in != NULL)
            {
                np_message_t* old_msg = iter_prop_msg_cache_in->val;                            
                np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
                _np_msgproperty_threshold_decrease(iter_prop);                
            }
            sll_free(np_message_ptr, iter_prop->msg_cache_in)

            np_unref_obj(np_msgproperty_t, iter_prop, ref_system_msgproperty); 
            iter_prop = RB_MIN(rbt_msgproperty, np_module(msgproperties)->__msgproperty_table);
        }

        // ? RB_FREE(_module->__msgproperty_table);

        free(_module->__msgproperty_table);

        np_module_free(msgproperties);
    }    
}
/**
 ** registers the handler function #func# with the message type #type#,
 ** it also defines the acknowledgment requirement for this type
 **/
np_msgproperty_t* np_msgproperty_get(np_state_t* context, np_msg_mode_type mode_type, const char* subject)
{
    log_trace_msg(LOG_TRACE, "start: np_msgproperty_t* np_msgproperty_get(context, np_msg_mode_type mode_type, const char* subject){");
    assert(subject != NULL);

    np_msgproperty_t prop = { .msg_subject=(char*) subject, .mode_type=mode_type };
    return RB_FIND(rbt_msgproperty,np_module(msgproperties)->__msgproperty_table, &prop);
}
np_msgproperty_t* np_msgproperty_get_or_create(np_state_t* context, np_msg_mode_type mode_type, const char* subject)
{
    np_msgproperty_t* ret = np_msgproperty_get(context, DEFAULT_MODE, subject);

    bool created= false;
    if (NULL == ret)
    {
        log_msg(LOG_INFO | LOG_MSGPROPERTY, "Indirect %"PRIu8" creation of msgproperty %s", mode_type, subject);	
        // create a default set of properties for listening to messages
        np_new_obj(np_msgproperty_t, ret);
        ret->msg_subject = strndup(subject, 255);
        ret->mode_type |= mode_type;
        ret->mep_type = ANY_TO_ANY;
        np_msgproperty_register(ret);
    } 
    if(!FLAG_CMP(ret->mode_type, mode_type))
    {
        log_msg(LOG_INFO | LOG_MSGPROPERTY, "Indirect %"PRIu8" configuration of msgproperty %s", mode_type, subject);	
        ret->mode_type |= mode_type;
        _np_msgproperty_update_disovery(context,ret);
    }
    if(created){
        np_unref_obj(np_msgproperty_t, ret, ref_obj_creation);
    }
    return ret;
}
int16_t _np_msgproperty_comp(const np_msgproperty_t* const search_filter, const np_msgproperty_t* const prop2)
{
    int16_t ret = -1;
    // TODO: check how to use bitmasks with red-black-tree efficiently	

    assert(!( search_filter == NULL ||  search_filter->msg_subject == NULL || prop2 == NULL || prop2->msg_subject == NULL)); //"Comparing properties where one is NULL");	

    int16_t i = strncmp( search_filter->msg_subject, prop2->msg_subject, 255);
    
    if (0 != i) ret = i;
    else if (0 ==  search_filter->mode_type) ret =  (0);		// Ignore bitmask ?
    else if ( search_filter->mode_type == prop2->mode_type) ret =  (0);		// Is it the same bitmask ?
    else if (0 < ( search_filter->mode_type & prop2->mode_type)) ret = (0);	// for searching: Are some test bits set ?
    else if ( search_filter->mode_type > prop2->mode_type)  ret = ( 1);		// for sorting / inserting different entries
    else if ( search_filter->mode_type < prop2->mode_type)  ret = (-1);

    return ret;
}

void _np_msgproperty_register_job(np_state_t * context, np_jobargs_t args) {
    _np_msgproperty_update_disovery(context, (np_msgproperty_t*)args.custom_data);
}
void _np_msgproperty_update_disovery(np_state_t * context, np_msgproperty_t* msgprop) {
    np_message_intent_public_token_t* token = _np_msgproperty_upsert_token(msgprop);
    if (FLAG_CMP(msgprop->mode_type, OUTBOUND)) {
        np_aaatoken_t* old_token = _np_aaatoken_add_sender(msgprop->msg_subject, token);
        np_unref_obj(np_aaatoken_t, old_token, "_np_aaatoken_add_sender");
        _np_send_subject_discovery_messages(context, OUTBOUND, msgprop->msg_subject);
    }
    if (FLAG_CMP(msgprop->mode_type, INBOUND)) {
        np_aaatoken_t* old_token = _np_aaatoken_add_receiver(msgprop->msg_subject, token);
        np_unref_obj(np_aaatoken_t, old_token, "_np_aaatoken_add_receiver");
        _np_send_subject_discovery_messages(context, INBOUND, msgprop->msg_subject);
    }
    np_unref_obj(np_aaatoken_t, token, "_np_msgproperty_upsert_token");
}

void np_msgproperty_register(np_msgproperty_t* msgprops)
{
    np_ctx_memory(msgprops);
    log_trace_msg(LOG_TRACE, "start: void np_msgproperty_register(np_msgproperty_t* msgprops){ ");
    log_debug_msg(LOG_DEBUG, "registering user property: %s ", msgprops->msg_subject);

    np_ref_obj(np_msgproperty_t, msgprops, ref_system_msgproperty); 
    RB_INSERT(rbt_msgproperty, np_module(msgproperties)->__msgproperty_table, msgprops);

    //np_job_submit_event(context, PRIORITY_MOD_LEVEL_2, 0, _np_msgproperty_register_job, msgprops, "_np_msgproperty_register_job");
    _np_msgproperty_update_disovery(context, msgprops);

}

void _np_msgproperty_t_new(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* property)
{
    log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_t_new(void* property){");
    np_msgproperty_t* prop = (np_msgproperty_t*) property;

    prop->token_min_ttl = MSGPROPERTY_DEFAULT_MIN_TTL_SEC;
    prop->token_max_ttl = MSGPROPERTY_DEFAULT_MAX_TTL_SEC;

    prop->msg_audience	= NULL;
    prop->msg_subject	= NULL;
    prop->rep_subject	= NULL;

    prop->mode_type = OUTBOUND | INBOUND | ROUTE | TRANSFORM;
    prop->mep_type	= DEFAULT_TYPE;
    prop->ack_mode	= ACK_NONE;
    prop->priority	= PRIORITY_MOD_USER_DEFAULT;
    prop->retry		= 5;
    prop->msg_ttl	= 60.0;

    prop->max_threshold = 10;
    TSP_INITD(prop->msg_threshold, 0);

    prop->is_internal = false;
    prop->last_update = np_time_now();

    sll_init(np_callback_t, prop->clb_inbound);
    sll_init(np_callback_t, prop->clb_transform);
    sll_init(np_callback_t, prop->clb_outbound);
    sll_init(np_callback_t, prop->clb_route);

    sll_append(np_callback_t, prop->clb_outbound, _np_out);
    sll_append(np_callback_t, prop->clb_route, _np_glia_route_lookup);

    sll_init(np_usercallback_ptr, prop->user_receive_clb);
    sll_init(np_usercallback_ptr, prop->user_send_clb);

    // cache which will hold up to max_threshold messages
    prop->cache_policy = FIFO | OVERFLOW_PURGE;
    sll_init(np_message_ptr, prop->msg_cache_in);
    sll_init(np_message_ptr, prop->msg_cache_out);

    _np_threads_mutex_init(context, &prop->lock,"property lock");
    _np_threads_condition_init(context, &prop->msg_received);
    
    _np_threads_mutex_init(context, &prop->send_discovery_msgs_lock, "send_discovery_msgs_lock");

    _np_threads_mutex_init(context, &prop->unique_uuids_lock, "unique_uuids_lock");
    np_msgproperty_enable_check_for_unique_uuids(prop);
    prop->recv_key = NULL;
    prop->send_key = NULL;

    prop->current_sender_token = NULL;
    prop->current_receive_token = NULL;
}
void np_msgproperty_disable_check_for_unique_uuids(np_msgproperty_t* self) {
    np_ctx_memory(self);
    _LOCK_ACCESS(&self->unique_uuids_lock) {
        np_tree_free( self->unique_uuids);
        self->unique_uuids_check = false;
    }
}
void np_msgproperty_enable_check_for_unique_uuids(np_msgproperty_t* self) {
    np_ctx_memory(self);
    _LOCK_ACCESS(&self->unique_uuids_lock){
        self->unique_uuids = np_tree_create();
        self->unique_uuids_check = true;
    }
}

bool _np_msgproperty_check_msg_uniquety(np_msgproperty_t* self, np_message_t* msg_to_check)
{
    np_ctx_memory(self);
    bool ret = true;
    _LOCK_ACCESS(&self->unique_uuids_lock) {
        if (self->unique_uuids_check) {

            if (np_tree_find_str(self->unique_uuids, msg_to_check->uuid) == NULL) {
                np_tree_insert_str( self->unique_uuids, msg_to_check->uuid, np_treeval_new_d(_np_message_get_expiery(msg_to_check)));
            }
            else {
                ret = false;
            }
        }
    }
    return ret;
}
void _np_msgproperty_remove_msg_from_uniquety_list(np_msgproperty_t* self, np_message_t* msg_to_remove)
{	
    np_ctx_memory(self);
    _LOCK_ACCESS(&self->unique_uuids_lock) {
        if (self->unique_uuids_check) {
            np_tree_del_str(self->unique_uuids, msg_to_remove->uuid);
        }
    }
}

void _np_msgproperty_job_msg_uniquety(np_state_t* context, NP_UNUSED  np_jobargs_t args) {
    

    // TODO: iter over msgproeprties and remove expired msg uuid from unique_uuids
    // RB_INSERT(rbt_msgproperty, __msgproperty_table, property);

    np_msgproperty_t* iter_prop = NULL;
    double now;
    RB_FOREACH(iter_prop, rbt_msgproperty, np_module(msgproperties)->__msgproperty_table)
    {
        if (iter_prop->unique_uuids_check) {
            sll_init_full(char_ptr, to_remove);

            _LOCK_ACCESS(&iter_prop->unique_uuids_lock) {
                np_tree_elem_t* iter_tree = NULL;
                now = np_time_now();
                RB_FOREACH(iter_tree, np_tree_s, iter_prop->unique_uuids)
                {
                    if (iter_tree->val.value.d < now) {
                        sll_append(char_ptr, to_remove, iter_tree->key.value.s);
                    }
                }
            }

            sll_iterator(char_ptr) iter_to_rm = sll_first(to_remove);
            if(iter_to_rm != NULL) {
                log_debug_msg(LOG_DEBUG | LOG_MSGPROPERTY ,"UNIQUITY removing %"PRIu32" from %"PRIu16" items from unique_uuids for %s", sll_size(to_remove), iter_prop->unique_uuids->size, iter_prop->msg_subject);
                while (iter_to_rm != NULL)
                {
                    _LOCK_ACCESS(&iter_prop->unique_uuids_lock) {
                        np_tree_del_str(iter_prop->unique_uuids, iter_to_rm->val);
                    }
                    sll_next(iter_to_rm);
                }
            }
            sll_free(char_ptr, to_remove);
        }
    }
}

void _np_msgproperty_t_del(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* property)
{
    log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_t_del(void* property){");
    np_msgproperty_t* prop = (np_msgproperty_t*) property;

    log_debug_msg(LOG_DEBUG, "Deleting msgproperty %s",prop->msg_subject);

    assert(prop != NULL);

    _LOCK_ACCESS(&prop->lock){

        if (prop->msg_subject != NULL) {
            free(prop->msg_subject);
            prop->msg_subject = NULL;
        }

        if (prop->rep_subject != NULL) {
            free(prop->rep_subject);
            prop->rep_subject = NULL;
        }

        if(prop->msg_cache_in != NULL ) {
            sll_free(np_message_ptr, prop->msg_cache_in);
        }

        if(prop->msg_cache_out != NULL ) {
            sll_free(np_message_ptr, prop->msg_cache_out);
        }
        if(prop->user_receive_clb != NULL) {
            sll_iterator(np_usercallback_ptr)  iter_user_receive_clb = sll_first(prop->user_receive_clb);
            while(iter_user_receive_clb != NULL){
                free(iter_user_receive_clb->val);
                sll_next(iter_user_receive_clb);
            }
            sll_free(np_usercallback_ptr, prop->user_receive_clb);
        }
        if(prop->user_send_clb != NULL){
            sll_iterator(np_usercallback_ptr)  iter_user_send_clb = sll_first(prop->user_send_clb);
            while(iter_user_send_clb != NULL){
                free(iter_user_send_clb->val);
                sll_next(iter_user_send_clb);
            }
            sll_free(np_usercallback_ptr, prop->user_send_clb);
        }
        _np_threads_mutex_destroy(context, &prop->unique_uuids_lock);
        np_tree_free(prop->unique_uuids);
        
        np_unref_obj(np_aaatoken_t, prop->current_receive_token, ref_msgproperty_current_recieve_token);
        np_unref_obj(np_aaatoken_t, prop->current_sender_token, ref_msgproperty_current_sender_token);


        sll_free(np_callback_t, prop->clb_transform);
        sll_free(np_callback_t, prop->clb_route);
        sll_free(np_callback_t, prop->clb_outbound);
        sll_free(np_callback_t, prop->clb_inbound);

        TSP_DESTROY( prop->msg_threshold);


    }
    _np_threads_mutex_destroy(context, &prop->lock);
    _np_threads_condition_destroy(context, &prop->msg_received);
    _np_threads_mutex_destroy(context, &prop->send_discovery_msgs_lock);
        

}

void _np_msgproperty_check_sender_msgcache(np_msgproperty_t* send_prop)
{
    np_ctx_memory(send_prop);
    // check if we are (one of the) sending node(s) of this kind of message
    // should not return NULL
    log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG,
            "this node is one sender of messages, checking msgcache (%p / %u) ...",
            send_prop->msg_cache_out, sll_size(send_prop->msg_cache_out));

    // get message from cache (maybe only for one way mep ?!)
    uint16_t msg_available = 0;
    _LOCK_ACCESS(&send_prop->lock)
    {
        msg_available = sll_size(send_prop->msg_cache_out);
    }

    bool sending_ok = true;

    while (0 < msg_available && true == sending_ok)
    {
        np_message_t* msg_out = NULL;
        _LOCK_ACCESS(&send_prop->lock)
        {
            // if messages are available in cache, send them !
            if (send_prop->cache_policy & FIFO)
                msg_out = sll_head(np_message_ptr, send_prop->msg_cache_out);
            if (send_prop->cache_policy & LIFO)
                msg_out = sll_tail(np_message_ptr, send_prop->msg_cache_out);

            // check for more messages in cache after head/tail command
            msg_available = sll_size(send_prop->msg_cache_out);
        }

        if(NULL != msg_out) {
            _np_msgproperty_threshold_decrease(send_prop);
            sending_ok = _np_send_msg(send_prop->msg_subject, msg_out, send_prop, NULL);
            np_unref_obj(np_message_t, msg_out, ref_msgproperty_msgcache);

            log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG,
                    "message in cache found and re-send initialized");
        }  else {
        		break;
        }
    }
}

void _np_msgproperty_check_receiver_msgcache(np_msgproperty_t* recv_prop, np_dhkey_t from)
{
    np_ctx_memory(recv_prop);
    log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG,
            "this node is the receiver of messages, checking msgcache (%p / %u) ...",
            recv_prop->msg_cache_in, sll_size(recv_prop->msg_cache_in));
    // get message from cache (maybe only for one way mep ?!)
    uint16_t msg_available = 0;

    _LOCK_ACCESS(&recv_prop->lock)
    {
        msg_available = sll_size(recv_prop->msg_cache_in);
    }

    while ( 0 < msg_available )
    {
        np_message_t* msg_in = NULL;
        sll_iterator(np_message_ptr) peek;
        _LOCK_ACCESS(&recv_prop->lock)
        {
            // if messages are available in cache, try to decode them !
            if (FLAG_CMP(recv_prop->cache_policy, FIFO)){
                peek = sll_first(recv_prop->msg_cache_in);
                if(peek != NULL && peek->val != NULL && _np_dhkey_cmp(_np_message_get_sender(peek->val), &from) ==0){
                    msg_in = sll_head(np_message_ptr, recv_prop->msg_cache_in);
                }
            }
            else if (FLAG_CMP(recv_prop->cache_policy , LIFO)){
                peek = sll_last(recv_prop->msg_cache_in);
                if(peek != NULL && peek->val != NULL && _np_dhkey_cmp(_np_message_get_sender(peek->val), &from) ==0){
                    msg_in = sll_tail(np_message_ptr, recv_prop->msg_cache_in);
                }
            }

            msg_available = sll_size(recv_prop->msg_cache_in);
        }

        if(NULL != msg_in) {
            _np_msgproperty_threshold_decrease(recv_prop);
            if(_np_job_submit_msgin_event(0.0, recv_prop, context->my_node_key, msg_in, NULL)){
                np_unref_obj(np_message_t, msg_in, ref_msgproperty_msgcache);
            }else{
                 if (FLAG_CMP(recv_prop->cache_policy, FIFO)){
                    sll_prepend(np_message_ptr, recv_prop->msg_cache_in,msg_in);                    
                }
                else if (FLAG_CMP(recv_prop->cache_policy , LIFO)){
                    sll_append(np_message_ptr, recv_prop->msg_cache_in, msg_in);
                }
            }
        } else {
        		break;
        }

        TSP_GET(uint16_t, recv_prop->msg_threshold, current_threshold);
        if (current_threshold > recv_prop->max_threshold) break;
    }
}

void _np_msgproperty_add_msg_to_send_cache(np_msgproperty_t* msg_prop, np_message_t* msg_in)
{
    np_ctx_memory(msg_prop);
    _LOCK_ACCESS(&msg_prop->lock)
    {
        // cache already full ?
        if (msg_prop->max_threshold <= sll_size(msg_prop->msg_cache_out))
        {
            log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "send msg cache full, checking overflow policy ...");

            if (OVERFLOW_PURGE == (msg_prop->cache_policy & OVERFLOW_PURGE))
            {
                log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "OVERFLOW_PURGE: discarding message in send msgcache for %s", msg_prop->msg_subject);
                np_message_t* old_msg = NULL;

                if ((msg_prop->cache_policy & FIFO) > 0)
                    old_msg = sll_head(np_message_ptr, msg_prop->msg_cache_out);

                if ((msg_prop->cache_policy & LIFO) > 0)
                    old_msg = sll_tail(np_message_ptr, msg_prop->msg_cache_out);

                if (old_msg != NULL)
                {
                    // TODO: add callback hook to allow user space handling of discarded message
                    _np_msgproperty_threshold_decrease(msg_prop);
                    np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
                }
            }

            if (FLAG_CMP(msg_prop->cache_policy, OVERFLOW_REJECT))
            {
                log_msg(LOG_WARN,
                        "rejecting new message because cache is full");
                break;
            }
        }
        _np_msgproperty_threshold_increase(msg_prop);
        sll_prepend(np_message_ptr, msg_prop->msg_cache_out, msg_in);

        log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "added message to the sender msgcache (%p / %d) ...",
                msg_prop->msg_cache_out, sll_size(msg_prop->msg_cache_out));
        np_ref_obj(np_message_t, msg_in, ref_msgproperty_msgcache);
    }
}

void _np_msgproperty_cleanup_receiver_cache(np_msgproperty_t* msg_prop) {
    np_ctx_memory(msg_prop);
    _LOCK_ACCESS(&msg_prop->lock)
    {
        sll_iterator(np_message_ptr) iter_prop_msg_cache_in = sll_first(msg_prop->msg_cache_in);
        while (iter_prop_msg_cache_in != NULL)
        {
            sll_iterator(np_message_ptr) old_iter = iter_prop_msg_cache_in;
            sll_next(iter_prop_msg_cache_in); // we need to iterate before we delete the old iter
            np_message_t* old_msg = old_iter->val;
            if (_np_message_is_expired(old_msg)) {
                log_msg(LOG_WARN,"purging expired message (subj: %s, uuid: %s) from receiver cache ...", msg_prop->msg_subject, old_msg->uuid);
                sll_delete(np_message_ptr, msg_prop->msg_cache_in, old_iter);
                np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
                _np_msgproperty_threshold_decrease(msg_prop);
            }
        }
    }
    log_msg(LOG_AAATOKEN | LOG_DEBUG, "cleanup receiver cache for subject %s done", msg_prop->msg_subject);
}

void _np_msgproperty_add_msg_to_recv_cache(np_msgproperty_t* msg_prop, np_message_t* msg_in)
{
    np_ctx_memory(msg_prop);
    _LOCK_ACCESS(&msg_prop->lock)
    {
        // cache already full ?
        if (msg_prop->max_threshold <= sll_size(msg_prop->msg_cache_in))
        {
            log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "recv msg cache full, checking overflow policy ...");

            if (OVERFLOW_PURGE == (msg_prop->cache_policy & OVERFLOW_PURGE))
            {
                log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "OVERFLOW_PURGE: discarding message in recv msgcache for %s", msg_prop->msg_subject);
                np_message_t* old_msg = NULL;

                if (FLAG_CMP(msg_prop->cache_policy, FIFO))
                    old_msg = sll_head(np_message_ptr, msg_prop->msg_cache_in);
                else if (FLAG_CMP(msg_prop->cache_policy, LIFO) )
                    old_msg = sll_tail(np_message_ptr, msg_prop->msg_cache_in);

                if (old_msg != NULL)
                {
                    // TODO: add callback hook to allow user space handling of discarded message
                    _np_msgproperty_threshold_decrease(msg_prop);
                    np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
                }
            }

            if (FLAG_CMP(msg_prop->cache_policy , OVERFLOW_REJECT))
            {
                log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG,
                        "rejecting new message because cache is full");
                continue;
            }
        }
        _np_msgproperty_threshold_increase(msg_prop);
        np_ref_obj(np_message_t, msg_in, ref_msgproperty_msgcache);
        sll_prepend(np_message_ptr, msg_prop->msg_cache_in, msg_in);

        log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "added message to the recv msgcache (%p / %d) ...",
                      msg_prop->msg_cache_in, sll_size(msg_prop->msg_cache_in));
        
    }
}

void _np_msgproperty_threshold_increase(np_msgproperty_t* self) {
    np_ctx_memory(self);
    TSP_SCOPE(self->msg_threshold) {
        if(self->msg_threshold < self->max_threshold){
            self->msg_threshold++;
        }
    }
}

bool _np_messsage_threshold_breached(np_msgproperty_t* self) {
    np_ctx_memory(self);
    bool ret = false;
    TSP_SCOPE(self->msg_threshold) {
        if((self->msg_threshold+1) >= self->max_threshold){
            ret = true;
        }
    }
    return ret;
}

void _np_msgproperty_threshold_decrease(np_msgproperty_t* self) {
    np_ctx_memory(self);
    TSP_SCOPE(self->msg_threshold){
        if(self->msg_threshold > 0){
            self->msg_threshold--;
        }
    }
}

np_message_intent_public_token_t* _np_msgproperty_upsert_token(np_msgproperty_t* prop) {
    
    np_ctx_memory(prop);
    np_message_intent_public_token_t* ret = _np_aaatoken_get_local_mx(context, prop->msg_subject);

    double now = np_time_now();
    if (NULL == ret
// 		|| _np_aaatoken_is_valid(ret, np_aaatoken_type_message_intent) == false
        || (ret->expires_at - now) <= fmin(prop->token_min_ttl, MISC_RETRANSMIT_MSG_TOKENS_SEC)
        )
    {
        // Create a new msg token
        log_msg(LOG_AAATOKEN | LOG_DEBUG, "--- refresh for subject token: %25s --------", prop->msg_subject);
        np_aaatoken_t* msg_token_new = _np_token_factory_new_message_intent_token(prop);
        log_debug_msg(LOG_AAATOKEN | LOG_ROUTING | LOG_DEBUG, "creating new token for subject %s (%s replaces %s) ", prop->msg_subject, msg_token_new->uuid, ret == NULL ? "-" : ret->uuid);		
        _np_aaatoken_add_local_mx(msg_token_new->subject, msg_token_new);
        np_unref_obj(np_aaatoken_t, ret, "_np_aaatoken_get_local_mx");
        ret = msg_token_new;		
        ref_replace_reason(np_aaatoken_t, ret, "_np_token_factory_new_message_intent_token", FUNC);
    
    } else {
        ref_replace_reason(np_aaatoken_t, ret, "_np_aaatoken_get_local_mx", FUNC);
    }

    _LOCK_ACCESS(&prop->lock) {
        np_tree_find_str(ret->extensions, "msg_threshold")->val.value.ui = prop->msg_threshold;
    }
    log_msg(LOG_AAATOKEN | LOG_DEBUG, "--- done refresh for subject token: %25s new token has uuid %s", prop->msg_subject, ret->uuid);

    ASSERT(_np_aaatoken_is_valid(ret, np_aaatoken_type_message_intent), "AAAToken needs to be valid");
    
    return ret;
}


void np_msgproperty4user(struct np_mx_properties* dest, np_msgproperty_t* src) {

    dest->intent_ttl = src->token_max_ttl;
    dest->intent_update_after = src->token_min_ttl;
    dest->message_ttl = src->msg_ttl;
    if(src->rep_subject != NULL) {
        strncpy(dest->reply_subject, src->rep_subject, 255);
    }
    else {
        memset(dest->reply_subject, 0, sizeof(dest->reply_subject));
    }
    
    // ackmode conversion
    switch (src->ack_mode)
    {
    case ACK_NONE:
        dest->ackmode = NP_MX_ACK_NONE;
        break;
    case ACK_DESTINATION:
        dest->ackmode = NP_MX_ACK_DESTINATION;
        break;
    case ACK_CLIENT:
        dest->ackmode = NP_MX_ACK_CLIENT;
        break;
    default:
        dest->ackmode = NP_MX_ACK_NONE;
        break;
    }

    // cache_policy conversion
    if (FLAG_CMP(src->cache_policy, FIFO)) {
        if (FLAG_CMP(src->cache_policy, OVERFLOW_REJECT)) {
            dest->cache_policy = NP_MX_FIFO_REJECT;
        }
        else {
            dest->cache_policy = NP_MX_FIFO_PURGE;
        }			
    }
    else {
        if (FLAG_CMP(src->cache_policy, OVERFLOW_REJECT)) {
            dest->cache_policy = NP_MX_LIFO_REJECT;
        }
        else {
            dest->cache_policy = NP_MX_LIFO_PURGE;
        }
    }
}

void np_msgproperty_from_user(np_state_t* context, np_msgproperty_t* dest, struct np_mx_properties* src) {

	assert(context != NULL);
    assert(src != NULL);
    assert(dest != NULL);
    dest->token_max_ttl = src->intent_ttl;
    dest->token_min_ttl = src->intent_update_after;
    dest->msg_ttl = src->message_ttl;

    if (src->reply_subject[0] != '\0' && (dest->rep_subject == NULL || strncmp(dest->rep_subject, src->reply_subject, 255) != 0))
    {
        char* old = dest->rep_subject;
        dest->rep_subject = strndup(src->reply_subject, 255);
        if(old) free(old);
    } else {
         dest->rep_subject = NULL;
    }

    // ackmode conversion
    switch (src->ackmode)
    {
    case NP_MX_ACK_DESTINATION:
        dest->ack_mode = ACK_DESTINATION;
        break;
    case NP_MX_ACK_CLIENT:
        dest->ack_mode = ACK_CLIENT;
        break;
    default:
        dest->ack_mode = ACK_NONE;
        break;
    }

    switch (src->cache_policy)
    {
    case NP_MX_FIFO_REJECT:
        dest->cache_policy = FIFO | OVERFLOW_REJECT;
        break;
    case NP_MX_FIFO_PURGE:
        dest->cache_policy = FIFO | OVERFLOW_PURGE;
        break;
    case NP_MX_LIFO_REJECT:
        dest->cache_policy = LIFO | OVERFLOW_REJECT;
        break;
    case NP_MX_LIFO_PURGE:
        dest->cache_policy = LIFO | OVERFLOW_PURGE;
        break;
    default:
        break;
    }

    // mep type conversion	
    dest->mep_type= ANY_TO_ANY;
}
