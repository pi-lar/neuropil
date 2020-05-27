//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that a node can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>

#include "core/np_comp_msgproperty.h"
#include "core/np_comp_intent.h"

#include "np_axon.h"
#include "np_aaatoken.h"
#include "np_bloom.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_message.h"
#include "np_pheromones.h"
#include "np_statistics.h"
#include "np_token_factory.h"
#include "np_responsecontainer.h"
#include "np_tree.h"
#include "np_treeval.h"

#include "util/np_event.h"
#include "util/np_statemachine.h"

#include "neuropil_data.h"

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_msgproperty_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_msgproperty_ptr);

#include "../np_msgproperty_init.c"

void _np_msgproperty_t_new(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* property)
{
    log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_t_new(void* property){");
    np_msgproperty_t* prop = (np_msgproperty_t*) property;

    prop->token_min_ttl = MSGPROPERTY_DEFAULT_MIN_TTL_SEC;
    prop->token_max_ttl = MSGPROPERTY_DEFAULT_MAX_TTL_SEC;

    prop->msg_audience	= NULL;
    prop->msg_subject	= NULL;
    prop->rep_subject	= NULL;

    prop->mode_type = OUTBOUND | INBOUND;
    prop->mep_type  = DEFAULT_TYPE;
    prop->ack_mode  = ACK_NONE;
    prop->priority  = PRIORITY_MOD_USER_DEFAULT;
    prop->retry     = 5;
    prop->msg_ttl   = 60.0;

    prop->cache_size    = 8;
    prop->max_threshold = 2;
    prop->msg_threshold = 0;

    double now = np_time_now();
    prop->is_internal = false;
    prop->last_update = now;
    prop->last_intent_tx_update = now;
    prop->last_intent_rx_update = now;
    prop->last_pheromone_tx_update = now;
    prop->last_pheromone_rx_update = now;

    sll_init(np_evt_callback_t, prop->clb_inbound);
    sll_init(np_evt_callback_t, prop->clb_outbound);

    sll_init(np_usercallback_ptr, prop->user_receive_clb);
    sll_init(np_usercallback_ptr, prop->user_send_clb);

    // cache which will hold up to max_threshold messages
    prop->cache_policy = FIFO | OVERFLOW_PURGE;

    prop->response_handler    = np_tree_create(); // only used for msghandler NP_ACK
    prop->redelivery_messages = np_tree_create(); // only used for msghandler "is_internal=false"

    sll_init(np_message_ptr, prop->msg_cache_in);
    sll_init(np_message_ptr, prop->msg_cache_out);

    prop->unique_uuids_in  = np_tree_create();
    prop->unique_uuids_out = np_tree_create();
    prop->unique_uuids_check = true;

    prop->current_sender_token = NULL;
    prop->current_receive_token = NULL;
}

void _np_msgproperty_t_del(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* property)
{
    log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_t_del(void* property){");
    np_msgproperty_t* prop = (np_msgproperty_t*) property;

    log_debug_msg(LOG_DEBUG, "Deleting msgproperty %s",prop->msg_subject);

    assert(prop != NULL);

    if (prop->msg_subject != NULL) {
        free(prop->msg_subject); prop->msg_subject = NULL;
    }
    if (prop->rep_subject != NULL) {
        free(prop->rep_subject); prop->rep_subject = NULL;
    }

    np_tree_free(prop->unique_uuids_in);
    np_tree_free(prop->unique_uuids_out);
    np_tree_free(prop->response_handler); //
    np_tree_free(prop->redelivery_messages); //

    if(prop->msg_cache_in != NULL ) {
        sll_free(np_message_ptr, prop->msg_cache_in);
    }
    if(prop->msg_cache_out != NULL ) {
        sll_free(np_message_ptr, prop->msg_cache_out);
    }

    if(prop->user_receive_clb != NULL) {
        sll_free(np_usercallback_ptr, prop->user_receive_clb);
    }
    if(prop->user_send_clb != NULL){
        sll_free(np_usercallback_ptr, prop->user_send_clb);
    }
    np_tree_free(prop->unique_uuids_in);
    np_tree_free(prop->unique_uuids_out);
    
    np_unref_obj(np_aaatoken_t, prop->current_receive_token, ref_msgproperty_current_recieve_token);
    np_unref_obj(np_aaatoken_t, prop->current_sender_token, ref_msgproperty_current_sender_token);

    sll_free(np_evt_callback_t, prop->clb_outbound);
    sll_free(np_evt_callback_t, prop->clb_inbound);
}

/**
 ** _np_msgproperty_init
 ** Initialize message property subsystem.
 **/
bool _np_msgproperty_init (np_state_t* context)
{
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

            // receiving property
            np_dhkey_t search_key_rx = np_dhkey_create_from_hostport(property->msg_subject, "local_rx");
            np_key_t* my_property_key_rx = _np_keycache_find_or_create(context, search_key_rx);
            np_util_event_t ev_rx = { .type=(evt_property|evt_internal), .context=context, .user_data=property };
            _np_key_handle_event(my_property_key_rx, ev_rx, false);
            np_ref_obj(np_msgproperty_t, property, ref_system_msgproperty); 
            np_unref_obj(np_key_t, my_property_key_rx, "_np_keycache_find_or_create");

            // fprintf(stdout, "register handler (tx): %s\n", property->msg_subject);
            // sending property
            np_dhkey_t search_key_tx = np_dhkey_create_from_hostport(property->msg_subject, "local_tx");
            np_key_t* my_property_key_tx = _np_keycache_find_or_create(context, search_key_tx);
            np_util_event_t ev_tx = { .type=(evt_property|evt_internal), .context=context, .user_data=property };
            _np_key_handle_event(my_property_key_tx, ev_tx, false);
            np_ref_obj(np_msgproperty_t, property, ref_system_msgproperty); 
            np_unref_obj(np_key_t, my_property_key_tx, "_np_keycache_find_or_create");
        }            
        sll_next(__np_internal_messages);
    }
    sll_free(np_msgproperty_ptr, msgproperties);
    return true;
}

void _np_msgproperty_destroy (np_state_t* context)
{   
    // NEUROPIL_INTERN_MESSAGES
    np_sll_t(np_msgproperty_ptr, msgproperties);
    msgproperties = default_msgproperties(context);
    sll_iterator(np_msgproperty_ptr) __np_internal_messages = sll_first(msgproperties);
    while (__np_internal_messages != NULL) {
        np_msgproperty_t* property = __np_internal_messages->val;

        np_dhkey_t search_key_rx = np_dhkey_create_from_hostport(property->msg_subject, "local_rx");
        _np_keycache_remove(context, search_key_rx);

        np_dhkey_t search_key_tx = np_dhkey_create_from_hostport(property->msg_subject, "local_tx");
        _np_keycache_remove(context, search_key_tx);

        sll_next(__np_internal_messages);
    }
}

/**
 ** returns the msgproperty struct #func# for the given #mode_type# and #subject#,
 **/
np_msgproperty_t* _np_msgproperty_get(np_state_t* context, np_msg_mode_type mode_type, const char* subject)
{
    log_trace_msg(LOG_TRACE, "start: np_msgproperty_t* np_msgproperty_get(context, np_msg_mode_type mode_type, const char* subject){");
    assert(subject != NULL);

    np_msgproperty_t* ret = NULL;

    if (FLAG_CMP(mode_type, INBOUND) )
    {   // search receiving property
        np_dhkey_t search_key_rx = np_dhkey_create_from_hostport(subject, "local_rx");
        np_key_t* my_property_key_rx = _np_keycache_find(context, search_key_rx);

        if (my_property_key_rx == NULL) return NULL;
        
        log_debug_msg(LOG_DEBUG, "get i: msgproperty %s: get %p from list: %p (%d)", subject, sll_first(my_property_key_rx->entities)->val, my_property_key_rx, sll_size(my_property_key_rx->entities));
        // NP_CAST(sll_first(my_property_key_rx->entities), np_msgproperty_t, property);
        // if (np_memory_get_type(property) == np_memory_types_np_msgproperty_t)
        assert((np_memory_get_type(sll_first(my_property_key_rx->entities)->val) == np_memory_types_np_msgproperty_t));
        ret = sll_first(my_property_key_rx->entities)->val;
        np_unref_obj(np_key_t, my_property_key_rx, "_np_keycache_find");
        return ret; 
        // else 
        // return NULL;
    }

    if (FLAG_CMP(mode_type, OUTBOUND) )
    {
        // search sending property
        np_dhkey_t search_key_tx = np_dhkey_create_from_hostport(subject, "local_tx");
        np_key_t* my_property_key_tx = _np_keycache_find(context, search_key_tx);

        if (my_property_key_tx == NULL) return NULL;

        log_debug_msg(LOG_DEBUG, "get o: msgproperty %s: get %p from list: %p(%d)", subject, sll_first(my_property_key_tx->entities)->val, my_property_key_tx, sll_size(my_property_key_tx->entities));
        // NP_CAST(sll_first(my_property_key_tx->entities), np_msgproperty_t, property);
        // if (np_memory_get_type(property) == np_memory_types_np_msgproperty_t)
        assert((np_memory_get_type(sll_first(my_property_key_tx->entities)->val) == np_memory_types_np_msgproperty_t));
        ret = sll_first(my_property_key_tx->entities)->val;
        np_unref_obj(np_key_t, my_property_key_tx, "_np_keycache_find");
        return ret; 
        // else 
        // return NULL;
    }
    
    log_msg(LOG_WARN, "msgproperty %s: unknown send/receive mode", subject);
    return NULL; 
}

/**
 ** returns the msgproperty struct #func# for the given #mode_type# and #subject#, and creates it if it is not yet present
 **/
np_msgproperty_t* _np_msgproperty_get_or_create(np_state_t* context, np_msg_mode_type mode_type, const char* subject)
{
    np_msgproperty_t* ret = _np_msgproperty_get(context, mode_type, subject);
    bool created= false;

    if (NULL == ret)
    {
        log_msg(LOG_INFO | LOG_MSGPROPERTY, "Indirect %"PRIu8" creation of msgproperty %s", mode_type, subject);	
        // create a default set of properties for listening to messages
        np_new_obj(np_msgproperty_t, ret);
        ret->msg_subject = strndup(subject, 255);
        ret->mode_type = mode_type;
        ret->mep_type = ANY_TO_ANY;
        np_msgproperty_register(ret);
    } 

    if(created) {
        np_unref_obj(np_msgproperty_t, ret, ref_obj_creation);
    }
    return ret;
}

void np_msgproperty_register(np_msgproperty_t* msg_property)
{
    np_ctx_memory(msg_property);
    log_trace_msg(LOG_TRACE, "start: void np_msgproperty_register(np_msgproperty_t* msgprops){ ");
    log_debug_msg(LOG_DEBUG, "registering user property: %s ", msg_property->msg_subject);

    if (strlen(msg_property->msg_subject) > 0)
    {
        log_debug_msg(LOG_DEBUG, "register handler: %s", msg_property->msg_subject);

        if (FLAG_CMP(msg_property->mode_type, INBOUND) ) {
            // receiving property
            np_dhkey_t search_key_rx = np_dhkey_create_from_hostport(msg_property->msg_subject, "local_rx");
            np_key_t* my_property_key_rx = _np_keycache_find_or_create(context, search_key_rx);
            np_util_event_t ev_rx = { .type=(evt_property|evt_internal), .context=context, .user_data=msg_property };
            _np_key_handle_event(my_property_key_rx, ev_rx, false);
            np_ref_obj(np_msgproperty_t, msg_property, ref_system_msgproperty); 
            np_unref_obj(np_key_t, my_property_key_rx, "_np_keycache_find_or_create");
            log_debug_msg(LOG_DEBUG, "register handler: %s", _np_key_as_str(my_property_key_rx));
        }

        if (FLAG_CMP(msg_property->mode_type, OUTBOUND) ) {
            // sending property
            np_dhkey_t search_key_tx = np_dhkey_create_from_hostport(msg_property->msg_subject, "local_tx");
            np_key_t* my_property_key_tx = _np_keycache_find_or_create(context, search_key_tx);
            np_util_event_t ev_tx = { .type=(evt_property|evt_internal), .context=context, .user_data=msg_property };
            _np_key_handle_event(my_property_key_tx, ev_tx, false);
            np_ref_obj(np_msgproperty_t, msg_property, ref_system_msgproperty); 
            np_unref_obj(np_key_t, my_property_key_tx, "_np_keycache_find_or_create");
            log_debug_msg(LOG_DEBUG, "register handler: %s", _np_key_as_str(my_property_key_tx));
        }
    }            
}

np_dhkey_t _np_msgproperty_dhkey(np_msg_mode_type mode_type, const char* subject) 
{
    if (mode_type == INBOUND)
        return np_dhkey_create_from_hostport(subject, "local_rx");
    else
        return np_dhkey_create_from_hostport(subject, "local_tx");
}

bool _np_msgproperty_check_msg_uniquety_in(np_msgproperty_t* self, np_message_t* msg_to_check)
{
    bool ret = true;
    if (self->unique_uuids_check) 
    {
        char _to_check[50] = {0};
        if (msg_to_check->is_single_part) {
            uint16_t chunks   = np_tree_find_str(msg_to_check->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[0];
            uint16_t chunk_no = np_tree_find_str(msg_to_check->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[1];
            sprintf(_to_check, "%s:%05d:%05d", msg_to_check->uuid, chunks, chunk_no);
        } else {
            sprintf(_to_check, "%s:%05d:%05d", msg_to_check->uuid, 0, 0);
        }

        if (np_tree_find_str(self->unique_uuids_in, _to_check) == NULL) 
        {
            np_tree_insert_str( self->unique_uuids_in, _to_check, np_treeval_new_d(_np_message_get_expiery(msg_to_check)));
        }
        else 
        {
            ret = false;
        }
    }
    return ret;
}

bool _np_msgproperty_check_msg_uniquety_out(np_msgproperty_t* self, np_message_t* msg_to_check)
{
    bool ret = true;
    if (self->unique_uuids_check) 
    {
        char _to_check[50] = {0};
        if (msg_to_check->is_single_part) {
            uint16_t chunks   = np_tree_find_str(msg_to_check->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[0];
            uint16_t chunk_no = np_tree_find_str(msg_to_check->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[1];
            sprintf(_to_check, "%s:%05d:%05d", msg_to_check->uuid, chunks, chunk_no);
        } else {
            sprintf(_to_check, "%s:%05d:%05d", msg_to_check->uuid, 0, 0);
        }

        if (np_tree_find_str(self->unique_uuids_out, _to_check) == NULL) 
        {
            np_tree_insert_str( self->unique_uuids_out, _to_check, np_treeval_new_d(_np_message_get_expiery(msg_to_check)));
        }
        else 
        {
            ret = false;
        }
    }
    return ret;
}

void _np_msgproperty_remove_msg_from_uniquety_list(np_msgproperty_t* self, np_message_t* msg_to_remove)
{	
    if (self->unique_uuids_check) {
        np_tree_del_str(self->unique_uuids_in, msg_to_remove->uuid);
    }
}

void _np_msgproperty_job_msg_uniquety(np_msgproperty_t* self) 
{
    np_ctx_memory(self);
    // TODO: iter over msgproeprties and remove expired msg uuid from unique_uuids
    double now;
    if (self->unique_uuids_check) 
    {
        sll_init_full(char_ptr, to_remove);

        np_tree_elem_t* iter_tree = NULL;
        now = np_time_now();
        RB_FOREACH(iter_tree, np_tree_s, self->unique_uuids_in)
        {
            if (iter_tree->val.value.d < now) {
                sll_append(char_ptr, to_remove, iter_tree->key.value.s);
            }
        }

        sll_iterator(char_ptr) iter_to_rm = sll_first(to_remove);
        if(iter_to_rm != NULL) {
            log_debug_msg(LOG_DEBUG | LOG_MSGPROPERTY ,"UNIQUITY removing %"PRIu32" from %"PRIu16" items from unique_uuids for %s", 
                                                        sll_size(to_remove), self->unique_uuids_in->size, self->msg_subject);
            while (iter_to_rm != NULL)
            {
                np_tree_del_str(self->unique_uuids_in, iter_to_rm->val);
                sll_next(iter_to_rm);
            }
        }
        sll_clear(char_ptr, to_remove);

        iter_tree = NULL;
        RB_FOREACH(iter_tree, np_tree_s, self->unique_uuids_out)
        {
            if (iter_tree->val.value.d < now) {
                sll_append(char_ptr, to_remove, iter_tree->key.value.s);
            }
        }

        iter_to_rm = sll_first(to_remove);
        if(iter_to_rm != NULL) {
            log_debug_msg(LOG_DEBUG | LOG_MSGPROPERTY ,"UNIQUITY removing %"PRIu32" from %"PRIu16" items from unique_uuids for %s", 
                                                        sll_size(to_remove), self->unique_uuids_out->size, self->msg_subject);
            while (iter_to_rm != NULL)
            {
                np_tree_del_str(self->unique_uuids_out, iter_to_rm->val);
                sll_next(iter_to_rm);
            }
        }
        sll_free(char_ptr, to_remove);
    }
}

void _np_msgproperty_cleanup_response_handler(np_msgproperty_t* self) 
{
    np_ctx_memory(self);

    // remove expired msg uuid from response uuids
    double now = np_time_now();
    sll_init_full(char_ptr, to_remove);

    np_tree_elem_t* iter_tree = NULL;
    np_responsecontainer_t* current = NULL;
    now = np_time_now();

    RB_FOREACH(iter_tree, np_tree_s, self->response_handler)
    {
        bool handle_event = false;

        current = (np_responsecontainer_t *) iter_tree->val.value.v;
        // TODO: find correct dhkey from responsecontainer and use it as target_dhkey
        np_util_event_t response_event = { .context=context, .user_data=current };

        if (current->received_at < now && current->received_at > current->send_at) 
        {   // notify about ack response
            response_event.type = (evt_internal|evt_response);
            sll_append(char_ptr, to_remove, iter_tree->key.value.s);
            handle_event = true;
        }
        else if (current->expires_at < now) 
        {   // notify about timeout
            response_event.type = (evt_timeout|evt_response);
            sll_append(char_ptr, to_remove, iter_tree->key.value.s);
            handle_event = true;
        }
        
        np_dhkey_t _null = {0};
        if (handle_event) 
        {
            np_ref_obj(np_responsecontainer_t, response_event.user_data, ref_obj_usage);
            if (!_np_dhkey_equal(&current->msg_dhkey, &_null) ) 
            {  // clean up message redlivery
                response_event.target_dhkey=current->msg_dhkey;
                _np_keycache_handle_event(context, current->msg_dhkey, response_event, false); 
            }
            if (!_np_dhkey_equal(&current->dest_dhkey, &_null) ) 
            {   // clean up ping ack
                response_event.target_dhkey=current->dest_dhkey;
                _np_keycache_handle_event(context, current->dest_dhkey, response_event, false);
            }
            np_unref_obj(np_responsecontainer_t, response_event.user_data, ref_obj_creation);
        }
    }

    sll_iterator(char_ptr) iter_to_rm = sll_first(to_remove);
    if(iter_to_rm != NULL) 
    {
        log_debug_msg(LOG_DEBUG | LOG_MSGPROPERTY ,"RESPONSE removing %"PRIu32" from %"PRIu16" items from response_handler", 
                                                    sll_size(to_remove), self->response_handler->size);
        while (iter_to_rm != NULL)
        {
            np_tree_del_str(self->response_handler, iter_to_rm->val);
            sll_next(iter_to_rm);
        }
    }
    sll_free(char_ptr, to_remove);
}

void _np_msgproperty_check_sender_msgcache(np_msgproperty_t* send_prop)
{
    np_ctx_memory(send_prop);
    // check if we are (one of the) sending node(s) of this kind of message
    // should not return NULL
    log_debug_msg(LOG_DEBUG,
            "this node is one sender of messages, checking msgcache (%p / %u) ...",
            send_prop->msg_cache_out, sll_size(send_prop->msg_cache_out));

    // get message from cache (maybe only for one way mep ?!)
    uint16_t msg_available = 0;
    msg_available = sll_size(send_prop->msg_cache_out);

    while (0 < msg_available && msg_available <= send_prop->cache_size)
    {
        np_message_t* msg_out = NULL;
        // if messages are available in cache, send them !
        if (FLAG_CMP(send_prop->cache_policy, FIFO) )
            msg_out = sll_head(np_message_ptr, send_prop->msg_cache_out);
        else if (FLAG_CMP(send_prop->cache_policy, LIFO) )
            msg_out = sll_tail(np_message_ptr, send_prop->msg_cache_out);
        else
            break;
        
        // check for more messages in cache after head/tail command
        msg_available = sll_size(send_prop->msg_cache_out);

        if(NULL != msg_out) 
        {
            np_dhkey_t subject_dhkey = _np_msgproperty_dhkey(OUTBOUND, send_prop->msg_subject);
            np_dhkey_t target_dhkey = {0};

            np_ref_obj(np_message_t, msg_out, ref_message_in_send_system); // this ref reason has been removed on first try, re-add
            np_util_event_t send_event = { .type=(evt_userspace | evt_message), .context=context, .user_data=msg_out, .target_dhkey=target_dhkey };
            _np_keycache_handle_event(context, subject_dhkey, send_event, false);

            np_unref_obj(np_message_t, msg_out, ref_msgproperty_msgcache);
            log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG,
                    "message in sender cache found and resend initialized");
        }  else {
        		break;
        }
    }
}

void _np_msgproperty_check_receiver_msgcache(np_msgproperty_t* recv_prop, np_dhkey_t from)
{
    np_ctx_memory(recv_prop);
    log_debug_msg(LOG_DEBUG,
            "this node is the receiver of messages, checking msgcache (%p / %u) ...",
            recv_prop->msg_cache_in, sll_size(recv_prop->msg_cache_in));
    // get message from cache (maybe only for one way mep ?!)
    uint16_t msg_available = 0;

    msg_available = sll_size(recv_prop->msg_cache_in);

    while (0 < msg_available && msg_available <= recv_prop->cache_size)
    {
        // grab a message
        np_message_t* msg_in = NULL;
        sll_iterator(np_message_ptr) peek;
        // if messages are available in cache, try to decode them !
        if (FLAG_CMP(recv_prop->cache_policy, FIFO)){
            peek = sll_first(recv_prop->msg_cache_in);
            if(peek != NULL && peek->val != NULL && _np_dhkey_cmp(_np_message_get_sender(peek->val), &from) ==0){
                msg_in = sll_head(np_message_ptr, recv_prop->msg_cache_in);
            }
        }
        else 
        if (FLAG_CMP(recv_prop->cache_policy , LIFO))
        {
            peek = sll_last(recv_prop->msg_cache_in);
            if(peek != NULL && peek->val != NULL && _np_dhkey_cmp(_np_message_get_sender(peek->val), &from) ==0){
                msg_in = sll_tail(np_message_ptr, recv_prop->msg_cache_in);
            }
        }
        // recalc number of available messages
        msg_available = sll_size(recv_prop->msg_cache_in);

        // handle selected message
        if(NULL != msg_in) 
        {
            np_ref_obj(np_message_t, msg_in, ref_message_in_send_system); // this ref reason has been removed on first try, re-add
            np_dhkey_t in_handler = _np_msgproperty_dhkey(INBOUND, recv_prop->msg_subject);
            np_util_event_t msg_in_event = { .type=(evt_external|evt_message), .context=context, .target_dhkey=in_handler, .user_data=msg_in };
            _np_keycache_handle_event(context, in_handler, msg_in_event, false);

            np_unref_obj(np_message_t, msg_in, ref_msgproperty_msgcache);
            log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG,
                    "message in receiver cache found and redelivery initialized");

        } else {
            break;
        }

        // do not continue processing message if max treshold is reached
        if (recv_prop->msg_threshold > recv_prop->max_threshold) break;
    }
}

void _np_msgproperty_add_msg_to_send_cache(np_msgproperty_t* msg_prop, np_message_t* msg_in) 
{
    np_ctx_memory(msg_prop);
    // cache already full ?
    if (msg_prop->cache_size <= sll_size(msg_prop->msg_cache_out))
    {
        log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "send msg cache full, checking overflow policy ...");

        if (FLAG_CMP(msg_prop->cache_policy, OVERFLOW_PURGE))
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
                np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
            }
        }

        if (FLAG_CMP(msg_prop->cache_policy, OVERFLOW_REJECT))
        {
            log_msg(LOG_WARN,
                    "rejecting new message because cache is full");
            return;
        }
    }

    np_ref_obj(np_message_t, msg_in, ref_msgproperty_msgcache);
    sll_prepend(np_message_ptr, msg_prop->msg_cache_out, msg_in);

    log_debug_msg(LOG_DEBUG, "added message to the sender msgcache (%p / %d) ...",
            msg_prop->msg_cache_out, sll_size(msg_prop->msg_cache_out));
}

void _np_msgproperty_cleanup_receiver_cache(np_msgproperty_t* msg_prop)
{
    np_ctx_memory(msg_prop);

    log_debug(LOG_MSGPROPERTY,
            "this node is a receiver of messages, checking msgcache (%s: %p / %u) ...",
            msg_prop->msg_subject, msg_prop->msg_cache_in, sll_size(msg_prop->msg_cache_in));

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
        }
    }
    log_msg(LOG_AAATOKEN | LOG_DEBUG, "cleanup receiver cache for subject %s done", msg_prop->msg_subject);
}

void _np_msgproperty_cleanup_sender_cache(np_msgproperty_t* msg_prop)
{
    np_ctx_memory(msg_prop);

    log_debug(LOG_MSGPROPERTY,
            "this node is a sender of messages, checking msgcache (%s: %p / %u) ...",
            msg_prop->msg_subject, msg_prop->msg_cache_out, sll_size(msg_prop->msg_cache_out));

    sll_iterator(np_message_ptr) iter_prop_msg_cache_out = sll_first(msg_prop->msg_cache_out);
    while (iter_prop_msg_cache_out != NULL)
    {
        sll_iterator(np_message_ptr) old_iter = iter_prop_msg_cache_out;
        // we need to iterate before we delete the old iter        
        sll_next(iter_prop_msg_cache_out); 

        np_message_t* old_msg = old_iter->val;
        if (_np_message_is_expired(old_msg)) {
            log_msg(LOG_WARN,"purging expired message (subj: %s, uuid: %s) from sender cache ...", msg_prop->msg_subject, old_msg->uuid);
            sll_delete(np_message_ptr, msg_prop->msg_cache_out, old_iter);
            np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
        }
    }
    log_debug_msg(LOG_MSGPROPERTY, "cleanup sender cache for subject %s done", msg_prop->msg_subject);
}

void _np_msgproperty_add_msg_to_recv_cache(np_msgproperty_t* msg_prop, np_message_t* msg_in)
{
    np_ctx_memory(msg_prop);
    // cache already full ?
    if (msg_prop->cache_size <= sll_size(msg_prop->msg_cache_in))
    {
        log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "recv msg cache full, checking overflow policy ...");

        if (FLAG_CMP(msg_prop->cache_policy, OVERFLOW_PURGE) )
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
                np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
            }
        }

        if (FLAG_CMP(msg_prop->cache_policy, OVERFLOW_REJECT))
        {
            log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG,
                    "rejecting new message because cache is full");
            return;
        }
    }


    np_ref_obj(np_message_t, msg_in, ref_msgproperty_msgcache);
    sll_prepend(np_message_ptr, msg_prop->msg_cache_in, msg_in);

    log_debug_msg(LOG_MSGPROPERTY, "added message to the recv msgcache (%p / %d) ...",
                    msg_prop->msg_cache_in, sll_size(msg_prop->msg_cache_in));    
}

void _np_msgproperty_threshold_increase(np_msgproperty_t* self) 
{
    if(self->msg_threshold < self->max_threshold){
        self->msg_threshold++;
    }
}

bool _np_msgproperty_threshold_breached(np_msgproperty_t* self) 
{
    if((self->msg_threshold) > self->max_threshold){
        return true;
    }
    return false;
}

void _np_msgproperty_threshold_decrease(np_msgproperty_t* self) 
{
    if(self->msg_threshold > 0) {
        self->msg_threshold--;
    }
}

void __np_msgproperty_redeliver_messages(np_msgproperty_t* self) 
{
    np_ctx_memory(self);

    // remove expired msg uuid from response uuids
    double now = np_time_now();
    double resend_interval = self->msg_ttl / (self->retry+1);

    np_tree_elem_t* iter_tree = NULL;
    np_message_t* current = NULL;

    RB_FOREACH(iter_tree, np_tree_s, self->redelivery_messages)
    {
        bool handle_event = false;
        current = (np_message_t *) iter_tree->val.value.v;
        np_dhkey_t property_dhkey = _np_msgproperty_dhkey(OUTBOUND, self->msg_subject);

        if (current->redelivery_at + resend_interval < now)
        {   // send message redelivery attempt
            current->redelivery_at = now;
            np_ref_obj(np_message_t, current, ref_message_in_send_system);
            np_util_event_t message_event = { .type=(evt_message|evt_internal), .context=context, .user_data=current, .target_dhkey=property_dhkey };
            _np_keycache_handle_event(context, property_dhkey, message_event, false);
            log_msg(LOG_INFO, "re-delivery of message %s / %s", iter_tree->key.value.s, self->msg_subject);
        }
    }
}

struct __np_token_ledger {
	np_pll_t(np_aaatoken_ptr, recv_tokens); // link to runtime interest data on which this node is interested in
	np_pll_t(np_aaatoken_ptr, send_tokens); // link to runtime interest data on which this node is interested in
};

static int8_t _np_aaatoken_cmp (np_aaatoken_ptr first, np_aaatoken_ptr second)
{
    int8_t ret_check = 0;

    if (first == second) return (0);

    if (first == NULL || second == NULL ) return (-1);

    ret_check = strncmp(first->issuer, second->issuer, 65);
    if (0 != ret_check )
    {
        return (ret_check);
    }

    ret_check = strncmp(first->subject, second->subject, (strnlen(first->subject,255)));
    if (0 != ret_check )
    {
        return (ret_check);
    }

    ret_check = strncmp(first->realm, second->realm, strlen(first->realm));
    if (0 != ret_check )
    {
        return (ret_check);
    }

    return (0);
}

/*
static int8_t _np_aaatoken_cmp_exact (np_aaatoken_ptr first, np_aaatoken_ptr second)
{
    int8_t ret_check = 0;

    if (first == second) return (0);

    if (first == NULL || second == NULL ) return (-1);

    ret_check = sodium_memcmp(first->crypto.derived_kx_public_key, second->crypto.derived_kx_public_key, crypto_sign_PUBLICKEYBYTES);
    if (0 != ret_check )
    {
        return (ret_check);
    }

    ret_check = strncmp(first->uuid, second->uuid, NP_UUID_BYTES);
    if (0 != ret_check )
    {
        return (ret_check);
    }

    return _np_aaatoken_cmp(first,second);
}
*/

void _np_msgproperty_create_token_ledger(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_property_check(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);    
    NP_CAST(event.user_data, np_aaatoken_t, token);

    if (sll_size(my_property_key->entities) == 1) 
    {
        // could be empty on first use, therefore create and append it to the entities
        log_debug_msg(LOG_DEBUG, "creating ledger lists for %s / %s", token->subject, _np_key_as_str(my_property_key));
        struct __np_token_ledger* token_ledger = malloc( sizeof (struct __np_token_ledger) );
        pll_init(np_aaatoken_ptr, token_ledger->recv_tokens);
        pll_init(np_aaatoken_ptr, token_ledger->send_tokens);
    
        sll_append(void_ptr, my_property_key->entities, token_ledger);
    }
}

np_aaatoken_t* _np_msgproperty_get_mxtoken(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void _np_msgproperty_get_mxtoken(...){");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);    

    np_msgproperty_t* property       = sll_first(my_property_key->entities)->val;
    struct __np_token_ledger* ledger = sll_last(my_property_key->entities)->val;

    np_dhkey_t send_dhkey = _np_msgproperty_dhkey(OUTBOUND, property->msg_subject);
    np_dhkey_t recv_dhkey = _np_msgproperty_dhkey(INBOUND, property->msg_subject);

    np_pll_t(np_aaatoken_ptr, token_list=NULL);
    if (_np_dhkey_equal(&my_property_key->dhkey, &send_dhkey) ) 
    {
        log_debug_msg(LOG_DEBUG, "start: void _np_msgproperty_get_mxtoken SENDER(...){ %s", _np_key_as_str(my_property_key));
        token_list = ledger->send_tokens;
    }
    
    if (_np_dhkey_equal(&my_property_key->dhkey, &recv_dhkey) ) 
    {
        log_debug_msg(LOG_DEBUG, "start: void _np_msgproperty_get_mxtoken RECEIVER(...){%s", _np_key_as_str(my_property_key));
        token_list = ledger->recv_tokens;
    }

    if (token_list == NULL)
    {
        log_debug_msg(LOG_DEBUG, "start: void _np_msgproperty_get_mxtoken NONE (...){");
        return NULL;
    }

    if (pll_size(token_list)==0)
    {
        return NULL;
    }
    else                         
    {
        np_ref_obj(np_aaatoken_t, pll_first(token_list)->val, ref_obj_usage);
        return pll_first(token_list)->val;
    }
}

void _np_msgproperty_upsert_token(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void _np_msgproperty_upsert_token(...){");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);    

    np_msgproperty_t* property       = sll_first(my_property_key->entities)->val;
    struct __np_token_ledger* ledger = sll_last(my_property_key->entities)->val;

    np_dhkey_t send_dhkey = _np_msgproperty_dhkey(OUTBOUND, property->msg_subject);
    np_dhkey_t recv_dhkey = _np_msgproperty_dhkey(INBOUND, property->msg_subject);

    np_pll_t(np_aaatoken_ptr, token_list=NULL);
    if (_np_dhkey_equal(&my_property_key->dhkey, &send_dhkey) ) 
    {
        log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "start: void _np_msgproperty_upsert_token SENDER(...){%s", _np_key_as_str(my_property_key));
        token_list = ledger->send_tokens;
    }
    else if (_np_dhkey_equal(&my_property_key->dhkey, &recv_dhkey) ) 
    {
        log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "start: void _np_msgproperty_upsert_token RECEIVER(...){%s", _np_key_as_str(my_property_key));
        token_list = ledger->recv_tokens;
    }
    else
    {
        log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "start: void _np_msgproperty_upsert_token NONE (...){");
        return;
    }

    double now = np_time_now();

    pll_iterator(np_aaatoken_ptr) iter = pll_first(token_list);
    // create new mx token
    do {
        if (NULL == iter)
        {
            log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "--- new mxtoken for subject: %25s --------", property->msg_subject);
            np_aaatoken_t* msg_token_new = _np_token_factory_new_message_intent_token(property);
            pll_insert(np_aaatoken_ptr, token_list, msg_token_new, false, _np_aaatoken_cmp);
            ref_replace_reason(np_aaatoken_t, msg_token_new, "_np_token_factory_new_message_intent_token", ref_aaatoken_local_mx_tokens);
        }
        else if ( (iter->val->expires_at - now) <= fmax(property->token_min_ttl + 1.0, MSGPROPERTY_DEFAULT_MIN_TTL_SEC) )
        {   // Create a new msg token
            log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "--- refresh mxtoken for subject: %25s --------", property->msg_subject);
            np_aaatoken_t* msg_token_new = _np_token_factory_new_message_intent_token(property);
            np_aaatoken_t* tmp_token = pll_replace(np_aaatoken_ptr, token_list, msg_token_new, _np_aaatoken_cmp);
            ref_replace_reason(np_aaatoken_t, msg_token_new, "_np_token_factory_new_message_intent_token", ref_aaatoken_local_mx_tokens);
            np_unref_obj(np_aaatoken_ptr, tmp_token, ref_aaatoken_local_mx_tokens);
        }
        else
        {
            log_debug(LOG_MSGPROPERTY, "--- update mxtoken for subject: %25s token: %s--------", property->msg_subject,iter->val->uuid);
            np_data_value max_threshold;
            max_threshold.unsigned_integer = property->max_threshold;
            enum np_data_return r;
            r = np_set_data(iter->val->attributes, (struct np_data_conf){ .key = "max_threshold", .type = NP_DATA_TYPE_UNSIGNED_INT}, max_threshold);
            assert(r == np_ok);
            np_data_value msg_threshold;
            msg_threshold.unsigned_integer = property->msg_threshold;
            //r = np_set_data(iter->val->attributes, (struct np_data_conf){ .key = "msg_threshold", .type = NP_DATA_TYPE_UNSIGNED_INT}, msg_threshold);
            assert(r == np_ok);
        }

        if (iter != NULL) pll_next(iter);

    } while (NULL != iter);
}

void np_msgproperty4user(struct np_mx_properties* dest, np_msgproperty_t* src)
{
    dest->message_ttl = src->msg_ttl;

    dest->intent_ttl = src->token_max_ttl;
    dest->intent_update_after = src->token_min_ttl;

    dest->cache_size = src->cache_size;
    dest->max_parallel = src->max_threshold;
    dest->max_retry = src->retry;

    if(src->rep_subject != NULL) {
        strncpy(dest->reply_subject, src->rep_subject, 255);
    }
    else {
        memset(dest->reply_subject, 0, sizeof(dest->reply_subject));
    }
    
    // ackmode conversion
    switch (src->ack_mode)
    {
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

void np_msgproperty_from_user(np_state_t* context, np_msgproperty_t* dest, struct np_mx_properties* src) 
{
	assert(context != NULL);
    assert(src != NULL);
    assert(dest != NULL);

    if (src->intent_ttl > 0.0) {
        dest->token_max_ttl = src->intent_ttl;
    }

    if (src->intent_update_after > 0.0) {
        dest->token_min_ttl = src->intent_update_after;
        // reset to trigger discovery messages
        dest->last_intent_rx_update = (dest->last_intent_rx_update - dest->token_min_ttl);
        dest->last_intent_tx_update = (dest->last_intent_tx_update - dest->token_min_ttl);
    }

    if (src->message_ttl > 0.0) {
        dest->msg_ttl = src->message_ttl;
    }
    if (src->max_retry > 0) {
        dest->retry = src->max_retry;
    }    

    if (src->cache_size > 0) {
        dest->cache_size = src->cache_size;
    }
    if (src->max_parallel > 0) {
        dest->max_threshold = src->max_parallel;
    }

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

// NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_USE_MSGPROPERTY, __np_set_property, __is_msgproperty);
bool __is_msgproperty(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_msgproperty(...){");
    // np_ctx_memory(statemachine->_user_data);
    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_property) && FLAG_CMP(event.type, evt_internal);
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_msgproperty_t);

    return ret;
}

void __np_set_property(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void _np_set_property(...) {");

    NP_CAST(statemachine->_user_data, np_key_t,         my_property_key);
    NP_CAST(event.user_data,          np_msgproperty_t, property);

    np_ref_obj(no_key_t, my_property_key, "__np_set_property");
    my_property_key->type |= np_key_type_subject;

    sll_append(void_ptr, my_property_key->entities, property);
    log_debug_msg(LOG_DEBUG, "sto  :msgproperty %s: %p added to list: %p / %p", property->msg_subject, property, my_property_key, my_property_key->entities);
    

    if (property->is_internal == false) {
        _np_msgproperty_create_token_ledger(statemachine, event);
        if (false == sll_contains(np_evt_callback_t, property->clb_outbound, _np_out_callback_wrapper, np_evt_callback_t_sll_compare_type)) 
        {   // first encrypt the payload for receiver 
            sll_append(np_evt_callback_t, property->clb_outbound, _np_out_callback_wrapper);
        }

        if (false == sll_contains(np_evt_callback_t, property->clb_outbound, _np_out_default, np_evt_callback_t_sll_compare_type)) 
        {   // then route and send message
            sll_append(np_evt_callback_t, property->clb_outbound, _np_out_default);
        }

        if (my_property_key->bloom_scent == NULL) {
            np_dhkey_t target_dhkey = _np_msgproperty_dhkey(INBOUND, property->msg_subject);
            my_property_key->bloom_scent   = _np_neuropil_bloom_create();
            _np_neuropil_bloom_add(my_property_key->bloom_scent, target_dhkey);
        }
    }
}

void __np_property_update(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_property_update(...) {");

    NP_CAST(statemachine->_user_data, np_key_t,   my_property_key);

    NP_CAST(sll_first(my_property_key->entities)->val, np_msgproperty_t, old_property);
    NP_CAST(event.user_data, np_msgproperty_t, new_property);
    // buggy, but for now ...
    *old_property = *new_property;
}

void __np_msgproperty_send_available_messages(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void __np_msgproperty_send_available_messages(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, property_key);
    NP_CAST(sll_first(property_key->entities)->val, np_msgproperty_t, property);

    // upsert message intent token
    np_aaatoken_t* intent_token = _np_msgproperty_get_mxtoken(statemachine, event);
    if (NULL == intent_token) return;

    np_tree_t* intent_data = np_tree_create();

    np_aaatoken_encode(intent_data, intent_token);
    np_unref_obj(np_aaatoken_t, intent_token, ref_obj_usage);

    np_dhkey_t send_dhkey = _np_msgproperty_dhkey(OUTBOUND, property->msg_subject);
    np_dhkey_t recv_dhkey = _np_msgproperty_dhkey(INBOUND,  property->msg_subject);
    np_dhkey_t target_dhkey = recv_dhkey; // np_dhkey_create_from_hostport(property->msg_subject, "0");

    np_util_event_t available_event = { .type=(evt_internal|evt_message), .context=context, .target_dhkey=target_dhkey};

    double now = np_time_now();

    if (_np_dhkey_equal(&property_key->dhkey, &send_dhkey) &&
       (now - property->last_intent_tx_update) > property->token_min_ttl)
    {   // send our token, search for receiver of messages
        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out, ref_message_in_send_system);
        _np_message_create( msg_out, target_dhkey, context->my_node_key->dhkey, _NP_MSG_AVAILABLE_SENDER, np_tree_clone(intent_data));

        log_msg(LOG_INFO, "sending available message for %s as a sender: _NP_MSG_AVAILABLE_SENDER {msg uuid: %s / intent uuid: %s)", property->msg_subject, msg_out->uuid, intent_token->uuid);

        np_dhkey_t available_dhkey = _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_AVAILABLE_SENDER);
        available_event.user_data = msg_out;
        _np_keycache_handle_event(context, available_dhkey, available_event, false);
        property->last_intent_tx_update = now;
    }

    if (_np_dhkey_equal(&property_key->dhkey, &recv_dhkey) &&
       ( (now - property->last_intent_rx_update) > property->token_min_ttl) &&
       sll_contains(np_evt_callback_t, property->clb_inbound, _np_in_callback_wrapper, np_evt_callback_t_sll_compare_type))
    {   // send our token, search for sender of messages
        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out, ref_message_in_send_system);
        _np_message_create(msg_out, target_dhkey, context->my_node_key->dhkey, _NP_MSG_AVAILABLE_RECEIVER, np_tree_clone(intent_data) );

        log_msg(LOG_INFO, "sending available message for %s as a receiver: _NP_MSG_AVAILABLE_RECEIVER {msg uuid: %s / intent uuid: %s)", property->msg_subject, msg_out->uuid, intent_token->uuid);

        np_dhkey_t available_dhkey = _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_AVAILABLE_RECEIVER);
        available_event.user_data = msg_out;
        _np_keycache_handle_event(context, available_dhkey, available_event, false);
        property->last_intent_rx_update = now;
    }
    np_tree_free(intent_data);
}

void __np_msgproperty_send_pheromone_messages(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void __np_msgproperty_send_pheromone_messages(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, property_key);
    NP_CAST(sll_first(property_key->entities)->val, np_msgproperty_t, property);

    np_dhkey_t send_dhkey = _np_msgproperty_dhkey(OUTBOUND, property->msg_subject);
    np_dhkey_t recv_dhkey = _np_msgproperty_dhkey(INBOUND,  property->msg_subject);
    np_dhkey_t target_dhkey = recv_dhkey; // np_dhkey_create_from_hostport(property->msg_subject, "0");

    bool is_send = _np_dhkey_equal(&property_key->dhkey, &send_dhkey);
    bool is_recv = _np_dhkey_equal(&property_key->dhkey, &recv_dhkey);
    double last_pheromone_update = 0.0;

    np_util_event_t pheromone_event = { .type=(evt_internal|evt_message), .context=context, .target_dhkey=target_dhkey};

    unsigned char* buffer = NULL;
    uint16_t buffer_size = 0;
    _np_neuropil_bloom_serialize(property_key->bloom_scent, &buffer, &buffer_size);

    np_tree_t* bloom_data = np_tree_create();

    float _target_age = 0.2;
    float _return_age = _target_age;

    np_sll_t(np_dhkey_t, result_list) = NULL;
    sll_init(np_dhkey_t, result_list);

    if (is_send)
    {
        np_tree_insert_int(bloom_data, -(target_dhkey.t[0] % 257)-1, np_treeval_new_bin((void*) buffer, buffer_size));
        log_debug_msg(LOG_DEBUG, "adding %25s bloom data at %i", property->msg_subject, -(target_dhkey.t[0] % 257)-1);

        _np_pheromone_snuffle_receiver(context, result_list, target_dhkey, &_return_age);
        last_pheromone_update = property->last_pheromone_tx_update;

        if (FLAG_CMP(property->ack_mode, ACK_DESTINATION) ||
            FLAG_CMP(property->ack_mode, ACK_CLIENT     )  )
        {
            np_dhkey_t ack_dhkey = _np_msgproperty_dhkey(INBOUND,  _NP_MSG_ACK);

            if (FLAG_CMP(property->ack_mode, ACK_DESTINATION))
                _np_dhkey_add(&ack_dhkey, &ack_dhkey, &context->my_node_key->dhkey);
            if (FLAG_CMP(property->ack_mode, ACK_CLIENT))
                _np_dhkey_add(&ack_dhkey, &ack_dhkey, &context->my_identity->dhkey);

            np_bloom_t* ack_scent = _np_neuropil_bloom_create();
            _np_neuropil_bloom_add(ack_scent, ack_dhkey);
            unsigned char* ack_buffer = NULL;
            uint16_t ack_buffer_size = 0;
            _np_neuropil_bloom_serialize(ack_scent, &ack_buffer, &ack_buffer_size);
            
            np_tree_insert_int(bloom_data, (ack_dhkey.t[0] % 257)+1, np_treeval_new_bin((void*) ack_buffer, ack_buffer_size));
            log_debug_msg(LOG_DEBUG, "adding %25s bloom data at %i", _NP_MSG_ACK, (ack_dhkey.t[0] % 257)+1);

            free(ack_buffer);
            _np_bloom_free(ack_scent);
        }
    }

    if (is_recv &&
        sll_contains(np_evt_callback_t, property->clb_inbound, _np_in_callback_wrapper, np_evt_callback_t_sll_compare_type))
    {
        np_tree_insert_int(bloom_data,  (target_dhkey.t[0] % 257)+1, np_treeval_new_bin((void*) buffer, buffer_size));
        log_debug_msg(LOG_DEBUG, "adding %25s bloom data at %i", property->msg_subject, (target_dhkey.t[0] % 257)+1);

        _np_pheromone_snuffle_sender(context, result_list, target_dhkey, &_return_age);
        last_pheromone_update = property->last_pheromone_rx_update;
    }

    sll_free(np_dhkey_t, result_list);

    if (_return_age > _target_age) _target_age = _return_age;

    double now = np_time_now();

    if (last_pheromone_update > 0 &&
        (now - last_pheromone_update) > (_target_age * property->token_min_ttl) )
    {
        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out, ref_message_in_send_system);
        _np_message_create(msg_out, target_dhkey, context->my_node_key->dhkey, _NP_MSG_PHEROMONE_UPDATE, np_tree_clone(bloom_data));

        log_debug_msg(LOG_DEBUG, "sending pheromone trail message for subject %s: _NP_MSG_PHEROMONE_UPDATE {msg uuid: %s} / %f success probability", 
                property->msg_subject, msg_out->uuid, _target_age);

        np_dhkey_t pheromone_dhkey = _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_PHEROMONE_UPDATE);
        pheromone_event.user_data = msg_out;
        _np_keycache_handle_event(context, pheromone_dhkey, pheromone_event, false);

        if (is_recv) property->last_pheromone_rx_update = now;
        if (is_send) property->last_pheromone_tx_update = now;
    }

    np_tree_free(bloom_data);
    free(buffer);
}

void __np_property_check(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_property_check(...) {");

    NP_CAST(statemachine->_user_data, np_key_t,  my_property_key);    
    NP_CAST(sll_first(my_property_key->entities)->val, np_msgproperty_t, property);

    log_trace_msg(LOG_TRACE, "start: void __np_property_check(...) { %s", _np_key_as_str(my_property_key));

    if (property->response_handler)
    {
        _np_msgproperty_cleanup_response_handler(property);
    }

    if ( FLAG_CMP(property->mode_type, OUTBOUND ) ) {
        // _np_msgproperty_check_sender_msgcache(property);
        _np_msgproperty_cleanup_sender_cache(property);
    }

    if ( FLAG_CMP(property->mode_type, INBOUND ) ) {
        _np_msgproperty_cleanup_receiver_cache(property);
    }

    double now = _np_time_now(context);
    if (property->is_internal == false) 
    {
        _np_msgproperty_upsert_token(statemachine, event);

        __np_msgproperty_send_pheromone_messages(statemachine, event);
        __np_msgproperty_send_available_messages(statemachine, event);
    
        __np_intent_check(statemachine, event);
    }

    property->last_update = now;
    _np_msgproperty_job_msg_uniquety(property);
}

// NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY, __np_property_handle_msg,  __is_message);
bool __is_external_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_external_message(...){");

    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);

    // if ( ret) ret &= property->is_internal;
    return ret;
}

void __np_property_handle_in_msg(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_property_handle_in_msg(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
    NP_CAST(sll_first(my_property_key->entities)->val, np_msgproperty_t, property);

    NP_CAST(event.user_data, np_message_t, msg_in);

    bool ret = _np_msgproperty_check_msg_uniquety_in(property, msg_in);

    _np_msgproperty_threshold_increase(property);
    sll_iterator(np_evt_callback_t) iter = sll_first(property->clb_inbound);
    while (iter != NULL && ret)
    {
        if (iter->val != NULL) 
        {
            ret &= iter->val(context, event);
        }
        sll_next(iter);
    }

    if (property->is_internal == false &&
        ret == true) 
    {
        // call user callbacks
        sll_iterator(np_usercallback_ptr) iter_usercallbacks = sll_first(property->user_receive_clb);
        while (iter_usercallbacks != NULL && ret)
        {
            ret &= iter_usercallbacks->val->fn(context, msg_in, msg_in->body, iter_usercallbacks->val->data);
            sll_next(iter_usercallbacks);
        }
        log_debug(LOG_DEBUG, "(msg: %s) invoked user callback", msg_in->uuid);
    }

    _np_msgproperty_threshold_decrease(property);

    if (ret) _np_increment_received_msgs_counter(property->msg_subject);

    log_debug(LOG_DEBUG, "in: (subject: %s / msg: %s) handling complete", property->msg_subject, msg_in->uuid);    
    np_unref_obj(np_message_t, msg_in, ref_message_in_send_system);
}

bool __is_internal_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_internal_message(...) {");

    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_internal);
    if ( ret) ret &= !FLAG_CMP(event.type, evt_redeliver);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);
    // if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_message_t);

    return ret;
} 

void __np_property_handle_out_msg(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_property_handle_out_msg(...) { %p", statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);    
    NP_CAST(sll_first(my_property_key->entities)->val, np_msgproperty_t, property);

    NP_CAST(event.user_data, np_message_t, msg_out);

    // need duplicate check when forwarding messages
    bool ret = _np_msgproperty_check_msg_uniquety_out(property, msg_out);

    _np_msgproperty_threshold_increase(property);
    if (property->is_internal == false)
    {
        sll_iterator(np_usercallback_ptr) iter_usercallbacks = sll_first(property->user_send_clb);
        while (iter_usercallbacks != NULL && ret)
        {
            ret &= iter_usercallbacks->val->fn(context, msg_out, (msg_out == NULL ? NULL : msg_out->body), iter_usercallbacks->val->data);
            sll_next(iter_usercallbacks);
        }
    }

    sll_iterator(np_evt_callback_t) iter = sll_first(property->clb_outbound);
    while (iter != NULL && ret)
    {
        if (iter->val != NULL) {
            ret &= iter->val(context, event);
        }
        sll_next(iter);
    }

    if (FLAG_CMP(property->ack_mode, ACK_NONE))
        _np_msgproperty_threshold_decrease(property);

    if (ret) {
        _np_increment_send_msgs_counter(property->msg_subject);
    }
    np_unref_obj(np_message_t, msg_out, ref_message_in_send_system);
}

void __np_property_redelivery_set(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_property_redelivery_set(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
    NP_CAST(sll_first(my_property_key->entities)->val, np_msgproperty_t, property);
    NP_CAST(event.user_data, np_message_t, message);

    if (np_tree_find_str(property->redelivery_messages, message->uuid) == NULL) 
    {
        log_msg(LOG_INFO, "storing message %s / %s for possible re-delivery", message->uuid, property->msg_subject);
        _np_msgproperty_threshold_increase(property);
        np_tree_insert_str(property->redelivery_messages, message->uuid, np_treeval_new_v(message) );
        np_ref_obj(np_message_t, message, FUNC);
    }
}

void __np_response_handler_set(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_response_handler_set(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
    NP_CAST(sll_first(my_property_key->entities)->val, np_msgproperty_t, property);
    NP_CAST(event.user_data, np_responsecontainer_t, responsehandler);

    if (property->is_internal)
    {   // registration of response handler for message type NP_ACK
        np_tree_insert_str(property->response_handler, responsehandler->uuid, np_treeval_new_v(responsehandler) );
    }
    else
    {   // a responsehandler reporting a timeout or an acknowledgement
        CHECK_STR_FIELD_BOOL(property->redelivery_messages, responsehandler->uuid, msg_tree_elem, "NO UUID FOUND") 
        {
            log_msg(LOG_INFO, "message %s / %s acknowledged or timed out", responsehandler->uuid, property->msg_subject);

            np_unref_obj(np_message_t, msg_tree_elem->val.value.v, "__np_property_redelivery_set");
            np_tree_del_str(property->redelivery_messages, responsehandler->uuid);
            _np_msgproperty_threshold_decrease(property);        
        }
        np_unref_obj(np_responsecontainer_t, responsehandler, ref_obj_usage);
    }    
}

bool __is_message_redelivery_event(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_message_redelivery_event(...) {");

    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_message);
    if ( ret) ret &= (FLAG_CMP(event.type, evt_redeliver) && FLAG_CMP(event.type, evt_internal) );
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);

    return ret;
}

bool __is_response_event(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_response_event(...) {");

    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_response);
    if ( ret) ret &= (FLAG_CMP(event.type, evt_timeout) || FLAG_CMP(event.type, evt_internal) );
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_responsecontainer_t);

    return ret;
}

void __np_property_handle_intent(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_property_handle_intent(...){");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
    NP_CAST(event.user_data, np_aaatoken_t, intent_token);

    NP_CAST(sll_first(my_property_key->entities)->val, np_msgproperty_t, real_prop);

    // always?: just store the available tokens in memory and update them if new data arrives
    np_dhkey_t sendtoken_issuer_key = np_aaatoken_get_partner_fp(intent_token); 
    if (_np_dhkey_equal(&sendtoken_issuer_key, &context->my_node_key->dhkey) )
    {
        // only add the token if it is not from ourself (in case of IN/OUTBOUND on same subject)
        // TODO: CHECK IF NESSECARY
    }
    bool needs_authz = false;
    // add token, authorization could be in the future
    np_dhkey_t target_inbound_dhkey = _np_msgproperty_dhkey(INBOUND, intent_token->subject);
    np_dhkey_t target_outbound_dhkey = _np_msgproperty_dhkey(OUTBOUND, intent_token->subject);

    // choose correct target ledger
    if (_np_dhkey_equal(&target_inbound_dhkey, &my_property_key->dhkey) &&
        sll_contains(np_evt_callback_t, real_prop->clb_inbound, _np_in_callback_wrapper, np_evt_callback_t_sll_compare_type))
    {
        log_msg(LOG_INFO, "adding sending intent %s for subject %s", intent_token->uuid, real_prop->msg_subject);
        np_aaatoken_t* old_token = _np_intent_add_sender(my_property_key, intent_token);
        np_unref_obj(np_aaatoken_t, old_token, "send_tokens");

        // check if some messages are left in the cache
        _np_msgproperty_check_receiver_msgcache(real_prop, _np_aaatoken_get_issuer(intent_token));
        needs_authz = true;
    }

    // choose correct target ledger
    if (_np_dhkey_equal(&target_outbound_dhkey, &my_property_key->dhkey)) 
    {
        log_msg(LOG_INFO, "adding receiver intent %s for subject %s", intent_token->uuid, real_prop->msg_subject);
        np_aaatoken_t* old_token = _np_intent_add_receiver(my_property_key, intent_token);
        np_unref_obj(np_aaatoken_t, old_token, "recv_tokens");

        // check if some messages are left in the cache
        _np_msgproperty_check_sender_msgcache(real_prop);
        needs_authz = true;
    }

    if (IS_NOT_AUTHORIZED(intent_token->state) && needs_authz == true) 
    {
        log_msg(LOG_INFO, "authorizing intent %s for subject %s", intent_token->uuid, real_prop->msg_subject);
        np_dhkey_t authz_target = context->my_identity->dhkey;
        // if (real_prop->realm) authz_target = real_prop->realm->dhkey;
        np_util_event_t authz_event = { .type=(evt_token|evt_external|evt_authz), .context=context, .user_data=intent_token, .target_dhkey=authz_target };
        _np_keycache_handle_event(context, authz_target, authz_event, false);
    }

    np_unref_obj(np_aaatoken_t, intent_token, "np_token_factory_read_from_tree");
}
