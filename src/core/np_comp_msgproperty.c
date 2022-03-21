//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
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
#include "np_attributes.h"
#include "util/np_bloom.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_message.h"
#include "np_pheromones.h"
#include "np_statistics.h"
#include "np_token_factory.h"
#include "np_responsecontainer.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "util/np_event.h"
#include "np_eventqueue.h"
#include "util/np_statemachine.h"

#include "neuropil_data.h"

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_msgproperty_conf_ptr);
NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_msgproperty_run_ptr);

NP_SLL_GENERATE_IMPLEMENTATION(np_msgproperty_conf_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_msgproperty_run_ptr);


#include "../np_msgproperty_init.c.part"

static np_dhkey_t __local_tx_dhkey = {0}; 
static np_dhkey_t __local_rx_dhkey = {0};

struct np_redelivery_data_s {
    np_dhkey_t target;
    double redelivery_at;
    np_message_t* message;
};
typedef struct np_redelivery_data_s np_redelivery_data_t;


np_dhkey_t _np_msgproperty_tweaked_dhkey(np_msg_mode_type mode_type, np_dhkey_t subject) 
{
    np_dhkey_t result = {0};
    if (mode_type == INBOUND)
        _np_dhkey_add(&result, &__local_rx_dhkey, &subject);
    if (mode_type == OUTBOUND)
        _np_dhkey_add(&result, &__local_tx_dhkey, &subject);

    return result;
}

np_dhkey_t _np_msgproperty_dhkey(np_msg_mode_type mode_type, const char* subject) 
{
    np_dhkey_t _dhkey = _np_dhkey_generate_hash(subject, strnlen(subject, 256));
    if (mode_type == INBOUND)
        _np_dhkey_add(&_dhkey, &__local_rx_dhkey, &_dhkey);
    if (mode_type == OUTBOUND)
        _np_dhkey_add(&_dhkey, &__local_tx_dhkey, &_dhkey);
    
    return _dhkey;
}

void __np_msgproperty_threshold_increase(const np_msgproperty_conf_t* const self_conf, np_msgproperty_run_t* self) 
{
    if(self->msg_threshold < self_conf->max_threshold){
        self->msg_threshold++;
    }
}

bool __np_msgproperty_threshold_breached(const np_msgproperty_conf_t* const self_conf, np_msgproperty_run_t* self) 
{
    if((self->msg_threshold) > self_conf->max_threshold){
        return true;
    }
    return false;
}

void __np_msgproperty_threshold_decrease(NP_UNUSED const np_msgproperty_conf_t* const self_conf, np_msgproperty_run_t* self) 
{
    if(self->msg_threshold > 0) {
        self->msg_threshold--;
    }
}

void _np_msgproperty_conf_t_new(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* property)
{
    log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_conf_t_new(void* property){");
    struct np_msgproperty_conf_s* prop = (struct np_msgproperty_conf_s*) property;

    prop->token_min_ttl = MSGPROPERTY_DEFAULT_MIN_TTL_SEC;
    prop->token_max_ttl = MSGPROPERTY_DEFAULT_MAX_TTL_SEC;

    // prop->msg_audience	= NULL;
    prop->msg_subject	= NULL;
    prop->rep_subject	= NULL;

    prop->mode_type = OUTBOUND | INBOUND;
    prop->mep_type  = DEFAULT_TYPE;
    prop->ack_mode  = ACK_NONE;
    prop->priority  = PRIORITY_MOD_USER_DEFAULT;
    prop->retry     = 4;
    prop->msg_ttl   = 15.0;

    // cache which will hold up to max_threshold messages
    prop->cache_policy = FIFO | OVERFLOW_PURGE;
    prop->cache_size    = 8;
    prop->max_threshold = 2;

    prop->is_internal = false;
    prop->audience_type = NP_MX_AUD_PUBLIC;

    prop->unique_uuids_check = false;

    memset(&prop->audience_id,        0, NP_FINGERPRINT_BYTES);
    memset(&prop->subject_dhkey,      0, NP_FINGERPRINT_BYTES);
    memset(&prop->subject_dhkey_in,   0, NP_FINGERPRINT_BYTES);
    memset(&prop->subject_dhkey_out,  0, NP_FINGERPRINT_BYTES);
    // memset(&prop->subject_dhkey_wire, 0, NP_FINGERPRINT_BYTES);
}

void _np_msgproperty_run_t_new(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* property)
{
    log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_run_t_new(void* property){");

    struct np_msgproperty_run_s* prop = (struct np_msgproperty_run_s*) property;

    sll_init(np_evt_callback_t, prop->callbacks);
    sll_init(np_usercallback_ptr, prop->user_callbacks);

    prop->msg_threshold = 0;

    prop->response_handler    = np_tree_create(); // only used for msghandler NP_ACK
    prop->redelivery_messages = np_tree_create(); // only used for msghandler "is_internal=false"

    sll_init(np_message_ptr, prop->msg_cache);

    prop->unique_uuids  = np_tree_create();

    np_init_datablock(prop->attributes,sizeof(prop->attributes));

    double now = np_time_now();
    prop->last_update = now;
    prop->last_intent_update = 0;
    prop->last_pheromone_update = 0;

    prop->authorize_func = NULL;
}

void _np_msgproperty_conf_t_del(NP_UNUSED np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* property)
{
    // log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_conf_t_del(void* property){");
    struct np_msgproperty_conf_s* prop = (struct np_msgproperty_conf_s*) property;

    log_debug_msg(LOG_MSGPROPERTY, "Deleting msgproperty %s", prop->msg_subject);
    assert(prop != NULL);

    if (prop->msg_subject != NULL) {
        free(prop->msg_subject); prop->msg_subject = NULL;
    }
    if (prop->rep_subject != NULL) {
        free(prop->rep_subject); prop->rep_subject = NULL;
    }
}

void _np_msgproperty_run_t_del(NP_UNUSED np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* property)
{
    // log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_run_t_del(void* property){");
    struct np_msgproperty_run_s* prop = (struct np_msgproperty_run_s*) property;

    // log_debug_msg(LOG_MSGPROPERTY, "Deleting msgproperty %s", prop->msg_subject);

    assert(prop != NULL);

    np_tree_free(prop->unique_uuids);
    np_tree_free(prop->response_handler); //
    np_tree_free(prop->redelivery_messages); //

    if(prop->msg_cache != NULL ) {
        sll_free(np_message_ptr, prop->msg_cache);
    }

    if(prop->user_callbacks != NULL) {
        sll_free(np_usercallback_ptr, prop->user_callbacks);
    }
    sll_free(np_evt_callback_t, prop->callbacks);
}

/**
 ** _np_msgproperty_init
 ** Initialize message property subsystem.
 **/
bool _np_msgproperty_init (np_state_t* context)
{
    __local_tx_dhkey = _np_dhkey_generate_hash("local_tx", 8);
    __local_rx_dhkey = _np_dhkey_generate_hash("local_rx", 8);

    // NEUROPIL_INTERN_MESSAGES
    np_sll_t(np_msgproperty_conf_ptr, msgproperties);
    msgproperties = default_msgproperties(context);
    sll_iterator(np_msgproperty_conf_ptr) __np_internal_messages = sll_first(msgproperties);

    while (__np_internal_messages != NULL)
    {
        np_msgproperty_conf_t* property = __np_internal_messages->val;
        property->is_internal = true;
        property->audience_type = NP_MX_AUD_PUBLIC;

        if (strlen(property->msg_subject) > 0)
        {
            // np_dhkey_t subject_dhkey = {0};
            np_generate_subject( (np_subject *) &property->subject_dhkey, property->msg_subject, strnlen(property->msg_subject, 256));
#ifdef DEBUG
            char hex[65];            
            log_debug_msg(LOG_MSGPROPERTY, "register handler: %s (%u) hex: %s", property->msg_subject, strnlen(property->msg_subject, 256), sodium_bin2hex(hex, 65, &property->subject_dhkey, 32));
#endif
            np_msgproperty_register(property);
        }            
        sll_next(__np_internal_messages);
    }
    sll_free(np_msgproperty_conf_ptr, msgproperties);
    return true;
}

void _np_msgproperty_destroy (np_state_t* context)
{   
    // NEUROPIL_INTERN_MESSAGES
    np_sll_t(np_msgproperty_conf_ptr, msgproperties);
    msgproperties = default_msgproperties(context);
    sll_iterator(np_msgproperty_conf_ptr) __np_internal_messages = sll_first(msgproperties);
    while (__np_internal_messages != NULL) 
    {
        np_msgproperty_conf_t* property = __np_internal_messages->val;
        np_dhkey_t subject_in_dhkey = _np_msgproperty_dhkey(INBOUND, property->msg_subject);
        _np_keycache_remove(context, subject_in_dhkey);
        np_dhkey_t subject_out_dhkey = _np_msgproperty_dhkey(OUTBOUND, property->msg_subject);
        _np_keycache_remove(context, subject_out_dhkey);

        sll_next(__np_internal_messages);
    }
    
}

/**
 ** returns the msgproperty struct #func# for the given #mode_type# and #subject#,
 **/
np_msgproperty_conf_t* _np_msgproperty_conf_get(np_state_t* context, np_msg_mode_type mode_type, np_dhkey_t subject)
{
    log_trace_msg(LOG_TRACE, "start: np_msgproperty_conf_t* np_msgproperty_get(context, np_msg_mode_type mode_type, const char* subject){");
    // assert(subject != NULL);

    np_msgproperty_conf_t* ret = NULL;
     // _np_msgproperty_dhkey(DEFAULT_MODE, subject);

    if (FLAG_CMP(mode_type, INBOUND) )
    {   // search receiving property
        np_dhkey_t search_in_dhkey = _np_msgproperty_tweaked_dhkey(INBOUND, subject);
        // np_dhkey_t search_key_rx = np_dhkey_create_from_hostport(subject, "local_rx");
        np_key_t* my_property_key_rx = _np_keycache_find(context, search_in_dhkey);
        if (my_property_key_rx == NULL) return NULL;
    
        assert((np_memory_get_type(my_property_key_rx->entity_array[0]) == np_memory_types_np_msgproperty_conf_t));
        ret = my_property_key_rx->entity_array[0];
        log_debug_msg(LOG_MSGPROPERTY, "get %u: msgproperty %s: get %p from list: %p", mode_type, ret->msg_subject, my_property_key_rx->entity_array[0], my_property_key_rx);

        np_unref_obj(np_key_t, my_property_key_rx, "_np_keycache_find");
        return ret; 
    }

    if (FLAG_CMP(mode_type, OUTBOUND) )
    {
        // search sending property
        np_dhkey_t search_out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, subject);
        np_key_t* my_property_key_tx = _np_keycache_find(context, search_out_dhkey);

        if (my_property_key_tx == NULL) return NULL;
        assert((np_memory_get_type(my_property_key_tx->entity_array[0]) == np_memory_types_np_msgproperty_conf_t));

        ret = my_property_key_tx->entity_array[0];
        log_debug_msg(LOG_MSGPROPERTY, "get %u: msgproperty %s: get %p from list: %p", mode_type, ret->msg_subject, my_property_key_tx->entity_array[0], my_property_key_tx);

        np_unref_obj(np_key_t, my_property_key_tx, "_np_keycache_find");
        return ret; 
    }
    
    log_warn(LOG_MSGPROPERTY, "msgproperty %s: unknown send/receive mode", subject);
    return NULL; 
}

np_msgproperty_run_t* _np_msgproperty_run_get(np_state_t* context, np_msg_mode_type mode_type, np_dhkey_t subject)
{
    log_trace_msg(LOG_TRACE, "start: np_msgproperty_conf_t* np_msgproperty_get(context, np_msg_mode_type mode_type, const char* subject){");
    assert(! FLAG_CMP(mode_type, DEFAULT_MODE));
    assert(  FLAG_CMP(mode_type, INBOUND) || FLAG_CMP(mode_type, OUTBOUND) );

    np_msgproperty_run_t* ret = NULL;
    // search property
    np_dhkey_t search_in_dhkey = _np_msgproperty_tweaked_dhkey(mode_type, subject);

    np_key_t* my_property_key_rx = _np_keycache_find(context, search_in_dhkey);
    if (my_property_key_rx != NULL && my_property_key_rx->entity_array[1] != NULL) 
    {
        assert((np_memory_get_type(my_property_key_rx->entity_array[1]) == np_memory_types_np_msgproperty_run_t));
        ret = my_property_key_rx->entity_array[1];
        log_debug_msg(LOG_MSGPROPERTY, "get %d: msgproperty %s: get %p from list: %p", mode_type, ((np_msgproperty_conf_t*) my_property_key_rx->entity_array[0])->msg_subject, my_property_key_rx->entity_array[1], my_property_key_rx);
        np_unref_obj(np_key_t, my_property_key_rx, "_np_keycache_find");
    }
    return ret; 
}

/**
 ** returns the msgproperty struct #func# for the given #mode_type# and #subject#, and creates it if it is not yet present
 **/
np_msgproperty_conf_t* _np_msgproperty_get_or_create(np_state_t* context, np_msg_mode_type mode_type, np_dhkey_t subject)
{
    np_msgproperty_conf_t* prop = _np_msgproperty_conf_get(context, mode_type, subject);
    bool created= false;

    if (NULL == prop)
    {
        log_msg(LOG_INFO | LOG_MSGPROPERTY, "Indirect %" PRIu8 " creation of msgproperty %08" PRIx32 ":%08" PRIx32, mode_type, subject.t[0], subject.t[1]);
        // create a default set of properties for listening to messages
        np_new_obj(np_msgproperty_conf_t, prop);
        if (NULL == prop->msg_subject) {
            prop->msg_subject = calloc(65, sizeof(char));
            np_id_str(prop->msg_subject, &subject);
            // prop->msg_subject = calloc(33, sizeof(char));
            // snprintf(prop->msg_subject, 24, "%08"PRIx32 ":%08"PRIx32, subject.t[0], subject.t[1]); 
        }
        prop->subject_dhkey = subject;
        prop->mode_type = mode_type;
        prop->mep_type = ANY_TO_ANY;
    } 

    if(created) {
        np_unref_obj(np_msgproperty_conf_t, prop, ref_obj_creation);
    }
    return prop;
}

void np_msgproperty_register(np_msgproperty_conf_t* msg_property)
{
    np_ctx_memory(msg_property);
    log_trace_msg(LOG_TRACE, "start: void np_msgproperty_register(np_msgproperty_conf_t* msgprops){ ");
    log_debug_msg(LOG_MSGPROPERTY, "registering user property: %s ", msg_property->msg_subject);

    msg_property->subject_dhkey_in  = _np_msgproperty_tweaked_dhkey(INBOUND, msg_property->subject_dhkey);
    msg_property->subject_dhkey_out = _np_msgproperty_tweaked_dhkey(OUTBOUND, msg_property->subject_dhkey);

    log_debug_msg(LOG_MSGPROPERTY, "register handler: %s", msg_property->msg_subject);

    if (FLAG_CMP(msg_property->mode_type, INBOUND) || 
        FLAG_CMP(msg_property->mode_type, OUTBOUND) 
    ) {
        np_ref_obj(np_msgproperty_conf_t, msg_property, FUNC); 
    }

    if (FLAG_CMP(msg_property->mode_type, INBOUND) ) 
    {
        // receiving property
        // np_dhkey_t search_key_rx = np_dhkey_create_from_hostport(msg_property->msg_subject, "local_rx");
        np_key_t* my_property_key_rx = _np_keycache_find_or_create(context, msg_property->subject_dhkey_in);
        np_util_event_t ev_rx = { .type=(evt_property|evt_internal), .user_data=msg_property, .target_dhkey=msg_property->subject_dhkey_in };
        _np_event_runtime_start_with_event(context, msg_property->subject_dhkey_in, ev_rx);
        log_debug_msg(LOG_MSGPROPERTY, "register handler in : %s", _np_key_as_str(my_property_key_rx));
        np_unref_obj(np_key_t, my_property_key_rx, "_np_keycache_find_or_create");
    }

    if (FLAG_CMP(msg_property->mode_type, OUTBOUND) ) {
        // sending property
        np_key_t* my_property_key_tx = _np_keycache_find_or_create(context, msg_property->subject_dhkey_out);
        np_util_event_t ev_tx = { .type=(evt_property|evt_internal), .user_data=msg_property, .target_dhkey=msg_property->subject_dhkey_out };
        _np_event_runtime_start_with_event(context, msg_property->subject_dhkey_out, ev_tx);        
        log_debug_msg(LOG_MSGPROPERTY, "register handler out: %s", _np_key_as_str(my_property_key_tx));
        np_unref_obj(np_key_t, my_property_key_tx, "_np_keycache_find_or_create");
    }
}

bool _np_msgproperty_check_msg_uniquety(np_msgproperty_conf_t* self_conf, np_msgproperty_run_t* self_run, np_message_t* msg_to_check)
{
    bool ret = true;
    if (self_conf->unique_uuids_check) 
    {
        char _to_check[50] = {0};
        sprintf(_to_check, "%s:%05"PRIu32":%05"PRIu32, msg_to_check->uuid, msg_to_check->no_of_chunks, msg_to_check->no_of_chunk);

        if (np_tree_find_str(self_run->unique_uuids, _to_check) == NULL) 
        {
            np_tree_insert_str( self_run->unique_uuids, _to_check, np_treeval_new_d(_np_message_get_expiery(msg_to_check)));
        }
        else 
        {
            ret = false;
        }
    }
    return ret;
}
/*
bool _np_msgproperty_check_msg_uniquety_out(np_msgproperty_conf_t* self, np_message_t* msg_to_check)
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
*/
void _np_msgproperty_remove_msg_from_uniquety_list(np_msgproperty_run_t* self, np_message_t* msg_to_remove)
{	
    // if (self->unique_uuids_check) {
        np_tree_del_str(self->unique_uuids, msg_to_remove->uuid);
    // }
}

void _np_msgproperty_job_msg_uniquety(np_msgproperty_conf_t* self_conf, np_msgproperty_run_t* self_run) 
{
    np_ctx_memory(self_conf);
    // TODO: iter over msgproeprties and remove expired msg uuid from unique_uuids
    double now;
    if (self_conf->unique_uuids_check) 
    {
        sll_init_full(char_ptr, to_remove);

        np_tree_elem_t* iter_tree = NULL;
        now = np_time_now();
        RB_FOREACH(iter_tree, np_tree_s, self_run->unique_uuids)
        {
            if (iter_tree->val.value.d < now) {
                sll_append(char_ptr, to_remove, iter_tree->key.value.s);
            }
        }

        sll_iterator(char_ptr) iter_to_rm = sll_first(to_remove);
        if(iter_to_rm != NULL) {
            log_debug_msg(LOG_DEBUG | LOG_MSGPROPERTY ,"UNIQUITY removing %"PRIu32" from %"PRIu16" items from unique_uuids for %s", 
                                                        sll_size(to_remove), self_run->unique_uuids->size, self_conf->msg_subject);
            while (iter_to_rm != NULL)
            {
                np_tree_del_str(self_run->unique_uuids, iter_to_rm->val);
                sll_next(iter_to_rm);
            }
        }
        // sll_clear(char_ptr, to_remove);

        // iter_tree = NULL;
        // RB_FOREACH(iter_tree, np_tree_s, self->unique_uuids_out)
        // {
        //     if (iter_tree->val.value.d < now) {
        //         sll_append(char_ptr, to_remove, iter_tree->key.value.s);
        //     }
        // }

        // iter_to_rm = sll_first(to_remove);
        // if(iter_to_rm != NULL) {
        //     log_debug_msg(LOG_DEBUG | LOG_MSGPROPERTY ,"UNIQUITY removing %"PRIu32" from %"PRIu16" items from unique_uuids for %s", 
        //                                                 sll_size(to_remove), self->unique_uuids_out->size, self->msg_subject);
        //     while (iter_to_rm != NULL)
        //     {
        //         np_tree_del_str(self->unique_uuids_out, iter_to_rm->val);
        //         sll_next(iter_to_rm);
        //     }
        // }
        sll_free(char_ptr, to_remove);
    }
}

void __np_msgproperty_event_cleanup_response_handler(void * context, np_util_event_t ev){
    np_unref_obj(np_responsecontainer_t, ev.user_data, "_np_msgproperty_cleanup_response_handler");
}
void _np_msgproperty_cleanup_response_handler(np_msgproperty_run_t* self, const np_util_event_t event) 
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
        np_util_event_t response_event = { .user_data=current};

        if (current->expires_at < now) 
        {   // notify about timeout
            response_event.type = (evt_timeout|evt_response);
            handle_event = true;
        } else if (current->received_at != 0) 
        {   // notify about ack response
            response_event.type = (evt_internal|evt_response);            
            handle_event = true;
        }
        
        if (handle_event) 
        {
            
            if (!_np_dhkey_equal(&current->msg_dhkey, &dhkey_zero) ) 
            {  // clean up message redlivery

                np_ref_obj(np_responsecontainer_t, response_event.user_data, FUNC);
                response_event.cleanup = __np_msgproperty_event_cleanup_response_handler;

                response_event.target_dhkey=current->msg_dhkey;
                _np_event_runtime_add_event(context, event.current_run, current->msg_dhkey, response_event); 
                /* POSSIBLE ASYNC POINT
                char buf[100];
                snprintf(buf, 100, "urn:np:responsecontainer:message:%s", current->uuid);
                if(!np_jobqueue_submit_event(context, 0, current->dest_dhkey, response_event, buf)){
                    log_error("Jobqueue rejected new job for responsecontainer message id %s", 
                        current->uuid
                    );
                }
                */
            }

            if (!_np_dhkey_equal(&current->dest_dhkey, &dhkey_zero) &&
                _np_keycache_exists(context, current->dest_dhkey, NULL)) 
            {   // clean up ping ack

                np_ref_obj(np_responsecontainer_t, response_event.user_data, FUNC);
                response_event.cleanup = __np_msgproperty_event_cleanup_response_handler;

                response_event.target_dhkey=current->dest_dhkey;
                _np_event_runtime_add_event(context, event.current_run, current->dest_dhkey, response_event);
                /* POSSIBLE ASYNC POINT
                char buf[100];
                snprintf(buf, 100, "urn:np:responsecontainer:ping_ack:%s", current->uuid);
                if(!np_jobqueue_submit_event(context, 0, current->dest_dhkey, response_event, buf)){
                    log_error("Jobqueue rejected new job for responsecontainer ping_ack id %s", 
                        current->uuid
                    );
                }
                */
            }
            
            np_unref_obj(np_responsecontainer_t, current, "_np_message_add_response_handler");
            sll_append(char_ptr, to_remove, iter_tree->key.value.s);
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

void _np_msgproperty_check_msgcache(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);    
    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);
    // NP_CAST(event.user_data, np_message_t, message);

    // check if we are (one of the) sending node(s) of this kind of message
    // should not return NULL
    log_debug_msg(LOG_ROUTING,
            "this node is one sender of messages, checking msgcache (%p / %u) ...",
            property_run->msg_cache, sll_size(property_run->msg_cache));

    // get message from cache (maybe only for one way mep ?!)
    uint16_t msg_available = 0;
    msg_available = sll_size(property_run->msg_cache);

    while (0 < msg_available && msg_available <= property_conf->cache_size)
    {
        np_message_t* msg_out = NULL;
        // if messages are available in cache, send them !
        if (FLAG_CMP(property_conf->cache_policy, FIFO) )
            msg_out = sll_head(np_message_ptr, property_run->msg_cache);
        else if (FLAG_CMP(property_conf->cache_policy, LIFO) )
            msg_out = sll_tail(np_message_ptr, property_run->msg_cache);
        else
            break;
        
        // check for more messages in cache after head/tail command
        // msg_available = sll_size(send_prop->msg_cache_out);
        msg_available--;

        if(NULL != msg_out)
        {
            np_dhkey_t target_dhkey = {0};
            log_debug(LOG_MSGPROPERTY, "message in sender cache found and initialize resend for msg %s",msg_out->uuid);

            np_util_event_t send_event = { .type=(evt_internal | evt_userspace | evt_message), .user_data=msg_out, .target_dhkey=target_dhkey };
            _np_event_runtime_add_event(context, event.current_run, property_conf->subject_dhkey_out, send_event);

            np_unref_obj(np_message_t, msg_out, ref_msgproperty_msgcache);
        }
        else 
        {
    		break;
        }
    }
}

void _np_msgproperty_check_msgcache_for(np_util_statemachine_t* statemachine, np_event_runtime_t * current_run, const np_util_event_t event)
// void _np_msgproperty_check_msgcache_for(np_msgproperty_run_t* recv_prop, np_dhkey_t from)
{
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);    
    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);
    // NP_CAST(event.user_data, np_message_t, message);

    log_debug_msg(LOG_MSGPROPERTY|LOG_ROUTING,
            "this node is the receiver of messages, checking msgcache (%p / %u) ...",
            property_run->msg_cache, sll_size(property_run->msg_cache));
    // get message from cache (maybe only for one way mep ?!)
    uint16_t msg_available = 0;

    msg_available = sll_size(property_run->msg_cache);

    while (0 < msg_available && msg_available <= property_conf->cache_size)
    {
        // grab a message
        np_message_t* msg = NULL;
        sll_iterator(np_message_ptr) peek;
        // if messages are available in cache, try to decode them !
        if (FLAG_CMP(property_conf->cache_policy, FIFO)){
            peek = sll_first(property_run->msg_cache);
            if(peek != NULL && peek->val != NULL && _np_dhkey_cmp(_np_message_get_sender(peek->val), &event.target_dhkey) == 0){
                msg = sll_head(np_message_ptr, property_run->msg_cache);
            }
        }
        else 
        if (FLAG_CMP(property_conf->cache_policy , LIFO))
        {
            peek = sll_last(property_run->msg_cache);
            if(peek != NULL && peek->val != NULL && _np_dhkey_cmp(_np_message_get_sender(peek->val), &event.target_dhkey) == 0){
                msg = sll_tail(np_message_ptr, property_run->msg_cache);
            }
        }
        // recalc number of available messages
        // msg_available = sll_size(recv_prop->msg_cache_in);
        msg_available--;

        // handle selected message
        if(NULL != msg) 
        {
            log_debug(LOG_MSGPROPERTY, "message in receiver cache found and initialize redelivery for msg %s", msg->uuid);
            np_dhkey_t in_handler = property_conf->subject_dhkey_in; // (INBOUND, property_conf->msg_subject);
            np_util_event_t msg_in_event = { .type=(evt_external|evt_message), .target_dhkey=in_handler, .user_data=msg };
            _np_event_runtime_add_event(context, current_run, in_handler, msg_in_event);

            np_unref_obj(np_message_t, msg, ref_msgproperty_msgcache);

        } else {
            break;
        }

        // do not continue processing message if max treshold is reached
        if (property_run->msg_threshold > property_conf->max_threshold) break;
    }
}

void _np_msgproperty_cleanup_cache(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);    
    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);

    log_debug(LOG_MSGPROPERTY,
            "checking for outdated messages in msgcache (%s: %p / %u) ...",
            property_conf->msg_subject, property_run->msg_cache, sll_size(property_run->msg_cache));

    sll_iterator(np_message_ptr) iter_prop_msg_cache = sll_first(property_run->msg_cache);
    while (iter_prop_msg_cache != NULL)
    {
        sll_iterator(np_message_ptr) old_iter = iter_prop_msg_cache;
        sll_next(iter_prop_msg_cache); // we need to iterate before we delete the old iter

        np_message_t* old_msg = old_iter->val;
        ASSERT(old_msg != NULL, "cannot have an empty element");
        if (_np_message_is_expired(old_msg)) {
            // log_msg(LOG_WARNING,"purging expired message (subj: %s, uuid: %s) from receiver cache ...", msg_prop->msg_subject, old_msg->uuid);
            sll_delete(np_message_ptr, property_run->msg_cache, old_iter);
            np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
        }
    }
    log_debug_msg(LOG_MSGPROPERTY, "cleanup receiver cache for subject %s done", property_conf->msg_subject);
}

void __np_property_add_msg_to_cache(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);    
    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);
    NP_CAST(event.user_data, np_message_t, message);    
    // cache already full ?
    if (property_conf->cache_size <= sll_size(property_run->msg_cache))
    {
        log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "msg cache full, checking overflow policy ...");

        if (FLAG_CMP(property_conf->cache_policy, OVERFLOW_PURGE) )
        {
            log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG, "OVERFLOW_PURGE: discarding message in msgcache for %s", property_conf->msg_subject);
            np_message_t* old_msg = NULL;

            if (FLAG_CMP(property_conf->cache_policy, FIFO))
                old_msg = sll_head(np_message_ptr, property_run->msg_cache);
            else if (FLAG_CMP(property_conf->cache_policy, LIFO) )
                old_msg = sll_tail(np_message_ptr, property_run->msg_cache);

            if (old_msg != NULL)
            {
                // TODO: add callback hook to allow user space handling of discarded message
                np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
            }
        }

        if (FLAG_CMP(property_conf->cache_policy, OVERFLOW_REJECT))
        {
            log_debug_msg(LOG_MSGPROPERTY | LOG_DEBUG,
                    "rejecting new message because cache is full");
        }
    }

    np_ref_obj(np_message_t, message, ref_msgproperty_msgcache);

    log_debug(LOG_MSGPROPERTY|LOG_ROUTING, "added message (%s) to msgcache (%p / %d) ...",
                    message->uuid,
                    property_run->msg_cache, 
                    sll_size(property_run->msg_cache)
    );

    sll_prepend(np_message_ptr, property_run->msg_cache, message);
}

void __np_msgproperty_redeliver_messages(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t,  my_property_key);    
    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);

    // remove expired msg uuid from response uuids
    double now = np_time_now();
    double resend_interval = property_conf->msg_ttl / (property_conf->retry+1);

    np_tree_elem_t* iter_tree = NULL;
    np_redelivery_data_t* current = NULL;

    RB_FOREACH(iter_tree, np_tree_s, property_run->redelivery_messages)
    {
        current = (np_redelivery_data_t *) iter_tree->val.value.v;

        if (current->redelivery_at < now)
        {   // send message redelivery attempt
            current->redelivery_at = current->redelivery_at + resend_interval;

            np_message_t* redeliver_copy = NULL;
            np_new_obj(np_message_t, redeliver_copy, FUNC);
            np_message_clone(redeliver_copy, current->message);

            np_util_event_t message_event = { .type=(evt_message|evt_internal), .user_data=redeliver_copy, .target_dhkey=current->target};
            _np_event_runtime_add_event(context, event.current_run, property_conf->subject_dhkey_out, message_event);
            /*
            char buf[100];
            snprintf(buf,100,"urn:np:message:redelivery:%s",redeliver_copy->uuid);
            if(!np_jobqueue_submit_event(context, 0, property_conf->subject_dhkey_out, message_event, buf)){
                log_error("Jobqueue rejected new job for message redelivery of msg %s. No resend will be initiated.", 
                    redeliver_copy->uuid
                );
            }else{
                log_info(LOG_ROUTING, "re-delivery of message %s / %s inititated", iter_tree->key.value.s, property_conf->msg_subject);
            }
            */
           log_info(LOG_ROUTING, "re-delivery of message %s / %s inititated", iter_tree->key.value.s, property_conf->msg_subject);
            
            np_unref_obj(np_message_t, redeliver_copy, FUNC);
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

void __load_internal_callback(char* msg_subject, np_msg_mode_type mode, sll_return(np_evt_callback_t) callback_list)
{
    size_t msg_subject_len = strnlen(msg_subject, 256);
    if (0 == strncmp(msg_subject, _DEFAULT, msg_subject_len) )
    {
        if (mode == OUTBOUND) sll_append(np_evt_callback_t, callback_list, _np_out_default);
        // if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list, _np_in_ack );
    }
    if (0 == strncmp(msg_subject, _FORWARD, msg_subject_len) )
    {
        if (mode == OUTBOUND) sll_append(np_evt_callback_t, callback_list, _np_out_forward);
        // if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list, _np_in_ack );
    }
    if (0 == strncmp(msg_subject, _NP_MSG_HANDSHAKE, msg_subject_len) )
    {
        if (mode == OUTBOUND) sll_append(np_evt_callback_t, callback_list, _np_out_handshake);
        if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list, _np_in_handshake );
    }
    if (0 == strncmp(msg_subject, _NP_MSG_ACK, msg_subject_len) )
    {
        if (mode == OUTBOUND) sll_append(np_evt_callback_t, callback_list, _np_out_ack);
        if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list, _np_in_ack );
    }
    if (0 == strncmp(msg_subject, _NP_MSG_JOIN_REQUEST, msg_subject_len) )
    {
        if (mode == OUTBOUND) sll_append(np_evt_callback_t, callback_list, _np_out_join);
        if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list, _np_in_join );
    }
    if (0 == strncmp(msg_subject, _NP_MSG_LEAVE_REQUEST, msg_subject_len) )
    {
        if (mode == OUTBOUND) sll_append(np_evt_callback_t, callback_list, _np_out_leave);
        if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list, _np_in_leave );
    }
    if (0 == strncmp(msg_subject, _NP_MSG_PING_REQUEST, msg_subject_len) )
    {
        if (mode == OUTBOUND) sll_append(np_evt_callback_t, callback_list, _np_out_ping);
        if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list, _np_in_ping );
    }
    if (0 == strncmp(msg_subject, _NP_MSG_PIGGY_REQUEST, msg_subject_len) )
    {
        if (mode == OUTBOUND) sll_append(np_evt_callback_t, callback_list, _np_out_piggy);
        if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list, _np_in_piggy );
    }
    if (0 == strncmp(msg_subject, _NP_MSG_UPDATE_REQUEST, msg_subject_len) )
    {
        if (mode == OUTBOUND) sll_append(np_evt_callback_t, callback_list, _np_out_update);
        if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list, _np_in_update );
    }
    if (0 == strncmp(msg_subject, _NP_MSG_AVAILABLE_RECEIVER, msg_subject_len) )
    {
        if (mode == OUTBOUND) sll_append(np_evt_callback_t, callback_list, _np_out_available_messages);
        if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list, _np_in_available_receiver );
    }
    if (0 == strncmp(msg_subject, _NP_MSG_AVAILABLE_SENDER, msg_subject_len) )
    {
        if (mode == OUTBOUND) sll_append(np_evt_callback_t, callback_list, _np_out_available_messages);
        if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list, _np_in_available_sender );
    }
    if (0 == strncmp(msg_subject, _NP_MSG_PHEROMONE_UPDATE, msg_subject_len) )
    {
        if (mode == OUTBOUND) sll_append(np_evt_callback_t, callback_list, _np_out_pheromone);
        if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list, _np_in_pheromone );
    }
}

void _np_msgproperty_create_token_ledger(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_create_token_ledger(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);    
    // NP_CAST(event.user_data,          np_msgproperty_conf_t, property);
    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property);

    if (property->is_internal == true) return;

    if (my_property_key->entity_array[2] == NULL) 
    {
        // could be empty on first use, therefore create and append it to the entities
        log_debug_msg(LOG_MSGPROPERTY, "creating ledger lists for %s / %s", property->msg_subject, _np_key_as_str(my_property_key));
        struct __np_token_ledger* token_ledger = malloc( sizeof (struct __np_token_ledger) );
        pll_init(np_aaatoken_ptr, token_ledger->recv_tokens);
        pll_init(np_aaatoken_ptr, token_ledger->send_tokens);
    
        my_property_key->entity_array[2] = token_ledger;
    }
    else 
    {
        struct __np_token_ledger* token_ledger = my_property_key->entity_array[2];

        pll_clear(np_aaatoken_ptr, token_ledger->recv_tokens);
        pll_clear(np_aaatoken_ptr, token_ledger->send_tokens);
    }
}

void _np_msgproperty_create_runtime_info(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_create_runtime_info(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);    
    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property);

    np_msgproperty_run_t* property_run = NULL;
    np_new_obj(np_msgproperty_run_t, property_run);

    my_property_key->entity_array[1] = property_run;

    if (_np_dhkey_equal(&my_property_key->dhkey, &property->subject_dhkey_out))
    {
        if (false == property->is_internal && property->audience_type != NP_MX_AUD_VIRTUAL)
        { 
            log_trace_msg(LOG_TRACE, "start: adding standard callbacks");
            if (false == sll_contains(np_evt_callback_t, property_run->callbacks, _np_out_callback_wrapper, np_evt_callback_t_sll_compare_type)) 
            {   // first encrypt the payload for receiver 
                sll_append(np_evt_callback_t, property_run->callbacks, _np_out_callback_wrapper);
            }
            if (false == sll_contains(np_evt_callback_t, property_run->callbacks, _np_out_default, np_evt_callback_t_sll_compare_type)) 
            {   // then route and send message
                sll_append(np_evt_callback_t, property_run->callbacks, _np_out_default);
            }
        }
        else 
        {
            log_trace_msg(LOG_TRACE, "start: adding internal callback");
            __load_internal_callback(property->msg_subject, OUTBOUND, property_run->callbacks);
        }
    }

    if (_np_dhkey_equal(&my_property_key->dhkey, &property->subject_dhkey_in))
    {
        if (FLAG_CMP(property->ack_mode, NP_MX_ACK_DESTINATION) &&
            false == sll_contains(np_evt_callback_t, property_run->callbacks, _check_and_send_destination_ack, np_evt_callback_t_sll_compare_type)) 
        {   // potentially send an ack for a message
            sll_append(np_evt_callback_t, property_run->callbacks, _check_and_send_destination_ack);
        }

        if (false == property->is_internal && property->audience_type != NP_MX_AUD_VIRTUAL)
        { 
            log_trace_msg(LOG_TRACE, "start: adding standard callbacks");
            if (false == sll_contains(np_evt_callback_t, property_run->callbacks, _np_in_callback_wrapper, np_evt_callback_t_sll_compare_type)) 
            {   // decrypt or cache the message
                sll_append(np_evt_callback_t, property_run->callbacks, _np_in_callback_wrapper);
            }
            // if (FLAG_CMP(property->ack_mode, NP_MX_ACK_CLIENT) &&
            //     false == sll_contains(np_evt_callback_t, property_run->callbacks, _check_and_send_client_ack, np_evt_callback_t_sll_compare_type)) 
            // {   // potentially send an ack for a message
            //     sll_append(np_evt_callback_t, property_run->callbacks, _check_and_send_client_ack);
            // }
        }
        else 
        {
            log_trace_msg(LOG_TRACE, "start: adding internal callback");
            __load_internal_callback(property->msg_subject, INBOUND, property_run->callbacks);
        }
    }
}

np_aaatoken_t* _np_msgproperty_get_mxtoken(np_context * context, np_key_t * my_property_key)
{
    log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_get_mxtoken(...){");
 
    np_msgproperty_conf_t* property  = my_property_key->entity_array[0];
    struct __np_token_ledger* ledger = my_property_key->entity_array[2];

    np_dhkey_t send_dhkey = property->subject_dhkey_out; // _np_msgproperty_dhkey(OUTBOUND, property->msg_subject);
    np_dhkey_t recv_dhkey = property->subject_dhkey_in;  // _np_msgproperty_dhkey(INBOUND, property->msg_subject);

    np_pll_t(np_aaatoken_ptr, token_list=NULL);
    if (_np_dhkey_equal(&my_property_key->dhkey, &send_dhkey) ) 
    {
        log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_get_mxtoken SENDER(...){ %s", _np_key_as_str(my_property_key));
        token_list = ledger->send_tokens;
    }
    
    if (_np_dhkey_equal(&my_property_key->dhkey, &recv_dhkey) ) 
    {
        log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_get_mxtoken RECEIVER(...){%s", _np_key_as_str(my_property_key));
        token_list = ledger->recv_tokens;
    }

    if (token_list == NULL)
    {
        log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_get_mxtoken NONE (...){");
        return NULL;
    }

    if (pll_size(token_list)==0)
    {
        return NULL;
    }
    else                         
    {
        np_ref_obj(np_aaatoken_t, pll_first(token_list)->val, FUNC);
        return pll_first(token_list)->val;
    }
}

void _np_msgproperty_upsert_token(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_upsert_token(...){");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);    

    np_msgproperty_conf_t* property      = my_property_key->entity_array[0];
    np_msgproperty_run_t*  property_run  = my_property_key->entity_array[1];
    struct __np_token_ledger* ledger     = my_property_key->entity_array[2];

    np_dhkey_t send_dhkey = property->subject_dhkey_out; // _np_msgproperty_dhkey(OUTBOUND, property->msg_subject);
    np_dhkey_t recv_dhkey = property->subject_dhkey_in;  // _np_msgproperty_dhkey(INBOUND, property->msg_subject);

    np_pll_t(np_aaatoken_ptr, token_list=NULL);
    if (_np_dhkey_equal(&my_property_key->dhkey, &send_dhkey) ) 
    {
        log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_upsert_token SENDER(...){%s", _np_key_as_str(my_property_key));
        token_list = ledger->send_tokens;
    }
    else if (_np_dhkey_equal(&my_property_key->dhkey, &recv_dhkey) ) 
    {
        log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_upsert_token RECEIVER(...){%s", _np_key_as_str(my_property_key));
        token_list = ledger->recv_tokens;
    }
    else
    {
        log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_upsert_token NONE (...){");
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
        else if ( (iter->val->expires_at - now) < fmax(property->token_min_ttl + 1.0, MSGPROPERTY_DEFAULT_MIN_TTL_SEC) )
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

            enum np_data_return r = np_could_not_read_object;
            r = np_merge_data(iter->val->attributes, property_run->attributes);
            ASSERT(r == np_ok,"Could not write \"max_threshold\" into attributes. Error: %"PRIu32, r);

            r = np_could_not_read_object;
            r = np_set_data(iter->val->attributes, (struct np_data_conf){ .key = "max_threshold", .type = NP_DATA_TYPE_UNSIGNED_INT}, max_threshold);
            ASSERT(r == np_ok,"Could not write \"max_threshold\" into attributes. Error: %"PRIu32, r);
            /*
            np_data_value msg_threshold;
            msg_threshold.unsigned_integer = property->msg_threshold;
            r = np_set_data(iter->val->attributes, (struct np_data_conf){ .key = "msg_threshold", .type = NP_DATA_TYPE_UNSIGNED_INT}, msg_threshold);
            ASSERT(r == np_ok,"Could not write \"msg_threshold\" into attributes. Error: %"PRIu32, r);
            */
        }

        if (iter != NULL) pll_next(iter);

    } while (NULL != iter);
}

void np_msgproperty4user(struct np_mx_properties* dest, np_msgproperty_conf_t* src)
{
    dest->message_ttl = src->msg_ttl;

    dest->intent_ttl = src->token_max_ttl;
    dest->intent_update_after = src->token_min_ttl;

    dest->cache_size = src->cache_size;
    dest->max_parallel = src->max_threshold;
    dest->max_retry = src->retry;

    if (FLAG_CMP(src->mode_type, INBOUND)) dest->role = NP_MX_CONSUMER;
    if (FLAG_CMP(src->mode_type, OUTBOUND)) dest->role = NP_MX_PROVIDER;
    if (FLAG_CMP(src->mode_type, DEFAULT_MODE)) dest->role = NP_MX_PROSUMER;

    if(src->rep_subject != NULL) {
        memcpy(dest->reply_id, &src->reply_dhkey, NP_FINGERPRINT_BYTES);
        sodium_bin2hex(dest->reply_id, 65, &src->reply_dhkey, NP_FINGERPRINT_BYTES);
    }
    else {
        memset(dest->reply_id, 0, NP_FINGERPRINT_BYTES);
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

void np_msgproperty_from_user(np_state_t* context, np_msgproperty_conf_t* dest, struct np_mx_properties* src) 
{
	assert(context != NULL);
    assert(src != NULL);
    assert(dest != NULL);

    if (src->role == NP_MX_CONSUMER) dest->mode_type = INBOUND;
    if (src->role == NP_MX_PROVIDER) dest->mode_type = OUTBOUND;
    if (src->role == NP_MX_PROSUMER) dest->mode_type = DEFAULT_MODE;

    if (src->intent_ttl > 0.0) {
        dest->token_max_ttl = src->intent_ttl;
    }

    if (src->intent_update_after > 0.0) {
        dest->token_min_ttl = src->intent_update_after;
        // reset to trigger discovery messages
        // dest->last_intent_update = (dest->last_intent_update - dest->token_min_ttl);
        // dest->last_intent_update = (dest->last_intent_update - dest->token_min_ttl);
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

    if (src->reply_id[0] != '\0' && (dest->rep_subject == NULL || strncmp(dest->rep_subject, src->reply_id, 255) != 0))
    {
        char* old = dest->rep_subject;
        dest->rep_subject = strndup(src->reply_id, 255);
        if(old) free(old);

    } else {
         dest->rep_subject = NULL;
    }

    dest->audience_type = src->audience_type;    
    memcpy(&dest->audience_id, src->audience_id, NP_FINGERPRINT_BYTES);

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
    // log_trace_msg(LOG_TRACE, "start: bool __is_msgproperty(...){");
    // np_ctx_memory(statemachine->_user_data);
    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_property) && FLAG_CMP(event.type, evt_internal);
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_msgproperty_conf_t);
    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

bool __is_msgproperty_lifecycle_enable(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    // np_ctx_memory(statemachine->_user_data);
    // log_trace_msg(LOG_TRACE, "start: bool __is_msgproperty(...){");
    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_enable);
    if ( ret) ret  = FLAG_CMP(event.type, evt_property) && FLAG_CMP(event.type, evt_internal);
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_msgproperty_run_t);
    
    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

bool __is_msgproperty_lifecycle_disable(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: bool __is_msgproperty(...){");
    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_disable);
    if ( ret) ret  = FLAG_CMP(event.type, evt_property) && FLAG_CMP(event.type, evt_internal);
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_msgproperty_run_t);
    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);

    return ret;
}

void __np_property_lifecycle_set(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    // noop, state handled by state machine
}

void __np_set_property(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_set_property(...) {");

    NP_CAST(statemachine->_user_data, np_key_t,              my_property_key);
    NP_CAST(event.user_data,          np_msgproperty_conf_t, property);

    np_ref_obj(no_key_t, my_property_key, "__np_set_property");
    my_property_key->type |= np_key_type_subject;

    my_property_key->entity_array[0] = property;
    log_debug_msg(LOG_MSGPROPERTY, "sto  :msgproperty %s: %p added to list: %p / %p", property->msg_subject, property, my_property_key, my_property_key->entity_array[0]);
    
    // create runtime parts of msgproperty
    _np_msgproperty_create_runtime_info(statemachine, event);
    // create token ledger for user supplied message exchanges
    _np_msgproperty_create_token_ledger(statemachine, event);

    if (my_property_key->bloom_scent == NULL) 
    {
        // np_dhkey_t target_dhkey = _np_msgproperty_tweaked_dhkey(INBOUND, property->subject_dhkey);
        my_property_key->bloom_scent   = _np_neuropil_bloom_create();
        _np_neuropil_bloom_add(my_property_key->bloom_scent, property->subject_dhkey);
    }
}

void __np_property_update(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    // np_ctx_memory(statemachine->_user_data);
    // log_trace_msg(LOG_TRACE, "start: void __np_property_update(...) {");

    NP_CAST(statemachine->_user_data, np_key_t,   my_property_key);

    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, old_property);
    NP_CAST(event.user_data, np_msgproperty_conf_t, new_property);
    // buggy, but for now ...
    *old_property = *new_property;
}

void __np_msgproperty_send_available_messages(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_msgproperty_send_available_messages(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, property_key);
    NP_CAST(property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(property_key->entity_array[1], np_msgproperty_run_t, property_run);

    // upsert message intent token
    np_aaatoken_t* intent_token = _np_msgproperty_get_mxtoken(context, property_key);
    if (NULL == intent_token) return;

    double now = np_time_now();
    // if ((now - property_run->last_intent_update) > property_conf->token_min_ttl) 
    if ( property_run->last_intent_update == 0 ||
        (now - property_run->last_intent_update) > MIN(property_conf->token_min_ttl/3, NP_TOKEN_MIN_RESEND_INTERVAL_SEC)
    ) {
        np_tree_t* intent_data = np_tree_create();

        np_dhkey_t send_dhkey = property_conf->subject_dhkey_out;
        np_dhkey_t recv_dhkey = property_conf->subject_dhkey_in;

        np_dhkey_t target_dhkey = property_conf->subject_dhkey; 

        np_dhkey_t available_out_dhkey = {0};


        np_aaatoken_encode(intent_data, intent_token);
        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out, FUNC);

        np_util_event_t available_event = { .type=(evt_internal|evt_message), .target_dhkey=target_dhkey};
        np_dhkey_t available_dhkey = {0};

        if (_np_dhkey_equal(&property_key->dhkey, &send_dhkey))
        {   // send our token, search for receiver of messages
            np_generate_subject( (np_subject *) &available_dhkey, _NP_MSG_AVAILABLE_SENDER, strnlen(_NP_MSG_AVAILABLE_SENDER, 256));
            _np_message_create( msg_out, target_dhkey, context->my_node_key->dhkey, available_dhkey, np_tree_clone(intent_data));
            log_info(LOG_ROUTING,
                "sending available message for %s as a sender: _NP_MSG_AVAILABLE_SENDER {msg uuid: %s / intent uuid: %s)", 
                property_conf->msg_subject, msg_out->uuid, intent_token->uuid
            );

            available_out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, available_dhkey);
        }
        else if (_np_dhkey_equal(&property_key->dhkey, &recv_dhkey))
        {
            np_generate_subject( (np_subject *) &available_dhkey, _NP_MSG_AVAILABLE_RECEIVER, strnlen(_NP_MSG_AVAILABLE_RECEIVER, 256));
            _np_message_create(msg_out, target_dhkey, context->my_node_key->dhkey, available_dhkey, np_tree_clone(intent_data) );
            log_info(LOG_ROUTING,
                "sending available message for %s as a receiver: _NP_MSG_AVAILABLE_RECEIVER {msg uuid: %s / intent uuid: %s)",
                property_conf->msg_subject, msg_out->uuid, intent_token->uuid
            );
            available_out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, available_dhkey);
        }
        else 
        {
            log_error("sending available message for %s in unknown state", property_conf->msg_subject);
            ABORT("sending available message for %s in unknown state", property_conf->msg_subject);
        }

        available_event.user_data = msg_out;
        _np_event_runtime_add_event(context, event.current_run, available_out_dhkey, available_event);
        property_run->last_intent_update = now;
        np_unref_obj(np_message_t, msg_out, FUNC);

        np_tree_free(intent_data);
    }
    np_unref_obj(np_aaatoken_t, intent_token, "_np_msgproperty_get_mxtoken");
}

void __np_msgproperty_send_pheromone_messages(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_msgproperty_send_pherolast_pheromone_updatemone_messages(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, property_key);
    NP_CAST(property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(property_key->entity_array[1], np_msgproperty_run_t, property_run);

    np_dhkey_t send_dhkey = property_conf->subject_dhkey_out;
    np_dhkey_t recv_dhkey = property_conf->subject_dhkey_in;
    np_dhkey_t target_dhkey = property_conf->subject_dhkey; // np_dhkey_create_from_hostport(property->msg_subject, "0");

    bool is_send = _np_dhkey_equal(&property_key->dhkey, &send_dhkey);
    bool is_recv = _np_dhkey_equal(&property_key->dhkey, &recv_dhkey);
    

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
        np_tree_insert_int(bloom_data, 
            _np_pheromone_calc_table_position(target_dhkey,np_pheromone_direction_receiver), 
            np_treeval_new_bin((void*) buffer, buffer_size)
        );
        log_debug_msg(LOG_MSGPROPERTY|LOG_PHEROMONE, "adding %25s bloom data at %i", 
            property_conf->msg_subject, 
            _np_pheromone_calc_table_position(target_dhkey,np_pheromone_direction_receiver)
        );

        _np_pheromone_snuffle_receiver(context, result_list, target_dhkey, &_return_age);

        if (FLAG_CMP(property_conf->ack_mode, ACK_DESTINATION) ||
            FLAG_CMP(property_conf->ack_mode, ACK_CLIENT     )  )
        {
            np_dhkey_t ack_dhkey = {0}; 
            if (FLAG_CMP(property_conf->ack_mode, ACK_DESTINATION))
                ack_dhkey = context->my_node_key->dhkey;
            if (FLAG_CMP(property_conf->ack_mode, ACK_CLIENT))
                ack_dhkey = context->my_identity->dhkey;

            np_generate_subject( (np_subject*) &ack_dhkey, _NP_MSG_ACK, strnlen(_NP_MSG_ACK, 256));

            np_bloom_t* ack_scent = _np_neuropil_bloom_create();
            _np_neuropil_bloom_add(ack_scent, ack_dhkey);
            unsigned char* ack_buffer = NULL;
            uint16_t ack_buffer_size = 0;
            _np_neuropil_bloom_serialize(ack_scent, &ack_buffer, &ack_buffer_size);
            
            np_tree_insert_int(bloom_data, 
                _np_pheromone_calc_table_position(ack_dhkey,np_pheromone_direction_sender), 
                np_treeval_new_bin((void*) ack_buffer, ack_buffer_size)
            );
            log_debug_msg(LOG_MSGPROPERTY|LOG_PHEROMONE, "adding %25s bloom data at %i",
                _NP_MSG_ACK,
                _np_pheromone_calc_table_position(ack_dhkey,np_pheromone_direction_sender)
            );

            free(ack_buffer);
            _np_bloom_free(ack_scent);
        }
    }
    else if (is_recv)
    {        
        np_tree_insert_int(bloom_data,  
            _np_pheromone_calc_table_position(target_dhkey,np_pheromone_direction_sender),
            np_treeval_new_bin((void*) buffer, buffer_size)
        );
        log_debug_msg(LOG_MSGPROPERTY|LOG_PHEROMONE, "adding %25s bloom data at %i", 
            property_conf->msg_subject, 
            _np_pheromone_calc_table_position(target_dhkey,np_pheromone_direction_sender)
        );

        _np_pheromone_snuffle_sender(context, result_list, target_dhkey, &_return_age);
    }
    sll_free(np_dhkey_t, result_list);

    double  last_pheromone_update = property_run->last_pheromone_update;

    if (_return_age > _target_age) _target_age = _return_age;

    double now = np_time_now(   );

    np_util_event_t pheromone_event = { .type=(evt_internal|evt_message), .target_dhkey=target_dhkey};

    if (last_pheromone_update == 0 ||
        (now - last_pheromone_update) > (_target_age * property_conf->token_min_ttl) )
    {
        np_dhkey_t pheromone_dhkey = {0};
        np_generate_subject( (np_subject *) &pheromone_dhkey, _NP_MSG_PHEROMONE_UPDATE, 20);

        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out, FUNC);
        _np_message_create(msg_out, target_dhkey, context->my_node_key->dhkey, pheromone_dhkey, np_tree_clone(bloom_data));

        log_info(LOG_MSGPROPERTY|LOG_PHEROMONE, 
            "sending pheromone trail message for subject %s: _NP_MSG_PHEROMONE_UPDATE {msg uuid: %s} / %f success probability", 
            property_conf->msg_subject,
            msg_out->uuid,
            _target_age
        );

        np_dhkey_t pheromone_out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, pheromone_dhkey);
        pheromone_event.user_data = msg_out;
        _np_event_runtime_add_event(context, event.current_run, pheromone_out_dhkey, pheromone_event);

        property_run->last_pheromone_update = now;
        np_unref_obj(np_message_t, msg_out, FUNC);

    }

    np_tree_free(bloom_data);
    free(buffer);
}

void __np_property_check(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_property_check(...) {");

    NP_CAST(statemachine->_user_data, np_key_t,  my_property_key);    
    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);

    log_trace_msg(LOG_TRACE, "start: void __np_property_check(...) { %s", _np_key_as_str(my_property_key));

    if (property_run->response_handler != NULL)
    {
        _np_msgproperty_cleanup_response_handler(property_run, event);
    }

    if (property_conf->is_internal == false) 
    {
        if ( FLAG_CMP(property_conf->mode_type, OUTBOUND ) )
        {
            __np_msgproperty_redeliver_messages(statemachine, event);
        }
        _np_msgproperty_cleanup_cache(statemachine, event);

        _np_msgproperty_upsert_token(statemachine, event);

        if(np_has_joined(context))
        {
            __np_msgproperty_send_pheromone_messages(statemachine, event);
            __np_msgproperty_send_available_messages(statemachine, event);
        }
    
        __np_intent_check(statemachine, event);
    }

    property_run->last_update = _np_time_now(context);
    
    _np_msgproperty_job_msg_uniquety(property_conf, property_run);

    if (event.user_data != NULL) {
        log_msg(LOG_WARNING, "unexpected datatype %"PRIu8" attached to event (__np_property_check)", np_memory_get_type(event.user_data));
    }
}

// NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY, __np_property_handle_msg,  __is_message);
bool __is_external_message(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    bool ret = false;

    if (!ret) ret  = FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);

    return ret;
}

void __np_property_handle_in_msg(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_property_handle_in_msg(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);

    NP_CAST(event.user_data, np_message_t, msg_in);

    bool ret = _np_msgproperty_check_msg_uniquety(property_conf, property_run, msg_in);

    __np_msgproperty_threshold_increase(property_conf, property_run);

    sll_iterator(np_evt_callback_t) iter = sll_first(property_run->callbacks);
    while (iter != NULL && ret)
    {
        if (iter->val != NULL) 
        {
            ret &= iter->val(context, event);
            if(!ret) break;
        }
        sll_next(iter);
    }
    log_trace(LOG_MESSAGE,"(msg: %s) property callbacks result: %"PRIu8" audience_type:%"PRIu8, 
    msg_in->uuid, ret, property_conf->audience_type);

    if (property_conf->is_internal == false &&
        property_conf->audience_type != NP_MX_AUD_VIRTUAL && 
        ret == true) 
    {
        // call user callbacks
        sll_iterator(np_usercallback_ptr) iter_usercallbacks = sll_first(property_run->user_callbacks);
        while (iter_usercallbacks != NULL && ret)
        {
            log_debug(LOG_MESSAGE, "(msg: %s) invoking user callback %p", msg_in->uuid, iter_usercallbacks->val->fn);
            ret &= iter_usercallbacks->val->fn(context, msg_in, msg_in->body, iter_usercallbacks->val->data);
            sll_next(iter_usercallbacks);
        }
        log_info(LOG_MESSAGE, "(msg: %s) invoked user callbacks. result: %"PRIu8, msg_in->uuid, ret);
    }

    __np_msgproperty_threshold_decrease(property_conf, property_run);

    if (ret) _np_increment_received_msgs_counter(property_conf->subject_dhkey);

    log_debug(LOG_MESSAGE, "in: (subject: %s / msg: %s) handling complete", property_conf->msg_subject, msg_in->uuid);
}

bool __is_internal_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    // np_ctx_memory(statemachine->_user_data);
    // log_trace_msg(LOG_TRACE, "start: bool __is_internal_message(...) {");

    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_internal);
    if ( ret) ret &= !FLAG_CMP(event.type, evt_redeliver);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);
    // if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_message_t);

    return ret;
} 

bool __is_sender_token_available(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);

    bool ret = false;

    NP_CAST(statemachine->_user_data, np_key_t, property_key);
    NP_CAST(property_key->entity_array[0], np_msgproperty_conf_t, my_property_conf);
    NP_CAST(property_key->entity_array[1], np_msgproperty_run_t, my_property_run);
    
    if (__is_external_message(statemachine, event))
    {
        if (!ret) ret = my_property_conf->is_internal;  // internal messages have no token
        if (!ret)
        {
            ret = !__np_msgproperty_threshold_breached(my_property_conf, my_property_run);
            //TODO: EXPERIMENT: maybe get dhkey_zero
            np_aaatoken_ptr tmp_token = _np_intent_get_sender_token(property_key, event.target_dhkey);
            ret &= (tmp_token != NULL);            
            if (tmp_token != NULL) np_unref_obj(np_aaatoken_ptr, tmp_token, "_np_intent_get_sender_token");
        }
    }
    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

bool __is_receiver_token_available(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);

    bool ret = false;

    if (__is_internal_message(statemachine, event))
    {
        NP_CAST(statemachine->_user_data, np_key_t, property_key);
        NP_CAST(property_key->entity_array[0], np_msgproperty_conf_t, my_property_conf);
        NP_CAST(property_key->entity_array[1], np_msgproperty_run_t, my_property_run);
        
        if (!ret) ret  = my_property_conf->is_internal; // internal messages have no token
        if (!ret)
        {
            ret = !__np_msgproperty_threshold_breached(my_property_conf, my_property_run);
            np_sll_t(np_aaatoken_ptr, tmp_token_list);
            sll_init(np_aaatoken_ptr, tmp_token_list);
            _np_intent_get_all_receiver(property_key, event.target_dhkey, &tmp_token_list);
            ret &= (sll_size(tmp_token_list) > 0);
            np_aaatoken_unref_list(tmp_token_list, "_np_intent_get_all_receiver");
            sll_free(np_aaatoken_ptr, tmp_token_list);
        }
    }
    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

bool __is_no_token_available(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);

    bool ret = false;
    // the fact that this check is called can only mean that no token has been found in an earlier check
    // so we just have to check whether this is an internal or external message as a criteria that no token
    // has been found or that the threshold has been breached. we still need the check for the message type
    // to differentiate from e.g. lifecycle events

    // NP_CAST(statemachine->_user_data, np_key_t, property_key);
    // NP_CAST(property_key->entity_array[0], np_msgproperty_conf_t, my_property_conf);
    ret = event.user_data != NULL;
    if(ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);
    if (!ret) ret = __is_internal_message(statemachine, event) || 
                    __is_external_message(statemachine, event);
    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

void __np_property_handle_out_msg(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_property_handle_out_msg(...) { %p", statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);

    NP_CAST(event.user_data, np_message_t, msg_out);

    bool user_result = true;    

    __np_msgproperty_threshold_increase(property_conf, property_run);
    if (
        property_conf->audience_type != NP_MX_AUD_VIRTUAL && 
        property_conf->is_internal == false)
    {
        sll_iterator(np_usercallback_ptr) iter_usercallbacks = sll_first(property_run->user_callbacks);
        while (iter_usercallbacks != NULL && user_result)
        {
            user_result &= iter_usercallbacks->val->fn(context, msg_out, (msg_out == NULL ? NULL : msg_out->body), iter_usercallbacks->val->data);
            sll_next(iter_usercallbacks);
        }
        log_trace(LOG_MESSAGE,"(msg: %s) %s user result: %"PRIu8,msg_out->uuid, FUNC, user_result);
    }
    sll_iterator(np_evt_callback_t) iter = sll_first(property_run->callbacks);
    while (iter != NULL && user_result)
    {
        if (iter->val != NULL) {
            user_result &= iter->val(context, event);
            if(!user_result) break;
        }
        sll_next(iter);
    }

    if (FLAG_CMP(property_conf->ack_mode, ACK_NONE))
        __np_msgproperty_threshold_decrease(property_conf, property_run);

    if (user_result) {
        _np_increment_send_msgs_counter(property_conf->subject_dhkey);
    }
    log_trace(LOG_MESSAGE,"(msg: %s) %s result: %"PRIu8,msg_out->uuid, FUNC, user_result);
}

void __np_property_redelivery_set(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_property_redelivery_set(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);
    NP_CAST(event.user_data, np_message_t, message);

    double resend_interval = property_conf->msg_ttl / (property_conf->retry+1);

    if (np_tree_find_str(property_run->redelivery_messages, message->uuid) == NULL) 
    {
        log_msg(LOG_INFO, "storing message %s / %s for possible re-delivery", message->uuid, property_conf->msg_subject);
        __np_msgproperty_threshold_increase(property_conf, property_run);
        np_redelivery_data_t* redeliver = malloc(sizeof(np_redelivery_data_t));
        _np_dhkey_assign(&redeliver->target, &event.target_dhkey);
        redeliver->message = message;
        redeliver->redelivery_at = message->send_at + resend_interval;
        np_tree_insert_str(property_run->redelivery_messages, message->uuid, np_treeval_new_v(redeliver) );
        np_ref_obj(np_message_t, message, FUNC);
    }
}

void __np_response_handler_set(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_response_handler_set(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);
    NP_CAST(event.user_data, np_responsecontainer_t, responsehandler);

    if (property_conf->is_internal)
    {   // registration of response handler for message type NP_ACK
        if (np_tree_find_str(property_run->response_handler, responsehandler->uuid) == NULL)
            np_tree_insert_str(property_run->response_handler, responsehandler->uuid, np_treeval_new_v(responsehandler) );
    }
    else
    {   // a responsehandler reporting a timeout or an acknowledgement
        CHECK_STR_FIELD_BOOL(property_run->redelivery_messages, responsehandler->uuid, msg_tree_elem, "NO UUID FOUND") 
        {
            log_msg(LOG_INFO, "message %s / %s acknowledged or timed out", responsehandler->uuid, property_conf->msg_subject);
            np_redelivery_data_t* redeliver = msg_tree_elem->val.value.v;
            np_unref_obj(np_message_t, redeliver->message, "__np_property_redelivery_set");
            np_tree_del_str(property_run->redelivery_messages, responsehandler->uuid);
            free(redeliver);
            __np_msgproperty_threshold_decrease(property_conf, property_run);        
        }
        //np_unref_obj(np_responsecontainer_t, responsehandler, ref_obj_usage);
    }
}

bool __is_message_redelivery_event(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    // np_ctx_memory(statemachine->_user_data);
    // log_trace_msg(LOG_TRACE, "start: bool __is_message_redelivery_event(...) {");

    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_message);
    if ( ret) ret &= (FLAG_CMP(event.type, evt_redeliver) && FLAG_CMP(event.type, evt_internal) );
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);
    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);

    return ret;
}

bool __is_response_event(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    // log_trace_msg(LOG_TRACE, "start: bool __is_response_event(...) {");

    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_response);
    if ( ret) ret &= (FLAG_CMP(event.type, evt_timeout) || FLAG_CMP(event.type, evt_internal) );
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_responsecontainer_t);
    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

void __np_property_handle_intent(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __np_property_handle_intent(...){");

    NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
    NP_CAST(event.user_data, np_aaatoken_t, intent_token);

    NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
    NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);

    np_dhkey_t audience_id = {0};
    if (property_conf->audience_type == NP_MX_AUD_PROTECTED) 
    {
        np_str_id((np_id*) &audience_id, intent_token->audience);
    }

    if(_np_policy_check_compliance(property_run->required_attributes_policy, &intent_token->attributes) &&
       ( _np_dhkey_equal(&context->my_identity->dhkey , &audience_id) || _np_dhkey_equal(&context->realm_id, &audience_id)) )
    {
        // always?: just store the available tokens in memory and update them if new data arrives
        np_dhkey_t sendtoken_issuer_key = np_aaatoken_get_partner_fp(intent_token);

        if (_np_dhkey_equal(&sendtoken_issuer_key, &context->my_node_key->dhkey) )
        {
            // only add the token if it is not from ourself (in case of IN/OUTBOUND on same subject)
            // TODO: CHECK IF NECCESARY
        }
        bool needs_authz = false;

        // choose correct target ledger
        if (_np_dhkey_equal(&property_conf->subject_dhkey_in, &my_property_key->dhkey) /* &&
             sll_contains(np_evt_callback_t, property_run->callbacks, _np_in_callback_wrapper, np_evt_callback_t_sll_compare_type)*/ )
        {
            log_info(LOG_ROUTING, "adding sending intent %s for subject %s", intent_token->uuid, property_conf->msg_subject);
            np_aaatoken_t* old_token = _np_intent_add_sender(my_property_key, intent_token);
            np_unref_obj(np_aaatoken_t, old_token, ref_aaatoken_local_mx_tokens);

            // check if some messages are left in the cache
            np_dhkey_t issuer_dhkey = np_dhkey_create_from_hash(intent_token->issuer);
            np_util_event_t msgcache_event = { .target_dhkey=issuer_dhkey };
            _np_msgproperty_check_msgcache_for(statemachine, event.current_run, msgcache_event);

            needs_authz = true;
        }

        // choose correct target ledger
        if (_np_dhkey_equal(&property_conf->subject_dhkey_out, &my_property_key->dhkey)) 
        {
            np_dhkey_t _intent_token_id = np_aaatoken_get_fingerprint(intent_token, true);
            char _intent_token_id_s[65]={0};
            _np_dhkey_str(&_intent_token_id,_intent_token_id_s);
            log_info(LOG_ROUTING, "adding receiver intent %s for subject %s fingerprint %s",
                 intent_token->uuid, property_conf->msg_subject,  _intent_token_id_s
            );
            np_aaatoken_t* old_token = _np_intent_add_receiver(my_property_key, intent_token);
            np_unref_obj(np_aaatoken_t, old_token, ref_aaatoken_local_mx_tokens);

            // check if some messages are left in the cache
            _np_msgproperty_check_msgcache(statemachine, event);
            needs_authz = true;
        }

        if (IS_NOT_AUTHORIZED(intent_token->state) && needs_authz == true)
        {    
            log_info(LOG_AAATOKEN, "token %s from %s complies with subject policy %s", intent_token->uuid, intent_token->issuer, intent_token->subject );

            log_info(LOG_ROUTING, "authorizing intent %s for subject %s", intent_token->uuid, property_conf->msg_subject);
            np_dhkey_t authz_target = context->my_identity->dhkey;
            np_util_event_t authz_event = { .type=(evt_token|evt_external|evt_authz), .user_data=intent_token, .target_dhkey=event.target_dhkey };
            _np_event_runtime_add_event(context, event.current_run, authz_target, authz_event);
        }
    }
}