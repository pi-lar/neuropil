//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include "sodium.h"
#include "tree/tree.h"

#include "np_keycache.h"

#include "core/np_comp_node.h"

#include "np_aaatoken.h"
#include "np_constants.h"
#include "np_dhkey.h"
#include "np_legacy.h"
#include "util/np_list.h"
#include "neuropil_log.h"
#include "np_log.h"
#include "np_network.h"
#include "np_node.h"
#include "np_key.h"
#include "np_settings.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_eventqueue.h"

// RB_HEAD(rbt_msgproperty, np_msgproperty_s);
// RB_PROTOTYPE(rbt_msgproperty, np_msgproperty_s, link, property_comp);
// RB_GENERATE(rbt_msgproperty, np_msgproperty_s, link, _np_msgproperty_comp);

typedef struct st_keycache_s st_keycache_t;
RB_GENERATE(st_keycache_s, np_key_s, link, _np_key_cmp);

np_module_struct(keycache) {
    np_state_t* context;
    st_keycache_t* __key_cache;
    double __last_udpate;
    np_dhkey_t _check_state_iterator;
};

bool _np_keycache_init(np_state_t* context)
{
    bool ret = false;
    if (!np_module_initiated(keycache)) {
        np_module_malloc(keycache);
        _module->__key_cache = (st_keycache_t*)malloc(sizeof(st_keycache_t));
        CHECK_MALLOC(_module->__key_cache);
       _np_dhkey_assign(&_module->_check_state_iterator, &dhkey_zero);
        RB_INIT(_module->__key_cache);
        np_dhkey_t _null = {0};
        _np_dhkey_assign(&np_module(keycache)->_check_state_iterator, &_null);

        ret = true;
    }
    return ret;
}

void _np_keycache_destroy(np_state_t* context){
    if (np_module_initiated(keycache)) {
        np_module_var(keycache);
        np_key_t *iter = NULL;

        _LOCK_MODULE(np_keycache_t)
        {
            while((iter = RB_ROOT(_module->__key_cache)) != NULL)
            {
                _np_key_destroy(iter);
            }
            free(_module->__key_cache);
        }
        np_module_free(keycache);
    }
}

np_key_t* _np_keycache_find_or_create(np_state_t* context, np_dhkey_t search_dhkey)
{
    log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_find_or_create(...){" );

    // log_trace_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_keycache_find_or_create start");
    np_key_t* key = NULL;
    np_key_t search_key = { .dhkey = search_dhkey };

    _LOCK_MODULE(np_keycache_t)
    {
        key = RB_FIND(st_keycache_s, np_module(keycache)->__key_cache, &search_key);
        if (NULL == key)
        {
            key = _np_keycache_create(context, search_dhkey);
            ref_replace_reason(np_key_t, key, "_np_keycache_create", FUNC);
        }
        else {
            np_ref_obj(np_key_t, key);
        }
        // key->last_update = np_time_now();
    }
    // log_trace_msg(LOG_TRACE | LOG_VERBOSE, "logpoint _np_keycache_find_or_create end");
    return (key);
}

bool _np_keycache_exists(np_state_t* context, np_dhkey_t search_dhkey, np_key_ro_t * readonly_buffer) {

    bool ret = false;
    np_key_t* return_key = NULL;
    np_key_t search_key = { .dhkey = search_dhkey };

    _LOCK_MODULE(np_keycache_t)
    {
        return_key = RB_FIND(st_keycache_s, np_module(keycache)->__key_cache, &search_key);
        if (NULL != return_key)
        {
            ret = true;

            if(readonly_buffer != NULL){
                np_ref_obj(np_key_t, return_key, FUNC);
            }
        }
    }
    if(readonly_buffer != NULL && return_key != NULL){
        _np_key_readonly_copy(context, readonly_buffer,return_key);
        np_unref_obj(np_key_t, return_key, FUNC);
    }
    return ret;

}

np_key_t* _np_keycache_create(np_state_t* context, np_dhkey_t search_dhkey)
{
    log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_create(np_dhkey_t search_dhkey){");
    np_key_t* key = NULL;

    np_new_obj(np_key_t, key, FUNC);
    _np_dhkey_assign(&key->dhkey, &search_dhkey);
    _np_dhkey_str(&key->dhkey, key->dhkey_str);
    key->created_at = np_time_now();
    key->last_update = key->created_at;

    _np_keycache_add(context, key);
    
    return key;
}

np_key_t* _np_keycache_find(np_state_t* context, const np_dhkey_t search_dhkey)
{
    log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_find(const np_dhkey_t search_dhkey){");
    np_key_t* return_key = NULL;
    np_key_t search_key = { .dhkey = search_dhkey };

    _LOCK_MODULE(np_keycache_t)
    {
        return_key = RB_FIND(st_keycache_s, np_module(keycache)->__key_cache, &search_key);
        if (NULL != return_key)
        {
            np_ref_obj(np_key_t, return_key);
        }
    }
    return return_key;
}

np_key_t* _np_keycache_find_by_details(
        np_state_t* context,
        char* details_container,
        bool search_myself,
        enum np_node_status search_handshake_status,
        bool require_handshake_status,
        bool require_dns,
        bool require_port,
        bool require_hash
    )
{
    log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_find_by_details(		char* details_container,		bool search_myself,		handshake_status_e is_handshake_send,		bool require_handshake_status,		bool require_dns,		bool require_port,		bool require_hash	){");
    np_key_t* ret = NULL;
    np_key_t *iter = NULL;

    np_key_t* my_node_key = context->my_node_key;
    np_key_t* my_identity = context->my_identity;

    _LOCK_MODULE(np_keycache_t)
    {
        RB_FOREACH(iter, st_keycache_s, np_module(keycache)->__key_cache)
        {
            if(true == search_myself){
                if (
                    true == _np_dhkey_equal(&iter->dhkey, &my_node_key->dhkey) ||
                    true == _np_dhkey_equal(&iter->dhkey, &my_identity->dhkey) )
                {
                    continue;
                }
            }
            np_node_t* node = _np_key_get_node(iter);
            if (
                    (!require_handshake_status ||
                            (NULL != node &&
                                node->_handshake_status == search_handshake_status									
                            ) 

                    ) &&
                    (!require_hash ||
                            strstr(details_container, iter->dhkey_str) != NULL
                    ) &&
                    (!require_dns ||
                            (NULL != node &&
                            NULL != node->dns_name &&
                            strstr(details_container, node->dns_name) != NULL
                            )
                    ) &&
                    (!require_port ||
                            (NULL != node &&
                            NULL != node->port &&
                            strstr(details_container, node->port) != NULL
                            )
                    )
            )
            {
                np_ref_obj(np_key_t, iter);
                ret = iter;
                // ret->last_update = np_time_now();
                break;
            }
        }
    }

    return (ret);
}

bool _np_keycache_exists_state(np_state_t* context, np_util_event_t args) 
{
    np_key_t *iter = NULL;
    uint16_t i = 0;
    bool process_state_check = false;

    sll_init_full(np_dhkey_t, tmp_to_transition);

    _LOCK_MODULE(np_keycache_t)
    {
        RB_FOREACH(iter, st_keycache_s, np_module(keycache)->__key_cache)
        {
            if (_np_dhkey_equal(&dhkey_zero, &np_module(keycache)->_check_state_iterator) )
                _np_dhkey_assign(&np_module(keycache)->_check_state_iterator, &iter->dhkey);

            // fast forward to dhkey and then begin to execute state changes
            if ((
                    _np_dhkey_equal(&iter->dhkey, &np_module(keycache)->_check_state_iterator) ||
                    true == process_state_check
                ) &&
                i < _NP_KEYCACHE_ITERATION_STEPS 
            ) {
                log_debug(LOG_KEYCACHE, "iteration on key %s", _np_key_as_str(iter));
                process_state_check = true;
                // log_trace_msg(LOG_TRACE, "start: void _np_keycache_exists_state(...) { %p", iter);
                sll_append(np_dhkey_t, tmp_to_transition, iter->dhkey);

                // The following debug message should only be active if we want to debug the state machine
                // it does not respact the locking mechanisms
                //log_debug(LOG_KEYCACHE, "sm %p %d %s", iter, iter->type, iter->sm._state_table[iter->sm._current_state]->_state_name);
                i++;
            }

            // iteration steps interval reached, store dhkey for next iteration
            if (i >= _NP_KEYCACHE_ITERATION_STEPS)
            {
                log_debug(LOG_KEYCACHE, "stopping iteration at key %s", _np_key_as_str(iter));
                _np_dhkey_assign(&np_module(keycache)->_check_state_iterator, &iter->dhkey);
                break;
            }
        }
        // end of list interval exit - reset start dhkey to zero
        if (i < _NP_KEYCACHE_ITERATION_STEPS)
            _np_dhkey_assign(&np_module(keycache)->_check_state_iterator, &dhkey_zero);
    }

    sll_iterator(np_dhkey_t) transition_iter = sll_first(tmp_to_transition);
    char buf[100];
    while(transition_iter!=NULL)
    {
        np_util_event_t noop_event = { .type = evt_noop, .user_data=NULL };
        //_np_event_runtime_add_event(context, args.current_run,  transition_iter->val, noop_event);        
        _np_event_runtime_start_with_event(context, transition_iter->val, noop_event);
        /* POSSIBLE ASYNC POINT
        snprintf(buf, 100, "urn:np:job:event:noop:%s", np_id_str(buf, &transition_iter->val));
        np_jobqueue_submit_event(context, 0, transition_iter->val, noop_event, buf);
        */

        sll_next(transition_iter);
    }
    sll_free(np_dhkey_t, tmp_to_transition);

    _np_memory_job_memory_management(context, args);

    return true;
}

np_key_t* _np_keycache_find_deprecated(np_state_t* context)
{
    log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_find_deprecated(){");

    np_key_t* return_key = NULL;
    np_key_t *iter = NULL;
    _LOCK_MODULE(np_keycache_t)
    {
        RB_FOREACH(iter, st_keycache_s, np_module(keycache)->__key_cache)
        {

            // our own key / identity never deprecates
            if (true == _np_dhkey_equal(&iter->dhkey, &context->my_node_key->dhkey) ||
                true == _np_dhkey_equal(&iter->dhkey, &context->my_identity->dhkey) )
            {
                continue;
            }

            double now = np_time_now();

            if ((now - NP_KEYCACHE_DEPRECATION_INTERVAL) > iter->last_update)
            {
                np_ref_obj(np_key_t, iter);
                return_key = iter;
                break;
            }
        }
    }
    return (return_key);
}

sll_return(np_key_ptr) _np_keycache_get_all(np_state_t* context)
{
    np_sll_t(np_key_ptr, ret) = sll_init(np_key_ptr, ret);
    np_key_t *iter = NULL;
    _LOCK_MODULE(np_keycache_t)
    {
        RB_FOREACH(iter, st_keycache_s, np_module(keycache)->__key_cache)
        {
            np_ref_obj(np_key_t, iter);
            sll_append(np_key_ptr, ret, iter);
        }
    }
    return (ret);
}

np_key_t* _np_keycache_remove(np_state_t* context, np_dhkey_t search_dhkey)
{
    log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_remove(np_dhkey_t search_dhkey){");
    np_key_t* rem_key = NULL;
    np_key_t search_key = { .dhkey = search_dhkey };

    _LOCK_MODULE(np_keycache_t)
    {
        rem_key = RB_FIND(st_keycache_s, np_module(keycache)->__key_cache, &search_key);
        if (NULL != rem_key) {
            RB_REMOVE(st_keycache_s, np_module(keycache)->__key_cache, rem_key);
            rem_key->is_in_keycache = false;

            np_unref_obj(np_key_t, rem_key, ref_keycache);
            np_module(keycache)->__last_udpate = np_time_now();
        }
    }
    return rem_key;
}

np_key_t* _np_keycache_add(np_state_t* context, np_key_t* subject_key)
{
    assert(subject_key != NULL);
    assert(_np_memory_rtti_check(subject_key, np_memory_types_np_key_t));

    log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_add(np_key_t* key){");
    _LOCK_MODULE(np_keycache_t)
    {
        RB_INSERT(st_keycache_s, np_module(keycache)->__key_cache, subject_key);
        // subject_key->last_update = np_time_now();
        subject_key->is_in_keycache = true;
        np_ref_obj(np_key_t, subject_key, ref_keycache);
        np_module(keycache)->__last_udpate = subject_key->last_update;
    }
    return subject_key;
}

/**
 * @brief Execute a event in a given keys context/lock
 * 
 * @param context The application Context to work in
 * @param dhkey The target key to lock
 * @param event  The event configuration
 */
void _np_keycache_execute_event(np_state_t* context, np_dhkey_t dhkey, np_util_event_t event)
{
    log_trace_msg(LOG_TRACE, "start: void _np_keycache_execute_event(...){");

    np_key_t* key = _np_keycache_find(context, dhkey);
    if (key != NULL)
    {
        if (event.type != evt_noop){
            log_info(LOG_KEYCACHE|LOG_EVENT, "key to handle event_type: %"PRIu8" key_type: %"PRIu32, event.type, key->type);
        }
        _np_key_handle_event(key, event);
        np_unref_obj(np_key_t, key, "_np_keycache_find");
    } else {
        if (NULL != event.user_data) {
            char buf[65]={0};
            _np_dhkey_str(&dhkey, buf);
            log_debug_msg(LOG_ERROR,
                "event not handled (eventtype: %"PRIu8", datatype: %"PRId16" keytype: %"PRId16" key: %s)",
                event.type, (int16_t) (event.user_data? np_memory_get_type(event.user_data):-1), (int16_t)(key ? key->type:-1), buf
            );
            log_info(LOG_EXPERIMENT,
                "event not handled (eventtype: %"PRIu8", datatype: %"PRId16" keytype: %"PRId16")",
                event.type, (int16_t) (event.user_data? np_memory_get_type(event.user_data):-1), (int16_t)(key ? key->type:-1)
            );
        }
        log_info(LOG_KEYCACHE|LOG_EVENT, "no key to handle event %"PRIu8, event.type );
    }
}

/** _np_keycache_find_closest_key_to:
 ** finds the closest node in the array of #hosts# to #key# and put that in min_key.
 */
np_key_t* _np_keycache_find_closest_key_to (np_state_t* context,  np_sll_t(np_key_ptr, list_of_keys), const np_dhkey_t* const key)
{
    np_dhkey_t  dif, minDif = { 0 };
    np_key_t *min_key = NULL;

    sll_iterator(np_key_ptr) iter = sll_first(list_of_keys);
    bool first_run = true;
    while (NULL != iter)
    {
        _np_dhkey_distance (&dif, key, &(iter->val->dhkey));
        // Set reference point at first iteration, then compare current iterations distance with shortest known distance
        int8_t cmp = _np_dhkey_cmp(&dif, &minDif);
        if (true == first_run || cmp <= 0)
        {
            min_key = iter->val;
            _np_dhkey_assign (&minDif, &dif);
        }
        first_run = false;
        sll_next(iter);		
    }

    if (sll_size(list_of_keys) == 0)
    {
        log_msg(LOG_KEY | LOG_WARNING, "minimum size for closest key calculation not met !");
    }
    return (min_key);
}

/** sort_hosts:
 ** Sorts #hosts# based on common prefix match and key distance from #np_key_t*
 */
void _np_keycache_sort_keys_cpm (np_sll_t(np_key_ptr, node_keys), const np_dhkey_t* key)
{
    np_dhkey_t dif1, dif2;

    uint16_t pmatch1 = 0;
    uint16_t pmatch2 = 0;

    if (sll_size(node_keys) < 2) return;

    np_key_t* tmp;
    sll_iterator(np_key_ptr) iter1 = sll_first(node_keys);
    sll_iterator(np_key_ptr) iter2;
    do
    {
        iter2 = sll_get_next(iter1);

        if (NULL == iter2) break;

        do
        {
            pmatch1 = _np_dhkey_index (key, &iter1->val->dhkey);
            pmatch2 = _np_dhkey_index (key, &iter2->val->dhkey);
            if (pmatch2 > pmatch1)
            {
                tmp = iter1->val;
                iter1->val = iter2->val;
                iter2->val = tmp;
            }
            else if (pmatch1 == pmatch2)
            {
                _np_dhkey_distance (&dif1, &iter1->val->dhkey, key);
                _np_dhkey_distance (&dif2, &iter2->val->dhkey, key);
                if (_np_dhkey_cmp (&dif2, &dif1) < 0)
                {
                    tmp = iter1->val;
                    iter1->val = iter2->val;
                    iter2->val = tmp;
                }
            }
        } while (NULL != (sll_next(iter2)) );
    } while (NULL != (sll_next(iter1)) );
}

/** sort_hosts_key:
 ** Sorts #hosts# based on their key distance from #np_key_t*
 */
void _np_keycache_sort_keys_kd (np_sll_t(np_key_ptr, list_of_keys), const np_dhkey_t* key)
{
    np_dhkey_t dif1, dif2;

    // entry check for empty list
    if (sll_size(list_of_keys)<2) return;

    sll_iterator(np_key_ptr) curr = sll_first(list_of_keys);
    // np_ctx_memory(curr->val);
    bool swap;
    do {
        curr = sll_first(list_of_keys);
        swap = false;
        
        while (NULL != curr) {
            // Maintain pointers.
            sll_iterator(np_key_ptr) next = sll_get_next(curr);

            // Cannot swap last element with its next.
            while (NULL != next)
            {
                // Swap if items in wrong order.
                _np_dhkey_distance(&dif1, &curr->val->dhkey, key);
                _np_dhkey_distance(&dif2, &next->val->dhkey, key);
                if (_np_dhkey_cmp(&dif2, &dif1) < 0)
                {
                    swap = true;
                    np_key_t* tmp = curr->val;
                    curr->val = next->val;
                    next->val = tmp;
                    // Notify loop to do one more pass.
                    break;
                }
                // continue with the loop
                sll_next(next);
            }
            sll_next(curr);

        }
    } while (swap);
}



