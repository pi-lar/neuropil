//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include "neuropil.h"
#include "np_legacy.h"

#include "event/ev.h"
#include "sodium.h"

#include "np_log.h"
#include "np_tree.h"
#include "np_types.h"
#include "np_treeval.h"
#include "np_threads.h"
#include "np_keycache.h"
#include "np_aaatoken.h"
#include "np_token_factory.h"
#include "np_network.h"
#include "np_node.h"
#include "core/np_comp_msgproperty.h"
#include "np_key.h"
#include "np_route.h"
#include "np_statistics.h"
#include "np_jobqueue.h"
#include "np_constants.h"

#include "core/np_comp_msgproperty.h"

#include "util/np_event.h"
#include "util/np_statemachine.h"


_NP_GENERATE_MEMORY_IMPLEMENTATION(np_key_t);

NP_SLL_GENERATE_IMPLEMENTATION(np_key_ptr);
NP_PLL_GENERATE_IMPLEMENTATION(np_key_ptr);

int8_t _np_key_cmp(np_key_t* const k1, np_key_t* const k2)
{
    if (k1 == NULL) return -1;
    if (k2 == NULL) return  1;
 
    return _np_dhkey_cmp(&k1->dhkey,&k2->dhkey);
}

int8_t _np_key_cmp_inv(np_key_t* const k1, np_key_t* const k2)
{	
    return -1 * _np_key_cmp(k1, k2);
}

// STATE MACHINE FUNCTIONS AND DEFINITIONS
enum NP_KEY_STATES {
    UNUSED = 0,
    IN_SETUP,
    IN_USE_IDENTITY,
    IN_USE_WILDCARD,
    IN_USE_NODE,
    IN_USE_INTENT,
    IN_USE_MSGPROPERTY,
    IN_DESTROY,
    MAX_KEY_STATES
};

void __keystate_noop(np_util_statemachine_t* statemachine, const np_util_event_t event) {
    // empty by design
}

void __add_transitions_for(const np_key_t* my_key, enum np_key_type requested_type); 


#include "core/np_comp_identity.c"
#include "core/np_comp_node.c"

// IN_USE_... -> IN_DESTROY transition conditions / actions
bool __is_key_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_decl(event.context);
    bool ret = false;

    NP_CAST(statemachine->_user_data, np_key_t, my_key);
    
    if (!ret) ret  = (my_key->last_update < (_np_time_now(context)+3600) );
    if ( ret) ret &= (my_key->type == np_key_type_unknown);
    if ( ret) ret &= (sll_size(my_key->entities) == 0);

    return ret;
}

// IN_DESTROY entry action
void __np_key_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    NP_CAST(statemachine->_user_data, np_key_t, my_key);
    _np_key_destroy(my_key);
}

void __add_transitions_for(const np_key_t* my_key, enum np_key_type requested_type) 
{
    assert( FLAG_CMP(my_key->type, requested_type) != np_key_type_unknown );
    // potentially add transitions for state behaviour, unused yet
    switch (requested_type) {
        case np_key_type_ident:
        case np_key_type_subject:
        case np_key_type_wildcard:
        case np_key_type_alias:
        default:
            break;
    }
}


void __np_key_populate_states(np_key_t* key)
{
    np_ctx_memory(key);

    static bool population_done = false;
    static np_util_statemachine_state_t* states[MAX_KEY_STATES];

    if (!population_done)
    {
        NP_UTIL_STATEMACHINE_STATE(states, UNUSED, "UNUSED", __keystate_noop, __keystate_noop, __keystate_noop );

            NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_SETUP, __np_node_set, __is_node_handshake_token );
            NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_SETUP, __np_node_set, __is_node_token           );

            NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_USE_IDENTITY, __np_set_identity, __is_identity_aaatoken);

            NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_USE_MSGPROPERTY, __np_set_property, __is_msgproperty);
            // NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_USE_WILDCARD, __np_set_wildcard, __is_wildcard_node);
            // NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_USE_INTENT, __np_set_intent, __is_intent_aaatoken);

        NP_UTIL_STATEMACHINE_STATE(states, IN_SETUP, "IN_SETUP", __keystate_noop, __keystate_noop, __keystate_noop);
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP, IN_SETUP, __np_node_handle_completion, NULL);
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP, IN_USE_NODE, __np_node_update, __is_node_complete);
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP, IN_DESTROY, __np_node_handle_leave, __is_node_join_nack);

        NP_UTIL_STATEMACHINE_STATE(states, IN_USE_IDENTITY, "IN_USE_IDENTITY", __keystate_noop, __keystate_noop, __keystate_noop);
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_IDENTITY, IN_USE_IDENTITY, __np_identity_update, NULL);
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_IDENTITY, IN_DESTROY,      __np_identity_destroy, __is_identity_invalid);

        NP_UTIL_STATEMACHINE_STATE(states, IN_USE_WILDCARD, "IN_USE_WILDCARD", __keystate_noop, __keystate_noop, __keystate_noop);
            // NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_WILDCARD, IN_DESTROY, __np_add_node, __is_node_aaatoken);

        NP_UTIL_STATEMACHINE_STATE(states, IN_USE_NODE, "IN_USE_NODE", __keystate_noop, __keystate_noop, __keystate_noop);
            // NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_NODE, IN_DESTROY, __np_node_handle_leave, __is_node_leaving);
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_NODE, IN_DESTROY, __np_node_destroy, __is_node_invalid);

        NP_UTIL_STATEMACHINE_STATE(states, IN_USE_INTENT, "IN_USE_INTENT", __keystate_noop, __keystate_noop, __keystate_noop);
            // NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_INTENT, IN_DESTROY, __np_add_node, __is_node_aaatoken);

        NP_UTIL_STATEMACHINE_STATE(states, IN_USE_MSGPROPERTY, "IN_USE_MSGPROPERTY", __keystate_noop, __keystate_noop, __keystate_noop);
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY, __np_property_update, __is_msgproperty);
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY, __np_property_handle_msg,  __is_external_message);
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY, __np_property_check,  NULL);
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_DESTROY        , __keystate_noop , __is_key_invalid);
   
        NP_UTIL_STATEMACHINE_STATE(states, IN_DESTROY, "IN_DESTROY", __keystate_noop, __np_key_destroy, __keystate_noop);
            // NP_UTIL_STATEMACHINE_TRANSITION(states, IN_DESTROY, UNUSED, __np_destroy, NULL);

        population_done = true;
    }

    NP_UTIL_STATEMACHINE_INIT(key->sm, context, UNUSED, states, key);
}

char* _np_key_as_str(np_key_t* key)
{
    assert(key != NULL);
    np_ctx_memory(key);

    if (NULL == key->dhkey_str){
        key->dhkey_str = (char*) malloc(65);
        CHECK_MALLOC(key->dhkey_str);
    }
    _np_dhkey_str(&key->dhkey, key->dhkey_str);
    log_debug_msg(LOG_KEY | LOG_DEBUG, "dhkey_str = %lu (%s)", strlen(key->dhkey_str), key->dhkey_str);

    return (key->dhkey_str);
}

void np_key_ref_list(np_sll_t(np_key_ptr, sll_list), const char* reason, const char* reason_desc)
{
    np_state_t* context = NULL; 
    sll_iterator(np_key_ptr) iter = sll_first(sll_list);	
    while (NULL != iter)
    {
        if (context == NULL && iter->val != NULL) {
            context = np_ctx_by_memory(iter->val);
        }
        np_ref_obj(np_key_t, (iter->val), reason, reason_desc);
        sll_next(iter);
    }
}

void np_key_unref_list(np_sll_t(np_key_ptr, sll_list) , const char* reason)
{
    np_state_t* context = NULL;
    sll_iterator(np_key_ptr) iter = sll_first(sll_list);
    while (NULL != iter)
    {
        
        if (context == NULL && iter->val != NULL) {
            context = np_ctx_by_memory(iter->val);
        }
        np_unref_obj(np_key_t, (iter->val), reason);
        sll_next(iter);
    }
}

/**
 * Destroys a key with all resources
 */
void _np_key_destroy(np_key_t* to_destroy) 
{
    np_ctx_memory(to_destroy);
    char* keyident = NULL;

    bool destroy = false;

    if(!to_destroy->in_destroy)
    {
        to_destroy->in_destroy = true;
        destroy = true;
    }

    if(destroy) {        
        keyident = _np_key_as_str(to_destroy);

        log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key and associated data structures: %s", keyident);

        log_debug_msg(LOG_KEY | LOG_DEBUG, "refcount of key %s at destroy: %"PRIu32, keyident, np_memory_get_refcount(to_destroy));

        np_key_t* deleted;
        np_key_t* added;

        _np_route_leafset_update(to_destroy, false, &deleted, &added);
        _np_route_update(to_destroy, false, &deleted, &added);
        _np_set_latency(to_destroy->dhkey, 0);
        _np_set_success_avg(to_destroy->dhkey, 0);
        _np_network_disable(to_destroy->network);

        // if(to_destroy->is_in_keycache) {
        //     _np_keycache_remove(context, to_destroy->dhkey);
        // }

        // delete old receive tokens
        if (NULL != to_destroy->recv_tokens)
        {
            pll_iterator(np_aaatoken_ptr) iter = pll_first(to_destroy->recv_tokens);
            while (NULL != iter)
            {
                np_unref_obj(np_aaatoken_t, iter->val, "recv_tokens");
                pll_next(iter);
            }
            pll_free(np_aaatoken_ptr, to_destroy->recv_tokens);
            to_destroy->recv_tokens = NULL;
        }

        // delete send tokens
        if (NULL != to_destroy->send_tokens)
        {
            pll_iterator(np_aaatoken_ptr) iter = pll_first(to_destroy->send_tokens);
            while (NULL != iter)
            {
                np_unref_obj(np_aaatoken_t, iter->val, "send_tokens");
                pll_next(iter);
            }
            pll_free(np_aaatoken_ptr, to_destroy->send_tokens);
            to_destroy->send_tokens = NULL;
        }
    
        np_sll_t(np_key_ptr, aliasse) = _np_keycache_find_aliase(to_destroy);
        sll_iterator(np_key_ptr) iter = sll_first(aliasse);

        while (iter != NULL) {
            log_debug_msg(LOG_KEY | LOG_DEBUG, "destroy of key %s as identified as alias for %s", _np_key_as_str(iter->val), keyident);

            np_unref_obj(np_key_t, iter->val->parent_key, ref_key_parent);
            iter->val->parent_key = NULL;
            np_unref_obj(np_key_t, iter->val, "_np_keycache_find_aliase");
            sll_next(iter);
        }
        sll_free(np_key_ptr, aliasse);

        if (to_destroy->parent_key != NULL) {
            np_unref_obj(np_key_t, to_destroy->parent_key, ref_key_parent);
            to_destroy->parent_key = NULL;
        }

        if(to_destroy->node) np_unref_obj(np_node_t, to_destroy->node, ref_key_node);
        if(to_destroy->network) {
            _np_network_set_key(to_destroy->network, NULL);
            np_unref_obj(np_network_t,  to_destroy->network,    ref_key_network);
        }

        log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key and associated data structures done.");            
    }
}

void _np_key_t_new(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* key)
{
    log_trace_msg(LOG_TRACE | LOG_KEY, "start: void _np_key_t_new(void* key){");

    np_key_t* new_key = (np_key_t*) key;

    // new_key->type = np_key_type_unknown;
    // new_key->in_destroy = false;
    // new_key->is_in_keycache = false;

    __np_key_populate_states(new_key);

    // _np_threads_mutex_init(context, &new_key->key_lock, "keylock");

    new_key->created_at  = np_time_now();
    new_key->last_update = np_time_now();

    new_key->dhkey_str = NULL;
    
    sll_init(void_ptr, new_key->entities); // link to components attached to this key id

    new_key->node = NULL;		  // link to a neuropil node if this key represents a node
    new_key->network = NULL;      // link to a neuropil node if this key represents a node
    new_key->aaa_token = NULL;

    // used internally only
    // new_key->recv_property = NULL;
    // new_key->send_property = NULL;

    new_key->local_mx_tokens = NULL; // link to runtime interest data on which this node is interested in

    new_key->send_tokens = NULL; // link to runtime interest data on which this node is interested in
    new_key->recv_tokens = NULL; // link to runtime interest data on which this node is interested in

    new_key->parent_key = NULL;
    log_msg(LOG_DEBUG, "Created new key");

}

void _np_key_t_del(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* key)
{
    log_trace_msg(LOG_TRACE | LOG_KEY, "start: void _np_key_t_del(void* key){");
    np_key_t* old_key = (np_key_t*) key;

    _np_key_destroy(old_key);

    // delete string presentation of key
    if (NULL != old_key->dhkey_str)
    {
        free (old_key->dhkey_str);
        old_key->dhkey_str = NULL;
    }

    // unref and delete of other object pointers has to be done outside of this function
    // otherwise double locking the memory pool will lead to a deadlock
    // np_unref_obj(np_msgproperty_t, 	old_key->recv_property, ref_key_recv_property);
    // np_unref_obj(np_msgproperty_t, 	old_key->send_property, ref_key_send_property);
    np_unref_obj(np_aaatoken_t,		old_key->aaa_token, ref_key_aaa_token);

    if (old_key->local_mx_tokens != NULL) {
        pll_iterator(np_aaatoken_ptr) iter = pll_first(old_key->local_mx_tokens);
        while(iter != NULL){
            np_unref_obj(np_aaatoken_t, iter->val,ref_aaatoken_local_mx_tokens);
            pll_next(iter);
        }
        pll_free(np_aaatoken_ptr, old_key->local_mx_tokens);
    }

    // _np_threads_mutex_destroy(context, &old_key->key_lock);
}

/**
* Gets a np_key_t or a NULL pointer for the given hash value.
* Generates warnings and aborts the process if a misschief configuration is found.
* @param targetDhkey hash value of a node
* @return
*/
np_key_t* _np_key_get_by_key_hash(np_state_t* context, char* targetDhkey)
{
    log_trace_msg(LOG_TRACE, "start: np_key_t* _np_key_get_by_key_hash(char* targetDhkey){");
    np_key_t* target = NULL;

    if (NULL != targetDhkey) {

        target = _np_keycache_find_by_details(context, targetDhkey, false, np_handshake_status_Connected, true, false, false, true);

        if (NULL == target) {
            log_msg(LOG_WARN,
                "could not find the specific target %s for message. broadcasting msg", targetDhkey);
        }
        else {
            log_debug_msg(LOG_DEBUG, "could find the specific target %s for message.", targetDhkey);
        }

        if (NULL != target && strcmp(_np_key_as_str(target), targetDhkey) != 0) {
            log_msg(LOG_ERROR,
                "Found target key (%s) does not match requested target key (%s)! Aborting",
                _np_key_as_str(target), targetDhkey);
            abort();
        }
    }
    return target;
}

void _np_key_set_recv_property(np_key_t* self, np_msgproperty_t* prop) {
    np_ctx_memory(self);
    // np_ref_switch(np_msgproperty_t, self->recv_property, ref_key_recv_property, prop);

}

void _np_key_set_send_property(np_key_t* self, np_msgproperty_t* prop) {
    np_ctx_memory(self);
    // np_ref_switch(np_msgproperty_t, self->send_property, ref_key_send_property, prop);
}

void _np_key_set_network(np_key_t* self, np_network_t* ng) {
    np_ctx_memory(self);
    np_ref_switch(np_network_t, self->network, ref_key_network, ng);
}
