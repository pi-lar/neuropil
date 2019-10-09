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
#include "np_key.h"
#include "np_route.h"
#include "np_statistics.h"
#include "np_jobqueue.h"
#include "np_constants.h"

#include "core/np_comp_alias.h"
#include "core/np_comp_identity.h"
#include "core/np_comp_intent.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"

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
    IN_SETUP_NODE,
    IN_SETUP_ALIAS,
    IN_SETUP_WILDCARD,
    IN_SETUP_IDENTITY,
    IN_USE_IDENTITY,    // user supplied identities and private key nodes
    IN_USE_NODE,        // holds connection status / outbound transport encryption
    IN_USE_ALIAS,       // holds inbound decryption
    IN_USE_INTENT,      // intent storage
    IN_USE_MSGPROPERTY, // inbound and outbound message creation (payload encryption / routing decision / lookup / chunking / ...)
    IN_DESTROY,
    MAX_KEY_STATES
};

// parent_key hierarchy:
// my_identity (1) -> (n) my_node_key (1) -> (n) node (1) -> (0|1) alias 
// my_identity (1) -> (n) my_node_key (1) -> (n) mspgproperties (dht)
// my_identity (1) -> (n) mspgproperties (usr)
// my_node_key (1) -> (n) intents

void __np_key_to_trinity(np_key_t* key, struct __np_node_trinity *trinity) 
{
    sll_iterator(void_ptr) iter = sll_first(key->entities);

    while (iter != NULL) {

        if (_np_memory_rtti_check(iter->val, np_memory_types_np_node_t))     trinity->node    = iter->val;
        if (_np_memory_rtti_check(iter->val, np_memory_types_np_aaatoken_t)) trinity->token   = iter->val;
        if (_np_memory_rtti_check(iter->val, np_memory_types_np_network_t))  trinity->network = iter->val;

        sll_next(iter);
    }
}

np_network_t* _np_key_get_network(np_key_t* key) 
{
    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(key, &trinity);

    return trinity.network;
}

np_node_t* _np_key_get_node(np_key_t* key) 
{
    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(key, &trinity);

    return trinity.node;
}

np_aaatoken_t* _np_key_get_token(np_key_t* key) 
{
    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(key, &trinity);

    return trinity.token;
}


void __keystate_noop(np_util_statemachine_t* statemachine, const np_util_event_t event) {
    // empty by design
}

void __add_transitions_for(const np_key_t* my_key, enum np_key_type requested_type); 

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
        NP_UTIL_STATEMACHINE_STATE(states, UNUSED, "UNUSED", __keystate_noop, __keystate_noop, __keystate_noop ); // initial unused state

            NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_SETUP_WILDCARD , __np_wildcard_set, __is_wildcard_key    ); // handle internal wildcard key            
            NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_SETUP_ALIAS    , __np_alias_set   , __is_alias_handshake_token ); // handle internal received handsjake token to setup alias key
            NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_SETUP_NODE     , __np_node_set    , __is_node_handshake_token    ); // handle external handshake token (after alias key has been created)
            NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_SETUP_NODE     , __np_node_set    , __is_node_token              ); // handle node token (updates)
            NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_USE_IDENTITY   , __np_set_identity, __is_identity_aaatoken ); // create node or identity structures (private key is present)
            NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_USE_MSGPROPERTY, __np_set_property, __is_msgproperty    ); // create msgproperty 
            NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_USE_INTENT     , __np_set_intent  , __is_intent_token);     // message intent handling

        NP_UTIL_STATEMACHINE_STATE(states, IN_SETUP_ALIAS, "IN_SETUP_ALIAS", __keystate_noop, __np_create_session, __keystate_noop); // create node as well and "steal" network sructure

            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_ALIAS, IN_SETUP_ALIAS, __np_alias_decrypt    , __is_crypted_message); // decrypt transport encryption
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_ALIAS, IN_SETUP_ALIAS, __np_handle_np_message, __is_join_in_message); // join and leave message are allowed
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_ALIAS, IN_USE_ALIAS  , __np_node_upgrade     , __is_node_authn); // only here for state transition
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_ALIAS, IN_DESTROY    , __np_alias_destroy    , __is_alias_invalid); // node has left, invalidate node

        NP_UTIL_STATEMACHINE_STATE(states, IN_SETUP_NODE, "IN_SETUP_NODE", __keystate_noop, __np_create_client_network, __keystate_noop);

            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_NODE, IN_SETUP_NODE, __np_node_send_direct      , __is_handshake_message); // received remote handshake message
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_NODE, IN_SETUP_NODE, __np_node_send_encrypted   , __is_join_out_message); // received authn information (eventually through identity join)
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_NODE, IN_SETUP_NODE, __np_node_update_token     , __is_node_token); // received a full node token (join)
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_NODE, IN_USE_NODE  , __np_node_upgrade          , __is_node_authn); // received authn information (eventually through identity join)
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_NODE, IN_SETUP_NODE, __np_node_shutdown         , __is_shutdown_event); // node is told to shutdown (i.e. authn failed)
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_NODE, IN_DESTROY   , __np_node_destroy          , __is_node_invalid); // node is not used anymore
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_NODE, IN_SETUP_NODE, __np_node_handle_completion, NULL); // check node status and send out handshake / join messages

        NP_UTIL_STATEMACHINE_STATE(states, IN_SETUP_IDENTITY, "IN_SETUP_IDENTITY", __keystate_noop, __keystate_noop, __keystate_noop);

            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_IDENTITY, IN_USE_IDENTITY, __np_identity_update , __is_identity_authn); // identity has been authenticated (also authn partner node, there could be more than one token)
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_IDENTITY, IN_DESTROY     , __np_identity_destroy, __is_identity_invalid); // identity hasn't received an authn 

        NP_UTIL_STATEMACHINE_STATE(states, IN_SETUP_WILDCARD, "IN_SETUP_WILDCARD", __keystate_noop, __np_create_client_network, __keystate_noop);

            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_WILDCARD, IN_SETUP_WILDCARD, __np_node_send_direct      , __is_handshake_message); // received handshake message, send it out without encryption
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_WILDCARD, IN_DESTROY       , __np_wildcard_destroy      , __is_node_handshake_token ); // received a handshake token, finalize wildcard
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_WILDCARD, IN_DESTROY       , __np_wildcard_destroy      , __is_wildcard_invalid); // wildcards are only valid for a minute
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_SETUP_WILDCARD, IN_SETUP_WILDCARD, __np_node_handle_completion, NULL); // check node status and send out handshake / join messages

        NP_UTIL_STATEMACHINE_STATE(states, IN_USE_ALIAS, "IN_USE_ALIAS", __keystate_noop, __keystate_noop, __keystate_noop);
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_ALIAS, IN_USE_ALIAS, __np_alias_decrypt    , __is_crypted_message); // decrypt transport encryption
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_ALIAS, IN_USE_ALIAS, __np_handle_usr_msg   , __is_usr_in_message); // pass on to the specific message intent
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_ALIAS, IN_USE_ALIAS, __np_handle_np_message, __is_dht_message); // handle dht messages (ping, piggy, leave, update, ack)
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_ALIAS, IN_USE_ALIAS, __np_handle_np_message, __is_discovery_message); // handle discovery messages (sender list, dicover sender, ...)
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_ALIAS, IN_USE_ALIAS, __np_handle_np_forward, __is_forward_message); // handle forwarding of all other messages , but fill ara routing table
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_ALIAS, IN_DESTROY  , __np_alias_destroy    , __is_alias_invalid); // node has left, invalidate node
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_ALIAS, IN_USE_ALIAS, __np_alias_update      , NULL); // cleanup message part cache for incoming messages

        NP_UTIL_STATEMACHINE_STATE(states, IN_USE_NODE, "IN_USE_NODE", __keystate_noop, __np_node_add_to_leafset, __np_node_destroy);

            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_NODE, IN_USE_NODE, __np_node_send_encrypted     , __is_np_message); // received authn information (eventually through identity join)
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_NODE, IN_USE_NODE, __np_node_handle_response    , __is_response_event); // user changed mx_properties
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_NODE, IN_DESTROY , __np_node_remove_from_routing, __is_node_invalid); // check last ping received value, or node invalidated by leave message
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_NODE, IN_USE_NODE , __np_node_shutdown          , __is_shutdown_event); // node is not used anymore
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_NODE, IN_USE_NODE, __np_node_update             , NULL); // i.e. send out ping / piggy messages

        NP_UTIL_STATEMACHINE_STATE(states, IN_USE_IDENTITY, "IN_USE_IDENTITY", __keystate_noop, __np_create_identity_network, __np_identity_destroy); // create local network in case of node private key

            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_IDENTITY, IN_USE_IDENTITY, __np_extract_handshake      , __is_unencrypted_np_message); // check for local identity validity
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_IDENTITY, IN_USE_IDENTITY, __np_identity_handle_authn  , __is_authn_request); // check for local identity validity
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_IDENTITY, IN_USE_IDENTITY, __np_identity_handle_authz  , __is_authz_request); // check for local identity validity
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_IDENTITY, IN_USE_IDENTITY, __np_identity_handle_account, __is_account_request); // check for local identity validity
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_IDENTITY, IN_DESTROY     , __np_identity_shutdown      , __is_shutdown_event); // node is not used anymore
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_IDENTITY, IN_DESTROY     , __np_identity_shutdown      , __is_identity_invalid); // check for local identity validity

        NP_UTIL_STATEMACHINE_STATE(states, IN_USE_INTENT, "IN_USE_INTENT", __keystate_noop, __keystate_noop, __keystate_noop);

            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_INTENT, IN_USE_INTENT, __np_intent_receiver_update, __is_receiver_intent_token); // add intent token
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_INTENT, IN_USE_INTENT, __np_intent_sender_update  , __is_sender_intent_token); // add intent token
            // NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_INTENT, IN_USE_INTENT, __np_intent_update         , __is_intent_authz); // add authorization for intent token
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_INTENT, IN_DESTROY   , __np_intent_destroy        , __is_intent_invalid); // no updates received for xxx minutes?
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_INTENT, IN_USE_INTENT, __np_intent_check          ,  NULL); // send out intents if dht distance is not mmatching anymore

        NP_UTIL_STATEMACHINE_STATE(states, IN_USE_MSGPROPERTY, "IN_USE_MSGPROPERTY", __keystate_noop, __keystate_noop, __keystate_noop);

            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY, __np_response_handler_set   , __is_response_event); // user changed mx_properties
            // NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY, __np_property_out_usermsg   , __is_usr_message); // send out intents
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY, __np_property_handle_in_msg , __is_external_message); // call usr callback function
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY, __np_property_handle_out_msg, __is_internal_message); // call usr callback function
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY, __np_property_handle_intent , __is_intent_authz); // received authn information (eventually through identity join)
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY, __np_property_update        , __is_msgproperty); // user changed mx_properties
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY, __np_property_check         ,  NULL); // send out intents
            NP_UTIL_STATEMACHINE_TRANSITION(states, IN_USE_MSGPROPERTY, IN_DESTROY        , __keystate_noop             , __is_key_invalid);
   
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

    keyident = _np_key_as_str(to_destroy);

    log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key and associated data structures: %s", keyident);
    log_debug_msg(LOG_KEY | LOG_DEBUG, "refcount of key %s at destroy: %"PRIu32, keyident, np_memory_get_refcount(to_destroy));

    _np_keycache_remove(context, to_destroy->dhkey);
    np_unref_obj(np_key_t, to_destroy, "_np_keycache_finalize");

    /*
        if (to_destroy->parent_key != NULL) {
            np_unref_obj(np_key_t, to_destroy->parent_key, ref_key_parent);
            to_destroy->parent_key = NULL;
        }
    */
    log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key and associated data structures done.");
}

void _np_key_t_new(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* key)
{
    log_trace_msg(LOG_TRACE | LOG_KEY, "start: void _np_key_t_new(void* key){");

    np_key_t* new_key = (np_key_t*) key;

    // new_key->type = np_key_type_unknown;
    // new_key->is_in_keycache = false;

    __np_key_populate_states(new_key);

    new_key->created_at  = np_time_now();
    new_key->last_update = np_time_now();

    new_key->dhkey_str = NULL;
    
    sll_init(void_ptr, new_key->entities); // link to components attached to this key id

    new_key->parent_key = NULL;

    char mutex_str[64];      
    snprintf(mutex_str, 63, "urn:np:key:%s", "access");              
    _np_threads_mutex_init(context, &new_key->key_lock, "key_lock");
}

void _np_key_t_del(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* key)
{
    log_trace_msg(LOG_TRACE | LOG_KEY, "start: void _np_key_t_del(void* key){");
    np_key_t* old_key = (np_key_t*) key;

    sll_free(void_ptr, old_key->entities);

    _np_threads_mutex_destroy(context, &old_key->key_lock);

    // delete string presentation of key
    if (NULL != old_key->dhkey_str)
    {
        free (old_key->dhkey_str);
        old_key->dhkey_str = NULL;
    }
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

        target = _np_keycache_find_by_details(context, targetDhkey, false, np_status_Connected, true, false, false, true);

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

void _np_key_handle_event(np_key_t* key, np_util_event_t event, bool force)
{
    assert (key!=NULL);
    np_ctx_memory(key);

    // TODO: add per obj event queue
    // log_debug_msg(LOG_DEBUG, "sm b: %p %d %s", key, key->type, key->sm._state_table[key->sm._current_state]->_state_name);
    if (force) 
    {
        _LOCK_ACCESS(&key->key_lock) 
        {   // push down all event from queue and execute this event
            np_util_statemachine_invoke_auto_transition(&key->sm, event);
        }
    }
    else
    {
        if (0 == _np_threads_mutex_trylock(context, &key->key_lock, FUNC))
        {
            np_util_statemachine_invoke_auto_transition(&key->sm, event);
            _np_threads_mutex_unlock(context, &key->key_lock);
        }
        else
        {   // check queue and append OR if queue is empty execute directly
            np_jobqueue_submit_event(context, NP_SLEEP_MIN, key->dhkey, event, FUNC);
        }
    }       
    // log_debug_msg(LOG_DEBUG, "sm a: %p %d %s", key, key->type, key->sm._state_table[key->sm._current_state]->_state_name);
}
