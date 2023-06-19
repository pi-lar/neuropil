//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project
#include "np_key.h"

#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "event/ev.h"
#include "sodium.h"

#include "neuropil.h"
#include "neuropil_log.h"

#include "core/np_comp_alias.h"
#include "core/np_comp_identity.h"
#include "core/np_comp_intent.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_constants.h"
#include "np_jobqueue.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_route.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_types.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_key_t);

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(void_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(void_ptr);

int8_t _np_key_cmp(np_key_t *const k1, np_key_t *const k2) {
  if (k1 == NULL) return -1;
  if (k2 == NULL) return 1;

  return _np_dhkey_cmp(&k1->dhkey, &k2->dhkey);
}

int8_t _np_key_cmp_inv(np_key_t *const k1, np_key_t *const k2) {
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
  IN_USE_MSGPROPERTY, // inbound and outbound message creation (payload
                      // encryption / routing decision / lookup / chunking /
                      // ...)
  ON_HOLD_MSGPROPERTY, // disabled data channel
  IN_DESTROY,
  MAX_KEY_STATES
};

// parent_key hierarchy:
// my_identity (1) -> (n) my_node_key (1) -> (n) node (1) -> (0|1) alias
// my_identity (1) -> (n) my_node_key (1) -> (n) mspgproperties (dht)
// my_identity (1) -> (n) mspgproperties (usr)
// my_node_key (1) -> (n) intents

void __np_key_to_trinity(np_key_t *key, struct __np_node_trinity *trinity) {
  ASSERT(key->entity_array[0] == NULL ||
             _np_memory_rtti_check(key->entity_array[0],
                                   np_memory_types_np_aaatoken_t),
         "entity at 0 should be a token");
  if (_np_memory_rtti_check(key->entity_array[1],
                            np_memory_types_np_aaatoken_t))
    trinity->token = key->entity_array[1];
  if (_np_memory_rtti_check(key->entity_array[2], np_memory_types_np_node_t))
    trinity->node = key->entity_array[2];
  if (_np_memory_rtti_check(key->entity_array[3], np_memory_types_np_network_t))
    trinity->network = key->entity_array[3];
}

np_network_t *_np_key_get_network(np_key_t *key) {
  return key->entity_array[3];
}

np_node_t *_np_key_get_node(np_key_t *key) { return key->entity_array[2]; }

np_aaatoken_t *_np_key_get_token(np_key_t *key) { return key->entity_array[1]; }

void __keystate_noop(np_util_statemachine_t *statemachine,
                     const np_util_event_t   event) {
  // empty by design
}

bool __is_noop_event(np_util_statemachine_t *statemachine,
                     const np_util_event_t   event) {
  return FLAG_CMP(event.type, evt_noop);
}

void __add_transitions_for(const np_key_t  *my_key,
                           enum np_key_type requested_type);

// IN_USE_... -> IN_DESTROY transition conditions / actions
bool __is_key_invalid(np_util_statemachine_t *statemachine,
                      const np_util_event_t   event) {
  np_ctx_decl(statemachine->_context);
  bool ret = false;

  NP_CAST(statemachine->_user_data, np_key_t, my_key);

  if (!ret) ret = (my_key->last_update < (_np_time_now(context) + 3600));
  if (ret) ret &= FLAG_CMP(my_key->type, np_key_type_unknown);
  // if ( ret) ret &= (sll_size(my_key->entities) == 0);

  return ret;
}

// IN_DESTROY entry action
void __np_key_destroy(np_util_statemachine_t *statemachine,
                      const np_util_event_t   event) {
  np_ctx_decl(statemachine->_context);
  NP_CAST(statemachine->_user_data, np_key_t, my_key);
  _np_key_destroy(my_key);
}

void __add_transitions_for(const np_key_t  *my_key,
                           enum np_key_type requested_type) {
  assert(FLAG_CMP(my_key->type, requested_type) != np_key_type_unknown);
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

void __np_key_populate_states(np_key_t *key) {
  np_ctx_memory(key);

  static bool                          population_done = false;
  static np_util_statemachine_state_t *states[MAX_KEY_STATES];

  if (!population_done) {

    // clang-format off

    // initial unused state
    NP_UTIL_STATEMACHINE_STATE(
        states, UNUSED, "UNUSED",
        __keystate_noop,__keystate_noop, __keystate_noop); 


    // handle internal wildcard key
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, UNUSED, IN_SETUP_WILDCARD,
        __np_wildcard_set, __is_wildcard_key); 
    // handle internal node info (piggy)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, UNUSED, IN_SETUP_NODE,
        __np_node_set_node, __is_node_info); 
    // handle internal received handshake token to setup alias key 
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, UNUSED, IN_SETUP_ALIAS,
        __np_alias_set, __is_alias_handshake_token); 
    // handle external udp handshake network connection info
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, UNUSED, UNUSED,
        __np_alias_set_node, __is_alias_node_info); 
    // handle external handshake token (after alias key has been created)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, UNUSED, IN_SETUP_NODE,
        __np_node_set, __is_node_handshake_token); 
    // handle node token (updates)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, UNUSED, IN_SETUP_NODE,
        __np_node_set, __is_node_token); 
    // create node or identity structures (private key is present)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, UNUSED, IN_USE_IDENTITY,
        __np_set_identity, __is_identity_aaatoken); 
    // create msgproperty
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, UNUSED, IN_USE_MSGPROPERTY,
        __np_set_property, __is_msgproperty);
    // unused node, destroy it
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, UNUSED, IN_DESTROY,
        __np_alias_set_node_destroy, __is_unused);


    // create node as well and "steal" network structure
    NP_UTIL_STATEMACHINE_STATE(
        states, IN_SETUP_ALIAS, "IN_SETUP_ALIAS",
        __keystate_noop, __np_create_session, __keystate_noop); 
    // decrypt transport encryption
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_ALIAS, IN_SETUP_ALIAS,
        __np_alias_decrypt, __is_crypted_message);
    // join and leave message are allowed
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_ALIAS, IN_SETUP_ALIAS,
        __np_handle_np_message, __is_join_in_message);
    // only here for state transition
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_ALIAS, IN_SETUP_ALIAS,
        __np_node_update_token, __is_node_token); 
    // only here for state transition
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_ALIAS, IN_USE_ALIAS,
        __np_node_upgrade, __is_node_authn); 
    // node has left, invalidate node
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_ALIAS, IN_DESTROY,
        __np_alias_destroy, __is_alias_invalid); 


    NP_UTIL_STATEMACHINE_STATE(
        states, IN_SETUP_NODE, "IN_SETUP_NODE",
        __keystate_noop, __np_create_client_network, __keystate_noop);
    // send handshake message to remote side
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_NODE, IN_SETUP_NODE,
        __np_node_send_direct, __is_handshake_message); 
    // received authn information (eventually through identity join)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_NODE, IN_SETUP_NODE,
        __np_node_send_encrypted, __is_join_out_message); 
     // received authn information (eventually through identity join)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_NODE, IN_SETUP_NODE,
        __np_node_discard_message, __is_invalid_message);
    // received a full node token (join)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_NODE, IN_SETUP_NODE,
        __np_node_update_token, __is_node_token); 
    // received authn information (eventually through identity join)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_NODE, IN_USE_NODE,
        __np_node_identity_upgrade, __is_node_identity_authn); 
    // received authn information (eventually through identity join)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_NODE, IN_USE_NODE,
        __np_node_upgrade, __is_node_authn); 
    // node is told to shutdown (i.e. authn failed)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_NODE, IN_DESTROY,
        __np_node_destroy, __is_shutdown_event); 
    // node is not used anymore
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_NODE, IN_DESTROY, 
        __np_node_destroy, __is_node_invalid); 
    // check node status and send out handshake / join messages
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_NODE, IN_SETUP_NODE,
        __np_node_handle_completion, NULL); 


    NP_UTIL_STATEMACHINE_STATE(
        states, IN_SETUP_IDENTITY, "IN_SETUP_IDENTITY",
        __keystate_noop, __keystate_noop, __keystate_noop);
    // identity has been authenticated (also authn partner node, there could be more than one token)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_IDENTITY, IN_USE_IDENTITY,
        __np_identity_update, __is_identity_authn); 
    // identity hasn't received an authn
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_IDENTITY, IN_DESTROY,
        __np_identity_destroy, __is_identity_invalid); 


    NP_UTIL_STATEMACHINE_STATE(
        states, IN_SETUP_WILDCARD, "IN_SETUP_WILDCARD",
        __keystate_noop, __np_create_client_network, __keystate_noop);
    // received handshake message, send it out without encryption
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_WILDCARD, IN_SETUP_WILDCARD,
        __np_node_send_direct, __is_handshake_message); 
    // received a handshake token, finalize wildcard
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_WILDCARD, IN_DESTROY,
        __np_wildcard_destroy, __is_node_handshake_token); 
    // wildcards are only valid for a minute
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_WILDCARD, IN_DESTROY,
        __np_wildcard_destroy, __is_wildcard_invalid); 
    // check node status and send out handshake / join messages
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_SETUP_WILDCARD, IN_SETUP_WILDCARD,
        __np_node_handle_completion, NULL); 


    NP_UTIL_STATEMACHINE_STATE(
        states, IN_USE_ALIAS, "IN_USE_ALIAS",
        __keystate_noop, __keystate_noop, __keystate_noop);
    // decrypt transport encryption
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_ALIAS, IN_USE_ALIAS,
        __np_alias_decrypt, __is_crypted_message); 
    // pass on to the specific message intent
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_ALIAS, IN_USE_ALIAS,
        __np_handle_usr_msg, __is_usr_in_message);
    // handle dht messages (ping, piggy, leave, update, ack)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_ALIAS, IN_USE_ALIAS,
        __np_handle_np_message, __is_dht_message); 
    // handle pheromone messages
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_ALIAS, IN_USE_ALIAS,
        __np_handle_pheromone, __is_pheromone_message); 
    // handle discovery messages (sender list, discover sender, ...)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_ALIAS, IN_USE_ALIAS,
        __np_handle_np_discovery, __is_discovery_message); 
    // handle forwarding of all other messages , but fill ara routing table
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_ALIAS, IN_USE_ALIAS,
        __np_handle_np_forward, __is_forward_message); 
    // node has left, invalidate node
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_ALIAS, IN_DESTROY,
        __np_alias_destroy, __is_alias_invalid); 
    // node is not used anymore
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_ALIAS, IN_USE_ALIAS,
        __np_alias_shutdown, __is_shutdown_event);
    // dupplicate authn event?
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_ALIAS, IN_USE_ALIAS,
        NULL, __is_node_authn);
    // cleanup message part cache for incoming messages
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_ALIAS, IN_USE_ALIAS,
        __np_alias_update, NULL); 


    // a peer node 
    NP_UTIL_STATEMACHINE_STATE(
        states, IN_USE_NODE, "IN_USE_NODE",
        __keystate_noop, __np_node_add_to_leafset, __np_node_destroy);
    // received authn information (eventually through identity join)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_NODE, IN_USE_NODE,
        __np_node_split_message, __is_np_message); 
    // received authn information (eventually through identity join)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_NODE, IN_USE_NODE,
        __np_node_send_encrypted, __is_np_messagepart); 
    // user changed mx_properties
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_NODE,IN_USE_NODE,
        __np_node_handle_response, __is_response_event); 
    // node invalidated by leave message or own shutdown event
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_NODE, IN_USE_NODE,
        __np_node_send_shutdown, __is_shutdown_event); 
    // check last ping received value, or node not in leafset/routing table
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_NODE, IN_USE_NODE,
        __np_node_send_shutdown_event, __has_to_leave); 
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_NODE, IN_DESTROY,
        __np_node_send_shutdown, __is_node_invalid); 
    // i.e. send out ping / piggy messages
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_NODE, IN_USE_NODE,
        __np_node_update, NULL); 


    // create local network in case of node private key    
    NP_UTIL_STATEMACHINE_STATE(
        states, IN_USE_IDENTITY, "IN_USE_IDENTITY",
        __keystate_noop, __np_create_identity_network, __np_identity_destroy); 
    // check for local identity validity
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_IDENTITY, IN_USE_IDENTITY,
        __np_extract_handshake, __is_unencrypted_np_message);
    // check for local identity validity         
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_IDENTITY, IN_USE_IDENTITY,
        __np_identity_handle_authn, __is_authn_request); 
    // check for local identity validity
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_IDENTITY, IN_USE_IDENTITY,
        __np_identity_handle_authz, __is_authz_request);
    // check for local identity validity
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_IDENTITY, IN_USE_IDENTITY,
        __np_identity_handle_account, __is_account_request); 
    // node is not used anymore
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_IDENTITY, IN_DESTROY,
        __np_identity_shutdown,  __is_shutdown_event); 
    // check for local identity validity
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_IDENTITY, IN_DESTROY,
        __np_identity_shutdown, __is_identity_invalid); 


    NP_UTIL_STATEMACHINE_STATE(
        states, IN_USE_MSGPROPERTY, "IN_USE_MSGPROPERTY",
        __keystate_noop, __keystate_noop, __keystate_noop);
    // user changed mx_properties
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_MSGPROPERTY, ON_HOLD_MSGPROPERTY,
        __np_property_lifecycle_set, __is_msgproperty_lifecycle_disable); 
    // user changed mx_properties
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY,
        __np_response_handler_set, __is_response_event); 
    // user changed mx_properties
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY,
        __np_property_redelivery_set, __is_message_redelivery_event);
    // call usr callback function
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY,
        __np_property_handle_in_msg, __is_sender_token_available); 
    // call usr callback function
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY,
        __np_property_handle_out_msg, __is_receiver_token_available); 
    // received authn information (eventually through identity join)
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY,
        __np_property_handle_intent, __is_intent_authz); 
     // call usr callback function
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY,
        __np_property_add_msg_to_cache, __is_no_token_available);
    // user changed mx_properties
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY,
        __np_property_update, __is_msgproperty); 
    // send out intents
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, IN_USE_MSGPROPERTY, IN_USE_MSGPROPERTY,
        __np_property_check, __is_noop_event); 


    NP_UTIL_STATEMACHINE_STATE(
        states, ON_HOLD_MSGPROPERTY, "ON_HOLD_MSGPROPERTY",
        __keystate_noop, __keystate_noop, __keystate_noop);
    // user changed mx_properties
    NP_UTIL_STATEMACHINE_TRANSITION(
        states, ON_HOLD_MSGPROPERTY, IN_USE_MSGPROPERTY,
        __np_property_lifecycle_set, __is_msgproperty_lifecycle_enable); 


    NP_UTIL_STATEMACHINE_STATE(
        states, IN_DESTROY, "IN_DESTROY",
        __keystate_noop, __np_key_destroy, __keystate_noop);

    // clang-format on

    population_done = true;
  }

  NP_UTIL_STATEMACHINE_INIT(key->sm, context, UNUSED, states, key);
}

char *_np_key_as_str(np_key_t *key) {
  assert(key != NULL);
  np_ctx_memory(key);

  return (key->dhkey_str);
}

/**
 * Destroys a key with all resources
 */
void _np_key_destroy(np_key_t *to_destroy) {
  np_ctx_memory(to_destroy);
  char *keyident = NULL;

  keyident = _np_key_as_str(to_destroy);

  log_debug_msg(LOG_KEY,
                "cleanup of key and associated data structures: %s",
                keyident);
  log_debug_msg(LOG_MEMORY,
                "refcount of key %s at destroy: %" PRIu32,
                keyident,
                np_memory_get_refcount(to_destroy));

  _np_keycache_remove(context, to_destroy->dhkey);

  log_debug_msg(LOG_KEY | LOG_DEBUG,
                "cleanup of key and associated data structures done.");
}

void _np_key_t_new(np_state_t       *context,
                   NP_UNUSED uint8_t type,
                   NP_UNUSED size_t  size,
                   void             *key) {
  log_trace_msg(LOG_TRACE | LOG_KEY, "start: void _np_key_t_new(void* key){");

  np_key_t *new_key = (np_key_t *)key;

  // new_key->type = np_key_type_unknown;
  // new_key->is_in_keycache = false;

  __np_key_populate_states(new_key);

  new_key->created_at  = np_time_now();
  new_key->last_update = np_time_now();

  // sll_init(void_ptr, new_key->entities); // link to components attached to
  // this key id
  memset(new_key->entity_array, 0, 8 * sizeof(void_ptr));
  new_key->parent_dhkey = dhkey_zero;
  new_key->bloom_scent  = NULL;

  char mutex_str[100] = {0};
  snprintf(mutex_str, 100, "urn:np:key_lock:%s", _np_key_as_str(new_key));
  _np_threads_mutex_init(context, &new_key->key_lock, mutex_str);
}

void _np_key_t_del(np_state_t       *context,
                   NP_UNUSED uint8_t type,
                   NP_UNUSED size_t  size,
                   void             *key) {
  log_trace_msg(LOG_TRACE | LOG_KEY, "start: void _np_key_t_del(void* key){");
  np_key_t *old_key = (np_key_t *)key;

  // sll_free(void_ptr, old_key->entities);
  if (old_key->bloom_scent != NULL) {
    _np_bloom_free(old_key->bloom_scent);
  }

  memset(old_key->entity_array, 0, 8 * sizeof(void_ptr));

  _np_threads_mutex_destroy(context, &old_key->key_lock);
}

void _np_key_handle_event(np_key_t *key, np_util_event_t event) {
  assert(key != NULL);
  np_ctx_memory(key);

  _LOCK_ACCESS(&key->key_lock) {
    char *old_state = key->sm._state_table[key->sm._current_state]->_state_name;
    // push down all event from queue and execute this event
    log_debug(LOG_EVENT,
              "key: %s/%p event: %" PRIu32 " attempt transition from %s",
              _np_key_as_str(key),
              key,
              event.type,
              old_state);
    if (!np_util_statemachine_invoke_auto_transition(&key->sm, event)) {
      if (event.type != evt_noop) {
        log_debug(LOG_WARNING,
                  "key: %s/%p event: %" PRIu32 " NO transition: %s ",
                  _np_key_as_str(key),
                  key,
                  event.type,
                  old_state);
      }
    } else {
      log_debug(LOG_EVENT | LOG_KEY,
                "key: %s/%p event: %" PRIu32 " state change: %s -> %s",
                _np_key_as_str(key),
                key,
                event.type,
                old_state,
                key->sm._state_table[key->sm._current_state]->_state_name);
    }

    if (event.type != evt_noop) key->last_update = np_time_now();
  }
}

void _np_key_readonly_copy(np_state_t  *context,
                           np_key_ro_t *buffer,
                           np_key_t    *source) {
  ASSERT(buffer != NULL, "buffer needs to be set");
  ASSERT(source != NULL, "source needs to be set");
  _LOCK_ACCESS(&source->key_lock) {
    buffer->dhkey        = source->dhkey;
    buffer->parent_dhkey = source->parent_dhkey;
    buffer->type         = source->type;
  }
}