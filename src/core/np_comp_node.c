//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that
// a node can have. It is included form np_key.c, therefore there are no extra
// #include directives.

#include "core/np_comp_node.h"

#include <inttypes.h>

#include "util/np_event.h"
#include "util/np_statemachine.h"

#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_eventqueue.h"
#include "np_evloop.h"
#include "np_glia.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_pheromones.h"
#include "np_responsecontainer.h"
#include "np_route.h"

// IN_SETUP -> IN_USE transition condition / action #1
bool __is_node_handshake_token(np_util_statemachine_t *statemachine,
                               const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);
  NP_CAST(statemachine->_user_data, np_key_t, key);

  bool ret = false;

  if (!ret)
    ret = FLAG_CMP(event.type, evt_token) && FLAG_CMP(event.type, evt_external);
  if (ret)
    ret &=
        (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
  if (ret) {
    NP_CAST(event.user_data, np_aaatoken_t, hs_token);
    ret &= FLAG_CMP(hs_token->type, np_aaatoken_type_handshake);

    if (ret && hs_token->issuer != NULL) {
      np_dhkey_t issuer_dhkey = {0};
      np_str_id(&issuer_dhkey, hs_token->issuer);
      ret &= _np_dhkey_equal(&issuer_dhkey, &event.__source_dhkey);
    }
    ret &= _np_aaatoken_is_valid(context, hs_token, hs_token->type);

    // TODO: check whether a new passive node actually still fist into our
    // leafset? if not -> stop the handshake early and interrupt protocol
    //
    // <your code to check for possible leafset insertion here>
    // ret = false
  }
  return ret;
}

bool __is_shutdown_event(np_util_statemachine_t *statemachine,
                         const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, key);

  bool ret = false;

  if (!ret) ret = FLAG_CMP(event.type, evt_shutdown);

  if (ret && FLAG_CMP(event.type, evt_external)) {
    NP_CAST(event.user_data, np_aaatoken_t, remote_token);

    np_aaatoken_t *local_token = _np_key_get_token(key);

    ret &= _np_aaatoken_is_valid(context, remote_token, np_aaatoken_type_node);
    if (NULL != local_token && ret)
      ret &= (0 == memcmp(remote_token->crypto.ed25519_public_key,
                          local_token->crypto.ed25519_public_key,
                          crypto_sign_ed25519_PUBLICKEYBYTES));
  }

  if (ret && FLAG_CMP(event.type, evt_internal)) {
    ret &= _np_dhkey_equal(&key->dhkey, &event.target_dhkey);
  }

  // if ( ret) ret &= (np_memory_get_type(event.user_data) ==
  // np_memory_types_np_aaatoken_t);

  return ret;
}

bool __is_node_token(np_util_statemachine_t *statemachine,
                     const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  if (!ret)
    ret = FLAG_CMP(event.type, evt_token) && FLAG_CMP(event.type, evt_external);
  if (ret)
    ret &=
        (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
  if (ret) {
    NP_CAST(event.user_data, np_aaatoken_t, token);
    ret &= FLAG_CMP(token->type, np_aaatoken_type_node);
    ret &= !token->private_key_is_set;
    ret &= _np_aaatoken_is_valid(context, token, token->type);
  }

  return ret;
}

// IN_USE -> IN_DESTROY transition condition / action #1
bool __is_node_invalid(np_util_statemachine_t         *statemachine,
                       NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  if (!FLAG_CMP(event.type, evt_noop)) return false;

  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  if (!ret) ret = FLAG_CMP(node_key->type, np_key_type_unknown);

  double now = np_time_now();
  if (!ret && (node_key->created_at + BAD_LINK_REMOVE_GRACETIME) > now) {
    return false;
  }

  if (!ret) ret = (_np_key_get_node(node_key) == NULL);

  np_node_t *node = _np_key_get_node(node_key);

  if (!ret) ret = (node->connection_attempts > 15);

  if (!ret) // check whether leave msg has been sent
  {
    np_node_t *node = _np_key_get_node(node_key);
    ret             = (node->leave_send_at > node->join_send_at) ? true : false;
    if (ret) {
      log_info(LOG_ROUTING,
               NULL,
               "bad node [left mesh]: %s , is_in_leafset: %d, "
               "is_in_routing_table: %d",
               _np_key_as_str(node_key),
               node->is_in_leafset,
               node->is_in_routing_table);
    }
  }

  if (!ret) // check for not in routing / leafset table anymore
  {
    ret = (!node->is_in_leafset) && (!node->is_in_routing_table);
    if (ret) {
      log_info(LOG_ROUTING,
               NULL,
               "bad node [no routing]: %s , is_in_leafset: %d, "
               "is_in_routing_table: %d",
               _np_key_as_str(node_key),
               node->is_in_leafset,
               node->is_in_routing_table);
    }

    log_trace(LOG_TRACE,
              "end  : bool __is_node_invalid(...) not in routing table { "
              "%d (%d / %d / %f < %f)",
              ret,
              node->is_in_leafset,
              node->is_in_routing_table,
              (node_key->created_at + BAD_LINK_REMOVE_GRACETIME),
              np_time_now());
  }

  if (!ret) // bad node connectivity
  {
    ret = (node->success_avg < BAD_LINK);
    if (ret) {
      log_info(LOG_ROUTING,
               NULL,
               "bad node [connectivity]: %s success_avg: %f ",
               _np_key_as_str(node_key),
               node->success_avg);
    }
    log_trace(LOG_TRACE,
              NULL,
              "end  : bool __is_node_invalid(...) bad connectivity { %d "
              "(%d / %d / %f < %f)",
              ret,
              node->is_in_leafset,
              node->is_in_routing_table,
              (node_key->created_at + BAD_LINK_REMOVE_GRACETIME),
              np_time_now());
  }

  if (!ret) // token expired
  {
    np_aaatoken_t *node_token = _np_key_get_token(node_key);
    ret                       = (node_token == NULL);
    if (!ret) {
      ret = !_np_aaatoken_is_valid(context, node_token, node_token->type);
    }
    if (ret) {
      log_info(LOG_ROUTING,
               NULL,
               "bad node [token expired]: %s",
               _np_key_as_str(node_key));
    }
    log_trace(LOG_TRACE,
              NULL,
              "end  : bool __is_node_invalid(...) token invalid { %d (%d / "
              "%d / %f < %f)",
              ret,
              node->is_in_leafset,
              node->is_in_routing_table,
              (node_key->created_at + BAD_LINK_REMOVE_GRACETIME),
              np_time_now());
  }

  return ret;
}

// check whether the connection to a node has to be terminated
bool __has_to_leave(np_util_statemachine_t *statemachine,
                    const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool   ret = false;
  double now = np_time_now();

  if (!FLAG_CMP(event.type, evt_noop)) return false;

  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  if (!ret) ret = !FLAG_CMP(node_key->type, np_key_type_node);

  if (!ret &&
      ((node_key->created_at + BAD_LINK_REMOVE_GRACETIME) > (now + NP_PI))) {
    return false;
  }

  if (!ret) ret = (_np_key_get_node(node_key) == NULL);

  if (!ret) {
    np_node_t *node = _np_key_get_node(node_key);
    if (node->leave_send_at > node->join_send_at) return false;
  }

  if (!ret) // check for not in routing / leafset table anymore
  {
    np_node_t *node = _np_key_get_node(node_key);
    ret = (node->is_in_leafset == false && node->is_in_routing_table == false);
    if (ret) {
      log_info(LOG_ROUTING,
               NULL,
               "bad node [no routing]: %s , is_in_leafset: %d, "
               "is_in_routing_table: %d",
               _np_key_as_str(node_key),
               node->is_in_leafset,
               node->is_in_routing_table);
    }
  }
  if (!ret) // bad node connectivity
  {
    np_node_t *node = _np_key_get_node(node_key);
    ret             = (node->success_avg < BAD_LINK);
    if (ret) {
      log_info(LOG_ROUTING,
               NULL,
               "bad node [connectivity]: %s success_avg: %f ",
               _np_key_as_str(node_key),
               node->success_avg);
    }
  }

  return ret;
}

bool __is_wildcard_key(np_util_statemachine_t *statemachine,
                       const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  if (!ret) ret = FLAG_CMP(event.type, evt_internal);
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_node_t);
  if (ret) {
    NP_CAST(event.user_data, np_node_t, node);
    ret &= _np_node_check_address_validity(node);
    ret &= node->host_key[0] == '*';
  }

  return ret;
}

bool __is_node_info(np_util_statemachine_t *statemachine,
                    const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  // NP_CAST(statemachine->_user_data, np_key_t, node_key);

  if (!ret) ret = FLAG_CMP(event.type, evt_internal);
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_node_t);
  if (ret) {
    NP_CAST(event.user_data, np_node_t, node);
    ret &= _np_node_check_address_validity(node);
    ret &= node->host_key[0] != '*';
  }

  return ret;
}

void __np_node_set_node(np_util_statemachine_t *statemachine,
                        const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);
  NP_CAST(event.user_data, np_node_t, node);

  if (!FLAG_CMP(node_key->type, np_key_type_node)) {
    np_ref_obj(np_key_t, node_key, "__np_node_set");
    node_key->type |= np_key_type_node;
  }
  log_trace(LOG_TRACE,
            NULL,
            "start: void __np_node_set_node(...) { %s:%s",
            node->ip_string,
            node->port);

  if (node_key->entity_array[e_nodeinfo] == NULL) {
    node_key->entity_array[e_nodeinfo] = node;
    np_ref_obj(np_node_t, node, "__np_node_set");
  } else {
    log_trace(LOG_TRACE,
              NULL,
              "start: void __np_node_set_node(...) { %s:%s",
              ((np_node_t *)node_key->entity_array[e_nodeinfo])->ip_string,
              ((np_node_t *)node_key->entity_array[e_nodeinfo])->port);
  }
}

bool __is_node_authn(np_util_statemachine_t *statemachine,
                     const np_util_event_t   event) {
  // { .type=(evt_internal|evt_token), .user_data=authn_token,
  // .target_dhkey=event.target_dhkey};
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  // NP_CAST(statemachine->_user_data, np_key_t, node_key);
  // NP_CAST(event.user_data, np_node_t, my_node);

  if (!ret)
    ret =
        (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_token));
  if (ret) ret &= FLAG_CMP(event.type, evt_authn);
  if (ret)
    ret &=
        _np_memory_rtti_check(event.user_data, np_memory_types_np_aaatoken_t);

  return ret;
}

bool __is_node_identity_authn(np_util_statemachine_t *statemachine,
                              const np_util_event_t   event) {
  // { .type=(evt_internal|evt_token), .user_data=authn_token,
  // .target_dhkey=event.target_dhkey};
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  // NP_CAST(statemachine->_user_data, np_key_t, node_key);

  if (!ret)
    ret =
        (FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_token));
  if (ret) ret &= FLAG_CMP(event.type, evt_authn);
  if (ret)
    ret &=
        _np_memory_rtti_check(event.user_data, np_memory_types_np_aaatoken_t);

  if (ret) {
    NP_CAST(event.user_data, np_aaatoken_t, token);
    ret &= FLAG_CMP(token->type, np_aaatoken_type_identity);
    if (ret) {
      np_dhkey_t partner_fp = np_aaatoken_get_partner_fp(token);
      NP_CAST(statemachine->_user_data, np_key_t, node_key);
      ret &= _np_dhkey_equal(&partner_fp, &node_key->dhkey);
    }
  }

  return ret;
}

void __np_node_set(np_util_statemachine_t *statemachine,
                   const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);
  NP_CAST(event.user_data, np_aaatoken_t, node_token);

  if (!FLAG_CMP(node_key->type, np_key_type_node)) {
    np_ref_obj(np_key_t, node_key, "__np_node_set");
    node_key->type |= np_key_type_node;
  }

  if (node_token->type == np_aaatoken_type_handshake) {
    node_key->entity_array[e_handshake_token] = node_token;
  }

  if (node_token->type == np_aaatoken_type_node)
    node_key->entity_array[e_aaatoken] = node_token;

  np_ref_obj(np_aaatoken_t, node_token, "__np_node_set");
  node_token->state = AAA_VALID;

  np_node_t *node = _np_node_from_token(node_token, np_aaatoken_type_handshake);
  if (NULL != node) {
    if (FLAG_CMP(node->protocol, PASSIVE)) {
      np_key_t *alias_key = _np_keycache_find(context, event.target_dhkey);
      if (NULL != alias_key) {
        // if this node is not null, then a passive node contacted us first
        np_node_t *alias_node = _np_key_get_node(alias_key);
        if (NULL != alias_node) {
          log_warn(LOG_NETWORK,
                   NULL,
                   "connecting passive node, check ip %s",
                   alias_node->ip_string);
          node_key->entity_array[e_nodeinfo] = alias_node;
          alias_node->protocol |= node->protocol;

          log_debug(LOG_ROUTING,
                    NULL,
                    "node_status: %d:%s:%s",
                    alias_node->protocol,
                    alias_node->ip_string,
                    alias_node->port);
          log_debug(LOG_ROUTING | LOG_HANDSHAKE,
                    NULL,
                    "node_status: %d %f",
                    alias_node->_handshake_status,
                    alias_node->handshake_send_at);

          np_ref_obj(np_node_t, alias_node, "_np_node_from_token");
          np_unref_obj(np_node_t, node, "_np_node_from_token");

          node = alias_node;
        } else {
          log_warn(LOG_NETWORK,
                   NULL,
                   "try to connect passive node, but found no alias node");
        }
        np_unref_obj(np_key_t, alias_key, "_np_keycache_find");
      } else {
        log_warn(LOG_NETWORK,
                 NULL,
                 "try to connect passive node, but found no alias key");
      }
    }

    if (_np_node_cmp(node, node_key->entity_array[e_nodeinfo]) != 0) {
      ASSERT(node_key->entity_array[e_nodeinfo] == NULL,
             "element needs to be dereferenced first.");
      node_key->entity_array[e_nodeinfo] = node;
    }
    np_ref_obj(np_node_t, node_key->entity_array[e_nodeinfo], "__np_node_set");

    // handle handshake token after wildcard join
    char *tmp_connection_str = np_get_connection_string_from(node_key, false);
    np_dhkey_t wildcard_dhkey =
        np_dhkey_create_from_hostport("*", tmp_connection_str);

    np_key_t *hs_wildcard_key = _np_keycache_find(context, wildcard_dhkey);
    if (NULL != hs_wildcard_key) {
      np_node_t *wc_node      = _np_key_get_node(hs_wildcard_key);
      node->handshake_send_at = wc_node->handshake_send_at;
      node->_handshake_status = wc_node->_handshake_status;

      np_unref_obj(np_key_t, hs_wildcard_key, "_np_keycache_find");
    }
    log_debug(LOG_ROUTING | LOG_HANDSHAKE,
              NULL,
              "node_status: %d %f",
              node->_handshake_status,
              node->handshake_send_at);
    free(tmp_connection_str);
    np_unref_obj(np_node_t, node, "_np_node_from_token");
  }
}

void __np_wildcard_set(np_util_statemachine_t *statemachine,
                       const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, wildcard_key);
  NP_CAST(event.user_data, np_node_t, node);

  np_ref_obj(np_key_t, wildcard_key, "__np_wildcard_set");
  wildcard_key->type |= np_key_type_wildcard;

  if (wildcard_key->entity_array[e_nodeinfo] == NULL) {
    wildcard_key->entity_array[e_nodeinfo] = node;
    np_ref_obj(np_node_t, node, "__np_wildcard_set");
  }
}

void __np_filter_remove_passive_nodes(np_state_t *context,
                                      np_sll_t(np_key_ptr, sll_of_keys),
                                      const char *ref_source) {
  np_sll_t(np_key_ptr, to_remove_keys);
  sll_init(np_key_ptr, to_remove_keys);

  sll_iterator(np_key_ptr) iter = sll_first(sll_of_keys);
  while (iter != NULL) {
    np_node_t *node = _np_key_get_node(iter->val);
    if (node != NULL && FLAG_CMP(node->protocol, PASSIVE)) {
      sll_append(np_key_ptr, to_remove_keys, iter->val);
    }
    sll_next(iter);
  }
  iter = sll_first(to_remove_keys);
  while (iter != NULL) {
    np_key_ptr current = iter->val;
    sll_remove(np_key_ptr, sll_of_keys, current, np_key_ptr_sll_compare_type);
    np_unref_obj(np_key_t, current, ref_source);
    sll_next(iter);
  }
  sll_free(np_key_ptr, to_remove_keys)
}

void __np_node_add_to_leafset(np_util_statemachine_t         *statemachine,
                              NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  struct __np_node_trinity trinity = {0};
  __np_key_to_trinity(node_key, &trinity);

  if (trinity.node->is_in_leafset == false) {
    np_key_t *added = NULL, *deleted = NULL;
    _np_route_leafset_update(node_key, true, &deleted, &added);

    if (added != NULL) {
      trinity.node->is_in_leafset = true;
      log_info(LOG_ROUTING,
               NULL,
               "[routing disturbance] added to leafset: %s:%s:%s / %f / %1.2f",
               _np_key_as_str(added),
               trinity.node->ip_string,
               trinity.node->port,
               trinity.node->last_success,
               trinity.node->success_avg);
    }
    if (deleted != NULL) {
      _np_key_get_node(deleted)->is_in_leafset = false;
      log_info(LOG_ROUTING,
               NULL,
               "[routing disturbance] deleted from leafset (due to update): "
               "%s:%s:%s / last_success: %f (diff: %f) / success_avg: %1.2f",
               _np_key_as_str(deleted),
               _np_key_get_node(deleted)->ip_string,
               _np_key_get_node(deleted)->port,
               _np_key_get_node(deleted)->last_success,
               np_time_now() - _np_key_get_node(deleted)->last_success,
               _np_key_get_node(deleted)->success_avg);
    }
    // TODO: trigger re-fill of leafset? see piggy messages
  }
}

void __np_node_remove_from_routing_leafset(np_util_statemachine_t *statemachine,
                                           NP_UNUSED const np_util_event_t
                                               event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  struct __np_node_trinity trinity = {0};
  __np_key_to_trinity(node_key, &trinity);

  if (trinity.node->is_in_leafset == true) {
    np_key_t *added = NULL, *deleted = NULL;
    _np_route_leafset_update(node_key, false, &deleted, &added);
    ASSERT(added == NULL, "Cannot add to leafset here");
    if (deleted != NULL) {
      _np_pheromone_exhale(context);
      _np_key_get_node(deleted)->is_in_leafset = false;
      log_info(LOG_ROUTING,
               NULL,
               "[routing disturbance] deleted from leafset: %s:%s:%s / "
               "last_success: %f (diff: %f) / success_avg: %1.2f",
               _np_key_as_str(deleted),
               _np_key_get_node(deleted)->ip_string,
               _np_key_get_node(deleted)->port,
               _np_key_get_node(deleted)->last_success,
               np_time_now() - _np_key_get_node(deleted)->last_success,
               _np_key_get_node(deleted)->success_avg);
    } else {
      log_error(NULL,
                "%s",
                "deletion from leafset unsuccesful, reason unknown !!!");
    }
  }
}

void __np_node_remove_from_routing_table(np_util_statemachine_t *statemachine,
                                         NP_UNUSED const np_util_event_t
                                             event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  struct __np_node_trinity trinity = {0};
  __np_key_to_trinity(node_key, &trinity);

  if (trinity.node->is_in_routing_table == true) {
    np_key_t *added = NULL, *deleted = NULL;
    _np_route_update(node_key, false, &deleted, &added);

    if (deleted != NULL) {
      _np_pheromone_exhale(context);
      _np_key_get_node(deleted)->is_in_routing_table = false;
      log_info(LOG_ROUTING,
               NULL,
               "[routing disturbance] deleted from routing table: %s:%s:%s / "
               "%f / %1.2f",
               _np_key_as_str(deleted),
               _np_key_get_node(deleted)->ip_string,
               _np_key_get_node(deleted)->port,
               _np_key_get_node(deleted)->last_success,
               _np_key_get_node(deleted)->success_avg);
    } else {
      log_error(NULL,
                "%s",
                "deletion from routing table unsuccesful, reason unknown !!!");
    }
  }
}

void __np_node_remove_from_routing(np_util_statemachine_t         *statemachine,
                                   NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  __np_node_remove_from_routing_leafset(statemachine, event);
  __np_node_remove_from_routing_table(statemachine, event);
}

void __np_node_handle_completion(np_util_statemachine_t *statemachine,
                                 const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  struct __np_node_trinity trinity = {0};
  __np_key_to_trinity(node_key, &trinity);

  double now = np_time_now();

  np_dhkey_t hs_dhkey = _np_msgproperty_dhkey(WIRE_FORMAT, _NP_MSG_HANDSHAKE);
  np_dhkey_t join_dhkey =
      _np_msgproperty_dhkey(WIRE_FORMAT, _NP_MSG_JOIN_REQUEST);

  np_msgproperty_conf_t *hs_prop =
      _np_msgproperty_conf_get(context, OUTBOUND, hs_dhkey);
  np_msgproperty_conf_t *join_prop =
      _np_msgproperty_conf_get(context, OUTBOUND, join_dhkey);

  log_debug(LOG_HANDSHAKE,
            NULL,
            "node handshake status: %d %f // %p %" PRIu8,
            trinity.node->_handshake_status,
            trinity.node->handshake_send_at,
            hs_prop,
            node_key->type);
  log_debug(LOG_HANDSHAKE,
            NULL,
            "node join      status: %d %f // %p",
            trinity.node->_joined_status,
            trinity.node->join_send_at,
            join_prop);

  struct np_e2e_message_s *msg_out = NULL;
  TSP_GET(bool, trinity.node->session_key_is_set, session_key_is_set);

  if (trinity.node->_handshake_status < np_node_status_Connected &&
      (trinity.node->handshake_send_at + hs_prop->msg_ttl) < now) {
    np_new_obj(np_message_t, msg_out);
    _np_message_create(msg_out,
                       node_key->dhkey,
                       context->my_node_key->dhkey,
                       hs_dhkey,
                       NULL);

    enum np_node_status old_node_status = trinity.node->_handshake_status;
    trinity.node->_handshake_status     = np_node_status_Initiated;
    log_info(LOG_HANDSHAKE,
             NULL,
             "set %s %s _handshake_status: %" PRIu8 " -> %" PRIu8,
             FUNC,
             trinity.node->ip_string,
             old_node_status,
             trinity.node->_handshake_status);

    trinity.node->handshake_send_at = now;
    trinity.node->connection_attempts++;

    log_info(LOG_ROUTING, msg_out->uuid, "sending internal handshake event");
    np_util_event_t handshake_event = {.type = (evt_internal | evt_message),
                                       .user_data    = msg_out,
                                       .target_dhkey = node_key->dhkey};

    _np_event_runtime_add_event(
        context,
        event.current_run,
        _np_msgproperty_tweaked_dhkey(OUTBOUND, hs_dhkey),
        handshake_event);

    log_trace(LOG_TRACE,
              NULL,
              "start: __np_node_handle_completion(...) { node now (hand)   "
              " : %p / %p %d",
              node_key,
              trinity.node,
              trinity.node->_handshake_status);
    np_unref_obj(np_message_t, msg_out, ref_obj_creation);

  } else if (session_key_is_set == true &&
             trinity.node->_joined_status < np_node_status_Connected &&
             (trinity.node->join_send_at + join_prop->msg_ttl) < now) {

    np_new_obj(np_message_t, msg_out);
    _np_message_create(msg_out,
                       node_key->dhkey,
                       context->my_node_key->dhkey,
                       join_dhkey,
                       NULL);

    trinity.node->_joined_status = np_node_status_Initiated;
    trinity.node->join_send_at   = now;
    trinity.node->connection_attempts++;

    log_info(LOG_ROUTING, msg_out->uuid, "sending internal join event");

    np_util_event_t join_event = {.type         = (evt_internal | evt_message),
                                  .user_data    = msg_out,
                                  .target_dhkey = node_key->dhkey};
    _np_event_runtime_add_event(
        context,
        event.current_run,
        _np_msgproperty_tweaked_dhkey(OUTBOUND, join_dhkey),
        join_event);

    log_trace_msg(LOG_TRACE,
                  NULL,
                  "start: __np_node_handle_completion(...) { node now (join)   "
                  " : %p / %p %d",
                  node_key,
                  trinity.node,
                  trinity.node->_joined_status);
    np_unref_obj(np_message_t, msg_out, ref_obj_creation);
  }
}

void __np_node_identity_upgrade(np_util_statemachine_t *statemachine,
                                const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, alias_or_node_key);
  NP_CAST(event.user_data, np_aaatoken_t, token);

  struct __np_node_trinity trinity = {0};
  __np_key_to_trinity(alias_or_node_key, &trinity);

  __np_node_handle_completion(&alias_or_node_key->sm, event);

  if (FLAG_CMP(trinity.token->type, np_aaatoken_type_node)) {
    trinity.token->state |= AAA_AUTHENTICATED;
    trinity.node->_joined_status = np_node_status_Connected;
  }
}

void __np_node_update(np_util_statemachine_t *statemachine,
                      const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  if (FLAG_CMP(node_key->type, np_key_type_interface) ||
      node_key == context->my_node_key) {
    // no follow up actions for our own node and interfaces
    return;
  }

  np_node_t *node  = _np_key_get_node(node_key);
  float      total = 0.0;

  // TODO: find good metric/calculation for _prune_modifier
  uint8_t _prune_modifier = NP_MSG_FORWARD_FILTER_PRUNE_RATE;
  if (node->msg_forward_filter->_p != _prune_modifier) {
    node->msg_forward_filter->_p = _prune_modifier;
    log_debug(LOG_MISC | LOG_NETWORK,
              NULL,
              "FORWARD duplicate check adjusted, now using bit-pruning: %d)",
              _prune_modifier);
  }

  // calculate average ping success value
  float old_success_avg = node->success_avg;
  for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++) {
    total += node->success_win[i];
  }
  node->success_avg = total / NP_NODE_SUCCESS_WINDOW;

  // calculate average latency value
  total                 = 0.0;
  float old_latency_avg = node->latency;
  for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++) {
    total += node->latency_win[i];
  }
  node->latency = total / NP_NODE_SUCCESS_WINDOW;

  if (node->latency != old_latency_avg ||
      node->success_avg != old_success_avg ||
      node->next_routing_table_update < np_time_now()) {
    log_info(LOG_MISC | LOG_EXPERIMENT,
             NULL,
             "connection status to node %.4s:%.15s:%.6s "
             "success rate now: %1.2f (last update was %2u) "
             "now: %1.6f (last update was %1.6fsec)",
             _np_network_get_protocol_string(context, node->protocol),
             node->ip_string,
             node->port,
             node->success_avg,
             node->success_win[node->success_win_index],
             node->latency,
             node->latency_win[node->latency_win_index]);
  }

  // the node received a shutdown event or decided to shutdown by the rules
  // below do not further process events
  if (node->leave_send_at > node->join_send_at) {
    return;
  }

  // insert into the routing table after a specific time period
  // reason: routing is based on latency, therefore we need a stable connection
  // before inserting
  if (node->is_in_routing_table == false &&
      node->success_win[node->success_win_index] == 1 &&
      (node_key->created_at + MISC_SEND_PINGS_SEC) < np_time_now() &&
      !FLAG_CMP(node->protocol, PASSIVE)) {
    np_key_t  *added = NULL, *deleted = NULL;
    np_node_t *node_1 = NULL;

    _np_route_update(node_key, true, &deleted, &added);

    if (added != NULL) {
      // TODO: send an event to node_1 to remove it from the routing, otherwise
      // we do not have the lock
      node_1                      = _np_key_get_node(added);
      node_1->is_in_routing_table = true;
    }

    if (deleted != NULL) {
      // TODO: send an event to node_1 to remove it from the routing, otherwise
      // we do not have the lock
      node_1                      = _np_key_get_node(deleted);
      node_1->is_in_routing_table = false;
    }
  }

  double now = np_time_now();
  // follow up actions
  if ((node->success_avg > BAD_LINK) && (now >= node->next_ping_update)) {
    np_dhkey_t ping_dhkey = {0};
    np_generate_subject(&ping_dhkey,
                        _NP_MSG_PING_REQUEST,
                        strnlen(_NP_MSG_PING_REQUEST, 256));

    // issue ping messages
    struct np_e2e_message_s *msg_out = NULL;
    np_new_obj(np_message_t, msg_out);
    np_tree_t *empty_body = np_tree_create();
    _np_message_create(msg_out,
                       node_key->dhkey,
                       context->my_node_key->dhkey,
                       ping_dhkey,
                       empty_body);
    np_tree_free(empty_body);

    np_dhkey_t ping_out_dhkey =
        _np_msgproperty_tweaked_dhkey(OUTBOUND, ping_dhkey);
    np_util_event_t ping_event = {.type         = (evt_internal | evt_message),
                                  .target_dhkey = node_key->dhkey,
                                  .user_data    = msg_out};
    np_jobqueue_submit_event(context,
                             0.0,
                             ping_out_dhkey,
                             ping_event,
                             "event: ping out");
    log_debug(LOG_ROUTING,
              msg_out->uuid,
              "submitted ping to target key %s / %p",
              _np_key_as_str(node_key),
              node_key);
    np_unref_obj(np_message_t, msg_out, ref_obj_creation);

    if (node->success_win[node->success_win_index] == 0)
      node->next_ping_update = now + MISC_SEND_PINGS_SEC;
    else
      node->next_ping_update =
          now + MISC_SEND_PINGS_MAX_EVERY_X_SEC * node->success_avg;
  }

  // there seem to be (a couple of) failure(s) to contact the peer node, remove
  // it from the routing table if the link quality is below GOOD_LINK to have
  // space for other nodes in the network
  if (node->success_win[node->success_win_index] == 0 &&
      node->is_in_routing_table == true && node->success_avg <= GOOD_LINK) {
    __np_node_remove_from_routing_table(statemachine, event);
  }

  if ((node->success_avg > BAD_LINK) &&
      (node->next_routing_table_update < np_time_now())) {
    /* send one row of our routing table back to the peer node */
    np_sll_t(np_key_ptr, sll_of_keys) = NULL;
    sll_of_keys              = _np_route_row_lookup(context, node_key->dhkey);
    char *source_sll_of_keys = "_np_route_row_lookup";

    if (sll_size(sll_of_keys) < 1) {
      // nothing found, send a pointer into the dht to exchange some data at
      // least, prevents small clusters from not exchanging all data
      np_key_unref_list(sll_of_keys,
                        source_sll_of_keys); // only for completion
      sll_free(np_key_ptr, sll_of_keys);
      sll_of_keys        = _np_route_lookup(context, node_key->dhkey, 2);
      source_sll_of_keys = "_np_route_lookup";
    }

    if (sll_size(sll_of_keys) > 0) {
      log_debug(LOG_ROUTING,
                NULL,
                "job submit piggyinfo to %s:%s!",
                node->ip_string,
                node->port);

      np_dhkey_t piggy_dhkey = {0};
      np_generate_subject(&piggy_dhkey,
                          _NP_MSG_PIGGY_REQUEST,
                          strnlen(_NP_MSG_PIGGY_REQUEST, 256));

      np_tree_t *msg_body = np_tree_create();
      _np_node_encode_multiple_to_jrb(msg_body, sll_of_keys, false);

      struct np_e2e_message_s *msg_out = NULL;
      np_new_obj(np_message_t, msg_out); // ref_obj_creation
      _np_message_create(msg_out,
                         node_key->dhkey,
                         context->my_node_key->dhkey,
                         piggy_dhkey,
                         msg_body);

      log_info(LOG_ROUTING, msg_out->uuid, "sending internal piggy event");

      np_dhkey_t piggy_out_dhkey =
          _np_msgproperty_tweaked_dhkey(OUTBOUND, piggy_dhkey);
      np_util_event_t piggy_event = {.type = (evt_internal | evt_message),
                                     .target_dhkey = node_key->dhkey,
                                     .user_data    = msg_out};
      np_jobqueue_submit_event(context,
                               0.0,
                               piggy_out_dhkey,
                               piggy_event,
                               "event: piggy out");
      np_tree_free(msg_body);
      np_unref_obj(np_message_t, msg_out, ref_obj_creation);
    }
    np_key_unref_list(sll_of_keys, source_sll_of_keys);
    sll_free(np_key_ptr, sll_of_keys);

    node->next_routing_table_update =
        np_time_now() + MISC_SEND_PIGGY_REQUESTS_SEC;
  }
}

void __np_node_upgrade(np_util_statemachine_t *statemachine,
                       const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, alias_or_node_key);
  NP_CAST(event.user_data, np_aaatoken_t, token);

  // if this is an alias, trigger the state transition of the corresponding node
  // key
  if (FLAG_CMP(alias_or_node_key->type, np_key_type_alias)) {
    log_debug(LOG_ROUTING,
              token->uuid,
              "update alias with full token -> state change");
    if (alias_or_node_key->entity_array[e_aaatoken] == NULL) {
      alias_or_node_key->entity_array[e_aaatoken] = token;
      np_ref_obj(np_aaatoken_t, token, "__np_alias_set");
    }

  } else {
    // node key and alias key share the same data structures, updating once
    // counts for both
    struct __np_node_trinity trinity = {0};
    __np_key_to_trinity(alias_or_node_key, &trinity);

    // eventually send out our own data for mtls
    __np_node_handle_completion(&alias_or_node_key->sm, event);

    if (alias_or_node_key->entity_array[e_aaatoken] == NULL) {
      log_debug(LOG_MISC, token->uuid, "setting full token");
      alias_or_node_key->entity_array[e_aaatoken] = token;
      np_ref_obj(np_aaatoken_t, token, "__np_node_set");

      __np_key_to_trinity(alias_or_node_key, &trinity);
    }

    trinity.token->state |= AAA_AUTHENTICATED;
    trinity.node->_joined_status = np_node_status_Connected;

    if (!FLAG_CMP(trinity.node->protocol, PASSIVE)) {
      log_debug(LOG_ROUTING,
                token->uuid,
                "sending np.update.request to peers in the network");
      // send out update request to other nodes that are hash-wise "nearer"
      // aka forward handshake token
      np_tree_t *jrb_token = np_tree_create();
      np_tree_t *jrb_data  = np_tree_create();
      np_aaatoken_encode(jrb_token,
                         alias_or_node_key->entity_array[e_handshake_token]);
      np_tree_insert_str(jrb_data,
                         _NP_URN_NODE_PREFIX,
                         np_treeval_new_cwt(jrb_token));
      np_dhkey_t update_dhkey = {0};
      np_generate_subject(&update_dhkey,
                          _NP_MSG_UPDATE_REQUEST,
                          strnlen(_NP_MSG_UPDATE_REQUEST, 256));

      struct np_e2e_message_s *msg_out = NULL;
      np_new_obj(np_message_t, msg_out);
      _np_message_create(msg_out,
                         event.target_dhkey,
                         context->my_node_key->dhkey,
                         update_dhkey,
                         jrb_data);

      log_info(LOG_ROUTING, token->uuid, "sending internal node update event");
      // send update messages to nodes near to this fingerprint
      np_util_event_t update_event = {
          .type         = (evt_message | evt_internal),
          .user_data    = msg_out,
          .target_dhkey = np_aaatoken_get_fingerprint(token, false)};

      _np_event_runtime_add_event(
          context,
          event.current_run,
          _np_msgproperty_tweaked_dhkey(OUTBOUND, update_dhkey),
          update_event);
      np_unref_obj(np_message_t, msg_out, ref_obj_creation);

      np_tree_free(jrb_token);
      np_tree_free(jrb_data);
    }
  }
}

void __np_node_update_token(np_util_statemachine_t *statemachine,
                            const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);
  NP_CAST(event.user_data, np_aaatoken_t, node_token);

  if (node_token->type == np_aaatoken_type_handshake &&
      node_key->entity_array[e_handshake_token] == NULL) {

    node_key->entity_array[e_handshake_token] = node_token;
    if (node_key->type == np_key_type_alias) {
      np_ref_obj(np_aaatoken_t, node_token, "__np_alias_set");
    } else {
      np_ref_obj(np_aaatoken_t, node_token, "__np_node_set");
    }
  }

  if (node_token->type == np_aaatoken_type_node &&
      node_key->entity_array[e_aaatoken] == NULL) {

    node_key->entity_array[e_aaatoken] = node_token;
    if (node_key->type == np_key_type_alias) {
      np_ref_obj(np_aaatoken_t, node_token, "__np_alias_set");
    } else {
      np_ref_obj(np_aaatoken_t, node_token, "__np_node_set");
    }
  }
  // TODO: add uuid check whether the two token match
  node_token->state = AAA_VALID;

  if (node_key->type == np_key_type_alias) {
    return;
  }

  struct __np_node_trinity trinity = {0};
  __np_key_to_trinity(node_key, &trinity);
  TSP_GET(bool, trinity.node->session_key_is_set, session_key_is_set);

  if (session_key_is_set == true &&
      trinity.node->_joined_status < np_node_status_Connected) {
    // send out our own join message, as we have just received the join
    // request from the peer
    np_dhkey_t join_dhkey =
        _np_msgproperty_dhkey(WIRE_FORMAT, _NP_MSG_JOIN_REQUEST);
    struct np_e2e_message_s *msg_out = NULL;
    np_new_obj(np_message_t, msg_out);
    _np_message_create(msg_out,
                       node_key->dhkey,
                       context->my_node_key->dhkey,
                       join_dhkey,
                       NULL);

    log_info(LOG_ROUTING, msg_out->uuid, "sending internal join event");

    trinity.node->_joined_status = np_node_status_Connected;
    trinity.node->join_send_at   = np_time_now();

    np_util_event_t join_event = {.type         = (evt_internal | evt_message),
                                  .user_data    = msg_out,
                                  .target_dhkey = node_key->dhkey};
    _np_event_runtime_add_event(
        context,
        event.current_run,
        _np_msgproperty_tweaked_dhkey(OUTBOUND, join_dhkey),
        join_event);

    log_debug(LOG_ROUTING,
              msg_out->uuid,
              "start: __np_node_update_token(...) { node now (join)    : "
              "%p / %p %d",
              node_key,
              trinity.node,
              trinity.node->_joined_status);
    np_unref_obj(np_message_t, msg_out, ref_obj_creation);
  }
}

void __np_node_destroy(np_util_statemachine_t         *statemachine,
                       NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  struct __np_node_trinity trinity = {0};
  __np_key_to_trinity(node_key, &trinity);

  __np_node_remove_from_routing(statemachine, event);

  _np_network_disable(trinity.network);

  if (node_key->entity_array[e_network] != NULL)
    np_unref_obj(np_network_t,
                 node_key->entity_array[e_network],
                 "__np_create_client_network");
  if (node_key->entity_array[e_nodeinfo] != NULL) {
    np_unref_obj(np_node_t,
                 node_key->entity_array[e_nodeinfo],
                 "__np_node_set");
  }
  if (node_key->entity_array[e_aaatoken] != NULL)
    np_unref_obj(np_aaatoken_t,
                 node_key->entity_array[e_aaatoken],
                 "__np_node_set");
  if (node_key->entity_array[e_handshake_token] != NULL)
    np_unref_obj(np_aaatoken_t,
                 node_key->entity_array[e_handshake_token],
                 "__np_node_set");

  node_key->type = np_key_type_unknown;
  np_unref_obj(np_key_t, node_key, "__np_node_set");
}

void __np_node_send_shutdown_event(np_util_statemachine_t *statemachine,
                                   const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  np_dhkey_t      leave_dhkey  = node_key->dhkey;
  np_util_event_t shutdown_evt = {.type         = (evt_internal | evt_shutdown),
                                  .user_data    = NULL,
                                  .target_dhkey = leave_dhkey};
  _np_event_runtime_start_with_event(context, leave_dhkey, shutdown_evt);
}

void __np_node_send_shutdown(np_util_statemachine_t *statemachine,
                             const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);
  np_node_t *node = _np_key_get_node(node_key);

  if (FLAG_CMP(event.type, evt_internal) &&
      FLAG_CMP(event.type, evt_shutdown) && node->success_avg > BAD_LINK &&
      node->leave_send_at < node->join_send_at) {
    // 1: create leave message
    np_tree_t *jrb_data    = np_tree_create();
    np_tree_t *jrb_my_node = np_tree_create();
    np_aaatoken_encode(jrb_my_node, _np_key_get_token(context->my_node_key));
    np_tree_insert_str(jrb_data,
                       _NP_URN_NODE_PREFIX,
                       np_treeval_new_cwt(jrb_my_node));

    np_dhkey_t leave_dhkey = {0};
    np_generate_subject(&leave_dhkey,
                        _NP_MSG_LEAVE_REQUEST,
                        strnlen(_NP_MSG_LEAVE_REQUEST, 256));

    struct np_e2e_message_s *msg_out = NULL;
    np_new_obj(np_message_t, msg_out);
    _np_message_create(msg_out,
                       node_key->dhkey,
                       context->my_node_key->dhkey,
                       leave_dhkey,
                       jrb_data);

    np_util_event_t leave_evt = {.type         = (evt_internal | evt_message),
                                 .user_data    = msg_out,
                                 .target_dhkey = node_key->dhkey};
    _np_event_runtime_add_event(
        context,
        event.current_run,
        _np_msgproperty_tweaked_dhkey(OUTBOUND, leave_dhkey),
        leave_evt);
    np_unref_obj(np_message_t, msg_out, ref_obj_creation);

    np_tree_free(jrb_my_node);
    np_tree_free(jrb_data);
  }

  node->leave_send_at = np_time_now();
}

void __np_create_client_network(np_util_statemachine_t         *statemachine,
                                NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  struct __np_node_trinity node_trinity = {0};
  __np_key_to_trinity(node_key, &node_trinity);

  // lookup wildcard to extract existing np_network_t structure
  char *tmp_connection_str = np_get_connection_string_from(node_key, false);
  log_debug(LOG_NETWORK,
            NULL,
            "__np_create_client_network key %p (type: %d): %s",
            node_key,
            node_key->type,
            tmp_connection_str);

  if (tmp_connection_str) {
    np_dhkey_t wildcard_dhkey =
        np_dhkey_create_from_hostport("*", tmp_connection_str);
    np_key_t *wildcard_key = _np_keycache_find(context, wildcard_dhkey);

    // take over existing wildcard network if it exists
    if (NULL != wildcard_key && wildcard_key != node_key) {
      struct __np_node_trinity wildcard_trinity = {0};
      __np_key_to_trinity(wildcard_key, &wildcard_trinity);
      if (NULL != wildcard_trinity.network) {
        log_info(LOG_NETWORK, "_np_network_stop %s", FUNC);
        _np_network_stop(wildcard_trinity.network, true);
        _np_network_set_key(wildcard_trinity.network, node_key->dhkey);

        np_ref_obj(np_network_t,
                   wildcard_trinity.network,
                   "__np_create_client_network");
        node_key->entity_array[e_network] = wildcard_trinity.network;

        __np_key_to_trinity(node_key, &node_trinity);

        _np_network_start(wildcard_trinity.network, true);
      }
      np_unref_obj(np_key_t, wildcard_key, "_np_keycache_find");
    } else if (wildcard_key == node_key) {
      np_unref_obj(np_key_t, wildcard_key, "_np_keycache_find");
    }
    free(tmp_connection_str);
  }

  // look out for alias network after tcp accept
  np_key_t *alias_key = _np_keycache_find(context, event.target_dhkey);
  if (NULL != alias_key) np_unref_obj(np_key_t, alias_key, "_np_keycache_find");

  np_key_t *outgoing_key = NULL;
  if (!_np_glia_node_can_be_reached(context,
                                    node_trinity.node->ip_string,
                                    node_trinity.node->protocol,
                                    &outgoing_key)) {
    log_msg(
        LOG_WARNING,
        NULL,
        "node with connection string %s:%s:%s is not reachable",
        _np_network_get_protocol_string(context, node_trinity.node->protocol),
        node_trinity.node->ip_string,
        node_trinity.node->port);
    return;
  }

  if (NULL == node_trinity.network &&
      NULL != node_trinity.node) { // create outgoing network

    // find interface that we have to use for the incoming passive
    // connection

    np_node_t *my_node = _np_key_get_node(outgoing_key);

    np_network_t *new_network = NULL;
    np_new_obj(np_network_t, new_network);
    log_debug(LOG_NETWORK,
              NULL,
              "to   node_info: %" PRIu16 ":%s:%s",
              node_trinity.node->protocol,
              node_trinity.node->ip_string,
              node_trinity.node->port);
    log_debug(LOG_NETWORK,
              NULL,
              "from node_info: %" PRIu16 ":%s:%s",
              my_node->protocol,
              my_node->ip_string,
              my_node->port);
    if (FLAG_CMP(node_trinity.node->protocol, PASSIVE)) {
      if (FLAG_CMP(my_node->protocol, UDP)) {
        np_network_t *my_network = _np_key_get_network(outgoing_key);
        // send messages from own socket
        if (_np_network_init(new_network,
                             false,
                             my_node->protocol,
                             node_trinity.node->ip_string,
                             node_trinity.node->port,
                             node_trinity.node->max_messages_per_sec,
                             my_network->socket,
                             PASSIVE)) {
          node_key->entity_array[e_network] = new_network;
          ref_replace_reason(np_network_t,
                             new_network,
                             ref_obj_creation,
                             "__np_create_client_network");
          log_debug(LOG_NETWORK,
                    NULL,
                    "connected to passive node: %" PRIu16 ":%s:%s",
                    node_trinity.node->protocol,
                    node_trinity.node->ip_string,
                    node_trinity.node->port);
        }
        _np_network_enable(new_network);
      } else if (FLAG_CMP(my_node->protocol, TCP)) {
        // on passive TCP add read network
        struct __np_node_trinity alias_trinity = {0};
        __np_key_to_trinity(alias_key, &alias_trinity);

        log_debug(LOG_NETWORK,
                  NULL,
                  "connecting passive node: %" PRIu16 ":%s:%s for alias %s",
                  node_trinity.node->protocol,
                  node_trinity.node->ip_string,
                  node_trinity.node->port,
                  _np_key_as_str(alias_key));

        if (_np_network_init(new_network,
                             false,
                             my_node->protocol,
                             alias_trinity.node->ip_string,
                             alias_trinity.node->port,
                             alias_trinity.node->max_messages_per_sec,
                             alias_trinity.network->socket,
                             PASSIVE)) {
          np_ref_obj(np_network_t, new_network, "__np_create_client_network");
          node_key->entity_array[e_network] = new_network;

          log_debug(LOG_NETWORK,
                    NULL,
                    "connected to passive node: %" PRIu16 ":%s:%s",
                    node_trinity.node->protocol,
                    node_trinity.node->ip_string,
                    node_trinity.node->port);
        }
        //_np_network_set_key(new_network, context->my_identity->dhkey);
      }
    } else {
      if (_np_network_init(new_network,
                           false,
                           node_trinity.node->protocol,
                           node_trinity.node->ip_string,
                           node_trinity.node->port,
                           node_trinity.node->max_messages_per_sec,
                           -1,
                           UNKNOWN_PROTO)) {
        if (FLAG_CMP(my_node->protocol, PASSIVE)) {
          log_debug(LOG_NETWORK,
                    NULL,
                    "connected as passive node to: %d:%s:%s",
                    node_trinity.node->protocol,
                    node_trinity.node->ip_string,
                    node_trinity.node->port);
          // set our identity key because of tcp passive network connection
          // (this node is passive)
          _np_network_init(new_network,
                           true,
                           node_trinity.node->protocol,
                           node_trinity.node->ip_string,
                           node_trinity.node->port,
                           node_trinity.node->max_messages_per_sec,
                           new_network->socket,
                           UNKNOWN_PROTO);
          _np_network_set_key(new_network, context->my_identity->dhkey);
        } else {
          // or use our node dhkey for other types of network connections
          _np_network_set_key(new_network, node_key->dhkey);
        }
        node_key->entity_array[e_network] = new_network;
        ref_replace_reason(np_network_t,
                           new_network,
                           ref_obj_creation,
                           "__np_create_client_network");

        _np_network_enable(new_network);
      } else {
        log_warn(LOG_NETWORK | LOG_ROUTING,
                 NULL,
                 "creation of client network failed, invalidating key %s "
                 "(type: %d)",
                 _np_key_as_str(node_key),
                 node_key->type);
        node_key->type = np_key_type_unknown;
      }
    }
  }
  np_unref_obj(np_key_t, outgoing_key, "_np_keycache_find_interface");
}

bool __is_wildcard_invalid(np_util_statemachine_t         *statemachine,
                           NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  NP_CAST(statemachine->_user_data, np_key_t, wildcard_key);

  if (!ret) ret = FLAG_CMP(wildcard_key->type, np_key_type_wildcard);
  if (ret) ret &= ((wildcard_key->created_at + 10.0) < np_time_now());

  return ret;
}

void __np_wildcard_destroy(np_util_statemachine_t         *statemachine,
                           NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, wildcard_key);

  struct __np_node_trinity trinity = {0};
  __np_key_to_trinity(wildcard_key, &trinity);
  if (NULL != trinity.network) {
    log_info(LOG_NETWORK, "_np_network_stop %s", FUNC);
    _np_network_stop(trinity.network, false);
    np_unref_obj(np_network_t, trinity.network, "__np_create_client_network");
  }

  if (NULL != trinity.node) {
    np_unref_obj(np_node_t, trinity.node, "__np_wildcard_set");
  }

  wildcard_key->type &= ~np_key_type_wildcard;
  np_unref_obj(np_key_t, wildcard_key, "__np_wildcard_set");
}

void _np_node_build_network_packet(struct np_n2n_messagepart_s *part) {
  np_ctx_memory(part);

  if (!part->is_forwarded_part) {
    np_new_obj(BLOB_1024, part->msg_chunk, ref_obj_creation);
    np_ref_obj(BLOB_1024, part->msg_chunk, ref_obj_usage);
  }

  assert(part->msg_chunk != NULL);
  void *msg_chunk = part->msg_chunk;

  // memcpy(msg_chunk + 0, &mac_n, 16);
  memcpy(msg_chunk + 16, &part->seq, sizeof(uint32_t));
  memcpy(msg_chunk + 20, &part->hop_count, sizeof(uint16_t));
  // memcpy(msg_chunk + 16, &trinity.node->rlnc_n, 32);
  // memcpy(msg_chunk + 52, &trinity->node->ack_seq, 4);

  if (!part->is_forwarded_part) {
    memcpy(msg_chunk + MSG_INSTRUCTIONS_SIZE,
           part->e2e_msg_part.mac_e,
           MSG_MAC_SIZE);
    sodium_add(msg_chunk + MSG_INSTRUCTIONS_SIZE,
               (unsigned char *)&part->chunk_offset,
               sizeof(uint16_t));
    log_debug(LOG_MESSAGE,
              part->e2e_msg_part.uuid,
              "modified base message chunk %" PRIu16,
              *(uint16_t *)(msg_chunk + MSG_INSTRUCTIONS_SIZE));
    memcpy(msg_chunk + MSG_INSTRUCTIONS_SIZE + MSG_MAC_SIZE,
           part->e2e_msg_part.msg_header,
           MSG_HEADER_SIZE);
    memcpy(msg_chunk + MSG_INSTRUCTIONS_SIZE + MSG_MAC_SIZE + MSG_HEADER_SIZE,
           part->e2e_msg_part.msg_body,
           MSG_CHUNK_SIZE_1024 - MSG_HEADER_SIZE - MSG_MAC_SIZE -
               MSG_NONCE_SIZE);
    memcpy(msg_chunk + MSG_INSTRUCTIONS_SIZE + MSG_CHUNK_SIZE_1024 -
               MSG_NONCE_SIZE,
           part->e2e_msg_part.nonce,
           MSG_NONCE_SIZE);
    if (part->chunk_offset > 0)
      sodium_sub(msg_chunk + MSG_INSTRUCTIONS_SIZE + MSG_CHUNK_SIZE_1024 -
                     MSG_NONCE_SIZE,
                 (unsigned char *)&part->chunk_offset,
                 sizeof(uint16_t));
  }
}

void __np_node_send_direct(np_util_statemachine_t *statemachine,
                           const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);
  NP_CAST(event.user_data, struct np_n2n_messagepart_s, hs_messagepart);

  struct __np_node_trinity trinity = {0};
  __np_key_to_trinity(node_key, &trinity);

  if (trinity.network == NULL) return;

  hs_messagepart->seq = trinity.network->seqend++;

  _np_node_build_network_packet(hs_messagepart);

  char *packet = hs_messagepart->msg_chunk;

  log_info(LOG_MESSAGE, hs_messagepart->e2e_msg_part.uuid, "sending msg part");

  _LOCK_ACCESS(&trinity.network->access_lock) {

    np_ref_obj(BLOB_1024, packet, ref_obj_usage);
    sll_append(void_ptr, trinity.network->out_events, (void *)packet);

    log_trace(LOG_TRACE,
              hs_messagepart->e2e_msg_part.uuid,
              "start: void __np_node_send_direct(...) { %d",
              sll_size(trinity.network->out_events));
  }

  _np_network_start(trinity.network, false);
  _np_event_invoke_out(context);

  if (!hs_messagepart->is_forwarded_part) {
    np_unref_obj(BLOB_1024, hs_messagepart->msg_chunk, ref_obj_creation);
  }
}

void __np_node_split_message(np_util_statemachine_t *statemachine,
                             const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);
  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  NP_CAST(event.user_data, struct np_e2e_message_s, default_msg);
  struct __np_node_trinity trinity = {0};
  __np_key_to_trinity(node_key, &trinity);

  if (default_msg->state == msgstate_binary) {
    _np_message_serialize_chunked(context, default_msg);
  }
  assert(default_msg->state == msgstate_chunked);

  for (uint16_t i = 0; i < *default_msg->parts; i++) {
    log_debug(LOG_ROUTING,
              default_msg->uuid,
              "sending message part %" PRIu16 " to hop %s",
              i,
              _np_key_as_str(node_key));

    struct np_n2n_messagepart_s *msg_part   = default_msg->msg_chunks[i];
    np_util_event_t              send_event = event;
    send_event.user_data                    = msg_part;

    _np_event_runtime_add_event(context,
                                event.current_run,
                                node_key->dhkey,
                                send_event);
  }
}

void __np_node_send_encrypted(np_util_statemachine_t *statemachine,
                              const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);
  NP_CAST(event.user_data, struct np_n2n_messagepart_s, msg_part);

  struct __np_node_trinity trinity = {0};
  __np_key_to_trinity(node_key, &trinity);

  // encryption destroys the message uuid, bad for logging
  char tmp_uuid[NP_UUID_BYTES] = {0};
  memcpy(tmp_uuid, msg_part->e2e_msg_part.uuid, NP_UUID_BYTES);

  np_crypto_session_t crypto_session = _np_key_get_node(node_key)->session;
  if (!crypto_session.session_key_to_write_is_set) {
    log_msg(LOG_WARNING,
            msg_part->e2e_msg_part.uuid,
            "crypto session not set, not sending messagepart");
    return; // TODO: this is happening ... Check if we could prevent this
  } else {
    log_debug(LOG_ROUTING, tmp_uuid, "fetched crypto session to %p", node_key);
  }

  if (trinity.network == NULL) return;

  // memcpy(packet + 0, &mac_n, 16);
  msg_part->seq = trinity.network->seqend++;
  // memcpy(packet + 16, &trinity.node->rlnc_n, 32);
  // memcpy(packet + 52, &trinity->node->ack_seq, 4);

  _np_node_build_network_packet(msg_part);
  unsigned char *packet = msg_part->msg_chunk;

  int encryption = -1;

  log_debug(LOG_MESSAGE,
            tmp_uuid,
            "using shared secret from target %s on "
            "system %s to encrypt data",
            _np_key_as_str(node_key),
            _np_key_as_str(context->my_node_key));

  encryption = np_crypto_session_encrypt(
      context,
      &crypto_session,
      packet + MSG_MAC_SIZE, // encrypt header
      MSG_INSTRUCTIONS_SIZE + MSG_CHUNK_SIZE_1024 - MSG_MAC_SIZE -
          MSG_NONCE_SIZE,
      packet, // store mac for messages
      MSG_MAC_SIZE,
      packet + MSG_MAC_SIZE, // data to encrypt (msg header + body)
      MSG_INSTRUCTIONS_SIZE + MSG_CHUNK_SIZE_1024 - MSG_MAC_SIZE -
          MSG_NONCE_SIZE,
      NULL, // adversary data to protect
      0,
      packet + MSG_INSTRUCTIONS_SIZE + MSG_CHUNK_SIZE_1024 - MSG_NONCE_SIZE);

  if (encryption != 0) {
    log_msg(LOG_ERROR,
            tmp_uuid,
            "incorrect encryption of message (not sending to %s:%s)",
            trinity.node->ip_string,
            trinity.node->port);
  } else {
    /* send data */
    if (NULL != trinity.network->out_events) {
      /*
      #ifdef DEBUG
                  char tmp_hex[MSG_CHUNK_SIZE_1024*2+1] = { 0 };
                  sodium_bin2hex(tmp_hex, MSG_CHUNK_SIZE_1024*2+1, enc_buffer,
      MSG_CHUNK_SIZE_1024); log_debug(LOG_MESSAGE,
                      "(msg: %s) appending to eventqueue (part: %"PRIu16"/%p)
      %p
      (%d bytes) to queue for %s:%s, hex: 0x%.5s...%s", part->uuid,
      part->part+1, part, enc_buffer, MSG_CHUNK_SIZE_1024,
      trinity.node->dns_name, trinity.node->port,tmp_hex, tmp_hex +
      strlen(tmp_hex) -5
                  );
      #endif // DEBUG
      */
      log_debug(LOG_ROUTING,
                tmp_uuid,
                "sending message part: %" PRIu16 " / %p to %s:%s / %s",
                msg_part->chunk_offset,
                packet,
                trinity.network->ip,
                trinity.network->port,
                _np_key_as_str(node_key));

      _LOCK_ACCESS(&trinity.network->access_lock) {
        np_ref_obj(BLOB_1024, msg_part->msg_chunk, ref_obj_usage);
        sll_append(void_ptr, trinity.network->out_events, (void *)packet);
      }

      _np_network_start(trinity.network, false);
      _np_event_invoke_out(context);

    } else {
      log_info(LOG_MESSAGE,
               tmp_uuid,
               "Dropping part of msg due to uninitialized network");
    }
  }

  if (!msg_part->is_forwarded_part) {
    np_unref_obj(BLOB_1024, msg_part->msg_chunk, ref_obj_creation);
  }
}

bool __is_new_np_messagepart(np_util_statemachine_t *statemachine,
                             const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);
  NP_CAST(event.user_data, struct np_n2n_messagepart_s, msg_part);

  np_node_t *node = _np_key_get_node(node_key);

  // check for duplicate message sending (outbound)
  char _additional_data[64] = {0};
  memcpy(_additional_data, msg_part->e2e_msg_part.uuid, NP_UUID_BYTES);
  memcpy(_additional_data + NP_UUID_BYTES,
         msg_part->e2e_msg_part.nonce,
         MSG_NONCE_SIZE);
  memcpy(_additional_data + NP_UUID_BYTES + MSG_NONCE_SIZE,
         &msg_part->chunk_offset,
         sizeof(uint16_t));

  np_dhkey_t _cache_msg_id = *msg_part->e2e_msg_part.audience;
  np_generate_subject((np_subject *)&_cache_msg_id,
                      _additional_data,
                      NP_UUID_BYTES + MSG_NONCE_SIZE + sizeof(uint16_t));

  bool is_duplicate =
      node->msg_forward_filter->op.check_cb(node->msg_forward_filter,
                                            _cache_msg_id);

#ifdef DEBUG
  char buf[65], tmp[65];
  if (is_duplicate) {
    log_debug(
        LOG_MESSAGE,
        msg_part->e2e_msg_part.uuid,
        "not allowing message part to target %s, as msg was already send "
        "before "
        "(%s)",
        np_id_str(buf, (const unsigned char *)msg_part->e2e_msg_part.audience),
        np_id_str(tmp, (const unsigned char *)&_cache_msg_id));
  } else {
    log_debug(
        LOG_MESSAGE,
        msg_part->e2e_msg_part.uuid,
        "    allowing message part to target %s, as msg was not     send "
        "before "
        "(%s)",
        np_id_str(buf, (const unsigned char *)msg_part->e2e_msg_part.audience),
        np_id_str(tmp, (const unsigned char *)&_cache_msg_id));
  }
#endif

  return !is_duplicate;
}

void __np_node_discard_message(np_util_statemachine_t *statemachine,
                               const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);
  NP_CAST(event.user_data, np_messagepart_t, part);

  log_warn(LOG_ROUTING,
           part->uuid,
           "discarding message, node %s not in desired state. peer could be "
           "responding too slow",
           _np_key_as_str(node_key));
  // np_memory_free(context, part);
}

bool __is_np_message(np_util_statemachine_t *statemachine,
                     const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  if (!ret)
    ret = (FLAG_CMP(event.type, evt_internal) &&
           FLAG_CMP(event.type, evt_message));

  NP_CAST(statemachine->_user_data, np_key_t, node_key);
  if (ret) ret &= FLAG_CMP(node_key->type, np_key_type_node);
  if (ret) ret &= (event.user_data != NULL);
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);
  return ret;
}

bool __is_np_messagepart(np_util_statemachine_t *statemachine,
                         const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  if (!ret)
    ret = (FLAG_CMP(event.type, evt_internal) &&
           FLAG_CMP(event.type, evt_message));

  NP_CAST(statemachine->_user_data, np_key_t, node_key);
  if (ret) ret &= FLAG_CMP(node_key->type, np_key_type_node);
  if (ret) ret &= (event.user_data != NULL);
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data,
                                 np_memory_types_np_messagepart_t);
  if (ret) {
    ret &= __is_new_np_messagepart(statemachine, event);
  }
  if (ret) {
    NP_CAST(event.user_data, struct np_n2n_messagepart_s, msg_part);
    /* prevent handshake messages after initial node setup */
    np_dhkey_t hs_dhkey = {0};
    np_generate_subject(&hs_dhkey,
                        _NP_MSG_HANDSHAKE,
                        strnlen(_NP_MSG_HANDSHAKE, 256));
    ret &= (!_np_dhkey_equal(msg_part->e2e_msg_part.subject, &hs_dhkey));
  }
  return ret;
}

bool __is_handshake_message(np_util_statemachine_t *statemachine,
                            const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  NP_CAST(statemachine->_user_data, np_key_t, node_key);

  if (!ret)
    ret = (FLAG_CMP(event.type, evt_internal) &&
           FLAG_CMP(event.type, evt_message));
  if (ret)
    ret &= FLAG_CMP(node_key->type, np_key_type_wildcard) ||
           FLAG_CMP(node_key->type, np_key_type_node);
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data,
                                 np_memory_types_np_messagepart_t);
  if (ret) {
    NP_CAST(event.user_data, struct np_n2n_messagepart_s, hs_messagepart);
    np_dhkey_t handshake_dhkey = {0};
    np_generate_subject(&handshake_dhkey,
                        _NP_MSG_HANDSHAKE,
                        strnlen(_NP_MSG_HANDSHAKE, 256));

    ret &=
        _np_dhkey_equal(hs_messagepart->e2e_msg_part.subject, &handshake_dhkey);
  }

  return ret;
}

bool __is_invalid_message(np_util_statemachine_t *statemachine,
                          const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  if (!ret)
    ret = (FLAG_CMP(event.type, evt_message) &&
           FLAG_CMP(event.type, evt_internal));
  if (ret) ret &= (event.user_data != NULL);

  if (ret)
    ret &= _np_memory_rtti_check(event.user_data,
                                 np_memory_types_np_messagepart_t);

  return ret;
}

bool __is_join_out_message(np_util_statemachine_t *statemachine,
                           const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  if (!ret)
    ret = (FLAG_CMP(event.type, evt_message) &&
           FLAG_CMP(event.type, evt_internal));
  if (ret) ret &= (event.user_data != NULL);

  if (ret)
    ret &= _np_memory_rtti_check(event.user_data,
                                 np_memory_types_np_messagepart_t);
  if (ret) {
    NP_CAST(event.user_data, struct np_n2n_messagepart_s, join_message);
    np_dhkey_t join_dhkey = {0};
    np_generate_subject(&join_dhkey,
                        _NP_MSG_JOIN_REQUEST,
                        strnlen(_NP_MSG_JOIN_REQUEST, 256));
    np_dhkey_t leave_dhkey = {0};
    np_generate_subject(&leave_dhkey,
                        _NP_MSG_LEAVE_REQUEST,
                        strnlen(_NP_MSG_LEAVE_REQUEST, 256));
    ret &= (_np_dhkey_equal(join_message->e2e_msg_part.subject, &join_dhkey) ||
            _np_dhkey_equal(join_message->e2e_msg_part.subject, &leave_dhkey));
  }
  return ret;
}

void __np_node_handle_response(np_util_statemachine_t *statemachine,
                               const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, node_key);
  np_node_t *node = _np_key_get_node(node_key);

  node->success_win_index++;
  node->latency_win_index++;

  if (node->success_win_index == NP_NODE_SUCCESS_WINDOW)
    node->success_win_index = 0;

  if (node->latency_win_index == NP_NODE_SUCCESS_WINDOW)
    node->latency_win_index = 0;

  if (!FLAG_CMP(event.type, evt_timeout) &&
      !FLAG_CMP(event.type, evt_response)) {
    log_msg(LOG_INFO,
            NULL,
            "unknown responsehandler called, not doing any action ...");
    return;
  }

  NP_CAST(event.user_data, np_responsecontainer_t, response);

  if (FLAG_CMP(event.type, evt_timeout)) {
    node->success_win[node->success_win_index % NP_NODE_SUCCESS_WINDOW] = 0;
    node->latency_win[node->latency_win_index % NP_NODE_SUCCESS_WINDOW] =
        (response->expires_at - response->send_at);

  } else if (FLAG_CMP(event.type, evt_response)) {
    node->last_success = np_time_now();
    node->success_win[node->success_win_index % NP_NODE_SUCCESS_WINDOW] = 1;
    double new_latency_value = (response->received_at - response->send_at);
    if (node->latency == -1) {
      for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++) {
        node->latency_win[i] = new_latency_value;
      }
    }

    if (new_latency_value > 0.0) {
      node->latency_win[node->latency_win_index % NP_NODE_SUCCESS_WINDOW] =
          new_latency_value;
    } else {
      node->latency_win[node->latency_win_index % NP_NODE_SUCCESS_WINDOW] =
          node->latency;
    }
  }
}
