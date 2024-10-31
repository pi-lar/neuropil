// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project

// this file contains the state machine conditions, transitions and states that
// an identity can have. It is included form np_key.c, therefore there are no
// extra #include directives.

#include "core/np_comp_alias.h"

#include "inttypes.h"
#include "stdio.h"

#include "neuropil.h"
#include "neuropil_data.h"
#include "neuropil_log.h"

#include "core/np_comp_node.h"
#include "util/np_bloom.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"
#include "util/np_tree.h"

#include "np_aaatoken.h"
#include "np_eventqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_pheromones.h"
#include "np_route.h"
#include "np_statistics.h"

struct np_e2e_message_s *
_np_alias_check_msgpart_cache(np_state_t                  *context,
                              struct np_n2n_messagepart_s *msgpart_to_check) {

  struct np_e2e_message_s *ret = NULL;

#ifdef DEBUG
  // np_tree_elem_t *ele =
  //     np_tree_find_str(msg_to_check->header, _NP_MSG_HEADER_SUBJECT);
  // assert(ele != NULL);
  char subject[100] = {0};
  strncpy(subject, msgpart_to_check->e2e_msg_part.subject, 32);
#endif

  np_dhkey_t check_dhkey = {0};
  // needs to be aligned with the setup in np_comp_node.c
  // funtion _np_node_build_network_packet modifies the e2e mac of
  // followup pakets
  np_generate_subject(&check_dhkey,
                      msgpart_to_check->e2e_msg_part.uuid,
                      NP_UUID_BYTES);
  np_generate_subject(&check_dhkey,
                      msgpart_to_check->e2e_msg_part.mac_e + sizeof(uint16_t),
                      MSG_MAC_SIZE - sizeof(uint16_t));

  // Detect from instructions if this msg was orginally chunked
  bool _seen_before = true;
  _LOCK_MODULE(np_message_part_cache_t) {
    _seen_before =
        context->msg_part_filter->op.check_cb(context->msg_part_filter,
                                              check_dhkey);
  }

  uint16_t current_count_of_chunks = 0;

  if (!_seen_before) {
    if (*msgpart_to_check->e2e_msg_part.parts > 1) {
      _LOCK_MODULE(np_message_part_cache_t) {
        // if there exists multiple chunks, check if we already have one in
        // cache
        np_tree_elem_t *tmp =
            np_tree_find_dhkey(context->msg_part_cache, check_dhkey);
        if (NULL != tmp) {
          // there exists a msg(part) in our msgcache for this msg uuid
          // lets add our msgpart to this msg
          struct np_e2e_message_s *msg_in_cache = tmp->val.value.v;

          _np_message_add_chunk(msg_in_cache,
                                msgpart_to_check,
                                &current_count_of_chunks);

          log_debug(LOG_MESSAGE,
                    msg_in_cache->uuid,
                    "message %p / %p",
                    msg_in_cache,
                    msg_in_cache->msg_chunks);

          if (current_count_of_chunks != *msg_in_cache->parts) {
            log_debug(LOG_MESSAGE,
                      msg_in_cache->uuid,
                      "message not complete yet (%" PRIu32 " of %" PRIu16
                      "), waiting for missing parts",
                      current_count_of_chunks,
                      *msg_in_cache->parts);
            // nothing to return as we still wait for chunks
          } else {

            log_debug(LOG_MESSAGE,
                      msg_in_cache->uuid,
                      "message is complete now  (%" PRIu32 " of %" PRIu16 ")",
                      current_count_of_chunks,
                      *msg_in_cache->parts);

            ret = msg_in_cache;
            // removing the message from the cache system
            ref_replace_reason(np_message_t,
                               msg_in_cache,
                               ref_msgpartcache,
                               FUNC);
            context->msg_part_filter->op.add_cb(context->msg_part_filter,
                                                check_dhkey);
            np_tree_del_dhkey(context->msg_part_cache, check_dhkey);
          }
        } else {
          // there exists no msg(part) in our msgcache for this msg uuid
          // TODO: limit msg_part_cache size

          // there is no chunk for this msg in cache,
          // so we insert this message into out cache
          // as a structure to accumulate further chunks into
          np_new_obj(np_message_t, ret, ref_msgpartcache);
          // we need to unref this after we finish
          // the handling of this msg
          _np_message_add_chunk(ret,
                                msgpart_to_check,
                                &current_count_of_chunks);

          // TODO: increase buffer size of the first message to keep all other
          // parts as well
          np_tree_insert_dhkey(context->msg_part_cache,
                               check_dhkey,
                               np_treeval_new_v(ret));
          log_debug(LOG_MESSAGE,
                    msgpart_to_check->e2e_msg_part.uuid,
                    "message is in msgpartcache now, total of %" PRIu32
                    " chunks expected",
                    *msgpart_to_check->e2e_msg_part.parts);
          ret = NULL;
        }
      }
    } else {
      // If this is the only chunk, then return it as is
      log_debug(LOG_MESSAGE,
                msgpart_to_check->e2e_msg_part.uuid,
                "message is unchunked");
      np_new_obj(np_message_t, ret, FUNC);
      _np_message_add_chunk(ret, msgpart_to_check, &current_count_of_chunks);

      _LOCK_MODULE(np_message_part_cache_t) {
        context->msg_part_filter->op.add_cb(context->msg_part_filter,
                                            check_dhkey);
      }
    }
  } else {
    log_debug(LOG_MESSAGE,
              msgpart_to_check->e2e_msg_part.uuid,
              "discarding message (%" PRIu16
              " parts) because it was handled before",
              *msgpart_to_check->e2e_msg_part.parts);
    ret = NULL;
  }
  return ret;
}

bool _np_alias_cleanup_msgpart_cache(np_state_t               *context,
                                     NP_UNUSED np_util_event_t event) {
  np_sll_t(np_dhkey_t, to_del);
  sll_init(np_dhkey_t, to_del);

  _LOCK_MODULE(np_message_part_cache_t) {
    if (context->msg_part_cache->size > 0) {
      log_debug(
          LOG_MISC,
          NULL,
          "MSG_PART_TABLE checking (left-over) message parts (size: %" PRIsizet
          ")",
          context->msg_part_cache->size);
      np_tree_elem_t *tmp = NULL;
      RB_FOREACH (tmp, np_tree_s, context->msg_part_cache) {
        struct np_e2e_message_s *msg = tmp->val.value.v;
        if (true == _np_message_is_expired(msg)) {
          log_info(LOG_MISC,
                   msg->uuid,
                   "MSG_PART_TABLE removing (left-over) message part");
          np_unref_obj(np_message_t, msg, ref_msgpartcache);
          sll_append(np_dhkey_t, to_del, tmp->key.value.dhkey);
        }
      }
    }
    _np_decaying_bloom_decay(context->msg_part_filter);
    sll_iterator(np_dhkey_t) iter = sll_first(to_del);
    while (NULL != iter) {
      np_tree_del_dhkey(context->msg_part_cache, iter->val);
      sll_next(iter);
    }
  }
  sll_free(np_dhkey_t, to_del);

  uint16_t _peer_nodes = _np_route_my_key_count_routes(context) +
                         _np_route_my_key_count_neighbors(context, NULL, NULL);
  uint8_t _size_modifier = floor(cbrt(_peer_nodes));

  _LOCK_MODULE(np_message_part_cache_t) {
    log_debug(LOG_MISC,
              NULL,
              "MSG_PART_TABLE duplicate check has currently space for: %" PRIu16
              " items (s: %" PRIsizet " / p: %" PRIu8 ")",
              context->msg_part_filter->_free_items,
              context->msg_part_filter->_size,
              context->msg_part_filter->_p);

    size_t _size_adjustment = NP_MSG_PART_FILTER_SIZE;
    if (_size_modifier > 0)
      _size_adjustment = _size_modifier * NP_MSG_PART_FILTER_SIZE;
    if (context->msg_part_filter->_size != _size_adjustment) {
      context->msg_part_filter->_size = _size_adjustment;
      context->msg_part_filter->op.clear_cb(context->msg_part_filter);
      log_debug(
          LOG_MISC,
          NULL,
          "MSG_PART_TABLE duplicate check adjusted, now using size: %" PRIsizet,
          _size_adjustment);
    }

    uint8_t _prune_adjustment = 1;
    if (_size_modifier > _prune_adjustment) _prune_adjustment = _size_modifier;
    if (context->msg_part_filter->_p != _prune_adjustment) {
      context->msg_part_filter->_p = _prune_adjustment;
      log_debug(
          LOG_MISC,
          NULL,
          "MSG_PART_TABLE duplicate check adjusted, now using bit-pruning: %d)",
          _prune_adjustment);
    }
  }

  return true;
}

bool __is_alias_handshake_token(np_util_statemachine_t *statemachine,
                                const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  if (!ret)
    ret = FLAG_CMP(event.type, evt_token) && FLAG_CMP(event.type, evt_external);
  if (ret)
    ret &=
        _np_memory_rtti_check(event.user_data, np_memory_types_np_aaatoken_t);
  if (ret) {
    NP_CAST(event.user_data, np_aaatoken_t, hs_token);
    ret &= (hs_token->type == np_aaatoken_type_handshake);
    if (ret && hs_token->issuer != NULL) {
      np_dhkey_t issuer_dhkey = {0};
      np_str_id(&issuer_dhkey, hs_token->issuer);

      ret &= !_np_dhkey_equal(&issuer_dhkey, &event.__source_dhkey);
    }
    ret &= _np_aaatoken_is_valid(context, hs_token, hs_token->type);
  }
  return ret;
}

void __np_alias_set(np_util_statemachine_t *statemachine,
                    const np_util_event_t   event) {
  // handle internal received handshake token
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, peer_alias_key);
  NP_CAST(event.user_data, np_aaatoken_t, handshake_token);

  if (!FLAG_CMP(peer_alias_key->type, np_key_type_alias)) {
    peer_alias_key->type |= np_key_type_alias;
    np_ref_obj(np_key_t, peer_alias_key, "__np_alias_set");
  }

  // fix TCP setup and set correct key
  np_network_t *peer_alias_network = _np_key_get_network(peer_alias_key);
  if (peer_alias_network != NULL) {
    log_info(LOG_NETWORK, "_np_network_stop %s", FUNC);
    _np_network_stop(peer_alias_network, true);
    ref_replace_reason(np_network_t,
                       peer_alias_network,
                       ref_obj_creation,
                       "__np_alias_set");
    _np_network_set_key(peer_alias_network, peer_alias_key->dhkey);
    _np_network_start(peer_alias_network, true);
  }

  if (peer_alias_key->entity_array[e_handshake_token] == NULL) {
    peer_alias_key->entity_array[e_handshake_token] = handshake_token;
    np_ref_obj(np_aaatoken_t, handshake_token, "__np_alias_set");
  }
  np_dhkey_t search_key = {0};
  _np_str_dhkey(handshake_token->issuer, &search_key);

  log_msg(LOG_DEBUG,
          NULL,
          "setup of alias %p (%u)",
          peer_alias_key,
          statemachine->_current_state);

  np_node_t *peer_alias_node    = NULL;
  np_key_t  *peer_interface_key = _np_keycache_find(context, search_key);
  if (NULL == peer_interface_key) {
    // TODO: check if this code gets executed ever ...
    peer_alias_node = peer_alias_key->entity_array[e_nodeinfo];
    if (peer_alias_node == NULL) {
      peer_alias_node =
          _np_node_from_token(handshake_token, handshake_token->type);
      ref_replace_reason(np_node_t,
                         peer_alias_node,
                         "_np_node_from_token",
                         "__np_alias_set");
      peer_alias_key->entity_array[e_nodeinfo] = peer_alias_node;
    }

  } else {
    peer_alias_key->parent_dhkey = peer_interface_key->dhkey;

    peer_alias_node = peer_alias_key->entity_array[e_nodeinfo];
    if (NULL != peer_alias_node &&
        peer_alias_node != _np_key_get_node(peer_interface_key)) {
      np_unref_obj(np_node_t, peer_alias_node, "__np_alias_set");
      peer_alias_node = _np_key_get_node(peer_interface_key);
      np_ref_obj(np_node_t, peer_alias_node, "__np_alias_set");
      peer_alias_key->entity_array[e_nodeinfo] = peer_alias_node;

    } else if (NULL == peer_alias_node) {
      peer_alias_node = _np_key_get_node(peer_interface_key);
      if (peer_alias_node != NULL) {
        np_ref_obj(np_node_t, peer_alias_node, "__np_alias_set");
        peer_alias_key->entity_array[e_nodeinfo] = peer_alias_node;
      }
    }
    log_msg(LOG_DEBUG,
            NULL,
            "start: void __np_alias_set(...) %p / %p {",
            peer_interface_key,
            peer_alias_node);
  }

  // fetch own outgoing interface
  char local_ip[64] = {0};
  _np_network_get_outgoing_ip(NULL,
                              peer_alias_node->ip_string,
                              peer_alias_node->protocol,
                              local_ip);
  np_key_t *my_interface_key =
      _np_keycache_find_interface(context, local_ip, NULL);
  np_node_t *my_interface_node = _np_key_get_node(my_interface_key);

  // check node key for passive network connection (partner or own node is
  // passive)
  if (NULL != peer_interface_key && NULL != my_interface_node &&
      (FLAG_CMP(peer_alias_node->protocol, PASSIVE) ||
       FLAG_CMP(my_interface_node->protocol, PASSIVE))) {
    // take over existing network if partner is passive
    log_debug(LOG_NETWORK,
              NULL,
              "try to take over existing network (passive mode)");
    struct __np_node_trinity node_trinity = {0};
    __np_key_to_trinity(peer_interface_key, &node_trinity);
    if (NULL != node_trinity.network) {
      log_debug(LOG_NETWORK, NULL, "take over existing network (passive mode)");
      if (peer_alias_key->entity_array[e_network] != node_trinity.network) {
        log_info(LOG_NETWORK, "_np_network_stop %s", FUNC);
        _np_network_stop(node_trinity.network, true);
        np_ref_obj(np_network_t, node_trinity.network, "__np_alias_set");
        peer_alias_key->entity_array[e_network] = node_trinity.network;
        // set our key to receive and decrypt messages
        _np_network_start(peer_alias_key->entity_array[e_network], true);
      }
      _np_network_set_key(peer_alias_key->entity_array[e_network],
                          peer_alias_key->dhkey);
    }
  }

  if (NULL != peer_interface_key)
    np_unref_obj(np_key_t, peer_interface_key, "_np_keycache_find");

  if (NULL != my_interface_key)
    np_unref_obj(np_key_t, my_interface_key, "_np_keycache_find_interface");

  handshake_token->state = AAA_VALID;
}

bool __is_unused(np_util_statemachine_t *statemachine,
                 const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);
  NP_CAST(statemachine->_user_data, np_key_t, key);

  return (key->last_update + BAD_LINK_REMOVE_GRACETIME) < np_time_now();
}

void __np_alias_set_node_destroy(np_util_statemachine_t *statemachine,
                                 const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);

  log_info(LOG_EXPERIMENT,
           NULL,
           "removing leftover node key: %s",
           _np_key_as_str(alias_key));

  np_unref_obj(np_node_t,
               alias_key->entity_array[e_nodeinfo],
               "__np_alias_set");

  if (FLAG_CMP(alias_key->type, np_key_type_alias)) {
    np_unref_obj(np_key_t, alias_key, "__np_alias_set");
  }
}

bool __is_alias_node_info(np_util_statemachine_t *statemachine,
                          const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  if (!ret) ret = FLAG_CMP(event.type, evt_external);
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_node_t);
  if (ret) {
    NP_CAST(event.user_data, np_node_t, my_node);
    ret &= _np_node_check_address_validity(my_node);
  }

  return ret;
}

void __np_alias_set_node(np_util_statemachine_t *statemachine,
                         const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);
  NP_CAST(event.user_data, np_node_t, node);

  log_trace_msg(LOG_TRACE,
                "start: void __np_alias_set_node(...) { %s:%s",
                node->ip_string,
                node->port);

  if (alias_key->entity_array[e_nodeinfo] == NULL) {
    if (!FLAG_CMP(alias_key->type, np_key_type_alias)) {
      alias_key->type |= np_key_type_alias;
      np_ref_obj(np_key_t, alias_key, "__np_alias_set");
    }

    log_debug(LOG_ROUTING,
              NULL,
              "created new alias structure %s / %s",
              node->ip_string,
              node->port);

    np_ref_obj(np_node_t, node, "__np_alias_set");
    alias_key->entity_array[e_nodeinfo] = node;
  }
}

void __np_create_session(np_util_statemachine_t         *statemachine,
                         NP_UNUSED const np_util_event_t event) {

  // create crypto session
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);

  np_aaatoken_t *handshake_token = alias_key->entity_array[e_handshake_token];
  np_node_t     *alias_node      = alias_key->entity_array[e_nodeinfo];

  // fetch own outgoing interface
  char outgoing_ip[64] = {0};
  _np_network_get_outgoing_ip(NULL,
                              alias_node->ip_string,
                              alias_node->protocol,
                              outgoing_ip);
  np_key_t *interface_key =
      _np_keycache_find_interface(context, outgoing_ip, NULL);
  if (interface_key == NULL) {
    interface_key =
        _np_keycache_find_interface(context, context->main_ip, NULL);
  }

  np_aaatoken_t *my_token = interface_key->entity_array[e_aaatoken];
  np_node_t     *my_node  = _np_key_get_node(interface_key);

  // HAS TO BE be there
  struct np_data_conf cfg;
  np_data_value       remote_hs_prio = {0};

  if (np_get_data(handshake_token->attributes,
                  NP_HS_PRIO,
                  &cfg,
                  &remote_hs_prio) != np_ok) {
    log_error(handshake_token->uuid,
              "structural error in token. Missing %s key",
              NP_HS_PRIO);
  }

  TSP_SCOPE(alias_node->session_key_is_set) {

    if (remote_hs_prio.unsigned_integer < my_node->handshake_priority) {
      np_crypto_session(context,
                        &my_token->crypto,
                        &alias_node->session,
                        &handshake_token->crypto,
                        false);
      log_info(LOG_AAATOKEN,
               handshake_token->uuid,
               "handshake session created in server mode. remote-prio: %" PRIu32
               " local-prio: %" PRIu32 " %p ",
               remote_hs_prio.unsigned_integer,
               my_node->handshake_priority,
               handshake_token);
    } else {
      np_crypto_session(context,
                        &my_token->crypto,
                        &alias_node->session,
                        &handshake_token->crypto,
                        true);
      log_info(LOG_AAATOKEN,
               handshake_token->uuid,
               "handshake session created in client mode. remote-prio: %" PRIu32
               " local-prio: %" PRIu32 " %p ",
               remote_hs_prio.unsigned_integer,
               my_node->handshake_priority,
               handshake_token);
    }
    log_info(LOG_AAATOKEN,
             handshake_token->uuid,
             "session %s %s _handshake_status",
             FUNC,
             alias_node->ip_string);
    // enum np_node_status old_e = alias_node->_handshake_status;
    // alias_node->_handshake_status = np_node_status_WaitForConfirmation;
    // log_info(LOG_HANDSHAKE,"set %s %s _handshake_status: %"PRIu8" -> %"PRIu8,
    //     FUNC, alias_node->dns_name, old_e , alias_node->_handshake_status
    // );
    alias_node->session_key_is_set = true;
  }
  if (NULL != interface_key)
    np_unref_obj(np_key_t, interface_key, "_np_keycache_find_interface");
}

bool __is_crypted_message(np_util_statemachine_t *statemachine,
                          const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);
  if (!ret) ret = FLAG_CMP(alias_key->type, np_key_type_alias);
  if (ret) ret &= FLAG_CMP(event.type, evt_message);
  if (ret) ret &= (FLAG_CMP(event.type, evt_external));
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data, np_memory_types_BLOB_1024);
  // if ( ret) ret &=
  // TODO: check crypto signature of incomming message
  // TODO: check increasing counter of partner node

  return ret;
}

void __np_alias_decrypt(
    np_util_statemachine_t *statemachine,
    const np_util_event_t   event) { // decrypt transport encryption
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);
  NP_CAST(event.user_data, unsigned char, packet);

  TSP_GET(bool,
          _np_key_get_node(alias_key)->session_key_is_set,
          session_key_is_set);

  if (!session_key_is_set) {
    log_error(NULL,
              "%s",
              "received message before crypto session setup completed");
    return;
  }

  np_crypto_session_t *crypto_session = &_np_key_get_node(alias_key)->session;
  if (!crypto_session->session_key_to_read_is_set)
    return; // TODO: this is happening ... Check if we could prevent this
  else {
    log_debug(LOG_ROUTING, NULL, "fetched crypto session to %p", alias_key);
  }

  log_debug(LOG_ROUTING,
            NULL,
            "/start decrypting message with alias %s",
            _np_key_as_str(alias_key));

#ifdef DEBUG
  char msg_hex[2 * (MSG_INSTRUCTIONS_SIZE + MSG_CHUNK_SIZE_1024) + 1];
  sodium_bin2hex(msg_hex,
                 2 * (MSG_INSTRUCTIONS_SIZE + MSG_CHUNK_SIZE_1024) + 1,
                 packet,
                 MSG_INSTRUCTIONS_SIZE + MSG_CHUNK_SIZE_1024);
  log_debug(LOG_MESSAGE, NULL, "Try to decrypt data: 0x%s", msg_hex);
#endif

  int crypto_result = np_crypto_session_decrypt(
      context,
      crypto_session,
      packet + MSG_MAC_SIZE,
      MSG_INSTRUCTIONS_SIZE + MSG_CHUNK_SIZE_1024 - MSG_MAC_SIZE -
          MSG_NONCE_SIZE,
      packet,
      MSG_MAC_SIZE,
      packet + MSG_MAC_SIZE,
      MSG_INSTRUCTIONS_SIZE + MSG_CHUNK_SIZE_1024 - MSG_MAC_SIZE -
          MSG_NONCE_SIZE,
      NULL,
      0,
      packet + MSG_INSTRUCTIONS_SIZE + MSG_CHUNK_SIZE_1024 - MSG_NONCE_SIZE);

  log_debug(LOG_MESSAGE,
            np_memory_get_id(alias_key),
            "using shared secret from source %s "
            "= %" PRIi32 " to decrypt data",
            _np_key_as_str(alias_key),
            crypto_result);

  if (crypto_result != 0) {
    log_info(LOG_MESSAGE,
             NULL,
             "incorrect decryption of message send from %s",
             _np_key_as_str(alias_key));
    return;
  }

  struct np_n2n_messagepart_s *part;
  np_new_obj(np_messagepart_t, part);

  if (!_np_message_deserialize_header_and_instructions(event.user_data, part)) {
    log_debug(LOG_SERIALIZATION,
              NULL,
              "incorrect header deserialization of message send from %s",
              _np_key_as_str(alias_key));
    np_unref_obj(np_messagepart_t, part, ref_obj_creation);
    return;
  }

  // TODO: compare sequence number and check for increase

  log_debug(LOG_SERIALIZATION,
            part->e2e_msg_part.uuid,
            "correct header deserialization of message");

  np_util_event_t in_message_evt = {.type      = (evt_external | evt_message),
                                    .user_data = part,
                                    .target_dhkey = alias_key->dhkey};

  if (!np_jobqueue_submit_event(context,
                                0,
                                alias_key->dhkey,
                                in_message_evt,
                                "urn:np:message:toalias")) {
    _np_event_runtime_add_event(context,
                                event.current_run,
                                alias_key->dhkey,
                                in_message_evt);
  }
  np_unref_obj(np_messagepart_t, part, ref_obj_creation);
}

bool __is_msgpart_expired(const struct np_n2n_messagepart_s *part) {
  np_ctx_memory(part);
  double   now    = np_time_now();
  double   tstamp = 0.0;
  uint32_t ttl    = 0;
  memcpy(&tstamp, part->e2e_msg_part.tstamp, sizeof(double));
  memcpy(&ttl, part->e2e_msg_part.ttl, sizeof(uint32_t));

  return (now < (tstamp + ttl));
}

bool __is_join_in_message(np_util_statemachine_t *statemachine,
                          const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);
  if (!ret) ret = FLAG_CMP(alias_key->type, np_key_type_alias);
  if (ret)
    ret &= (FLAG_CMP(event.type, evt_message) &&
            FLAG_CMP(event.type, evt_external));
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
    ret &= __is_msgpart_expired(join_message);
    ret &= (_np_dhkey_equal(join_message->e2e_msg_part.subject, &join_dhkey)) ||
           (_np_dhkey_equal(join_message->e2e_msg_part.subject, &leave_dhkey));
  }
  return ret;
}

bool __is_forward_message(np_util_statemachine_t *statemachine,
                          const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);
  if (!ret) ret = FLAG_CMP(alias_key->type, np_key_type_alias);
  if (ret)
    ret &=
        FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
  if (ret) ret &= (event.user_data != NULL);
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data,
                                 np_memory_types_np_messagepart_t);
  if (ret) {
    np_node_t *alias_node = _np_key_get_node(alias_key);

    ret = (alias_node != NULL &&
           (alias_node->is_in_leafset || alias_node->is_in_routing_table));
  }

  if (ret) {
    NP_CAST(event.user_data, struct np_n2n_messagepart_s, forward_message);
    /* TODO: use the bloom, luke */
    // messagepart is not addressed to our node --> forward
    ret &= __is_msgpart_expired(forward_message);
    ret &= !_np_dhkey_equal(&context->my_node_key->dhkey,
                            forward_message->e2e_msg_part.audience);
    log_trace(LOG_MESSAGE,
              ((struct np_e2e_message_s *)event.user_data)->uuid,
              "message %s return: %" PRIu8,
              FUNC,
              ret);
  }

  return ret;
}

bool __is_discovery_message(np_util_statemachine_t *statemachine,
                            const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = __is_forward_message(statemachine, event);
  if (ret) {
    NP_CAST(event.user_data, struct np_n2n_messagepart_s, discovery_message);
    /* TODO: use the bloom, luke */
    ret &= __is_msgpart_expired(discovery_message);

    np_dhkey_t avail_recv_dhkey = {0};
    np_generate_subject((np_subject *)&avail_recv_dhkey,
                        _NP_MSG_AVAILABLE_RECEIVER,
                        strnlen(_NP_MSG_AVAILABLE_RECEIVER, 256));
    np_dhkey_t avail_send_dhkey = {0};
    np_generate_subject((np_subject *)&avail_send_dhkey,
                        _NP_MSG_AVAILABLE_SENDER,
                        strnlen(_NP_MSG_AVAILABLE_SENDER, 256));
    // use the bloom to exclude other message types
    ret &= (_np_dhkey_equal(discovery_message->e2e_msg_part.subject,
                            &avail_recv_dhkey)) ||
           (_np_dhkey_equal(discovery_message->e2e_msg_part.subject,
                            &avail_send_dhkey));
    log_trace(LOG_MESSAGE,
              ((struct np_e2e_message_s *)event.user_data)->uuid,
              "message %s return: %" PRIu8,
              FUNC,
              ret);
  }

  return ret;
}

bool __is_pheromone_message(np_util_statemachine_t *statemachine,
                            const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);
  if (!ret) ret = FLAG_CMP(alias_key->type, np_key_type_alias);
  if (ret)
    ret &=
        FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
  if (ret) ret &= (event.user_data != NULL);
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data,
                                 np_memory_types_np_messagepart_t);
  if (ret) {
    np_node_t *alias_node = _np_key_get_node(alias_key);

    ret = (alias_node != NULL &&
           (alias_node->is_in_leafset || alias_node->is_in_routing_table));
  }

  if (ret) {
    NP_CAST(event.user_data, struct np_n2n_messagepart_s, pheromone_message);

    ret &= __is_msgpart_expired(pheromone_message);

    np_dhkey_t pheromone_dhkey = {0};
    np_generate_subject((np_subject *)&pheromone_dhkey,
                        _NP_MSG_PHEROMONE_UPDATE,
                        strnlen(_NP_MSG_PHEROMONE_UPDATE, 256));
    ret &= (_np_dhkey_equal(pheromone_message->e2e_msg_part.subject,
                            &pheromone_dhkey));
    log_trace(LOG_MESSAGE,
              pheromone_message->e2e_msg_part->uuid,
              "message %s return: %" PRIu8,
              FUNC,
              ret);
  }

  return ret;
}

bool __is_dht_message(np_util_statemachine_t *statemachine,
                      const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);
  if (!ret) ret = FLAG_CMP(alias_key->type, np_key_type_alias);
  if (ret)
    ret &=
        FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
  if (ret) ret &= (event.user_data != NULL);
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data,
                                 np_memory_types_np_messagepart_t);

  if (ret) {
    np_node_t *alias_node = _np_key_get_node(alias_key);

    ret = (alias_node != NULL &&
           (alias_node->is_in_leafset || alias_node->is_in_routing_table));
  }

  if (ret) {
    NP_CAST(event.user_data, struct np_n2n_messagepart_s, dht_message);
    /* TODO: use the bloom, luke */

    np_dhkey_t ack_dhkey = {0};
    np_generate_subject((np_subject *)&ack_dhkey,
                        _NP_MSG_ACK,
                        strnlen(_NP_MSG_ACK, 256));
    np_dhkey_t ping_dhkey = {0};
    np_generate_subject((np_subject *)&ping_dhkey,
                        _NP_MSG_PING_REQUEST,
                        strnlen(_NP_MSG_PING_REQUEST, 256));
    np_dhkey_t piggy_dhkey = {0};
    np_generate_subject((np_subject *)&piggy_dhkey,
                        _NP_MSG_PIGGY_REQUEST,
                        strnlen(_NP_MSG_PIGGY_REQUEST, 256));
    np_dhkey_t update_dhkey = {0};
    np_generate_subject((np_subject *)&update_dhkey,
                        _NP_MSG_UPDATE_REQUEST,
                        strnlen(_NP_MSG_UPDATE_REQUEST, 256));
    np_dhkey_t leave_dhkey = {0};
    np_generate_subject((np_subject *)&leave_dhkey,
                        _NP_MSG_LEAVE_REQUEST,
                        strnlen(_NP_MSG_LEAVE_REQUEST, 256));

    ret &= (_np_dhkey_equal(dht_message->e2e_msg_part.subject, &ack_dhkey) ||
            _np_dhkey_equal(dht_message->e2e_msg_part.subject, &ping_dhkey) ||
            _np_dhkey_equal(dht_message->e2e_msg_part.subject, &piggy_dhkey) ||
            _np_dhkey_equal(dht_message->e2e_msg_part.subject, &update_dhkey) ||
            _np_dhkey_equal(dht_message->e2e_msg_part.subject, &leave_dhkey));
  }

  if (ret) {
    NP_CAST(event.user_data, struct np_n2n_messagepart_s, dht_message);
    ret &= __is_msgpart_expired(dht_message);
    ret &= _np_dhkey_equal(&context->my_node_key->dhkey,
                           dht_message->e2e_msg_part.audience);
    log_debug(LOG_MESSAGE,
              dht_message->e2e_msg_part.uuid,
              "message is %s DHT msg.",
              (ret ? "a " : "no"));
  }
  return ret;
}

bool __is_usr_in_message(np_util_statemachine_t *statemachine,
                         const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);
  if (!ret) ret = FLAG_CMP(alias_key->type, np_key_type_alias);
  if (ret)
    ret &=
        FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
  if (ret) ret &= (event.user_data != NULL);
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data,
                                 np_memory_types_np_messagepart_t);

  if (ret) {
    NP_CAST(event.user_data, struct np_n2n_messagepart_s, usr_message);

    ret &= __is_msgpart_expired(usr_message);

    np_msgproperty_conf_t *user_prop =
        _np_msgproperty_conf_get(context,
                                 INBOUND,
                                 *usr_message->e2e_msg_part.subject);
    ret &= (NULL != user_prop);
    if (ret) ret &= !user_prop->is_internal;
    if (ret) ret &= (user_prop->audience_type != NP_MX_AUD_VIRTUAL);

    // }
    log_trace(LOG_MESSAGE,
              usr_message->e2e_msg_part.uuid,
              "%s return: %" PRIu8,
              FUNC,
              ret);
  }

  return ret;
}

void __np_handle(np_util_statemachine_t *statemachine,
                 const np_util_event_t   event) {
  // handle ght messages (ping, piggy, ...)x
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(event.user_data, struct np_n2n_messagepart_s, msg_part);

  struct np_e2e_message_s *msg_to_use =
      _np_alias_check_msgpart_cache(context, msg_part);

  if (msg_to_use != NULL &&
      true == _np_message_deserialize_chunks(msg_to_use)) {

    np_dhkey_t subject_dhkey_in =
        _np_msgproperty_tweaked_dhkey(INBOUND, *msg_to_use->subject);
    np_util_event_t msg_event = event;
    msg_event.user_data       = msg_to_use;

    char buff[100] = {0};
    np_regenerate_subject(context, buff, 100, msg_to_use->subject);
    log_info(LOG_ROUTING,
             msg_to_use->uuid,
             "handling message for subject: %s %s",
             buff,
             np_id_str(buff, msg_to_use->audience));

    if (false == np_jobqueue_submit_event(context,
                                          0.0,
                                          subject_dhkey_in,
                                          msg_event,
                                          "event: full message in")) {
      _np_event_runtime_add_event(context,
                                  event.current_run,
                                  subject_dhkey_in,
                                  msg_event);
    }
    np_unref_obj(np_message_t, msg_to_use, "_np_alias_check_msgpart_cache");

  } else if (msg_to_use != NULL) {
    log_debug(LOG_MESSAGE, msg_to_use->uuid, "deleting defect message");
    np_unref_obj(np_message_t, msg_to_use, "_np_alias_check_msgpart_cache");
  }
}

void __np_handle_np_discovery(np_util_statemachine_t *statemachine,
                              const np_util_event_t   event) {
  // handle discovery messages (available_sender, available_receiver, ...)
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);
  NP_CAST(event.user_data, struct np_n2n_messagepart_s, message);

  // the value "event.target_dhkey" is set to an alias key when the request
  // has been forwarded from another node.
  np_dhkey_t      last_hop        = alias_key->parent_dhkey;
  np_util_event_t available_event = event;
  available_event.target_dhkey    = last_hop;

  // increase our pheromone trail by adding a stronger scent
  // TODO: move to np_dendrit.c and handle reply field as well
  np_dhkey_t avail_recv_dhkey = {0};
  np_dhkey_t avail_send_dhkey = {0};
  np_generate_subject((np_subject *)&avail_recv_dhkey,
                      _NP_MSG_AVAILABLE_RECEIVER,
                      strnlen(_NP_MSG_AVAILABLE_RECEIVER, 256));
  np_generate_subject((np_subject *)&avail_send_dhkey,
                      _NP_MSG_AVAILABLE_SENDER,
                      strnlen(_NP_MSG_AVAILABLE_SENDER, 256));

  bool find_receiver =
      _np_dhkey_equal(&avail_send_dhkey, message->e2e_msg_part.subject);
  bool find_sender =
      _np_dhkey_equal(&avail_recv_dhkey, message->e2e_msg_part.subject);

  bool _forward_discovery_msg =
      _np_pheromone_inhale_target(context,
                                  *message->e2e_msg_part.audience,
                                  last_hop,
                                  find_sender,
                                  find_receiver);

  if (_forward_discovery_msg) {

    char _buffer[101] = {0};
    np_regenerate_subject(context,
                          _buffer,
                          100,
                          message->e2e_msg_part.audience);
    log_info(LOG_ROUTING,
             message->e2e_msg_part.uuid,
             "invoke forwarding of message token (subject: %s parts: "
             "%" PRIu16 ")",
             _buffer,
             *message->e2e_msg_part.parts);

    message->is_forwarded_part = true;

    np_dhkey_t discover_out_dhkey =
        _np_msgproperty_tweaked_dhkey(OUTBOUND, *message->e2e_msg_part.subject);
    np_util_event_t discover_event = event;
    discover_event.target_dhkey    = last_hop;
    discover_event.type            = (evt_internal | evt_message);

    if (false == np_jobqueue_submit_event(context,
                                          0.0,
                                          discover_out_dhkey,
                                          discover_event,
                                          "event: forward discovery")) {
      _np_event_runtime_add_event(context,
                                  event.current_run,
                                  discover_out_dhkey,
                                  discover_event);
    }
  }

  np_dhkey_t lookup_key = {0};
  // check whether this node is interested in this kind of message
  if (find_receiver) {
    log_debug(LOG_ROUTING,
              message->e2e_msg_part.uuid,
              "lookup receiver for message token, subject %08" PRIx32
              ":%08" PRIx32 " in keycache",
              (*message->e2e_msg_part.audience).t[0],
              (*message->e2e_msg_part.audience).t[1]);
    lookup_key =
        _np_msgproperty_tweaked_dhkey(INBOUND, *message->e2e_msg_part.audience);
  }
  if (find_sender) {
    log_debug(LOG_ROUTING,
              message->e2e_msg_part.uuid,
              "lookup sender for message token, subject %08" PRIx32
              ":%08" PRIx32 " in keycache",
              (*message->e2e_msg_part.audience).t[0],
              (*message->e2e_msg_part.audience).t[1]);
    lookup_key = _np_msgproperty_tweaked_dhkey(OUTBOUND,
                                               *message->e2e_msg_part.audience);
  }

  np_key_t *subject_key = _np_keycache_find(context, lookup_key);
  if (NULL != subject_key) {
    char _buffer[101] = {0};
    np_regenerate_subject(context, _buffer, 100, &lookup_key);

    log_debug(LOG_MESSAGE | LOG_AAATOKEN,
              message->e2e_msg_part.uuid,
              "handling message token, subject %s found in keycache",
              _buffer);
    __np_handle(statemachine, available_event);
    np_unref_obj(np_key_t, subject_key, "_np_keycache_find");
  }

__np_cleanup__: {}
}

void __np_handle_pheromone(np_util_statemachine_t *statemachine,
                           const np_util_event_t   event) {
  // handle ght messages (ping, piggy, ...)
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  // check whether node and alias are in the correct state
  NP_CAST(statemachine->_user_data, np_key_t, alias_key);
  NP_CAST(event.user_data, struct np_n2n_messagepart_s, pheromone_message);

  np_key_ro_t readonly_parent_key = {0};
  if (!ret) ret = _np_dhkey_equal(&alias_key->dhkey, &event.target_dhkey);
  if (ret)
    ret &= _np_keycache_exists(context,
                               alias_key->parent_dhkey,
                               &readonly_parent_key);
  if (ret) ret &= FLAG_CMP(readonly_parent_key.type, np_key_type_node);

  if (ret) {
    np_node_t *node = _np_key_get_node(alias_key);
    ret &= (node != NULL);
    if (ret) ret &= (node->is_in_leafset || node->is_in_routing_table);
  }

  if (ret) {
    np_util_event_t pheromone_evt = event;
    pheromone_evt.target_dhkey    = alias_key->parent_dhkey;
    __np_handle(statemachine, pheromone_evt);
  }
}

void __np_handle_np_message(np_util_statemachine_t *statemachine,
                            const np_util_event_t   event) {
  // handle ght messages (ping, piggy, ...)
  np_ctx_memory(statemachine->_user_data);

  __np_handle(statemachine, event);
}

void __np_handle_np_forward(np_util_statemachine_t *statemachine,
                            const np_util_event_t   event) {
  // handle other messages
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);
  NP_CAST(event.user_data, struct np_n2n_messagepart_s, message_in);

  np_dhkey_t subj_dhkey = *message_in->e2e_msg_part.subject;

  np_dhkey_t ack_dhkey = {0};
  np_generate_subject(&ack_dhkey, _NP_MSG_ACK, strnlen(_NP_MSG_ACK, 256));
  np_dhkey_t forward_dhkey = {0};
  np_generate_subject(&forward_dhkey, _FORWARD, strnlen(_FORWARD, 256));

  // np_dhkey_t subj_in_dhkey     = _np_msgproperty_tweaked_dhkey(INBOUND,
  // subj_dhkey);
  np_dhkey_t forward_out_dhkey =
      _np_msgproperty_tweaked_dhkey(OUTBOUND, forward_dhkey);
  np_dhkey_t ack_out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, ack_dhkey);

  _np_pheromone_inhale_target(context,
                              *message_in->e2e_msg_part.audience,
                              alias_key->parent_dhkey,
                              false,
                              true);

  char _buffer[101] = {0};
  np_regenerate_subject(context,
                        _buffer,
                        100,
                        message_in->e2e_msg_part.subject);
  log_info(LOG_ROUTING,
           message_in->e2e_msg_part.uuid,
           "forwarding message (subject %s parts: %" PRIu16 ")",
           _buffer,
           *message_in->e2e_msg_part.parts);

  np_dhkey_t msg_handler = {0};
  // by default use the forward handler
  _np_dhkey_assign(&msg_handler, &forward_out_dhkey);
  // if it is an acknowledge message, then use the build-in ack_out property
  if (_np_dhkey_equal(&ack_dhkey, &subj_dhkey))
    _np_dhkey_assign(&msg_handler, &ack_out_dhkey);

  message_in->is_forwarded_part = true;

  np_util_event_t forward_event = event;
  // set node key as target to prevent loops when forwarding
  forward_event.target_dhkey = alias_key->parent_dhkey;
  forward_event.type         = (evt_internal | evt_message);

  np_jobqueue_submit_event(context,
                           0.0,
                           msg_handler,
                           forward_event,
                           "event: forward message");
  // _np_event_runtime_add_event(context,
  //                             event.current_run,
  //                             msg_handler,
  //                             forward_event);

__np_cleanup__: {}
}

void __np_handle_usr_msg(np_util_statemachine_t *statemachine,
                         const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(event.user_data, struct np_n2n_messagepart_s, usr_message);

  np_util_event_t usr_event = event;
  _np_dhkey_assign(&usr_event.target_dhkey, usr_message->e2e_msg_part.audience);

  __np_handle_np_forward(statemachine, usr_event);
  __np_handle(statemachine, usr_event);

__np_cleanup__: {}
}

bool __is_alias_invalid(np_util_statemachine_t         *statemachine,
                        NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);

  log_trace(LOG_TRACE,
            NULL,
            "__is_alias_invalid(...) { [0]:%p [1]:%p [2]:%p [3]:%p }",
            alias_key->entity_array[e_handshake_token],
            alias_key->entity_array[e_aaatoken],
            alias_key->entity_array[e_nodeinfo],
            alias_key->entity_array[e_network]);

  if (!ret) {
    ret = FLAG_CMP(alias_key->type, np_key_type_unknown);
  }

  if (!ret &&
      (alias_key->created_at + BAD_LINK_REMOVE_GRACETIME) > np_time_now()) {
    return false;
  }

  if (!ret && _np_dhkey_cmp(&dhkey_zero, &alias_key->parent_dhkey) != 0 &&
      !_np_keycache_exists(context, alias_key->parent_dhkey, NULL)) {
    log_info(LOG_ROUTING,
             NULL,
             "alias %s does not have a parent key anymore.",
             _np_key_as_str(alias_key));
    return true;
  }

  // check for activity on the alias key. the last_update field receives
  // updates whenever an event has been handled, except for noop events. alias
  // keys only receive events when there is activity on the network layer. no
  // in activity
  // -> no alias needed -> shutdown input channel
  if (!ret &&
      (alias_key->last_update + BAD_LINK_REMOVE_GRACETIME) < np_time_now()) {
    log_info(LOG_ROUTING,
             NULL,
             "alias %s is a bad link (timeout) ",
             _np_key_as_str(alias_key));
    return true;
  }

  np_node_t *alias_node = _np_key_get_node(alias_key);
  if (!ret) // check for not in routing / leafset table anymore
  {
    ret = (!alias_node->is_in_leafset) && (!alias_node->is_in_routing_table);
    log_trace(LOG_TRACE,
              NULL,
              "end  : bool __is_alias_invalid(...) { %d (%d / %d / %f < %f)",
              ret,
              alias_node->is_in_leafset,
              alias_node->is_in_routing_table,
              (alias_key->created_at + BAD_LINK_REMOVE_GRACETIME),
              np_time_now());

    if (ret)
      log_info(LOG_ROUTING,
               NULL,
               "alias %s is not in routing or leafset",
               _np_key_as_str(alias_key));
  }

  if (!ret) // bad node connectivity
  {
    ret = (alias_node->success_avg < BAD_LINK);
    log_trace_msg(
        LOG_TRACE,
        NULL,
        "end  : bool __is_alias_invalid(...) { %d (%d / %d / %f < %f)",
        ret,
        alias_node->is_in_leafset,
        alias_node->is_in_routing_table,
        (alias_key->created_at + BAD_LINK_REMOVE_GRACETIME),
        np_time_now());
    if (ret)
      log_info(LOG_ROUTING,
               NULL,
               "alias %s is a bad link (response) ",
               _np_key_as_str(alias_key));
  }

  if (!ret) // token expired
  {
    np_aaatoken_t *alias_token = _np_key_get_token(alias_key);
    ret                        = (alias_token == NULL);
    if (!ret) {
      ret = !_np_aaatoken_is_valid(context, alias_token, np_aaatoken_type_node);
      if (ret)
        log_info(LOG_ROUTING,
                 NULL,
                 "alias %s is invalid",
                 _np_key_as_str(alias_key));
    } else {
      log_info(LOG_ROUTING,
               NULL,
               "alias %s has no token",
               _np_key_as_str(alias_key));
    }
    log_trace(LOG_TRACE,
              NULL,
              "end %p: bool __is_alias_invalid(...) { %d (%d / %d / %f < %f)",
              alias_token,
              ret,
              alias_node->is_in_leafset,
              alias_node->is_in_routing_table,
              (alias_key->created_at + BAD_LINK_REMOVE_GRACETIME),
              np_time_now());
  }

  return ret;
}

void __np_alias_shutdown(np_util_statemachine_t         *statemachine,
                         NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);
  log_info(LOG_KEY, NULL, "shutdown alias key %s 1", _np_key_as_str(alias_key));
  alias_key->parent_dhkey = dhkey_zero;
  alias_key->type         = np_key_type_unknown;
}

void __np_alias_destroy(np_util_statemachine_t         *statemachine,
                        NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, alias_key);

  struct __np_node_trinity trinity = {0};
  __np_key_to_trinity(alias_key, &trinity);

  log_info(LOG_KEY,
           NULL,
           "destroying alias key %s 1",
           _np_key_as_str(alias_key));

  if (FLAG_CMP(alias_key->type, np_key_type_alias)) {
    np_unref_obj(np_key_t, alias_key, "__np_alias_set");
  }

  if (alias_key->entity_array[e_handshake_token] != NULL)
    np_unref_obj(np_aaatoken_t,
                 alias_key->entity_array[e_handshake_token],
                 "__np_alias_set");
  if (trinity.token != NULL)
    np_unref_obj(np_aaatoken_t, trinity.token, "__np_alias_set");
  if (alias_key->entity_array[e_nodeinfo] != NULL) {
    np_unref_obj(np_node_t,
                 alias_key->entity_array[e_nodeinfo],
                 "__np_alias_set");
  }
  if (trinity.network != NULL) {
    _np_network_disable(trinity.network);
    np_unref_obj(np_network_t, trinity.network, "__np_alias_set");
  }
  // memset(alias_key->entity_array, 0, 8*sizeof(void_ptr));

  alias_key->type = np_key_type_unknown;
}

void __np_alias_update(np_util_statemachine_t *statemachine,
                       const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  if (event.user_data != NULL) {
    // this can happen!
    // e.g. nodes may send out one superflous join message because messages
    // may have time overlap. Then statemachine already pushed the alias to
    // the correct state --> the IN_USE state doesn't handle join messages
    enum np_memory_types_e memory_type = np_memory_get_type(event.user_data);
    if (memory_type == np_memory_types_np_messagepart_t) {
      NP_CAST(event.user_data, struct np_n2n_messagepart_s, msgpart);
      log_debug(LOG_MESSAGE,
                msgpart->e2e_msg_part.uuid,
                "unexpected datatype %" PRIu8
                " (messagepart)"
                " attached to event (event type: %" PRIu8 ")",
                memory_type,
                event.type);
    } else if (memory_type == np_memory_types_np_message_t) {
      NP_CAST(event.user_data, struct np_e2e_message_s, msg);
      log_debug(LOG_MESSAGE,
                msg->uuid,
                "unexpected datatype %" PRIu8
                " (message) "
                " attached to event (event type: %" PRIu8 ")",
                memory_type,
                event.type);
    } else {
      log_msg(LOG_WARNING,
              NULL,
              "unexpected datatype %" PRIu8
              " () "
              " attached to event (event type: %" PRIu8 ")",
              memory_type,
              event.type);
    }
  }

  _np_alias_cleanup_msgpart_cache(context, event);
}
