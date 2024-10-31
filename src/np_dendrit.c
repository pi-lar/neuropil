//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "np_dendrit.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "event/ev.h"
#include "sodium.h"

#include "neuropil.h"
#include "neuropil_log.h"

#include "core/np_comp_intent.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"
#include "util/np_event.h"
#include "util/np_list.h"
#include "util/np_serialization.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_bootstrap.h"
#include "np_constants.h"
#include "np_dhkey.h"
#include "np_eventqueue.h"
#include "np_evloop.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_node.h"
#include "np_pheromones.h"
#include "np_responsecontainer.h"
#include "np_route.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_token_factory.h"

bool _check_and_send_destination_ack(np_state_t     *context,
                                     np_util_event_t msg_event) {
  NP_CAST(msg_event.user_data, struct np_e2e_message_s, msg);

  // TODO: check intent token for ack indicator if user space message
  enum np_msg_flags msg_flags = {0};
  memcpy(&msg_flags, msg->msg_flags, sizeof(uint16_t));

  if (FLAG_CMP(msg_flags, msg_ack_dest)) {

    bool _use_node_ack = false;
    // from value is filled with different values: either the fingerprint of
    // the session token, or the real node dhkey
    np_dhkey_t target_dhkey = *msg->audience;
    np_dhkey_t from_dhkey   = {0};
    // check for node (hop-by-hop) ack
    if (_np_dhkey_equal(msg->audience, &context->my_node_key->dhkey)) {
      _use_node_ack       = true;
      np_key_t *alias_key = NULL;
      alias_key           = _np_keycache_find(context, msg_event.target_dhkey);
      if (NULL != alias_key) {
        log_debug(LOG_MESSAGE, msg->uuid, "ack of message");
        _np_dhkey_assign(&from_dhkey, &alias_key->parent_dhkey);
        np_unref_obj(np_key_t, alias_key, "_np_keycache_find");
      } else {
        _np_dhkey_assign(&from_dhkey, &msg_event.target_dhkey);
        log_debug(LOG_MESSAGE, msg->uuid, "ack of message");
      }
    }

    // check for subject (end-to-end) ack
    if (false == _use_node_ack) { // lookup crypto sender token to extract use
                                  // node info
      np_dhkey_t subject_dhkey = *msg->subject;
      np_dhkey_t in_subject_dhkey =
          _np_msgproperty_tweaked_dhkey(INBOUND, subject_dhkey);

      np_key_t *subject_key = _np_keycache_find(context, in_subject_dhkey);
      if (NULL == subject_key) {
        log_debug(LOG_MESSAGE, msg->uuid, "e2e  ack key not found");
        return true;
      }

      if (_np_intent_get_ack_session(subject_key, target_dhkey, &from_dhkey)) {
        log_debug(LOG_MESSAGE, msg->uuid, "e2e  ack of message     found");
      } else {
        log_debug(LOG_MESSAGE, msg->uuid, "e2e  ack of message not found");
        return true;
      }
      np_unref_obj(np_key_t, subject_key, "_np_keycache_find");
    }

    np_dhkey_t ack_subject = {0};
    np_generate_subject(&ack_subject, _NP_MSG_ACK, strnlen(_NP_MSG_ACK, 256));

    np_dhkey_t ack_out_dhkey =
        _np_msgproperty_tweaked_dhkey(OUTBOUND, ack_subject);

    np_tree_t *msg_body = np_tree_create();
    np_tree_insert_str(msg_body,
                       _NP_MSG_INST_RESPONSE_UUID,
                       np_treeval_new_bin(msg->uuid, NP_UUID_BYTES));

    struct np_e2e_message_s *msg_out = NULL;
    np_new_obj(np_message_t, msg_out);
    _np_message_create(msg_out,
                       from_dhkey,
                       context->my_node_key->dhkey,
                       ack_subject,
                       msg_body);
#ifdef DEBUG
    char tmp[NP_UUID_BYTES * 2 + 1];
    sodium_bin2hex(tmp, NP_UUID_BYTES * 2 + 1, msg_out->uuid, NP_UUID_BYTES);
    log_debug(LOG_MESSAGE, msg->uuid, "ack of message with %s", tmp);
#endif

    np_util_event_t ack_event = {.type         = evt_message | evt_internal,
                                 .target_dhkey = ack_out_dhkey,
                                 .user_data    = msg_out};
    np_jobqueue_submit_event(context,
                             0.0,
                             ack_out_dhkey,
                             ack_event,
                             "event: ack out");
    // _np_event_runtime_add_event(context,
    //                             msg_event.current_run,
    //                             ack_out_dhkey,
    //                             ack_event);
    np_tree_free(msg_body);
    np_unref_obj(np_message_t, msg_out, ref_obj_creation);
  }
  return true;
}

bool _np_in_ping(np_state_t *context, np_util_event_t msg_event) {

  NP_CAST(msg_event.user_data, struct np_e2e_message_s, msg);
  // if (false == _np_message_readbody(msg)) {
  //   log_warn(LOG_MESSAGE, msg->uuid, "received no sender token payload");
  //   return false;
  // }

  log_debug(LOG_ROUTING, msg->uuid, "_np_in_ping");
  // for now: nothing more to do. work is done only on the sending end
  // ack handling happens in a separate callback

  return true;
}

/**
 ** neuropil_piggy_message:
 ** This function is responsible to add the piggy backing node information
 *that is sent along with
 ** other ctrl messages or separately to the routing table. the PIGGY
 *message type is a separate
 ** message type.
 **/
bool _np_in_piggy(np_state_t *context, np_util_event_t msg_event) {

  NP_CAST(msg_event.user_data, struct np_e2e_message_s, msg);
  if (false == _np_message_readbody(msg)) {
    log_warn(LOG_MESSAGE, msg->uuid, "received no sender token payload");
    return false;
  }

  np_node_t *node_entry               = NULL;
  np_sll_t(np_node_ptr, o_piggy_list) = NULL;

  o_piggy_list = _np_node_decode_multiple_from_jrb(context, msg->msg_body);

  log_debug(LOG_ROUTING,
            msg->uuid,
            "received piggy msg (%" PRIu32 " nodes)",
            sll_size(o_piggy_list));

  while (NULL != (node_entry = sll_head(np_node_ptr, o_piggy_list))) {
    // ignore passive nodes, we cannot send a handshake to them
    if (FLAG_CMP(node_entry->protocol, PASSIVE)) {
      np_unref_obj(np_node_t, node_entry, "_np_node_decode_from_jrb");
      continue;
    }

    np_key_t *my_key = _np_keycache_find_interface(context,
                                                   node_entry->ip_string,
                                                   node_entry->port);
    if (my_key != NULL) {
      np_unref_obj(np_key_t, my_key, "_np_keycache_find_interface");
      np_unref_obj(np_node_t, node_entry, "_np_node_decode_from_jrb");
      continue;
    }

    // add entries in the message to our routing table
    // routing table is responsible to handle possible double entries
    np_dhkey_t search_key = np_dhkey_create_from_hash(node_entry->host_key);

    // TODO: those new entries in the piggy message must be authenticated
    // before sending join requests
    np_key_t *piggy_key = _np_keycache_find(context, search_key);
    if (piggy_key == NULL) {
      bool send_join                    = false;
      np_sll_t(np_key_ptr, sll_of_keys) = NULL;
      sll_of_keys = _np_route_row_lookup(context, search_key);

      // send join if ...
      if (sll_size(sll_of_keys) < NP_ROUTES_MAX_ENTRIES) {
        // our routing table is not full
        send_join = true;
      } else {
        // our routing table is full, but the new dhkey is closer to us
        _np_keycache_sort_keys_kd(sll_of_keys, &context->my_node_key->dhkey);
        send_join = _np_dhkey_between(&search_key,
                                      &context->my_node_key->dhkey,
                                      &sll_last(sll_of_keys)->val->dhkey,
                                      true);
      }

      // check whether we can connect to this node
      char ip_buffer[64] = {0};
      _np_network_get_outgoing_ip(NULL,
                                  node_entry->ip_string,
                                  node_entry->protocol,
                                  ip_buffer);
      np_key_t *interface_key =
          _np_keycache_find_interface(context, ip_buffer, NULL);

      if (send_join && interface_key != NULL) {

        piggy_key = _np_keycache_find_or_create(context, search_key);
        np_util_event_t new_node_evt = {.type      = (evt_internal),
                                        .user_data = node_entry};
        _np_event_runtime_add_event(context,
                                    msg_event.current_run,
                                    search_key,
                                    new_node_evt);
        log_info(LOG_ROUTING,
                 msg->uuid,
                 "node %s is qualified for a piggy join.",
                 _np_key_as_str(piggy_key));
        np_unref_obj(np_key_t, piggy_key, "_np_keycache_find_or_create");
      }

      if (interface_key != NULL)
        np_unref_obj(np_key_t, interface_key, "_np_keycache_find_interface");
      np_key_unref_list(sll_of_keys, "_np_route_row_lookup");
      sll_free(np_key_ptr, sll_of_keys);

    } else if (NULL != _np_key_get_node(piggy_key) &&
               _np_key_get_node(piggy_key)->success_avg > BAD_LINK &&
               (np_time_now() - piggy_key->created_at) >=
                   BAD_LINK_REMOVE_GRACETIME) {
      // let's try to fill up our leafset, routing table is filled by
      // internal state
      // TODO: realize this via an event, otherwise locking of the piggy key
      // is not in place
      __np_node_add_to_leafset(&piggy_key->sm, msg_event);
      np_unref_obj(np_key_t, piggy_key, "_np_keycache_find");
    } else {
      log_debug(LOG_ROUTING,
                msg->uuid,
                "node %s is not qualified for a further piggy actions.",
                _np_key_as_str(piggy_key));
      np_unref_obj(np_key_t, piggy_key, "_np_keycache_find");
    }
    np_unref_obj(np_node_t, node_entry, "_np_node_decode_from_jrb");
  }
  sll_free(np_node_ptr, o_piggy_list);

  return true;
}

/** _np_in_callback_wrapper
 ** _np_in_callback_wrapper is used when a callback function is used to
 *receive messages
 ** The purpose is automated acknowledge handling in case of ACK_CLIENT
 *message subjects
 ** the user defined callback has to return true in case the ack can be
 *send, or false
 ** if e.g. validation of the message has failed.
 **/
bool _np_in_callback_wrapper(np_state_t *context, np_util_event_t msg_event) {

  NP_CAST(msg_event.user_data, struct np_e2e_message_s, msg_in);

  log_debug(LOG_DEBUG, msg_in->uuid, "start callback wrapper");

  enum np_return ret = np_ok;

  np_dhkey_t prop_in_dhkey =
      _np_msgproperty_tweaked_dhkey(INBOUND, *msg_in->subject);
  np_key_t *prop_in_key = _np_keycache_find(context, prop_in_dhkey);

  NP_CAST(prop_in_key->entity_array[0], np_msgproperty_conf_t, msg_prop);

  np_dhkey_t session_id = *msg_in->audience;

  np_crypto_session_t crypto_session = {0};
  bool                session_found =
      _np_intent_get_crypto_session(prop_in_key, session_id, &crypto_session);

  ret = _np_message_decrypt_payload(msg_in, &crypto_session);

  if (ret == np_ok && false == _np_message_readbody(msg_in)) {
    log_debug(LOG_MESSAGE, msg_in->uuid, "couldn't read message body");
    return false;
  }

  if (ret == np_ok && session_found &&
      crypto_session.session_type == crypto_session_initial) {
    log_msg(LOG_DEBUG,
            msg_in->uuid,
            "initial crypto_session message detected (%s), importing values",
            msg_prop->msg_subject);
    _np_intent_import_session(prop_in_key, msg_in->msg_body, crud_create);
    // TODO: actually not an error, here for comparison in line 368
    ret = np_unknown_error;
  }

  np_unref_obj(np_key_t, prop_in_key, "_np_keycache_find");

  if (ret != np_ok) {
    log_msg(LOG_DEBUG | LOG_MESSAGE,
            msg_in->uuid,
            "could not decrypt data or initial session message");
    return false;
  }
  return true;
}

/** _np_in_leave_req:
 ** internal function that is called at the destination of a LEAVE message.
 *This
 ** call encodes the leaf set of the current host and sends it to the
 *joiner.
 **/
bool _np_in_leave(np_state_t *context, np_util_event_t msg_event) {

  NP_CAST(msg_event.user_data, struct np_e2e_message_s, msg);
  if (false == _np_message_readbody(msg)) {
    log_warn(LOG_MESSAGE, msg->uuid, "received no sender token payload");
    return false;
  }

  np_tree_elem_t *node_token_ele =
      np_tree_find_str(msg->msg_body, _NP_URN_NODE_PREFIX);
  if (node_token_ele != NULL) {
    np_aaatoken_t *node_token =
        np_token_factory_read_from_tree(context,
                                        node_token_ele->val.value.tree);
    if (node_token != NULL) {

      np_util_event_t shutdown_event = {.type = evt_shutdown | evt_external};
      shutdown_event.user_data       = node_token;

      np_dhkey_t search_key = np_aaatoken_get_fingerprint(node_token, false);

      shutdown_event.target_dhkey = search_key;
      // shutdown node
      _np_event_runtime_add_event(context,
                                  msg_event.current_run,
                                  search_key,
                                  shutdown_event);

      shutdown_event.target_dhkey = msg_event.target_dhkey;
      // shutdown alias
      _np_event_runtime_add_event(context,
                                  msg_event.current_run,
                                  msg_event.target_dhkey,
                                  shutdown_event);

      np_unref_obj(np_aaatoken_t,
                   node_token,
                   "np_token_factory_read_from_tree");
    }
  }
  return true;
}

/** _np_in_join_req:
 ** internal function that is called at the destination of a JOIN message.
 *This
 ** call encodes the leaf set of the current host and sends it to the
 *joiner.
 **/
bool _np_in_join(np_state_t *context, np_util_event_t msg_event) {

  NP_CAST(msg_event.user_data, struct np_e2e_message_s, msg);

  if (false == _np_message_readbody(msg)) {
    log_warn(LOG_MESSAGE, msg->uuid, "received no sender token payload");
    return false;
  }

  np_key_t               *join_node_key   = NULL;
  np_dhkey_t              join_node_dhkey = {0};
  np_node_public_token_t *join_node_token = NULL;

  np_dhkey_t               join_ident_dhkey = {0};
  np_ident_public_token_t *join_ident_token = NULL;

  np_util_event_t authn_event = {.type = evt_authn | evt_external | evt_token};
  authn_event.target_dhkey    = msg_event.target_dhkey;

  np_tree_elem_t *node_token_ele =
      np_tree_find_str(msg->msg_body, _NP_URN_NODE_PREFIX);
  if (node_token_ele == NULL) {
    // silently exit join protocol for invalid msg syntax
    log_trace(LOG_MESSAGE, msg->uuid, "JOIN request: bad msg syntax");
    goto __np_cleanup__;
  }

  join_node_token =
      np_token_factory_read_from_tree(context, node_token_ele->val.value.tree);
  if (join_node_token == NULL) {
    // silently exit join protocol for unknown node tokens
    log_trace(LOG_MESSAGE, msg->uuid, "JOIN request: missing node token");
    goto __np_cleanup__;
  }

  if (!_np_aaatoken_is_valid(context, join_node_token, np_aaatoken_type_node)) {
    // silently exit join protocol for invalid token type
    log_warn(LOG_AAATOKEN, msg->uuid, "JOIN request: invalid node token");
    goto __np_cleanup__;
  }

  // build a hash to find a place in the dhkey table, not for signing !
  join_node_dhkey = np_aaatoken_get_fingerprint(join_node_token, false);

  np_tree_elem_t *ident_token_ele =
      np_tree_find_str(msg->msg_body, _NP_URN_IDENTITY_PREFIX);

  if (ident_token_ele != NULL) {
    join_ident_token =
        np_token_factory_read_from_tree(context,
                                        ident_token_ele->val.value.tree);
    if (NULL == join_ident_token ||
        false == _np_aaatoken_is_valid(context,
                                       join_ident_token,
                                       np_aaatoken_type_identity)) {
      // silently exit join protocol for invalid identity token
      log_warn(LOG_AAATOKEN, msg->uuid, "JOIN request: invalid identity token");
      goto __np_cleanup__;
    }
    // build a hash to find a place in the dhkey table, not for signing !
    join_ident_dhkey = np_aaatoken_get_fingerprint(join_ident_token, false);

    np_dhkey_t partner_of_ident_dhkey =
        np_aaatoken_get_partner_fp(join_ident_token);
    if (_np_dhkey_equal(&dhkey_zero, &partner_of_ident_dhkey) == true ||
        _np_dhkey_equal(&join_node_dhkey, &partner_of_ident_dhkey) == false) {
      char fp_n[65], fp_p[65];
      _np_dhkey_str(&join_node_dhkey, fp_n);
      _np_dhkey_str(&partner_of_ident_dhkey, fp_p);
      log_warn(LOG_AAATOKEN,
               msg->uuid,
               "JOIN request: node fingerprint must match partner fingerprint "
               "in identity token. (node: %s / partner: %s)",
               fp_n,
               fp_p);
      goto __np_cleanup__;
    }

    np_dhkey_t partner_of_node_dhkey =
        np_aaatoken_get_partner_fp(join_node_token);
    if (_np_dhkey_equal(&dhkey_zero, &partner_of_node_dhkey) == true ||
        _np_dhkey_equal(&join_ident_dhkey, &partner_of_node_dhkey) == false) {
      char fp_i[65], fp_p[65];
      _np_dhkey_str(&join_ident_dhkey, fp_i);
      _np_dhkey_str(&partner_of_node_dhkey, fp_p);
      log_warn(LOG_AAATOKEN,
               msg->uuid,
               "JOIN request: identity fingerprint must match partner "
               "fingerprint in node token. (identity: %s / partner: %s)",
               fp_i,
               fp_p);
      goto __np_cleanup__;
    }

#ifdef DEBUG
    char tmp[65] = {0};
    log_debug(LOG_ROUTING,
              join_ident_token->uuid,
              "JOIN request: identity %s would like to join",
              np_id_str(tmp, &partner_of_node_dhkey));
#endif
    // everything is fine and we can continue
    authn_event.user_data = join_ident_token;
  }

  join_node_key = _np_keycache_find(context, join_node_dhkey);
  if (join_node_key == NULL) {
    // no handshake before join ? exit join protocol ...
    log_debug(LOG_ROUTING,
              msg->uuid,
              "JOIN request: no corresponding node key found");
    goto __np_cleanup__;
  } else if (join_ident_token ==
             NULL) { // pure node join without additional identity :-(
    log_debug(LOG_ROUTING,
              msg->uuid,
              "JOIN request: node     %s would like to join",
              _np_key_as_str(join_node_key));
    authn_event.user_data = join_node_token;

    // needed to create initial node structure
    _np_event_runtime_add_event(context,
                                msg_event.current_run,
                                join_node_key->dhkey,
                                authn_event);

    // update alias token
    _np_event_runtime_add_event(context,
                                msg_event.current_run,
                                msg_event.target_dhkey,
                                authn_event);

    // Authenticate token by main identity
    _np_event_runtime_add_event(context,
                                msg_event.current_run,
                                context->my_identity->dhkey,
                                authn_event);
  } else if (join_ident_token != NULL) { // update node token and wait for
                                         // identity authentication
    log_debug(LOG_ROUTING,
              msg->uuid,
              "JOIN request: node     %s would like to join",
              _np_key_as_str(join_node_key));

    np_util_event_t token_event = {.type = evt_token | evt_external};
    token_event.target_dhkey    = join_node_dhkey;
    token_event.user_data       = join_node_token;

    // update node token
    _np_event_runtime_add_event(context,
                                msg_event.current_run,
                                join_node_key->dhkey,
                                token_event);
    // update alias token
    _np_event_runtime_add_event(context,
                                msg_event.current_run,
                                msg_event.target_dhkey,
                                token_event);

    // authenticate token by main identity
    _np_event_runtime_add_event(context,
                                msg_event.current_run,
                                context->my_identity->dhkey,
                                authn_event);
  } else { // silently exit join protocol as we already joined this key
    log_debug(LOG_ROUTING,
              msg->uuid,
              "JOIN request: no corresponding identity key found");
  }

__np_cleanup__:
  np_unref_obj(np_aaatoken_t,
               join_node_token,
               "np_token_factory_read_from_tree");
  np_unref_obj(np_aaatoken_t,
               join_ident_token,
               "np_token_factory_read_from_tree");
  np_unref_obj(np_key_t, join_node_key, "_np_keycache_find");

  return true;
}

bool _np_in_ack(np_state_t *context, np_util_event_t msg_event) {

  NP_CAST(msg_event.user_data, struct np_e2e_message_s, msg);
  if (false == _np_message_readbody(msg)) {
    log_warn(LOG_MESSAGE, msg->uuid, "received no sender token payload");
    return false;
  }

  CHECK_STR_FIELD(msg->msg_body, _NP_MSG_INST_RESPONSE_UUID, ack_uuid);

  np_dhkey_t ack_in_dhkey = _np_msgproperty_dhkey(INBOUND, _NP_MSG_ACK);
  np_key_t  *ack_key      = _np_keycache_find(context, ack_in_dhkey);
  NP_CAST(ack_key->entity_array[1], np_msgproperty_run_t, property);

  np_tree_elem_t *response_entry =
      np_tree_find_str(property->response_handler, ack_uuid.value.bin);

#ifdef DEBUG
  char tmp[NP_UUID_BYTES * 2 + 1];
  sodium_bin2hex(tmp, NP_UUID_BYTES * 2 + 1, ack_uuid.value.bin, NP_UUID_BYTES);
#endif

  if (response_entry != NULL) {
    // just an acknowledgement of own messages send out earlier
    NP_CAST(response_entry->val.value.v, np_responsecontainer_t, response);
    response->received_at = np_time_now();

#ifdef DEBUG
    log_info(LOG_MESSAGE, msg->uuid, "msg is acknowledgment of uuid=%s", tmp);
#endif

  } else {
#ifdef DEBUG
    log_warn(LOG_MESSAGE,
             msg->uuid,
             "msg is acknowledgment of uuid=%s but we do not "
             "know of this msg",
             tmp);
#endif
  }

  np_unref_obj(np_key_t, ack_key, "_np_keycache_find");

__np_cleanup__: {}

  return true;
}

// TODO: write a function that handles path discovery
// TODO: if this is not the target node, add my own address to the update
// message
// TODO: if this is the target node, change target to sending instance and
// send again receive information about new nodes in the network and try to
// contact new nodes
bool _np_in_update(np_state_t *context, np_util_event_t msg_event) {

  NP_CAST(msg_event.user_data, struct np_e2e_message_s, msg);
  if (false == _np_message_readbody(msg)) {
    log_warn(LOG_MESSAGE, msg->uuid, "received no sender token payload");
    return false;
  }

  np_tree_t *update_tree =
      np_tree_find_str(msg->msg_body, _NP_URN_NODE_PREFIX)->val.value.tree;

  np_aaatoken_t *update_token = NULL;
  np_new_obj(np_aaatoken_t, update_token);

  np_aaatoken_decode(update_tree, update_token);

  if (false == _np_aaatoken_is_valid(context,
                                     update_token,
                                     np_aaatoken_type_handshake)) {
    np_unref_obj(np_aaatoken_t, update_token, ref_obj_creation);
    return false;
  }

  np_dhkey_t      update_dhkey = _np_aaatoken_get_issuer(update_token);
  np_util_event_t update_event = {.type         = (evt_external | evt_token),
                                  .user_data    = update_token,
                                  .target_dhkey = update_dhkey};

  // potentially create the new node
  if (!_np_keycache_exists(context, update_dhkey, NULL)) {
    np_key_t *update_key = _np_keycache_find_or_create(context, update_dhkey);
    _np_event_runtime_add_event(context,
                                msg_event.current_run,
                                update_dhkey,
                                update_event);
    np_unref_obj(np_key_t, update_key, "_np_keycache_find_or_create");
  }

  // and forward the token to another hop
  _np_message_setbody(msg, msg->msg_body);

  np_dhkey_t update_prop_dhkey =
      _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_UPDATE_REQUEST);
  update_event.type         = (evt_message | evt_internal);
  update_event.user_data    = msg;
  update_event.target_dhkey = update_prop_dhkey;

  _np_event_runtime_add_event(context,
                              msg_event.current_run,
                              update_prop_dhkey,
                              update_event);

  np_unref_obj(np_aaatoken_t, update_token, ref_obj_creation);

  return true;
}

// TODO: handle both available message with the same message callback. Only
// the msg_mode is different and depends on the message type
bool _np_in_available_sender(np_state_t *context, np_util_event_t msg_event) {

  NP_CAST(msg_event.user_data, struct np_e2e_message_s, available_msg_in);

  if (false == _np_message_readbody(available_msg_in)) {
    log_warn(LOG_MESSAGE,
             available_msg_in->uuid,
             "received no sender token payload");
    return false;
  }

  // extract e2e encryption details for sender
  np_message_intent_public_token_t *msg_token = NULL;
  // TODO: use CHECK_STR_FIELD(...)
  np_tree_elem_t *intent_token_ele =
      np_tree_find_str(available_msg_in->msg_body, _NP_URN_INTENT_PREFIX);

  if (intent_token_ele == NULL) {
    log_warn(LOG_ROUTING, available_msg_in->uuid, "received no sender token");
    return true;
  }
  msg_token = np_token_factory_read_from_tree(context,
                                              intent_token_ele->val.value.tree);
  if (msg_token) {
    // TODO: cross check with message header subject field: dhkey has to
    // match the subject in the token
    np_dhkey_t subject_dhkey = {0};
    np_str_id((np_id *)&subject_dhkey, msg_token->subject);
    np_dhkey_t available_msg_type =
        _np_msgproperty_tweaked_dhkey(INBOUND, subject_dhkey);

    np_util_event_t authz_event = {.type =
                                       (evt_token | evt_external | evt_authz),
                                   .user_data    = msg_token,
                                   .target_dhkey = available_msg_type};
    _np_event_runtime_add_event(context,
                                msg_event.current_run,
                                available_msg_type,
                                authz_event);

#ifdef DEBUG
    char uuid_hex[2 * NP_UUID_BYTES + 1];
    sodium_bin2hex(uuid_hex,
                   2 * NP_UUID_BYTES + 1,
                   msg_token->uuid,
                   NP_UUID_BYTES);
    log_debug(LOG_ROUTING,
              available_msg_in->uuid,
              "received sender token (%8s)",
              uuid_hex);
#endif
    np_unref_obj(np_aaatoken_t, msg_token, "np_token_factory_read_from_tree");
  } else {
    log_warn(LOG_ROUTING, available_msg_in->uuid, "received no sender token");
  }
  return true;
}

bool _np_in_available_receiver(np_state_t *context, np_util_event_t msg_event) {

  NP_CAST(msg_event.user_data, struct np_e2e_message_s, available_msg_in);

  if (false == _np_message_readbody(available_msg_in)) {
    log_warn(LOG_ROUTING,
             available_msg_in->uuid,
             "received no receiver token payload");
    return false;
  }

  // extract e2e encryption details for sender
  np_message_intent_public_token_t *msg_token = NULL;
  np_tree_elem_t                   *intent_token_ele =
      np_tree_find_str(available_msg_in->msg_body, _NP_URN_INTENT_PREFIX);
  msg_token = np_token_factory_read_from_tree(context,
                                              intent_token_ele->val.value.tree);
  if (msg_token) {
    // TODO: cross check with message header subject field: dhkey has to
    // match the subject in the token
    np_dhkey_t subject_dhkey = {0};
    np_str_id(&subject_dhkey, msg_token->subject);
    np_dhkey_t available_msg_type =
        _np_msgproperty_tweaked_dhkey(OUTBOUND, subject_dhkey);

    np_util_event_t authz_event = {.type =
                                       (evt_token | evt_external | evt_authz),
                                   .user_data    = msg_token,
                                   .target_dhkey = available_msg_type};
    _np_event_runtime_add_event(context,
                                msg_event.current_run,
                                available_msg_type,
                                authz_event);
#ifdef DEBUG
    char uuid_hex[2 * NP_UUID_BYTES + 1];
    sodium_bin2hex(uuid_hex,
                   2 * NP_UUID_BYTES + 1,
                   msg_token->uuid,
                   NP_UUID_BYTES);
    log_debug(LOG_ROUTING,
              available_msg_in->uuid,
              "received receiver token (%8s)",
              uuid_hex);
#endif
    np_unref_obj(np_aaatoken_t, msg_token, "np_token_factory_read_from_tree");

  } else {
    log_warn(LOG_ROUTING, available_msg_in->uuid, "received no receiver token");
  }
  return true;
}

bool _np_in_pheromone(np_state_t *context, np_util_event_t msg_event) {

  NP_CAST(msg_event.user_data, struct np_e2e_message_s, pheromone_msg_in);

  // create a copy now for forwarding pheromones later
  struct np_e2e_message_s *generic_forward_msg = NULL;
  np_new_obj(np_message_t, generic_forward_msg);
  np_message_clone(generic_forward_msg, pheromone_msg_in);

  if (false == _np_message_readbody(pheromone_msg_in)) {
    return false;
  }

  // we have the final node hash in the following field and thus the know
  // the next hop
  np_dhkey_t _last_hop_dhkey = msg_event.target_dhkey;

  np_tree_elem_t *tmp                      = NULL;
  bool            forward_pheromone_update = false;
  np_sll_t(np_dhkey_t, result_list)        = NULL;
  sll_init(np_dhkey_t, result_list);

  RB_FOREACH (
      tmp,
      np_tree_s,
      pheromone_msg_in->msg_body) { // only one element per message right now
    np_bloom_t *_scent = _np_neuropil_bloom_create();
    _np_neuropil_bloom_deserialize(_scent, tmp->val.value.bin, tmp->val.size);

    double _delay = 0;
    memcpy(&_delay, pheromone_msg_in->tstamp, sizeof(double));
    double _now = np_time_now();
    while (_delay < _now) {
      _np_neuropil_bloom_age_decrement(_scent);
      _delay += NP_PI / 314;
    }

    float _in_age = _np_neuropil_bloom_intersect_age(_scent, _scent);
    // float _in_age = _np_neuropil_bloom_get_heuristic(_scent,
    // msg_to.value.dhkey);
    if (_in_age == 0.0) {
      log_debug(LOG_PHEROMONE,
                pheromone_msg_in->uuid,
                "dropping pheromone trail message age now %f",
                _in_age);
      _np_bloom_free(_scent);
      continue;
    }

    float _old_age = _in_age;
    // update the internal pheromone table
    np_pheromone_t _pheromone = {0};
    _pheromone._subj_bloom    = _scent;
    _pheromone._pos           = tmp->key.value.i;

    if (0 > tmp->key.value.i) {
      ASSERT(0 > tmp->key.value.i && tmp->key.value.i >= -257,
             "index must be negative and between 0 and -257 (including)");
      log_debug(LOG_PHEROMONE,
                pheromone_msg_in->uuid,
                "update of send pheromone trail message, receiver age now %f",
                _in_age);
      _np_pheromone_snuffle_receiver(context,
                                     result_list,
                                     *pheromone_msg_in->audience,
                                     &_old_age);
      _pheromone._sender = _last_hop_dhkey;
    } else {
      ASSERT(0 < tmp->key.value.i && tmp->key.value.i <= 257,
             "index must be positive and between 0 and  257 (including)");
      log_debug(LOG_PHEROMONE,
                pheromone_msg_in->uuid,
                "update of recv pheromone trail message, sender age now %f",
                _in_age);
      _np_pheromone_snuffle_sender(context,
                                   result_list,
                                   *pheromone_msg_in->audience,
                                   &_old_age);
      _pheromone._receiver = _last_hop_dhkey;
    }

    log_debug(LOG_PHEROMONE,
              pheromone_msg_in->uuid,
              "update of pheromone trail: %" PRIi16
              " : age in: %f, but have age: / %f",
              _pheromone._pos,
              _in_age,
              _old_age);
    forward_pheromone_update |= _np_pheromone_inhale(context, _pheromone);

    _np_bloom_free(_scent);
  }

  if (forward_pheromone_update) { // forward the received pheromone

    log_debug(LOG_ROUTING | LOG_PHEROMONE,
              generic_forward_msg->uuid,
              "forward pheromone trail message");

    np_dhkey_t pheromone_dhkey =
        _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_PHEROMONE_UPDATE);
    np_util_event_t pheromone_event = {.type = (evt_internal | evt_message),
                                       .target_dhkey =
                                           *generic_forward_msg->audience};
    pheromone_event.user_data       = generic_forward_msg;

    // forward to axon sending unit with main direction "msg_to"
    _np_event_runtime_add_event(context,
                                msg_event.current_run,
                                pheromone_dhkey,
                                pheromone_event);

    // forward to axon sending unit with main direction set to existing
    // trails
    sll_iterator(np_dhkey_t) iter = sll_first(result_list);
    while (iter != NULL) { // exclude from further routing if dhkey matches:
      if (!_np_dhkey_equal(&iter->val, &_last_hop_dhkey) && // last hop
          !_np_dhkey_equal(&iter->val,
                           &context->my_node_key->dhkey)) // our own node dhkey
      {
        struct np_e2e_message_s *trail_forward_msg = NULL;
        np_new_obj(np_message_t, trail_forward_msg);
        np_message_clone(trail_forward_msg, generic_forward_msg);

        pheromone_event.user_data    = trail_forward_msg;
        pheromone_event.target_dhkey = iter->val;
        _np_event_runtime_add_event(context,
                                    msg_event.current_run,
                                    pheromone_dhkey,
                                    pheromone_event);
        np_unref_obj(np_message_t, trail_forward_msg, ref_obj_creation);
      }
      sll_next(iter);
    }
  }
  // cleanup
  sll_free(np_dhkey_t, result_list);
  np_unref_obj(np_message_t, generic_forward_msg, ref_obj_creation);
  return true;
}

bool _np_in_handshake(np_state_t *context, np_util_event_t msg_event) {

  NP_CAST(msg_event.user_data, struct np_e2e_message_s, msg);

  np_handshake_token_t *handshake_token = NULL;
  np_key_t             *msg_source_key  = NULL;
  np_key_t             *hs_wildcard_key = NULL;
  np_key_t             *hs_alias_key    = NULL;

  np_tree_elem_t *hs_token_ele =
      np_tree_find_str(msg->msg_body, _NP_URN_HANDSHAKE_PREFIX);
  handshake_token =
      np_token_factory_read_from_tree(context, hs_token_ele->val.value.tree);

  if (handshake_token == NULL ||
      !_np_aaatoken_is_valid(context,
                             handshake_token,
                             np_aaatoken_type_handshake)) {
    log_msg(LOG_ERROR, msg->uuid, "incorrect handshake signature in message");
    goto __np_cleanup__;
  } else {
    log_debug(LOG_HANDSHAKE,
              msg->uuid,
              "decoding of handshake message from %s / %s (i:%f/e:%f) complete",
              handshake_token->subject,
              handshake_token->issuer,
              handshake_token->issued_at,
              handshake_token->expires_at);
  }

  // store the handshake data in the node cache,
  np_dhkey_t search_dhkey = np_dhkey_create_from_hash(handshake_token->issuer);
  msg_source_key          = _np_keycache_find_or_create(context, search_dhkey);
  if (NULL == msg_source_key) { // should never happen
    log_msg(LOG_ERROR, msg->uuid, "handshake key is NULL!");
    goto __np_cleanup__;
  }

  // setup sending encryption
  np_util_event_t hs_event = msg_event;
  hs_event.user_data       = handshake_token;
  hs_event.type            = (evt_external | evt_token);
  /*
  Sollte eigentlich _np_event_runtime_add_event sein,
  aber der folgende code muss dann in eine cleanup methode
  o.ä. ausgelagert werden da aktuell nicht auf Asynchronität ausgelegt
  */
  _np_event_runtime_start_with_event(context, search_dhkey, hs_event);

  log_debug(LOG_HANDSHAKE,
            msg->uuid,
            "Update node key done! %p",
            msg_source_key);

  // network init could have failed
  if (FLAG_CMP(msg_source_key->type, np_key_type_node)) {
    // setup inbound decryption session with the alias key
    hs_alias_key = _np_keycache_find_or_create(context, msg_event.target_dhkey);
    hs_alias_key->parent_dhkey = msg_source_key->dhkey;

    hs_event.type = (evt_external | evt_token);
    _np_event_runtime_add_event(context,
                                msg_event.current_run,
                                hs_alias_key->dhkey,
                                hs_event);

    log_trace_msg(LOG_HANDSHAKE,
                  msg->uuid,
                  "Update alias key done! %p",
                  hs_alias_key);
    np_unref_obj(np_key_t, hs_alias_key, "_np_keycache_find_or_create");

    // finally delete possible wildcard #
    char *tmp_connection_str = handshake_token->subject +
                               12 /*_NP_URN_NODE_PREFIX + Protocol*/
                               + 5;
    np_dhkey_t wildcard_dhkey =
        np_dhkey_create_from_hostport("*", tmp_connection_str);
    hs_wildcard_key = _np_keycache_find(context, wildcard_dhkey);
    if (NULL != hs_wildcard_key) {
      hs_wildcard_key->parent_dhkey = msg_source_key->dhkey;

      np_util_event_t hs_event = msg_event;
      hs_event.type            = (evt_external | evt_token);
      hs_event.user_data       = handshake_token;
      _np_event_runtime_add_event(context,
                                  msg_event.current_run,
                                  hs_wildcard_key->dhkey,
                                  hs_event);
      np_unref_obj(np_key_t, hs_wildcard_key, "_np_keycache_find");

      log_trace_msg(LOG_TRACE, msg->uuid, "Update wildcard key done!");
    }
  }

__np_cleanup__:
  np_unref_obj(np_aaatoken_t,
               handshake_token,
               "np_token_factory_read_from_tree");
  np_unref_obj(np_key_t, msg_source_key, "_np_keycache_find_or_create");

  return true;
}
