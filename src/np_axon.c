//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "np_axon.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "event/ev.h"
#include "sodium.h"

#include "neuropil_data.h"
#include "neuropil_log.h"

#include "core/np_comp_intent.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"
#include "util/np_bloom.h"
#include "util/np_event.h"
#include "util/np_list.h"
#include "util/np_serialization.h"
#include "util/np_tree.h"

#include "np_aaatoken.h"
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
#include "np_settings.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_token_factory.h"
#include "np_types.h"
#include "np_util.h"

bool _np_out_callback_wrapper(np_state_t           *context,
                              const np_util_event_t event) {

  bool ret = false;

  NP_CAST(event.user_data, struct np_e2e_message_s, message);

  np_dhkey_t prop_out_dhkey =
      _np_msgproperty_tweaked_dhkey(OUTBOUND, *message->subject);
  np_key_t *prop_out_key = _np_keycache_find(context, prop_out_dhkey);

  ASSERT(prop_out_key != NULL, "msgproperty key cannot be null");

  NP_CAST(prop_out_key->entity_array[0],
          np_msgproperty_conf_t,
          my_property_conf);
  NP_CAST(prop_out_key->entity_array[1], np_msgproperty_run_t, my_property_run);

  // retrieval of crypto session cannot fail (was already checked)
  np_crypto_session_t crypto_session = {0};
  _np_intent_get_crypto_session(prop_out_key,
                                *message->audience,
                                &crypto_session);

  log_debug(LOG_MESSAGE,
            message->uuid,
            "msg for subject '%s' has valid token",
            my_property_conf->msg_subject);

  if (FLAG_CMP(my_property_conf->ack_mode, ACK_DESTINATION)) {
    // TODO: create a copy in case of re-delivery for un-acked messages
    struct np_e2e_message_s *redeliver_copy = NULL;
    np_new_obj(np_message_t, redeliver_copy);

    np_message_clone(redeliver_copy, message);
    _np_message_add_response_handler(redeliver_copy, event, false);

    np_util_event_t redeliver_event = {
        .type         = (evt_redeliver | evt_internal | evt_message),
        .target_dhkey = event.target_dhkey,
        .user_data    = redeliver_copy};
    _np_event_runtime_add_event(context,
                                event.current_run,
                                prop_out_dhkey,
                                redeliver_event);
    np_unref_obj(np_message_t, redeliver_copy, ref_obj_creation);
  }

  // encrypt the relevant message part itself
  if (np_ok != _np_message_encrypt_payload(message, &crypto_session)) {
    return false;
  }
  memset(&crypto_session, 0, sizeof(np_crypto_session_t));

  np_unref_obj(np_key_t, prop_out_key, "_np_keycache_find");
  return (true);
}

bool __np_axon_split_message(np_state_t *context, const np_util_event_t event) {

  NP_CAST(event.user_data, struct np_e2e_message_s, out_msg);

  if (_np_memory_rtti_check(out_msg, np_memory_types_np_message_t)) {

    _np_message_serialize_chunked(context, out_msg);
    for (uint16_t i = 0; i < *out_msg->parts; i++) {
      log_debug(LOG_ROUTING | LOG_MESSAGE,
                out_msg->uuid,
                "sending    message part %" PRIu16,
                i);

      struct np_n2n_messagepart_s *msg_part   = out_msg->msg_chunks[i];
      np_util_event_t              send_event = event;
      send_event.user_data                    = msg_part;

      if (false == np_jobqueue_submit_event(context,
                                            0.0,
                                            event.target_dhkey,
                                            send_event,
                                            "event: message out")) {
        _np_event_runtime_add_event(context,
                                    event.current_run,
                                    event.target_dhkey,
                                    send_event);
      }
    }
  } else if (_np_memory_rtti_check(out_msg, np_memory_types_np_messagepart_t)) {
    np_util_event_t send_event = event;
    send_event.user_data       = event.user_data;
    if (false == np_jobqueue_submit_event(context,
                                          0.0,
                                          event.target_dhkey,
                                          send_event,
                                          "event: message out")) {
      _np_event_runtime_add_event(context,
                                  event.current_run,
                                  event.target_dhkey,
                                  send_event);
    }
  } else {
    // fatal development error
    assert(true == false);
  }
  return (true);
}

bool __np_axon_send_chunks(np_state_t              *context,
                           np_event_runtime_t      *current_run,
                           struct np_e2e_message_s *msg,
                           np_dhkey_t               msg_to,
                           np_sll_t(np_dhkey_t, tmp)) {

  bool ret = false;
  // 3: send over to msg splitter
  char buf[65] = {0};

  sll_iterator(np_dhkey_t) key_iter = sll_first(tmp);
  while (key_iter != NULL) {
    if (!_np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey) &&
        _np_keycache_exists(context, key_iter->val, NULL)) {
      log_info(LOG_ROUTING,
               msg->uuid,
               "sending    message to hop %s",
               np_id_str(buf, &key_iter->val));

      // duplicate message in case of more than one destination node
      void *message_to_send = msg;
      if (_np_memory_rtti_check(msg, np_memory_types_np_message_t)) {
        struct np_e2e_message_s *duplicate_msg = NULL;
        np_new_obj(np_message_t, duplicate_msg);
        np_message_clone(duplicate_msg, msg);
        message_to_send = duplicate_msg;
      } else if (_np_memory_rtti_check(msg, np_memory_types_np_messagepart_t)) {
        struct np_n2n_messagepart_s *duplicate_msg = NULL;
        np_new_obj(np_messagepart_t, duplicate_msg);
        np_messagepart_clone(context,
                             duplicate_msg,
                             (struct np_n2n_messagepart_s *)msg);
        message_to_send = duplicate_msg;
      }

      // async handover of message to node
      np_util_event_t send_event = {.type      = (evt_internal | evt_message),
                                    .user_data = message_to_send,
                                    .target_dhkey = msg_to};
      np_jobqueue_submit_event(context,
                               0.0,
                               key_iter->val,
                               send_event,
                               "event: message out");

      if (_np_memory_rtti_check(msg, np_memory_types_np_message_t)) {
        np_unref_obj(np_message_t, message_to_send, ref_obj_creation);
      }
      if (_np_memory_rtti_check(msg, np_memory_types_np_messagepart_t)) {
        np_unref_obj(np_messagepart_t, message_to_send, ref_obj_creation);
      }

      ret = true;
    } else {
      char buf[65] = {0};
      log_info(LOG_ROUTING,
               msg->uuid,
               "do not send message to hop %s as: %s %s",
               np_id_str(buf, &key_iter->val),
               _np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey)
                   ? "target would be me"
                   : "",
               _np_keycache_exists(context, key_iter->val, NULL)
                   ? ""
                   : "target is not connected to me");
    }
    sll_next(key_iter);
  }
  return ret;
}

int8_t __dhkey_compare(const np_dhkey_t left, const np_dhkey_t right) {
  return _np_dhkey_cmp(&left, &right);
}

bool _np_out_forward(np_state_t *context, np_util_event_t event) {

  bool ret = false;
  NP_CAST(event.user_data, struct np_n2n_messagepart_s, forward_msg);

  if (!_np_route_my_key_has_connection(context)) {
    log_info(
        LOG_ROUTING,
        forward_msg->e2e_msg_part.uuid,
        "--- request for forward message out, but no connections left ...");
    return ret;
  }

  uint8_t i          = 0;
  float   target_age = 1.0;

  np_sll_t(np_dhkey_t, tmp) = NULL;
  sll_init(np_dhkey_t, tmp);
  do {
    _np_pheromone_snuffle_receiver(context,
                                   tmp,
                                   *forward_msg->e2e_msg_part.subject,
                                   &target_age);

    // remove the node, where the message came from, from list
    sll_remove(np_dhkey_t, tmp, event.target_dhkey, __dhkey_compare);
    i++;
    target_age -= 0.1;
  } while (sll_size(tmp) == 0 && i < 8);

  sll_iterator(np_dhkey_t) target_iter = sll_first(tmp);
  while (NULL != target_iter) {
    // remove previous hop from potential sender list
    if (_np_dhkey_equal(&target_iter->val, &event.target_dhkey)) {

#ifdef DEBUG
      char buf[65];
      buf[64] = '\0';
      log_debug(LOG_ROUTING,
                forward_msg->e2e_msg_part.uuid,
                "discarding available message to previous hop %s",
                np_id_str(buf, &target_iter->val));
#endif // DEBUG

      sll_delete(np_dhkey_t, tmp, target_iter);
      break;
    }
    sll_next(target_iter);
  }

  // increase hop count
  forward_msg->hop_count++;

  char buf[65]                      = {0};
  sll_iterator(np_dhkey_t) key_iter = sll_first(tmp);
  while (key_iter != NULL) {
    if (!_np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey) &&
        _np_keycache_exists(context, key_iter->val, NULL)) {

      log_info(LOG_ROUTING,
               forward_msg->e2e_msg_part.uuid,
               "forwarding     message to hop %s",
               np_id_str(buf, &key_iter->val));

      struct np_n2n_messagepart_s *duplicate_msg = NULL;
      np_new_obj(np_messagepart_t, duplicate_msg);
      np_messagepart_clone(context, duplicate_msg, forward_msg);

      np_util_event_t send_event = {.type      = (evt_internal | evt_message),
                                    .user_data = duplicate_msg,
                                    .target_dhkey =
                                        *forward_msg->e2e_msg_part.audience};
      np_jobqueue_submit_event(context,
                               0.0,
                               key_iter->val,
                               send_event,
                               "event: message out");
      // _np_event_runtime_add_event(context,
      //                             current_run,
      //                             key_iter->val,
      //                             send_event);
      /* POSSIBLE ASYNC POINT
      char buf[100];
      snprintf(buf, 100, "urn:np:message:splitter:%s", msg->uuid);
      if(!np_jobqueue_submit_event(context, 0, key_iter->val, send_event,
      buf)){ log_error("Jobqueue rejected new job for messagepart delivery of
      msg %s", msg->uuid
          );
      }
      */
      ret = true;
      np_unref_obj(np_messagepart_t, duplicate_msg, ref_obj_creation);
    } else {
      log_info(LOG_ROUTING,
               forward_msg->e2e_msg_part.uuid,
               "not forwarding message to hop %s",
               np_id_str(buf, &key_iter->val));
    }
    sll_next(key_iter);
    _np_increment_forwarding_counter(*forward_msg->e2e_msg_part.subject);
  }

  if (sll_size(tmp) == 0) {
    log_info(LOG_ROUTING,
             forward_msg->e2e_msg_part.uuid,
             "--- request for forward message out, but no routing found ...");
  }

  // 4 cleanup
  sll_free(np_dhkey_t, tmp);
  _np_pheromone_exhale(context);

  return ret;
}

bool _np_out_default(np_state_t *context, np_util_event_t event) {

  bool ret = false;
  NP_CAST(event.user_data, struct np_e2e_message_s, default_msg);

  if (!_np_route_my_key_has_connection(context)) {
    log_info(LOG_ROUTING,
             default_msg->uuid,
             "--- request for default message out, but no connections "
             "left ...");
    return ret;
  }

  float target_probability  = 1.0;
  np_sll_t(np_dhkey_t, tmp) = NULL;
  sll_init(np_dhkey_t, tmp);

  // np_dhkey_t recv_dhkey = _np_msgproperty_dhkey(INBOUND,
  // msg_subj.value.dhkey);
  uint8_t i = 0;
  while (sll_size(tmp) == 0 && i < 8) {
    _np_pheromone_snuffle_receiver(context,
                                   tmp,
                                   *default_msg->subject,
                                   &target_probability);
    i++;
    target_probability -= 0.1;
  };

  if (sll_size(tmp) > 0) {
    ret = __np_axon_send_chunks(context,
                                event.current_run,
                                default_msg,
                                *default_msg->audience,
                                tmp);
  } else {
    log_info(LOG_ROUTING,
             default_msg->uuid,
             "--- request for default message out, but no routing found ...");
  }

  // 4 cleanup
  sll_free(np_dhkey_t, tmp);

  //_np_pheromone_exhale(context);

  return ret;
}

bool _np_out_available_messages(np_state_t *context, np_util_event_t event) {

  bool                     ret               = false;
  struct np_e2e_message_s *available_msg     = NULL;
  bool                     cleanup_avail_msg = false;

  if (true ==
      _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t)) {
    available_msg = event.user_data;
  } else if (true == _np_memory_rtti_check(event.user_data,
                                           np_memory_types_np_messagepart_t)) {
    NP_CAST(event.user_data, struct np_n2n_messagepart_s, msg_part);
    np_new_obj(np_message_t, available_msg);

    available_msg->subject  = msg_part->e2e_msg_part.subject;
    available_msg->audience = msg_part->e2e_msg_part.audience;
    available_msg->uuid     = msg_part->e2e_msg_part.uuid;
    cleanup_avail_msg       = true;

    // increase hop count
    if (msg_part->is_forwarded_part) msg_part->hop_count++;

  } else {
    assert(true == false);
  }

  log_debug(LOG_ROUTING, available_msg->uuid, "handling available request");

  if (!_np_route_my_key_has_connection(context)) {
    log_info(LOG_ROUTING,
             available_msg->uuid,
             "--- request for available message out, but no connections "
             "left ...");
    return ret;
  }

  float original_target_age = 1.0;
  np_sll_t(np_dhkey_t, tmp) = NULL;
  sll_init(np_dhkey_t, tmp);

  np_dhkey_t sender_dhkey   = {0};
  np_dhkey_t receiver_dhkey = {0};
  np_generate_subject(&sender_dhkey,
                      _NP_MSG_AVAILABLE_SENDER,
                      strnlen(_NP_MSG_AVAILABLE_SENDER, 256));
  np_generate_subject(&receiver_dhkey,
                      _NP_MSG_AVAILABLE_RECEIVER,
                      strnlen(_NP_MSG_AVAILABLE_RECEIVER, 256));

  bool find_receiver = _np_dhkey_equal(available_msg->subject, &sender_dhkey);
  bool find_sender   = _np_dhkey_equal(available_msg->subject, &receiver_dhkey);
  char _msg_subj_str[100] = {0};
  np_regenerate_subject(context, _msg_subj_str, 100, available_msg->subject);

  uint8_t i = 0;
  while (sll_size(tmp) == 0 && i < 9) {
    float target_age = original_target_age;

    if (find_receiver) {
      _np_pheromone_snuffle_receiver(context,
                                     tmp,
                                     *available_msg->audience,
                                     &target_age);
    } else if (find_sender) {
      _np_pheromone_snuffle_sender(context,
                                   tmp,
                                   *available_msg->audience,
                                   &target_age);
    } else {
      log_error(NULL, "%s", "cannot search for both, receiver and sender");
      break;
    }
    i++;
    original_target_age -= 0.1;
    log_debug(LOG_ROUTING,
              available_msg->uuid,
              "--- request for available message out %s: search: "
              "%f found: %f",
              _msg_subj_str,
              original_target_age,
              target_age);
  };

  sll_iterator(np_dhkey_t) target_iter = sll_first(tmp);
  while (NULL != target_iter) {
    // remove previous hop from sender list
    if (_np_dhkey_equal(&target_iter->val, &event.target_dhkey)) {

#ifdef DEBUG
      char buf[65];
      buf[64] = '\0';
      log_debug(LOG_ROUTING,
                available_msg->uuid,
                "discarding available message to previous hop %s",
                np_id_str(buf, &target_iter->val));
#endif // DEBUG

      sll_delete(np_dhkey_t, tmp, target_iter);
      break;
    }
    sll_next(target_iter);
  }

  if (sll_size(tmp) > 0) {
    ret = __np_axon_send_chunks(context,
                                event.current_run,
                                event.user_data,
                                *available_msg->audience,
                                tmp);
  }

  sll_free(np_dhkey_t, tmp);
  if (cleanup_avail_msg)
    np_unref_obj(np_message_t, available_msg, ref_obj_creation);
  _np_pheromone_exhale(context);

  return ret;
}

bool _np_out_pheromone(np_state_t *context, np_util_event_t msg_event) {

  bool ret = false;
  NP_CAST(msg_event.user_data, struct np_e2e_message_s, pheromone_msg_out);

  if (!_np_route_my_key_has_connection(context)) {
    log_info(LOG_ROUTING,
             pheromone_msg_out->uuid,
             "--- request for pheromone update message out, but no connections "
             "left ...");
    return ret;
  }

  // check for the routing intent: generic or to a specific node
  bool is_generic_direction =
      _np_dhkey_equal(pheromone_msg_out->audience, &msg_event.target_dhkey);

  np_sll_t(np_dhkey_t, tmp_dhkeys);
  sll_init(np_dhkey_t, tmp_dhkeys);
  // 1: find next hop based on fingerprint of the token
  np_sll_t(np_key_ptr, tmp) = NULL;

  char *source_sll_of_keys = "_np_route_lookup";

  if (is_generic_direction) {
    // lookup based on 2: leafset excluded
    tmp = _np_route_lookup(context, msg_event.target_dhkey, 2);
    if (sll_size(tmp) > 0)
      sll_append(np_dhkey_t, tmp_dhkeys, sll_first(tmp)->val->dhkey);

  } else {
    // already found a pheromone scent, use it!
    sll_init(np_key_ptr, tmp);
    sll_append(np_dhkey_t, tmp_dhkeys, msg_event.target_dhkey);
  }

  // no result from a targeted search in the key space, but we do have routing
  // entries in our table -> use the best match of the whole table. Important
  // for smaller networks, corner case on larger networks
  if (sll_size(tmp) == 0 && _np_route_my_key_count_routes(context) > 0) {
    tmp                = _np_route_get_table(context);
    source_sll_of_keys = "_np_route_get_table";
    _np_keycache_sort_keys_cpm(tmp, &msg_event.target_dhkey);
    sll_append(np_dhkey_t, tmp_dhkeys, sll_first(tmp)->val->dhkey);
  }

  log_info(LOG_ROUTING,
           pheromone_msg_out->uuid,
           "have pheromone request for %d hops (%s)",
           sll_size(tmp_dhkeys),
           is_generic_direction ? "generic" : "targeted");

  if (sll_size(tmp_dhkeys) > 0) {
    // only send if a target has been found
    ret = __np_axon_send_chunks(context,
                                msg_event.current_run,
                                pheromone_msg_out,
                                msg_event.target_dhkey,
                                tmp_dhkeys);
  }

  _np_pheromone_exhale(context);

  // 4 cleanup
  np_key_unref_list(tmp, source_sll_of_keys);
  sll_free(np_key_ptr, tmp);
  sll_free(np_dhkey_t, tmp_dhkeys);

  return ret;
}

/**
 ** _np_network_append_msg_to_out_queue: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
bool _np_out_ack(np_state_t *context, np_util_event_t event) {

  bool                     ret                 = false;
  struct np_e2e_message_s *ack_msg             = NULL;
  bool                     cleanup_ack_message = false;

  if (true ==
      _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t)) {
    ack_msg = event.user_data;
  } else if (true == _np_memory_rtti_check(event.user_data,
                                           np_memory_types_np_messagepart_t)) {
    NP_CAST(event.user_data, struct np_n2n_messagepart_s, msg_part);
    np_new_obj(np_message_t, ack_msg);

    ack_msg->subject  = msg_part->e2e_msg_part.subject;
    ack_msg->audience = msg_part->e2e_msg_part.audience;
    ack_msg->uuid     = msg_part->e2e_msg_part.uuid;

    cleanup_ack_message = true;
  } else {
    assert(true == false);
  }

  if (!_np_route_my_key_has_connection(context)) {
    log_info(
        LOG_ROUTING,
        ack_msg->uuid,
        "--- request for forward message out, but no connections left ...");
    return ret;
  }

  float target_age          = 1.0;
  np_sll_t(np_dhkey_t, tmp) = NULL;
  sll_init(np_dhkey_t, tmp);

  np_dhkey_t ack_to_dhkey = *ack_msg->audience;

  // 1: check if the ack is for a direct neighbour
  np_key_t *target_key = _np_keycache_find(context, *ack_msg->audience);
  if (NULL == target_key) {
    // no --> 2: follow the ack trail of the "to" + "ack" dhkey path
    np_generate_subject(&ack_to_dhkey, _NP_MSG_ACK, strnlen(_NP_MSG_ACK, 256));
    // lookup based on original msg subject, but snuffle for sender
    while (sll_size(tmp) == 0 && target_age > BAD_LINK) {
      _np_pheromone_snuffle_receiver(context, tmp, ack_to_dhkey, &target_age);
      target_age -= 0.1;
    };
    // routing based on pheromones, exhale ...
    // _np_pheromone_exhale(context);
  } else {
    // yes --> 3a check whether the neighbour is in our routing/leafset table
    np_node_t *node = _np_key_get_node(target_key);
    if (node->is_in_leafset || node->is_in_routing_table) {
      // yes --> 3b. append to result list
      sll_append(np_dhkey_t, tmp, ack_to_dhkey);
      np_unref_obj(np_key_t, target_key, "_np_keycache_find");
    }
  }

  if (sll_size(tmp) >= 0) { // exit early if no routing has been found
    ret = __np_axon_send_chunks(context,
                                event.current_run,
                                event.user_data,
                                *ack_msg->audience,
                                tmp);
  } else {
    log_info(LOG_ROUTING,
             ack_msg->uuid,
             "--- request for ack message out, but no routing found ...");
  }

  sll_free(np_dhkey_t, tmp);
  if (cleanup_ack_message)
    np_unref_obj(np_message_t, ack_msg, ref_obj_creation);
  return ret;
}

bool _np_out_ping(np_state_t *context, const np_util_event_t event) {

  NP_CAST(event.user_data, struct np_e2e_message_s, ping_msg);

  _np_message_add_response_handler(ping_msg, event, true);
  log_debug(LOG_MESSAGE, ping_msg->uuid, "added response handler to message");

  bool serialize_ok = _np_message_serialize_chunked(context, ping_msg);

  np_util_event_t ping_event = {.type         = (evt_internal | evt_message),
                                .user_data    = ping_msg,
                                .target_dhkey = event.target_dhkey};
  _np_event_runtime_add_event(context,
                              event.current_run,
                              ping_event.target_dhkey,
                              ping_event);

  return true;
}

bool _np_out_piggy(np_state_t *context, const np_util_event_t event) {

  NP_CAST(event.user_data, struct np_e2e_message_s, piggy_msg);

#ifdef DEBUG
  np_key_t *target_key = _np_keycache_find(context, event.target_dhkey);
  if (target_key != NULL) {
    log_debug(LOG_ROUTING,
              piggy_msg->uuid,
              "submitting piggy to target key %s / %p",
              _np_key_as_str(target_key),
              target_key);
    np_unref_obj(np_key_t, target_key, "_np_keycache_find");
  }
#endif // DEBUG
  bool serialize_ok = _np_message_serialize_chunked(context, piggy_msg);

  np_util_event_t piggy_event = {.type         = (evt_internal | evt_message),
                                 .user_data    = piggy_msg,
                                 .target_dhkey = event.target_dhkey};
  _np_event_runtime_add_event(context,
                              event.current_run,
                              event.target_dhkey,
                              piggy_event);
  return true;
}

bool _np_out_update(np_state_t *context, const np_util_event_t event) {

  NP_CAST(event.user_data, struct np_e2e_message_s, update_msg);

  if (!_np_route_my_key_has_connection(context)) {
    log_info(LOG_ROUTING,
             update_msg->uuid,
             "--- request for update message out, but no connections left ...");
    return false;
  }

  // 3: find next hop based on fingerprint of the token
  np_sll_t(np_key_ptr, tmp) = NULL;
  uint8_t i                 = 1;
  do {
    // _np_route_lookup returns an empty list, delete it first on repeat
    if (tmp != NULL) sll_free(np_key_ptr, tmp);

    // lookup routing information
    tmp = _np_route_lookup(context, event.target_dhkey, i);
    i++;
  } while (sll_size(tmp) == 0 && i < 5);

  if (tmp == NULL || sll_size(tmp) == 0) {
    log_warn(LOG_ROUTING,
             update_msg->uuid,
             "--- request for update message out, but no connections left ...");
    if (tmp != NULL) sll_free(np_key_ptr, tmp);
    return false;
  }
  np_key_t *target = sll_first(tmp)->val;

  if (_np_dhkey_equal(&target->dhkey, &context->my_node_key->dhkey)) {
    log_warn(LOG_ROUTING,
             update_msg->uuid,
             "--- request for update message out, but this is already the "
             "nearest node ...");
    np_key_unref_list(tmp, "_np_route_lookup");
    sll_free(np_key_ptr, tmp);
    return false;
  }

  _np_dhkey_assign(update_msg->audience, &target->dhkey);

  log_debug(LOG_ROUTING,
            update_msg->uuid,
            "submitting update request to target key %s / %p",
            _np_key_as_str(target),
            target);

  bool serialize_ok = _np_message_serialize_chunked(context, update_msg);

  np_util_event_t update_event = {.type         = (evt_internal | evt_message),
                                  .user_data    = update_msg,
                                  .target_dhkey = event.target_dhkey};
  _np_event_runtime_add_event(context,
                              event.current_run,
                              target->dhkey,
                              update_event);

  // 5 cleanup
  np_key_unref_list(tmp, "_np_route_lookup");
  sll_free(np_key_ptr, tmp);

  return true;
}

bool _np_out_leave(np_state_t *context, const np_util_event_t event) {

  NP_CAST(event.user_data, struct np_e2e_message_s, leave_msg);

  bool serialize_ok = _np_message_serialize_chunked(context, leave_msg);

#ifdef DEBUG
  np_key_t *target_key = _np_keycache_find(context, event.target_dhkey);
  if (target_key != NULL) {
    log_debug(LOG_ROUTING,
              leave_msg->uuid,
              "submitting leave to target key %s / %p",
              _np_key_as_str(target_key),
              target_key);
    np_unref_obj(np_key_t, target_key, "_np_keycache_find");
  }
#endif // DEBUG
  np_util_event_t leave_event = {.type         = (evt_internal | evt_message),
                                 .user_data    = leave_msg,
                                 .target_dhkey = event.target_dhkey};
  _np_event_runtime_add_event(context,
                              event.current_run,
                              event.target_dhkey,
                              leave_event);
  // 5 cleanup
  return true;
}

bool _np_out_join(np_state_t *context, const np_util_event_t event) {

  NP_CAST(event.user_data, struct np_e2e_message_s, join_msg);

  np_tree_t *jrb_msg_body = np_tree_create();
  np_tree_t *jrb_my_node  = np_tree_create();
  np_tree_t *jrb_my_ident = NULL;

  // 1: create join payload
  np_aaatoken_encode(jrb_my_node, _np_key_get_token(context->my_node_key));
  np_tree_insert_str(jrb_msg_body,
                     _NP_URN_NODE_PREFIX,
                     np_treeval_new_cwt(jrb_my_node));
  log_debug(LOG_MESSAGE | LOG_ROUTING,
            join_msg->uuid,
            "added random identity token to join message");
  if (_np_key_cmp(context->my_identity, context->my_node_key) != 0) {
    jrb_my_ident = np_tree_create();
    np_aaatoken_encode(jrb_my_ident,
                       np_token_factory_get_public_ident_token(
                           _np_key_get_token(context->my_identity)));
    np_tree_insert_str(jrb_msg_body,
                       _NP_URN_IDENTITY_PREFIX,
                       np_treeval_new_cwt(jrb_my_ident));
    log_debug(LOG_MESSAGE | LOG_ROUTING,
              join_msg->uuid,
              "added user identity token to join message");
  }

  // 2. set it as body of message
  _np_message_setbody(join_msg, jrb_msg_body);

  bool serialize_ok = _np_message_serialize_chunked(context, join_msg);

#ifdef DEBUG
  np_key_t *target_key = _np_keycache_find(context, event.target_dhkey);
  if (target_key != NULL) {
    log_debug(LOG_ROUTING,
              join_msg->uuid,
              "submitting join request to target key %s / %p",
              _np_key_as_str(target_key),
              target_key);
    np_unref_obj(np_key_t, target_key, "_np_keycache_find");
  }
#endif // DEBUG

  np_util_event_t join_event = {.type         = (evt_internal | evt_message),
                                .user_data    = join_msg,
                                .target_dhkey = event.target_dhkey};
  _np_event_runtime_add_event(context,
                              event.current_run,
                              event.target_dhkey,
                              join_event);
  // 5 cleanup
  np_tree_free(jrb_msg_body);
  np_tree_free(jrb_my_node);
  if (NULL != jrb_my_ident) np_tree_free(jrb_my_ident);

  return true;
}

bool _np_out_handshake(np_state_t *context, const np_util_event_t event) {

  NP_CAST(event.user_data, struct np_e2e_message_s, hs_message);

  np_key_t     *target_key     = _np_keycache_find(context, event.target_dhkey);
  np_node_t    *target_node    = _np_key_get_node(target_key);
  np_network_t *target_network = _np_key_get_network(target_key);

  char local_ip[64] = {0};

  if (_np_node_check_address_validity(target_node) &&
      np_ok == _np_network_get_outgoing_ip(target_network,
                                           target_node->ip_string,
                                           target_node->protocol,
                                           local_ip)) {

    np_key_t *outgoing_node =
        _np_keycache_find_interface(context, local_ip, NULL);

    np_handshake_token_t *my_token = NULL;

    if (outgoing_node == NULL) {
      log_msg(LOG_WARNING,
              hs_message->uuid,
              "%s",
              "target node ip address doesn't match with our interface list");
      return false;
    } else {
      my_token = outgoing_node->entity_array[e_handshake_token];
    }

    np_tree_t *msg_body = np_tree_create();
    np_tree_t *jrb_body = np_tree_create();

    np_aaatoken_encode(jrb_body, my_token);
    np_tree_insert_str(msg_body,
                       _NP_URN_HANDSHAKE_PREFIX,
                       np_treeval_new_cwt(jrb_body));

    _np_message_setbody(hs_message, msg_body);

    np_tree_free(jrb_body);
    np_tree_free(msg_body);

    bool serialize_ok = _np_message_serialize_chunked(context, hs_message);

    if (*hs_message->parts != 1 && serialize_ok) {
      log_msg(LOG_ERROR,
              hs_message->uuid,
              "HANDSHAKE MESSAGE IS NOT 1024 BYTES IN SIZE! Message will not "
              "be send");
    } else {
      /* send data if handshake status is still just initialized or less */
      log_debug(LOG_ROUTING | LOG_HANDSHAKE,
                hs_message->uuid,
                "sending handshake message to %s (%s:%s)",
                _np_key_as_str(target_key),
                target_node->ip_string,
                target_node->port);

      np_util_event_t handshake_send_evt = {
          .type         = (evt_internal | evt_message),
          .user_data    = hs_message->msg_chunks[0],
          .target_dhkey = event.target_dhkey};
      _np_event_runtime_add_event(context,
                                  event.current_run,
                                  event.target_dhkey,
                                  handshake_send_evt);
    }
  } else {
    log_msg(LOG_ERROR,
            hs_message->uuid,
            "target node is not valid or cannot be joined");
  }

  np_unref_obj(np_key_t, target_key, "_np_keycache_find");

  return true;
}
