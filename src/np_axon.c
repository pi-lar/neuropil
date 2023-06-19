//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
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

/** message split up maths
 ** message size = 1b (common header) + 40b (encryption) +
 **                msg (header + instructions) + msg (properties + body) + msg
 *(footer)
 ** if (size > MSG_CHUNK_SIZE_1024)
 **     fixed_size = 1b + 40b + msg (header + instructions)
 **     payload_size = msg (properties) + msg(body) + msg(footer)
 **     #_of_chunks = int(payload_size / (MSG_CHUNK_SIZE_1024 - fixed_size)) + 1
 **     chunk_size = payload_size / #_of_chunks
 **     garbage_size = #_of_chunks * (fixed_size + chunk_size) %
 *MSG_CHUNK_SIZE_1024 // spezial behandlung garbage_size < 3
 **     add garbage
 ** else
 **     add garbage
 **/

bool _np_out_callback_wrapper(np_state_t           *context,
                              const np_util_event_t event) {
  log_trace_msg(LOG_TRACE, "start: void __np_out_callback_wrapper(...){");

  bool ret = false;

  NP_CAST(event.user_data, np_message_t, message);
  CHECK_STR_FIELD(message->header, _NP_MSG_HEADER_TO, msg_session_id);

  np_dhkey_t prop_out_dhkey =
      _np_msgproperty_tweaked_dhkey(OUTBOUND,
                                    *(_np_message_get_subject(message)));
  np_key_t *prop_out_key = _np_keycache_find(context, prop_out_dhkey);
  ASSERT(prop_out_key != NULL, "msgproperty key cannot be null");

  NP_CAST(prop_out_key->entity_array[0],
          np_msgproperty_conf_t,
          my_property_conf);
  NP_CAST(prop_out_key->entity_array[1], np_msgproperty_run_t, my_property_run);

  np_crypto_session_t crypto_session = {0};
  bool found_session = _np_intent_get_crypto_session(prop_out_key,
                                                     msg_session_id.value.dhkey,
                                                     &crypto_session);
  log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
                "(msg: %s) for subject \"%s\" has valid token",
                message->uuid,
                my_property_conf->msg_subject);

  if (FLAG_CMP(my_property_conf->ack_mode, ACK_DESTINATION)) {
    // TODO: create a copy in case of re-delivery for un-acked messages
    np_message_t *redeliver_copy = NULL;
    np_new_obj(np_message_t, redeliver_copy, FUNC);

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
    // POSSIBLE ASYNC POINT
    // char buf[100];
    // snprintf(buf,
    //          100,
    //          "urn:np:message:redelivery_conf:%s",
    //          redeliver_copy->uuid);
    // if (!np_jobqueue_submit_event(context,
    //                               0,
    //                               prop_out_dhkey,
    //                               redeliver_event,
    //                               buf)) {
    //   log_error(
    //       "Jobqueue rejected new job for message redelivery configuration of
    //       " "msg %s. No resend will be initiated.", redeliver_copy->uuid);
    // }
    np_unref_obj(np_message_t, redeliver_copy, FUNC);
  }

  // encrypt the relevant message part itself
  _np_message_encrypt_payload(message, &crypto_session);
  memset(&crypto_session, 0, sizeof(np_crypto_session_t));

  ret = true;

__np_cleanup__:
  np_unref_obj(np_key_t, prop_out_key, "_np_keycache_find");
  return ret;
}

void __np_axon_chunk_and_send(np_state_t         *context,
                              np_event_runtime_t *current_run,
                              np_message_t       *msg,
                              np_dhkey_t          msg_to,
                              np_sll_t(np_dhkey_t, tmp)) {

  // 2: chunk the message if required
  if (msg->is_single_part == false) {
    _np_message_calculate_chunking(msg);
    _np_message_serialize_chunked(context, msg);
  }

  // 3: send over to msg splitter
  char            buf[65]  = {0};
  uint16_t        chunk_id = 0;
  uint16_t        chunks   = 0;
  np_tree_elem_t *_tmp;
  if (msg->instructions != NULL &&
      NULL !=
          (_tmp = np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS))) {
    chunks   = _tmp->val.value.a2_ui[0];
    chunk_id = _tmp->val.value.a2_ui[1];
  }

  // check for duplicate message sending (outbound)
  np_dhkey_t _cache_msg_id = msg_to;
  np_generate_subject(&_cache_msg_id, msg->uuid, NP_UUID_BYTES);
  np_generate_subject(&_cache_msg_id, &chunk_id, sizeof(uint16_t));

  bool _send_before = false;
  np_spinlock_lock(&context->msg_forward_filter_lock);
  {
    _send_before =
        _np_decaying_bloom_check(context->msg_forward_filter, _cache_msg_id);
    if (!_send_before) {
      _np_decaying_bloom_decay(context->msg_forward_filter);
      _np_decaying_bloom_add(context->msg_forward_filter, _cache_msg_id);
    } else {
      log_info(LOG_ROUTING,
               "not sending message (%s) to target %s",
               msg->uuid,
               np_id_str(buf, &msg_to));
      np_spinlock_unlock(&context->msg_forward_filter_lock);
      return;
    }
  }
  np_spinlock_unlock(&context->msg_forward_filter_lock);

  sll_iterator(np_dhkey_t) key_iter = sll_first(tmp);
  while (key_iter != NULL) {
    if (!_np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey) &&
        _np_keycache_exists(context, key_iter->val, NULL)) {
      log_info(LOG_ROUTING,
               "sending    message (%s) to hop %s",
               msg->uuid,
               np_id_str(buf, &key_iter->val));
      np_util_event_t send_event = {.type      = (evt_internal | evt_message),
                                    .user_data = msg,
                                    .target_dhkey = msg_to};
      _np_event_runtime_add_event(context,
                                  current_run,
                                  key_iter->val,
                                  send_event);
      /* POSSIBLE ASYNC POINT
      char buf[100];
      snprintf(buf, 100, "urn:np:message:splitter:%s", msg->uuid);
      if(!np_jobqueue_submit_event(context, 0, key_iter->val, send_event, buf)){
          log_error("Jobqueue rejected new job for messagepart delivery of msg
      %s", msg->uuid
          );
      }
      */
    } else {
      char buf[65] = {0};
      log_info(LOG_ROUTING,
               "do not send message (%s) to hop %s as: %s %s %s",
               msg->uuid,
               np_id_str(buf, &key_iter->val),
               _send_before ? "msg was already send;" : "",
               _np_dhkey_equal(&key_iter->val, &context->my_node_key->dhkey)
                   ? "target would be me;"
                   : "",
               _np_keycache_exists(context, key_iter->val, NULL)
                   ? ""
                   : "target is not connected to me;");
    }
    sll_next(key_iter);
  }
}

int8_t __dhkey_compare(const np_dhkey_t left, const np_dhkey_t right) {
  return _np_dhkey_cmp(&left, &right);
}

bool _np_out_forward(np_state_t *context, np_util_event_t event) {
  log_trace_msg(LOG_TRACE, "start: bool _np_out_forward(...){");

  NP_CAST(event.user_data, np_message_t, forward_msg);

  // CHECK_STR_FIELD(forward_msg->header, _NP_MSG_HEADER_FROM, msg_from);
  CHECK_STR_FIELD(forward_msg->header, _NP_MSG_HEADER_TO, msg_to);
  CHECK_STR_FIELD(forward_msg->header, _NP_MSG_HEADER_SUBJECT, msg_subj);

  if (!_np_route_my_key_has_connection(context)) {
    log_msg(
        LOG_INFO,
        "--- request for forward message (%s) out, but no connections left ...",
        forward_msg->uuid);
    return false;
  }

  uint8_t i          = 0;
  float   target_age = 1.0;

  np_sll_t(np_dhkey_t, tmp) = NULL;
  sll_init(np_dhkey_t, tmp);
  do {
    _np_pheromone_snuffle_receiver(context,
                                   tmp,
                                   msg_subj.value.dhkey,
                                   &target_age);

    // remove the node, where the message came from, from list
    sll_remove(np_dhkey_t, tmp, event.target_dhkey, __dhkey_compare);
    i++;
    target_age -= 0.1;
  } while (sll_size(tmp) == 0 && i < 8);

  if (sll_size(tmp) == 0) {
    log_info(
        LOG_ROUTING,
        "--- request for forward message (%s) out, but no routing found ...",
        forward_msg->uuid);
    sll_free(np_dhkey_t, tmp);
    return false;

  } else {
    log_info(LOG_ROUTING,
             "--- forward message (%s) out, %d hops found ...",
             forward_msg->uuid,
             sll_size(tmp));
  }
  __np_axon_chunk_and_send(context,
                           event.current_run,
                           forward_msg,
                           msg_to.value.dhkey,
                           tmp);

  // 4 cleanup
  sll_free(np_dhkey_t, tmp);
  _np_pheromone_exhale(context);

__np_cleanup__ : {}

  return true;
}

bool _np_out_default(np_state_t *context, np_util_event_t event) {
  log_trace_msg(LOG_TRACE, "start: bool _np_out_default(...){");

  NP_CAST(event.user_data, np_message_t, default_msg);

  CHECK_STR_FIELD(default_msg->header, _NP_MSG_HEADER_TO, msg_to);
  CHECK_STR_FIELD(default_msg->header, _NP_MSG_HEADER_SUBJECT, msg_subj);

  if (!_np_route_my_key_has_connection(context)) {
    log_info(LOG_ROUTING,
             "--- request for default message (%s)  out, but no connections "
             "left ...",
             default_msg->uuid);
    return false;
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
                                   msg_subj.value.dhkey,
                                   &target_probability);
    i++;
    target_probability -= 0.1;
  };

  if (sll_size(tmp) == 0) {
    log_info(
        LOG_ROUTING,
        "--- request for default message (%s) out, but no routing found ...",
        default_msg->uuid);
    sll_free(np_dhkey_t, tmp);
    return false;
  }

  __np_axon_chunk_and_send(context,
                           event.current_run,
                           default_msg,
                           msg_to.value.dhkey,
                           tmp);

  // 4 cleanup
  sll_free(np_dhkey_t, tmp);

__np_cleanup__ : {}

  //_np_pheromone_exhale(context);

  return true;
}

bool _np_out_available_messages(np_state_t *context, np_util_event_t event) {
  log_trace_msg(LOG_TRACE, "start: bool _np_out_available_messages(...){");

  NP_CAST(event.user_data, np_message_t, available_msg);
  ASSERT(available_msg->header != NULL, "Header Tree has to be filled");

  CHECK_STR_FIELD(available_msg->header, _NP_MSG_HEADER_TO, msg_to);
  CHECK_STR_FIELD(available_msg->header, _NP_MSG_HEADER_SUBJECT, msg_subj);

  log_debug_msg(LOG_ROUTING,
                "handling available request {%s}",
                available_msg->uuid);

  if (!_np_route_my_key_has_connection(context)) {
    log_debug_msg(
        LOG_WARNING,
        "--- request for available message {%s} out, but no connections "
        "left ...",
        available_msg->uuid);
    return false;
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

  bool find_receiver = _np_dhkey_equal(&msg_subj.value.dhkey, &sender_dhkey);
  bool find_sender   = _np_dhkey_equal(&msg_subj.value.dhkey, &receiver_dhkey);
  char _msg_subj_str[100] = {0};
  np_regenerate_subject(context, _msg_subj_str, 100, &msg_subj.value.dhkey);

  uint8_t i = 0;
  while (sll_size(tmp) == 0 && i < 9) {
    float target_age = original_target_age;

    if (find_receiver) {
      _np_pheromone_snuffle_receiver(context,
                                     tmp,
                                     msg_to.value.dhkey,
                                     &target_age);
    } else if (find_sender) {
      _np_pheromone_snuffle_sender(context,
                                   tmp,
                                   msg_to.value.dhkey,
                                   &target_age);
    } else {
      log_error(LOG_ERROR, "cannot search for both, receiver and sender");
      break;
    }
    i++;
    original_target_age -= 0.1;
    log_debug_msg(LOG_ROUTING,
                  "--- (msg: %s) request for available message out %s: search: "
                  "%f found: %f",
                  available_msg->uuid,
                  _msg_subj_str,
                  original_target_age,
                  target_age);
  };

  if (sll_size(tmp) == 0) {
    log_debug_msg(
        LOG_ROUTING,
        "--- (msg: %s) request for available message (%s) out, but no "
        "routing found ... find_receiver: %" PRIu8 " find_sender: %" PRIu8,
        available_msg->uuid,
        _msg_subj_str,
        find_receiver,
        find_sender);
    sll_free(np_dhkey_t, tmp);
    return false;
  }

  sll_iterator(np_dhkey_t) target_iter = sll_first(tmp);
  while (NULL != target_iter) {
    // remove previous hop from sender list
    char buf[65];
    buf[64] = '\0';
    if (_np_dhkey_equal(&target_iter->val, &event.target_dhkey)) {
      log_msg(LOG_DEBUG | LOG_ROUTING,
              "discarding available message to previous hop %s",
              np_id_str(buf, &target_iter->val));
      sll_delete(np_dhkey_t, tmp, target_iter);
      break;
    }
    sll_next(target_iter);
  }

  if (sll_size(tmp) > 0) {
    __np_axon_chunk_and_send(context,
                             event.current_run,
                             available_msg,
                             msg_to.value.dhkey,
                             tmp);
  }
  sll_free(np_dhkey_t, tmp);

  _np_pheromone_exhale(context);

__np_cleanup__ : {}

  return true;
}

bool _np_out_pheromone(np_state_t *context, np_util_event_t msg_event) {
  log_trace_msg(LOG_TRACE, "start: bool _np_out_pheromone(...) {");

  if (!_np_route_my_key_has_connection(context)) {
    log_msg(LOG_WARNING,
            "--- request for pheromone update message out, but no connections "
            "left ...");
    return false;
  }

  NP_CAST(msg_event.user_data, np_message_t, pheromone_msg_out);
  CHECK_STR_FIELD(pheromone_msg_out->header, _NP_MSG_HEADER_TO, msg_to);

  // check for the routing intent: generic or to a specific node
  bool is_generic_direction =
      _np_dhkey_equal(&msg_to.value.dhkey, &msg_event.target_dhkey);
  np_sll_t(np_dhkey_t, tmp_dhkeys);
  sll_init(np_dhkey_t, tmp_dhkeys);

  // 1: find next hop based on fingerprint of the token
  np_sll_t(np_key_ptr, tmp) = NULL;

  char *source_sll_of_keys = "_np_route_lookup";

  if (is_generic_direction) {
    // lookup based on 2: leafset excluded
    tmp = _np_route_lookup(context, msg_event.target_dhkey, 2);
    if (sll_size(tmp) == 0) {
      sll_free(np_key_ptr, tmp);
      // lookup based on 1: leafset included
      tmp = _np_route_lookup(context, msg_event.target_dhkey, 1);
    }
    if (sll_size(tmp) > 0)
      sll_append(np_dhkey_t, tmp_dhkeys, sll_first(tmp)->val->dhkey);

  } else {
    // already found a pheromone scent, use it!
    sll_init(np_key_ptr, tmp);
    sll_append(np_dhkey_t, tmp_dhkeys, msg_event.target_dhkey);
  }

  log_msg(LOG_INFO | LOG_ROUTING,
          "have pheromone request for %d hops (%s)",
          sll_size(tmp_dhkeys),
          is_generic_direction ? "generic" : "targeted");

  if (sll_size(tmp_dhkeys) > 0) {
    // only send if a target has been found
    __np_axon_chunk_and_send(context,
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

__np_cleanup__ : {}

  return true;
}

/**
 ** _np_network_append_msg_to_out_queue: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
bool _np_out_ack(np_state_t *context, np_util_event_t event) {
  log_trace_msg(LOG_TRACE,
                "start: bool _np_send_ack(np_state_t* context, np_util_event_t "
                "msg_event){");

  NP_CAST(event.user_data, np_message_t, ack_msg);

  CHECK_STR_FIELD(ack_msg->header,
                  _NP_MSG_HEADER_TO,
                  msg_to); // dhkey of a node
  CHECK_STR_FIELD(ack_msg->header,
                  _NP_MSG_HEADER_SUBJECT,
                  msg_subj); // "ack" msg subject

  if (!_np_route_my_key_has_connection(context)) {
    log_msg(LOG_INFO,
            "--- request for forward message out, but no connections left ...");
    return false;
  }

  float target_age          = 1.0;
  np_sll_t(np_dhkey_t, tmp) = NULL;
  sll_init(np_dhkey_t, tmp);

  np_dhkey_t ack_to_dhkey = msg_to.value.dhkey;

  // 1: check if the ack is for a direct neighbour
  np_key_t *target_key = _np_keycache_find(context, ack_to_dhkey);
  if (NULL == target_key) {
    // no --> 2: follow the ack trail of the "to" + "ack" dhkey path
    np_generate_subject(&ack_to_dhkey, _NP_MSG_ACK, strnlen(_NP_MSG_ACK, 256));
    // lookup based on original msg subject, but snuffle for sender
    uint8_t i = 0;
    while (sll_size(tmp) == 0 && target_age > BAD_LINK) {
      _np_pheromone_snuffle_receiver(context, tmp, ack_to_dhkey, &target_age);
      target_age -= 0.1;
    };
    // routing based on pheromones, exhale ...
    _np_pheromone_exhale(context);
  } else {
    // yes --> 3a check whether the neighbour is in our routing/leafset table
    np_node_t *node = _np_key_get_node(target_key);
    if (node->is_in_leafset || node->is_in_routing_table) {
      // yes --> 3b. append to result list
      sll_append(np_dhkey_t, tmp, ack_to_dhkey);
      np_unref_obj(np_key_t, target_key, "_np_keycache_find");
    }
  }

  if (sll_size(tmp) == 0) { // exit early if no routing has been found
    log_info(LOG_ROUTING,
             "--- request for ack message out, but no routing found ...");
    sll_free(np_dhkey_t, tmp);
    return false;
  }

  __np_axon_chunk_and_send(context,
                           event.current_run,
                           ack_msg,
                           msg_to.value.dhkey,
                           tmp);

  sll_free(np_dhkey_t, tmp);

__np_cleanup__ : {}

  return true;
}

bool _np_out_ping(np_state_t *context, const np_util_event_t event) {
  log_trace_msg(LOG_TRACE, "start: bool _np_out_ping(...) {");

  NP_CAST(event.user_data, np_message_t, ping_msg);
  log_trace_msg(LOG_ROUTING,
                "_np_out_ping for message uuid %s",
                ping_msg->uuid);

  // 2: chunk the message if required
  _np_message_calculate_chunking(ping_msg);
  _np_message_serialize_chunked(context, ping_msg);

  _np_message_add_response_handler(ping_msg, event, true);

  // 3: send over the message parts
  _LOCK_ACCESS(&ping_msg->msg_chunks_lock) {
    pll_iterator(np_messagepart_ptr) iter = pll_first(ping_msg->msg_chunks);
    while (NULL != iter) {
      memcpy(iter->val->uuid, ping_msg->uuid, NP_UUID_BYTES);
      np_util_event_t ping_event = {.type      = (evt_internal | evt_message),
                                    .user_data = iter->val,
                                    .target_dhkey = event.target_dhkey};
      _np_event_runtime_add_event(context,
                                  event.current_run,
                                  ping_event.target_dhkey,
                                  ping_event);

      pll_next(iter);
    }
  }

  return true;
}

bool _np_out_piggy(np_state_t *context, const np_util_event_t event) {
  log_trace_msg(LOG_TRACE, "start: bool _np_out_piggy(...) {");

  NP_CAST(event.user_data, np_message_t, piggy_msg);

  // TODO: use
  // __np_axon_chunk_and_send(context, event.current_run, piggy_msg, ...);

  // 2: chunk the message if required
  _np_message_calculate_chunking(piggy_msg);
  _np_message_serialize_chunked(context, piggy_msg);

  // 3: send over the message parts
  _LOCK_ACCESS(&piggy_msg->msg_chunks_lock) {
    pll_iterator(np_messagepart_ptr) iter = pll_first(piggy_msg->msg_chunks);
    while (NULL != iter) {
#ifdef DEBUG
      np_key_t *target_key = _np_keycache_find(context, event.target_dhkey);
      if (target_key != NULL) {
        log_debug_msg(LOG_ROUTING,
                      "submitting piggy to target key %s / %p",
                      _np_key_as_str(target_key),
                      target_key);
        np_unref_obj(np_key_t, target_key, "_np_keycache_find");
      }
#endif // DEBUG
      memcpy(iter->val->uuid, piggy_msg->uuid, NP_UUID_BYTES);
      np_util_event_t piggy_event = {.type      = (evt_internal | evt_message),
                                     .user_data = iter->val,
                                     .target_dhkey = event.target_dhkey};
      _np_event_runtime_add_event(context,
                                  event.current_run,
                                  event.target_dhkey,
                                  piggy_event);

      pll_next(iter);
    }
  }

  return true;
}

bool _np_out_update(np_state_t *context, const np_util_event_t event) {
  log_trace_msg(LOG_TRACE, "start: bool _np_out_update(...) {");

  if (!_np_route_my_key_has_connection(context)) {
    log_msg(LOG_WARNING,
            "--- request for update message out, but no connections left ...");
    return false;
  }

  NP_CAST(event.user_data, np_message_t, update_msg);

  // 3: find next hop based on fingerprint of the token
  np_sll_t(np_key_ptr, tmp) = NULL;
  uint8_t i                 = 1;
  do {
    tmp = _np_route_lookup(context, event.target_dhkey, i);
    i++;
  } while (sll_size(tmp) == 0 && i < 5);

  if (tmp == NULL || sll_size(tmp) == 0) {
    log_msg(
        LOG_WARNING,
        "--- request for update message out, but no connections left (2) ...");
    return false;
  }
  np_key_t *target = sll_first(tmp)->val;

  if (_np_dhkey_equal(&target->dhkey, &context->my_node_key->dhkey)) {
    log_msg(LOG_WARNING,
            "--- request for update message out, but this is already the "
            "nearest node ...");
    np_key_unref_list(tmp, "_np_route_lookup");
    sll_free(np_key_ptr, tmp);
    return false;
  }

  np_tree_replace_str(update_msg->header,
                      _NP_MSG_HEADER_TO,
                      np_treeval_new_dhkey(target->dhkey));
  _np_message_trace_info("MSG_OUT_UPDATE", update_msg);

  // 4: chunk the message if required
  // TODO: send two separate messages?
  _np_message_calculate_chunking(update_msg);
  _np_message_serialize_chunked(context, update_msg);

  // 5: send over the message parts
  _LOCK_ACCESS(&update_msg->msg_chunks_lock) {
    pll_iterator(np_messagepart_ptr) iter = pll_first(update_msg->msg_chunks);
    while (NULL != iter) {
      log_debug_msg(LOG_ROUTING,
                    "submitting update request to target key %s / %p",
                    _np_key_as_str(target),
                    target);
      memcpy(iter->val->uuid, update_msg->uuid, NP_UUID_BYTES);
      np_util_event_t update_event = {.type      = (evt_internal | evt_message),
                                      .user_data = iter->val,
                                      .target_dhkey = event.target_dhkey};
      _np_event_runtime_add_event(context,
                                  event.current_run,
                                  target->dhkey,
                                  update_event);
      pll_next(iter);
    }
  }

  // 5 cleanup
  np_key_unref_list(tmp, "_np_route_lookup");
  sll_free(np_key_ptr, tmp);

  return true;
}

bool _np_out_leave(np_state_t *context, const np_util_event_t event) {
  log_trace_msg(LOG_TRACE, "start: bool _np_out_leave(...) {");

  NP_CAST(event.user_data, np_message_t, leave_msg);

  // 2: chunk the message if required
  _np_message_calculate_chunking(leave_msg);
  _np_message_serialize_chunked(context, leave_msg);

  // 3: send over the message parts
  _LOCK_ACCESS(&leave_msg->msg_chunks_lock) {
    pll_iterator(np_messagepart_ptr) iter = pll_first(leave_msg->msg_chunks);

    while (NULL != iter) {
#ifdef DEBUG
      np_key_t *target_key = _np_keycache_find(context, event.target_dhkey);
      if (target_key != NULL) {
        log_debug_msg(LOG_ROUTING,
                      "submitting leave to target key %s / %p",
                      _np_key_as_str(target_key),
                      target_key);
        np_unref_obj(np_key_t, target_key, "_np_keycache_find");
      }
#endif // DEBUG
      memcpy(iter->val->uuid, leave_msg->uuid, NP_UUID_BYTES);
      np_util_event_t leave_event = {.type      = (evt_internal | evt_message),
                                     .user_data = iter->val,
                                     .target_dhkey = event.target_dhkey};
      _np_event_runtime_add_event(context,
                                  event.current_run,
                                  event.target_dhkey,
                                  leave_event);

      pll_next(iter);
    }
  }
  // 5 cleanup
  return true;
}

bool _np_out_join(np_state_t *context, const np_util_event_t event) {
  log_trace_msg(LOG_TRACE, "start: bool _np_out_join_req(...) {");

  NP_CAST(event.user_data, np_message_t, join_msg);

  np_tree_t *jrb_data     = np_tree_create();
  np_tree_t *jrb_my_node  = np_tree_create();
  np_tree_t *jrb_my_ident = NULL;

  // 1: create join payload
  np_aaatoken_encode(jrb_my_node, _np_key_get_token(context->my_node_key));
  np_tree_insert_str(jrb_data,
                     _NP_URN_NODE_PREFIX,
                     np_treeval_new_cwt(jrb_my_node));

  if (_np_key_cmp(context->my_identity, context->my_node_key) != 0) {
    jrb_my_ident = np_tree_create();
    np_aaatoken_encode(jrb_my_ident,
                       np_token_factory_get_public_ident_token(
                           _np_key_get_token(context->my_identity)));
    np_tree_insert_str(jrb_data,
                       _NP_URN_IDENTITY_PREFIX,
                       np_treeval_new_cwt(jrb_my_ident));
  }
  // 2. set it as body of message
  _np_message_setbody(join_msg, jrb_data);

  // 3: chunk the message if required
  // TODO: send two separate messages?
  _np_message_calculate_chunking(join_msg);
  _np_message_serialize_chunked(context, join_msg);

  // 4: send over the message parts

#ifdef DEBUG
  np_key_t *target_key = _np_keycache_find(context, event.target_dhkey);
  if (target_key != NULL) {
    log_debug(LOG_ROUTING,
              "submitting join request (%s) to target key %s / %p",
              join_msg->uuid,
              _np_key_as_str(target_key),
              target_key);
    np_unref_obj(np_key_t, target_key, "_np_keycache_find");
  }
#endif // DEBUG
  _LOCK_ACCESS(&join_msg->msg_chunks_lock) {
    pll_iterator(np_messagepart_ptr) iter = pll_first(join_msg->msg_chunks);
    while (NULL != iter) {
      memcpy(iter->val->uuid, join_msg->uuid, NP_UUID_BYTES);
      np_util_event_t join_event = {.type      = (evt_internal | evt_message),
                                    .user_data = iter->val,
                                    .target_dhkey = event.target_dhkey};
      _np_event_runtime_add_event(context,
                                  event.current_run,
                                  event.target_dhkey,
                                  join_event);
      pll_next(iter);
    }
  }
  // 5 cleanup
  np_tree_free(jrb_my_node);
  if (NULL != jrb_my_ident) np_tree_free(jrb_my_ident);

  return true;
}

bool _np_out_handshake(np_state_t *context, const np_util_event_t event) {
  log_trace_msg(LOG_TRACE, "start: bool _np_out_handshake(...) {");

  NP_CAST(event.user_data, np_message_t, hs_message);

  np_key_t *target_key = _np_keycache_find(context, event.target_dhkey);

  np_node_t *target_node = _np_key_get_node(target_key);
  // np_node_t* my_node = _np_key_get_node(context->my_node_key);

  NP_PERFORMANCE_POINT_START(handshake_out);
  if (_np_node_check_address_validity(target_node)) {
    np_tree_t *jrb_body = np_tree_create();
    // get our node identity from the cache
    np_handshake_token_t *my_token =
        _np_token_factory_new_handshake_token(context);

    np_aaatoken_encode(jrb_body, my_token);
    np_tree_insert_str(hs_message->body,
                       _NP_URN_HANDSHAKE_PREFIX,
                       np_treeval_new_cwt(jrb_body));
    // _np_message_setbody(hs_message, jrb_body);

    np_unref_obj(np_aaatoken_t,
                 my_token,
                 "_np_token_factory_new_handshake_token");

    _np_message_calculate_chunking(hs_message);

    bool serialize_ok = _np_message_serialize_chunked(context, hs_message);

    if (hs_message->no_of_chunks != 1 || serialize_ok == false) {
      log_msg(LOG_ERROR,
              "HANDSHAKE MESSAGE IS NOT 1024 BYTES IN SIZE! Message will not "
              "be send");
      log_debug(LOG_HANDSHAKE,
                "HANDSHAKE MESSAGE: no_of_chunks:%" PRIu32
                ", serialize: %" PRIu8,
                hs_message->no_of_chunks,
                serialize_ok);
    } else {
      /* send data if handshake status is still just initialized or less */
      log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE | LOG_DEBUG,
                    "sending handshake message %s to %s (%s:%s)",
                    hs_message->uuid,
                    _np_key_as_str(target_key),
                    target_node->dns_name,
                    target_node->port);

      _LOCK_ACCESS(&hs_message->msg_chunks_lock) {
        pll_iterator(np_messagepart_ptr) iter =
            pll_first(hs_message->msg_chunks);
        np_ref_obj(np_messagepart_t, iter->val, FUNC);
        np_util_event_t handshake_send_evt = {
            .type         = (evt_internal | evt_message),
            .user_data    = iter->val,
            .target_dhkey = event.target_dhkey};
        _np_event_runtime_add_event(context,
                                    event.current_run,
                                    event.target_dhkey,
                                    handshake_send_evt);
      }
    }
  } else {
    log_msg(LOG_ERROR, "target node is not valid");
  }
  NP_PERFORMANCE_POINT_END(handshake_out);

  np_unref_obj(np_key_t, target_key, "_np_keycache_find");

  return true;
}
