//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that
// a node can have. It is included form np_key.c, therefore there are no extra
// #include directives.

#include "core/np_comp_msgproperty.h"

#include <inttypes.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "neuropil_data.h"

#include "core/np_comp_intent.h"
#include "util/np_bloom.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_aaatoken.h"
#include "np_attributes.h"
#include "np_axon.h"
#include "np_eventqueue.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_message.h"
#include "np_pheromones.h"
#include "np_responsecontainer.h"
#include "np_statistics.h"
#include "np_token_factory.h"

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_msgproperty_conf_ptr);
NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_msgproperty_run_ptr);

NP_SLL_GENERATE_IMPLEMENTATION(np_msgproperty_conf_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_msgproperty_run_ptr);

#include "../np_msgproperty_init.c.part"

static np_dhkey_t __local_tx_dhkey = {0};
static np_dhkey_t __local_rx_dhkey = {0};

struct np_redelivery_data_s {
  np_dhkey_t               target;
  double                   redelivery_at;
  struct np_e2e_message_s *message;
};
typedef struct np_redelivery_data_s np_redelivery_data_t;

np_dhkey_t _np_msgproperty_tweaked_dhkey(np_msg_mode_type mode_type,
                                         np_dhkey_t       subject) {
  np_dhkey_t result = {0};
  if (mode_type == INBOUND) _np_dhkey_add(&result, &__local_rx_dhkey, &subject);
  if (mode_type == OUTBOUND)
    _np_dhkey_add(&result, &__local_tx_dhkey, &subject);

  return result;
}

np_dhkey_t _np_msgproperty_dhkey(np_msg_mode_type mode_type,
                                 const char      *subject) {
  np_dhkey_t _dhkey = _np_dhkey_generate_hash(subject, strnlen(subject, 256));
  if (mode_type == INBOUND) _np_dhkey_add(&_dhkey, &__local_rx_dhkey, &_dhkey);
  if (mode_type == OUTBOUND) _np_dhkey_add(&_dhkey, &__local_tx_dhkey, &_dhkey);

  return _dhkey;
}

void __np_msgproperty_threshold_increase(
    const np_msgproperty_conf_t *const self_conf, np_msgproperty_run_t *self) {
  if (self->msg_threshold < self_conf->max_threshold) {
    self->msg_threshold++;
  }
}

bool __np_msgproperty_threshold_breached(
    const np_msgproperty_conf_t *const self_conf, np_msgproperty_run_t *self) {
  if ((self->msg_threshold) > self_conf->max_threshold) {
    return true;
  }
  return false;
}

void __np_msgproperty_threshold_decrease(
    NP_UNUSED const np_msgproperty_conf_t *const self_conf,
    np_msgproperty_run_t                        *self) {
  if (self->msg_threshold > 0) {
    self->msg_threshold--;
  }
}

void _np_msgproperty_conf_t_new(np_state_t       *context,
                                NP_UNUSED uint8_t type,
                                NP_UNUSED size_t  size,
                                void             *property) {
  struct np_msgproperty_conf_s *prop = (struct np_msgproperty_conf_s *)property;

  prop->token_min_ttl = MSGPROPERTY_DEFAULT_MIN_TTL_SEC;
  prop->token_max_ttl = MSGPROPERTY_DEFAULT_MAX_TTL_SEC;

  // prop->msg_audience	= NULL;
  prop->msg_subject = NULL;
  prop->rep_subject = NULL;

  prop->mode_type = OUTBOUND | INBOUND;
  prop->mep_type  = DEFAULT_TYPE;
  prop->ack_mode  = ACK_NONE;
  prop->priority  = PRIORITY_MOD_USER_DEFAULT;
  prop->retry     = 3;
  prop->msg_ttl   = MSGPROPERTY_DEFAULT_MSG_TTL;

  // cache which will hold up to max_threshold messages
  prop->cache_policy  = FIFO | OVERFLOW_PURGE;
  prop->cache_size    = 16;
  prop->max_threshold = 2;

  prop->is_internal   = false;
  prop->audience_type = NP_MX_AUD_PUBLIC;

  prop->unique_uuids_check = false;

  memset(&prop->audience_id, 0, NP_FINGERPRINT_BYTES);
  memset(&prop->subject_dhkey, 0, NP_FINGERPRINT_BYTES);
  memset(&prop->subject_dhkey_in, 0, NP_FINGERPRINT_BYTES);
  memset(&prop->subject_dhkey_out, 0, NP_FINGERPRINT_BYTES);
  // memset(&prop->subject_dhkey_wire, 0, NP_FINGERPRINT_BYTES);
}

void _np_msgproperty_run_t_new(np_state_t       *context,
                               NP_UNUSED uint8_t type,
                               NP_UNUSED size_t  size,
                               void             *property) {

  struct np_msgproperty_run_s *prop = (struct np_msgproperty_run_s *)property;

  sll_init(np_evt_callback_t, prop->callbacks);
  sll_init(np_usercallback_ptr, prop->user_callbacks);

  prop->msg_threshold = 0;

  prop->response_handler = np_tree_create(); // only used for msghandler NP_ACK
  prop->redelivery_messages =
      np_tree_create(); // only used for msghandler "is_internal=false"

  dll_init(np_message_ptr, prop->msg_cache);

  prop->unique_uuids = np_tree_create();

  np_init_datablock(prop->attributes, sizeof(prop->attributes));

  double now                  = np_time_now();
  prop->last_update           = now;
  prop->last_intent_update    = 0;
  prop->last_pheromone_update = 0;

  prop->authorize_func = NULL;
}

void _np_msgproperty_conf_t_del(NP_UNUSED np_state_t *context,
                                NP_UNUSED uint8_t     type,
                                NP_UNUSED size_t      size,
                                void                 *property) {
  // log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_conf_t_del(void*
  // property){");
  struct np_msgproperty_conf_s *prop = (struct np_msgproperty_conf_s *)property;

  log_debug(LOG_MSGPROPERTY,
            NULL,
            "Deleting msgproperty %s",
            prop->msg_subject);
  assert(prop != NULL);

  if (prop->msg_subject != NULL) {
    free(prop->msg_subject);
    prop->msg_subject = NULL;
  }
  if (prop->rep_subject != NULL) {
    free(prop->rep_subject);
    prop->rep_subject = NULL;
  }
}

void _np_msgproperty_run_t_del(NP_UNUSED np_state_t *context,
                               NP_UNUSED uint8_t     type,
                               NP_UNUSED size_t      size,
                               void                 *property) {
  // log_trace_msg(LOG_TRACE, "start: void _np_msgproperty_run_t_del(void*
  // property){");
  struct np_msgproperty_run_s *prop = (struct np_msgproperty_run_s *)property;

  // log_debug(LOG_MSGPROPERTY, NULL, "Deleting msgproperty %s",
  // prop->msg_subject);

  assert(prop != NULL);

  np_tree_free(prop->unique_uuids);
  np_tree_free(prop->response_handler);    //
  np_tree_free(prop->redelivery_messages); //

  if (prop->msg_cache != NULL) {
    dll_free(np_message_ptr, prop->msg_cache);
  }

  if (prop->user_callbacks != NULL) {
    sll_free(np_usercallback_ptr, prop->user_callbacks);
  }
  sll_free(np_evt_callback_t, prop->callbacks);
}

/**
 ** _np_msgproperty_init
 ** Initialize message property subsystem.
 **/
bool _np_msgproperty_init(np_state_t *context) {
  __local_tx_dhkey = _np_dhkey_generate_hash("local_tx", 8);
  __local_rx_dhkey = _np_dhkey_generate_hash("local_rx", 8);

  // NEUROPIL_INTERN_MESSAGES
  np_sll_t(np_msgproperty_conf_ptr, msgproperties);
  msgproperties = default_msgproperties(context);
  sll_iterator(np_msgproperty_conf_ptr) __np_internal_messages =
      sll_first(msgproperties);

  while (__np_internal_messages != NULL) {
    np_msgproperty_conf_t *property = __np_internal_messages->val;
    property->is_internal           = true;
    property->audience_type         = NP_MX_AUD_PUBLIC;

    if (strlen(property->msg_subject) > 0) {
      // np_dhkey_t subject_dhkey = {0};
      np_generate_subject((np_subject *)&property->subject_dhkey,
                          property->msg_subject,
                          strnlen(property->msg_subject, 256));
#ifdef DEBUG
      char hex[65];
      log_debug(LOG_MSGPROPERTY,
                NULL,
                "register handler: %s (%" PRIsizet ") hex: %s",
                property->msg_subject,
                strnlen(property->msg_subject, 256),
                sodium_bin2hex(hex, 65, &property->subject_dhkey, 32));
#endif
      np_msgproperty_register(property);
    }
    sll_next(__np_internal_messages);
  }
  sll_free(np_msgproperty_conf_ptr, msgproperties);
  return true;
}

void _np_msgproperty_destroy(np_state_t *context) {
  // NEUROPIL_INTERN_MESSAGES
  np_sll_t(np_msgproperty_conf_ptr, msgproperties);
  msgproperties = default_msgproperties(context);
  sll_iterator(np_msgproperty_conf_ptr) __np_internal_messages =
      sll_first(msgproperties);
  while (__np_internal_messages != NULL) {
    np_msgproperty_conf_t *property = __np_internal_messages->val;
    np_dhkey_t             subject_in_dhkey =
        _np_msgproperty_dhkey(INBOUND, property->msg_subject);
    _np_keycache_remove(context, subject_in_dhkey);
    np_dhkey_t subject_out_dhkey =
        _np_msgproperty_dhkey(OUTBOUND, property->msg_subject);
    _np_keycache_remove(context, subject_out_dhkey);

    sll_next(__np_internal_messages);
  }
}

/**
 ** returns the msgproperty struct #func# for the given #mode_type# and
 *#subject#,
 **/
np_msgproperty_conf_t *_np_msgproperty_conf_get(np_state_t      *context,
                                                np_msg_mode_type mode_type,
                                                np_dhkey_t       subject) {
  np_msgproperty_conf_t *ret = NULL;
  // _np_msgproperty_dhkey(DEFAULT_MODE, subject);

  if (FLAG_CMP(mode_type, INBOUND)) { // search receiving property
    np_dhkey_t search_in_dhkey =
        _np_msgproperty_tweaked_dhkey(INBOUND, subject);
    np_key_t *my_property_key_rx = _np_keycache_find(context, search_in_dhkey);
    if (my_property_key_rx == NULL) return NULL;

    assert((np_memory_get_type(my_property_key_rx->entity_array[0]) ==
            np_memory_types_np_msgproperty_conf_t));
    ret = my_property_key_rx->entity_array[0];
    log_debug(LOG_MSGPROPERTY,
              NULL,
              "get %u: msgproperty %s: get %p from list: %p",
              mode_type,
              ret->msg_subject,
              my_property_key_rx->entity_array[0],
              my_property_key_rx);

    np_unref_obj(np_key_t, my_property_key_rx, "_np_keycache_find");
    return ret;
  }

  if (FLAG_CMP(mode_type, OUTBOUND)) {
    // search sending property
    np_dhkey_t search_out_dhkey =
        _np_msgproperty_tweaked_dhkey(OUTBOUND, subject);
    np_key_t *my_property_key_tx = _np_keycache_find(context, search_out_dhkey);

    if (my_property_key_tx == NULL) return NULL;
    assert((np_memory_get_type(my_property_key_tx->entity_array[0]) ==
            np_memory_types_np_msgproperty_conf_t));

    ret = my_property_key_tx->entity_array[0];
    log_debug(LOG_MSGPROPERTY,
              NULL,
              "get %u: msgproperty %s: get %p from list: %p",
              mode_type,
              ret->msg_subject,
              my_property_key_tx->entity_array[0],
              my_property_key_tx);

    np_unref_obj(np_key_t, my_property_key_tx, "_np_keycache_find");
    return ret;
  }

  return NULL;
}

np_msgproperty_run_t *_np_msgproperty_run_get(np_state_t      *context,
                                              np_msg_mode_type mode_type,
                                              np_dhkey_t       subject) {
  assert(!FLAG_CMP(mode_type, DEFAULT_MODE));
  assert(FLAG_CMP(mode_type, INBOUND) || FLAG_CMP(mode_type, OUTBOUND));

  np_msgproperty_run_t *ret = NULL;
  // search property
  np_dhkey_t search_in_dhkey =
      _np_msgproperty_tweaked_dhkey(mode_type, subject);

  np_key_t *my_property_key_rx = _np_keycache_find(context, search_in_dhkey);
  if (my_property_key_rx != NULL &&
      my_property_key_rx->entity_array[1] != NULL) {
    assert((np_memory_get_type(my_property_key_rx->entity_array[1]) ==
            np_memory_types_np_msgproperty_run_t));
    ret = my_property_key_rx->entity_array[1];
    log_debug(LOG_MSGPROPERTY,
              NULL,
              "get %d: msgproperty %s: get %p from list: %p",
              mode_type,
              ((np_msgproperty_conf_t *)my_property_key_rx->entity_array[0])
                  ->msg_subject,
              my_property_key_rx->entity_array[1],
              my_property_key_rx);
    np_unref_obj(np_key_t, my_property_key_rx, "_np_keycache_find");
  }
  return ret;
}

/**
 ** returns the msgproperty struct #func# for the given #mode_type# and
 *#subject#, and creates it if it is not yet present
 **/
np_msgproperty_conf_t *_np_msgproperty_get_or_create(np_state_t      *context,
                                                     np_msg_mode_type mode_type,
                                                     np_dhkey_t       subject) {
  np_msgproperty_conf_t *prop =
      _np_msgproperty_conf_get(context, mode_type, subject);
  bool created = false;

  if (NULL == prop) {
    log_info(LOG_MSGPROPERTY,
             NULL,
             "Indirect %" PRIu8 " creation of msgproperty %08" PRIx32
             ":%08" PRIx32,
             mode_type,
             subject.t[0],
             subject.t[1]);
    // create a default set of properties for listening to messages
    np_new_obj(np_msgproperty_conf_t, prop);
    if (NULL == prop->msg_subject) {
      prop->msg_subject = calloc(65, sizeof(char));
      np_id_str(prop->msg_subject, &subject);
      // prop->msg_subject = calloc(33, sizeof(char));
      // snprintf(prop->msg_subject, 24, "%08"PRIx32 ":%08"PRIx32, subject.t[0],
      // subject.t[1]);
    }
    prop->subject_dhkey = subject;
    prop->mode_type     = mode_type;
    prop->mep_type      = ANY_TO_ANY;
  }

  if (created) {
    np_unref_obj(np_msgproperty_conf_t, prop, ref_obj_creation);
  }
  return prop;
}

void np_msgproperty_register(np_msgproperty_conf_t *msg_property) {
  np_ctx_memory(msg_property);

  log_debug(LOG_MSGPROPERTY,
            NULL,
            "registering user property: %s ",
            msg_property->msg_subject);

  msg_property->subject_dhkey_in =
      _np_msgproperty_tweaked_dhkey(INBOUND, msg_property->subject_dhkey);
  msg_property->subject_dhkey_out =
      _np_msgproperty_tweaked_dhkey(OUTBOUND, msg_property->subject_dhkey);

  log_debug(LOG_MSGPROPERTY,
            NULL,
            "register handler: %s",
            msg_property->msg_subject);

  if (FLAG_CMP(msg_property->mode_type, INBOUND) ||
      FLAG_CMP(msg_property->mode_type, OUTBOUND)) {
    np_ref_obj(np_msgproperty_conf_t, msg_property, FUNC);
  }

  if (FLAG_CMP(msg_property->mode_type, INBOUND)) {
    // receiving property
    np_key_t *my_property_key_rx =
        _np_keycache_find_or_create(context, msg_property->subject_dhkey_in);
    np_util_event_t ev_rx = {.type         = (evt_property | evt_internal),
                             .user_data    = msg_property,
                             .target_dhkey = msg_property->subject_dhkey_in};
    _np_event_runtime_start_with_event(context,
                                       msg_property->subject_dhkey_in,
                                       ev_rx);
    log_debug(LOG_MSGPROPERTY,
              NULL,
              "register handler in : %s",
              _np_key_as_str(my_property_key_rx));
    np_unref_obj(np_key_t, my_property_key_rx, "_np_keycache_find_or_create");
  }

  if (FLAG_CMP(msg_property->mode_type, OUTBOUND)) {
    // sending property
    np_key_t *my_property_key_tx =
        _np_keycache_find_or_create(context, msg_property->subject_dhkey_out);
    np_util_event_t ev_tx = {.type         = (evt_property | evt_internal),
                             .user_data    = msg_property,
                             .target_dhkey = msg_property->subject_dhkey_out};
    _np_event_runtime_start_with_event(context,
                                       msg_property->subject_dhkey_out,
                                       ev_tx);
    log_debug(LOG_MSGPROPERTY,
              NULL,
              "register handler out: %s",
              _np_key_as_str(my_property_key_tx));
    np_unref_obj(np_key_t, my_property_key_tx, "_np_keycache_find_or_create");
  }
}

bool _np_msgproperty_check_msg_uniquety(np_msgproperty_conf_t   *self_conf,
                                        np_msgproperty_run_t    *self_run,
                                        struct np_e2e_message_s *msg_to_check) {
  bool ret = true;
  if (self_conf->unique_uuids_check) {

    if (np_tree_find_uuid(self_run->unique_uuids, msg_to_check->uuid) == NULL) {
      np_tree_insert_uuid(
          self_run->unique_uuids,
          msg_to_check->uuid,
          np_treeval_new_d(_np_message_get_expiry(msg_to_check)));
    } else {
      ret = false;
    }
  }
  return ret;
}

void _np_msgproperty_remove_msg_from_uniquety_list(
    np_msgproperty_run_t *self, struct np_e2e_message_s *msg_to_remove) {
  np_tree_del_uuid(self->unique_uuids, msg_to_remove->uuid);
}

void _np_msgproperty_job_msg_uniquety(np_msgproperty_conf_t *self_conf,
                                      np_msgproperty_run_t  *self_run) {
  np_ctx_memory(self_conf);
  // TODO: iter over msgproeprties and remove expired msg uuid from unique_uuids
  double now;
  if (self_conf->unique_uuids_check) {
    sll_init_full(void_ptr, to_remove);

    np_tree_elem_t *iter_tree = NULL;
    now                       = np_time_now();
    RB_FOREACH (iter_tree, np_tree_s, self_run->unique_uuids) {
      if (iter_tree->val.value.d < now) {
        sll_append(void_ptr, to_remove, iter_tree->key.value.uuid);
      }
    }

    sll_iterator(void_ptr) iter_to_rm = sll_first(to_remove);
    if (iter_to_rm != NULL) {
      log_debug(LOG_MSGPROPERTY,
                NULL,
                "UNIQUITY removing %" PRIu32 " from %" PRIsizet
                " items from unique_uuids for %s",
                sll_size(to_remove),
                self_run->unique_uuids->size,
                self_conf->msg_subject);
      while (iter_to_rm != NULL) {
        np_tree_del_uuid(self_run->unique_uuids, iter_to_rm->val);
        sll_next(iter_to_rm);
      }
    }
    // sll_clear(char_ptr, to_remove);

    // iter_tree = NULL;
    // RB_FOREACH(iter_tree, np_tree_s, self->unique_uuids_out)
    // {
    //     if (iter_tree->val.value.d < now) {
    //         sll_append(void_ptr, to_remove, iter_tree->key.value.bin);
    //     }
    // }

    // iter_to_rm = sll_first(to_remove);
    // if(iter_to_rm != NULL) {
    //     log_debug_msg(LOG_DEBUG | LOG_MSGPROPERTY , NULL,"UNIQUITY removing
    //     %"PRIu32" from %"PRIu16" items from unique_uuids for %s",
    //                                                 sll_size(to_remove),
    //                                                 self->unique_uuids_out->size,
    //                                                 self->msg_subject);
    //     while (iter_to_rm != NULL)
    //     {
    //         np_tree_del_uuid(self->unique_uuids_out, iter_to_rm->val);
    //         sll_next(iter_to_rm);
    //     }
    // }
    sll_free(void_ptr, to_remove);
  }
}

void __np_msgproperty_event_cleanup_response_handler(void           *context,
                                                     np_util_event_t ev) {
  np_unref_obj(np_responsecontainer_t,
               ev.user_data,
               "_np_msgproperty_cleanup_response_handler");
}

void _np_msgproperty_cleanup_response_handler(np_msgproperty_run_t *self,
                                              const np_util_event_t event) {
  np_ctx_memory(self);

  // remove expired msg uuid from response uuids
  double now = np_time_now();
  sll_init_full(void_ptr, to_remove);

  np_tree_elem_t         *iter_tree  = NULL;
  np_responsecontainer_t *current    = NULL;
  uint8_t                 max_events = NP_PI_INT * 10;

  RB_FOREACH (iter_tree, np_tree_s, self->response_handler) {
    bool handle_event = false;

    current = (np_responsecontainer_t *)iter_tree->val.value.v;
    // TODO: find correct dhkey from responsecontainer and use it as
    // target_dhkey
    np_util_event_t response_event = {.user_data = current};

    if (current->expires_at < now) { // notify about timeout
      response_event.type = (evt_timeout | evt_response);
      handle_event        = true;
    } else if (current->received_at != 0) { // notify about ack response
      response_event.type = (evt_internal | evt_response);
      handle_event        = true;
    }

    if (handle_event) {

      if (!_np_dhkey_equal(&current->msg_dhkey,
                           &dhkey_zero)) { // clean up message redlivery

        np_ref_obj(np_responsecontainer_t, response_event.user_data, FUNC);
        // response_event.cleanup =
        //     __np_msgproperty_event_cleanup_response_handler;

        response_event.target_dhkey = current->msg_dhkey;
        _np_event_runtime_add_event(context,
                                    event.current_run,
                                    current->msg_dhkey,
                                    response_event);
        /* POSSIBLE ASYNC POINT
        char buf[100];
        snprintf(buf, 100, "urn:np:responsecontainer:message:%s",
        current->uuid); if(!np_jobqueue_submit_event(context, 0,
        current->dest_dhkey, response_event, buf)){ log_error("Jobqueue rejected
        new job for responsecontainer message id %s", current->uuid
            );
        }
        */
        np_unref_obj(np_responsecontainer_t, response_event.user_data, FUNC);
      }

      if (!_np_dhkey_equal(&current->dest_dhkey, &dhkey_zero) &&
          _np_keycache_exists(context,
                              current->dest_dhkey,
                              NULL)) { // clean up ping ack

        np_ref_obj(np_responsecontainer_t, response_event.user_data, FUNC);

        response_event.target_dhkey = current->dest_dhkey;
        _np_event_runtime_add_event(context,
                                    event.current_run,
                                    current->dest_dhkey,
                                    response_event);
        /* POSSIBLE ASYNC POINT
        char buf[100];
        snprintf(buf, 100, "urn:np:responsecontainer:ping_ack:%s",
        current->uuid); if(!np_jobqueue_submit_event(context, 0,
        current->dest_dhkey, response_event, buf)){ log_error("Jobqueue rejected
        new job for responsecontainer ping_ack id %s", current->uuid
            );
        }
        */
        np_unref_obj(np_responsecontainer_t, response_event.user_data, FUNC);
      }

      np_unref_obj(np_responsecontainer_t,
                   current,
                   "_np_message_add_response_handler");
      sll_append(void_ptr, to_remove, &iter_tree->key.value.uuid);
    }

    /// prevent overload of eventqueue
    if (max_events == 0) break;
    max_events--;
  }

  sll_iterator(void_ptr) iter_to_rm = sll_first(to_remove);
  if (iter_to_rm != NULL) {
    log_debug(LOG_MSGPROPERTY,
              NULL,
              "RESPONSE removing %" PRIu32 " of %" PRIsizet
              " items from response_handler",
              sll_size(to_remove),
              self->response_handler->size);
    while (iter_to_rm != NULL) {
      np_tree_del_uuid(self->response_handler, iter_to_rm->val);
      sll_next(iter_to_rm);
    }
  }
  sll_free(void_ptr, to_remove);
}

void _np_msgproperty_check_msgcache(np_util_statemachine_t *statemachine,
                                    const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(my_property_key->entity_array[0],
          np_msgproperty_conf_t,
          property_conf);
  NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);
  // NP_CAST(event.user_data, np_message_t, message);
  bool is_send = _np_dhkey_equal(&my_property_key->dhkey,
                                 &property_conf->subject_dhkey_out);
  bool is_recv = _np_dhkey_equal(&my_property_key->dhkey,
                                 &property_conf->subject_dhkey_in);

  // check if we are (one of the) sending node(s) of this kind of message
  // should not return NULL
  log_debug(LOG_ROUTING,
            NULL,
            "this node is one %s of messages, checking msgcache (%p / %u) ...",
            is_send ? "sender" : "receiver",
            property_run->msg_cache,
            dll_size(property_run->msg_cache));

  // get message from cache (maybe only for one way mep ?!)
  uint32_t msg_visit_counter        = dll_size(property_run->msg_cache);
  dll_iterator(np_message_ptr) peek = NULL;

  while (0 < msg_visit_counter &&
         msg_visit_counter <= property_conf->cache_size) {
    struct np_e2e_message_s *msg_out = NULL;
    // if messages are available in cache, send them !
    if (FLAG_CMP(property_conf->cache_policy, FIFO)) {
      peek = (peek == NULL) ? dll_first(property_run->msg_cache) : peek;
      if (peek != NULL && peek->val != NULL &&
          _np_intent_has_crypto_session(
              my_property_key,
              *_np_message_get_sessionid(peek->val))) {
        msg_out = peek->val;
        dll_next(peek);
      }

    } else if (FLAG_CMP(property_conf->cache_policy, LIFO)) {
      peek = (peek == NULL) ? dll_last(property_run->msg_cache) : peek;
      if (peek != NULL && peek->val != NULL &&
          _np_intent_has_crypto_session(
              my_property_key,
              *_np_message_get_sessionid(peek->val))) {
        msg_out = peek->val;
        dll_previous(peek);
      }
    }

    // check for more messages in cache after head/tail command
    // msg_available = dll_size(send_prop->msg_cache_out);
    msg_visit_counter--;

    if (NULL != msg_out) {
      log_debug(LOG_ROUTING,
                msg_out->uuid,
                "message in %s cache found and initialize resend",
                is_send ? "sender" : "receiver");

      np_util_event_t msg_event = {.user_data = msg_out};

      _np_dhkey_assign(&msg_event.target_dhkey,
                       _np_message_get_sessionid(msg_out));

      if (is_send) {
        msg_event.type = (evt_internal | evt_userspace | evt_message);
        _np_event_runtime_add_event(context,
                                    event.current_run,
                                    property_conf->subject_dhkey_out,
                                    msg_event);
      }
      if (is_recv) {
        msg_event.type = (evt_external | evt_message);
        _np_event_runtime_add_event(context,
                                    event.current_run,
                                    property_conf->subject_dhkey_in,
                                    msg_event);
      }

      np_unref_obj(np_message_t, msg_out, ref_msgproperty_msgcache);
      dll_remove(np_message_ptr, property_run->msg_cache, msg_out);
    }
    if (peek == NULL) {
      break;
    }
  }
}

void _np_msgproperty_check_msgcache_for(np_util_statemachine_t *statemachine,
                                        const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(my_property_key->entity_array[0],
          np_msgproperty_conf_t,
          property_conf);
  NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);
  // NP_CAST(event.user_data, np_message_t, message);

  char buf[65];
  log_debug(LOG_ROUTING,
            NULL,
            "this node is the receiver of messages, checking msgcache "
            "(%p / %u) %s ...",
            property_run->msg_cache,
            dll_size(property_run->msg_cache),
            np_id_str(buf, &event.target_dhkey));
  // get message from cache (maybe only for one way mep ?!)

  if (!_np_intent_has_crypto_session(my_property_key, event.target_dhkey))
    return;

  uint32_t msg_visit_counter = dll_size(property_run->msg_cache);

  dll_iterator(np_message_ptr) peek = NULL;
  while (0 < msg_visit_counter &&
         msg_visit_counter <= property_conf->cache_size) {
    // grab a message
    struct np_e2e_message_s *msg = NULL;
    // if messages are available in cache, try to decode them !
    if (FLAG_CMP(property_conf->cache_policy, FIFO)) {
      peek = (peek == NULL) ? dll_first(property_run->msg_cache) : peek;
      if (peek != NULL && peek->val != NULL &&
          _np_dhkey_equal(_np_message_get_sessionid(peek->val),
                          &event.target_dhkey)) {
        msg = peek->val;
        dll_next(peek);
      }
    } else if (FLAG_CMP(property_conf->cache_policy, LIFO)) {
      peek = (peek == NULL) ? dll_last(property_run->msg_cache) : peek;
      if (peek != NULL && peek->val != NULL &&
          _np_dhkey_equal(_np_message_get_sessionid(peek->val),
                          &event.target_dhkey)) {
        msg = peek->val;
        dll_previous(peek);
      }
    }
    msg_visit_counter--;

    // handle selected message
    if (NULL != msg) {
      log_debug(
          LOG_MESSAGE | LOG_ROUTING,
          msg->uuid,
          "message in receiver cache found and initialize redelivery for");
      // recalc number of available messages
      np_dhkey_t in_handler =
          property_conf->subject_dhkey_in; // (INBOUND,
                                           // property_conf->msg_subject);

      np_util_event_t msg_in_event = {.type      = (evt_external | evt_message),
                                      .user_data = msg};
      _np_dhkey_assign(&msg_in_event.target_dhkey,
                       _np_message_get_sessionid(msg));

      _np_event_runtime_add_event(context,
                                  event.current_run,
                                  in_handler,
                                  msg_in_event);

      np_unref_obj(np_message_t, msg, ref_msgproperty_msgcache);
      dll_remove(np_message_ptr, property_run->msg_cache, msg);
    }

    if (peek == NULL) {
      break;
    }

    // do not continue processing message if max treshold is reached
    if (property_run->msg_threshold > property_conf->max_threshold) break;
  }
}

void _np_msgproperty_cleanup_cache(np_util_statemachine_t         *statemachine,
                                   NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(my_property_key->entity_array[0],
          np_msgproperty_conf_t,
          property_conf);
  NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);

  log_debug(LOG_MSGPROPERTY,
            NULL,
            "checking for outdated messages in msgcache (%s: %p / %u) ...",
            property_conf->msg_subject,
            property_run->msg_cache,
            dll_size(property_run->msg_cache));

  dll_iterator(np_message_ptr) iter_prop_msg_cache =
      dll_first(property_run->msg_cache);
  while (iter_prop_msg_cache != NULL) {
    dll_iterator(np_message_ptr) old_iter = iter_prop_msg_cache;
    dll_next(iter_prop_msg_cache); // we need to iterate before we delete the
                                   // old iter

    struct np_e2e_message_s *old_msg = old_iter->val;
    ASSERT(old_msg != NULL, "cannot have an empty element");
    if (_np_message_is_expired(old_msg)) {
      log_debug(LOG_MESSAGE,
                old_msg->uuid,
                "purging expired message (subj: %s) from receiver cache ...",
                property_conf->msg_subject);
      dll_delete(np_message_ptr, property_run->msg_cache, old_iter);
      np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
    }
  }
  log_debug(LOG_MSGPROPERTY,
            NULL,
            "cleanup receiver cache for subject %s done",
            property_conf->msg_subject);
}

void __np_property_add_msg_to_cache(np_util_statemachine_t *statemachine,
                                    const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(my_property_key->entity_array[0],
          np_msgproperty_conf_t,
          property_conf);
  NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);
  NP_CAST(event.user_data, struct np_e2e_message_s, message);
  // cache already full ?
  if (property_conf->cache_size <= dll_size(property_run->msg_cache)) {
    log_debug(LOG_MSGPROPERTY,
              NULL,
              "msg cache full, checking overflow policy ...");

    if (FLAG_CMP(property_conf->cache_policy, OVERFLOW_PURGE)) {
      log_debug(LOG_MSGPROPERTY,
                NULL,
                "OVERFLOW_PURGE: discarding message in msgcache for %s",
                property_conf->msg_subject);
      struct np_e2e_message_s *old_msg = NULL;

      if (FLAG_CMP(property_conf->cache_policy, FIFO)) {
        old_msg = dll_head(np_message_ptr, property_run->msg_cache);
      } else if (FLAG_CMP(property_conf->cache_policy, LIFO)) {
        old_msg = dll_tail(np_message_ptr, property_run->msg_cache);
      }

      if (old_msg != NULL) {
        log_warn(
            LOG_MSGPROPERTY,
            old_msg->uuid,
            "(policy: PURGE) discarding old message because cache is full");
        // TODO: add callback hook to allow user space handling of
        // discarded message
        np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
      }
    }

    if (FLAG_CMP(property_conf->cache_policy, OVERFLOW_REJECT)) {
      log_warn(LOG_WARNING,
               message->uuid,
               "(policy: REJECT) rejecting new message because cache is full");
      return;
    }
  }

  dll_append(np_message_ptr, property_run->msg_cache, message);
  np_ref_obj(np_message_t, message, ref_msgproperty_msgcache);

  log_debug(LOG_MSGPROPERTY | LOG_ROUTING,
            message->uuid,
            "added message to msgcache (%p / %d / %x) ...",
            property_run->msg_cache,
            property_conf->cache_size,
            property_conf->cache_policy);
}

void __np_msgproperty_redeliver_messages(np_util_statemachine_t *statemachine,
                                         const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(my_property_key->entity_array[0],
          np_msgproperty_conf_t,
          property_conf);
  NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);

  // remove expired msg uuid from response uuids
  double now             = np_time_now();
  double resend_interval = property_conf->msg_ttl / (property_conf->retry + 1);

  np_tree_elem_t       *iter_tree = NULL;
  np_redelivery_data_t *current   = NULL;

  RB_FOREACH (iter_tree, np_tree_s, property_run->redelivery_messages) {
    current = (np_redelivery_data_t *)iter_tree->val.value.v;

    if (current->redelivery_at < now) { // send message redelivery attempt

      struct np_e2e_message_s *redeliver_copy = NULL;
      np_new_obj(np_message_t, redeliver_copy);
      np_message_clone(redeliver_copy, current->message);

      memcpy(redeliver_copy->tstamp, &current->redelivery_at, sizeof(double));

      np_util_event_t message_event = {.type = (evt_message | evt_internal),
                                       .user_data    = redeliver_copy,
                                       .target_dhkey = current->target};
      _np_event_runtime_add_event(context,
                                  event.current_run,
                                  property_conf->subject_dhkey_out,
                                  message_event);

      current->redelivery_at = current->redelivery_at + resend_interval;
      /*
      char buf[100];
      snprintf(buf,100,"urn:np:message:redelivery:%s",redeliver_copy->uuid);
      if(!np_jobqueue_submit_event(context, 0, property_conf->subject_dhkey_out,
      message_event, buf)){ log_error("Jobqueue rejected new job for message
      redelivery of msg %s. No resend will be initiated.", redeliver_copy->uuid
          );
      }else{
          log_info(LOG_ROUTING, "re-delivery of message %s / %s inititated",
      iter_tree->key.value.s, property_conf->msg_subject);
      }
      */
      log_info(LOG_ROUTING,
               iter_tree->key.value.uuid,
               "re-delivery of message %s inititated",
               property_conf->msg_subject);

      np_unref_obj(np_message_t, redeliver_copy, ref_obj_creation);
    }
  }
}

struct __np_token_ledger {
  np_pll_t(np_aaatoken_ptr, recv_tokens); // link to runtime interest data on
                                          // which this node is interested in
  np_pll_t(np_aaatoken_ptr, send_tokens); // link to runtime interest data on
                                          // which this node is interested in
};

static int8_t _np_aaatoken_cmp(np_aaatoken_ptr first, np_aaatoken_ptr second) {
  int8_t ret_check = 0;

  if (first == second) return (0);

  if (first == NULL || second == NULL) return (-1);

  ret_check = strncmp(first->issuer, second->issuer, 65);
  if (0 != ret_check) {
    return (ret_check);
  }

  ret_check =
      strncmp(first->subject, second->subject, (strnlen(first->subject, 255)));
  if (0 != ret_check) {
    return (ret_check);
  }

  ret_check = strncmp(first->realm, second->realm, strlen(first->realm));
  if (0 != ret_check) {
    return (ret_check);
  }

  return (0);
}

/*
static int8_t _np_aaatoken_cmp_exact (np_aaatoken_ptr first, np_aaatoken_ptr
second)
{
    int8_t ret_check = 0;

    if (first == second) return (0);

    if (first == NULL || second == NULL ) return (-1);

    ret_check = sodium_memcmp(first->crypto.derived_kx_public_key,
second->crypto.derived_kx_public_key, crypto_sign_PUBLICKEYBYTES); if (0 !=
ret_check )
    {
        return (ret_check);
    }

    ret_check = memcmp(first->uuid, second->uuid, NP_UUID_BYTES);
    if (0 != ret_check )
    {
        return (ret_check);
    }

    return _np_aaatoken_cmp(first,second);
}
*/

void __load_internal_callback(char            *msg_subject,
                              np_msg_mode_type mode,
                              sll_return(np_evt_callback_t) callback_list) {
  size_t msg_subject_len = strnlen(msg_subject, 256);
  if (0 == strncmp(msg_subject, _DEFAULT, msg_subject_len)) {
    if (mode == OUTBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_out_default);
    // if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list,
    // _np_in_ack );
  }
  if (0 == strncmp(msg_subject, _FORWARD, msg_subject_len)) {
    if (mode == OUTBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_out_forward);
    // if (mode == INBOUND)  sll_append(np_evt_callback_t, callback_list,
    // _np_in_ack );
  }
  if (0 == strncmp(msg_subject, _NP_MSG_HANDSHAKE, msg_subject_len)) {
    if (mode == OUTBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_out_handshake);
    if (mode == INBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_in_handshake);
  }
  if (0 == strncmp(msg_subject, _NP_MSG_ACK, msg_subject_len)) {
    if (mode == OUTBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_out_ack);
    if (mode == INBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_in_ack);
  }
  if (0 == strncmp(msg_subject, _NP_MSG_JOIN_REQUEST, msg_subject_len)) {
    if (mode == OUTBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_out_join);
    if (mode == INBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_in_join);
  }
  if (0 == strncmp(msg_subject, _NP_MSG_LEAVE_REQUEST, msg_subject_len)) {
    if (mode == OUTBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_out_leave);
    if (mode == INBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_in_leave);
  }
  if (0 == strncmp(msg_subject, _NP_MSG_PING_REQUEST, msg_subject_len)) {
    if (mode == OUTBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_out_ping);
    if (mode == INBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_in_ping);
  }
  if (0 == strncmp(msg_subject, _NP_MSG_PIGGY_REQUEST, msg_subject_len)) {
    if (mode == OUTBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_out_piggy);
    if (mode == INBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_in_piggy);
  }
  if (0 == strncmp(msg_subject, _NP_MSG_UPDATE_REQUEST, msg_subject_len)) {
    if (mode == OUTBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_out_update);
    if (mode == INBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_in_update);
  }
  if (0 == strncmp(msg_subject, _NP_MSG_AVAILABLE_RECEIVER, msg_subject_len)) {
    if (mode == OUTBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_out_available_messages);
    if (mode == INBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_in_available_receiver);
  }
  if (0 == strncmp(msg_subject, _NP_MSG_AVAILABLE_SENDER, msg_subject_len)) {
    if (mode == OUTBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_out_available_messages);
    if (mode == INBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_in_available_sender);
  }
  if (0 == strncmp(msg_subject, _NP_MSG_PHEROMONE_UPDATE, msg_subject_len)) {
    if (mode == OUTBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_out_pheromone);
    if (mode == INBOUND)
      sll_append(np_evt_callback_t, callback_list, _np_in_pheromone);
  }
}

void _np_msgproperty_create_token_ledger(np_util_statemachine_t *statemachine,
                                         const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  // NP_CAST(event.user_data,          np_msgproperty_conf_t, property);
  NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property);

  if (property->is_internal == true) return;

  if (my_property_key->entity_array[2] == NULL) {
    // could be empty on first use, therefore create and append it to the
    // entities
    log_debug(LOG_MSGPROPERTY,
              NULL,
              "creating ledger lists for %s / %s",
              property->msg_subject,
              _np_key_as_str(my_property_key));
    struct __np_token_ledger *token_ledger =
        malloc(sizeof(struct __np_token_ledger));
    pll_init(np_aaatoken_ptr, token_ledger->recv_tokens);
    pll_init(np_aaatoken_ptr, token_ledger->send_tokens);

    my_property_key->entity_array[2] = token_ledger;
  } else {
    struct __np_token_ledger *token_ledger = my_property_key->entity_array[2];

    pll_clear(np_aaatoken_ptr, token_ledger->recv_tokens);
    pll_clear(np_aaatoken_ptr, token_ledger->send_tokens);
  }
}

void _np_msgproperty_create_runtime_info(np_util_statemachine_t *statemachine,
                                         const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(my_property_key->entity_array[0], np_msgproperty_conf_t, property);

  np_msgproperty_run_t *property_run = NULL;
  np_new_obj(np_msgproperty_run_t, property_run);

  my_property_key->entity_array[1] = property_run;

  if (_np_dhkey_equal(&my_property_key->dhkey, &property->subject_dhkey_out)) {
    if (false == property->is_internal &&
        property->audience_type != NP_MX_AUD_VIRTUAL) {
      if (false ==
          sll_contains(np_evt_callback_t,
                       property_run->callbacks,
                       _np_out_callback_wrapper,
                       np_evt_callback_t_sll_compare_type)) { // first encrypt
                                                              // the payload
                                                              // for receiver
        sll_append(np_evt_callback_t,
                   property_run->callbacks,
                   _np_out_callback_wrapper);
      }
      if (false ==
          sll_contains(np_evt_callback_t,
                       property_run->callbacks,
                       _np_out_default,
                       np_evt_callback_t_sll_compare_type)) { // then route and
                                                              // send message
        sll_append(np_evt_callback_t, property_run->callbacks, _np_out_default);
      }
    } else {
      __load_internal_callback(property->msg_subject,
                               OUTBOUND,
                               property_run->callbacks);
    }
  }

  if (_np_dhkey_equal(&my_property_key->dhkey, &property->subject_dhkey_in)) {
    if (FLAG_CMP(property->ack_mode, ACK_DESTINATION) &&
        false ==
            sll_contains(
                np_evt_callback_t,
                property_run->callbacks,
                _check_and_send_destination_ack,
                np_evt_callback_t_sll_compare_type)) { // potentially send an
                                                       // ack for a message
      sll_append(np_evt_callback_t,
                 property_run->callbacks,
                 _check_and_send_destination_ack);
    }

    if (false == property->is_internal &&
        property->audience_type != NP_MX_AUD_VIRTUAL) {
      if (false ==
          sll_contains(
              np_evt_callback_t,
              property_run->callbacks,
              _np_in_callback_wrapper,
              np_evt_callback_t_sll_compare_type)) { // decrypt or cache
                                                     // the message
        sll_append(np_evt_callback_t,
                   property_run->callbacks,
                   _np_in_callback_wrapper);
      }
      // if (FLAG_CMP(property->ack_mode, NP_MX_ACK_CLIENT) &&
      //     false == sll_contains(np_evt_callback_t, property_run->callbacks,
      //     _check_and_send_client_ack, np_evt_callback_t_sll_compare_type))
      // {   // potentially send an ack for a message
      //     sll_append(np_evt_callback_t, property_run->callbacks,
      //     _check_and_send_client_ack);
      // }
    } else {
      __load_internal_callback(property->msg_subject,
                               INBOUND,
                               property_run->callbacks);
    }
  }
}

np_aaatoken_t *_np_msgproperty_get_mxtoken(np_context *context,
                                           np_key_t   *my_property_key) {

  np_msgproperty_conf_t    *property = my_property_key->entity_array[0];
  struct __np_token_ledger *ledger   = my_property_key->entity_array[2];

  np_dhkey_t send_dhkey =
      property->subject_dhkey_out; // _np_msgproperty_dhkey(OUTBOUND,
                                   // property->msg_subject);
  np_dhkey_t recv_dhkey =
      property->subject_dhkey_in; // _np_msgproperty_dhkey(INBOUND,
                                  // property->msg_subject);

  np_pll_t(np_aaatoken_ptr, token_list = NULL);
  if (_np_dhkey_equal(&my_property_key->dhkey, &send_dhkey)) {
    log_trace(LOG_TRACE,
              NULL,
              "start: void _np_msgproperty_get_mxtoken SENDER(...){ %s",
              _np_key_as_str(my_property_key));
    token_list = ledger->send_tokens;
  }

  if (_np_dhkey_equal(&my_property_key->dhkey, &recv_dhkey)) {
    log_trace(LOG_TRACE,
              NULL,
              "start: void _np_msgproperty_get_mxtoken RECEIVER(...){%s",
              _np_key_as_str(my_property_key));
    token_list = ledger->recv_tokens;
  }

  if (token_list == NULL) {
    log_trace(LOG_TRACE,
              NULL,
              "start: void _np_msgproperty_get_mxtoken NONE (...){");
    return NULL;
  }

  if (pll_size(token_list) == 0) {
    return NULL;
  } else {
    np_ref_obj(np_aaatoken_t, pll_first(token_list)->val, FUNC);
    return pll_first(token_list)->val;
  }
}

void _np_msgproperty_upsert_token(np_util_statemachine_t         *statemachine,
                                  NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);

  np_msgproperty_conf_t    *property     = my_property_key->entity_array[0];
  np_msgproperty_run_t     *property_run = my_property_key->entity_array[1];
  struct __np_token_ledger *ledger       = my_property_key->entity_array[2];

  bool for_receiver = false;

  np_dhkey_t send_dhkey =
      property->subject_dhkey_out; // _np_msgproperty_dhkey(OUTBOUND,
                                   // property->msg_subject);
  np_dhkey_t recv_dhkey =
      property->subject_dhkey_in; // _np_msgproperty_dhkey(INBOUND,
                                  // property->msg_subject);

  np_pll_t(np_aaatoken_ptr, token_list = NULL);
  if (_np_dhkey_equal(&my_property_key->dhkey, &send_dhkey)) {
    log_trace_msg(LOG_TRACE,
                  NULL,
                  "start: void _np_msgproperty_upsert_token SENDER(...){%s",
                  _np_key_as_str(my_property_key));
    token_list = ledger->send_tokens;
  } else if (_np_dhkey_equal(&my_property_key->dhkey, &recv_dhkey)) {
    log_trace_msg(LOG_TRACE,
                  NULL,
                  "start: void _np_msgproperty_upsert_token RECEIVER(...){%s",
                  _np_key_as_str(my_property_key));
    for_receiver = true;
    token_list   = ledger->recv_tokens;
  } else {
    log_trace(LOG_TRACE,
              NULL,
              "start: void _np_msgproperty_upsert_token NONE (...){");
    return;
  }

  double now = np_time_now();

  pll_iterator(np_aaatoken_ptr) iter = pll_first(token_list);
  // create new mx token
  do {
    if (NULL == iter) {
      np_aaatoken_t *msg_token_new =
          _np_token_factory_new_message_intent_token(property);
      log_debug(LOG_MSGPROPERTY,
                msg_token_new->uuid,
                "--- new mxtoken for subject: %25s --------",
                property->msg_subject);
      pll_insert(np_aaatoken_ptr,
                 token_list,
                 msg_token_new,
                 false,
                 _np_aaatoken_cmp);
      // create own crypto session with random values
      _np_intent_update_session(my_property_key,
                                msg_token_new,
                                for_receiver,
                                crud_create);
      ref_replace_reason(np_aaatoken_t,
                         msg_token_new,
                         "_np_token_factory_new_message_intent_token",
                         ref_aaatoken_local_mx_tokens);
    } else if ((iter->val->expires_at - now) <
               fmax(property->token_min_ttl + 1.0,
                    MSGPROPERTY_DEFAULT_MIN_TTL_SEC)) { // Create a new msg
                                                        // token
      np_aaatoken_t *msg_token_new =
          _np_token_factory_new_message_intent_token(property);
      log_debug(LOG_MSGPROPERTY,
                msg_token_new->uuid,
                "--- refresh mxtoken for subject: %25s --------",
                property->msg_subject);
      np_aaatoken_t *tmp_token = pll_replace(np_aaatoken_ptr,
                                             token_list,
                                             msg_token_new,
                                             _np_aaatoken_cmp);
      // update own crypto session with random values
      _np_intent_update_session(my_property_key,
                                msg_token_new,
                                for_receiver,
                                crud_create);
      ref_replace_reason(np_aaatoken_t,
                         msg_token_new,
                         "_np_token_factory_new_message_intent_token",
                         ref_aaatoken_local_mx_tokens);
      np_unref_obj(np_aaatoken_ptr, tmp_token, ref_aaatoken_local_mx_tokens);
      // triggers resending of token to peers
      property_run->last_intent_update = 0.0;
    } else {
      log_debug(LOG_MSGPROPERTY | LOG_AAATOKEN,
                iter->val->uuid,
                "--- update mxtoken for subject: %25s token: --------",
                property->msg_subject);
      // update with attribute set on the property
      enum np_data_return r = np_could_not_read_object;
      r = np_merge_data(iter->val->attributes, property_run->attributes);
      ASSERT(r == np_ok,
             "Could not merge property attributes into token. Error: "
             "%" PRIu32,
             r);

      // update msg_threshold to latest value
      np_data_value msg_threshold;
      msg_threshold.unsigned_integer = property_run->msg_threshold;

      r = np_could_not_read_object;
      // currently disabled, needs more elaboration
      // r = np_set_data(iter->val->attributes,
      //                 (struct np_data_conf){.key  = "msg_threshold",
      //                                       .type =
      //                                       NP_DATA_TYPE_UNSIGNED_INT},
      //                 msg_threshold);
      // ASSERT(r == np_ok,
      //        "Could not write \"msg_threshold\" into attributes. Error: "
      //        "%" PRIu32,
      //        r);
      // update own crypto session with changed attribute values
      _np_intent_update_session(my_property_key,
                                iter->val,
                                for_receiver,
                                crud_update);
    }

    if (iter != NULL) pll_next(iter);

  } while (NULL != iter);
}

void np_msgproperty4user(struct np_mx_properties *dest,
                         np_msgproperty_conf_t   *src) {
  dest->message_ttl = src->msg_ttl;

  dest->intent_ttl          = src->token_max_ttl;
  dest->intent_update_after = src->token_min_ttl;

  dest->cache_size   = src->cache_size;
  dest->max_parallel = src->max_threshold;
  dest->max_retry    = src->retry;

  if (FLAG_CMP(src->mode_type, INBOUND)) dest->role = NP_MX_CONSUMER;
  if (FLAG_CMP(src->mode_type, OUTBOUND)) dest->role = NP_MX_PROVIDER;
  if (FLAG_CMP(src->mode_type, DEFAULT_MODE)) dest->role = NP_MX_PROSUMER;

  if (src->rep_subject != NULL) {
    memcpy(dest->reply_id, &src->reply_dhkey, NP_FINGERPRINT_BYTES);
  } else {
    memset(dest->reply_id, 0, NP_FINGERPRINT_BYTES);
  }

  // ackmode conversion
  switch (src->ack_mode) {
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
    } else {
      dest->cache_policy = NP_MX_FIFO_PURGE;
    }
  } else {
    if (FLAG_CMP(src->cache_policy, OVERFLOW_REJECT)) {
      dest->cache_policy = NP_MX_LIFO_REJECT;
    } else {
      dest->cache_policy = NP_MX_LIFO_PURGE;
    }
  }
}

void np_msgproperty_from_user(np_state_t              *context,
                              np_msgproperty_conf_t   *dest,
                              struct np_mx_properties *src) {
  assert(context != NULL);
  assert(src != NULL);
  assert(dest != NULL);

  dest->mode_type = DEFAULT_MODE;
  if (src->role == NP_MX_CONSUMER) dest->mode_type = INBOUND;
  if (src->role == NP_MX_PROVIDER) dest->mode_type = OUTBOUND;
  if (src->role == NP_MX_PROSUMER) dest->mode_type = DEFAULT_MODE;

  if (src->intent_ttl > 0.0) {
    dest->token_max_ttl = src->intent_ttl;
  }

  if (src->intent_update_after > 0.0) {
    dest->token_min_ttl = src->intent_update_after;
    // reset to trigger discovery messages
    // dest->last_intent_update = (dest->last_intent_update -
    // dest->token_min_ttl); dest->last_intent_update =
    // (dest->last_intent_update - dest->token_min_ttl);
  } else {
    dest->token_min_ttl = MSGPROPERTY_DEFAULT_MIN_TTL_SEC;
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

  if (src->reply_id[0] != '\0' &&
      (dest->rep_subject == NULL ||
       strncmp(dest->rep_subject, src->reply_id, 255) != 0)) {
    char *old         = dest->rep_subject;
    dest->rep_subject = strndup(src->reply_id, 255);
    if (old) free(old);

  } else {
    dest->rep_subject = NULL;
  }

  dest->audience_type = src->audience_type;
  memcpy(&dest->audience_id, src->audience_id, NP_FINGERPRINT_BYTES);

  // ackmode conversion
  switch (src->ackmode) {
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

  switch (src->cache_policy) {
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
  dest->mep_type = ANY_TO_ANY;
}

// NP_UTIL_STATEMACHINE_TRANSITION(states, UNUSED, IN_USE_MSGPROPERTY,
// __np_set_property, __is_msgproperty);
bool __is_msgproperty(np_util_statemachine_t *statemachine,
                      const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);
  bool ret = false;

  if (!ret)
    ret = FLAG_CMP(event.type, evt_property) &&
          FLAG_CMP(event.type, evt_internal);
  if (ret)
    ret &= (np_memory_get_type(event.user_data) ==
            np_memory_types_np_msgproperty_conf_t);
  return ret;
}

bool __is_msgproperty_lifecycle_enable(np_util_statemachine_t *statemachine,
                                       const np_util_event_t   event) {
  bool ret = false;

  if (!ret) ret = FLAG_CMP(event.type, evt_enable);
  if (ret)
    ret = FLAG_CMP(event.type, evt_property) &&
          FLAG_CMP(event.type, evt_internal);
  if (ret)
    ret &= (np_memory_get_type(event.user_data) ==
            np_memory_types_np_msgproperty_run_t);

  return ret;
}

bool __is_msgproperty_lifecycle_disable(np_util_statemachine_t *statemachine,
                                        const np_util_event_t   event) {
  bool ret = false;

  if (!ret) ret = FLAG_CMP(event.type, evt_disable);
  if (ret)
    ret = FLAG_CMP(event.type, evt_property) &&
          FLAG_CMP(event.type, evt_internal);
  if (ret)
    ret &= (np_memory_get_type(event.user_data) ==
            np_memory_types_np_msgproperty_run_t);

  return ret;
}

void __np_property_lifecycle_set(np_util_statemachine_t *statemachine,
                                 const np_util_event_t   event) {
  // noop, state handled by state machine
}

void __np_set_property(np_util_statemachine_t *statemachine,
                       const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(event.user_data, np_msgproperty_conf_t, property);

  np_ref_obj(no_key_t, my_property_key, "__np_set_property");
  my_property_key->type |= np_key_type_subject;

  my_property_key->entity_array[0] = property;
  log_debug(LOG_MSGPROPERTY,
            NULL,
            "sto  :msgproperty %s: %p added to list: %p / %p",
            property->msg_subject,
            property,
            my_property_key,
            my_property_key->entity_array[0]);

  // create runtime parts of msgproperty
  _np_msgproperty_create_runtime_info(statemachine, event);
  // create token ledger for user supplied message exchanges
  _np_msgproperty_create_token_ledger(statemachine, event);

  if (my_property_key->bloom_scent == NULL) {
    my_property_key->bloom_scent = _np_neuropil_bloom_create();
    _np_neuropil_bloom_add(my_property_key->bloom_scent,
                           property->subject_dhkey);
  }
}

void __np_property_update(np_util_statemachine_t *statemachine,
                          const np_util_event_t   event) {
  // np_ctx_memory(statemachine->_user_data);
  // log_trace_msg(LOG_TRACE, "start: void __np_property_update(...) {");

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);

  NP_CAST(my_property_key->entity_array[0],
          np_msgproperty_conf_t,
          old_property);
  NP_CAST(event.user_data, np_msgproperty_conf_t, new_property);
  // buggy, but for now ...
  *old_property = *new_property;
}

void __np_msgproperty_send_available_messages(
    np_util_statemachine_t *statemachine, const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, property_key);
  NP_CAST(property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
  NP_CAST(property_key->entity_array[1], np_msgproperty_run_t, property_run);

  // upsert message intent token
  np_aaatoken_t *intent_token =
      _np_msgproperty_get_mxtoken(context, property_key);
  if (NULL == intent_token) {
    log_msg(LOG_ERROR, NULL, "missing peer intent token");
    return;
  }

  double now = np_time_now();

  if (property_run->last_intent_update == 0 ||
      (now - property_run->last_intent_update) >
          MIN((double)property_conf->token_min_ttl,
              NP_TOKEN_MIN_RESEND_INTERVAL_SEC)) {

    np_tree_t *intent_data = np_tree_create();
    np_tree_t *msg_body    = np_tree_create();

    np_dhkey_t send_dhkey = property_conf->subject_dhkey_out;
    np_dhkey_t recv_dhkey = property_conf->subject_dhkey_in;

    np_dhkey_t target_dhkey = property_conf->subject_dhkey;

    np_dhkey_t available_out_dhkey = {0};

    np_aaatoken_encode(intent_data, intent_token);
    struct np_e2e_message_s *msg_out = NULL;
    np_new_obj(np_message_t, msg_out);

    np_util_event_t available_event = {.type = (evt_internal | evt_message),
                                       .target_dhkey = target_dhkey};
    np_dhkey_t      available_dhkey = {0};

    char uuid_hex[NP_UUID_BYTES * 2 + 1];
    sodium_bin2hex(uuid_hex,
                   2 * NP_UUID_BYTES + 1,
                   intent_token->uuid,
                   NP_UUID_BYTES);

    if (_np_dhkey_equal(&property_key->dhkey,
                        &send_dhkey)) { // send our token, search for
                                        // receiver of messages
      np_generate_subject((np_subject *)&available_dhkey,
                          _NP_MSG_AVAILABLE_SENDER,
                          strnlen(_NP_MSG_AVAILABLE_SENDER, 256));
      np_tree_insert_str(msg_body,
                         _NP_URN_INTENT_PREFIX,
                         np_treeval_new_cwt(intent_data));
      _np_message_create(msg_out,
                         target_dhkey,
                         context->my_node_key->dhkey,
                         available_dhkey,
                         msg_body);

      log_info(LOG_ROUTING,
               msg_out->uuid,
               "sending available message for %s as a sender: "
               "_NP_MSG_AVAILABLE_SENDER {intent uuid: %s)",
               property_conf->msg_subject,
               uuid_hex);

      available_out_dhkey =
          _np_msgproperty_tweaked_dhkey(OUTBOUND, available_dhkey);
    } else if (_np_dhkey_equal(&property_key->dhkey, &recv_dhkey)) {
      np_generate_subject((np_subject *)&available_dhkey,
                          _NP_MSG_AVAILABLE_RECEIVER,
                          strnlen(_NP_MSG_AVAILABLE_RECEIVER, 256));
      np_tree_insert_str(msg_body,
                         _NP_URN_INTENT_PREFIX,
                         np_treeval_new_cwt(intent_data));
      _np_message_create(msg_out,
                         target_dhkey,
                         context->my_node_key->dhkey,
                         available_dhkey,
                         msg_body);

      log_info(LOG_ROUTING,
               msg_out->uuid,
               "sending available message for %s as a receiver: "
               "_NP_MSG_AVAILABLE_RECEIVER {intent uuid: %s)",
               property_conf->msg_subject,
               uuid_hex);
      available_out_dhkey =
          _np_msgproperty_tweaked_dhkey(OUTBOUND, available_dhkey);
    } else {
      log_error(NULL,
                "sending available message for %s in unknown state",
                property_conf->msg_subject);
      ABORT("sending available message for %s in unknown state",
            property_conf->msg_subject);
    }

    available_event.user_data = msg_out;
    _np_event_runtime_add_event(context,
                                event.current_run,
                                available_out_dhkey,
                                available_event);
    property_run->last_intent_update = now;
    // set the session identifier for default messages
    property_run->current_fp = np_aaatoken_get_fingerprint(intent_token, false);

    np_tree_free(intent_data);
    np_tree_free(msg_body);
    np_unref_obj(np_message_t, msg_out, ref_obj_creation);

  } else {
    log_debug(LOG_AAATOKEN | LOG_MSGPROPERTY,
              intent_token->uuid,
              "not sending available message for %s / %f - %d - %f",
              property_conf->msg_subject,
              property_run->last_intent_update,
              property_conf->token_min_ttl,
              now - property_run->last_intent_update);
  }
  np_unref_obj(np_aaatoken_t, intent_token, "_np_msgproperty_get_mxtoken");
}

void __np_msgproperty_send_pheromone_messages(
    np_util_statemachine_t         *statemachine,
    NP_UNUSED const np_util_event_t event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, property_key);
  NP_CAST(property_key->entity_array[0], np_msgproperty_conf_t, property_conf);
  NP_CAST(property_key->entity_array[1], np_msgproperty_run_t, property_run);

  np_dhkey_t send_dhkey   = property_conf->subject_dhkey_out;
  np_dhkey_t recv_dhkey   = property_conf->subject_dhkey_in;
  np_dhkey_t target_dhkey = property_conf->subject_dhkey;

  bool is_send = _np_dhkey_equal(&property_key->dhkey, &send_dhkey);
  bool is_recv = _np_dhkey_equal(&property_key->dhkey, &recv_dhkey);

  unsigned char *buffer      = NULL;
  uint16_t       buffer_size = 0;
  _np_neuropil_bloom_serialize(property_key->bloom_scent,
                               &buffer,
                               &buffer_size);

  np_tree_t *bloom_data = np_tree_create();

  float _target_age = BAD_LINK;
  float _return_age = _target_age;

  np_sll_t(np_dhkey_t, result_list) = NULL;
  sll_init(np_dhkey_t, result_list);

  if (is_send) {
    np_tree_insert_int(
        bloom_data,
        _np_pheromone_calc_table_position(target_dhkey,
                                          np_pheromone_direction_receiver),
        np_treeval_new_bin((void *)buffer, buffer_size));
    log_debug(
        LOG_MSGPROPERTY | LOG_PHEROMONE,
        NULL,
        "adding %25s bloom data at %i",
        property_conf->msg_subject,
        _np_pheromone_calc_table_position(target_dhkey,
                                          np_pheromone_direction_receiver));

    _np_pheromone_snuffle_receiver(context,
                                   result_list,
                                   target_dhkey,
                                   &_return_age);

    if (FLAG_CMP(property_conf->ack_mode, ACK_DESTINATION) ||
        FLAG_CMP(property_conf->ack_mode, ACK_CLIENT)) {

      np_dhkey_t ack_dhkey = context->my_node_key->dhkey;
      np_generate_subject((np_subject *)&ack_dhkey,
                          _NP_MSG_ACK,
                          strnlen(_NP_MSG_ACK, 256));

      np_bloom_t *ack_scent = _np_neuropil_bloom_create();
      _np_neuropil_bloom_add(ack_scent, ack_dhkey);
      // increase pheromone strength for acknowledge part, there is no way to
      // increase it with a signal from the "opposite" side
      for (uint8_t i = 0; i < 16; i++) {
        _np_neuropil_bloom_age_increment(ack_scent);
      }

      unsigned char *ack_buffer      = NULL;
      uint16_t       ack_buffer_size = 0;
      _np_neuropil_bloom_serialize(ack_scent, &ack_buffer, &ack_buffer_size);

      np_tree_insert_int(
          bloom_data,
          _np_pheromone_calc_table_position(ack_dhkey,
                                            np_pheromone_direction_sender),
          np_treeval_new_bin((void *)ack_buffer, ack_buffer_size));
      log_debug(
          LOG_MSGPROPERTY | LOG_PHEROMONE,
          NULL,
          "adding %25s bloom data at %i",
          _NP_MSG_ACK,
          _np_pheromone_calc_table_position(ack_dhkey,
                                            np_pheromone_direction_sender));

      free(ack_buffer);
      _np_bloom_free(ack_scent);
    }
  } else if (is_recv) {
    np_tree_insert_int(
        bloom_data,
        _np_pheromone_calc_table_position(target_dhkey,
                                          np_pheromone_direction_sender),
        np_treeval_new_bin((void *)buffer, buffer_size));
    log_debug(LOG_MSGPROPERTY | LOG_PHEROMONE,
              NULL,
              "adding %25s bloom data at %i",
              property_conf->msg_subject,
              _np_pheromone_calc_table_position(target_dhkey,
                                                np_pheromone_direction_sender));

    _np_pheromone_snuffle_sender(context,
                                 result_list,
                                 target_dhkey,
                                 &_return_age);
  }
  sll_free(np_dhkey_t, result_list);

  double last_pheromone_update = property_run->last_pheromone_update;

  if (_return_age > _target_age) _target_age = _return_age;

  double now = np_time_now();

  np_util_event_t pheromone_event = {.type = (evt_internal | evt_message),
                                     .target_dhkey = target_dhkey};

  if (last_pheromone_update == 0 ||
      (now - last_pheromone_update) >
          (_target_age * PHEROMONE_UPDATE_INTERVAL)) {
    np_dhkey_t pheromone_dhkey = {0};
    np_generate_subject((np_subject *)&pheromone_dhkey,
                        _NP_MSG_PHEROMONE_UPDATE,
                        20);

    struct np_e2e_message_s *msg_out = NULL;
    np_new_obj(np_message_t, msg_out);
    _np_message_create(msg_out,
                       target_dhkey,
                       context->my_node_key->dhkey,
                       pheromone_dhkey,
                       bloom_data);

    log_info(LOG_MSGPROPERTY | LOG_PHEROMONE,
             msg_out->uuid,
             "sending pheromone trail message for subject %s: "
             "_NP_MSG_PHEROMONE_UPDATE with %f success probability",
             property_conf->msg_subject,
             _target_age);

    np_dhkey_t pheromone_out_dhkey =
        _np_msgproperty_tweaked_dhkey(OUTBOUND, pheromone_dhkey);
    pheromone_event.user_data = msg_out;
    _np_event_runtime_add_event(context,
                                event.current_run,
                                pheromone_out_dhkey,
                                pheromone_event);

    property_run->last_pheromone_update = now;
    np_unref_obj(np_message_t, msg_out, ref_obj_creation);
  }

  np_tree_free(bloom_data);
  free(buffer);
}

void __np_property_check(np_util_statemachine_t *statemachine,
                         const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(my_property_key->entity_array[0],
          np_msgproperty_conf_t,
          property_conf);
  NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);

  if (property_run->response_handler != NULL) {
    _np_msgproperty_cleanup_response_handler(property_run, event);
  }

  if (property_conf->is_internal == false) {
    if (FLAG_CMP(property_conf->mode_type, OUTBOUND)) {
      __np_msgproperty_redeliver_messages(statemachine, event);
    }
    _np_msgproperty_check_msgcache(statemachine, event);
    _np_msgproperty_cleanup_cache(statemachine, event);

    _np_msgproperty_upsert_token(statemachine, event);

    if (np_has_joined(context)) {
      __np_msgproperty_send_pheromone_messages(statemachine, event);
      __np_msgproperty_send_available_messages(statemachine, event);
    }

    __np_intent_check(statemachine, event);
  }

  property_run->last_update = _np_time_now(context);

  _np_msgproperty_job_msg_uniquety(property_conf, property_run);

  if (event.user_data != NULL) {
    log_warn(LOG_GLOBAL | LOG_MSGPROPERTY,
             NULL,
             "unexpected datatype %" PRIu8
             " attached to event (__np_property_check)",
             np_memory_get_type(event.user_data));
  }
}

bool __is_external_message_event(np_util_statemachine_t *statemachine,
                                 const np_util_event_t   event) {
  bool ret = false;

  if (!ret)
    ret =
        FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_external);
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);

  return ret;
}

void __np_property_handle_in_msg(np_util_statemachine_t *statemachine,
                                 const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(my_property_key->entity_array[0],
          np_msgproperty_conf_t,
          property_conf);
  NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);

  bool ret = true;

  if (_np_memory_rtti_check(event.user_data, np_memory_types_np_message_t)) {
    NP_CAST(event.user_data, struct np_e2e_message_s, msg_in);
    ret =
        _np_msgproperty_check_msg_uniquety(property_conf, property_run, msg_in);
  }

  __np_msgproperty_threshold_increase(property_conf, property_run);

  sll_iterator(np_evt_callback_t) iter = sll_first(property_run->callbacks);
  while (iter != NULL && ret) {
    if (iter->val != NULL) {
      ret &= iter->val(context, event);
      if (!ret) break;
    }
    sll_next(iter);
  }

  if (property_conf->is_internal == false &&
      property_conf->audience_type != NP_MX_AUD_VIRTUAL && ret == true) {
    // call user callbacks
    NP_CAST(event.user_data, struct np_e2e_message_s, msg_in);
    sll_iterator(np_usercallback_ptr) iter_usercallbacks =
        sll_first(property_run->user_callbacks);
    while (iter_usercallbacks != NULL && ret) {
      log_debug(LOG_MESSAGE,
                msg_in->uuid,
                "invoking user callback %p",
                iter_usercallbacks->val->fn);
      ret &= iter_usercallbacks->val->fn(context,
                                         msg_in,
                                         msg_in->msg_body,
                                         iter_usercallbacks->val->data);
      log_info(LOG_MESSAGE,
               msg_in->uuid,
               "invoked user callbacks. result: %s",
               ret ? "ok" : "error");
      sll_next(iter_usercallbacks);
    }
  }

  __np_msgproperty_threshold_decrease(property_conf, property_run);

  if (ret) _np_increment_received_msgs_counter(property_conf->subject_dhkey);

  if (dll_size(property_run->msg_cache) > 0)
    _np_msgproperty_check_msgcache_for(statemachine, event);
}

bool __is_internal_message_event(np_util_statemachine_t *statemachine,
                                 const np_util_event_t   event) {
  bool ret = false;

  if (!ret)
    ret =
        FLAG_CMP(event.type, evt_message) && FLAG_CMP(event.type, evt_internal);
  if (ret) ret &= !FLAG_CMP(event.type, evt_redeliver);
  if (ret)
    ret &=
        (_np_memory_rtti_check(event.user_data, np_memory_types_np_message_t) ||
         _np_memory_rtti_check(event.user_data,
                               np_memory_types_np_messagepart_t));

  return ret;
}

bool __is_sender_token_available(np_util_statemachine_t *statemachine,
                                 const np_util_event_t   event) {

  bool ret = false;

  NP_CAST(statemachine->_user_data, np_key_t, property_key);
  NP_CAST(property_key->entity_array[0],
          np_msgproperty_conf_t,
          my_property_conf);
  NP_CAST(property_key->entity_array[1], np_msgproperty_run_t, my_property_run);

  if (__is_external_message_event(statemachine, event)) {
    if (!ret)
      ret = my_property_conf->is_internal; // internal messages have no token
    if (!ret) {
      ret = !__np_msgproperty_threshold_breached(my_property_conf,
                                                 my_property_run);
      // ret &= (FLAG_CMP(my_property_conf->cache_policy, FIFO) &&
      //         dll_size(my_property_run->msg_cache) == 0);
      ret &= _np_intent_has_crypto_session(property_key, event.target_dhkey);
    }
  }
  return ret;
}

bool __is_receiver_token_available(np_util_statemachine_t *statemachine,
                                   const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  bool ret = false;

  if (__is_internal_message_event(statemachine, event)) {
    NP_CAST(statemachine->_user_data, np_key_t, property_key);
    NP_CAST(property_key->entity_array[0],
            np_msgproperty_conf_t,
            my_property_conf);
    NP_CAST(property_key->entity_array[1],
            np_msgproperty_run_t,
            my_property_run);

    if (!ret)
      ret = my_property_conf->is_internal; // internal messages have no token
    if (!ret) {
      ret = !__np_msgproperty_threshold_breached(my_property_conf,
                                                 my_property_run);
      // ret &= (FLAG_CMP(my_property_conf->cache_policy, FIFO) &&
      //         dll_size(my_property_run->msg_cache) == 0);
      ret &= _np_intent_has_crypto_session(property_key, event.target_dhkey);
    }
  }
  return ret;
}

bool __is_no_token_available(np_util_statemachine_t *statemachine,
                             const np_util_event_t   event) {

  bool ret = false;
  // the fact that this check is called can only mean that no token has been
  // found in an earlier check. so we just have to repeat whether this is an
  // internal or external message as a criteria that no token has been found
  // or that the threshold has been breached. we still need the check for
  // the message type to differentiate from e.g. lifecycle events

  // NP_CAST(statemachine->_user_data, np_key_t, property_key);
  // NP_CAST(property_key->entity_array[0], np_msgproperty_conf_t,
  // my_property_conf);
  ret = event.user_data != NULL;
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);
  if (!ret)
    ret = __is_internal_message_event(statemachine, event) ||
          __is_external_message_event(statemachine, event);
  return ret;
}

void __np_property_handle_out_msg(np_util_statemachine_t *statemachine,
                                  const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(my_property_key->entity_array[0],
          np_msgproperty_conf_t,
          property_conf);
  NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);

  bool user_result = true;

  __np_msgproperty_threshold_increase(property_conf, property_run);
  if (property_conf->audience_type != NP_MX_AUD_VIRTUAL &&
      property_conf->is_internal == false) {
    NP_CAST(event.user_data, struct np_e2e_message_s, msg_out);
    sll_iterator(np_usercallback_ptr) iter_usercallbacks =
        sll_first(property_run->user_callbacks);
    while (iter_usercallbacks != NULL && user_result) {
      user_result &= iter_usercallbacks->val->fn(
          context,
          msg_out,
          (msg_out == NULL ? NULL : msg_out->msg_body),
          iter_usercallbacks->val->data);
      log_trace(LOG_MESSAGE,
                msg_out->uuid,
                "%s user callback result: %" PRIu8,
                FUNC,
                user_result);
      sll_next(iter_usercallbacks);
    }
  }

  sll_iterator(np_evt_callback_t) iter = sll_first(property_run->callbacks);
  while (iter != NULL && user_result) {
    if (iter->val != NULL) {
      user_result &= iter->val(context, event);
      if (!user_result) break;
    }
    sll_next(iter);
  }

  if (FLAG_CMP(property_conf->ack_mode, ACK_NONE))
    __np_msgproperty_threshold_decrease(property_conf, property_run);

  if (user_result) {
    _np_increment_send_msgs_counter(property_conf->subject_dhkey);
  }
}

void __np_property_redelivery_set(np_util_statemachine_t *statemachine,
                                  const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(my_property_key->entity_array[0],
          np_msgproperty_conf_t,
          property_conf);
  NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);
  NP_CAST(event.user_data, struct np_e2e_message_s, message);

  double resend_interval = property_conf->msg_ttl / (property_conf->retry + 1);

  if (np_tree_find_uuid(property_run->redelivery_messages, message->uuid) ==
      NULL) {
    log_msg(LOG_INFO,
            message->uuid,
            "storing message %s for possible re-delivery",
            property_conf->msg_subject);
    __np_msgproperty_threshold_increase(property_conf, property_run);
    np_redelivery_data_t *redeliver = malloc(sizeof(np_redelivery_data_t));
    _np_dhkey_assign(&redeliver->target, &event.target_dhkey);
    redeliver->message       = message;
    redeliver->redelivery_at = message->send_at + resend_interval;
    np_tree_insert_uuid(property_run->redelivery_messages,
                        message->uuid,
                        np_treeval_new_v(redeliver));
    np_ref_obj(np_message_t, message, FUNC);
  }
}

void __np_response_handler_set(np_util_statemachine_t *statemachine,
                               const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(my_property_key->entity_array[0],
          np_msgproperty_conf_t,
          property_conf);
  NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);
  NP_CAST(event.user_data, np_responsecontainer_t, responsehandler);

  np_tree_elem_t *msg_tree_elem = NULL;
  if (property_conf->is_internal) { // registration of response handler for
                                    // message type NP_ACK
    if (np_tree_find_uuid(property_run->response_handler,
                          &responsehandler->uuid) == NULL)
      np_tree_insert_uuid(property_run->response_handler,
                          &responsehandler->uuid,
                          np_treeval_new_v(responsehandler));
  } else { // a responsehandler reporting a timeout or an acknowledgement
    if ((msg_tree_elem = np_tree_find_uuid(property_run->redelivery_messages,
                                           &responsehandler->uuid)) != NULL) {
      log_msg(LOG_INFO,
              &responsehandler->uuid,
              "message %s acknowledged or timed out",
              property_conf->msg_subject);
      np_redelivery_data_t *redeliver = msg_tree_elem->val.value.v;
      np_unref_obj(np_message_t,
                   redeliver->message,
                   "__np_property_redelivery_set");
      np_tree_del_uuid(property_run->redelivery_messages,
                       &responsehandler->uuid);
      free(redeliver);
      __np_msgproperty_threshold_decrease(property_conf, property_run);
    }
    // np_unref_obj(np_responsecontainer_t, responsehandler, ref_obj_usage);
  }
}

bool __is_message_redelivery_event(np_util_statemachine_t *statemachine,
                                   const np_util_event_t   event) {
  bool ret = false;

  if (!ret) ret = FLAG_CMP(event.type, evt_message);
  if (ret)
    ret &= (FLAG_CMP(event.type, evt_redeliver) &&
            FLAG_CMP(event.type, evt_internal));
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t);

  return ret;
}

bool __is_response_event(np_util_statemachine_t *statemachine,
                         const np_util_event_t   event) {

  bool ret = false;

  if (!ret) ret = FLAG_CMP(event.type, evt_response);
  if (ret)
    ret &= (FLAG_CMP(event.type, evt_timeout) ||
            FLAG_CMP(event.type, evt_internal));
  if (ret)
    ret &= _np_memory_rtti_check(event.user_data,
                                 np_memory_types_np_responsecontainer_t);
  return ret;
}

void __np_property_handle_intent(np_util_statemachine_t *statemachine,
                                 const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, my_property_key);
  NP_CAST(event.user_data, np_aaatoken_t, intent_token);

  NP_CAST(my_property_key->entity_array[0],
          np_msgproperty_conf_t,
          property_conf);
  NP_CAST(my_property_key->entity_array[1], np_msgproperty_run_t, property_run);

  np_dhkey_t audience_id = {0};
  if (property_conf->audience_type == NP_MX_AUD_PROTECTED) {
    np_str_id((np_id *)&audience_id, intent_token->audience);
  }

  if (_np_policy_check_compliance(property_run->required_attributes_policy,
                                  &intent_token->attributes) &&
      (_np_dhkey_equal(&context->my_identity->dhkey, &audience_id) ||
       _np_dhkey_equal(&context->realm_id, &audience_id))) {
    log_info(LOG_AAATOKEN,
             intent_token->uuid,
             "policy compliance result for %s is access allowed",
             property_conf->msg_subject);
    // always?: just store the available tokens in memory and update them if
    // new data arrives
    np_dhkey_t sendtoken_issuer_key = np_aaatoken_get_partner_fp(intent_token);

    if (_np_dhkey_equal(&sendtoken_issuer_key, &context->my_node_key->dhkey)) {
      // only add the token if it is not from ourself (in case of IN/OUTBOUND
      // on same subject)
      // TODO: CHECK IF NECCESARY
    }
    bool needs_authz = false;

    // choose correct target ledger - receiver
    if (_np_dhkey_equal(&property_conf->subject_dhkey_in,
                        &my_property_key->dhkey)) {
      log_info(LOG_AAATOKEN,
               intent_token->uuid,
               "adding sending intent for subject %s",
               property_conf->msg_subject);
      np_aaatoken_t *old_token =
          _np_intent_add_sender(my_property_key, intent_token);

      if (IS_AUTHORIZED(intent_token->state)) {
        // check if some messages are left in the cache
        np_dhkey_t initial_session_fp = {0};
        np_dhkey_t intent_token_fp =
            np_aaatoken_get_fingerprint(intent_token, false);
        _np_dhkey_xor(&initial_session_fp,
                      &intent_token_fp,
                      &property_run->current_fp);
        np_util_event_t check_event = event;
        // check for session setup messages
        _np_dhkey_assign(&check_event.target_dhkey, &initial_session_fp);
        _np_msgproperty_check_msgcache_for(statemachine, check_event);
        // check for private messages
        _np_dhkey_assign(&check_event.target_dhkey, &intent_token_fp);
        _np_msgproperty_check_msgcache_for(statemachine, check_event);
      } else {
        needs_authz = true;
      }
      np_unref_obj(np_aaatoken_t, old_token, ref_aaatoken_local_mx_tokens);
    }
    // choose correct target ledger - sender
    if (_np_dhkey_equal(&property_conf->subject_dhkey_out,
                        &my_property_key->dhkey)) {

      if (IS_AUTHORIZED(intent_token->state)) {
        // TODO: should be done better - respect the uuid of the token and only
        // load each token once
        // first send out own intent token again
        property_run->last_intent_update = 0;
        __np_msgproperty_send_available_messages(statemachine, event);
      }

      // now import the new receiver token
      np_dhkey_t _intent_token_id =
          np_aaatoken_get_fingerprint(intent_token, true);
      char _intent_token_id_s[65] = {0};
      _np_dhkey_str(&_intent_token_id, _intent_token_id_s);
      log_info(LOG_AAATOKEN,
               intent_token->uuid,
               "adding receiver intent for subject %s fingerprint %s",
               property_conf->msg_subject,
               _intent_token_id_s);
      np_aaatoken_t *old_token =
          _np_intent_add_receiver(my_property_key, intent_token);

      if (IS_AUTHORIZED(intent_token->state)) {
        // check if some messages are left in the cache
        _np_msgproperty_check_msgcache(statemachine, event);
      } else {
        needs_authz = true;
      }
      np_unref_obj(np_aaatoken_t, old_token, ref_aaatoken_local_mx_tokens);
    }

    if (needs_authz == true) {
      log_info(LOG_AAATOKEN,
               intent_token->uuid,
               "token for %s complies with subject policy %s",
               intent_token->issuer,
               intent_token->subject);

      log_info(LOG_AAATOKEN,
               intent_token->uuid,
               "authorizing intent for subject %s",
               property_conf->msg_subject);
      np_dhkey_t      authz_target = context->my_identity->dhkey;
      np_util_event_t authz_event  = {.type =
                                          (evt_token | evt_external | evt_authz),
                                      .user_data    = intent_token,
                                      .target_dhkey = event.target_dhkey};
      _np_event_runtime_add_event(context,
                                  event.current_run,
                                  authz_target,
                                  authz_event);
    }
  } else {
    log_debug(LOG_AAATOKEN,
              intent_token->uuid,
              "policy compliance result for %s is access denied",
              property_conf->msg_subject);
  }
}
