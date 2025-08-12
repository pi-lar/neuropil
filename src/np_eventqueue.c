//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "np_eventqueue.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "event/ev.h"
#include "tree/tree.h"

#include "neuropil_log.h"

#include "core/np_comp_msgproperty.h"
#include "util/np_event.h"
#include "util/np_list.h"
#include "util/np_tree.h"

#include "np_aaatoken.h"
#include "np_constants.h"
#include "np_evloop.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_messagepart.h"
#include "np_route.h"
#include "np_settings.h"
#include "np_threads.h"
#include "np_types.h"
#include "np_util.h"

static const char _np_ref_event_runtime[] = "_np_event_runtime";

enum { np_event_runtime_max_size = 255 };

struct np_event_runtime_s {
  np_util_event_t  __chained_events[np_event_runtime_max_size];
  volatile uint8_t __chained_events_size;
};
/**
 * @brief Adds an event to a given event chain to be executed after the current
 * key lock is released.
 *
 * @param[in] context The application Context to work in
 * @param[in] runtime The event chain object
 * @param[in] dhkey The target key for the event
 * @param[in] event The event configuration itself
 */
void __np_event_runtime_add_event(np_state_t         *context,
                                  np_event_runtime_t *runtime,
                                  np_dhkey_t          dhkey,
                                  np_util_event_t     event,
                                  char               *fn_source) {
#ifdef DEBUG
  event.__fn_source = fn_source;
#endif
  if (runtime == NULL) {
    __np_event_runtime_start_with_event(context, dhkey, event, fn_source);
    return;
  }

  if (runtime->__chained_events_size == np_event_runtime_max_size) {
    // IS ERROR
    for (uint8_t _idx = 0; _idx < runtime->__chained_events_size; _idx++) {
      np_util_event_t next_event = runtime->__chained_events[_idx];

      np_key_t *__source_key =
          _np_keycache_find_or_create(context, next_event.__source_dhkey);
      char uuid_out[NP_UUID_BYTES] = {0};
      if (next_event.user_data != NULL &&
          _np_memory_rtti_check(next_event.user_data,
                                np_memory_types_np_message_t))
        memcpy(uuid_out,
               ((struct np_e2e_message_s *)next_event.user_data)->uuid,
               NP_UUID_BYTES);
      if (next_event.user_data != NULL &&
          _np_memory_rtti_check(next_event.user_data,
                                np_memory_types_np_messagepart_t))
        memcpy(uuid_out,
               ((struct np_n2n_messagepart_s *)next_event.user_data)
                   ->e2e_msg_part.uuid,
               NP_UUID_BYTES);
      log_error(uuid_out,
                "event@%" PRIu8 " event_type: %" PRIu32
                " key: %s key_type: %" PRIu32 " userdata_type: %" PRIu32,
                _idx,
                next_event.type,
                _np_key_as_str(__source_key),
                __source_key->type,
                np_memory_get_type(next_event.user_data));
      np_unref_obj(np_key_t, __source_key, "_np_keycache_find_or_create");
    }
  }
  ASSERT((runtime->__chained_events_size) < np_event_runtime_max_size,
         "Maximum event chaining reached %" PRIu8 "/%" PRIu8,
         runtime->__chained_events_size,
         np_event_runtime_max_size);

  np_key_t *__source_key = _np_keycache_find(context, dhkey);
  if (__source_key != NULL) {
    char uuid_out[NP_UUID_BYTES] = {0};
    if (event.user_data != NULL &&
        _np_memory_rtti_check(event.user_data, np_memory_types_np_message_t))
      memcpy(uuid_out,
             ((struct np_e2e_message_s *)event.user_data)->uuid,
             NP_UUID_BYTES);
    if (event.user_data != NULL &&
        _np_memory_rtti_check(event.user_data,
                              np_memory_types_np_messagepart_t))
      memcpy(
          uuid_out,
          ((struct np_n2n_messagepart_s *)event.user_data)->e2e_msg_part.uuid,
          NP_UUID_BYTES);
    log_debug(LOG_EVENT,
              uuid_out,
              "ADDING event@%" PRIu8 " event_type: %" PRIu32
              " key: %s key_type: %" PRIu8 " userdata_type: %" PRIu32,
              runtime->__chained_events_size,
              event.type,
              _np_key_as_str(__source_key),
              __source_key->type,
              np_memory_get_type(event.user_data));
    np_unref_obj(np_key_t, __source_key, "_np_keycache_find");
  }
  // ASSERT(!(runtime->__chained_events_size > 100 && event.type == 17 &&
  // _np_memory_rtti_check(event.user_data,np_memory_types_np_messagepart_t)),"TEST");

  _np_dhkey_assign(&event.__source_dhkey, &dhkey);
  event.current_run = runtime;
  if (event.user_data != NULL) {
    // increase the generic object reference counter
    np_ref_obj(np_unknown_t, event.user_data, _np_ref_event_runtime);
  }
  runtime->__chained_events[runtime->__chained_events_size] = event;
  runtime->__chained_events_size++;
}
/**
 * @brief Starts a synchronus executed event chain.
 *
 * @param[in] context The application Context to work in.
 * @param[in] dhkey   The target key for the event
 * @param[in] event   The event configuration itself
 */
void __np_event_runtime_start_with_event(np_state_t     *context,
                                         np_dhkey_t      dhkey,
                                         np_util_event_t event,
                                         char           *source) {
  np_event_runtime_t _run = {0};

  unsigned char  run_id[NP_UUID_BYTES];
  unsigned char *run_id2 = &run_id[0];
  // unsigned char *run_id2 = &run_id;
  np_uuid_create("urn:np:runtime:create_event_id", 5455, &run_id2);

  // add event to own chain
  __np_event_runtime_add_event(context, &_run, dhkey, event, source);
  log_info(LOG_EVENT,
           run_id,
           "start event chain for event_type: %" PRIu32 " user_data:%p",
           event.type,
           event.user_data);

  // iterate over event chain (which may increase with each executed event )
  uint8_t chained_events_idx = 0;
  while (chained_events_idx < _run.__chained_events_size) {
    np_util_event_t next_event = _run.__chained_events[chained_events_idx];
    // next_event.cleanup         = NULL;
    // next_event.user_data = next_event.user_data;
    log_info(LOG_EVENT,
             run_id,
             "run event chain %" PRIu8 " %s",
             chained_events_idx,
#ifdef DEBUG
             next_event.__fn_source
#else
             ""
#endif
    );
    _np_keycache_execute_event(context, next_event.__source_dhkey, next_event);
    log_debug(LOG_EVENT,
              run_id,
              "completed event chain / %" PRIu8 " %s",
              chained_events_idx,
              next_event.__fn_source);
    chained_events_idx++;
  }
  log_info(LOG_EVENT, run_id, "begin with event chain cleanup");
  // release all associated data and run cleanup functions
  chained_events_idx = 0;
  while (chained_events_idx < _run.__chained_events_size) {
    np_util_event_t next_event = _run.__chained_events[chained_events_idx];
    log_info(LOG_EVENT,
             run_id,
             "cleanup event chain %" PRIu8,
             chained_events_idx);

    if (next_event.user_data != NULL) {
      np_unref_obj(np_unknown_t, next_event.user_data, _np_ref_event_runtime);
    }
    chained_events_idx++;
  }

  log_debug(LOG_EVENT | LOG_VERBOSE,
            run_id,
            "Event chain depth at %" PRIu8 " (%5.1f%%)",
            chained_events_idx,
            (chained_events_idx / (np_event_runtime_max_size + .0)) * 100);
}
