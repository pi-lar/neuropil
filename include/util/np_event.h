//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_UTIL_EVENT_H_
#define _NP_UTIL_EVENT_H_

#include <stdbool.h>

#include "np_dhkey.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// TODO: event definitions need to move to another file
enum event_type {
  evt_noop = 0x0000, // update time

  evt_internal = 0x0001, // internal generated event
  evt_external = 0x0002, // external generated event, i.e. a message has arrived
  evt_timeout  = 0x0004, // internal timeout event, i.e. a message has not been
                         // acknowledged
  evt_userspace =
      0x0008, // generated in user space (i.e. outside of neuropil library)

  // user_data type
  evt_message  = 0x0010, // payload of type message / external
  evt_token    = 0x0020, // payload of type token
  evt_property = 0x0040, // payload of type msgproperty
  evt_response = 0x0080, // responsehandler to be passed around

  // special event types
  evt_authn     = 0x0100,
  evt_authz     = 0x0200,
  evt_accnt     = 0x0400,
  evt_redeliver = 0x0800,

  evt_shutdown = 0x1000,
  evt_disable  = 0x2000,
  evt_enable   = 0x4000,
};
typedef void (*np_event_cleanup_func)(void *context, np_util_event_t ev);

struct np_util_event_s {
  np_dhkey_t            __source_dhkey;
  np_dhkey_t            target_dhkey;
  enum event_type       type;
  void                 *user_data;
  np_event_cleanup_func cleanup;

  np_event_runtime_t *current_run;

#ifdef DEBUG
  char *__fn_source;
#endif
};

#ifdef __cplusplus
}
#endif

#endif /* _NP_UTIL_EVENT_H_ */
