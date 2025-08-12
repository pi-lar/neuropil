//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_EVENTQUEUE_H_
#define _NP_EVENTQUEUE_H_

#include <stdbool.h>

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

NP_API_INTERN
void __np_event_runtime_add_event(np_state_t         *context,
                                  np_event_runtime_t *runtime,
                                  np_dhkey_t          dhkey,
                                  np_util_event_t     event,
                                  char               *source);
NP_API_INTERN
void __np_event_runtime_start_with_event(np_state_t     *context,
                                         np_dhkey_t      dhkey,
                                         np_util_event_t event,
                                         char           *source);

#define _np_event_runtime_add_event(context, runtime, dhkey, event)            \
  __np_event_runtime_add_event(context, runtime, dhkey, event, FUNC);
#define _np_event_runtime_start_with_event(context, dhkey, event)              \
  __np_event_runtime_start_with_event(context, dhkey, event, FUNC);

#ifdef __cplusplus
}
#endif

#endif /* _NP_EVENTQUEUE_H_ */
