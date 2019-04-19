//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_UTIL_EVENT_H_
#define _NP_UTIL_EVENT_H_

#include <stdbool.h>
#include "np_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

// TODO: event definitions need to move to another file
enum event_type {
    noop = 0, // update time
    internal, // no payload
    message,  // payload of type message
    token,    // payload of type token
};

struct np_util_event_s {
    enum event_type type;
    np_state_t* context;
    void *user_data;
};

typedef struct np_util_event_s np_util_event_t;

#ifdef __cplusplus
}
#endif

#endif /* _NP_UTIL_EVENT_H_ */
