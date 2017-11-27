//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef NP_EVENT_H_
#define NP_EVENT_H_

#include "event/ev.h"

#ifdef __cplusplus
extern "C" {
#endif

void _np_events_async(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents);
void _np_events_read(np_jobargs_t* args);
void _np_event_rejoin_if_necessary(NP_UNUSED np_jobargs_t* args);
void _np_event_cleanup_msgpart_cache(NP_UNUSED np_jobargs_t* args);
void* _np_event_run();
double np_event_sleep(double time);
#ifdef __cplusplus
}
#endif


#endif /* NP_EVENT_H_ */
