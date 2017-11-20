//
// neuropil is copyright 2016-017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef _NP_EVENT_H_
#define _NP_EVENT_H_

#include "event/ev.h"

#ifdef __cplusplus
extern "C" {
#endif

NP_API_INTERN
void _np_events_async(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents);

NP_API_INTERN
void _np_events_read(np_jobargs_t* args);

NP_API_INTERN
void _np_event_rejoin_if_necessary(NP_UNUSED np_jobargs_t* args);

NP_API_INTERN
void _np_event_cleanup_msgpart_cache(NP_UNUSED np_jobargs_t* args);

NP_API_INTERN
void _np_suspend_event_loop();
NP_API_INTERN
void _np_resume_event_loop();

double np_event_sleep(double time);

#ifdef __cplusplus
}
#endif


#endif /* _NP_EVENT_H_ */
