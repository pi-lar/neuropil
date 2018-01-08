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

struct ev_loop * _np_event_get_loop_io();
struct ev_loop * _np_event_get_loop_http();
struct ev_loop * _np_event_get_loop_in();
struct ev_loop * _np_event_get_loop_out();

void _np_events_read_in(NP_UNUSED np_jobargs_t* args);
void _np_events_read_out(NP_UNUSED np_jobargs_t* args);
void _np_events_read_io(NP_UNUSED np_jobargs_t* args);
void _np_events_read_http(NP_UNUSED np_jobargs_t* args);
void _np_event_rejoin_if_necessary(NP_UNUSED np_jobargs_t* args);
void _np_event_cleanup_msgpart_cache(NP_UNUSED np_jobargs_t* args);
void* _np_event_in_run();
void* _np_event_http_run();
void* _np_event_out_run();
void* _np_event_io_run();
double np_event_sleep(double time);
void _np_suspend_event_loop_in();
void _np_resume_event_loop_in();
void _np_suspend_event_loop_out();
void _np_resume_event_loop_out();
void _np_suspend_event_loop_io();
void _np_resume_event_loop_io();
void _np_suspend_event_loop_http();
void _np_resume_event_loop_http();

#ifdef __cplusplus
}
#endif


#endif /* NP_EVENT_H_ */
