/*
 * np_event.h
 *
 *  Created on: 09.05.2017
 *      Author: sklampt
 */

#ifndef NP_EVENT_H_
#define NP_EVENT_H_

#include "event/ev.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ev_loop * _np_event_get_loop_io();
struct ev_loop * _np_event_get_loop_in();
struct ev_loop * _np_event_get_loop_out();

void _np_events_read_in(NP_UNUSED np_jobargs_t* args);
void _np_events_read_out(NP_UNUSED np_jobargs_t* args);
void _np_events_read_io(NP_UNUSED np_jobargs_t* args);
void _np_event_rejoin_if_necessary(NP_UNUSED np_jobargs_t* args);
void _np_event_cleanup_msgpart_cache(NP_UNUSED np_jobargs_t* args);
void* _np_event_in_run();
void* _np_event_out_run();
void* _np_event_io_run();
double np_event_sleep(double time);
#ifdef __cplusplus
}
#endif


#endif /* NP_EVENT_H_ */
