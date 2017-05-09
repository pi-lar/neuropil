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

void _np_events_async(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents);
void _np_events_read(np_jobargs_t* args);

void _np_suspend_event_loop();
void _np_resume_event_loop();


#ifdef __cplusplus
}
#endif


#endif /* NP_EVENT_H_ */
