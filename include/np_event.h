//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef _NP_EVENT_H_
#define _NP_EVENT_H_

#include "event/ev.h"
#include "neuropil.h"
#include "np_types.h"

#include "np_dhkey.h"
#include "util/np_event.h"

#ifdef __cplusplus
extern "C" {
#endif


#define NP_EVENT_EVLOOP_PROTOTYPE(LOOPNAME)								        \
NP_API_INTERN															        \
struct ev_loop * _np_event_get_loop_##LOOPNAME(np_state_t *context);	        \
NP_API_INTERN															        \
bool _np_events_read_##LOOPNAME(np_state_t* context, np_util_event_t event);    \
NP_API_INTERN															        \
void _np_event_##LOOPNAME##_run(np_state_t* context, np_thread_t* thread_ptr);	\
NP_API_INTERN															        \
void _np_event_suspend_loop_##LOOPNAME(np_state_t *context);			        \
NP_API_INTERN															        \
void _np_event_reconfigure_loop_##LOOPNAME(np_state_t *context); 		        \
NP_API_INTERN															        \
void _np_event_resume_loop_##LOOPNAME(np_state_t *context);                     \
NP_API_INTERN                                                                   \
void _np_event_invoke_##LOOPNAME(np_state_t *context);                          

NP_EVENT_EVLOOP_PROTOTYPE(in)
NP_EVENT_EVLOOP_PROTOTYPE(out)
NP_EVENT_EVLOOP_PROTOTYPE(http)
NP_EVENT_EVLOOP_PROTOTYPE(file)


NP_API_INTERN		
bool _np_event_init(np_state_t *context);

NP_API_INTERN		
void _np_event_destroy(np_state_t *context);


#ifdef __cplusplus
}
#endif


#endif /* NP_EVENT_H_ */
