//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef NP_EVENT_H_
#define NP_EVENT_H_

#include "event/ev.h"

#ifdef __cplusplus
extern "C" {
#endif

	
#define NP_EVENT_EVLOOP_PROTOTYPE(LOOPNAME)								\
NP_API_INTERN															\
struct ev_loop * _np_event_get_loop_##LOOPNAME(np_state_t *context);	\
NP_API_INTERN															\
void _np_events_read_##LOOPNAME(np_state_t* context, np_jobargs_t* args);\
NP_API_INTERN															\
void* _np_event_##LOOPNAME##_run(void* np_thread_ptr);					\
NP_API_INTERN															\
void _np_event_suspend_loop_##LOOPNAME(np_state_t *context);			\
NP_API_INTERN															\
void _np_event_resume_loop_##LOOPNAME(np_state_t *context);						

NP_EVENT_EVLOOP_PROTOTYPE(in)
NP_EVENT_EVLOOP_PROTOTYPE(out)
NP_EVENT_EVLOOP_PROTOTYPE(io)
NP_EVENT_EVLOOP_PROTOTYPE(http)

NP_API_INTERN		
void _np_event_cleanup_msgpart_cache(np_state_t* context, np_jobargs_t* args);
NP_API_INTERN		
bool _np_event_init(np_state_t *context);

#ifdef __cplusplus
}
#endif


#endif /* NP_EVENT_H_ */
