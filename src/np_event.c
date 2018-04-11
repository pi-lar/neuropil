//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netdb.h>
#include <inttypes.h>

#include "event/ev.h"
#include "tree/tree.h"

#include "np_log.h"
#include "np_jobqueue.h"

#include "np_key.h"
#include "np_keycache.h"
#include "np_event.h"
#include "np_threads.h"
#include "neuropil.h"
#include "np_types.h"
#include "np_list.h"
#include "np_route.h"
#include "np_tree.h"
#include "np_msgproperty.h"
#include "np_util.h"
#include "np_message.h"
#include "np_messagepart.h"
#include "np_memory.h"
#include "np_memory_v2.h"
#include "np_settings.h"
#include "np_constants.h"


#define __NP_EVENT_EVLOOP_STRUCTS(LOOPNAME)													\
	struct ev_loop * __loop_##LOOPNAME;														\
	ev_idle __loop_##LOOPNAME##_idle_watcher;												\
	np_mutex_t __loop_##LOOPNAME##_suspend;													\
	TSP(double, __loop_##LOOPNAME##_suspend_wait);											\
	TSP(ev_async, __libev_async_watcher_##LOOPNAME);


#define __NP_EVENT_EVLOOP_INIT(LOOPNAME)																		 \
	TSP_INITD(np_module(events)->__loop_##LOOPNAME##_suspend_wait, 0);											 \
	TSP_INIT(np_module(events)->__libev_async_watcher_##LOOPNAME);												 \
	_np_threads_mutex_init(context, &np_module(events)->__loop_##LOOPNAME##_suspend, "loop_"#LOOPNAME"_suspend");\
	np_module(events)->__loop_##LOOPNAME = ev_loop_new(EVFLAG_AUTO | EVFLAG_FORKCHECK);							 \
	if (np_module(events)->__loop_##LOOPNAME == FALSE) {											 			 \
		fprintf(stderr, "ERROR: cannot init "#LOOPNAME" event loop");								 			 \
		exit(EXIT_FAILURE);														   					 			 \
	}																			   					 			 \
	ev_set_userdata (np_module(events)->__loop_##LOOPNAME, context);											 \
	ev_set_io_collect_interval(np_module(events)->__loop_##LOOPNAME, NP_EVENT_IO_CHECK_PERIOD_SEC);				 \
	ev_set_timeout_collect_interval(np_module(events)->__loop_##LOOPNAME, NP_EVENT_IO_CHECK_PERIOD_SEC);		 \
	ev_async_init(&np_module(events)->__libev_async_watcher_##LOOPNAME, _np_events_async_break);				 \
	ev_async_start(np_module(events)->__loop_##LOOPNAME, &np_module(events)->__libev_async_watcher_##LOOPNAME);	 \
    /*ev_idle_init(&np_module(events)->__loop_##LOOPNAME##_idle_watcher, _np_events_idle); 						 \
    ev_idle_start(np_module(events)->__loop_##LOOPNAME, &np_module(events)->__loop_##LOOPNAME##_idle_watcher);*/ \
	ev_verify(np_module(events)->__loop_##LOOPNAME);															 \
																												 

#define __NP_EVENT_LOOP_FNs(LOOPNAME)																					\
	void _np_events_read_##LOOPNAME (np_state_t* context, np_jobargs_t* args)																\
	{																													\
																								\
		_LOCK_ACCESS(&np_module(events)->__loop_##LOOPNAME##_suspend) {													\
			EV_P = _np_event_get_loop_##LOOPNAME(context);																\
			TSP_GET(double, np_module(events)->__loop_##LOOPNAME##_suspend_wait, onhold);								\
			if (onhold == 0)																							\
				ev_run(EV_A_(EVRUN_ONCE | EVRUN_NOWAIT));																\
		}																												\
	}																													\
	void* _np_event_##LOOPNAME##_run(void* thread_pt) {																	\
		np_ctx_full(thread_pt);																							\
		_np_threads_set_self(thread_pt);																				\
		while (1) {																										\
			_LOCK_ACCESS(&np_module(events)->__loop_##LOOPNAME##_suspend) {												\
				TSP_GET(double, np_module(events)->__loop_##LOOPNAME##_suspend_wait, onhold);							\
				if (onhold == 0)																						\
				{																										\
					EV_P = _np_event_get_loop_##LOOPNAME(context);														\
					ev_run( EV_A_(0) );																					\
				}																										\
			}																											\
			np_time_sleep(NP_SLEEP_MIN);																				\
		}																												\
	}																													\
	void _np_event_suspend_loop_##LOOPNAME(np_state_t* context)															\
	{																													\
		TSP_SCOPE(np_module(events)->__loop_##LOOPNAME##_suspend_wait) {												\
			np_module(events)->__loop_##LOOPNAME##_suspend_wait++;														\
		}																												\
		TSP_SCOPE(np_module(events)->__libev_async_watcher_##LOOPNAME) {												\
			ev_async_send(_np_event_get_loop_##LOOPNAME(context), &np_module(events)->__libev_async_watcher_##LOOPNAME);\
		}																												\
		_LOCK_ACCESS(&np_module(events)->__loop_##LOOPNAME##_suspend) {/* wait for loop to break*/; } 					\
	}																													\
	void _np_event_resume_loop_##LOOPNAME(np_state_t *context)															\
	{																													\
		TSP_SCOPE( np_module(events)->__loop_##LOOPNAME##_suspend_wait) {												\
			np_module(events)->__loop_##LOOPNAME##_suspend_wait--;														\
		}																												\
	}																													\
	struct ev_loop * _np_event_get_loop_##LOOPNAME(np_state_t *context) {												\
		return (np_module(events)->__loop_##LOOPNAME);																	\
	}																								   					\

np_module_struct(events) {
	np_state_t* context;	
	__NP_EVENT_EVLOOP_STRUCTS(io);
	__NP_EVENT_EVLOOP_STRUCTS(in);
	__NP_EVENT_EVLOOP_STRUCTS(out);
	__NP_EVENT_EVLOOP_STRUCTS(http);
};

void _np_events_async_break(struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents)
{
	ev_break(loop, EVBREAK_ALL);
}

void _np_events_idle(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents)
{
	np_time_sleep(NP_EVENT_IO_CHECK_PERIOD_SEC);
}

__NP_EVENT_LOOP_FNs(in);
__NP_EVENT_LOOP_FNs(out);
__NP_EVENT_LOOP_FNs(io);
__NP_EVENT_LOOP_FNs(http);

void np_event_init(np_state_t* context) {
	if (!np_module_initiated(events)) {
		np_module_malloc(events);
		__NP_EVENT_EVLOOP_INIT(in);
		__NP_EVENT_EVLOOP_INIT(out);
		__NP_EVENT_EVLOOP_INIT(io);
		__NP_EVENT_EVLOOP_INIT(http);
	}
}

// TODO: move to glia
void _np_event_cleanup_msgpart_cache(np_state_t* context, np_jobargs_t* args)
{
	
	np_sll_t(np_message_ptr, to_del);
	sll_init(np_message_ptr, to_del);

	_LOCK_MODULE(np_message_part_cache_t)
	{
		np_state_t* state = context;
		np_tree_elem_t* tmp = NULL;

		RB_FOREACH(tmp, np_tree_s, state->msg_part_cache)
		{
			np_message_t* msg = tmp->val.value.v;
			// np_tryref_obj(np_message_t,msg, msgExists);

			if (TRUE == _np_message_is_expired(msg)) {
				sll_append(np_message_ptr, to_del, msg);
			}
		}

		sll_iterator(np_message_ptr) iter = sll_first(to_del);
		while (NULL != iter)
		{
			log_msg(LOG_INFO,
				"removing (left-over) message part for uuid: %s", iter->val->uuid);
			np_tree_del_str(state->msg_part_cache, iter->val->uuid);
			np_unref_obj(np_message_t, iter->val, ref_msgpartcache);
			sll_next(iter);
		}
	}
	sll_free(np_message_ptr, to_del);

	// np_key_unref_list(np_message_ptr, to_del, ref_msgpartcache); // cleanup
}

// TODO: move to glia
void _np_event_rejoin_if_necessary(np_state_t* context, np_jobargs_t* args)
{
	

	_np_route_rejoin_bootstrap(context, FALSE);
}
