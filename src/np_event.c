/*
 * np_event.c
 *
 *  Created on: 09.05.2017
 *      Author: sklampt
 */

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
#include "np_message.h"
#include "np_messagepart.h"
#include "np_memory.h"
#include "np_settings.h"


static np_bool __exit_libev_loop = FALSE;

// the optimal libev run interval remains to be seen
// if set too low, base cpu usage increases on no load
// static uint8_t __suspended_libev_loop = 0;
static int         __suspended_libev_loop = 0;
static double      __libev_interval = 0.0031415;
static ev_async    __libev_async_watcher;

// static ev_periodic __libev_periodic_watcher;
// static ev_idle __libev_idle_watcher;
// static ev_check __libev_check_watcher;


void _np_events_async(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents)
{
    log_msg(LOG_TRACE, "start: void _np_events_async(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents){");
	log_debug_msg(LOG_DEBUG, ".start._np_events_async");

	static int suspend_loop = 0;

	_LOCK_MODULE(np_event_t){
		suspend_loop = __suspended_libev_loop;
	}

	while (0 < suspend_loop)
	{
		_np_job_yield(__libev_interval);

		_LOCK_MODULE(np_event_t) {
			suspend_loop = __suspended_libev_loop;
		}
	}
}


void _np_event_cleanup_msgpart_cache(NP_UNUSED np_jobargs_t* args)
{
	np_sll_t(np_message_t,to_del);
	sll_init(np_message_t,to_del);

	_LOCK_MODULE(np_message_part_cache_t)
	{
		np_state_t* state = _np_state();
		np_tree_elem_t* tmp = NULL;

		RB_FOREACH(tmp, np_tree_s, state->msg_part_cache)
		{
			np_message_t* msg = tmp->val.value.v;
			// np_tryref_obj(np_message_t,msg, msgExists);

			if(TRUE == _np_message_is_expired(msg)) {
				sll_append(np_message_t,to_del,msg);
			}
		}

		sll_iterator(np_message_t) iter = sll_first(to_del);
		while (NULL != iter)
		{
			np_tree_del_str(state->msg_part_cache,iter->val->uuid);
			sll_next(iter);
		}
	}

	np_unref_list(np_message_t, to_del); // cleanup

    np_job_submit_event(MISC_MSGPARTCACHE_CLEANUP_INTERVAL_SEC, _np_event_cleanup_msgpart_cache);
}

void _np_event_rejoin_if_necessary(NP_UNUSED np_jobargs_t* args)
{
    log_msg(LOG_TRACE, "start: void _np_event_rejoin_if_necessary(NP_UNUSED np_jobargs_t* args){");

    _np_route_rejoin_bootstrap(FALSE);

	// Reschedule myself
    np_job_submit_event(MISC_REJOIN_BOOTSTRAP_INTERVAL_SEC, _np_event_rejoin_if_necessary);
}

/**
 ** _np_events_read
 ** schedule the libev event loop one time and reschedule again
 **/
void _np_events_read(NP_UNUSED np_jobargs_t* args)
{
    log_msg(LOG_TRACE, "start: void _np_events_read(NP_UNUSED np_jobargs_t* args){");
	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);

	// TODO: evaluate if 1 ore more threads are started and init appropriately
	np_bool isMultiThreaded = FALSE;

	if(TRUE == isMultiThreaded) {

		static np_bool async_setup_done = FALSE;
		if (FALSE == async_setup_done)
		{
			// TODO: move it outside of this function
			ev_async_init(&__libev_async_watcher, _np_events_async);
			async_setup_done = TRUE;
		}

		ev_set_io_collect_interval (EV_A_ __libev_interval);
		ev_set_timeout_collect_interval (EV_A_ __libev_interval);

		ev_run(EV_A_ (0));
		// never returns
	} else {

		_LOCK_MODULE(np_event_t) {
			if (0 == __suspended_libev_loop) {
				ev_run(EV_A_ (EVRUN_ONCE | EVRUN_NOWAIT));
			}
		}
	}

	if (TRUE == __exit_libev_loop) return;

	np_job_submit_event(__libev_interval, _np_events_read);
}
/**
 * Call this fucntion only in an event (as in async callback)
 */
void _np_suspend_event_loop()
{
    log_msg(LOG_TRACE, "start: void _np_suspend_event_loop(){");
	_LOCK_MODULE(np_event_t){
		__suspended_libev_loop++;
	}
    ev_async_send (EV_DEFAULT_ &__libev_async_watcher);
}

void _np_resume_event_loop()
{
    log_msg(LOG_TRACE, "start: void _np_resume_event_loop(){");
	_LOCK_MODULE(np_event_t) {
		__suspended_libev_loop--;
	}
}
