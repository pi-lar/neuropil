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
#include "np_constants.h"

struct ev_loop * loop_io = NULL;
struct ev_loop * loop_out = NULL;
struct ev_loop * loop_in = NULL;
np_bool initiated = FALSE;

void np_event_init() {
	_LOCK_MODULE(np_event_t) {
		if (initiated == FALSE) {
			initiated = TRUE;

			loop_io = ev_loop_new(EVFLAG_AUTO | EVFLAG_FORKCHECK);
			if (loop_io == FALSE) {
				fprintf(stderr, "ERROR: cannot init IO event loop");
				exit(EXIT_FAILURE);
			}
			
			loop_out = ev_loop_new(EVFLAG_AUTO | EVFLAG_FORKCHECK);
			if (loop_out == FALSE) {
				fprintf(stderr, "ERROR: cannot init OUT event loop");
				exit(EXIT_FAILURE);
			}

			//loop_in = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
			loop_in = ev_loop_new(EVFLAG_AUTO | EVFLAG_FORKCHECK);
			if (loop_in == FALSE) {
				fprintf(stderr, "ERROR: cannot init IN event loop");
				exit(EXIT_FAILURE);
			}
		}
	}
}

struct ev_loop * _np_event_get_loop_io() {
	np_event_init();
	return loop_io;
}

struct ev_loop * _np_event_get_loop_in() {
	np_event_init();
	return loop_in;
}

struct ev_loop * _np_event_get_loop_out() {
	np_event_init();
	return loop_out;
}




// the optimal libev run interval remains to be seen
// if set too low, base cpu usage increases on no load
static int         __suspended_libev_loop_io = 0;
static ev_async    __libev_async_watcher_io;
static int         __suspended_libev_loop_in = 0;
static ev_async    __libev_async_watcher_in;
static int         __suspended_libev_loop_out = 0;
static ev_async    __libev_async_watcher_out;


void _np_events_async_io(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents)
{
	log_msg(LOG_TRACE, "start: void _np_events_async(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents){");

	static int suspend_loop = 0;

	_LOCK_MODULE(np_event_t) {
		suspend_loop = __suspended_libev_loop_io;
	}

	while (0 < suspend_loop)
	{
		_np_job_yield(NP_EVENT_IO_CHECK_PERIOD_SEC);
		//np_time_sleep(NP_EVENT_IO_CHECK_PERIOD_SEC);

		_LOCK_MODULE(np_event_t) {
			suspend_loop = __suspended_libev_loop_io;
		}
	}
}

void _np_events_async_in(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents)
{
	log_msg(LOG_TRACE, "start: void _np_events_async(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents){");

	static int suspend_loop = 0;

	_LOCK_MODULE(np_event_t) {
		suspend_loop = __suspended_libev_loop_in;
	}

	while (0 < suspend_loop)
	{
		_np_job_yield(NP_EVENT_IO_CHECK_PERIOD_SEC);
		//np_time_sleep(NP_EVENT_IO_CHECK_PERIOD_SEC);

		_LOCK_MODULE(np_event_t) {
			suspend_loop = __suspended_libev_loop_in;
		}
	}
}

void _np_events_async_out(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents)
{
	log_msg(LOG_TRACE, "start: void _np_events_async(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents){");

	static int suspend_loop = 0;

	_LOCK_MODULE(np_event_t) {
		suspend_loop = __suspended_libev_loop_out;
	}

	while (0 < suspend_loop)
	{
		_np_job_yield(NP_EVENT_IO_CHECK_PERIOD_SEC);
		//np_time_sleep(NP_EVENT_IO_CHECK_PERIOD_SEC);

		_LOCK_MODULE(np_event_t) {
			suspend_loop = __suspended_libev_loop_out;
		}
	}
}

// TODO: move to glia
void _np_event_cleanup_msgpart_cache(NP_UNUSED np_jobargs_t* args)
{
	np_sll_t(np_message_ptr,to_del);
	sll_init(np_message_ptr,to_del);

	_LOCK_MODULE(np_message_part_cache_t)
	{
		np_state_t* state = _np_state();
		np_tree_elem_t* tmp = NULL;

		RB_FOREACH(tmp, np_tree_s, state->msg_part_cache)
		{
			np_message_t* msg = tmp->val.value.v;
			// np_tryref_obj(np_message_t,msg, msgExists);

			if(TRUE == _np_message_is_expired(msg)) {
				sll_append(np_message_ptr,to_del,msg);
			}
		}

		sll_iterator(np_message_ptr) iter = sll_first(to_del);
		while (NULL != iter)
		{
			np_tree_del_str(state->msg_part_cache,iter->val->uuid);
			np_unref_obj(np_message_t, iter->val, ref_msgpartcache);
			sll_next(iter);
		}
	}
	sll_free(np_message_ptr, to_del);

	// np_unref_list(np_message_ptr, to_del, ref_msgpartcache); // cleanup

}

// TODO: move to glia
void _np_event_rejoin_if_necessary(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_event_rejoin_if_necessary(NP_UNUSED np_jobargs_t* args){");

	_np_route_rejoin_bootstrap(FALSE);
}

/**
** _np_events_read
** schedule the libev event loop one time and reschedule again
**/
void _np_events_read_out(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_events_read(NP_UNUSED np_jobargs_t* args){");

	static int suspend_loop = 0;

	EV_P = _np_event_get_loop_out();
	_LOCK_MODULE(np_event_t) {
		suspend_loop = __suspended_libev_loop_out;
	}
}

/**
** _np_events_read
** schedule the libev event loop one time and reschedule again
**/
void _np_events_read_io(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_events_read(NP_UNUSED np_jobargs_t* args){");

	static int suspend_loop = 0;	

	EV_P = _np_event_get_loop_io();
	_LOCK_MODULE(np_event_t) {
		suspend_loop = __suspended_libev_loop_io;
	}

	if (0 < suspend_loop) {
		ev_run(EV_A_(EVRUN_ONCE | EVRUN_NOWAIT));
	}
}

/**
** _np_events_read
** schedule the libev event loop one time and reschedule again
**/
void _np_events_read_in(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_events_read(NP_UNUSED np_jobargs_t* args){");

	static int suspend_loop = 0;

	EV_P = _np_event_get_loop_in();
	_LOCK_MODULE(np_event_t) {
		suspend_loop = __suspended_libev_loop_in;
	}

	if (0 < suspend_loop) {
		ev_run(EV_A_(EVRUN_ONCE | EVRUN_NOWAIT));
	}
}

void* _np_event_in_run() {

	while (_np_threads_is_threadding_initiated() == FALSE) {
		np_time_sleep(0.01);
	}

	EV_P = _np_event_get_loop_in();

	ev_async_init(&__libev_async_watcher_in, _np_events_async_in);
	ev_async_start(EV_A_ &__libev_async_watcher_in);

	ev_set_io_collect_interval(EV_A_ NP_EVENT_IO_CHECK_PERIOD_SEC);
	ev_set_timeout_collect_interval(EV_A_ NP_EVENT_IO_CHECK_PERIOD_SEC);

	ev_run(EV_A_(0));
}

void* _np_event_io_run() {

	while (_np_threads_is_threadding_initiated() == FALSE) {
		np_time_sleep(0.01);
	}

	EV_P = _np_event_get_loop_io();

	ev_async_init(&__libev_async_watcher_io, _np_events_async_io);
	ev_async_start(EV_A_ &__libev_async_watcher_io);

	ev_set_io_collect_interval(EV_A_ NP_EVENT_IO_CHECK_PERIOD_SEC);
	ev_set_timeout_collect_interval(EV_A_ NP_EVENT_IO_CHECK_PERIOD_SEC);

	ev_run(EV_A_(0));
}

void* _np_event_out_run() {

	while (_np_threads_is_threadding_initiated() == FALSE) {
		np_time_sleep(0.01);
	}

	EV_P = _np_event_get_loop_out();

	ev_async_init(&__libev_async_watcher_out, _np_events_async_out);
	ev_async_start(EV_A_ &__libev_async_watcher_out);

	ev_set_io_collect_interval(EV_A_ NP_EVENT_IO_CHECK_PERIOD_SEC);
	ev_set_timeout_collect_interval(EV_A_ NP_EVENT_IO_CHECK_PERIOD_SEC);

	ev_run(EV_A_(0));
}

/**
 * Call this fucntion only in an event (as in async callback)
 */
void _np_suspend_event_loop_io()
{
	log_msg(LOG_TRACE, "start: void _np_suspend_event_loop(){");
	
	_LOCK_MODULE(np_event_t) {
		np_event_init();
		__suspended_libev_loop_io++;
	}
	ev_async_send(EV_DEFAULT_ &__libev_async_watcher_io);
}

void _np_resume_event_loop_io()
{
	log_msg(LOG_TRACE, "start: void _np_resume_event_loop(){");
	_LOCK_MODULE(np_event_t) {
		__suspended_libev_loop_io--;
	}
}

void _np_suspend_event_loop_in()
{
	log_msg(LOG_TRACE, "start: void _np_suspend_event_loop(){");
	_LOCK_MODULE(np_event_t) {
		np_event_init();
		__suspended_libev_loop_in++;
	}
	ev_async_send(EV_DEFAULT_ &__libev_async_watcher_in);
}

void _np_resume_event_loop_in()
{
	log_msg(LOG_TRACE, "start: void _np_resume_event_loop(){");
	_LOCK_MODULE(np_event_t) {
		__suspended_libev_loop_in--;
	}
}


void _np_suspend_event_loop_out()
{
	log_msg(LOG_TRACE, "start: void _np_suspend_event_loop(){");
	_LOCK_MODULE(np_event_t) {
		np_event_init();
		__suspended_libev_loop_out++;
	}
	ev_async_send(EV_DEFAULT_ &__libev_async_watcher_out);
}

void _np_resume_event_loop_out()
{
	log_msg(LOG_TRACE, "start: void _np_resume_event_loop(){");
	_LOCK_MODULE(np_event_t) {
		__suspended_libev_loop_out--;
	}
}

double np_event_sleep(double time) {	
	ev_sleep(time);
	return time;
}
