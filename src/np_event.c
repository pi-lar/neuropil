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
#include "np_settings.h"
#include "np_constants.h"

np_mutex_t loop_http_suspend;
np_mutex_t loop_io_suspend;
np_mutex_t loop_out_suspend; 
np_mutex_t loop_in_suspend;

struct ev_loop * loop_http = NULL;
struct ev_loop * loop_io = NULL;
struct ev_loop * loop_out = NULL;
struct ev_loop * loop_in = NULL;

TSP(double, loop_http_suspend_wait);
TSP(double, loop_io_suspend_wait);
TSP(double, loop_out_suspend_wait);
TSP(double, loop_in_suspend_wait);

TSP(static ev_async, __libev_async_watcher_http);
TSP(static ev_async, __libev_async_watcher_io);
TSP(static ev_async, __libev_async_watcher_out);
TSP(static ev_async, __libev_async_watcher_in);

void _np_events_async_break(struct ev_loop *loop, NP_UNUSED ev_async *watcher, NP_UNUSED int revents)
{
	ev_break(loop, EVBREAK_ALL);
}

#define LOOP_INIT(LOOPNAME)																		\
	TSP_INITD(double, loop_##LOOPNAME##_suspend_wait, 0);										\
	TSP_INIT(static ev_async, __libev_async_watcher_##LOOPNAME);								\
	_np_threads_mutex_init(&loop_##LOOPNAME##_suspend, "loop_"#LOOPNAME"_suspend");				\
	loop_##LOOPNAME = ev_loop_new(EVFLAG_AUTO | EVFLAG_FORKCHECK);								\
																								\
	if (loop_##LOOPNAME == FALSE) {																\
		fprintf(stderr, "ERROR: cannot init "#LOOPNAME" event loop");							\
		exit(EXIT_FAILURE);														   				\
	}																			   				\
	ev_set_io_collect_interval(loop_##LOOPNAME, NP_EVENT_IO_CHECK_PERIOD_SEC);					\
	ev_set_timeout_collect_interval(loop_##LOOPNAME, NP_EVENT_IO_CHECK_PERIOD_SEC);				\
	ev_verify(loop_##LOOPNAME);																	\
																				   				\
	_LOCK_ACCESS_W_PREFIX(a,&__libev_async_watcher_##LOOPNAME##_mutex) {						\
		ev_async_init(&__libev_async_watcher_##LOOPNAME, _np_events_async_break);				\
		ev_async_start(loop_##LOOPNAME, &__libev_async_watcher_##LOOPNAME);						\
	}																							\
			

void np_event_init() {	
	if (loop_io == NULL)
	{
		LOOP_INIT(io);
		LOOP_INIT(in);
		LOOP_INIT(http);
		LOOP_INIT(out);
	}
}

struct ev_loop * _np_event_get_loop_http() {
	np_event_init();
	return loop_http;
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

// TODO: move to glia
void _np_event_cleanup_msgpart_cache(NP_UNUSED np_jobargs_t* args)
{
	np_sll_t(np_message_ptr, to_del);
	sll_init(np_message_ptr, to_del);

	_LOCK_MODULE(np_message_part_cache_t)
	{
		np_state_t* state = _np_state();
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
	log_debug_msg(LOG_EVENT | LOG_DEBUG, " start %s", __func__);

	np_event_init();

	EV_P = _np_event_get_loop_out();

	while (1) {
		TSP_GET(double, loop_out_suspend_wait, onhold)
			if (onhold > 0)
				np_time_sleep(0.0001);
			else
				break;
	}

	_TRYLOCK_ACCESS(&loop_out_suspend) {
		TSP_GET(double, loop_out_suspend_wait, onhold);
		if (onhold == 0)
			ev_run(EV_A_(EVRUN_ONCE | EVRUN_NOWAIT));
	}
}

/**
** _np_events_read
** schedule the libev event loop one time and reschedule again
**/
void _np_events_read_io(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_events_read(NP_UNUSED np_jobargs_t* args){");
	log_debug_msg(LOG_EVENT | LOG_DEBUG, " start %s", __func__);
	np_event_init();

	EV_P = _np_event_get_loop_io();

	while (1) {
		TSP_GET(double, loop_io_suspend_wait, onhold)
			if (onhold > 0)
				np_time_sleep(0.0001);
			else
				break;
	}
	_TRYLOCK_ACCESS(&loop_io_suspend) {
		TSP_GET(double, loop_io_suspend_wait, onhold);
		if (onhold == 0)
			ev_run(EV_A_(EVRUN_ONCE | EVRUN_NOWAIT));
	}
}


void _np_events_read_http(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_events_read(NP_UNUSED np_jobargs_t* args){");
	log_debug_msg(LOG_EVENT | LOG_DEBUG, " start %s", __func__);
	np_event_init();

	EV_P = _np_event_get_loop_http();

	while (1) {
		TSP_GET(double, loop_http_suspend_wait, onhold)
			if (onhold > 0)
				np_time_sleep(0.0001);
			else
				break;
	}

	_TRYLOCK_ACCESS(&loop_http_suspend) {
		TSP_GET(double, loop_http_suspend_wait, onhold);
		if (onhold == 0)
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
	log_debug_msg(LOG_EVENT | LOG_DEBUG, " start %s", __func__);
	np_event_init();

	EV_P = _np_event_get_loop_in();

	while (1) {
		TSP_GET(double, loop_in_suspend_wait, onhold)
			if (onhold > 0)
				np_time_sleep(0.0001);
			else
				break;
	}

	_TRYLOCK_ACCESS(&loop_in_suspend) {
		TSP_GET(double, loop_in_suspend_wait, onhold);
		if (onhold == 0)
			ev_run(EV_A_(EVRUN_ONCE | EVRUN_NOWAIT));
	}
}

void* _np_event_in_run(void* np_thread_ptr) {
	log_debug_msg(LOG_EVENT | LOG_DEBUG, " start %s", __func__);	
	_np_threads_set_self(np_thread_ptr);

	EV_P = _np_event_get_loop_in();

	while (1) {
		while (1) {
			TSP_GET(double, loop_in_suspend_wait, onhold)
				if (onhold > 0)
					np_time_sleep(0.0001);
				else
					break;
		}

		_LOCK_ACCESS(&loop_in_suspend) {
			TSP_GET(double, loop_in_suspend_wait, onhold);
			if (onhold == 0)

			ev_run(EV_A_(0));
		}
	}
}

void* _np_event_io_run(void* np_thread_ptr) {
	log_debug_msg(LOG_EVENT | LOG_DEBUG, " start %s", __func__);
	_np_threads_set_self(np_thread_ptr);

	EV_P = _np_event_get_loop_io();

	while (1) {

		while (1) {
			TSP_GET(double, loop_io_suspend_wait, onhold)
				if (onhold > 0)
					np_time_sleep(0.0001);
				else
					break;
		}	

		_LOCK_ACCESS(&loop_io_suspend) {
			TSP_GET(double, loop_io_suspend_wait, onhold);
			if (onhold == 0)
			ev_run(EV_A_(0));
		}
	}
}

void* _np_event_out_run(void* np_thread_ptr) {
	log_debug_msg(LOG_EVENT | LOG_DEBUG, " start %s", __func__);
	_np_threads_set_self(np_thread_ptr);

	EV_P = _np_event_get_loop_out();

	while (1) {

		while (1) {
			TSP_GET(double, loop_out_suspend_wait, onhold)
				if (onhold > 0)
					np_time_sleep(0.0001);
				else
					break;
		}

		_LOCK_ACCESS(&loop_out_suspend) {
			TSP_GET(double, loop_out_suspend_wait, onhold);
			if (onhold == 0) 
				ev_run(EV_A_(0));
		}
	}
}

void* _np_event_http_run(void* np_thread_ptr) {
	log_debug_msg(LOG_EVENT | LOG_DEBUG, " start %s", __func__);
	_np_threads_set_self(np_thread_ptr);

	EV_P = _np_event_get_loop_http();

	_LOCK_ACCESS(&__libev_async_watcher_http_mutex) {
		ev_async_start(EV_A_ &__libev_async_watcher_http);
	}
	ev_set_io_collect_interval(EV_A_ NP_EVENT_IO_CHECK_PERIOD_SEC);
	ev_set_timeout_collect_interval(EV_A_ NP_EVENT_IO_CHECK_PERIOD_SEC);

	while (1) {

		while (1) {
			TSP_GET(double, loop_http_suspend_wait, onhold);
			if (onhold > 0)
				np_time_sleep(0.0001);
			else
				break;
		}
		_LOCK_ACCESS(&loop_http_suspend) {
			TSP_GET(double, loop_http_suspend_wait, onhold);
			if (onhold == 0){
				ev_run(EV_A_(0));
			}
		}
	}
}

/**
 * Call this fucntion only in an event (as in async callback)
 */
void _np_suspend_event_loop_io()
{
	log_msg(LOG_TRACE, "start: void _np_suspend_event_loop(){");
	np_event_init();

	TSP_SCOPE(double, loop_io_suspend_wait)
		loop_io_suspend_wait++;

	TSP_SCOPE(static ev_async, __libev_async_watcher_io)
		ev_async_send(_np_event_get_loop_io(), &__libev_async_watcher_io);

	_LOCK_ACCESS(&loop_io_suspend) {/*wait for loop to break*/; }
}

void _np_resume_event_loop_io()
{
	log_msg(LOG_TRACE, "start: void _np_resume_event_loop(){");
	TSP_SCOPE(double, loop_io_suspend_wait)
		loop_io_suspend_wait--;

}

void _np_suspend_event_loop_http()
{
	log_msg(LOG_TRACE, "start: void _np_suspend_event_loop(){");
	np_event_init();

	TSP_SCOPE(double, loop_http_suspend_wait)
		loop_http_suspend_wait++;

	TSP_SCOPE(static ev_async, __libev_async_watcher_http)
		ev_async_send(_np_event_get_loop_http(), &__libev_async_watcher_http);

	_LOCK_ACCESS(&loop_http_suspend) {/*wait for loop to break*/; }
}

void _np_resume_event_loop_http()
{
	log_msg(LOG_TRACE, "start: void _np_resume_event_loop(){");
	TSP_SCOPE(double, loop_http_suspend_wait)
		loop_http_suspend_wait--;
}

void _np_suspend_event_loop_in()
{
	log_msg(LOG_TRACE, "start: void _np_suspend_event_loop(){");
	np_event_init();

	TSP_SCOPE(double, loop_in_suspend_wait)
		loop_in_suspend_wait++;

	TSP_SCOPE(static ev_async, __libev_async_watcher_in)
		ev_async_send(_np_event_get_loop_in(), &__libev_async_watcher_in);

	_LOCK_ACCESS(&loop_in_suspend) {/*wait for loop to break*/; }
}

void _np_resume_event_loop_in()
{
	log_msg(LOG_TRACE, "start: void _np_resume_event_loop(){");
	TSP_SCOPE(double, loop_in_suspend_wait)
		loop_in_suspend_wait--;
}

void _np_suspend_event_loop_out()
{
	log_msg(LOG_TRACE, "start: void _np_suspend_event_loop(){");
	np_event_init();

	TSP_SCOPE(double, loop_out_suspend_wait)
		loop_out_suspend_wait++;

	TSP_SCOPE(static ev_async, __libev_async_watcher_out)
		ev_async_send(_np_event_get_loop_out(), &__libev_async_watcher_out);

	_LOCK_ACCESS(&loop_out_suspend) {/*wait for loop to break*/; }
}

void _np_resume_event_loop_out()
{
	log_msg(LOG_TRACE, "start: void _np_resume_event_loop(){");

	TSP_SCOPE(double, loop_out_suspend_wait)
		loop_out_suspend_wait--;
}


double np_event_sleep(double time) {
	ev_sleep(time);
	return time;
}