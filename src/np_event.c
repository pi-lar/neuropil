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

#include "np_log.h"
#include "np_jobqueue.h"

#include "np_event.h"
#include "neuropil.h"
#include "np_list.h"
#include "np_route.h"

static np_bool __exit_libev_loop = FALSE;

static pthread_mutex_t __libev_mutex = PTHREAD_MUTEX_INITIALIZER;
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
	log_msg(LOG_DEBUG, ".start._np_events_async");

	static int suspend_loop = 0;

	pthread_mutex_lock(&__libev_mutex);
	suspend_loop = __suspended_libev_loop;
	pthread_mutex_unlock(&__libev_mutex);

	while (0 < suspend_loop)
	{
		_np_job_yield(__libev_interval);

		pthread_mutex_lock(&__libev_mutex);
		suspend_loop = __suspended_libev_loop;
		pthread_mutex_unlock(&__libev_mutex);
	}

	log_msg(LOG_TRACE, ".end  ._np_events_async");
}

void _np_event_rejoin_if_necessary(NP_UNUSED np_jobargs_t* args)
{
	sll_return(np_key_t)  sll_routing_tbl;
	np_bool rejoin = FALSE;

	sll_routing_tbl = _np_route_get_table();

	if(sll_routing_tbl->size < 1 ) {
		rejoin = TRUE;
	}

	sll_free(np_key_t, sll_routing_tbl);

	if(TRUE == rejoin
			// check for state availibility to prevent test issues. TODO: Make network objects mockable
			&& _np_state() != NULL) {
		np_key_t* bootstrap = np_route_get_bootstrap_key();
		if(NULL != bootstrap){
			char* connection_str = np_get_connection_string_from(bootstrap, FALSE);
			np_send_wildcard_join(connection_str);
			free(connection_str);
		}
	}

	// Reschedule myself
    np_job_submit_event(10, _np_event_rejoin_if_necessary);
}
/**
 ** _np_events_read
 ** schedule the libev event loop one time and reschedule again
 **/
void _np_events_read(NP_UNUSED np_jobargs_t* args)
{
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

		pthread_mutex_lock(&__libev_mutex);

		if (! __suspended_libev_loop)
			ev_run(EV_A_ (EVRUN_ONCE | EVRUN_NOWAIT));

		pthread_mutex_unlock(&__libev_mutex);
	}

	if (TRUE == __exit_libev_loop) return;

	np_job_submit_event(__libev_interval, _np_events_read);
}

void _np_suspend_event_loop()
{
	pthread_mutex_lock(&__libev_mutex);
	__suspended_libev_loop++;
    pthread_mutex_unlock(&__libev_mutex);
    ev_async_send (EV_DEFAULT_ &__libev_async_watcher);
}

void _np_resume_event_loop()
{
	pthread_mutex_lock(&__libev_mutex);
	__suspended_libev_loop--;
	pthread_mutex_unlock(&__libev_mutex);
}
