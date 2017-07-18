//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>

#include "event/ev.h"

#include "np_jobqueue.h"

#include "dtime.h"
#include "neuropil.h"
#include "np_keycache.h"
#include "np_key.h"
#include "np_memory.h"
#include "np_msgproperty.h"
#include "np_message.h"
#include "np_log.h"
#include "np_threads.h"

static double __jobqueue_sleep_time = 0.3141592;

/* job_queue np_job_t structure */
struct np_job_s
{
	uint8_t type; // 1=msg handler, 2=internal handler, 4=unknown yet
	char* job_name;
	double tstamp;
	np_callback_t processorFunc;
	np_jobargs_t* args;
	np_job_t* next;
};

/* job_queue structure */
typedef struct np_jobqueue_s np_jobqueue_t;
struct np_jobqueue_s
{
	np_pll_t(np_job_ptr, job_list);
};

static np_jobqueue_t*  __np_job_queue;

static np_cond_t  __cond_empty;

int8_t _np_job_compare_job_tstamp(np_job_ptr job1, np_job_ptr job2)
{
    log_msg(LOG_TRACE, "start: int8_t _np_job_compare_job_tstamp(np_job_ptr job1, np_job_ptr job2){");
	if (job1->tstamp > job2->tstamp) return (-1);
	if (job1->tstamp < job2->tstamp) return ( 1);
	return (0);
}

NP_PLL_GENERATE_IMPLEMENTATION(np_job_ptr);

void _np_job_free (np_job_t * n)
{
    free (n);
}

np_jobargs_t* _np_job_create_args(np_message_t* msg, np_key_t* key, np_msgproperty_t* prop)
{
    log_msg(LOG_TRACE, "start: np_jobargs_t* _np_job_create_args(np_message_t* msg, np_key_t* key, np_msgproperty_t* prop){");

    np_tryref_obj(np_message_t, msg, hasMsg);
	np_tryref_obj(np_key_t, key, hasKey);
	np_tryref_obj(np_msgproperty_t, prop, hasProp);

	// create runtime arguments
	np_jobargs_t* jargs = (np_jobargs_t*) malloc(sizeof(np_jobargs_t));
	CHECK_MALLOC(jargs);

	jargs->msg = msg;
	jargs->is_resend = FALSE;
	jargs->target = key;
	jargs->properties = prop;

	return (jargs);
}

void _np_job_free_args(np_jobargs_t* args)
{
    log_msg(LOG_TRACE, "start: void* _np_job_free_args(np_jobargs_t* args){");

    if(args != NULL){
		np_unref_obj(np_message_t, args->msg);
		np_unref_obj(np_key_t, args->target);
		np_unref_obj(np_msgproperty_t, args->properties);
    }
	free(args);
}

np_job_t* _np_job_create_job(double delay, np_jobargs_t* jargs)
{
    log_msg(LOG_TRACE, "start: np_job_t* _np_job_create_job(double delay, np_jobargs_t* jargs){");
	// create job itself
	np_job_t* new_job = (np_job_t*) malloc(sizeof(np_job_t));
	CHECK_MALLOC(new_job);

	new_job->tstamp = ev_time() + delay;
	new_job->args = jargs;
	new_job->type = 1;
	return (new_job);
}

void _np_job_queue_insert(double delay, np_job_t* new_job)
{
    log_msg(LOG_TRACE, "start: void _np_job_queue_insert(double delay, np_job_t* new_job){");
	_LOCK_MODULE(np_jobqueue_t){

		pll_insert(np_job_ptr, __np_job_queue->job_list, new_job, TRUE, _np_job_compare_job_tstamp);
		// if (pll_size(__np_job_queue->job_list) >= 1 || delay == 0.0)
		if (0.0 == delay)
		{
			// restart all waiting jobs & yields
			_np_threads_module_condition_broadcast(&__cond_empty);
			// restart single job or yield
			// pthread_cond_signal(&__cond_empty);
		}
	}
}

/** (re-)submit message event
 **
 ** get the queue mutex "access",
 ** create a new np_job_t and pass func,args,args_size,
 ** add the new np_job_t to the queue, and
 ** signal the thread pool if the queue was empty.
 **/
void _np_job_resubmit_msgout_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop);
    jargs->is_resend = TRUE;

    // create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs);
    new_job->processorFunc = prop->clb_outbound;

	_np_job_queue_insert(delay, new_job);
}

void _np_job_resubmit_route_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop);
    jargs->is_resend = TRUE;

    // create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs);
    new_job->processorFunc = prop->clb_route;

	_np_job_queue_insert(delay, new_job);
}

void _np_job_submit_route_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop);

	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs);
    new_job->processorFunc = prop->clb_route; // ->msg_handler;

	_np_job_queue_insert(delay, new_job);
}

void _np_job_submit_msgin_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	// could be NULL if msg is not defined in this node
	// assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop);

    // create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs);
    new_job->processorFunc = prop->clb_inbound; // ->msg_handler;

	_np_job_queue_insert(delay, new_job);
}

void _np_job_submit_transform_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop);
    // create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs);
    new_job->processorFunc = prop->clb_transform; // ->msg_handler;

	_np_job_queue_insert(delay, new_job);
}

void _np_job_submit_msgout_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
    // create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop);

	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs);
    new_job->processorFunc = prop->clb_outbound;

	_np_job_queue_insert(delay, new_job);
}

void np_job_submit_event (double delay, np_callback_t callback)
{
	np_job_t* new_job = _np_job_create_job(delay, NULL);
    new_job->processorFunc = callback;
    new_job->type = 2;

	_np_job_queue_insert(delay, new_job);
}

/** job_queue_create
 *  initiate the queue and thread pool, returns a pointer to the initiated queue.
 **/
np_bool _np_job_queue_create()
{
    log_msg(LOG_TRACE, "start: np_bool _np_job_queue_create(){");
	__np_job_queue = (np_jobqueue_t *) malloc (sizeof(np_jobqueue_t));
	CHECK_MALLOC(__np_job_queue);

	if (NULL == __np_job_queue) return (FALSE);

	pll_init(np_job_ptr, __np_job_queue->job_list);

	_np_threads_condition_init(&__cond_empty);

    return (TRUE);
}

void _np_job_yield(const double delay)
{
    log_msg(LOG_TRACE, "start: void _np_job_yield(const double delay){");
	if (1 == _np_state()->thread_count)
	{
		ev_sleep(delay);
	}
	else
	{
		// unlock another thread
		_LOCK_MODULE(np_jobqueue_t){
			_np_threads_condition_signal(&__cond_empty);
		}

		if (0.0 != delay)
		{
			struct timeval tv_sleep = dtotv(ev_time() + delay);
			struct timespec waittime = { .tv_sec = tv_sleep.tv_sec, .tv_nsec=tv_sleep.tv_usec*1000 };
			// wait for time x to be unlocked again
			_LOCK_MODULE(np_jobqueue_t){
				_np_threads_module_condition_timedwait(&__cond_empty, np_jobqueue_t_lock, &waittime);
			}
		}
		else
		{
			// wait for next wakeup signal
			_LOCK_MODULE(np_jobqueue_t){
				_np_threads_module_condition_wait(&__cond_empty, np_jobqueue_t_lock);
			}
		}
	}
}

/** job_exec
 * runs a thread which is competing for jobs in the job queue
 * after getting the first job out of queue it will execute the corresponding callback with
 * defined job arguments
 */
void* _job_exec ()
{
	// np_state_t* state = _np_state();
	np_job_t* tmp = NULL;

	log_debug_msg(LOG_DEBUG, "job queue thread starting");

    double now;

	while (1)
	{
		_np_threads_lock_module(np_jobqueue_t_lock);

	    now = ev_time();
	    while (0 == pll_size(__np_job_queue->job_list))
		{
    		// log_debug_msg(LOG_DEBUG, "now %f: list empty, start sleeping", now);
			_np_threads_module_condition_wait(&__cond_empty, np_jobqueue_t_lock);
	    	// wake up, check first job in the queue to be executed by now
		}

    	np_job_ptr next_job = pll_first(__np_job_queue->job_list)->val;
    	if (now <= next_job->tstamp)
    	{
    		double sleep_time = next_job->tstamp - now;
    		if (sleep_time > __jobqueue_sleep_time) sleep_time = __jobqueue_sleep_time;
    		// log_debug_msg(LOG_DEBUG, "now %f: next execution %f", now, next_job->tstamp);
    		// log_debug_msg(LOG_DEBUG, "currently %d jobs, now sleeping for %f seconds", pll_size(Q->job_list), sleep_time);
    		struct timeval tv_sleep = dtotv(now + sleep_time);
    		struct timespec waittime = { .tv_sec = tv_sleep.tv_sec, .tv_nsec=tv_sleep.tv_usec*1000 };
			_np_threads_module_condition_timedwait(&__cond_empty, np_jobqueue_t_lock, &waittime);
	    	// now = dtime();
    		// log_debug_msg(LOG_DEBUG, "now %f: woke up or interupted", now);
	    	_np_threads_unlock_module(np_jobqueue_t_lock);
    		continue;
    	}
    	else
    	{
    		// log_debug_msg(LOG_DEBUG, "now %f --> executing %f", now, next_job->tstamp);
    		tmp = pll_head(np_job_ptr, __np_job_queue->job_list);
    		_np_threads_unlock_module(np_jobqueue_t_lock);
    	}

    	// sanity checks if the job list really returned an element
	    if (NULL == tmp) continue;
	    if (NULL == tmp->processorFunc) continue;
	    // log_debug_msg(LOG_DEBUG, "%hhd:     job-->%p func-->%p args-->%p", tmp->type, tmp, tmp->processorFunc, tmp->args);

	    if(tmp->args != NULL && tmp->args->msg != NULL) {
	    	log_msg(LOG_DEBUG, "handeling function for msg %s for %s",tmp->args->msg->uuid, _np_message_get_subject(tmp->args->msg));
	    }

    	tmp->processorFunc(tmp->args);

    	if(tmp->args != NULL && tmp->args->msg != NULL) {
	    	log_msg(LOG_DEBUG, "completed handeling function for msg %s for %s",tmp->args->msg ->uuid,_np_message_get_subject(tmp->args->msg));
	    }
	    // cleanup
    	_np_job_free_args(tmp->args);
	    _np_job_free(tmp);
	    tmp = NULL;
	}
    return (NULL);
}
