//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdint.h>
#include <float.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <inttypes.h>

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
#include "np_settings.h"
#include "np_constants.h"

/* job_queue np_job_t structure */
struct np_job_s
{
	uint8_t type; // 1=msg handler, 2=internal handler, 4=unknown yet
	char* job_name;
	double exec_not_before_tstamp;
	double interval;
	np_bool is_periodic;
	np_callback_t processorFunc;
	np_jobargs_t* args;
	double priority;
#ifdef DEBUG
	char ident[255];
#endif
};

/* job_queue structure */
typedef struct np_jobqueue_s np_jobqueue_t;
struct np_jobqueue_s
{
	np_pll_t(np_job_ptr, job_list);
};

static np_jobqueue_t * __np_job_queue;

static np_cond_t  __cond_empty;

np_job_t* _np_job_create_job(double delay, np_jobargs_t* jargs, double priority_modifier)
{
	log_msg(LOG_TRACE, "start: np_job_t* _np_job_create_job(double delay, np_jobargs_t* jargs){");
	// create job itself
	np_job_t* new_job = (np_job_t*) malloc(sizeof(np_job_t));
	CHECK_MALLOC(new_job);

	new_job->exec_not_before_tstamp = np_time_now() + delay;
	new_job->args = jargs;
	new_job->type = 1;
	new_job->priority =  priority_modifier;
	new_job->interval = 0;
	new_job->is_periodic = FALSE;
	
#ifdef DEBUG
	memset(new_job->ident,0,255);

	if (new_job->args != NULL && new_job->args->properties != NULL)
	{
		snprintf(new_job->ident, 254, "msg handler for %s", new_job->args->properties->msg_subject);
	}
#endif

	if(jargs != NULL){
		if(jargs->properties != NULL) {
			if(jargs->properties->priority < 1) {
				jargs->properties->priority = 1;
			}
			new_job->priority += jargs->properties->priority;
		}
	}

	return (new_job);
}
int8_t _np_job_compare_job_scheduling(np_job_ptr job1, np_job_ptr job2)
{
	log_msg(LOG_TRACE, "start: int8_t _np_job_compare_job_tstamp(np_job_ptr job1, np_job_ptr job2){");

	int8_t ret = 0;
	if (job1->exec_not_before_tstamp > job2->exec_not_before_tstamp) {
		ret = -1;
	}
	else if (job1->exec_not_before_tstamp < job2->exec_not_before_tstamp) {
		ret = 1;
	}else{
		if (job1->priority == job2->priority)
			ret = 0;
		else if (job1->priority > job2->priority)
			ret = -1;
		else
			ret = 1;
	}
	return (ret);
}

NP_PLL_GENERATE_IMPLEMENTATION(np_job_ptr);

void _np_job_free (np_job_t * n)
{
	free (n);
}

np_jobargs_t* _np_job_create_args(np_message_t* msg, np_key_t* key, np_msgproperty_t* prop)
{
	log_msg(LOG_TRACE, "start: np_jobargs_t* _np_job_create_args(np_message_t* msg, np_key_t* key, np_msgproperty_t* prop){");

	// optional parameters
	if (NULL != msg)  np_ref_obj(np_message_t, msg);
	if (NULL != key)  np_ref_obj(np_key_t, key);
	if (NULL != prop) np_ref_obj(np_msgproperty_t, prop);

	// create runtime arguments
	np_jobargs_t* jargs = (np_jobargs_t*) malloc(sizeof(np_jobargs_t));
	CHECK_MALLOC(jargs);

	jargs->is_resend = FALSE;
	jargs->msg = msg;
	jargs->target = key;
	jargs->properties = prop;

	return (jargs);
}

void _np_job_free_args(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void* _np_job_free_args(np_jobargs_t* args){");

	if(args != NULL) {
		np_unref_obj(np_message_t, args->msg,"_np_job_create_args");
		np_unref_obj(np_key_t, args->target,"_np_job_create_args");
		np_unref_obj(np_msgproperty_t, args->properties,"_np_job_create_args");
	}
	free(args);
}


void _np_job_queue_insert(np_job_t* new_job)
{
	log_msg(LOG_TRACE, "start: void _np_job_queue_insert(double delay, np_job_t* new_job){");
	_LOCK_MODULE(np_jobqueue_t) {
		pll_insert(np_job_ptr, __np_job_queue->job_list, new_job, TRUE, _np_job_compare_job_scheduling);
	}
	_np_threads_condition_signal(&__cond_empty);
	//_np_threads_condition_broadcast(&__cond_empty);	
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
	np_job_t* new_job = _np_job_create_job(delay, jargs, JOBQUEUE_PRIORITY_MOD_RESUBMIT_MSG_OUT);
	new_job->processorFunc = prop->clb_outbound;

	_np_job_queue_insert(new_job);
}

void _np_job_resubmit_route_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop);
	jargs->is_resend = TRUE;

	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs,JOBQUEUE_PRIORITY_MOD_RESUBMIT_ROUTE);
	new_job->processorFunc = prop->clb_route;

	_np_job_queue_insert(new_job);
}

void _np_job_submit_route_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop);

	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs, JOBQUEUE_PRIORITY_MOD_SUBMIT_ROUTE);
	new_job->processorFunc = prop->clb_route; // ->msg_handler;

	_np_job_queue_insert( new_job);
}

void _np_job_submit_msgin_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	if(msg != NULL && prop != NULL){
		if (msg->msg_property != NULL) {
			np_unref_obj(np_msgproperty_t, prop, ref_message_msg_property);
		}
		msg->msg_property = prop;
		np_ref_obj(np_msgproperty_t, prop, ref_message_msg_property);
	}


	// could be NULL if msg is not defined in this node
	// assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop);

	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs,JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_IN);
	new_job->processorFunc = prop->clb_inbound;

	_np_job_queue_insert(new_job);
}

void _np_job_submit_transform_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop);
	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs, JOBQUEUE_PRIORITY_MOD_TRANSFORM_MSG);
	new_job->processorFunc = prop->clb_transform; // ->msg_handler;

	_np_job_queue_insert(new_job);
}

void _np_job_submit_msgout_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);
	assert(NULL != msg);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop);

	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs, JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_OUT);
	new_job->processorFunc = prop->clb_outbound;

	_np_job_queue_insert(new_job);
}

void np_job_submit_event(double delay, np_callback_t callback, char* ident)
{
	np_job_t* new_job = _np_job_create_job(delay, NULL, JOBQUEUE_PRIORITY_MOD_SUBMIT_EVENT);
	new_job->processorFunc = callback;
	new_job->type = 2;
#ifdef DEBUG
	memcpy(new_job->ident, ident, min(254, strlen(ident)));
#endif

	_np_job_queue_insert(new_job);
}

void np_job_submit_event_periodic(double first_delay, double interval, np_callback_t callback,char* ident)
{
	log_debug_msg(LOG_DEBUG, "np_job_submit_event_periodic");
	np_job_t* new_job = _np_job_create_job(first_delay, NULL, JOBQUEUE_PRIORITY_MOD_SUBMIT_EVENT);
	new_job->processorFunc = callback;
	new_job->type = 2;
#ifdef DEBUG
	memcpy(new_job->ident, ident, min(254, strlen(ident)));
#endif
	new_job->interval = interval;
	new_job->is_periodic = TRUE;

	_np_job_queue_insert(new_job);
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
		_LOCK_MODULE(np_jobqueue_t) {
			if (0.0 != delay)
			{
				struct timeval tv_sleep = dtotv(np_time_now() + delay);
				struct timespec waittime = { .tv_sec = tv_sleep.tv_sec,.tv_nsec = tv_sleep.tv_usec * 1000 };
				// wait for time x to be unlocked again
				_np_threads_module_condition_timedwait(&__cond_empty, np_jobqueue_t_lock, &waittime);
			}
			else
			{
				// wait for next wakeup signal
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
	np_job_t* job_to_execute = NULL;

	log_debug_msg(LOG_DEBUG, "job queue thread starting");

	double now;

	while (1)
	{
		uint32_t job_count = 0;

		_LOCK_MODULE(np_jobqueue_t){

			now = np_time_now();

			np_job_ptr next_job = pll_first(__np_job_queue->job_list)->val;
			if (next_job == NULL || now <= next_job->exec_not_before_tstamp)
			{
				double sleep_time = NP_JOBQUEUE_MAX_SLEEPTIME_SEC;
				if(next_job != NULL) {
					sleep_time = next_job->exec_not_before_tstamp - now;
				}				

 				sleep_time = min(sleep_time, NP_JOBQUEUE_MAX_SLEEPTIME_SEC);

				struct timeval tv_sleep = dtotv(now + sleep_time);
				struct timespec waittime = { .tv_sec = tv_sleep.tv_sec, .tv_nsec=tv_sleep.tv_usec*1000 };

				_np_threads_module_condition_timedwait(&__cond_empty, np_jobqueue_t_lock, &waittime);
				_np_threads_unlock_module(np_jobqueue_t_lock);
				continue;
			}

			// log_debug_msg(LOG_DEBUG, "now %f --> executing %f", now, next_job->tstamp);
			job_to_execute = pll_head(np_job_ptr, __np_job_queue->job_list);
		}
		

		// sanity checks if the job list really returned an element
		if (NULL == job_to_execute) continue;
		if (NULL == job_to_execute->processorFunc) continue;
		log_debug_msg(LOG_DEBUG, "%hhd:     job-->%p func-->%p args-->%p", job_to_execute->type, job_to_execute, job_to_execute->processorFunc, job_to_execute->args);

		if (job_to_execute->args != NULL && job_to_execute->args->msg != NULL) {
			log_debug_msg(LOG_DEBUG, "handling function for msg %s for %s", job_to_execute->args->msg->uuid, _np_message_get_subject(job_to_execute->args->msg));
		}
		
		// do not process if the target is not available anymore (but do process if no target is required at all)
		if (job_to_execute->args == NULL || job_to_execute->args->target == NULL || job_to_execute->args->target->in_destroy == FALSE) {
			
#ifdef DEBUG_CALLBACKS			
			if (job_to_execute->ident[0] == 0) {
				sprintf(job_to_execute->ident, "%p", job_to_execute->processorFunc);
			}

			log_debug_msg(LOG_DEBUG, "start internal job callback function (@%f) %s",np_time_now(), job_to_execute->ident);
			double n1 = np_time_now();
#endif			
			job_to_execute->processorFunc(job_to_execute->args);

#ifdef DEBUG_CALLBACKS
			double n2 = np_time_now() - n1;						
			_np_util_debug_statistics_t* stat = _np_util_debug_statistics_add(job_to_execute->ident, n2);
			
			log_debug_msg(LOG_DEBUG , "internal job callback function %-45s(%"PRIu8"), duration: %10f, c:%6"PRIu32", %10f / %10f / %10f", stat->key, job_to_execute->type, n2, stat->count, stat->max, stat->avg, stat->min);
#endif
		}			

		if(job_to_execute->args != NULL && job_to_execute->args->msg != NULL) {
			log_debug_msg(LOG_DEBUG, "completed handeling function for msg %s for %s",job_to_execute->args->msg ->uuid,_np_message_get_subject(job_to_execute->args->msg));
		}
		if (job_to_execute->is_periodic == TRUE) {
			job_to_execute->exec_not_before_tstamp = np_time_now() + job_to_execute->interval;						
			_np_job_queue_insert(job_to_execute);			
		}
		else {
			// cleanup
			_np_job_free_args(job_to_execute->args);
			_np_job_free(job_to_execute);
		}
		job_to_execute = NULL;

	}
	return (NULL);
}
