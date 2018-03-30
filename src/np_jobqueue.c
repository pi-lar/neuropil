//
// neuropil is copyright 2016-2017 by pi-lar GmbH
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

#include "neuropil.h"
#include "np_types.h"

#include "np_jobqueue.h"

#include "dtime.h"
#include "np_keycache.h"
#include "np_key.h"
#include "np_memory.h"
#include "np_memory_v2.h"
#include "np_msgproperty.h"
#include "np_message.h"
#include "np_log.h"
#include "np_list.h"
#include "np_threads.h"
#include "np_settings.h"
#include "np_constants.h"

/* job_queue np_job_t structure */
struct np_job_s
{
	uint8_t type; // 1=msg handler, 2=internal handler, 4=unknown yet
	double exec_not_before_tstamp;
	double interval;
	np_bool is_periodic;
	sll_return(np_callback_t) processorFuncs;
	np_jobargs_t* args;
	double priority;

	double search_min_priority;
	double search_max_priority;
	double search_max_exec_not_before_tstamp;

#ifdef DEBUG
	char ident[255];
#endif
};

/* job_queue structure */
typedef struct np_jobqueue_s np_jobqueue_t;
struct np_jobqueue_s
{
	np_mutex_t available_workers_lock;
	np_dll_t(np_thread_ptr, available_workers);
	np_pll_t(np_job_ptr, job_list);
};

static np_jobqueue_t* __np_job_queue;
static np_cond_t      __cond_job_queue;

np_job_t* _np_job_create_job(double delay, np_jobargs_t* jargs, double priority_modifier, np_sll_t(np_callback_t, callbacks), const char* callbacks_ident)
{
	log_trace_msg(LOG_TRACE, "start: np_job_t* _np_job_create_job(double delay, np_jobargs_t* jargs){");
	// create job itself
	np_job_t* new_job = (np_job_t*)malloc(sizeof(np_job_t));
	CHECK_MALLOC(new_job);

	new_job->exec_not_before_tstamp = np_time_now() + (delay == 0 ? 0: max(0.001, delay));
	new_job->args = jargs;
	new_job->type = 1;
	new_job->priority = priority_modifier;
	new_job->interval = 0;
	new_job->is_periodic = FALSE;
	new_job->processorFuncs = callbacks;

#ifdef DEBUG
	memset(new_job->ident, 0, 255);
	if (new_job->args != NULL && new_job->args->properties != NULL)
	{
		snprintf(new_job->ident, 254, "msg handler for %-30s (fns: %p | %s)", new_job->args->properties->msg_subject, callbacks, callbacks_ident);
	}
	else if (callbacks_ident != NULL) {
		memcpy(new_job->ident, callbacks_ident, strnlen(callbacks_ident, 254));
	}
#endif

	if (jargs != NULL) {
		if (jargs->properties != NULL) {
			if (jargs->properties->priority < 1) {
				jargs->properties->priority = 1;
			}
			new_job->priority += jargs->properties->priority;
		}
	}

	return (new_job);
}
int8_t _np_job_compare_job_scheduling(np_job_ptr job1, np_job_ptr job2)
{
	log_trace_msg(LOG_TRACE, "start: int8_t _np_job_compare_job_tstamp(np_job_ptr job1, np_job_ptr job2){");

	int8_t ret = 0;	
	if (job1->exec_not_before_tstamp > job2->exec_not_before_tstamp) {
		ret = -1;
	}
	else if (job1->exec_not_before_tstamp < job2->exec_not_before_tstamp) {
		ret = 1;
	}
	else {
		if (job1->priority < job2->priority)
			ret = -1;
		else if (job1->priority > job2->priority)
			ret = 1;
	}
	
	return (ret);
}

NP_PLL_GENERATE_IMPLEMENTATION(np_job_ptr);

void _np_job_free(np_job_t * n)
{
	_np_job_free_args(n->args);
	free(n);
}

np_jobargs_t* _np_job_create_args(np_message_t* msg, np_key_t* key, np_msgproperty_t* prop, const char* reason_desc)
{
	log_trace_msg(LOG_TRACE, "start: np_jobargs_t* _np_job_create_args(np_message_t* msg, np_key_t* key, np_msgproperty_t* prop){");

	// optional parameters
	if (NULL != msg)  np_ref_obj(np_message_t, msg, __func__, reason_desc);
	if (NULL != key)  np_ref_obj(np_key_t, key, __func__, reason_desc);
	if (NULL != prop) np_ref_obj(np_msgproperty_t, prop, __func__, reason_desc);

	// create runtime arguments
	np_jobargs_t* jargs = (np_jobargs_t*)malloc(sizeof(np_jobargs_t));
	CHECK_MALLOC(jargs);

	jargs->is_resend = FALSE;
	jargs->msg = msg;
	jargs->target = key;
	jargs->properties = prop;
	jargs->custom_data = NULL;
	return (jargs);
}

void _np_job_free_args(np_jobargs_t* args)
{
	log_trace_msg(LOG_TRACE, "start: void* _np_job_free_args(np_jobargs_t* args){");

	if (args != NULL) {
		if (args->target)     np_unref_obj(np_key_t, args->target, "_np_job_create_args");
		if (args->msg)        np_unref_obj(np_message_t, args->msg, "_np_job_create_args");
		if (args->properties) np_unref_obj(np_msgproperty_t, args->properties, "_np_job_create_args");
	}
	free(args);
	args = NULL;
}

np_bool _np_job_queue_insert(np_job_t* new_job)
{
	log_trace_msg(LOG_TRACE, "start: void _np_job_queue_insert(double delay, np_job_t* new_job){");
	np_bool ret = FALSE;

	log_debug_msg(LOG_JOBS | LOG_DEBUG, "insert job into jobqueue (%p | %-70s). (property: %45s) (msg: %-36s) (target: %s)", new_job, new_job->ident,
		(new_job->args == NULL || new_job->args->properties == NULL) ? "-" : new_job->args->properties->msg_subject,
		(new_job->args == NULL || new_job->args->msg == NULL) ? "-" : new_job->args->msg->uuid,
		(new_job->args == NULL || new_job->args->target == NULL) ? "-" :
		(
		(0 == _np_key_cmp(new_job->args->target, np_state()->my_identity)) ? " == my identity" :
			(
			(0 == _np_key_cmp(new_job->args->target, np_state()->my_node_key)) ? "== my node" :
				_np_key_as_str(new_job->args->target)

				)
			)
	);

	_LOCK_MODULE(np_jobqueue_t)
	{
		// do not add job items that would overflow internal queue size
		double overflow_count = pll_size(__np_job_queue->job_list) + 1.0 - JOBQUEUE_MAX_SIZE;
		if (overflow_count > 0 && FALSE == new_job->is_periodic) {
			log_msg(LOG_WARN, "Discarding new job(s). Increase JOBQUEUE_MAX_SIZE to prevent missing data.");
		} else {
			// log_debug_msg(LOG_DEBUG, "insert  worker thread (%p) to job (%p) %s", NULL, new_job, new_job->ident);
			pll_insert(np_job_ptr, __np_job_queue->job_list, new_job, TRUE, _np_job_compare_job_scheduling);
			ret = TRUE;
		}

//		while (overflow_count > 0) {
//				pll_iterator(np_job_ptr) iter = pll_last(__np_job_queue->job_list);
//				do
//				{
//					if (iter->val->is_periodic == TRUE) {
//						pll_previous(iter);
//					}
//					else {
//						overflow_count--;
//#ifdef DEBUG
//						log_msg(LOG_ERROR, "Discarding job: %s", iter->val->ident);
//#endif
//						_np_job_free(iter->val);
//						pll_remove(np_job_ptr, __np_job_queue->job_list, iter->val, np_job_ptr_pll_compare_type);
//						break;
//					}
//				} while (iter != NULL);
//			}
//		}
	}
	_np_jobqueue_check();
	return ret;
}

void _np_jobqueue_check() {
	_np_threads_condition_signal(&__cond_job_queue);
	//_np_threads_condition_broadcast(&__cond_job_queue);
}

/** (re-)submit message event
 **
 ** get the queue mutex "access",
 ** create a new np_job_t and pass func,args,args_size,
 ** add the new np_job_t to the queue, and
 ** signal the thread pool if the queue was empty.
 **/
void _np_job_resubmit_msgout_event(double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop, __func__);
	jargs->is_resend = TRUE;

	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs, JOBQUEUE_PRIORITY_MOD_RESUBMIT_MSG_OUT, prop->clb_outbound, "clb_outbound");

	if (!_np_job_queue_insert(new_job)) {
		_np_job_free(new_job);
	}
}

void _np_job_resubmit_msgin_event(double delay, np_jobargs_t* jargs_org)
{
	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(jargs_org->msg, jargs_org->target, jargs_org->properties, __func__);
	jargs->is_resend = TRUE;
	jargs->custom_data =  jargs_org->custom_data;
	
	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs, JOBQUEUE_PRIORITY_MOD_RESUBMIT_MSG_IN, jargs_org->properties->clb_inbound, "clb_inbound");

	if (!_np_job_queue_insert(new_job)) {
		_np_job_free(new_job);
	}
}

void _np_job_resubmit_route_event(double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop, __func__);
	jargs->is_resend = TRUE;

	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs, JOBQUEUE_PRIORITY_MOD_RESUBMIT_ROUTE, prop->clb_route, "clb_route");

	if (!_np_job_queue_insert(new_job)) {
		_np_job_free(new_job);
	}
}

void _np_job_submit_route_event(double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop, __func__);

	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs, JOBQUEUE_PRIORITY_MOD_SUBMIT_ROUTE, prop->clb_route, "clb_route");


	if (!_np_job_queue_insert(new_job)) {
		_np_job_free(new_job);
	}
}

np_bool __np_job_submit_msgin_event(double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg, void* custom_data, char* tmp)
{
	// could be NULL if msg is not defined in this node
	// assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop, tmp);
	jargs->custom_data = custom_data;
	if (msg != NULL && prop != NULL) {
		if (msg->msg_property != NULL) {
			np_unref_obj(np_msgproperty_t, msg->msg_property, ref_message_msg_property);
		}
		np_ref_obj(np_msgproperty_t, prop, ref_message_msg_property);
		msg->msg_property = prop;
	}

	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs, JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_IN, prop->clb_inbound, "clb_inbound");

	if (!_np_job_queue_insert(new_job)) {
		_np_job_free(new_job);
		new_job = NULL;
	}
	return (new_job != NULL);
}

void _np_job_submit_transform_event(double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop, __func__);
	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs, JOBQUEUE_PRIORITY_MOD_TRANSFORM_MSG, prop->clb_transform, "clb_transform");


	if (!_np_job_queue_insert(new_job)) {
		_np_job_free(new_job);
	}
}

void _np_job_submit_msgout_event(double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	assert(NULL != prop);
	assert(NULL != msg);

	// create runtime arguments
	np_jobargs_t* jargs = _np_job_create_args(msg, key, prop, __func__);

	// create job itself
	np_job_t* new_job = _np_job_create_job(delay, jargs, JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_OUT, prop->clb_outbound, "clb_outbound");

	if (!_np_job_queue_insert(new_job)) {
		_np_job_free(new_job);
	}
}

void np_job_submit_event_periodic(double priority, double first_delay, double interval, np_callback_t callback, const char* ident)
{
	log_debug_msg(LOG_JOBS | LOG_DEBUG, "np_job_submit_event_periodic");

	np_sll_t(np_callback_t, callbacks);
	sll_init(np_callback_t, callbacks);
	sll_append(np_callback_t, callbacks, callback);

	np_job_t* new_job = _np_job_create_job(first_delay, NULL, priority * JOBQUEUE_PRIORITY_MOD_BASE_STEP, callbacks, ident);
	new_job->type = 2;
	new_job->interval = interval;
	new_job->is_periodic = TRUE;

	if (!_np_job_queue_insert(new_job)) {
		sll_free(np_callback_t, callbacks);
		_np_job_free(new_job);
	}
}

/** job_queue_create
 *  initiate the queue and thread pool, returns a pointer to the initiated queue.
 **/
np_bool _np_job_queue_create()
{
	log_trace_msg(LOG_TRACE, "start: np_bool _np_job_queue_create(){");
	__np_job_queue = (np_jobqueue_t *)malloc(sizeof(np_jobqueue_t));
	CHECK_MALLOC(__np_job_queue);

	if (NULL == __np_job_queue) return (FALSE);

	pll_init(np_job_ptr, __np_job_queue->job_list);
	dll_init(np_thread_ptr, __np_job_queue->available_workers);

	_np_threads_mutex_init(&__np_job_queue->available_workers_lock, "available_workers_lock");
	_np_threads_condition_init(&__cond_job_queue);

	return (TRUE);
}

void _np_job_queue_destroy()
{
	log_trace_msg(LOG_TRACE, "start: np_bool _np_job_queue_destroy(){");

	pll_free(np_job_ptr, __np_job_queue->job_list);
	dll_free(np_thread_ptr, __np_job_queue->available_workers);

	_np_threads_condition_destroy(&__cond_job_queue);
	_np_threads_mutex_destroy(&__np_job_queue->available_workers_lock);

	free(__np_job_queue);
}

void _np_job_yield(const double delay)
{
	log_trace_msg(LOG_TRACE, "start: void _np_job_yield(const double delay){");
	if (1 == np_state()->thread_count)
	{
		np_time_sleep(delay);
	}
	else
	{
		// unlock another threads
		_LOCK_MODULE(np_jobqueue_t) {
			_np_jobqueue_check();
		}

		_LOCK_MODULE(np_jobqueue_t) {
			if (0.0 != delay)
			{
				struct timeval tv_sleep = dtotv(np_time_now() + delay);
				struct timespec waittime = { .tv_sec = tv_sleep.tv_sec,.tv_nsec = tv_sleep.tv_usec * 1000 };
				// wait for time x to be unlocked again

				_np_threads_module_condition_timedwait(&__cond_job_queue, np_jobqueue_t_lock, &waittime);
			}
			else
			{
				// wait for next wakeup signal
				_np_threads_module_condition_wait(&__cond_job_queue, np_jobqueue_t_lock);
			}
		}
	}
}

static int8_t __np_job_cmp(np_job_ptr first, np_job_ptr second)
{
	int8_t ret = 1;
	if (first == second)
		ret = 0;
	return ret;
}

void* __np_jobqueue_run_jobs(void* np_thread_ptr_self)
{
	_np_threads_set_self(np_thread_ptr_self);

	np_thread_t* target = np_thread_ptr_self;
	double sleep_time;
	double now;

	np_bool run_next_job = FALSE;
	np_job_ptr next_job = NULL;

	while (1) {

		_LOCK_MODULE(np_jobqueue_t)
		{
			now = np_time_now();
			sleep_time = NP_JOBQUEUE_MAX_SLEEPTIME_SEC;
			run_next_job = FALSE;

			pll_iterator(np_job_ptr) iter_jobs = pll_first(__np_job_queue->job_list);
			np_job_ptr next_job = iter_jobs->val;
			// check time of job
			if (now <= next_job->exec_not_before_tstamp) {
				sleep_time = min(sleep_time, next_job->exec_not_before_tstamp - now);
			} else {
				pll_remove(np_job_ptr, __np_job_queue->job_list, next_job, __np_job_cmp);
				target->job = next_job;
				run_next_job = TRUE;
			}
		}

		if (run_next_job == TRUE) {
			__np_jobqueue_run_once(next_job);
		} else {
			struct timeval tv_sleep = dtotv(now + sleep_time);
			struct timespec waittime = { .tv_sec = tv_sleep.tv_sec,.tv_nsec = tv_sleep.tv_usec * 1000 };

			_np_threads_module_condition_timedwait(&__cond_job_queue, np_jobqueue_t_lock, &waittime);
		}
	}
}

int8_t __np_jobqueue_find_job_by_priority(np_job_ptr const a, np_job_ptr const search_key) {

	int8_t ret = a->exec_not_before_tstamp < search_key->search_max_exec_not_before_tstamp ? -1 : 1;

	if (search_key->search_max_priority >= a->priority && a->priority >= search_key->search_min_priority)
		ret = 0;

	return ret;
}

void* __np_jobqueue_run_manager(void* np_thread_ptr_self)
{
	_np_threads_set_self(np_thread_ptr_self);

	double now, sleep = NP_PI/100;
	dll_iterator(np_thread_ptr) iter_workers;

	np_job_t search_key = { 0 };
	np_thread_ptr current_worker = NULL;

	_LOCK_ACCESS(&__np_job_queue->available_workers_lock)
	{
		iter_workers = dll_first(__np_job_queue->available_workers);
	}

	while (1)
	{
		sleep = NP_PI/100;
		np_bool new_worker_job = FALSE;

		if (NULL != iter_workers)
		{
			current_worker = iter_workers->val;
			new_worker_job = FALSE;
			_TRYLOCK_ACCESS(&current_worker->job_lock)
			{
				search_key.search_min_priority = current_worker->min_job_priority;
				search_key.search_max_priority = current_worker->max_job_priority;
				search_key.search_max_exec_not_before_tstamp = np_time_now();

				_LOCK_MODULE(np_jobqueue_t)
				{
					np_job_t * next_job = pll_find(np_job_ptr, __np_job_queue->job_list, &search_key, __np_jobqueue_find_job_by_priority);
					if (next_job != NULL) {
						now = np_time_now();
						if (next_job->exec_not_before_tstamp <= now) {
							pll_remove(np_job_ptr, __np_job_queue->job_list, next_job, np_job_ptr_pll_compare_type);
							current_worker->job = next_job;
							new_worker_job = TRUE;
							// log_debug_msg(LOG_DEBUG, "assign  worker thread (%p) to job (%p)", current_worker, next_job);
						}
						else {
							sleep = min(sleep, now - next_job->exec_not_before_tstamp);
						}
					}
				}
			}

			if (new_worker_job == TRUE && current_worker->job) {
				// log_debug_msg(LOG_DEBUG, "start   worker thread (%p) job (%p)", current_worker, current_worker->job);
				_np_threads_condition_signal(&current_worker->job_lock.condition);
			}

			_LOCK_ACCESS(&__np_job_queue->available_workers_lock)
			{
				dll_next(iter_workers);
			}
		}
		else
		{	// wait for time x to be unlocked again
			_LOCK_MODULE(np_jobqueue_t)
			{
				struct timeval tv_sleep = dtotv(np_time_now() + MAX(NP_PI/1000, sleep));
				struct timespec waittime = { .tv_sec = tv_sleep.tv_sec, .tv_nsec = tv_sleep.tv_usec * 1000 };
				_np_threads_module_condition_timedwait(&__cond_job_queue, np_jobqueue_t_lock, &waittime);
			}

			_LOCK_ACCESS(&__np_job_queue->available_workers_lock)
			{
				iter_workers = dll_first(__np_job_queue->available_workers);
			}
		}
	}
}

uint32_t np_jobqueue_count()
{
	uint32_t ret = 0;

	_LOCK_MODULE(np_jobqueue_t)
	{
		ret = pll_size(__np_job_queue->job_list);
	}
	return ret;
}

void __np_jobqueue_run_once(np_job_t* job_to_execute)
{
	// sanity checks if the job list really returned an element
	if (NULL == job_to_execute) return;
	if (NULL == job_to_execute->processorFuncs) return;
	if (sll_size(((job_to_execute->processorFuncs))) <= 0) return;	
	
#ifdef NP_THREADS_CHECK_THREADING	
		log_debug_msg(LOG_DEBUG,
			"thread-->%15"PRIu64" job-->%15p remaining jobs: %"PRIu32") func_count-->%"PRIu32" funcs-->%15p args-->%15p prio:%10.2f not before: %15.10f jobname: %s",
			_np_threads_get_self()->id,
			job_to_execute,
			np_jobqueue_count(),
			sll_size((job_to_execute->processorFuncs)),
			(job_to_execute->processorFuncs),
			job_to_execute->args,
			job_to_execute->priority,
			job_to_execute->exec_not_before_tstamp,
			job_to_execute->ident
		);
#endif

#ifdef DEBUG
	if (job_to_execute->type == 1) {
		char* msg_uuid = "NULL";
		if (job_to_execute->args->msg != NULL) {
			msg_uuid = job_to_execute->args->msg->uuid;
		}
		// ignore _DEFAULT  property
		if (strcmp(job_to_execute->args->properties->msg_subject, _DEFAULT) != 0)
		{
			log_debug_msg(LOG_JOBS | LOG_DEBUG, "message handler called on subject: %50s msg: %-36s fns: %p", job_to_execute->args->properties->msg_subject, msg_uuid, (job_to_execute->processorFuncs));
		}
	}
#endif
	// do not process if the target is not available anymore (but do process if no target is required at all)

	np_bool exec_funcs = TRUE;
	if (job_to_execute->args != NULL && job_to_execute->args->target != NULL) {
		TSP_GET(np_bool, job_to_execute->args->target->in_destroy, in_destroy);
		exec_funcs &= (in_destroy == FALSE);
	}

	if (exec_funcs) {
#ifdef DEBUG_CALLBACKS
		if (job_to_execute->ident[0] == 0) {
			sprintf(job_to_execute->ident, "%p", (job_to_execute->processorFuncs));
		}

		log_debug_msg(LOG_JOBS | LOG_DEBUG, "start internal job callback function (@%f) %s", np_time_now(), job_to_execute->ident);
		double n1 = np_time_now();
#endif

		sll_iterator(np_callback_t) iter = sll_first((job_to_execute->processorFuncs));
		
		while (iter != NULL)
		{			
			iter->val(job_to_execute->args);
			sll_next(iter);
		}

#ifdef DEBUG_CALLBACKS
		double n2 = np_time_now() - n1;
		_np_util_debug_statistics_t* stat = _np_util_debug_statistics_add(job_to_execute->ident, n2);

		log_debug_msg(LOG_JOBS | LOG_DEBUG, "internal job callback function %-45s(%"PRIu8"), duration: %10f, c:%6"PRIu32", %10f / %10f / %10f", stat->key, job_to_execute->type, n2, stat->count, stat->max, stat->avg, stat->min);
#endif
	}

	if (job_to_execute->args != NULL && job_to_execute->args->msg != NULL) {
		log_debug_msg(LOG_JOBS | LOG_DEBUG, "completed handeling function for msg %s for %s", job_to_execute->args->msg->uuid, _np_message_get_subject(job_to_execute->args->msg));
	}	

	if (job_to_execute->is_periodic == TRUE) {
		job_to_execute->exec_not_before_tstamp = np_time_now() + job_to_execute->interval;

		if (!_np_job_queue_insert(job_to_execute)) {
			_np_job_free(job_to_execute);
		}
	}
	else {
		// cleanup
		_np_job_free(job_to_execute);
	}
	job_to_execute = NULL;
}

void _np_jobqueue_add_worker_thread(np_thread_t* self)
{
	_LOCK_ACCESS(&__np_job_queue->available_workers_lock)
	{
		// log_msg(LOG_DEBUG, "enqueue worker thread (%p) to job (%p)", self, self->job);
		dll_prepend(np_thread_ptr, __np_job_queue->available_workers, self);
	}
}

/** job_exec
 * runs a thread which is competing for jobs in the job queue
 * after getting the first job out of queue it will execute the corresponding callback with
 * defined job arguments
 */
void* __np_jobqueue_run_worker(void* np_thread_ptr)
{
	log_debug_msg(LOG_JOBS | LOG_THREADS | LOG_DEBUG, "job queue thread starting");

	_np_threads_set_self(np_thread_ptr);
	np_thread_t* my_thread = np_thread_ptr;
	
	while (1)
	{
		_LOCK_ACCESS(&my_thread->job_lock)
		{
			if (my_thread->job == NULL) {
				// log_debug_msg(LOG_DEBUG, "wait    worker thread (%p) to job (%p)", my_thread, my_thread->job);
				_np_threads_mutex_condition_wait(&my_thread->job_lock);
			}
			// log_debug_msg(LOG_DEBUG, "exec    worker thread (%p) to job (%p) %s", my_thread, my_thread->job, my_thread->job->ident);
			__np_jobqueue_run_once(my_thread->job);
			my_thread->job = NULL;
		}

	}
	return (NULL);
}
