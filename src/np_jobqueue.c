//
// neuropil is copyright 2016-2019 by pi-lar GmbH
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
#include <math.h>

#include "event/ev.h"

#include "np_legacy.h"
#include "np_types.h"

#include "np_jobqueue.h"

#include "dtime.h"
#include "np_keycache.h"
#include "np_key.h"
#include "np_memory.h"
#include "core/np_comp_msgproperty.h"
#include "np_message.h"
#include "np_log.h"
#include "np_list.h"
#include "np_threads.h"
#include "np_settings.h"
#include "np_constants.h"
#include "np_heap.h"
#include "np_threads.h"
#include "np_statistics.h"
#include "np_time.h"

int8_t _np_job_compare_job_scheduling(np_job_t job1, np_job_t new_job)
{
    int8_t ret = 0;
    if (job1.exec_not_before_tstamp > new_job.exec_not_before_tstamp) {
        ret = -1;
    }
    else if (job1.exec_not_before_tstamp < new_job.exec_not_before_tstamp) {
        ret = 1;
    }
    else {
        if (job1.priority > new_job.priority)
            ret = -1;
        else if (job1.priority < new_job.priority)
            ret = 1;
    }

    return (ret);
}

bool np_job_t_compare(np_job_t i, np_job_t j) {
    return (_np_job_compare_job_scheduling(j, i) == -1);
}

uint16_t np_job_t_binheap_get_priority (np_job_t job) {
    //TODO: reactivate prio increase
    return (uint16_t)PRIORITY_MOD_LEVEL_6 - job.priority;
    double tmp = job.exec_not_before_tstamp - _np_time_now(NULL);
    if (tmp < 0.0) tmp = 0.0;
    // fprintf(stdout, "%f %f --> %d\n", tmp, job.priority, (uint16_t) (job.priority + tmp*100000) / 10);
    return (uint16_t) (job.priority + tmp * JOBQUEUE_PRIORITY_MOD_BASE_STEP) / 10;
}

NP_BINHEAP_GENERATE_PROTOTYPES(np_job_t);

NP_BINHEAP_GENERATE_IMPLEMENTATION(np_job_t);

/* job_queue structure */
np_module_struct(jobqueue)
{
    np_state_t* context;
    np_cond_t   __cond_job_queue;

    np_mutex_t  available_workers_lock;
    np_dll_t(np_thread_ptr, available_workers);

    np_pheap_t(np_job_t, job_list);

    uint16_t periodic_jobs;
};

static np_jobargs_t __null_args = { .msg = NULL, .custom_data = NULL, .is_resend=false, .properties=NULL, .target=NULL };

np_job_t _np_job_create_job(np_state_t * context, double delay, np_jobargs_t jargs, double priority_modifier, np_sll_t(np_callback_t, callbacks), const char* callbacks_ident)
{
    log_trace_msg(LOG_TRACE, "start: np_job_t* _np_job_create_job(double delay, np_jobargs_t* jargs){");
    // create job itself
    np_job_t new_job = {0};
    // np_new_obj(np_job_t, &new_job);
    
    new_job.exec_not_before_tstamp = np_time_now() + (delay == 0 ? 0: fmax(NP_SLEEP_MIN, delay));
    new_job.args = jargs;
    new_job.type = 1;
    new_job.priority = priority_modifier;
    new_job.interval = 0;
    new_job.is_periodic = false;
    new_job.processorFuncs = callbacks;
    new_job.__del_processorFuncs = false;

#ifdef DEBUG
    memset(new_job.ident, 0, 255);
    if (new_job.args.properties != NULL)
    {
        snprintf(new_job.ident, 254, "msg handler for %-30s (fns: %10p | %15s)", new_job.args.properties->msg_subject, callbacks, callbacks_ident);
    }
    else if (callbacks_ident != NULL) {
        memcpy(new_job.ident, callbacks_ident, strnlen(callbacks_ident, 254));
    }
#endif

    // if (jargs != NULL) {
    if (jargs.properties != NULL) {
        if (jargs.properties->priority < 1) {
            jargs.properties->priority = 1;
        }
        new_job.priority += jargs.properties->priority;
    }
    // }
    return (new_job);
}

void _np_job_free(np_state_t* context, np_job_t* n)
{
    _np_job_free_args(context, n->args);
    if(n->__del_processorFuncs) sll_free(np_callback_t, n->processorFuncs);    
}

np_jobargs_t _np_job_create_args(np_state_t* context, np_message_t* msg, np_key_t* key, np_msgproperty_t* prop, const char* reason_desc)
{
    log_trace_msg(LOG_TRACE, "start: np_jobargs_t* _np_job_create_args(np_message_t* msg, np_key_t* key, np_msgproperty_t* prop){");

    // optional parameters
    if (NULL != msg)  np_ref_obj(np_message_t, msg, FUNC, reason_desc);
    if (NULL != key)  np_ref_obj(np_key_t, key, FUNC, reason_desc);
    if (NULL != prop) np_ref_obj(np_msgproperty_t, prop, FUNC, reason_desc);

    // create runtime arguments
    np_jobargs_t jargs = {0};
    // np_new_obj(np_jobargs_t, jargs);

    jargs.is_resend = false;
    jargs.msg = msg;
    jargs.target = key;
    jargs.properties = prop;
    jargs.custom_data = NULL;
    return (jargs);
}

void _np_job_free_args(np_state_t* context, np_jobargs_t args)
{
    if (args.target)     np_unref_obj(np_key_t, args.target, "_np_job_create_args");
    if (args.msg)        np_unref_obj(np_message_t, args.msg, "_np_job_create_args");
    if (args.properties) np_unref_obj(np_msgproperty_t, args.properties, "_np_job_create_args");
}

bool _np_job_queue_insert(np_state_t* context, np_job_t new_job)
{	
    NP_PERFORMANCE_POINT_START(jobqueue_insert);
    
    bool ret = false;

    log_debug_msg(LOG_JOBS | LOG_DEBUG, "insert job into jobqueue (%-70s). (property: %45s) (msg: %-36s) (target: %s)", new_job.ident,
        (new_job.args.properties == NULL) ? "-" : new_job.args.properties->msg_subject,
        (new_job.args.msg == NULL) ? "-" : new_job.args.msg->uuid,
        (new_job.args.target == NULL) ? "-" :
          (0 == _np_key_cmp(new_job.args.target, context->my_identity)) ? " == my identity" :
              (0 == _np_key_cmp(new_job.args.target, context->my_node_key)) ? "== my node" :
                _np_key_as_str(new_job.args.target)
    );

    _LOCK_MODULE(np_jobqueue_t)
    {
        // do not add job items that would overflow internal queue size
        bool  overflow = np_module(jobqueue)->job_list->count + np_module(jobqueue)->periodic_jobs + 1 > JOBQUEUE_MAX_SIZE;
        if (overflow && false == new_job.is_periodic) {
            log_msg(LOG_WARN, "Discarding new job(s). Increase JOBQUEUE_MAX_SIZE to prevent missing data");            
            log_debug(LOG_WARN, "Current Threads:\n%s",np_threads_print(context, false));
        } else {
            pheap_insert(np_job_t, np_module(jobqueue)->job_list, new_job);
            ret = true;
        }
    }
    if (ret == false) { log_debug(LOG_WARN, "Discarding Job %s", new_job.ident); }

    _np_jobqueue_check(context);

    NP_PERFORMANCE_POINT_END(jobqueue_insert);
    return ret;
}

void _np_jobqueue_check(np_state_t* context) {	
    
    _np_threads_condition_broadcast(context, &np_module(jobqueue)->__cond_job_queue);	
}

/** (re-)submit message event
 **
 ** get the queue mutex "access",
 ** create a new np_job_t and pass func,args,args_size,
 ** add the new np_job_t to the queue, and
 ** signal the thread pool if the queue was empty.
 **/
void _np_job_resubmit_msgout_event(np_state_t * context, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
    assert(NULL != prop);

    // create runtime arguments
    np_jobargs_t jargs = _np_job_create_args(context, msg, key, prop, FUNC);
    jargs.is_resend = true;

    // create job itself
    np_job_t new_job = _np_job_create_job(context, delay, jargs, JOBQUEUE_PRIORITY_MOD_RESUBMIT_MSG_OUT, prop->clb_outbound, "clb_outbound");

    if (!_np_job_queue_insert(context, new_job)) {
        _np_job_free(context, &new_job);
    }
}


void _np_job_resubmit_route_event(np_state_t * context, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
    assert(NULL != prop);

    // create runtime arguments
    np_jobargs_t jargs = _np_job_create_args(context, msg, key, prop, FUNC);
    jargs.is_resend = true;
    if (msg != NULL) msg->submit_type = np_message_submit_type_DIRECT;
    // create job itself
/*    np_job_t new_job = _np_job_create_job(context, delay, jargs, JOBQUEUE_PRIORITY_MOD_RESUBMIT_ROUTE, prop->clb_route, "clb_route");

    if (!_np_job_queue_insert(context, new_job)) {
        _np_job_free(context, &new_job);
    }
*/
}

bool _np_job_submit_route_event(np_state_t * context, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
    bool ret = true;
    assert(NULL != prop);

    // create runtime arguments
    np_jobargs_t jargs = _np_job_create_args(context, msg, key, prop, FUNC);

    if (msg != NULL) msg->submit_type = np_message_submit_type_ROUTE;

    // create job itself
/*    np_job_t new_job = _np_job_create_job(context, delay, jargs, JOBQUEUE_PRIORITY_MOD_SUBMIT_ROUTE, prop->clb_route, "clb_route");


    if (!_np_job_queue_insert(context, new_job)) {
        ret = false;
        _np_job_free(context, &new_job);
    }
*/
    return ret;
}


bool __np_job_submit_msgin_event(np_state_t * context, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg, void* custom_data, const char* tmp)
{
    bool ret = true;
    // create runtime arguments
    np_jobargs_t jargs = _np_job_create_args(context, msg, key, prop, tmp);
    jargs.custom_data = custom_data;

    if (msg != NULL && prop != NULL) {
        if (msg->msg_property != NULL) {
            np_unref_obj(np_msgproperty_t, msg->msg_property, ref_message_msg_property);
        }
        np_ref_obj(np_msgproperty_t, prop, ref_message_msg_property);
        msg->msg_property = prop;
    }

    // create job itself
    np_job_t new_job = _np_job_create_job(context, delay, jargs, JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_IN, prop->clb_inbound, "clb_inbound");

    if (!_np_job_queue_insert(context, new_job)) {
        _np_job_free(context, &new_job);        
         ret = false;
    }
    return ret;
}

void __np_job_submit_msgin_event_sync(np_state_t * context, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg, void* custom_data, const char* tmp)
{    
    // create runtime arguments
    np_jobargs_t jargs = _np_job_create_args(context, msg, key, prop, tmp);
    jargs.custom_data = custom_data;

    if (msg != NULL && prop != NULL) {
        if (msg->msg_property != NULL) {
            np_unref_obj(np_msgproperty_t, msg->msg_property, ref_message_msg_property);
        }
        np_ref_obj(np_msgproperty_t, prop, ref_message_msg_property);
        msg->msg_property = prop;
    }

    // create job itself
    np_job_t new_job = _np_job_create_job(context, 0, jargs, JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_IN, prop->clb_inbound, "clb_inbound");

    __np_jobqueue_run_once(context, new_job);    
}

bool _np_job_submit_transform_event(np_state_t * context, double delay, np_msgproperty_t* prop, np_key_t* key, void* custom_data)
{
    assert(NULL != prop);
    bool ret = true;
    // create runtime arguments
    np_jobargs_t jargs = _np_job_create_args(context, NULL, key, prop, FUNC);
    jargs.custom_data = custom_data;
    // create job itself
/*    np_job_t new_job = _np_job_create_job(context, delay, jargs, JOBQUEUE_PRIORITY_MOD_TRANSFORM_MSG, prop->clb_transform, "clb_transform");

    if (!_np_job_queue_insert(context, new_job)) {
        _np_job_free(context, &new_job);
        ret = false;
    }
*/
    return ret;
}

void _np_job_submit_msgout_event(np_state_t * context, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
    assert(NULL != prop);
    assert(NULL != msg);

    // create runtime arguments
    np_jobargs_t jargs = _np_job_create_args(context, msg, key, prop, FUNC);

    // create job itself
    np_job_t new_job = _np_job_create_job(context, delay, jargs, JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_OUT, prop->clb_outbound, "clb_outbound");

    if (!_np_job_queue_insert(context, new_job)) {
        _np_job_free(context, &new_job);
    }
}

void np_job_submit_event_periodic(np_state_t * context, double priority, double first_delay, double interval, np_callback_t callback, const char* ident)
{
    log_debug_msg(LOG_JOBS | LOG_DEBUG, "np_job_submit_event_periodic");

    np_sll_t(np_callback_t, callbacks);
    sll_init(np_callback_t, callbacks);
    sll_append(np_callback_t, callbacks, callback);

    np_job_t new_job = _np_job_create_job(context, first_delay, __null_args, priority * JOBQUEUE_PRIORITY_MOD_BASE_STEP, callbacks, ident);
    new_job.type = 2;
    new_job.interval = fmax(NP_SLEEP_MIN, interval);
    new_job.is_periodic = true;
    new_job.__del_processorFuncs = true;

    np_module(jobqueue)->periodic_jobs++;
    if (!_np_job_queue_insert(context, new_job)) {
        _np_job_free(context, &new_job);        
    }
    
}

bool np_job_submit_event(np_state_t* context, double priority, double delay, np_callback_t callback, void* data, const char* ident)
{
    bool ret = true;
    log_debug_msg(LOG_JOBS | LOG_DEBUG, "np_job_submit_event");

    np_sll_t(np_callback_t, callbacks);
    sll_init(np_callback_t, callbacks);
    sll_append(np_callback_t, callbacks, callback);

    np_jobargs_t jargs = _np_job_create_args(context, NULL, NULL, NULL, ident);

    np_job_t new_job = _np_job_create_job(context, delay, jargs, priority * JOBQUEUE_PRIORITY_MOD_BASE_STEP, callbacks, ident);
    new_job.type = 2;
    new_job.is_periodic = false;
    new_job.args.custom_data = data;
    new_job.__del_processorFuncs = true;

    if (!_np_job_queue_insert(context, new_job)) {
        _np_job_free(context, &new_job);
        ret = false;
    }
    return ret;	
}


/** job_queue_create
 *  initiate the queue and thread pool, returns a pointer to the initiated queue.
 **/
bool _np_jobqueue_init(np_state_t * context)
{
    if (!np_module_initiated(jobqueue)) {
        np_module_malloc(jobqueue);

        pheap_init(np_job_t, _module->job_list, JOBQUEUE_MAX_SIZE);

        dll_init(np_thread_ptr, _module->available_workers);

        _module->periodic_jobs = 0;

        _np_threads_mutex_init(context, &_module->available_workers_lock, "available_workers_lock");
        _np_threads_condition_init(context, &_module->__cond_job_queue);
    }
    return (true);
}

void _np_jobqueue_destroy(np_state_t* context) {
    if (np_module_initiated(jobqueue)) {
        np_module_var(jobqueue);
        
        _LOCK_MODULE(np_jobqueue_t)
        {
            np_job_t head;        
            uint16_t count = _module->job_list->count;
            for(uint16_t i=1; i <= count; i++) {
                head =_module->job_list->elements[i].data;            
                log_debug(LOG_MISC | LOG_JOBS, "cleanup of job i:%3"PRIu16" of %"PRIu16" %-50s - tstmp:%f sll_fns:%p prio:%7"PRIu16" count_fns%2"PRIu32" first_fn:%p",
                    i, count, head.ident, 
                    head.exec_not_before_tstamp, head.processorFuncs, 
                    _module->job_list->elements[i].priority,
                    (head.processorFuncs != NULL ? sll_size(head.processorFuncs):0), 
                    (head.processorFuncs != NULL && sll_size(head.processorFuncs)>0?sll_first(head.processorFuncs):NULL)
                );
                _np_job_free(context, &head);
            }
            pheap_free(np_job_t, _module->job_list);
        }
    
        dll_free(np_thread_ptr, _module->available_workers);

        _np_threads_mutex_destroy(context, &_module->available_workers_lock);
        _np_threads_condition_destroy(context, &_module->__cond_job_queue);

        np_module_free(jobqueue);
    }
}
 

void _np_job_yield(np_state_t * context, const double delay)
{
    log_trace_msg(LOG_TRACE, "start: void _np_job_yield(const double delay){");
    if (1 == context->thread_count)
    {
        np_time_sleep(delay);
    }
    else
    {
        // unlock another threads
        _LOCK_MODULE(np_jobqueue_t) {
            _np_jobqueue_check(context);
        }

        _LOCK_MODULE(np_jobqueue_t) {
            if (0.0 != delay)
            {
                // wait for time x to be unlocked again
                _np_threads_module_condition_timedwait(context, &np_module(jobqueue)->__cond_job_queue, np_jobqueue_t_lock, delay);
            }
            else
            {
                // wait for next wakeup signal
                _np_threads_module_condition_wait(context, &np_module(jobqueue)->__cond_job_queue, np_jobqueue_t_lock);
            }
        }
    }
}

/*
  @return the recommended time before calling this function again
*/
double __np_jobqueue_run_jobs_once(np_state_t * context, np_thread_t* my_thread) {

    double ret = NP_JOBQUEUE_MAX_SLEEPTIME_SEC;
    double now = np_time_now();
    bool run_next_job = false;

    np_job_t next_job = { 0 };

    _LOCK_MODULE(np_jobqueue_t)
    {
        if (np_module(jobqueue)->job_list->count > 1)
        {
            next_job = pheap_first(np_job_t, np_module(jobqueue)->job_list);

            // check time of job
            if (now < next_job.exec_not_before_tstamp) {
                ret = fmin(ret, next_job.exec_not_before_tstamp - now);
            } else {
                next_job = pheap_head(np_job_t, np_module(jobqueue)->job_list);
                run_next_job = true;
            }					
        }
    }
    
    if (run_next_job == true) {
        my_thread->job = next_job;
        np_thread_t* self = _np_threads_get_self(context);
        np_threads_busyness(context, self, true);
        __np_jobqueue_run_once(context, next_job);
        np_threads_busyness(context, self, false);
        ret = 0.0;
    }
    
    return ret;
}

void np_jobqueue_run_jobs_for(np_state_t * context, double duration)
{
    double now = np_time_now();
    double end = now + duration;
    double sleep;
    np_thread_t * thread = _np_threads_get_self(context);

    do
    {
        np_threads_busyness(context, thread,true);
        sleep = __np_jobqueue_run_jobs_once(context, thread);        
        np_threads_busyness(context, thread,false);
        if (sleep > 0.0) {            
            _LOCK_MODULE(np_jobqueue_t)
            {
                _np_threads_module_condition_timedwait(context, &np_module(jobqueue)->__cond_job_queue, np_jobqueue_t_lock, sleep);
            }
        }
        now   = np_time_now();
    }while (end > now);
}

void __np_jobqueue_run_jobs(np_state_t* context, np_thread_t* my_thread)
{    
    double sleep = 0.0;
    enum np_status tmp_status;
    while ((tmp_status = np_get_status(context)) != np_shutdown)
    {
        if (tmp_status == np_running) {
            sleep = __np_jobqueue_run_jobs_once(context, my_thread);
            if (sleep > 0.0) {
                // only sleep when there is not much to do (around a dozen periodic jobs could be ok)			
                _LOCK_MODULE(np_jobqueue_t)
                {
                    _np_threads_module_condition_timedwait(context, &np_module(jobqueue)->__cond_job_queue, np_jobqueue_t_lock, sleep);
                }
            }
        }
        else {
            sleep = NP_SLEEP_MIN;
        }

        if (sleep != 0) {
            log_debug_msg(LOG_JOBS, "Job Thread %"PRIu64" now waits %f seconds", my_thread->id, sleep);

            np_time_sleep(sleep);
        }
    }
}

void __np_jobqueue_run_manager(np_state_t *context, np_thread_t* my_thread)
{    
    double now;
    double sleep = NP_PI/100;

    dll_iterator(np_thread_ptr) iter_workers = NULL;
    np_thread_ptr current_worker = NULL;

    np_job_t search_key = { 0 };

    enum np_status tmp_status;
    while ((tmp_status=np_get_status(context)) != np_shutdown)
    {
        np_threads_busyness(context, my_thread,true);

        if (tmp_status == np_running) {
            now = np_time_now();
            
            /*
            _TRYLOCK_ACCESS(&np_module(jobqueue)->available_workers_lock)
            {
                iter_workers = dll_first(np_module(jobqueue)->available_workers);
            }
            // Fist run of manager sleeps
            */			
            if (NULL != iter_workers)
            {

                current_worker = iter_workers->val;
                bool new_worker_job = false;
                np_job_t next_job = { 0 };

                _TRYLOCK_ACCESS(&current_worker->job_lock)
                {
                    if (current_worker->_busy == false) {
                        NP_PERFORMANCE_POINT_START(jobqueue_manager_distribute_job);

                        search_key.search_max_exec_not_before_tstamp = now;
                        search_key.search_min_priority = current_worker->min_job_priority;
                        search_key.search_max_priority = current_worker->max_job_priority;

                        _LOCK_MODULE(np_jobqueue_t)
                        {
                            if(!pheap_is_empty(np_job_t, np_module(jobqueue)->job_list)){
                                next_job = pheap_first(np_job_t, np_module(jobqueue)->job_list);
                                if (next_job.exec_not_before_tstamp <= search_key.search_max_exec_not_before_tstamp &&
                                    (search_key.search_min_priority <= next_job.priority ||
                                        next_job.priority <= search_key.search_max_priority))
                                {
                                    next_job = pheap_head(np_job_t, np_module(jobqueue)->job_list);
                                    new_worker_job = true;
                                }
                                else
                                {
                                    sleep = fmin(sleep, next_job.exec_not_before_tstamp - now);
                                }
                            }
                        }
                        NP_PERFORMANCE_POINT_END(jobqueue_manager_distribute_job);
                    }


                    if (new_worker_job == true) {
                        log_debug_msg(LOG_JOBS, "start   worker thread (%p) job (%s)", current_worker, current_worker->job.ident);
                        current_worker->job = next_job;
                        np_threads_busyness(context, current_worker, true);                        
                        _np_threads_condition_signal(context, &current_worker->job_lock.condition);
                    }
                }
                _LOCK_ACCESS(&np_module(jobqueue)->available_workers_lock)
                {
                    dll_next(iter_workers);                    
                }
                np_threads_busyness_stat(context, my_thread); 
            }
            else
            {                
                // wait for time x to be unlocked again
                _LOCK_MODULE(np_jobqueue_t)
                {
                	//if (sleep > NP_SLEEP_MIN)
                    {
                		log_debug_msg(LOG_JOBS | LOG_VERBOSE, "JobManager waits  for %f sec", sleep);now = np_time_now();

                        np_threads_busyness(context, my_thread, false);
                		// only sleep when there is not much to do (around a dozen periodic jobs could be ok)
                		_np_threads_module_condition_timedwait(
                			context, 
                			&np_module(jobqueue)->__cond_job_queue, 
                			np_jobqueue_t_lock, 
                			fmax(NP_SLEEP_MIN, sleep)
                		);
                		np_threads_busyness(context, my_thread, true);
                		log_debug_msg(LOG_JOBS | LOG_VERBOSE, "JobManager waited for %f sec", np_time_now()-now);
                	}
                }                
                //np_time_sleep(0.005);
                _LOCK_ACCESS(&np_module(jobqueue)->available_workers_lock)
                {
                    iter_workers = dll_first(np_module(jobqueue)->available_workers);
                }
                sleep = NP_PI / 100;
            }
        }
        else {            
            np_time_sleep(0.05);
        }
    }
}

uint32_t np_jobqueue_count(np_state_t * context)
{
    uint32_t ret = 0;

    _LOCK_MODULE(np_jobqueue_t)
    {
        ret = np_module(jobqueue)->job_list->count;
    }
    return ret;
}

void __np_jobqueue_run_once(np_state_t* context, np_job_t job_to_execute)
{	
    //_np_time_update_cache(context);
    // sanity checks if the job list really returned an element
    // if (NULL == job_to_execute) return;
    if (NULL == job_to_execute.processorFuncs) {
        #ifdef NP_THREADS_CHECK_THREADING	
            np_thread_t * self = _np_threads_get_self(context);
            log_warn(LOG_JOBS,
                "thread-->%15"PRIu64" job remaining jobs: %"PRIu32") func_count--> NO FN LIST AVAILABLE args-->%15p prio:%10.2f not before: %15.10f jobname: %s",
                self->id,
                np_jobqueue_count(context),                
                &job_to_execute.args,
                job_to_execute.priority,
                job_to_execute.exec_not_before_tstamp,
                job_to_execute.ident
            );
        #endif
        return;
    }
    if (sll_size(((job_to_execute.processorFuncs))) <= 0) {
        #ifdef NP_THREADS_CHECK_THREADING	
            np_thread_t * self = _np_threads_get_self(context);
            log_warn(LOG_JOBS,
                "thread-->%15"PRIu64" job remaining jobs: %"PRIu32") func_count-->%"PRIu32" funcs--> EMPTY FN LIST %p args-->%15p (prop: %p ) prio:%10.2f not before: %15.10f jobname: %s",
                self->id,
                np_jobqueue_count(context),      
                sll_size((job_to_execute.processorFuncs)),          
                job_to_execute.processorFuncs,
                &job_to_execute.args,
                job_to_execute.args.properties,
                job_to_execute.priority,
                job_to_execute.exec_not_before_tstamp,
                job_to_execute.ident
            );
        #endif
        return;
    }
    NP_PERFORMANCE_POINT_START(jobqueue_run);

    double started_at = np_time_now();

#ifdef NP_THREADS_CHECK_THREADING	
        np_thread_t * self = _np_threads_get_self(context);
        log_debug_msg(LOG_JOBS | LOG_DEBUG,
            "thread-->%15"PRIu64" job remaining jobs: %"PRIu32") func_count-->%"PRIu32" funcs-->%15p ([0] == %15p) args-->%15p prio:%10.2f not before: %15.10f jobname: %s",
            self->id,
            np_jobqueue_count(context),
            sll_size((job_to_execute.processorFuncs)),
            (job_to_execute.processorFuncs),
            sll_first(job_to_execute.processorFuncs),
            &job_to_execute.args,
            job_to_execute.priority,
            job_to_execute.exec_not_before_tstamp,
            job_to_execute.ident
        );
#endif

#ifdef DEBUG
    if (job_to_execute.type == 1) {
        char* msg_uuid = "NULL";
        if (job_to_execute.args.msg != NULL) {
            msg_uuid = job_to_execute.args.msg->uuid;
        }
        // ignore _DEFAULT  property
        if (strcmp(job_to_execute.args.properties->msg_subject, _DEFAULT) != 0)
        {
            log_debug_msg(LOG_JOBS | LOG_DEBUG, "message handler called on subject: %50s msg: %-36s fns: %p", job_to_execute.args.properties->msg_subject, msg_uuid, (job_to_execute.processorFuncs));
        }
    }
#endif

    // do not process if the target is not available anymore (but do process if no target is required at all)
    bool exec_funcs = true;
    if (job_to_execute.args.target != NULL) {
        
        exec_funcs = !job_to_execute.args.target->in_destroy;
    }

    if (exec_funcs && job_to_execute.processorFuncs != NULL) {

#ifdef DEBUG_CALLBACKS
        if (job_to_execute.ident[0] == 0) {
            sprintf(job_to_execute.ident, "%p", (job_to_execute.processorFuncs));
        }

        double n1 = np_time_now();
        log_msg(LOG_JOBS | LOG_DEBUG, "start internal job callback function (@%f) %s", n1, job_to_execute.ident);
#endif

     sll_iterator(np_callback_t) iter = sll_first(job_to_execute.processorFuncs);
     while (iter != NULL)
    {
        if (iter->val != NULL) {
            iter->val(context, job_to_execute.args);
        }
        sll_next(iter);
    }

#ifdef DEBUG_CALLBACKS
        double n2 = np_time_now() - n1;
        _np_statistics_debug_t * stat = _np_statistics_debug_add(context, job_to_execute.ident, n2);
        log_msg(LOG_JOBS | LOG_DEBUG, 
            " functions %-90s(%"PRIu8"), fns: %"PRIu32" duration: %10f, c:%6"PRIu32", %10f / %10f / %10f", 
            stat->key, job_to_execute.type, 
            sll_size(job_to_execute.processorFuncs),
            n2, stat->count, stat->max, stat->avg, stat->min);
#endif

    }

#ifdef DEBUG
    if (job_to_execute.args.msg != NULL) {
        log_debug_msg(LOG_JOBS | LOG_DEBUG, "completed handeling function for msg %s for %s", job_to_execute.args.msg->uuid, _np_message_get_subject(job_to_execute.args.msg));
    }
#endif

    if (job_to_execute.is_periodic == true) {

        job_to_execute.exec_not_before_tstamp = fmax(started_at + job_to_execute.interval, np_time_now());
        if (!_np_job_queue_insert(context, job_to_execute)) {
            abort(); // Catastrophic faliure shuts system down
        }
    } else
    {	// cleanup
        _np_job_free(context, &job_to_execute);
        // job_to_execute = NULL;
    }
    NP_PERFORMANCE_POINT_END(jobqueue_run);

}

void _np_jobqueue_add_worker_thread(np_thread_t* self)
{
    np_ctx_memory(self);
    _LOCK_ACCESS(&np_module(jobqueue)->available_workers_lock)
    {
        log_debug_msg(LOG_JOBS, "Enqueue worker thread (%p) to job (%s)", self, self->job.ident);
        dll_prepend(np_thread_ptr, np_module(jobqueue)->available_workers, self);
    }
}

/** job_exec
 * runs a thread which is competing for jobs in the job queue
 * after getting the first job out of queue it will execute the corresponding callback with
 * defined job arguments
 */
void __np_jobqueue_run_worker(np_state_t* context, np_thread_t* my_thread)
{
    log_debug_msg(LOG_JOBS | LOG_THREADS | LOG_DEBUG, "job queue thread starting");
    
    enum np_status tmp_status;
    while ((tmp_status=np_get_status(context)) != np_shutdown)
    {
        if (tmp_status == np_running) {
            _LOCK_ACCESS(&my_thread->job_lock)
            {
                log_debug_msg(LOG_JOBS, "wait    worker thread (%p) to job (%s)", my_thread, my_thread->job.ident);                
                np_threads_busyness(context, my_thread, false);

                _np_threads_mutex_condition_wait(context, &my_thread->job_lock);
                if(my_thread->_busy == true) {
                    log_debug_msg(LOG_JOBS, "exec    worker thread (%p) to job (%s)", my_thread, my_thread->job.ident);
                    __np_jobqueue_run_once(context, my_thread->job);                
                }
            }
        }
        else {
            np_time_sleep(0);
        }
    }
}

void _np_jobqueue_idle(NP_UNUSED np_state_t* context, NP_UNUSED np_jobargs_t* arg)
{
    np_time_sleep(NP_PI/1000);
}


char* np_jobqueue_print(np_state_t * context, bool asOneLine) {
    char* ret = NULL;
    char* new_line = "\n";
    if (asOneLine == true) {
        new_line = "    ";
    }
#ifdef DEBUG

    ret = np_str_concatAndFree(ret,
        "%4s | %-15s | %-8s | %-5s | %-95s"	"%s",
        "No", "Next exec", "Periodic", "Prio", "Name",
        new_line
    ); 
    _LOCK_MODULE(np_jobqueue_t)
    {
        int i = 1;
        char tmp_time_s[255];
        while (np_module(jobqueue)->job_list->elements[i].sentinel == false && i < 20) {

            np_job_t tmp_job = np_module(jobqueue)->job_list->elements[i].data;
            double tmp_time = tmp_job.exec_not_before_tstamp - np_time_now();
            ret = np_str_concatAndFree(ret,
                "%3"PRId32". | %15s | %8s | %4.1f | %-95s"	"%s",
                i,
                np_util_stringify_pretty(np_util_stringify_time_ms, &tmp_time, tmp_time_s),
                tmp_job.is_periodic? "true" : "false",
                tmp_job.priority / JOBQUEUE_PRIORITY_MOD_BASE_STEP,
                np_util_string_trim_left(tmp_job.ident),
                new_line
            );

            i++;
        }
    }
#else
    ret = np_str_concatAndFree(ret, "Only available in DEBUG");
#endif
    return ret;
}
#ifdef DEBUG
 void _np_jobqueue_print_jobs(np_state_t* context){
    np_job_t head;        
      _LOCK_MODULE(np_jobqueue_t) {
        for(int i=1; i <= np_module(jobqueue)->job_list->count; i++) {
            if(!np_module(jobqueue)->job_list->elements[i].sentinel) {
                head = np_module(jobqueue)->job_list->elements[i].data;
                log_debug(LOG_MISC | LOG_JOBS, "print of job %-50s - @%f ", head.ident, head.exec_not_before_tstamp);            
            }
        }
    }
} 
#endif