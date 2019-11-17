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
#include "util/np_event.h"
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

bool np_job_t_compare(np_job_t i, np_job_t j) 
{
    return (_np_job_compare_job_scheduling(j, i) == -1);
}

uint16_t np_job_t_binheap_get_priority (np_job_t job) 
{
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

    np_mutex_t  available_workers_lock;

    np_pheap_t(np_job_t, job_list);

    np_sll_t(np_thread_ptr, available_workers);
    uint16_t periodic_jobs;
    uint16_t busy_workers;
};

void _np_job_free(np_state_t* context, np_job_t* n)
{
    if(n->__del_processorFuncs) sll_free(np_evt_callback_t, n->processorFuncs);    
}

bool _np_jobqueue_insert(np_state_t* context, np_job_t new_job)
{	
    NP_PERFORMANCE_POINT_START(jobqueue_insert);
    log_debug_msg(LOG_JOBS | LOG_DEBUG, "insert job into jobqueue (%-70s)", new_job.ident);
    
    bool ret = false;
    _LOCK_MODULE(np_jobqueue_t)
    {
        // do not add job items that would overflow internal queue size
        bool overflow = np_module(jobqueue)->job_list->count + np_module(jobqueue)->periodic_jobs + 1 > JOBQUEUE_MAX_SIZE;
            if (overflow && false == new_job.is_periodic) {
            log_msg(LOG_WARN, "Discarding new job(s). Increase JOBQUEUE_MAX_SIZE to prevent missing data");            
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

void _np_jobqueue_check(np_state_t* context) 
{	    
    _np_threads_module_condition_signal(context, np_jobqueue_t_lock);	
}

void np_jobqueue_submit_event_callbacks(np_state_t* context, double delay, np_dhkey_t next, np_util_event_t event, np_sll_t(np_evt_callback_t, callbacks), const char* ident)
{
    log_debug_msg(LOG_JOBS | LOG_DEBUG, "np_jobqueue_submit_event_periodic");

    np_job_t new_job = {};
    new_job.evt      = event;
    new_job.next     = next;
    new_job.priority = JOBQUEUE_PRIORITY_MOD_TRANSFORM_MSG * JOBQUEUE_PRIORITY_MOD_BASE_STEP;
    new_job.exec_not_before_tstamp = np_time_now();
    new_job.type = 2;
    new_job.is_periodic = false;
    new_job.interval = delay;
    new_job.processorFuncs = callbacks;
    new_job.__del_processorFuncs = false;

#ifdef DEBUG
    memset(new_job.ident, 0, 255);
    if (ident != NULL) {
        memcpy(new_job.ident, ident, strnlen(ident, 254));
    }
#endif

    if (!_np_jobqueue_insert(context, new_job)) {
        _np_job_free(context, &new_job);        
    }
}

void np_jobqueue_submit_event_periodic(np_state_t * context, double priority, double first_delay, double interval, np_evt_callback_t callback, const char* ident)
{
    log_debug_msg(LOG_JOBS | LOG_DEBUG, "np_jobqueue_submit_event_periodic");

    np_sll_t(np_evt_callback_t, callbacks);
    sll_init(np_evt_callback_t, callbacks);
    sll_append(np_evt_callback_t, callbacks, callback);

    np_job_t new_job = {};
    new_job.priority = priority * JOBQUEUE_PRIORITY_MOD_BASE_STEP;
    new_job.exec_not_before_tstamp = np_time_now() + (first_delay == 0 ? 0: fmax(NP_SLEEP_MIN, first_delay));
    new_job.type = 2;
    new_job.interval = fmax(NP_SLEEP_MIN, interval);
    new_job.processorFuncs = callbacks;
    new_job.is_periodic = true;
    new_job.__del_processorFuncs = true;

#ifdef DEBUG
    memset(new_job.ident, 0, 255);
    if (ident != NULL) {
        memcpy(new_job.ident, ident, strnlen(ident, 254));
    }
#endif

    np_module(jobqueue)->periodic_jobs++;

    if (!_np_jobqueue_insert(context, new_job)) {
        _np_job_free(context, &new_job);        
    }
}

bool np_jobqueue_submit_event(np_state_t* context, double delay, np_dhkey_t next, np_util_event_t event, const char* ident)
{
    bool ret = true;
    log_debug_msg(LOG_JOBS | LOG_DEBUG, "np_job_submit_event");

    np_job_t new_job = {0};
    
    new_job.evt = event;
    new_job.next = next;
    new_job.type = 1;
    new_job.exec_not_before_tstamp = np_time_now() + delay;
    new_job.priority = JOBQUEUE_PRIORITY_MOD_SUBMIT_ROUTE * JOBQUEUE_PRIORITY_MOD_BASE_STEP;
    new_job.interval = 0;
    new_job.is_periodic = false;
    new_job.processorFuncs = NULL;
    new_job.__del_processorFuncs = false;

#ifdef DEBUG
    memset(new_job.ident, 0, 255);
    memcpy(new_job.ident, ident, strnlen(ident, 254));
#endif

    if (!_np_jobqueue_insert(context, new_job)) {
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

        _module->periodic_jobs = 0;
        _module->busy_workers  = 0;
        sll_init(np_thread_ptr, _module->available_workers);
#ifdef DEBUG
        char mutex_str[64];      
        snprintf(mutex_str, 63, "urn:np:jobqueue:%s", "workers:available");              
        _np_threads_mutex_init(context, &_module->available_workers_lock, mutex_str);
#else
        _np_threads_mutex_init(context, &_module->available_workers_lock, "");
#endif // DEBUG
    }
    return (true);
}

void _np_jobqueue_destroy(np_state_t* context) 
{
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
    
        sll_free(np_thread_ptr, _module->available_workers);

        _np_threads_mutex_destroy(context, &_module->available_workers_lock);

        np_module_free(jobqueue);
    }
}

/*
  @return the recommended time before calling this function again
*/
double __np_jobqueue_run_jobs_once(np_state_t * context, np_thread_t* my_thread) 
{
    double ret = NP_JOBQUEUE_MAX_SLEEPTIME_SEC;
    double now = np_time_now();
    bool run_next_job = false;

    np_job_t next_job = { 0 };

    if (np_get_status(context) > np_uninitialized &&
        np_get_status(context) < np_shutdown      )
    {
        _LOCK_MODULE(np_jobqueue_t)
        {
            if (np_module(jobqueue)->job_list->count > 1)
            {
                next_job = pheap_first(np_job_t, np_module(jobqueue)->job_list);

                // check time of job
                if (now <= next_job.exec_not_before_tstamp) {
                    ret = fmin(ret, next_job.exec_not_before_tstamp - now);
                } else {
                    next_job = pheap_head(np_job_t, np_module(jobqueue)->job_list);
                    run_next_job = true;
                }
            }
        }
        if (run_next_job == true) 
        {
            my_thread->job = next_job;
            np_thread_t* self = _np_threads_get_self(context);
            __np_jobqueue_run_once(context, next_job);
            ret = 0.0;
        }
    }    
    return ret;
}

void np_jobqueue_run_jobs_for(np_state_t * context, double duration)
{
    double now = np_time_now();
    double end = now + duration;
    double sleep = NP_JOBQUEUE_MAX_SLEEPTIME_SEC;
    np_thread_t * thread = _np_threads_get_self(context);

    enum np_status np_runtime_status = np_get_status(context);
    do
    {
        np_threads_busyness(context, thread,true);
        sleep = __np_jobqueue_run_jobs_once(context, thread);        
        np_threads_busyness(context, thread,false);

        now = np_time_now();
        if (sleep > 0.0)
        {
            _LOCK_MODULE(np_jobqueue_t)
            {
                if (now+sleep > end) sleep = end-now;
                _np_threads_module_condition_timedwait(context, np_jobqueue_t_lock, sleep);
            }
        }
        np_runtime_status = np_get_status(context);

    } while (end > now && np_runtime_status > np_uninitialized && np_runtime_status < np_shutdown);
}

/** 
 * runs a thread which is competing for jobs in the job queue
 */
void __np_jobqueue_run_jobs(np_state_t* context, np_thread_t* my_thread)
{    
    double sleep = NP_JOBQUEUE_MAX_SLEEPTIME_SEC;

    sleep = __np_jobqueue_run_jobs_once(context, my_thread);
    if (sleep > 0.0)
    {
        np_threads_busyness(context, my_thread,false);
        _LOCK_MODULE(np_jobqueue_t)
        {
            if (my_thread == sll_first(np_module(jobqueue)->available_workers)->val )
                _np_threads_module_condition_timedwait(context, np_jobqueue_t_lock, sleep);
            else 
                _np_threads_module_condition_wait(context, np_jobqueue_t_lock);
        }
        np_threads_busyness(context, my_thread, true);
    }
}

/** 
 * runs a managed thread which is getting notified if jobs have to executed
 */
void __np_jobqueue_run_worker(np_state_t* context, np_thread_t* my_thread)
{
    np_threads_busyness(context, my_thread, false);

    log_debug_msg(LOG_DEBUG, "wait    worker thread (%p) last job (%s)", my_thread, my_thread->job.ident);            
    _np_threads_mutex_condition_wait(context, &my_thread->job_lock);

    np_threads_busyness(context, my_thread, true);

    log_debug_msg(LOG_DEBUG, "exec    worker thread (%p) to   job (%s)", my_thread, my_thread->job.ident);
    __np_jobqueue_run_once(context, my_thread->job);
}

void __np_jobqueue_run_manager(np_state_t *context, np_thread_t* my_thread)
{    
    double sleep = NP_PI/100;

    log_debug_msg(LOG_JOBS | LOG_VERBOSE, "JobManager waits  for %f sec", sleep);

    double now = np_time_now();

    sll_iterator(np_thread_ptr) iter_workers = NULL;
    _LOCK_ACCESS(&np_module(jobqueue)->available_workers_lock)
    {
        iter_workers = sll_first(np_module(jobqueue)->available_workers);
    }

    np_job_t search_key = { 0 };
    now = np_time_now();

    while (NULL != iter_workers)
    {
        bool new_worker_job = false;
        np_thread_ptr current_worker = iter_workers->val;

        _TRYLOCK_ACCESS(&current_worker->job_lock)
        {
            if (iter_workers->val != my_thread &&
                iter_workers->val->status == np_running)
            {
                NP_PERFORMANCE_POINT_START(jobqueue_manager_distribute_job);

                search_key.search_max_exec_not_before_tstamp = now;
                search_key.search_min_priority = current_worker->min_job_priority;
                search_key.search_max_priority = current_worker->max_job_priority;

                _LOCK_MODULE(np_jobqueue_t)
                {
                    if(!pheap_is_empty(np_job_t, np_module(jobqueue)->job_list)) {
                        np_job_t next_job = pheap_first(np_job_t, np_module(jobqueue)->job_list);
                        if (next_job.exec_not_before_tstamp <= search_key.search_max_exec_not_before_tstamp &&
                            (search_key.search_min_priority <= next_job.priority ||
                                next_job.priority <= search_key.search_max_priority))
                        {
                            current_worker->job = pheap_head(np_job_t, np_module(jobqueue)->job_list);
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
        }

        if (new_worker_job == true) 
        {
            log_debug_msg(LOG_JOBS, "start   worker thread (%p) with job (%s)", current_worker, current_worker->job.ident);
            _np_threads_mutex_condition_signal(context, &current_worker->job_lock);
        } 

        _LOCK_ACCESS(&np_module(jobqueue)->available_workers_lock)
        {
            sll_next(iter_workers);
        }

        np_threads_busyness_stat(context, my_thread);
    }

    np_threads_busyness(context, my_thread, false);
    _LOCK_MODULE(np_jobqueue_t)
    {
        _np_threads_module_condition_timedwait(
            context, 
            np_jobqueue_t_lock, 
            fmax(NP_SLEEP_MIN, sleep)
        );
        log_debug_msg(LOG_JOBS | LOG_VERBOSE, "JobManager waited for %f sec", np_time_now()-now);
    }
    np_threads_busyness(context, my_thread, true);
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
#ifdef NP_THREADS_CHECK_THREADING	
    if (NULL == job_to_execute.processorFuncs) 
    {
        np_thread_t * self = _np_threads_get_self(context);
        log_warn(LOG_JOBS,
            "thread-->%15"PRIu64" job remaining jobs: %"PRIu32") func_count--> NO FN LIST AVAILABLE prio:%10.2f not before: %15.10f jobname: %s",
            self->id,
            np_jobqueue_count(context),                
            job_to_execute.priority,
            job_to_execute.exec_not_before_tstamp,
            job_to_execute.ident
        );
    }
#endif
    
#ifdef NP_THREADS_CHECK_THREADING	
    np_thread_t * self = _np_threads_get_self(context);

    if (NULL != job_to_execute.processorFuncs && 
        sll_size(((job_to_execute.processorFuncs))) <= 0)
    {
        log_warn(LOG_JOBS,
            "thread-->%15"PRIu64" job remaining jobs: %"PRIu32") func_count-->%"PRIu32" funcs--> EMPTY FN LIST %p prio:%10.2f not before: %15.10f jobname: %s",
            self->id,
            np_jobqueue_count(context),      
            sll_size((job_to_execute.processorFuncs)),          
            job_to_execute.processorFuncs,
            job_to_execute.priority,
            job_to_execute.exec_not_before_tstamp,
            job_to_execute.ident
        );
        return;
    }
    else if (NULL != job_to_execute.processorFuncs && 
             sll_size(((job_to_execute.processorFuncs))) > 0)
    {
        log_debug_msg(LOG_JOBS | LOG_DEBUG,
            "thread-->%15"PRIu64" job remaining jobs: %"PRIu32") func_count-->%"PRIu32" funcs-->%15p ([0] == %15p) prio:%10.2f not before: %15.10f jobname: %s",
            self->id,
            np_jobqueue_count(context),
            sll_size((job_to_execute.processorFuncs)),
            (job_to_execute.processorFuncs),
            sll_first(job_to_execute.processorFuncs),
            job_to_execute.priority,
            job_to_execute.exec_not_before_tstamp,
            job_to_execute.ident
        );
    }
#endif

    NP_PERFORMANCE_POINT_START(jobqueue_run);
    double started_at = np_time_now();
    if (job_to_execute.processorFuncs != NULL) 
    {
#ifdef DEBUG_CALLBACKS
        if (job_to_execute.ident[0] == 0) {
            sprintf(job_to_execute.ident, "%p", (job_to_execute.processorFuncs));
        }
        double n1 = np_time_now();
        log_msg(LOG_JOBS | LOG_DEBUG, "start internal job callback function (@%f) %s", n1, job_to_execute.ident);
#endif

        sll_iterator(np_evt_callback_t) iter = sll_first(job_to_execute.processorFuncs);
        while (iter != NULL)
        {
            if (iter->val != NULL) {
                iter->val(context, job_to_execute.evt);
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
    else if (job_to_execute.processorFuncs == NULL) 
    {

#ifdef DEBUG_CALLBACKS
        if (job_to_execute.ident[0] == 0) 
        {
            sprintf(job_to_execute.ident, "%p", (job_to_execute.processorFuncs));
        }
        double n1 = np_time_now();
        log_msg(LOG_JOBS | LOG_DEBUG, "start keycache job callback function (@%f) %s", n1, job_to_execute.ident);
#endif

        _np_keycache_handle_event(context, job_to_execute.next, job_to_execute.evt, false);

#ifdef DEBUG_CALLBACKS
        double n2 = np_time_now() - n1;
        _np_statistics_debug_t * stat = _np_statistics_debug_add(context, job_to_execute.ident, n2);
        log_msg(LOG_JOBS | LOG_DEBUG, 
            " function  %-90s(%"PRIu8"), duration: %10f, c:%6"PRIu32", %10f / %10f / %10f", 
            stat->key, job_to_execute.type, 
            n2, stat->count, stat->max, stat->avg, stat->min);
#endif        
    }

    if (job_to_execute.is_periodic == true) 
    {

        job_to_execute.exec_not_before_tstamp = fmax(started_at + job_to_execute.interval, np_time_now());
        if (!_np_jobqueue_insert(context, job_to_execute)) {
            abort(); // Catastrophic failure - shut down system
        }
    }
    else
    {	// cleanup
        _np_job_free(context, &job_to_execute);
    }
    NP_PERFORMANCE_POINT_END(jobqueue_run);
}

void _np_jobqueue_add_worker_thread(np_thread_t* self)
{
    np_ctx_memory(self);
    _LOCK_ACCESS(&np_module(jobqueue)->available_workers_lock)
    {
        log_debug_msg(LOG_JOBS, "Enqueue worker thread (%p) to job (%s)", self, self->job.ident);
        sll_prepend(np_thread_ptr, np_module(jobqueue)->available_workers, self);
    }
}

void _np_jobqueue_idle(NP_UNUSED np_state_t* context, NP_UNUSED np_util_event_t* arg)
{
    np_time_sleep(0.0);
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