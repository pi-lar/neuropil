//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "np_jobqueue.h"

#include <assert.h>
#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtime.h"
#include "event/ev.h"

#include "neuropil_log.h"

#include "core/np_comp_alias.h"
#include "core/np_comp_msgproperty.h"
#include "util/np_event.h"
#include "util/np_heap.h"
#include "util/np_list.h"

#include "np_constants.h"
#include "np_eventqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_route.h"
#include "np_settings.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_time.h"
#include "np_types.h"

int8_t _np_job_compare_job_scheduling(np_job_t job1, np_job_t new_job) {
  int8_t ret = 0;
  if (job1.exec_not_before_tstamp > new_job.exec_not_before_tstamp) {
    ret = -1;
  } else if (job1.exec_not_before_tstamp < new_job.exec_not_before_tstamp) {
    ret = 1;
  } else {
    if (job1.priority > new_job.priority) ret = -1;
    else if (job1.priority < new_job.priority) ret = 1;
  }

  return (ret);
}

bool np_job_t_compare(np_job_t i, np_job_t j) {
  return (_np_job_compare_job_scheduling(j, i) == -1);
}

size_t np_job_t_binheap_get_priority(np_job_t job) {
  return (size_t)job.priority;
}

NP_BINHEAP_GENERATE_PROTOTYPES(np_job_t);

NP_BINHEAP_GENERATE_IMPLEMENTATION(np_job_t);

struct np_jobqueue_job_list {
  np_mutex_t job_list_lock;
  np_pheap_t(np_job_t, job_list);
};

/* job_queue structure */
np_module_struct(jobqueue) {
  np_state_t *context;

  TSP(np_sll_t(np_thread_ptr, ), available_workers);
  struct np_jobqueue_job_list job_queues[NP_PRIORITY_MAX_QUEUES + 1];
  // TSP( np_pheap_t(np_job_t, ), job_list);
  TSP(uint16_t, periodic_jobs);
};

void _np_job_free(np_state_t *context, np_job_t *n) {
  if (n->evt.user_data != NULL) {
    np_unref_obj(np_unknown_t, n->evt.user_data, "np_jobqueue_submit_event");
  }
  if (n->__del_processorFuncs != NULL)
    sll_free(np_evt_callback_t, n->processorFuncs);
}
/**
 * @brief Selects the next job to execute for a given max prio thread.
 *
 * @param[in] context The application context.
 * @param[out] buffer The job to execute if the return value is 0.
 * @param[in] max_prio max prio to search for.
 * @param[in] now Current timestamp.
 * @return double the time to sleep if no job is found. 0 if a job is copied
 * into buffer.
 */
double __np_jobqueue_select_job_to_run(np_state_t *context,
                                       np_job_t   *buffer,
                                       size_t      max_prio,
                                       double      now) {

  ASSERT(max_prio <= NP_PRIORITY_MAX_QUEUES, "");
  double ret  = NP_PI / 100;
  bool   stop = false;
  for (int queue_idx = 0; queue_idx <= max_prio; queue_idx++) {
    _TRYLOCK_ACCESS(&np_module(jobqueue)->job_queues[queue_idx].job_list_lock) {
      if (!pheap_is_empty(
              np_job_t,
              np_module(jobqueue)->job_queues[queue_idx].job_list)) {
        np_job_t next_job =
            pheap_first(np_job_t,
                        np_module(jobqueue)->job_queues[queue_idx].job_list);
        if (now <= next_job.exec_not_before_tstamp) {
          ret = fmin(ret, next_job.exec_not_before_tstamp - now);
        } else {
          *buffer =
              pheap_head(np_job_t,
                         np_module(jobqueue)->job_queues[queue_idx].job_list);
          // memcpy(buffer,&next_job,sizeof(np_job_t));
          stop = true;
          ret  = 0;
        }
      }
    }
    if (stop) break;
  }
  // fflush(NULL);
  return ret;
}

bool _np_jobqueue_insert(np_state_t *context,
                         np_job_t    new_job,
                         bool        exec_asap) {
  ASSERT(np_module_initiated(jobqueue),
         "Jobqueue needs to be iniated before we can add things there.");
  ASSERT(new_job.priority <= NP_PRIORITY_MAX_QUEUES,
         "jobs priority does not match a jobqueue.");
  // if there is only the user loop we need to priorize
  // all jobs in one queue as
  if (context->settings->n_threads <= 0) new_job.priority = NP_PRIORITY_HIGHEST;

  NP_PERFORMANCE_POINT_START(jobqueue_insert);

  bool ret = false;
  TSP_GET(uint16_t, np_module(jobqueue)->periodic_jobs, periodic_jobs);
  _LOCK_ACCESS(
      &np_module(jobqueue)->job_queues[new_job.priority].job_list_lock) {
    if (new_job.is_periodic) {
      pheap_insert(np_job_t,
                   np_module(jobqueue)->job_queues[new_job.priority].job_list,
                   new_job);
      ret = true;
    } else {
      // do not add job items that would overflow internal queue size
      if ((np_module(jobqueue)->job_queues[new_job.priority].job_list->count +
           1 /*this job*/) >=
          (np_module(jobqueue)->job_queues[new_job.priority].job_list->size -
           periodic_jobs /*always leave space for the periodic jobs*/)) {
        log_error(
            "Discarding new job(s). Increase JOBQUEUE_MAX_SIZE to prevent "
            "missing data");
      } else {
        pheap_insert(np_job_t,
                     np_module(jobqueue)->job_queues[new_job.priority].job_list,
                     new_job);
        ret = true;
      }
    }
  }

#ifdef DEBUG_CALLBACKS
  if (ret == false) {
    log_error("Discarding Job %s", new_job.ident);
  }
#else
  if (ret == false) {
    log_msg(LOG_WARNING, "Discarding Job. Build with DEBUG for further info.");
  }
#endif

  NP_PERFORMANCE_POINT_END(jobqueue_insert);

  if (ret && exec_asap) _np_jobqueue_check(context);

  return ret;
}

void _np_jobqueue_check(np_state_t *context) {
  _LOCK_MODULE(np_jobqueue_t) {
    _np_threads_module_condition_signal(context, np_jobqueue_t_lock);
  }
}

void np_jobqueue_submit_event_callbacks(np_state_t     *context,
                                        double          delay,
                                        np_dhkey_t      next,
                                        np_util_event_t event,
                                        np_sll_t(np_evt_callback_t, callbacks),
                                        const char *ident) {
  log_debug_msg(LOG_JOBS | LOG_DEBUG, "np_jobqueue_submit_event_callbacks");

  np_job_t new_job               = {};
  new_job.evt                    = event;
  new_job.next                   = next;
  new_job.priority               = JOBQUEUE_PRIORITY_MOD_TRANSFORM_MSG;
  new_job.exec_not_before_tstamp = np_time_now();
  new_job.type                   = 2;
  new_job.is_periodic            = false;
  new_job.interval               = delay;
  new_job.processorFuncs         = callbacks;
  new_job.__del_processorFuncs   = false;

#ifdef DEBUG_CALLBACKS
  ASSERT(ident != NULL && strlen(ident) > 0 && strlen(ident) < 255,
         "You need to define a valid identificator for this job");
  memcpy(new_job.ident, ident, strnlen(ident, 254));
  log_debug(LOG_JOBS, "Created Job %s", new_job.ident);
#endif

  if (!_np_jobqueue_insert(context, new_job, delay == 0)) {
    log_warn(LOG_JOBS, "Dropped callback event");
    _np_job_free(context, &new_job);
  }
}

void np_jobqueue_submit_event_periodic(np_state_t       *context,
                                       size_t            priority,
                                       double            first_delay,
                                       double            interval,
                                       np_evt_callback_t callback,
                                       const char       *ident) {
  log_debug_msg(LOG_JOBS | LOG_DEBUG, "np_jobqueue_submit_event_periodic");

  np_sll_t(np_evt_callback_t, callbacks);
  sll_init(np_evt_callback_t, callbacks);
  sll_append(np_evt_callback_t, callbacks, callback);

  np_job_t new_job = {};
  new_job.priority = priority;
  new_job.exec_not_before_tstamp =
      np_time_now() + (first_delay == 0 ? 0 : fmax(NP_SLEEP_MIN, first_delay));
  new_job.type                 = 2;
  new_job.interval             = fmax(NP_SLEEP_MIN, interval);
  new_job.processorFuncs       = callbacks;
  new_job.is_periodic          = true;
  new_job.__del_processorFuncs = true;

#ifdef DEBUG_CALLBACKS
  ASSERT(ident != NULL && strlen(ident) > 0 && strlen(ident) < 255,
         "You need to define a valid identificator for this job");
  memcpy(new_job.ident, ident, strnlen(ident, 254));
  log_debug(LOG_JOBS, "Created Job %s", new_job.ident);
#endif

  TSP_SET(np_module(jobqueue)->periodic_jobs,
          np_module(jobqueue)->periodic_jobs++);

  if (!_np_jobqueue_insert(context, new_job, first_delay == 0)) {
    _np_job_free(context, &new_job);
  }
}

bool np_jobqueue_submit_event(np_state_t     *context,
                              double          delay,
                              np_dhkey_t      next,
                              np_util_event_t event,
                              const char     *ident) {
  return np_jobqueue_submit_event_with_prio(context,
                                            delay,
                                            next,
                                            event,
                                            ident,
                                            JOBQUEUE_PRIORITY_MOD_SUBMIT_ROUTE);
}
bool np_jobqueue_submit_event_with_prio(np_state_t     *context,
                                        double          delay,
                                        np_dhkey_t      next,
                                        np_util_event_t event,
                                        const char     *ident,
                                        size_t          priority) {
  bool ret = true;
  log_debug_msg(LOG_JOBS | LOG_DEBUG, "np_job_submit_event");

  np_job_t new_job = {0};
  if (event.user_data != NULL) {
    np_ref_obj(np_unknown_t, event.user_data, "np_jobqueue_submit_event");
  }
  new_job.evt                    = event;
  new_job.next                   = next;
  new_job.type                   = 1;
  new_job.exec_not_before_tstamp = np_time_now() + delay;
  new_job.priority               = priority;
  new_job.interval               = 0;
  new_job.is_periodic            = false;
  new_job.processorFuncs         = NULL;
  new_job.__del_processorFuncs   = false;

#ifdef DEBUG_CALLBACKS
  ASSERT(ident != NULL && strlen(ident) > 0 && strlen(ident) < 255,
         "You need to define a valid identificator for this job");
  strncpy(new_job.ident, ident, 255);
  log_debug(LOG_JOBS, "Created Job %s", new_job.ident);
#endif

  if (!_np_jobqueue_insert(context, new_job, delay == 0)) {
    _np_job_free(context, &new_job);
    ret = false;
    log_info(LOG_JOBS, "Dropping job as jobqueue is rejecting it");
  }
  return ret;
}

/** job_queue_create
 *  initiate the queue and thread pool, returns a pointer to the initiated
 *queue.
 **/
bool _np_jobqueue_init(np_state_t *context) {
  if (!np_module_initiated(jobqueue)) {
    np_module_malloc(jobqueue);

    for (int i = 0; i <= NP_PRIORITY_MAX_QUEUES; i++) {
      _np_threads_mutex_init(context,
                             &_module->job_queues[i].job_list_lock,
                             "np:jobqueue:queue");
      pheap_init(np_job_t,
                 _module->job_queues[i].job_list,
                 context->settings->jobqueue_size);
    }
    TSP_INITD(_module->periodic_jobs, 0);

    TSP_INIT(_module->available_workers);
    sll_init(np_thread_ptr, _module->available_workers);

#ifdef DEBUG
    char mutex_str[64];
    snprintf(mutex_str, 63, "urn:np:jobqueue:%s", "workers:available");
#endif // DEBUG
    np_jobqueue_submit_event_periodic(context,
                                      NP_PRIORITY_LOWEST,
                                      180,
                                      180.00,
                                      np_memory_log,
                                      "np_memory_log");
    np_jobqueue_submit_event_periodic(context,
                                      NP_PRIORITY_LOWEST,
                                      0,
                                      60,
                                      __np_route_periodic_log,
                                      "__np_route_periodic_log");

    np_jobqueue_submit_event_periodic(context,
                                      NP_PRIORITY_HIGHEST,
                                      0.10,
                                      10.00,
                                      _np_memory_job_memory_management,
                                      "_np_memory_job_memory_management");
    np_jobqueue_submit_event_periodic(context,
                                      NP_PRIORITY_HIGH,
                                      0.10,
                                      0.250,
                                      _np_alias_cleanup_msgpart_cache,
                                      "_np_alias_cleanup_msgpart_cache");
    np_jobqueue_submit_event_periodic(context,
                                      NP_PRIORITY_HIGH,
                                      MISC_KEYCACHE_CLEANUP_INTERVAL_SEC,
                                      MISC_KEYCACHE_CLEANUP_INTERVAL_SEC,
                                      _np_keycache_exists_state,
                                      "_np_keycache_exists_state");
  }
  return (true);
}

void _np_jobqueue_destroy(np_state_t *context) {
  if (np_module_initiated(jobqueue)) {
    np_module_var(jobqueue);

    for (int queue = 0; queue <= NP_PRIORITY_MAX_QUEUES; queue++) {
      _LOCK_ACCESS(&np_module(jobqueue)->job_queues[queue].job_list_lock) {
        np_job_t head;
        uint16_t count = _module->job_queues[queue].job_list->count;
        for (uint16_t i = 1; i <= count; i++) {
          head = _module->job_queues[queue].job_list->elements[i].data;
          log_debug(
              LOG_MISC | LOG_JOBS,
              "cleanup of queue %" PRId32 " job i:%3" PRIu16 " of %" PRIu16
              " %-50s - tstmp:%f sll_fns:%p prio:%7" PRIsizet
              " count_fns%2" PRIu32 " first_fn:%p",
              queue,
              i,
              count,
              head.ident,
              head.exec_not_before_tstamp,
              head.processorFuncs,
              _module->job_queues[queue].job_list->elements[i].priority,
              (head.processorFuncs != NULL ? sll_size(head.processorFuncs) : 0),
              (head.processorFuncs != NULL && sll_size(head.processorFuncs) > 0
                   ? sll_first(head.processorFuncs)
                   : NULL));
          _np_job_free(context, &head);
        }
        pheap_free(np_job_t, _module->job_queues[queue].job_list);
      }
      TSP_DESTROY(_module->job_queues[queue].job_list);
    }

    np_spinlock_lock(&np_module(jobqueue)->available_workers_lock);
    sll_free(np_thread_ptr, _module->available_workers);
    np_spinlock_unlock(&np_module(jobqueue)->available_workers_lock);
    TSP_DESTROY(np_module(jobqueue)->available_workers);

    np_module_free(jobqueue);
  }
}

/*
  @return the recommended time before calling this function again
*/
double __np_jobqueue_run_jobs_once(np_state_t  *context,
                                   np_thread_t *my_thread) {
  double   ret      = NP_JOBQUEUE_MAX_SLEEPTIME_SEC;
  double   now      = np_time_now();
  np_job_t next_job = {0};

  ret = __np_jobqueue_select_job_to_run(context,
                                        &next_job,
                                        my_thread->max_job_priority,
                                        now);
  if (ret == 0) {
    my_thread->job     = next_job;
    my_thread->has_job = true;
    __np_jobqueue_run_once(context, next_job);
    my_thread->has_job = false;
  }
  return ret;
}

void np_jobqueue_run_jobs_for(np_state_t  *context,
                              np_thread_t *thread,
                              double       duration) {
  double now   = np_time_now();
  double end   = now + duration;
  double sleep = NP_JOBQUEUE_MAX_SLEEPTIME_SEC;

  enum np_status np_runtime_status = np_get_status(context);
  do {
    np_threads_busyness(context, thread, true);
    sleep = __np_jobqueue_run_jobs_once(context, thread);
    np_threads_busyness(context, thread, false);

    now = np_time_now();
    if (sleep > 0.0) {
      _LOCK_MODULE(np_jobqueue_t) {
        if (now + sleep > end) sleep = end - now;
        _np_threads_module_condition_timedwait(context,
                                               np_jobqueue_t_lock,
                                               sleep);
      }
    }
    np_runtime_status = np_get_status(context);

  } while (end > now && np_runtime_status > np_uninitialized &&
           np_runtime_status < np_shutdown);
}

/**
 * runs a thread which is competing for jobs in the job queue
 */
void __np_jobqueue_run_jobs(np_state_t *context, np_thread_t *my_thread) {
  double sleep = __np_jobqueue_run_jobs_once(context, my_thread);

  if (sleep > NP_SLEEP_MIN) {
    np_threads_busyness(context, my_thread, false);
    _LOCK_MODULE(np_jobqueue_t) {
      // if (my_thread->thread_type == np_thread_type_manager){
      _np_threads_module_condition_timedwait(context,
                                             np_jobqueue_t_lock,
                                             sleep);
      //}else{
      //_np_threads_module_condition_wait(context, np_jobqueue_t_lock);
      //}
    }
    np_threads_busyness(context, my_thread, true);
  }
}

/**
 * runs a managed thread which is getting notified if jobs have to executed
 */
// void __np_jobqueue_run_worker(np_state_t* context, np_thread_t* my_thread)
// {
//     // sporadic wakeup protection
//     if (false == my_thread->has_job)
//     {
//         np_threads_busyness(context, my_thread, false);
//         // log_debug_msg(LOG_THREADS, "wait    worker thread (%p) last job
//         (%s)", my_thread, my_thread->job.ident);
//         _np_threads_mutex_condition_wait(context, &my_thread->job_lock);
//         np_threads_busyness(context, my_thread, true);
//     }

//     if (true == my_thread->has_job)
//     {
//         log_debug_msg(LOG_THREADS, "exec    worker thread (%p) to   job
//         (%s)", my_thread, my_thread->job.ident);
//         __np_jobqueue_run_once(context, my_thread->job);
//         my_thread->has_job = false;
//     }
// }
// void __np_jobqueue_run_manager(np_state_t *context, np_thread_t* my_thread)
// {
//     double now = np_time_now();
//     double sleep = NP_PI/100;
//     log_debug_msg(LOG_JOBS, "JobManager enters distribution");

//     sll_iterator(np_thread_ptr) iter_workers = NULL;
//     TSP_SCOPE(np_module(jobqueue)->available_workers)
//     {
//         iter_workers = sll_first(np_module(jobqueue)->available_workers);
//     }
//     if(iter_workers != NULL)
//     {
//         while(true) {
//             now = np_time_now();
//             #ifdef NP_STATISTICS_THREADS
//                 my_thread->run_iterations++;
//             #endif
//             sleep = NP_PI/100;
//             bool do_not_sleep = false;
//             TSP_SCOPE(np_module(jobqueue)->job_list)
//             {
//                 if(!pheap_is_empty(np_job_t, np_module(jobqueue)->job_list))
//                 {
//                     np_job_t next_job = pheap_first(np_job_t,
//                     np_module(jobqueue)->job_list);

//                     if (next_job.exec_not_before_tstamp > now) {
//                         log_debug_msg(LOG_JOBS, "JobManager job waits");
//                         sleep = fmin(sleep, next_job.exec_not_before_tstamp -
//                         np_time_now());
//                     }
//                     else
//                     {
//                         log_debug_msg(LOG_JOBS, "JobManager tries to
//                         distribute job");

//                         NP_PERFORMANCE_POINT_START(jobqueue_manager_distribute_job);
//                         // find a worker
//                         np_thread_ptr best_worker = NULL;

//                         while(iter_workers != NULL) {
//                             np_thread_ptr current_worker = iter_workers->val;

//                             if ((/*current_worker->min_job_priority <=
//                             next_job.priority && */
//                                 next_job.priority <=
//                                 current_worker->max_job_priority)
//                             ) {
//                                 _TRYLOCK_ACCESS(&current_worker->job_lock)
//                                 {
//                                     if( !current_worker->has_job &&
//                                         (   best_worker == NULL ||
//                                             (current_worker->max_job_priority
//                                             < best_worker->max_job_priority)
//                                         )
//                                     ){
//                                         log_debug_msg(LOG_JOBS, "JobManager
//                                         found possible best worker");
//                                         best_worker = current_worker;
//                                     }
//                                 }
//                             }
//                             sll_next(iter_workers);
//                         }

//                         if(best_worker != NULL){
//                             do_not_sleep = true;
//                             _LOCK_ACCESS(&best_worker->job_lock)
//                             {
//                                 // should never happen as long as the manager
//                                 is the only one distibuting jobs
//                                 if(!best_worker->has_job){
//                                     // assign work
//                                     best_worker->job = pheap_head(np_job_t,
//                                     np_module(jobqueue)->job_list);
//                                     best_worker->has_job = true;
//                                     log_debug_msg(LOG_JOBS,
//                                         "JobManager starts worker thread (%p)
//                                         with job (%s)", best_worker,
//                                         best_worker->job.ident
//                                     );
//                                     _np_threads_mutex_condition_signal(context,
//                                     &best_worker->job_lock);
//                                 }
//                             }
//                         }
//                         NP_PERFORMANCE_POINT_END(jobqueue_manager_distribute_job);
//                     }
//                 }
//             }
//             if (!do_not_sleep && sleep > NP_SLEEP_MIN) {
//                 log_debug_msg(LOG_JOBS|LOG_EXPERIMENT, "JobManager waits  for
//                 %f sec", sleep); break;
//             }
//         }
//     }

//     np_threads_busyness(context, my_thread, false);
//     _LOCK_MODULE(np_jobqueue_t)
//     {
//         _np_threads_module_condition_timedwait(
//             context,
//             np_jobqueue_t_lock,
//             fmax(NP_SLEEP_MIN, sleep)
//         );
//         log_debug_msg(LOG_JOBS, "JobManager waited for %f sec",
//         np_time_now()-now);
//     }
//     np_threads_busyness(context, my_thread, true);
// }

uint32_t np_jobqueue_count(np_state_t *context) {
  uint32_t ret = 0;

  for (int queue_idx = 0; queue_idx <= NP_PRIORITY_MAX_QUEUES; queue_idx++) {
    _LOCK_ACCESS(&np_module(jobqueue)->job_queues[queue_idx].job_list_lock) {
      ret += np_module(jobqueue)->job_queues[queue_idx].job_list->count;
    }
  }
  return ret;
}

void __np_jobqueue_run_once(np_state_t *context, np_job_t job_to_execute) {
  //_np_time_update_cache(context);
  // sanity checks if the job list really returned an element
  // if (NULL == job_to_execute) return;
#ifdef NP_THREADS_CHECK_THREADING
  np_thread_t *self = _np_threads_get_self(context);
  if (NULL == job_to_execute.processorFuncs) {
    log_warn(LOG_JOBS,
             "thread-->%15" PRIu64 " job remaining jobs: %" PRIu32
             ") func_count--> NO FN LIST AVAILABLE prio:%10.2f not before: "
             "%15.10f jobname: %s",
             self->id,
             np_jobqueue_count(context),
             job_to_execute.priority,
             job_to_execute.exec_not_before_tstamp,
#ifdef DEBUG
             job_to_execute.ident
#else
             "<only in debug build>"
#endif
    );
  }

  if (NULL != job_to_execute.processorFuncs &&
      sll_size(((job_to_execute.processorFuncs))) == 0) {
    log_warn(LOG_JOBS,
             "thread-->%15" PRIu64 " job remaining jobs: %" PRIu32
             ") func_count-->%" PRIu32
             " funcs--> EMPTY FN LIST %p prio:%10.2f not before: %15.10f "
             "jobname: %s",
             self->id,
             np_jobqueue_count(context),
             sll_size((job_to_execute.processorFuncs)),
             job_to_execute.processorFuncs,
             job_to_execute.priority,
             job_to_execute.exec_not_before_tstamp,
#ifdef DEBUG_CALLBACKS
             job_to_execute.ident
#else
             "<only in debug build>"
#endif
    );
    return;
  } else if (NULL != job_to_execute.processorFuncs &&
             sll_size(((job_to_execute.processorFuncs))) > 0) {
    log_debug(LOG_JOBS,
              "thread-->%15" PRIu64 " job remaining jobs: %" PRIu32
              ") func_count-->%" PRIu32
              " funcs-->%15p ([0] == %15p) prio:%10.2" PRIsizet
              " not before: %15.10f jobname: %s",
              self->id,
              np_jobqueue_count(context),
              sll_size((job_to_execute.processorFuncs)),
              (job_to_execute.processorFuncs),
              sll_first(job_to_execute.processorFuncs),
              job_to_execute.priority,
              job_to_execute.exec_not_before_tstamp,
              job_to_execute.ident);
  }
#else
  log_debug_msg(LOG_JOBS, "executing job '%s'", job_to_execute.ident);
#endif
#ifdef NP_STATISTICS_THREADS
#ifndef NP_THREADS_CHECK_THREADING
  np_thread_t *self = _np_threads_get_self(context);
#endif
  self->run_iterations++;
#endif

  NP_PERFORMANCE_POINT_START(jobqueue_run);
  double started_at = np_time_now();
  if (job_to_execute.processorFuncs != NULL) {
#ifdef DEBUG_CALLBACKS
    if (job_to_execute.ident[0] == 0) {
      snprintf(job_to_execute.ident,
               254,
               "%p",
               (job_to_execute.processorFuncs));
    }
    double n1 = np_time_now();
    log_msg(LOG_JOBS | LOG_DEBUG,
            "start internal job callback function (@%f) %s",
            n1,
            job_to_execute.ident);
#endif

    sll_iterator(np_evt_callback_t) iter =
        sll_first(job_to_execute.processorFuncs);
    while (iter != NULL) {
      if (iter->val != NULL) {
        iter->val(context, job_to_execute.evt);
      }
      sll_next(iter);
    }

#ifdef DEBUG_CALLBACKS
    double                  n2 = np_time_now() - n1;
    _np_statistics_debug_t *stat =
        _np_statistics_debug_add(context, job_to_execute.ident, n2);
    _LOCK_ACCESS(&stat->lock) {

      log_msg(LOG_JOBS | LOG_DEBUG,
              " functions %-90s(%" PRIu8 "), fns: %" PRIu32
              " duration: %10f, c:%6" PRIu32 ", %10f / %10f / %10f",
              stat->key,
              job_to_execute.type,
              sll_size(job_to_execute.processorFuncs),
              n2,
              stat->count,
              stat->max,
              stat->avg,
              stat->min);
    }
#endif

  } else if (job_to_execute.processorFuncs == NULL) {

#ifdef DEBUG_CALLBACKS
    if (job_to_execute.ident[0] == 0) {
      snprintf(job_to_execute.ident,
               254,
               "%p",
               (job_to_execute.processorFuncs));
    }
    double n1 = np_time_now();
    log_msg(LOG_JOBS | LOG_DEBUG,
            "start keycache job callback function (@%f) %s",
            n1,
            job_to_execute.ident);
#endif

#ifdef DEBUG
    if (job_to_execute.evt.user_data != NULL) {
      enum np_memory_types_e _t =
          np_memory_get_type(job_to_execute.evt.user_data);
      if (_t == np_memory_types_np_message_t) {
        log_debug(LOG_DEBUG,
                  "executing job with message %s",
                  ((np_message_t *)job_to_execute.evt.user_data)->uuid);
      }
    }
#endif

    _np_event_runtime_start_with_event(context,
                                       job_to_execute.next,
                                       job_to_execute.evt);

#ifdef DEBUG_CALLBACKS
    double                  n2 = np_time_now() - n1;
    _np_statistics_debug_t *stat =
        _np_statistics_debug_add(context, job_to_execute.ident, n2);
    _LOCK_ACCESS(&stat->lock) {
      log_msg(LOG_JOBS | LOG_DEBUG,
              " function  %-90s(%" PRIu8 "), duration: %10f, c:%6" PRIu32
              ", %10f / %10f / %10f",
              stat->key,
              job_to_execute.type,
              n2,
              stat->count,
              stat->max,
              stat->avg,
              stat->min);
    }
#endif
  } else {
    log_warn(LOG_JOBS,
             "unknown job will not be executed (p: %i / ts: %f / t: %u)",
             job_to_execute.is_periodic,
             job_to_execute.exec_not_before_tstamp,
             job_to_execute.type);
  }

  if (job_to_execute.is_periodic == true) {
    job_to_execute.exec_not_before_tstamp =
        fmax(started_at + job_to_execute.interval, np_time_now());
    if (!_np_jobqueue_insert(context, job_to_execute, false)) {
      log_error("Catastrophic failure in jobqueue handeling");
      ABORT(
          "Catastrophic failure in jobqueue handeling"); // Catastrophic failure
                                                         // - shut down system
    }
  } else { // cleanup
    _np_job_free(context, &job_to_execute);
  }
  NP_PERFORMANCE_POINT_END(jobqueue_run);
}

void _np_jobqueue_add_worker_thread(np_thread_t *self) {
  np_ctx_memory(self);
  np_spinlock_lock(&np_module(jobqueue)->available_workers_lock);
  {
    log_debug_msg(LOG_JOBS,
                  "Enqueue worker thread (%p) to job (%s)",
                  self,
                  self->job.ident);
    sll_prepend(np_thread_ptr, np_module(jobqueue)->available_workers, self);
  }
  np_spinlock_unlock(&np_module(jobqueue)->available_workers_lock);
}

void _np_jobqueue_idle(NP_UNUSED np_state_t      *context,
                       NP_UNUSED np_util_event_t *arg) {
  np_time_sleep(0.0);
}

char *np_jobqueue_print(np_state_t *context, bool asOneLine) {
  char *ret      = NULL;
  char *new_line = "\n";
  if (asOneLine == true) {
    new_line = "    ";
  }

#ifdef DEBUG
  ret = np_str_concatAndFree(
      ret,
      "%5s | %4s  / %5s | %-15s | %-8s | %-8s | %-8s | %-95s"
      "%s",
      "QUEUE",
      "No",
      "Count",
      "Next exec",
      "Periodic",
      "BasePrio",
      "Prio",
      "Name",
      new_line);

  int    element_counter = 1;
  double now             = np_time_now();
  for (int queue_idx = 0; queue_idx <= NP_PRIORITY_MAX_QUEUES; queue_idx++) {
    char tmp_time_s[255];
    _LOCK_ACCESS(&np_module(jobqueue)->job_queues[queue_idx].job_list_lock) {
      int limiter = 0;
      while (limiter < 5) {

        np_job_t tmp_job = np_module(jobqueue)
                               ->job_queues[queue_idx]
                               .job_list->elements[limiter]
                               .data;
        double tmp_time = tmp_job.exec_not_before_tstamp - now;
        if (tmp_time > -999) {
          ret = np_str_concatAndFree(
              ret,
              " %5" PRId32 " | %3" PRId32 ". / %5" PRIu16
              " | %15s | %8s | %8" PRIsizet " | %8" PRIsizet
              " | %-95s"
              "%s",
              queue_idx,
              element_counter++,
              np_module(jobqueue)->job_queues[queue_idx].job_list->count,
              np_util_stringify_pretty(np_util_stringify_time_ms,
                                       &tmp_time,
                                       tmp_time_s),
              tmp_job.is_periodic ? "true" : "false",
              tmp_job.priority,
              np_job_t_binheap_get_priority(tmp_job),
              np_util_string_trim_left(tmp_job.ident),
              new_line);
        }
        limiter++;
      }
    }
  }
#else
  ret = np_str_concatAndFree(ret, "Only available in DEBUG");
#endif
  return ret;
}

#ifdef DEBUG
void _np_jobqueue_print_jobs(np_state_t *context) {
  np_job_t head;
  for (int queue_idx = 0; queue_idx <= NP_PRIORITY_MAX_QUEUES; queue_idx++) {
    _LOCK_ACCESS(&np_module(jobqueue)->job_queues[queue_idx].job_list_lock) {
      for (int i = 1;
           i <= np_module(jobqueue)->job_queues[queue_idx].job_list->count;
           i++) {
        if (!np_module(jobqueue)
                 ->job_queues[queue_idx]
                 .job_list->elements[i]
                 .sentinel) {
          head = np_module(jobqueue)
                     ->job_queues[queue_idx]
                     .job_list->elements[i]
                     .data;
          log_debug(LOG_MISC | LOG_JOBS,
                    "print of job %-50s - @%f ",
                    head.ident,
                    head.exec_not_before_tstamp);
        }
      }
    }
  }
}
#endif
