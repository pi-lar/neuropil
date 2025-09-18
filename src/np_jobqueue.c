//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
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

/* job_queue np_job_t structure */
struct np_job_s {
  uint8_t         type; // 1=msg handler, 2=internal handler, 4=unknown yet
  double          exec_not_before_tstamp;
  double          interval;
  bool            is_periodic;
  np_util_event_t evt;
  np_dhkey_t      next;

  size_t priority;
  double search_min_priority;
  double search_max_priority;

  double search_max_exec_not_before_tstamp;

  bool __del_processorFuncs;
  sll_return(np_evt_callback_t) processorFuncs;

#ifdef DEBUG_CALLBACKS
  char ident[255];
#endif
};

typedef struct np_job_s np_job_t;

int8_t _np_job_compare_job_scheduling(np_job_t new_job, np_job_t old_job) {
  int8_t ret = 0;
  if (old_job.exec_not_before_tstamp > new_job.exec_not_before_tstamp) {
    ret = -1;
  } else if (old_job.exec_not_before_tstamp < new_job.exec_not_before_tstamp) {
    ret = 1;
  } else {
    if (old_job.priority > new_job.priority) ret = -1;
    else if (old_job.priority < new_job.priority) ret = 1;
  }

  return (ret);
}

bool np_job_t_compare(np_job_t new_job, np_job_t old_job) {
  return (_np_job_compare_job_scheduling(new_job, old_job) == -1);
}

size_t np_job_t_binheap_get_priority(np_job_t job) {
  return (size_t)job.priority;
}

NP_BINHEAP_GENERATE_PROTOTYPES(np_job_t);

NP_BINHEAP_GENERATE_IMPLEMENTATION(np_job_t);

struct np_jobqueue_job_list {
  np_spinlock_t job_list_lock;
  np_pheap_t(np_job_t, job_list);
};

/* job_queue structure */
np_module_struct(jobqueue) {
  np_state_t *context;

  TSP(np_sll_t(np_thread_ptr, ), available_workers);
  struct np_jobqueue_job_list job_queues[NP_PRIORITY_MAX_QUEUES];
  double                      next_job_schedule[NP_PRIORITY_MAX_QUEUES];
  TSP(uint16_t, periodic_jobs);
};

void _np_job_free(np_state_t *context, np_job_t *n) {
  if (n->evt.user_data != NULL) {
    np_unref_obj(np_unknown_t, n->evt.user_data, "np_jobqueue_submit_event");
  }
  if (n->__del_processorFuncs) sll_free(np_evt_callback_t, n->processorFuncs);
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
                                       double      now) {

  double ret                        = NP_JOBQUEUE_MAX_SLEEPTIME_SEC;
  int8_t queue_index                = -1;
  double lowest_next_execution_time = now + 9.0f;

  for (size_t queue_idx = 0; queue_idx < NP_PRIORITY_MAX_QUEUES; queue_idx++) {
    // find the job with the lowest next execution time across all queues
    if (np_spinlock_trylock(
            &np_module(jobqueue)->job_queues[queue_idx].job_list_lock)) {

      if (np_module(jobqueue)->next_job_schedule[queue_idx] < now &&
          !pheap_is_empty(
              np_job_t,
              np_module(jobqueue)->job_queues[queue_idx].job_list)) {
        queue_index = np_module(jobqueue)->next_job_schedule[queue_idx] <
                              lowest_next_execution_time
                          ? queue_idx
                          : queue_index;
        lowest_next_execution_time =
            np_module(jobqueue)->next_job_schedule[queue_idx] <
                    lowest_next_execution_time
                ? np_module(jobqueue)->next_job_schedule[queue_idx]
                : lowest_next_execution_time;
      }
      np_spinlock_unlock(
          &np_module(jobqueue)->job_queues[queue_idx].job_list_lock);
    }
  }
  // calculate max sleep time
  ret = ((lowest_next_execution_time - now) < ret)
            ? lowest_next_execution_time - now
            : ret;

  if (queue_index >= 0) {
    // if we have an index, select the top job from it and return it
    np_spinlock_lock(
        &np_module(jobqueue)->job_queues[queue_index].job_list_lock);
    {
      if (!pheap_is_empty(
              np_job_t,
              np_module(jobqueue)->job_queues[queue_index].job_list)) {
        *buffer =
            pheap_head(np_job_t,
                       np_module(jobqueue)->job_queues[queue_index].job_list);
        if (!pheap_is_empty(
                np_job_t,
                np_module(jobqueue)->job_queues[queue_index].job_list)) {
          np_module(jobqueue)->next_job_schedule[queue_index] =
              pheap_first(np_job_t,
                          np_module(jobqueue)->job_queues[queue_index].job_list)
                  .exec_not_before_tstamp;
        } else {
          np_module(jobqueue)->next_job_schedule[queue_index] = 0.0;
        }
        ret = 0.0;
      }
    }
    np_spinlock_unlock(
        &np_module(jobqueue)->job_queues[queue_index].job_list_lock);
  }

  return ret;
}

bool _np_jobqueue_insert(np_state_t *context,
                         np_job_t    new_job,
                         bool        exec_asap) {

  ASSERT(np_module_initiated(jobqueue),
         "Jobqueue needs to be initiated before we can add things there.");

  bool    ret       = false;
  uint8_t queue_idx = new_job.is_periodic ? 0 : 1;

  np_spinlock_lock(&np_module(jobqueue)->job_queues[queue_idx].job_list_lock);
  {
    // do not add job items that would overflow internal queue size
    if ((np_module(jobqueue)->job_queues[queue_idx].job_list->count +
         1 /*this job*/) >= JOBQUEUE_MAX_SIZE) {
      log_error(NULL,
                "%s",
                "Discarding new job(s). Increase JOBQUEUE_MAX_SIZE to prevent "
                "missing data");
    } else {
      pheap_insert(np_job_t,
                   np_module(jobqueue)->job_queues[queue_idx].job_list,
                   new_job);
      np_module(jobqueue)->next_job_schedule[queue_idx] =
          pheap_first(np_job_t,
                      np_module(jobqueue)->job_queues[queue_idx].job_list)
              .exec_not_before_tstamp;
      ret = true;
    }
  }
  np_spinlock_unlock(&np_module(jobqueue)->job_queues[queue_idx].job_list_lock);

#ifdef DEBUG_CALLBACKS
  if (ret == false) {
    log_error(NULL, "Discarding Job %s", new_job.ident);
  }
#else
  if (ret == false) {
    log_msg(LOG_WARNING,
            NULL,
            "Discarding Job. Build with DEBUG for further info.");
  }
#endif

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
  ASSERT(ident != NULL && strnlen(ident, 256) > 0 && strnlen(ident, 256) < 255,
         "You need to define a valid identificator for this job");
  strncpy(new_job.ident, ident, strnlen(ident, 254));
  log_debug(LOG_JOBS, NULL, "Created Job %s", new_job.ident);
#endif

  if (!_np_jobqueue_insert(context, new_job, delay == 0)) {
    log_warn(LOG_JOBS, NULL, "Dropped callback event");
    _np_job_free(context, &new_job);
  }
}

void np_jobqueue_submit_event_periodic(np_state_t       *context,
                                       size_t            priority,
                                       double            first_delay,
                                       double            interval,
                                       np_evt_callback_t callback,
                                       const char       *ident) {

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
  ASSERT(ident != NULL && strnlen(ident, 256) > 0 && strnlen(ident, 256) < 255,
         "You need to define a valid identificator for this job");
  memcpy(new_job.ident, ident, strnlen(ident, 254));
  log_debug(LOG_JOBS, NULL, "Created Job %s", new_job.ident);
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
  ASSERT(ident != NULL && strnlen(ident, 256) > 0 && strnlen(ident, 256) < 255,
         "You need to define a valid identificator for this job");
  strncpy(new_job.ident, ident, 255);
  log_debug(LOG_JOBS, NULL, "Created Job %s", new_job.ident);
#endif

  if (!_np_jobqueue_insert(context, new_job, delay == 0)) {
    _np_job_free(context, &new_job);
    ret = false;
    log_info(LOG_JOBS, NULL, "Dropping job as jobqueue is rejecting it");
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

    for (int queue_idx = 0; queue_idx < NP_PRIORITY_MAX_QUEUES; queue_idx++) {
      np_spinlock_init(&_module->job_queues[queue_idx].job_list_lock,
                       PTHREAD_PROCESS_PRIVATE);
      pheap_init(np_job_t,
                 _module->job_queues[queue_idx].job_list,
                 context->settings->jobqueue_size);
      _module->next_job_schedule[queue_idx] = 0.0;
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
                                      0.100,
                                      _np_memory_job_memory_management,
                                      "_np_memory_job_memory_management");
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

    for (int queue_idx = 0; queue_idx < NP_PRIORITY_MAX_QUEUES; queue_idx++) {
      np_spinlock_lock(
          &np_module(jobqueue)->job_queues[queue_idx].job_list_lock);
      {
        np_job_t head;
        uint16_t count = _module->job_queues[queue_idx].job_list->count;
        for (uint16_t i = 1; i <= count; i++) {
          head = _module->job_queues[queue_idx].job_list->elements[i].data;
          log_debug(
              LOG_MISC | LOG_JOBS,
              NULL,
              "cleanup of queue %" PRId32 " job i:%3" PRIu16 " of %" PRIu16
              " %-50s - tstmp:%f sll_fns:%p prio:%7" PRIsizet
              " count_fns%2" PRIu32 " first_fn:%p",
              queue_idx,
              i,
              count,
              head.ident,
              head.exec_not_before_tstamp,
              head.processorFuncs,
              _module->job_queues[queue_idx].job_list->elements[i].priority,
              (head.processorFuncs != NULL ? sll_size(head.processorFuncs) : 0),
              (head.processorFuncs != NULL && sll_size(head.processorFuncs) > 0
                   ? sll_first(head.processorFuncs)
                   : NULL));
          _np_job_free(context, &head);
        }
        pheap_free(np_job_t, _module->job_queues[queue_idx].job_list);
      }
      np_spinlock_unlock(
          &np_module(jobqueue)->job_queues[queue_idx].job_list_lock);
      np_spinlock_destroy(
          &np_module(jobqueue)->job_queues[queue_idx].job_list_lock);
    }

    np_spinlock_lock(&np_module(jobqueue)->available_workers_lock);
    sll_free(np_thread_ptr, _module->available_workers);
    np_spinlock_unlock(&np_module(jobqueue)->available_workers_lock);
    TSP_DESTROY(np_module(jobqueue)->available_workers);

    np_module_free(jobqueue);
  }
}

void __np_jobqueue_run_once(np_state_t *context, np_job_t job_to_execute) {
  //_np_time_update_cache(context);
  // sanity checks if the job list really returned an element
  // if (NULL == job_to_execute) return;
#ifdef NP_THREADS_CHECK_THREADING
  np_thread_t *self = _np_threads_get_self(context);
  if (NULL == job_to_execute.processorFuncs) {
    log_warn(LOG_JOBS,
             NULL,
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
             NULL,
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
              NULL,
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
  log_debug(LOG_JOBS, NULL, "executing job '%s'", job_to_execute.ident);
#endif

#ifdef NP_STATISTICS_THREADS
#ifndef NP_THREADS_CHECK_THREADING
  np_thread_t *self = _np_threads_get_self(context);
#endif
  self->run_iterations++;
#endif

  double started_at = np_time_now();
  if (job_to_execute.processorFuncs != NULL) {

#ifdef DEBUG_CALLBACKS
    if (job_to_execute.ident[0] == 0) {
      snprintf(job_to_execute.ident,
               254,
               "%p",
               (job_to_execute.processorFuncs));
    }
    log_msg(LOG_JOBS | LOG_DEBUG,
            NULL,
            "start internal job callback function (@%f) %s",
            started_at,
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
    double                  n2 = np_time_now() - started_at;
    _np_statistics_debug_t *stat =
        _np_statistics_debug_add(context, job_to_execute.ident, n2);
    _LOCK_ACCESS(&stat->lock) {

      log_msg(LOG_JOBS | LOG_DEBUG,
              NULL,
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
    log_msg(LOG_JOBS | LOG_DEBUG,
            NULL,
            "start keycache job callback function (@%f) %s",
            started_at,
            job_to_execute.ident);
#endif

#ifdef DEBUG
    if (job_to_execute.evt.user_data != NULL) {
      enum np_memory_types_e _t =
          np_memory_get_type(job_to_execute.evt.user_data);
      if (_t == np_memory_types_np_message_t) {
        log_trace(LOG_DEBUG,
                  ((np_message_t *)job_to_execute.evt.user_data)->uuid,
                  "executing job with message");
      }
    }
#endif

    _np_event_runtime_start_with_event(context,
                                       job_to_execute.next,
                                       job_to_execute.evt);

#ifdef DEBUG_CALLBACKS
    double                  n2 = np_time_now() - started_at;
    _np_statistics_debug_t *stat =
        _np_statistics_debug_add(context, job_to_execute.ident, n2);
    _LOCK_ACCESS(&stat->lock) {
      log_msg(LOG_JOBS | LOG_DEBUG,
              NULL,
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
             NULL,
             "unknown job will not be executed (p: %i / ts: %f / t: %u)",
             job_to_execute.is_periodic,
             job_to_execute.exec_not_before_tstamp,
             job_to_execute.type);
  }

  if (job_to_execute.is_periodic == true) {
    job_to_execute.exec_not_before_tstamp =
        fmax(started_at + job_to_execute.interval, started_at);
    if (!_np_jobqueue_insert(context, job_to_execute, false)) {
      ABORT("Catastrophic failure in jobqueue handling"); // Catastrophic
                                                          // failure
                                                          // - shut down system
    }
  } else { // cleanup
    _np_job_free(context, &job_to_execute);
  }
}

/*
  @return the recommended time before calling this function again
*/
double __np_jobqueue_run_jobs_once(np_state_t  *context,
                                   np_thread_t *my_thread,
                                   double       now) {
  np_job_t next_job = {0};

  double ret = __np_jobqueue_select_job_to_run(context, &next_job, now);
  if (ret == 0) {
    np_threads_busyness(context, my_thread, true);
    __np_jobqueue_run_once(context, next_job);
    np_threads_busyness(context, my_thread, false);
  }

  return ret;
}

void np_jobqueue_run_jobs_for(np_state_t  *context,
                              np_thread_t *my_thread,
                              double       duration) {
  double now   = np_time_now();
  double end   = now + duration;
  double sleep = NP_JOBQUEUE_MAX_SLEEPTIME_SEC;

  enum np_status np_runtime_status = np_uninitialized;
  do {
    sleep = __np_jobqueue_run_jobs_once(context, my_thread, now);

    if (sleep > NP_SLEEP_MIN && duration > 0.0) {
      _LOCK_MODULE(np_jobqueue_t) {
        _np_threads_module_condition_timedwait(context,
                                               np_jobqueue_t_lock,
                                               sleep);
      }
    }
    np_runtime_status = np_get_status(context);
    now               = np_time_now();
  } while (end > now && np_runtime_status > np_uninitialized &&
           np_runtime_status < np_shutdown);
}

/**
 * runs a thread which is competing for jobs in the job queue
 */
void __np_jobqueue_run_jobs(np_state_t *context, np_thread_t *my_thread) {

  double now   = np_time_now();
  double sleep = __np_jobqueue_run_jobs_once(context, my_thread, now);
  if (sleep > NP_SLEEP_MIN) {
    _LOCK_MODULE(np_jobqueue_t) {
      if (my_thread->thread_type == np_thread_type_manager) {
        _np_threads_module_condition_timedwait(context,
                                               np_jobqueue_t_lock,
                                               sleep);
      } else {
        _np_threads_module_condition_wait(context, np_jobqueue_t_lock);
      }
    }
  }
}

uint32_t np_jobqueue_count(np_state_t *context) {
  uint32_t ret = 0;

  for (int queue_idx = 0; queue_idx < NP_PRIORITY_MAX_QUEUES; queue_idx++) {
    np_spinlock_lock(&np_module(jobqueue)->job_queues[queue_idx].job_list_lock);
    {
      ret += np_module(jobqueue)->job_queues[queue_idx].job_list->count;
    }
    np_spinlock_unlock(
        &np_module(jobqueue)->job_queues[queue_idx].job_list_lock);
  }
  return ret;
}

void _np_jobqueue_add_worker_thread(np_thread_t *self) {
  np_ctx_memory(self);
  np_spinlock_lock(&np_module(jobqueue)->available_workers_lock);
  {
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
  for (int queue_idx = 0; queue_idx < NP_PRIORITY_MAX_QUEUES; queue_idx++) {
    char tmp_time_s[255];
    np_spinlock_lock(&np_module(jobqueue)->job_queues[queue_idx].job_list_lock);
    {
      int limiter = 0;
      while (limiter < 11) {

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
              np_util_string_trim_left(tmp_job.ident, 255),
              new_line);
        }
        limiter++;
      }
    }
    np_spinlock_unlock(
        &np_module(jobqueue)->job_queues[queue_idx].job_list_lock);
  }
#else
  ret = np_str_concatAndFree(ret, "Only available in DEBUG");
#endif
  return ret;
}

#ifdef DEBUG
void _np_jobqueue_print_jobs(np_state_t *context) {
  np_job_t head;
  for (int queue_idx = 0; queue_idx < NP_PRIORITY_MAX_QUEUES; queue_idx++) {
    np_spinlock_lock(&np_module(jobqueue)->job_queues[queue_idx].job_list_lock);
    {
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
    np_spinlock_unlock(
        &np_module(jobqueue)->job_queues[queue_idx].job_list_lock);
  }
}
#endif
