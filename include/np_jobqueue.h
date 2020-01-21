//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_JOBQUEUE_H
#define _NP_JOBQUEUE_H

#include "np_memory.h"
#include "np_types.h"

#include "np_dhkey.h"
#include "util/np_event.h"

#ifdef __cplusplus
extern "C" {
#endif


/* jobargs structure used to pass type safe structs into the thread context */
typedef np_job_t* np_job_ptr;

/* job_queue np_job_t structure */
struct np_job_s
{
    uint8_t type; // 1=msg handler, 2=internal handler, 4=unknown yet
    double exec_not_before_tstamp;
    double interval;
    bool is_periodic;
    sll_return(np_evt_callback_t) processorFuncs;
    bool __del_processorFuncs;
    np_util_event_t evt;
    np_dhkey_t next;
    double priority;

    double search_min_priority;
    double search_max_priority;
    double search_max_exec_not_before_tstamp;

#ifdef DEBUG
    char ident[255];
#endif
};

/** _np_jobqueue_init
 *  initiate the queue and thread pool of size "pool_size" returns a pointer
 *  to the initiated queue
 **/
NP_API_INTERN
    bool _np_jobqueue_init(np_state_t* context);
NP_API_INTERN 
    void _np_jobqueue_destroy(np_state_t* context);

NP_API_INTERN
    bool _np_jobqueue_insert(np_state_t* context, np_job_t new_job);

NP_API_INTERN
    bool np_jobqueue_submit_event(np_state_t* context, double delay, np_dhkey_t next, np_util_event_t event, const char* ident);
NP_API_INTERN
    void np_jobqueue_submit_event_callbacks(np_state_t* context, double priority, np_dhkey_t next, np_util_event_t event, np_sll_t(np_evt_callback_t, callbacks), const char* ident);
NP_API_INTERN
    void np_jobqueue_submit_event_periodic(np_state_t* context, double delay, double first_delay, double interval, np_evt_callback_t callback, const char* ident);

NP_API_INTERN
    void __np_jobqueue_run_manager(np_state_t* context, np_thread_t* my_thread);
NP_API_INTERN
    void __np_jobqueue_run_worker (np_state_t* context, np_thread_t* my_thread);
NP_API_INTERN
    void __np_jobqueue_run_jobs(np_state_t* context, np_thread_t* my_thread);

NP_API_EXPORT
    void np_jobqueue_run_jobs_for(np_state_t* context, double duration);
NP_API_EXPORT
    double __np_jobqueue_run_jobs_once(np_state_t* context,np_thread_t* my_thread);

NP_API_INTERN
    void __np_jobqueue_run_once(np_state_t* context, np_job_t job_to_execute) ;

NP_API_INTERN
    void _np_jobqueue_check(np_state_t* context);

NP_API_INTERN
    void _np_jobqueue_add_worker_thread(np_thread_t* self);

NP_API_EXPORT
    uint32_t np_jobqueue_count(np_state_t* context);

NP_API_EXPORT
    char* np_jobqueue_print(np_state_t * context, bool asOneLine);

#ifdef DEBUG
NP_API_INTERN
    void _np_jobqueue_print_jobs(np_state_t* context);
#else
    #define _np_jobqueue_print_jobs(context);
#endif

#ifdef __cplusplus
}
#endif

#endif // _NP_JOBQUEUE_H
