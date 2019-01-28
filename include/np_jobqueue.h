//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_JOBQUEUE_H
#define _NP_JOBQUEUE_H

#include "np_memory.h"

#include "np_types.h"


#ifdef __cplusplus
extern "C" {
#endif


/* jobargs structure used to pass type safe structs into the thread context */
typedef np_job_t* np_job_ptr;

struct np_jobargs_s
{
    np_message_t* msg;
    np_msgproperty_t* properties;
    uint8_t is_resend;
    np_key_t* target;
    void* custom_data;	
};
/* job_queue np_job_t structure */
struct np_job_s
{
    uint8_t type; // 1=msg handler, 2=internal handler, 4=unknown yet
    double exec_not_before_tstamp;
    double interval;
    bool is_periodic;
    sll_return(np_callback_t) processorFuncs;
    bool __del_processorFuncs;
    np_jobargs_t args;
    double priority;

    double search_min_priority;
    double search_max_priority;
    double search_max_exec_not_before_tstamp;

#ifdef DEBUG
    char ident[255];
#endif
};

NP_API_INTERN
    np_jobargs_t _np_job_create_args(np_state_t* context, np_message_t* msg, np_key_t* key, np_msgproperty_t* prop, const char* reason_desc);

NP_API_INTERN
    void _np_job_free_args(np_state_t* context, np_jobargs_t args);

/** _np_jobqueue_init
 *  initiate the queue and thread pool of size "pool_size" returns a pointer
 *  to the initiated queue
 **/
NP_API_INTERN
    bool _np_jobqueue_init(np_state_t* context);
NP_API_INTERN 
    void _np_jobqueue_destroy(np_state_t* context);

NP_API_INTERN
    bool _np_job_queue_insert(np_state_t* context, np_job_t new_job);

NP_API_INTERN
    void np_job_submit_event_periodic(np_state_t* context, double priority, double first_delay, double interval, np_callback_t callback, const char* ident);

NP_API_INTERN
bool np_job_submit_event(np_state_t* context, double priority, double delay, np_callback_t callback, void* data, const char* ident);


NP_API_INTERN
    void _np_job_submit_msgout_event (np_state_t* context, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

#define _np_job_submit_msgin_event(delay, prop, key, msg, custom_data) __np_job_submit_msgin_event(context, delay, prop, key, msg, custom_data, FUNC)
NP_API_INTERN
    bool __np_job_submit_msgin_event (np_state_t* context, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg, void* custom_data, const char* tmp);

    #define np_job_submit_msgin_event_sync(prop, key, msg, custom_data) __np_job_submit_msgin_event_sync(context, prop, key, msg, custom_data, FUNC)
    NP_API_INTERN
    void __np_job_submit_msgin_event_sync(np_state_t * context, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg, void* custom_data, const char* tmp);

NP_API_INTERN
    bool _np_job_submit_route_event (np_state_t* context, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

NP_API_INTERN
    bool _np_job_submit_transform_event (np_state_t* context, double delay, np_msgproperty_t* prop, np_key_t* key, void* custom_data);

NP_API_INTERN
    void _np_job_resubmit_msgout_event (np_state_t* context, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

NP_API_INTERN
    void _np_job_resubmit_route_event (np_state_t* context, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

NP_API_INTERN
    void _np_job_yield(np_state_t* context, const double delay);

NP_API_INTERN
    void __np_jobqueue_run_worker (np_state_t* context, np_thread_t* my_thread);

NP_API_INTERN
    void __np_jobqueue_run_manager(np_state_t* context, np_thread_t* my_thread);

NP_API_INTERN
    void __np_jobqueue_run_jobs(np_state_t* context, np_thread_t* my_thread);

NP_API_INTERN
    void __np_jobqueue_run_once(np_state_t* context, np_job_t job_to_execute) ;

NP_API_INTERN
    void _np_jobqueue_check(np_state_t* context);

NP_API_INTERN
    void _np_jobqueue_add_worker_thread(np_thread_t* self);

NP_API_INTERN
    void _np_jobqueue_idle(NP_UNUSED np_state_t* context, NP_UNUSED np_jobargs_t* arg);

NP_API_EXPORT
    uint32_t np_jobqueue_count(np_state_t* context);

NP_API_EXPORT
    char* np_jobqueue_print(np_state_t * context, bool asOneLine);
NP_API_EXPORT
void np_jobqueue_run_jobs_for(np_state_t* context, double duration);
NP_API_EXPORT
double __np_jobqueue_run_jobs_once(np_state_t* context,np_thread_t* my_thread);


#ifdef DEBUG
NP_API_INTERN
void _np_jobqueue_print_jobs(np_state_t* context);
#else
    #define  _np_jobqueue_print_jobs(context);
#endif

NP_PLL_GENERATE_PROTOTYPES(np_job_ptr);

#ifdef __cplusplus
}
#endif

#endif // _NP_JOBQUEUE_H
