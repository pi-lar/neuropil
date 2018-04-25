//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_JOBQUEUE_H
#define _NP_JOBQUEUE_H

#include "np_memory.h"
#include "np_memory_v2.h"
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

NP_API_INTERN
	np_jobargs_t* _np_job_create_args(np_message_t* msg, np_key_t* key, np_msgproperty_t* prop, const char* reason_desc);

NP_API_INTERN
	void _np_job_free_args(np_jobargs_t* args);

/** _np_job_queue_create
 *  initiate the queue and thread pool of size "pool_size" returns a pointer
 *  to the initiated queue
 **/
NP_API_INTERN
	np_bool _np_job_queue_create();

NP_API_INTERN
	np_bool _np_job_queue_insert(np_job_t* new_job);

NP_API_INTERN
	void _np_job_resubmit_msgin_event(double delay, np_jobargs_t* jargs_org);

NP_API_EXPORT
	void np_job_submit_event_periodic(double priority, double first_delay, double interval, np_callback_t callback, const char* ident);

NP_API_INTERN
	void _np_job_submit_msgout_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

#define _np_job_submit_msgin_event(delay, prop, key, msg, custom_data) __np_job_submit_msgin_event(delay, prop, key, msg, custom_data, __func__)
NP_API_INTERN
	np_bool __np_job_submit_msgin_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg, void* custom_data, const char* tmp);

NP_API_INTERN
	void _np_job_submit_route_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

NP_API_INTERN
	void _np_job_submit_transform_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

NP_API_INTERN
	void _np_job_resubmit_msgout_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

NP_API_INTERN
	void _np_job_resubmit_route_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

NP_API_INTERN
	void _np_job_yield(const double delay);

NP_API_INTERN
	void* __np_jobqueue_run_worker (void* np_thread_ptr);

NP_API_INTERN
	void* __np_jobqueue_run_manager(void* np_thread_ptr_self);

NP_API_INTERN
	void* __np_jobqueue_run_jobs(void* np_thread_ptr_self);

NP_API_INTERN
	void __np_jobqueue_run_once(np_job_t* job_to_execute);

NP_API_INTERN
	void _np_jobqueue_check();

NP_API_INTERN
	void _np_jobqueue_add_worker_thread(np_thread_t* self);

NP_API_EXPORT
	uint32_t np_jobqueue_count();

NP_PLL_GENERATE_PROTOTYPES(np_job_ptr);

#ifdef __cplusplus
}
#endif

#endif // _NP_JOBQUEUE_H
