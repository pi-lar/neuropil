//
// neuropil is copyright 2016-2017 by pi-lar GmbH
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
typedef int np_error_t;

struct np_jobargs_s
{
	np_message_t* msg;
	np_msgproperty_t* properties;
	uint8_t is_resend;
	np_key_t* target;
	void* custom_data;

	np_error_t error_code;
};

NP_API_INTERN
np_jobargs_t* _np_job_create_args(np_message_t* msg, np_key_t* key, np_msgproperty_t* prop, char* reason_desc);
NP_API_INTERN
void _np_job_free_args(np_jobargs_t* args);

/** _np_job_queue_create
 *  initiate the queue and thread pool of size "pool_size" returns a pointer
 *  to the initiated queue
 **/
NP_API_INTERN
np_bool _np_job_queue_create();

NP_API_INTERN
void _np_job_queue_insert(np_job_t* new_job);

NP_API_EXPORT
void np_job_submit_event_periodic(double priority, double first_delay, double interval, np_callback_t callback, char* ident);

NP_API_INTERN
void _np_job_submit_msgout_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

NP_API_INTERN
void _np_job_submit_msgin_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg, void* custom_data);

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

/** __np_jobqueue_run
 ** if the queue,"job_q" is empty it would go to sleep and release the mutex
 ** else get the first job out of queue and execute it.
 **/
NP_API_INTERN
void* __np_jobqueue_run ();

NP_PLL_GENERATE_PROTOTYPES(np_job_ptr);

#ifdef __cplusplus
}
#endif

#endif // _NP_JOBQUEUE_H
