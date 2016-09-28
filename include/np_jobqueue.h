/**
 *  neuropil is copyright 2015 by pi-lar GmbH
 *  original version was taken from chimera project (MIT licensed), but heavily modified
 **/
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

	np_error_t error_code;
};



/** job_queue_create
 *  initiate the queue and thread pool of size "pool_size" returns a pointer
 *  to the initiated queue
 **/
NP_API_INTERN
np_bool _np_job_queue_create();

/** job_submit
 ** create a new node and pass "func","args","args_size"
 ** add the new node to the queue
 ** signal the thread pool if the queue was empty
 **/
NP_API_EXPORT
void np_job_submit_event (double delay, np_callback_t clb );

NP_API_INTERN
void _np_job_submit_msgout_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

NP_API_INTERN
void _np_job_submit_msgin_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

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

/** job_exec
 ** if the queue,"job_q" is empty it would go to sleep and release the mutex
 ** else get the first job out of queue and execute it.
 **/
NP_API_INTERN
void* _job_exec ();

NP_PLL_GENERATE_PROTOTYPES(np_job_ptr);

#ifdef __cplusplus
}
#endif

#endif // _NP_JOBQUEUE_H
