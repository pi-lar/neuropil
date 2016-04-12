/**
 *  copyright 2015 pi-lar GmbH
 *  original version was taken from chimera project (MIT licensed), but heavily modified
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_JOBQUEUE_H
#define _NP_JOBQUEUE_H

#include "include.h"

#include "np_keycache.h"
#include "np_memory.h"

#include "np_container.h"


#ifdef __cplusplus
extern "C" {
#endif


/* jobargs structure used to pass type safe structs into the thread context */
struct np_jobargs_s
{
	np_message_t* msg;
	np_msgproperty_t* properties;
	uint8_t is_resend;
	np_key_t* target;
};

/** job_queue_create
 *  initiate the queue and thread pool of size "pool_size" returns a pointer
 *  to the initiated queue
 **/
np_bool _np_job_queue_create();

/** job_submit
 ** create a new node and pass "func","args","args_size"
 ** add the new node to the queue
 ** signal the thread pool if the queue was empty
 **/
void np_job_submit_event (double delay, np_callback_t clb );
void np_job_submit_msg_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

void _np_job_resubmit_msg_event (double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

/** job_exec
 ** if the queue,"job_q" is empty it would go to sleep and release the mutex
 ** else get the first job out of queue and execute it.
 **/
void* _job_exec (void* state);

#ifdef __cplusplus
}
#endif

#endif // _NP_JOBQUEUE_H
