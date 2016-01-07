/**
 *  copyright 2015 pi-lar GmbH
 *  original version was taken from chimera project (MIT licensed), but heavily modified
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_JOBQUEUE_H
#define _NP_JOBQUEUE_H

#include "include.h"

#include "np_key.h"
#include "np_memory.h"

#include "np_container.h"

#ifdef __cplusplus
extern "C" {
#endif

/* job_queue np_job_t structure */
struct np_job_s {

	uint8_t type; // 1=msg handler, 2=internal handler, 4=unknown yet
	char* job_name;
	double tstamp;
	np_callback_t processorFunc;
	np_jobargs_t* args;
	np_job_t* next;
};

/* jobargs structure used to pass type safe structs into the thread context */
struct np_jobargs_s
{
	np_message_t* msg;
	np_msgproperty_t* properties;
	uint8_t is_resend;
	np_key_t* target;
};

/* job_queue structure */
struct np_joblist_s
{
	np_pll_t(np_job_ptr, job_list);

    pthread_mutex_t access;
    pthread_cond_t empty;
};

/** job_queue_create
 *  initiate the queue and thread pool of size "pool_size" returns a pointer
 *  to the initiated queue
 **/
np_joblist_t* job_queue_create ();

np_job_t* job_pull(np_joblist_t* l);
int job_available(np_joblist_t* l);
void np_job_free(np_job_t* job);

/** job_submit
 *  creat a new node and pass "func","args","args_size"
 *  add the new node to the queue
 *  signal the thread pool if the queue was empty
 **/
void job_submit_event (np_joblist_t* job_q, double delay, np_callback_t clb );
void job_resubmit_msg_event (np_joblist_t* job_q, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);
void job_submit_msg_event (np_joblist_t* job_q, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg);

/** job_exec
 * if the queue,"job_q" is empty it would go to sleep and releas the mutex
 *  else get the first job out of queue and execute it.
 **/
void* job_exec (void* state);

#ifdef __cplusplus
}
#endif

#endif // _NP_JOBQUEUE_H
