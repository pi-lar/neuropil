#ifndef _NP_JOBQUEUE_H
#define _NP_JOBQUEUE_H

#include "proton/message.h"

#include "include.h"

#include "key.h"

/* job_queue np_job_t structure */
struct np_job_t {

	int type; // 1=msg handler, 2=internal handler, 4=unknown yet
	char* job_name;
	np_callback_t processorFunc;
	struct np_jobargs_t* args;
	struct np_job_t* next;

};

/* job_queue structure */
struct np_joblist_t
{
	np_job_t* head;
    int size;

    pthread_mutex_t access;
    pthread_cond_t empty;
};

/* queue_queue structure */
struct np_jobargs_t
{
	pn_message_t* msg;
	Key* target;
	np_msgproperty_t* properties;
	char* trace_string;
};


/** job_queue_create:
 ** initiate the queue and thread pool of size "pool_size" returns a pointer
 ** to the initiated queue
 **/
np_joblist_t* job_queue_create ();

np_job_t* job_pull(np_joblist_t* l);
int job_available(np_joblist_t* l);
void np_job_free(np_job_t* job);

/** job_submit: 
 ** creat a new node and pass "func","args","args_size" 
 ** add the new node to the queue
 ** signal the thread pool if the queue was empty
 **/
void job_submit_event (np_joblist_t* job_q, np_callback_t clb );
void job_submit_msg_event (np_joblist_t* job_q, np_msgproperty_t* prop, Key* key, pn_message_t* msg);

/** job_exec:
 ** if the queue,"job_q" is empty it would go to sleep and releas the mutex
 **  else get the first job out of queue and execute it.
 */
void* job_exec (void* state);

#endif // _NP_JOBQUEUE_H
