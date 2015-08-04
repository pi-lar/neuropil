#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>

#include "np_jobqueue.h"

#include "include.h"
#include "neuropil.h"
#include "np_memory.h"
#include "np_message.h"
#include "log.h"



void np_job_free (np_job_t * n)
{
    free (n);
}

/** get the queue mutex "access",
 ** create a new np_job_t and pass func,args,args_size,
 ** add the new np_job_t to the queue, and
 ** signal the thread pool if the queue was empty.
 **/
void job_submit_msg_event (np_joblist_t* job_q, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	// log_msg(LOG_TRACE, "job_submit_msg_event starting ...");

    // create runtime arguments
    np_jobargs_t* jargs = (np_jobargs_t*) malloc (sizeof(np_jobargs_t));
    jargs->msg = msg;
    jargs->target = key;
    jargs->properties = prop;
    if (msg != NULL) np_ref_obj(np_message_t, jargs->msg);

    // create job itself
    np_job_t* new_job = (np_job_t *) malloc (sizeof(np_job_t));
    new_job->processorFunc = prop->clb; // ->msg_handler;
    new_job->args = jargs;
    new_job->type = 1;


    pthread_mutex_lock (&job_q->access);
    // log_msg(LOG_DEBUG, "1: new_job-->%p func-->%p args-->%p", new_job, new_job->processorFunc, new_job->args);

    // if (NULL == sll_first (job_q->job_list)) was_empty = 1;
    sll_append(np_job_t, job_q->job_list, new_job);
    if (sll_size(job_q->job_list) == 1)
    	pthread_cond_signal (&job_q->empty);
    // if (was_empty) pthread_cond_signal (&job_q->empty);

    pthread_mutex_unlock (&job_q->access);
	// log_msg(LOG_TRACE, "... job_submit_msg_event finished");
}

void job_submit_event (np_joblist_t* job_q, np_callback_t callback)
{
    np_job_t* new_job = (np_job_t *) malloc (sizeof (np_job_t));
    new_job->processorFunc = callback;
    new_job->args = NULL;
    new_job->type = 2;

    pthread_mutex_lock (&job_q->access);

    // log_msg(LOG_DEBUG, "2: new_job-->%p func-->%p args-->%p", new_job, new_job->processorFunc, new_job->args);
    // if (NULL == sll_first (job_q->job_list)) was_empty = 1;
    sll_append(np_job_t, job_q->job_list, new_job);
    if (sll_size(job_q->job_list) == 1)
    	pthread_cond_signal (&job_q->empty);
    // if (was_empty) pthread_cond_signal (&job_q->empty);

    pthread_mutex_unlock (&job_q->access);
}

/** job_queue_create
 *  initiate the queue and thread pool, returns a pointer to the initiated queue.
 **/
np_joblist_t *job_queue_create ()
{
	np_joblist_t* job_list = (np_joblist_t *) malloc (sizeof(np_joblist_t));

	sll_init(np_job_t, job_list->job_list);
    pthread_mutex_init (&job_list->access, NULL);
    pthread_cond_init (&job_list->empty, NULL);

    return (job_list);
}


/** job_exec
 * runs a thread which is competing for jobs in the job queue
 * after getting the first job out of queue it will execute the corresponding callback with
 * defined job arguments
 */
void* job_exec (void* np_state)
{
	np_state_t* state = (np_state_t*) np_state;
	np_joblist_t* Q = state->jobq;
	np_job_t* tmp = NULL;

	log_msg(LOG_DEBUG, "job queue thread starting");

	while (1)
	{
	    pthread_mutex_lock (&Q->access);
	    while (sll_empty(Q->job_list))
	    // if (sll_empty(Q->job_list))
		{
	    	pthread_cond_wait (&Q->empty, &Q->access);
		}
	    tmp = sll_head(np_job_t, Q->job_list);
	    pthread_mutex_unlock (&Q->access);

	    // sanity check if the job list really returned an element
	    // if (NULL == tmp || NULL == tmp->processorFunc) continue;
	    if (NULL == tmp) continue;
	    // log_msg(LOG_DEBUG, "%hhd:     job-->%p func-->%p args-->%p", tmp->type, tmp, tmp->processorFunc, tmp->args);

	    if (tmp->type == 1)
	    {
	    	tmp->processorFunc(state, tmp->args);
	    	if (tmp->args->msg) {
	    		np_unref_obj(np_message_t, tmp->args->msg);
	    		// just do a sanity check, it won't hurt :-)
	    		np_free_obj(np_message_t, tmp->args->msg);
	    	}
	    }
	    if (tmp->type == 2) {
	    	tmp->processorFunc(state, tmp->args);
	    }
	    // cleanup
	    free(tmp->args);
	    np_job_free(tmp);
	}
    return NULL;
}
