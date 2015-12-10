#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>

#include "np_jobqueue.h"

#include "include.h"
#include "dtime.h"
#include "neuropil.h"
#include "np_memory.h"
#include "np_message.h"
#include "log.h"

int8_t compare_job_tstamp(np_job_ptr job1, np_job_ptr job2)
{
	if (job1->tstamp > job2->tstamp) return -1;
	if (job1->tstamp < job2->tstamp) return  1;
	return 0;
}

void np_job_free (np_job_t * n)
{
    free (n);
}

/** (re-)submit message event
 **
 ** get the queue mutex "access",
 ** create a new np_job_t and pass func,args,args_size,
 ** add the new np_job_t to the queue, and
 ** signal the thread pool if the queue was empty.
 **/
void job_resubmit_msg_event (np_joblist_t* job_q, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg) {
    // create runtime arguments
    np_jobargs_t* jargs = (np_jobargs_t*) malloc (sizeof(np_jobargs_t));
    jargs->msg = msg;
    jargs->is_resend = TRUE;
    jargs->target = key;
    jargs->properties = prop;
    if (msg != NULL)
    {
    	np_ref_obj(np_message_t, jargs->msg);
    }
    if (NULL != jargs->target)
    {
    	np_ref_obj(np_key_t, jargs->target);
    }

    // create job itself
    np_job_t* new_job = (np_job_t *) malloc (sizeof(np_job_t));
    new_job->processorFunc = prop->clb; // ->msg_handler;
    new_job->tstamp = dtime() + delay;
    new_job->args = jargs;
    new_job->type = 1;

    pthread_mutex_lock (&job_q->access);
    // log_msg(LOG_DEBUG, "1: new_job-->%p func-->%p args-->%p", new_job, new_job->processorFunc, new_job->args);
    // log_msg(LOG_DEBUG, "requsting msg execution at: %f", new_job->tstamp);
    // if (NULL == sll_first (job_q->job_list)) was_empty = 1;
    pll_insert(np_job_ptr, job_q->job_list, new_job);
    if (pll_size(job_q->job_list) >= 1  || delay == 0.0)
    {
    	pthread_cond_signal (&job_q->empty);
    }
    // if (was_empty) pthread_cond_signal (&job_q->empty);

    pthread_mutex_unlock (&job_q->access);
	// log_msg(LOG_TRACE, "... job_submit_msg_event finished");
}

void job_submit_msg_event (np_joblist_t* job_q, double delay, np_msgproperty_t* prop, np_key_t* key, np_message_t* msg)
{
	// log_msg(LOG_TRACE, "job_submit_msg_event starting ...");

    // create runtime arguments
    np_jobargs_t* jargs = (np_jobargs_t*) malloc (sizeof(np_jobargs_t));
    jargs->msg = msg;
    jargs->is_resend = FALSE;
    jargs->target = key;
    jargs->properties = prop;
    if (NULL != jargs->msg)
    {
    	np_ref_obj(np_message_t, jargs->msg);
    }
    if (NULL != jargs->target)
    {
    	np_ref_obj(np_key_t, jargs->target);
    }

    // create job itself
    np_job_t* new_job = (np_job_t *) malloc (sizeof(np_job_t));
    new_job->processorFunc = prop->clb; // ->msg_handler;
    new_job->tstamp = dtime() + delay;
    new_job->args = jargs;
    new_job->type = 1;

    pthread_mutex_lock (&job_q->access);
    // log_msg(LOG_DEBUG, "1: new_job-->%p func-->%p args-->%p", new_job, new_job->processorFunc, new_job->args);
    // log_msg(LOG_DEBUG, "requsting msg execution at: %f", new_job->tstamp);
    // if (NULL == sll_first (job_q->job_list)) was_empty = 1;
    pll_insert(np_job_ptr, job_q->job_list, new_job);
    if (pll_size(job_q->job_list) >= 1  || delay == 0.0)
    {
    	pthread_cond_signal (&job_q->empty);
    }
    // if (was_empty) pthread_cond_signal (&job_q->empty);

    pthread_mutex_unlock (&job_q->access);
	// log_msg(LOG_TRACE, "... job_submit_msg_event finished");
}

void job_submit_event (np_joblist_t* job_q, double delay, np_callback_t callback)
{
    np_job_t* new_job = (np_job_t *) malloc (sizeof (np_job_t));
    new_job->tstamp = dtime() + delay;
    new_job->processorFunc = callback;
    new_job->args = NULL;
    new_job->type = 2;

    pthread_mutex_lock (&job_q->access);

    // log_msg(LOG_DEBUG, "requsting event execution at: %f", new_job->tstamp);
    // log_msg(LOG_DEBUG, "2: new_job-->%p func-->%p args-->%p", new_job, new_job->processorFunc, new_job->args);
    // if (NULL == sll_first (job_q->job_list)) was_empty = 1;
    pll_insert(np_job_ptr, job_q->job_list, new_job);
    if (pll_size(job_q->job_list) >= 1 || delay == 0.0)
    {
    	pthread_cond_signal (&job_q->empty);
    }
    // if (was_empty) pthread_cond_signal (&job_q->empty);

    pthread_mutex_unlock (&job_q->access);
}

/** job_queue_create
 *  initiate the queue and thread pool, returns a pointer to the initiated queue.
 **/
np_joblist_t *job_queue_create ()
{
	np_joblist_t* job_list = (np_joblist_t *) malloc (sizeof(np_joblist_t));

	pll_init(np_job_ptr, job_list->job_list, compare_job_tstamp);
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

	double default_sleep_time = 3.141592;
    double now;

	while (1)
	{
	    pthread_mutex_lock (&Q->access);
	    now = dtime();
	    while (0 == pll_size(Q->job_list))
		{
    		// log_msg(LOG_DEBUG, "now %f: list empty, start sleeping", now);
	    	pthread_cond_wait (&Q->empty, &Q->access);
	    	// wake up, check first job in the queue to be executed by now
		}

    	np_job_ptr next_job = pll_first(Q->job_list)->val;
    	if (now <= next_job->tstamp) {
    		double sleep_time = next_job->tstamp - now;
    		if (sleep_time > default_sleep_time) sleep_time = default_sleep_time;
    		// log_msg(LOG_DEBUG, "now %f: next execution %f", now, next_job->tstamp);
    		// log_msg(LOG_DEBUG, "currently %d jobs, now sleeping for %f seconds", pll_size(Q->job_list), sleep_time);
    		struct timeval tv_sleep = dtotv(now + sleep_time);
    		struct timespec waittime = { .tv_sec = tv_sleep.tv_sec, .tv_nsec=tv_sleep.tv_usec*1000 };
	    	pthread_cond_timedwait (&Q->empty, &Q->access, &waittime);
	    	// now = dtime();
    		// log_msg(LOG_DEBUG, "now %f: woke up or interupted", now);
	    	pthread_mutex_unlock (&Q->access);
    		continue;
    	}
    	else
    	{
		// log_msg(LOG_DEBUG, "now %f --> executing %f", now, next_job->tstamp);
    		tmp = pll_head(np_job_ptr, Q->job_list);
    		pthread_mutex_unlock (&Q->access);
    	}

    	// sanity check if the job list really returned an element
	    // if (NULL == tmp || NULL == tmp->processorFunc) continue;
	    if (NULL == tmp) continue;
	    // log_msg(LOG_DEBUG, "%hhd:     job-->%p func-->%p args-->%p", tmp->type, tmp, tmp->processorFunc, tmp->args);

    	tmp->processorFunc(state, tmp->args);

    	if (tmp->type == 1)
	    {
	    	if (NULL != tmp->args->msg)
	    	{
	        	np_unref_obj(np_message_t, tmp->args->msg);
	    	}
	        if (NULL != tmp->args->target)
	        {
	        	np_unref_obj(np_key_t, tmp->args->target);
	        }
	    }

	    // cleanup
	    free(tmp->args);
	    np_job_free(tmp);
	    tmp = NULL;
	}
    return NULL;
}
