#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>

#include "job_queue.h"

#include "include.h"
#include "np_memory.h"
#include "neuropil.h"
#include "message.h"
#include "log.h"



/**
 **  returns the first element of the list (queue)
 **/
np_job_t* list_get (np_joblist_t * l)
{
    np_job_t *curr;
    curr = l->head;

    if (curr == NULL)
	{
	    l->head = NULL;
	}
    else
	{
	    l->head = curr->next;
	}

    l->size--;
    return (curr);
}

/* insert a np_job_t new at the end of the list(queue) */
void list_insert (np_joblist_t* l, np_job_t* new)
{
    np_job_t *curr;
    curr = l->head;

    if (l->head == NULL)
	{
	    l->head = new;
	    l->size++;
	    return;
	}

    while (curr->next != NULL)
	{
	    curr = curr->next;
	}
    curr->next = new;
    l->size++;
}

int list_empty (np_joblist_t * l)
{
    if (l->head == NULL) return 1;
    else 				 return 0;
}


/**
 ** initiate the list(queue).
 **/
np_joblist_t *list_init ()
{
    np_joblist_t* new = (np_joblist_t *) malloc (sizeof (struct np_joblist_t));

    new->head = NULL;
    new->size = 0;

    pthread_mutex_init (&new->access, NULL);
    pthread_cond_init (&new->empty, NULL);

    return (new);
}

void np_job_free (np_job_t * n)
{
    // free (n->msg_prop); // not needed, message handling initialization stays on
	// pn_message_free (n->args->msg);
	// free (n->args);
    free (n);
}

np_job_t* job_pull (np_joblist_t * l) {
	return list_get(l);
}

int job_available (np_joblist_t * l) {
	return list_empty(l);
}

/** get the queue mutex "access",
 ** create a new np_job_t and pass func,args,args_size,
 ** add the new np_job_t to the queue, and
 ** signal the thread pool if the queue was empty.
 **/
void job_submit_msg_event (np_joblist_t* job_q, np_msgproperty_t* prop, np_key_t* key, np_obj_t* msg)
{
    int was_empty = 0;

    // create runtime arguments
    np_jobargs_t* jargs = (np_jobargs_t*) malloc (sizeof(struct np_jobargs_t));
    jargs->msg = msg;
    jargs->target = key;
    jargs->properties = prop;
    if (msg != NULL) np_ref(np_message_t, jargs->msg);

    // create job itself
    np_job_t* new_job = (np_job_t *) malloc (sizeof (struct np_job_t));
    new_job->processorFunc = prop->clb; // ->msg_handler;
    new_job->args = jargs;
    new_job->next = NULL;
    new_job->type = 1;
    // new_job->job_name = "";

    pthread_mutex_lock (&job_q->access);

    if (list_empty (job_q)) was_empty = 1;
    list_insert (job_q, new_job);
    if (was_empty) pthread_cond_signal (&job_q->empty);

    pthread_mutex_unlock (&job_q->access);
}

void job_submit_event (np_joblist_t* job_q, np_callback_t callback)
// void job_submit (np_joblist_t* job_q, np_node_t* node, np_message_t* msg, np_msgproperty_t* prop)
{
    int was_empty = 0;
    //  JobArgs * jargs = (jobArgs *)args;

    np_job_t* new_job = (np_job_t *) malloc (sizeof (struct np_job_t));
    new_job->processorFunc = callback;
    new_job->args = NULL;
    new_job->next = NULL;
    new_job->type = 2;

    pthread_mutex_lock (&job_q->access);
    if (list_empty (job_q)) was_empty = 1;
    list_insert (job_q, new_job);
    if (was_empty) pthread_cond_signal (&job_q->empty);
    pthread_mutex_unlock (&job_q->access);
}

/** initiate the queue and thread pool,
 * returns a pointer to the initiated queue. 
 */
np_joblist_t *job_queue_create ()
{
    np_joblist_t *Q = list_init ();
    return Q;
}


/** get the queue mutex "access" then
 * if the queue is empty it would go to sleep and release the mutex
 * else get the first job out of queue and execute it
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
	    while (list_empty(Q))
		{
	    	pthread_cond_wait (&Q->empty, &Q->access);
		}
	    tmp = job_pull(Q);
	    pthread_mutex_unlock (&Q->access);

	    if (tmp->type == 1) {
	    	tmp->processorFunc(state, tmp->args);
	    	if (tmp->args->msg) {
	    		np_unref(np_message_t, tmp->args->msg);
	    	}
	    }
	    if (tmp->type == 2)
		   	tmp->processorFunc(state, tmp->args);

	    free(tmp->args);
	    np_job_free(tmp);
	}
    return NULL;
}
