/**
 ** $Id: np.h,v 1.19 2006/06/07 09:21:28 krishnap Exp $
 **
 ** Matthew Allen
 ** description:
 **/
#ifndef _NEUROPIL_H_
#define _NEUROPIL_H_

#include <pthread.h>

#include "include.h"
#include "key.h"


struct np_state_s {

	np_global_t*         neuropil;
    np_nodecache_t*      nodes;
    np_routeglobal_t*    routes;
    np_messageglobal_t*  messages;
    np_networkglobal_t*  network;
    np_joblist_t*        jobq;
    np_aaatoken_cache_t* aaa_cache;

    int joined_network;

    pthread_attr_t attr;
    pthread_t* thread_ids;

};

struct np_global_s {

	np_obj_t  *me;
	np_key_t  *my_key;
	// np_obj_t *bootstrap;

	void *join;	/* semaphore */

	pthread_mutex_t lock;

	np_join_func_t join_func;

	np_aaa_func_t authorize_func;
	np_aaa_func_t authenticate_func;
	np_aaa_func_t accounting_func; // needed ?

};

/**
 ** np_init: port
 **  Initialize Chimera on port port and returns the ChimeraState * which 
 ** contains global state of different np modules.
 **/
np_state_t* np_init (int port);

/** np_setkey:
 ** Manually sets the key for the current node 
 **/
void np_setkey (const np_state_t* state, np_key_t* key);
void np_setjoinfunc(const np_state_t* state, np_join_func_t joinFunc);
void np_waitforjoin(const np_state_t* state);

void np_setauthorizing_cb(const np_state_t* state, np_aaa_func_t joinFunc);
void np_setauthenticate_cb(const np_state_t* state, np_aaa_func_t joinFunc);
void np_setaccounting_cb(const np_state_t* state, np_aaa_func_t joinFunc);


/** np_add_listener:
 ** register an integer message type to be routed by the np routing layer
 ** ack is the argument that defines whether this message type should be acked or not
 ** ack == 1 means message will be acknowledged, ack=2 means no acknowledge is necessary
 ** for this type of message. 
 **/
void np_set_listener (const np_state_t* state, np_callback_t msg_handler, char* subject, int ack, int retry, int threshold);
// register a callback that is executed when a new message arrives
// void np_callback      (const np_state_t* state, char* subject, char *data, int seqnum);

/** np_msg_*:
 ** Send a message of a specific type to a key containing size bytes of data. This will
 ** send data through the neuropil system and deliver it to the host closest to the
 ** key, which will in turn try to find a message handler
 **/
// oneway pattern
void np_send         (np_state_t* state, char* subject, char *data, unsigned long seqnum);
int  np_receive      (np_state_t* state, char* subject, char **data, unsigned long seqnum, int ack);

// push / pull for one of several nodes
void np_push      (const np_state_t* state, char* subject, char *data, int seqnum);
void np_pull      (const np_state_t* state, char* subject, char *data, int seqnum);

// pub / sub sending of messages
void np_pub      (const np_state_t* state, char* subject, char *data, int seqnum);
void np_sub      (const np_state_t* state, char* subject, char *data, int seqnum);


void np_start_job_queue(np_state_t* state, int pool_size);
// void np_get_job_queue(np_state_t* state);

/**
 ** np_ping:
 ** sends a ping message to the host. the message is acknowledged in network layer
 **/
void np_ping(np_state_t* state, np_key_t* key);
void np_send_ack(np_state_t* state, np_jobargs_t* args);


#endif /* _NEUROPIL_H_ */
