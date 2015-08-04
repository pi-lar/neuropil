/**
 *  copyright 2015 pi-lar GmbH
 *  original version was taken from chimera project (MIT licensed), but heavily modified
 *  Stephan Schwichtenberg
 **/
#ifndef _NEUROPIL_H_
#define _NEUROPIL_H_

#include <pthread.h>

#include "include.h"
#include "np_container.h"
#include "np_key.h"

SPLAY_HEAD(spt_key, np_key_s);
SPLAY_PROTOTYPE(spt_key, np_key_s, link, key_comp);

RB_HEAD(rbt_msgproperty, np_msgproperty_s);
RB_PROTOTYPE(rbt_msgproperty, np_msgproperty_s, link, property_comp);


struct np_state_s {

	np_key_t* my_key;

	// red-black-structure to maintain objects adressable with an hash key
	struct spt_key key_cache; //  = SPLAY_INITIALIZER(&key_cache);

	struct rbt_msgproperty msg_properties;
	np_jtree_t *msg_tokens;

	np_routeglobal_t   *routes;
    np_joblist_t       *jobq;

    pthread_mutex_t lock;
    pthread_attr_t attr;
    pthread_t* thread_ids;

	np_aaa_func_t  authenticate_func; // authentication callback
	np_aaa_func_t  authorize_func;    // authorization callback
	np_aaa_func_t  accounting_func;   // really needed ?
};


/** np_init
 ** Initializes neuropil subsystem to listen on the given port
 ** and returns the np_state_t* which contains global state of different np sub modules.
 **/
np_state_t* np_init (uint16_t port);

/** np_setkey
 ** Manually sets the key for the current node 
 **/
void np_setkey (const np_state_t* state, np_key_t* key);

// void np_setjoinfunc(const np_state_t* state, np_aaa_func_t join_func);
void np_waitforjoin(const np_state_t* state);

void np_setauthorizing_cb(np_state_t* state, np_aaa_func_t join_func);
void np_setauthenticate_cb(np_state_t* state, np_aaa_func_t join_func);
void np_setaccounting_cb(np_state_t* state, np_aaa_func_t join_func);

/** np_add_listener:
 ** register an integer message type to be routed by the np routing layer
 ** ack is the argument that defines whether this message type should be acked or not
 ** ack == 1 means message will be acknowledged, ack=2 means no acknowledge is necessary
 ** for this type of message. 
 **/
void np_set_listener (np_state_t* state, np_callback_t msg_handler, char* subject);

/** np_send|receive:
 *  Send/Receive a message of a specific type to a key containing size bytes of data. This will
 *  send data through the neuropil system and deliver it to the host closest to the
 *  key, which will in turn try to find a message handler
 **/
void     np_send         (np_state_t* state, char* subject, char *data, uint32_t seqnum);
uint32_t np_receive      (np_state_t* state, char* subject, char **data);

/** np_set|rem_mx_properties
 *  set properties of the message exchange given by subject
 *  a complete list of mx properties can be found in message.h
 **/
void np_set_mx_property(np_state_t* state, char* subject, const char* key, np_jval_t value);
void np_rem_mx_property(np_state_t* state, char* subject, const char* key);

// start the job queue and create pool_size threads to work on tasks
void np_start_job_queue(np_state_t* state, uint8_t pool_size);

/** np_ping
 *  sends a ping message to the host. the message is acknowledged in network layer
 **/
void np_ping(np_state_t* state, np_key_t* key);
void np_send_ack(np_state_t* state, np_jobargs_t* args);

#endif /* _NEUROPIL_H_ */
