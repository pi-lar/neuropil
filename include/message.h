/**
 ** $Id: message.h,v 1.20 2007/04/04 00:04:49 krishnap Exp $
 ** Matthew Allen
 ** description:
 **/
#ifndef _NP_MESSAGE_H_
#define _NP_MESSAGE_H_

#include <stdarg.h>

#include "proton/message.h"

#include "include.h"
#include "key.h"


typedef struct np_messageglobal_t
{
    np_jrb_t* in_handlers;
    np_jrb_t* out_handlers;
    np_jrb_t* trans_handlers;

    pthread_mutex_t input_lock;
    pthread_mutex_t output_lock;
    pthread_mutex_t trans_lock;

    np_jrb_t *interest_sources;
    np_jrb_t *interest_targets;
    pthread_mutex_t interest_lock;

} *np_messageglobal;


enum {
	DEFAULT_MODE = 0,
	INBOUND,
	OUTBOUND,
	TRANSFORM
} msg_mode;


enum {
	DEFAULT_TYPE = 0,
	ONEWAY,
	PUSHPULL,
	PUBSUB
} msg_type;


typedef struct np_msgproperty_t {

	char* msg_subject;
	int msg_mode;
	int msg_type;
	int priority;
	int ack_mode;
	int retry;
	const char* msg_format;
	np_callback_t clb;

	// np_node_t** aNodes;
	// void (*np_callback_t) (np_state_t* , np_jobargs_t*);
} *np_msgproperty;


typedef struct np_msginterest_t {

	// TODO: transport the real node data in the interest as well
	Key*          key;

	char*         msg_subject;
	int           msg_type;
	unsigned long msg_seqnum;
	int           msg_threshold;

	int send_ack;
	pn_data_t* payload;

	// only send/receive after opposite partner has been found
    pthread_mutex_t lock;
    pthread_cond_t  msg_received;

} *np_msginterest;


#define DEFAULT_SEQNUM 0
#define RETRANSMIT_THREAD_SLEEP 1
#define RETRANSMIT_INTERVAL 5
#define MAX_RETRY 3

#define ROUTE_LOOKUP "_NEUROPIL.ROUTE.LOOKUP"
#define NP_MSG_ACK "_NEUROPIL.ACK"

#define NP_MSG_PING_REQUEST "_NEUROPIL.PING.REQUEST"
#define NP_MSG_PING_REPLY "_NEUROPIL.PING.REPLY"

#define NP_MSG_JOIN_REQUEST "_NEUROPIL.JOIN.REQUEST"
#define NP_MSG_JOIN_ACK "_NEUROPIL.JOIN.ACK"
#define NP_MSG_JOIN_NACK "_NEUROPIL.JOIN.NACK"

#define NP_MSG_PIGGY_REQUEST "_NEUROPIL.NODES.PIGGY"
#define NP_MSG_UPDATE_REQUEST "_NEUROPIL.NODES.UPDATE"

#define NP_MSG_INTEREST "_NEUROPIL.MESSAGE.INTEREST"
#define NP_MSG_INTEREST_REJECT "_NEUROPIL.MESSAGE.INTEREST.REJECTION"
#define NP_MSG_AVAILABLE "_NEUROPIL.MESSAGE.AVAILABILITY"


/**
 ** message_init: chstate, port
 ** Initialize messaging subsystem on port and returns the MessageGlobal * which 
 ** contains global state of message subsystem.
 ** message_init also initiate the network subsystem
 **/
np_messageglobal_t* message_init (int port);

/**
 ** registers the handler function #func# with the message type #type#,
 ** it also defines the acknowledgment requirement for this type 
 **/
void np_message_register_handler (np_messageglobal_t *mg, np_msgproperty_t* msgprops);

/**
 ** return a handler for a given message subject
 **/
np_msgproperty_t* np_message_get_handler (np_messageglobal_t *mg, int msg_mode, const char* subject);
bool np_message_check_handler(np_messageglobal_t *mg, int msg_mode, const char* subject);

/** 
 ** message_create / free:
 ** creates the message to the destination #dest# the message format would be like:
 ** deletes the message and corresponding structures
 **/
pn_message_t* np_message_create(np_messageglobal_t *mg, Key* to, Key* from, const char* subject, pn_data_t* the_data);
void np_message_free(pn_message_t * msg);

// np_msgproperty_t*
void np_message_create_property(np_messageglobal_t *mg, const char* subject, int msg_mode, int msg_type, int ack_mode, int priority, int retry, np_callback_t callback);
np_msginterest_t* np_message_create_interest(const np_state_t* state, const char* subject, int msg_type, unsigned long seqnum, int threshold);


// update internal structure and return a interest if a matching pair has been found
np_msginterest_t* np_message_interest_update(np_messageglobal_t *mg, np_msginterest_t *interest);
np_msginterest_t* np_message_available_update(np_messageglobal_t *mg, np_msginterest_t *available);
// check whether an interest is existing
np_msginterest_t* np_message_interest_match(np_messageglobal_t *mg, const char *subject);
np_msginterest_t* np_message_available_match(np_messageglobal_t *mg, const char *subject);


np_msginterest_t* np_decode_msg_interest(np_messageglobal_t *mg, pn_data_t *amqp_data);
void np_message_encode_interest(pn_data_t *amqp_data, np_msginterest_t *interest);

// pn_message_t* message_create (Key to, Key from, const char* subject, va_list va);
// pn_message_t *message_create (Key dest, int type, int size, char *payload);


#endif /* _NP_MESSAGE_H_ */
