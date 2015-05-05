/**
 ** $Id: message.h,v 1.20 2007/04/04 00:04:49 krishnap Exp $
 ** Matthew Allen
 ** description:
 **/
#ifndef _NP_MESSAGE_H_
#define _NP_MESSAGE_H_

#include <stdarg.h>

#include "include.h"

#include "key.h"
#include "jrb.h"
#include "jval.h"
#include "cmp.h"

#define NP_MESSAGE_SIZE 65536

struct np_message_s {
 	np_jrb_t* header;
	np_jrb_t* instructions;
	np_jrb_t* properties;
	np_jrb_t* body;
	np_jrb_t* footer;
};

np_message_t* np_message_create_empty();

int np_message_decrypt_part(np_jrb_t* msg_part, unsigned char* enc_nonce, unsigned char* public_key, unsigned char* private_key);
int np_message_encrypt_part(np_jrb_t* msg_part, unsigned char* enc_nonce, unsigned char* public_key, unsigned char* private_key);

int np_message_serialize(np_message_t* msg, void* buffer, unsigned long* out_size);
np_message_t* np_message_deserialize(void* buffer);

inline void np_message_setproperties(np_message_t* msg, np_jrb_t* properties);
void np_message_addpropertyentry(np_message_t*, const char* key, np_jval_t value);
void np_message_delpropertyentry(np_message_t*, const char* key);

inline void np_message_setinstruction(np_message_t* msg, np_jrb_t* instructions);
void np_message_addinstructionentry(np_message_t*, const char* key, np_jval_t value);
void np_message_delinstructionentry(np_message_t*, const char* key);

inline void np_message_setbody(np_message_t* msg, np_jrb_t* body);
void np_message_addbodyentry(np_message_t*, const char* key, np_jval_t value);
void np_message_delbodyentry(np_message_t*, const char* key);

inline void np_message_setfooter(np_message_t* msg, np_jrb_t* footer);
void np_message_addfooterentry(np_message_t*, const char* key, np_jval_t value);
void np_message_delfooterentry(np_message_t*, const char* key);


struct np_messageglobal_s
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

};

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


struct np_msgproperty_s {
	char* msg_subject;
	int msg_mode;
	int msg_type;
	int priority;
	int ack_mode;
	int retry;
	const char* msg_format;
	np_callback_t clb;
};


struct np_msginterest_s {
	// TODO: transport the real node data in the interest as well
	np_key_t* key;

	char*         msg_subject;
	int           msg_type;
	unsigned long msg_seqnum;
	int           msg_threshold;

	int send_ack;
	np_jrb_t* payload;

	// only send/receive after opposite partner has been found
    pthread_mutex_t lock;
    pthread_cond_t  msg_received;
    pthread_condattr_t cond_attr;
};


#define DEFAULT_SEQNUM 0
#define RETRANSMIT_THREAD_SLEEP 1
#define RETRANSMIT_INTERVAL 5
#define MAX_RETRY 3

#define DEFAULT "_NP.DEFAULT"
#define ROUTE_LOOKUP "_NP.ROUTE.LOOKUP"

#define NP_MSG_ACK "_NP.ACK"
#define NP_MSG_HANDSHAKE "_NP.HANDSHAKE"

#define NP_MSG_PING_REQUEST "_NP.PING.REQUEST"
#define NP_MSG_PING_REPLY "_NP.PING.REPLY"

#define NP_MSG_JOIN_REQUEST "_NP.JOIN.REQUEST"
#define NP_MSG_JOIN_ACK "_NP.JOIN.ACK"
#define NP_MSG_JOIN_NACK "_NP.JOIN.NACK"

#define NP_MSG_PIGGY_REQUEST "_NP.NODES.PIGGY"
#define NP_MSG_UPDATE_REQUEST "_NP.NODES.UPDATE"

#define NP_MSG_INTEREST "_NP.MESSAGE.INTEREST"
#define NP_MSG_INTEREST_REJECT "_NP.MESSAGE.INTEREST.REJECTION"
#define NP_MSG_AVAILABLE "_NP.MESSAGE.AVAILABILITY"

static const char* NP_MSG_HEADER_TO = "address";
static const char* NP_MSG_HEADER_FROM = "from";
static const char* NP_MSG_HEADER_REPLY_TO = "reply_to";
static const char* NP_MSG_HEADER_SUBJECT = "subject";

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
int np_message_check_handler(np_messageglobal_t *mg, int msg_mode, const char* subject);

/** 
 ** message_create / free:
 ** creates the message to the destination #dest# the message format would be like:
 ** deletes the message and corresponding structures
 **/
np_message_t* np_message_create(np_messageglobal_t *mg, np_key_t* to, np_key_t* from, const char* subject, np_jrb_t* the_data);
void np_message_free(np_message_t* msg);

// np_msgproperty_t*
void np_message_create_property(np_messageglobal_t *mg, const char* subject, int msg_mode, int msg_type, int ack_mode, int priority, int retry, np_callback_t callback);
np_msginterest_t* np_message_create_interest(const np_state_t* state, const char* subject, int msg_type, unsigned long seqnum, int threshold);


// update internal structure and return a interest if a matching pair has been found
np_msginterest_t* np_message_interest_update(np_messageglobal_t *mg, np_msginterest_t *interest);
np_msginterest_t* np_message_available_update(np_messageglobal_t *mg, np_msginterest_t *available);
// check whether an interest is existing
np_msginterest_t* np_message_interest_match(np_messageglobal_t *mg, const char *subject);
np_msginterest_t* np_message_available_match(np_messageglobal_t *mg, const char *subject);


np_msginterest_t* np_decode_msg_interest(np_messageglobal_t *mg, np_jrb_t* data);
void np_message_encode_interest(np_jrb_t *amqp_data, np_msginterest_t *interest);

// np_message_t* message_create (np_key_t* 
// np_message_t *message_create (np_key_t* 


#endif /* _NP_MESSAGE_H_ */
