/**
 ** $Id: message.h,v 1.20 2007/04/04 00:04:49 krishnap Exp $
 ** Matthew Allen
 ** description:
 **/
#ifndef _NP_MESSAGE_H_
#define _NP_MESSAGE_H_

#include <stdarg.h>

#include "include.h"

#include "np_memory.h"

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

/** message_create / free:
 ** creates the message to the destination #dest# the message format would be like:
 ** deletes the message and corresponding structures
 **/
void np_message_create(np_message_t* msg, np_key_t* to, np_key_t* from, const char* subject, np_jrb_t* the_data);
/*
 * creation cleanup methods for messages / called internally by np_memory_h
 */
void np_message_t_new(void* msg);
void np_message_t_del(void* msg);

// encrypt / decrypt parts of a message
int np_message_decrypt_part(np_jrb_t* msg_part, unsigned char* enc_nonce, unsigned char* public_key, unsigned char* private_key);
int np_message_encrypt_part(np_jrb_t* msg_part, unsigned char* enc_nonce, unsigned char* public_key, unsigned char* private_key);

// (de-) serialize a message to a binary stream using message pack (cmp.h)
int np_message_serialize(np_message_t* msg, void* buffer, unsigned long* out_size);
int np_message_deserialize(np_message_t* msg, void* buffer);

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

/*
 * structure to hold informations about message handlers in the neuropil node
 * in_handlers are examined when messages are received
 * out_handlers are examined when messages should be send
 * trans_handlers are examined when it is unclear what should happen with a message
 * interest sources/targets are used to hold information about sending/receiving instances
 */
struct np_messageglobal_s
{
    np_jrb_t* in_handlers;
    pthread_mutex_t input_lock;

    np_jrb_t* out_handlers;
    pthread_mutex_t output_lock;

    np_jrb_t* trans_handlers;
    pthread_mutex_t trans_lock;

    np_jrb_t *interest_sources;
    np_jrb_t *interest_targets;
    pthread_mutex_t interest_lock;
};

typedef enum np_msg_mode_enum {
	DEFAULT_MODE = 0,
	INBOUND = 0x1,
	OUTBOUND = 0x2,
	ROUTE = 0x4,
	TRANSFORM = 0x8
} np_msg_mode_type;

/*
 * definition of message exchange pattern (MEP)
 * starting with the definition of sender / receiver / extra flags
 * continuing to define "higher" level MEP
 * SINGLE / ONE refers to a single np_node_t
 * GROUP refers to a group of np_node_t instances which share the same sending/receiving identity
 * ANY refers to a group of np_node_t instances which do not share the same sending/receiving identity
 */
typedef enum np_msg_mep_enum {
	DEFAULT_TYPE = 0x000,
	// base pattern for communication exchange
	SINGLE_SENDER = 0x010,       // - simple one  to one  communication
	GROUP_SENDER = 0x020,      // - oneway one  to many communication // receiver has not the same identity
	ANY_SENDER = 0x040,
	SINGLE_RECEIVER = 0x001,      // - oneway many to one  communictaion // sender has same identity
	GROUP_RECEIVER = 0x002,      // - oneway many to one  communictaion // sender has same identity
	ANY_RECEIVER = 0x004,
	FILTER_MSG = 0x100,
	HAS_REPLY = 0x200,
	STICKY_REPLY = 0x300,

	// simple combinations
	// ONE to ONE
	ONE_WAY = SINGLE_SENDER & SINGLE_RECEIVER,
	ONE_WAY_WITH_REPLY = ONE_WAY & HAS_REPLY,
	// ONE to GROUP
	ONE_TO_GROUP = SINGLE_SENDER & GROUP_RECEIVER,
	O2G_WITH_REPLY = ONE_TO_GROUP & HAS_REPLY,
	// ONE to ANY
	ONE_TO_ANY = SINGLE_SENDER & ANY_RECEIVER,
	O2A_WITH_REPLY = ONE_TO_ANY & HAS_REPLY,
	// GROUP to GROUP
	GROUP_TO_GROUP = GROUP_SENDER & GROUP_RECEIVER,
	G2G_WITH_REPLY = GROUP_TO_GROUP & HAS_REPLY,
	G2G_STICKY_REPLY = G2G_WITH_REPLY & STICKY_REPLY,
	// ANY to ANY
	ANY_TO_ANY = ANY_SENDER & ANY_RECEIVER,
	A2A_WITH_REPLY = ANY_TO_ANY & HAS_REPLY,
	A2A_STICKY_REPLY = A2A_WITH_REPLY & STICKY_REPLY,
	// GROUP to ANY
	GROUP_TO_ANY = GROUP_SENDER & ANY_RECEIVER,
	G2A_WITH_REPLY = GROUP_TO_ANY & HAS_REPLY,
	G2A_STICKY_REPLY = G2A_WITH_REPLY & STICKY_REPLY,
	// ANY to GROUP
	ANY_TO_GROUP = ANY_SENDER & GROUP_RECEIVER,
	A2G_WITH_REPLY = ANY_TO_GROUP & HAS_REPLY,
	A2G_STICKY_REPLY = A2G_WITH_REPLY & STICKY_REPLY,

	// more "speaking" combinations
	REQ_REP   = ONE_WAY_WITH_REPLY, // - allows to build clusters of stateless services to process user requests
	PIPELINE  = ONE_TO_GROUP,       // - splits up messages to a set of nodes / load balancing among many destinations
	AGGREGATE = O2A_WITH_REPLY,     // - aggregates messages from multiple sources and them among many destinations
	MULTICAST = GROUP_TO_GROUP & FILTER_MSG,
	BROADCAST = ONE_TO_ANY & GROUP_TO_ANY,
	INTERVIEW = A2G_WITH_REPLY,
	BUS       = ANY_TO_ANY,
	SURVEY    = A2A_STICKY_REPLY,
	PUBSUB    = BUS & FILTER_MSG,

} np_msg_mep_type;

// definition of message acknowlege
typedef enum np_msg_ack_enum {
	ACK_NONE = 0x00, // 0000 0000  - don't ack at all
	ACK_EACHHOP = 0x01, // 0000 0001 - each hop has to send a ack to the previous hop
	ACK_DESTINATION = 0x02, // 0000 0010 - message destination ack to message sender across multiple nodes
	ACK_CLIENT = 0x04,     // 0000 1000 - message to sender ack after/during processing the message on receiver side
} np_msg_ack_type;


struct np_msgproperty_s {
	char* msg_subject;
	np_msg_mode_type msg_mode;
	np_msg_mep_type msg_type;
	int priority;
	np_msg_ack_type ack_mode;
	unsigned int retry;
	const char* msg_format;
	np_callback_t clb;
};

struct np_msgcache_s {
	np_obj_t* payload;
	np_msgcache_t* next;
};

struct np_msginterest_s {
	// TODO: transport the real node data in the interest as well
	np_key_t* key;

	char*           msg_subject;
	np_msg_mep_type msg_type;
	np_msg_ack_type send_ack;
	unsigned long   msg_seqnum;
	unsigned int    msg_threshold;

	np_msgcache_t* msg_cache_first;
	np_msgcache_t* msg_cache_last;
	unsigned int msg_cache_size;
	// only send/receive after opposite partner has been found
    pthread_mutex_t    lock;
    pthread_cond_t     msg_received;
    pthread_condattr_t cond_attr;
};

unsigned int np_msgcache_size(np_msginterest_t* x);
np_obj_t* np_msgcache_pop(np_msginterest_t* x);
void np_msgcache_push(np_msginterest_t* x, np_obj_t* y);


#define DEFAULT_SEQNUM 0
#define RETRANSMIT_THREAD_SLEEP 1.0
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

static const char* NP_MSG_HEADER_SUBJECT   = "subject";
static const char* NP_MSG_HEADER_TO        = "address";
static const char* NP_MSG_HEADER_FROM      = "from";
static const char* NP_MSG_HEADER_REPLY_TO  = "reply_to";
static const char* NP_MSG_FOOTER_ALIAS_KEY = "_np.alias_key";

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
np_msgproperty_t* np_message_get_handler (np_messageglobal_t *mg, np_msg_mode_type msg_mode, const char* subject);
int np_message_check_handler(np_messageglobal_t *mg, np_msg_mode_type msg_mode, const char* subject);

// np_msgproperty_t*
void np_message_create_property(np_messageglobal_t *mg, const char* subject, np_msg_mode_type msg_mode, np_msg_mep_type msg_type, np_msg_ack_type ack_mode, unsigned int priority, unsigned int retry, np_callback_t callback);
np_msginterest_t* np_message_create_interest(const np_state_t* state, const char* subject, np_msg_mep_type msg_type, unsigned long seqnum, unsigned int threshold);

// update internal structure and return a interest if a matching pair has been found
np_msginterest_t* np_message_interest_update(np_messageglobal_t *mg, np_msginterest_t *interest);
np_msginterest_t* np_message_available_update(np_messageglobal_t *mg, np_msginterest_t *available);
// check whether an interest is existing
np_msginterest_t* np_message_interest_match(np_messageglobal_t *mg, const char *subject);
np_msginterest_t* np_message_available_match(np_messageglobal_t *mg, const char *subject);

np_msginterest_t* np_decode_msg_interest(np_messageglobal_t *mg, np_jrb_t* data);
void np_message_encode_interest(np_jrb_t *data, np_msginterest_t *interest);


#endif /* _NP_MESSAGE_H_ */
