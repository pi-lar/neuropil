/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_MSGPROPERTY_H_
#define _NP_MSGPROPERTY_H_

#include <stdarg.h>

#include "include.h"

#include "jval.h"
#include "np_container.h"
#include "np_jtree.h"
#include "np_key.h"
#include "np_memory.h"
#include "np_util.h"

#ifdef __cplusplus
extern "C" {
#endif

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
 * SINGLE / ONE refers to a single identity send from a specific np_node_t
 * GROUP refers to a group of np_node_t instances which share the same sending/receiving identity
 * ANY refers to a group of np_node_t instances which do not share the same sending/receiving identity
 */
typedef enum np_msg_mep_enum {

	DEFAULT_TYPE = 0x000,
	// filter mep by type
	RECEIVER_MASK = 0x00F,
	SENDER_MASK   = 0x0F0,
	FILTER_MASK   = 0xF00,
	// base pattern for communication exchange
	SINGLE_RECEIVER = 0x001,      // - to   one  communication // sender has single identity
	GROUP_RECEIVER = 0x002,       // - to   many communication // receiver has same identity
	ANY_RECEIVER = 0x004,         // - to   many communication // receiver is a set of identities
	SINGLE_SENDER = 0x010,        // - one  to   communication   // sender has a single identity
	GROUP_SENDER = 0x020,         // - many to   communication // sender share the same identity
	ANY_SENDER = 0x040,           // - many to   communication // sender is a set of identities
	// add-on message processing instructions
	FILTER_MSG = 0x100,           // filter a message with a given callback function (?)
	HAS_REPLY = 0x200,            // check reply_to field of the incoming message for a subject hash based reply
	STICKY_REPLY = 0x300,         // check reply_to field of the incoming message for a node hash based reply

	// possible combinations
	// ONE to ONE
	ONE_WAY = SINGLE_SENDER | SINGLE_RECEIVER,
	// ONE_WAY_WITH_REPLY = ONE_WAY | HAS_REPLY, // not possible, only one single sender
	ONE_WAY_WITH_REPLY = ONE_WAY | STICKY_REPLY,
	// ONE to GROUP
	ONE_TO_GROUP = SINGLE_SENDER | GROUP_RECEIVER,
	O2G_WITH_REPLY = ONE_TO_GROUP | STICKY_REPLY,
	// ONE to ANY
	ONE_TO_ANY = SINGLE_SENDER | ANY_RECEIVER,
	O2A_WITH_REPLY = ONE_TO_ANY | STICKY_REPLY,
	// GROUP to GROUP
	GROUP_TO_GROUP = GROUP_SENDER | GROUP_RECEIVER,
	G2G_WITH_REPLY = GROUP_TO_GROUP | HAS_REPLY,
	G2G_STICKY_REPLY = G2G_WITH_REPLY | STICKY_REPLY,
	// ANY to ANY
	ANY_TO_ANY = ANY_SENDER | ANY_RECEIVER,
	A2A_WITH_REPLY = ANY_TO_ANY | HAS_REPLY,
	A2A_STICKY_REPLY = A2A_WITH_REPLY | STICKY_REPLY,
	// GROUP to ANY
	GROUP_TO_ANY = GROUP_SENDER | ANY_RECEIVER,
	G2A_WITH_REPLY = GROUP_TO_ANY | HAS_REPLY,
	G2A_STICKY_REPLY = G2A_WITH_REPLY | STICKY_REPLY,
	// ANY to GROUP
	ANY_TO_GROUP = ANY_SENDER | GROUP_RECEIVER,
	A2G_WITH_REPLY = ANY_TO_GROUP | HAS_REPLY,
	A2G_STICKY_REPLY = A2G_WITH_REPLY | STICKY_REPLY,

	// human readable and more "speaking" combinations
	REQ_REP   = ONE_WAY_WITH_REPLY, // - allows to build clusters of stateless services to process requests
	PIPELINE  = ONE_TO_GROUP,       // - splits up messages to a set of nodes / load balancing among many destinations
	AGGREGATE = O2A_WITH_REPLY,     // - aggregates messages from multiple sources and them among many destinations
	MULTICAST = GROUP_TO_GROUP | FILTER_MSG,
	BROADCAST = ONE_TO_ANY | GROUP_TO_ANY,
	INTERVIEW = A2G_WITH_REPLY,
	BUS       = ANY_TO_ANY,
	SURVEY    = A2A_STICKY_REPLY,
	PUBSUB    = BUS | FILTER_MSG,

} np_msg_mep_type;

typedef enum np_msgcache_policy_enum {
	FIFO = 0x01,
	FILO = 0x02,
	OVERFLOW_REJECT = 0x10,
	OVERFLOW_PURGE = 0x20
} np_msgcache_policy_type;

// definition of message acknowlege
typedef enum np_msg_ack_enum {
	ACK_NONE = 0x00, // 0000 0000  - don't ack at all
	ACK_EACHHOP = 0x01, // 0000 0001 - each hop has to send a ack to the previous hop
	ACK_DESTINATION = 0x02, // 0000 0010 - message destination ack to message sender across multiple nodes
	ACK_CLIENT = 0x04,     // 0000 0100 - message to sender ack after/during processing the message on receiver side
} np_msg_ack_type;


struct np_msgproperty_s {
	// link to memory management
	np_obj_t* obj;

    RB_ENTRY(np_msgproperty_s) link; // link for cache management

    // link to node(s) which is/are interested in message exchange
    np_key_t* partner_key;

    char*            msg_subject;
	np_msg_mode_type mode_type;
	np_msg_mep_type  mep_type;
	np_msg_ack_type  ack_mode;
	double           ttl;
	uint8_t          priority;
	uint8_t          retry; // the # of retries when sending a message
	uint16_t         msg_threshold; // current cache size
	uint16_t         max_threshold; // local cache size

	// timestamp for cleanup thread
	double          last_update;

	// cache which will hold up to max_threshold messages
	np_msgcache_policy_type cache_policy;
	np_sll_t(np_message_t, msg_cache);

	// only send/receive after opposite partner has been found
    pthread_mutex_t    lock;
    pthread_cond_t     msg_received;
    pthread_condattr_t cond_attr;

    // callback function(s) to invoke when a message is received
    np_callback_t clb; // internal neuropil supplied
    np_usercallback_t user_clb; // external user supplied
};

_NP_GENERATE_MEMORY_PROTOTYPES(np_msgproperty_t);

_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, mode_type, np_msg_mode_type);
_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, mep_type, np_msg_mep_type);
_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, ack_mode, np_msg_ack_type);
_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, ttl, double);
_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, retry, uint8_t);
_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, max_threshold, uint16_t);

_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, partner_key, np_key_t*);


/** np_msgproperty_register
 ** registers the handler function #func# with the message type #type#,
 ** it also defines the acknowledgment requirement for this type
 **/
void np_msgproperty_register(np_state_t *state, np_msgproperty_t* msgprops);

/** np_msgproperty_get
 ** return a handler for a given message subject
 **/
np_msgproperty_t* np_msgproperty_get(np_state_t *state, np_msg_mode_type msg_mode, const char* subject);

// TODO: how can this be moved to a list of constants
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
#define NP_MSG_AVAILABLE "_NP.MESSAGE.AVAILABILITY"
#define NP_MSG_AUTHENTICATION_REQUEST "_NP.MESSAGE.AUTHENTICATE"
#define NP_MSG_AUTHORIZATION_REQUEST "_NP.MESSAGE.AUTHORIZE"
#define NP_MSG_ACCOUNTING_REQUEST "_NP.MESSAGE.ACCOUNT"

/**
 ** message_init
 ** Initialize messaging subsystem on port and returns the MessageGlobal * which 
 ** contains global state of message subsystem.
 **/
void _np_msgproperty_init (np_state_t* state);

/**
 ** compare two msg properties for rb cache management
 **/
int16_t _np_msgproperty_comp(const np_msgproperty_t* const prop1, const np_msgproperty_t* const prop2);

#ifdef __cplusplus
}
#endif


#endif /* _NP_MESSAGE_H_ */
