/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_MESSAGE_H_
#define _NP_MESSAGE_H_

#include <stdarg.h>

#include "include.h"

#include "jval.h"
#include "np_container.h"
#include "np_jtree.h"
#include "np_key.h"
#include "np_memory.h"
#include "np_util.h"

#define NP_MESSAGE_SIZE 65536

struct np_messagepart_s {
	np_jtree_t* header;
	np_jtree_t* instructions;
	void* msg_part;
};

typedef np_messagepart_t* np_messagepart_ptr;
NP_PLL_GENERATE_PROTOTYPES(np_messagepart_ptr);

struct np_message_s {
	np_obj_t* obj; // link to memory pool

	np_jtree_t* header;
	np_jtree_t* instructions;
	np_jtree_t* properties;
	np_jtree_t* body;
	np_jtree_t* footer;

	// only used if the message has to be split up into chunks
	np_bool is_single_part;
	uint16_t no_of_chunks;
	np_pll_t(np_messagepart_ptr, msg_chunks);
};

_NP_GENERATE_MEMORY_PROTOTYPES(np_message_t);


/** message_create / free:
 ** creates the message to the destination #dest# the message format would be like:
 ** deletes the message and corresponding structures
 **/
void np_message_create(np_message_t* msg, np_key_t* to, np_key_t* from, const char* subject, np_jtree_t* the_data);

void np_message_encrypt_payload(np_state_t* state, np_message_t* msg, np_aaatoken_t* tmp_token);
np_bool np_message_decrypt_payload(np_state_t* state, np_message_t* msg, np_aaatoken_t* tmp_token);

// encrypt / decrypt parts of a message
np_bool np_message_decrypt_part(np_jtree_t* msg_part, unsigned char* enc_nonce, unsigned char* public_key, unsigned char* private_key);
np_bool np_message_encrypt_part(np_jtree_t* msg_part, unsigned char* enc_nonce, unsigned char* public_key, unsigned char* private_key);

// (de-) serialize a message to a binary stream using message pack (cmp.h)
void np_message_calculate_chunking(np_message_t* msg);
np_message_t* np_message_check_chunks_complete(np_state_t* state, np_jobargs_t* args);
np_bool np_message_serialize(np_message_t* msg, void* buffer, uint64_t* out_size);
np_bool np_message_serialize_chunked(np_state_t* state, np_jobargs_t* args);
np_bool np_message_deserialize(np_message_t* msg, void* buffer);
np_bool np_message_deserialize_chunked(np_message_t* msg);

void np_message_setinstruction(np_message_t* msg, np_jtree_t* instructions);
void np_message_addinstructionentry(np_message_t*, const char* key, np_jval_t value);
void np_message_delinstructionentry(np_message_t*, const char* key);

void np_message_setproperties(np_message_t* msg, np_jtree_t* properties);
void np_message_addpropertyentry(np_message_t*, const char* key, np_jval_t value);
void np_message_delpropertyentry(np_message_t*, const char* key);

void np_message_setbody(np_message_t* msg, np_jtree_t* body);
void np_message_addbodyentry(np_message_t*, const char* key, np_jval_t value);
void np_message_delbodyentry(np_message_t*, const char* key);

inline void np_message_setfooter(np_message_t* msg, np_jtree_t* footer);
void np_message_addfooterentry(np_message_t*, const char* key, np_jval_t value);
void np_message_delfooterentry(np_message_t*, const char* key);


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
	STICKY_REPLY = 0x300,         // check reply_to filed of the incoming message for a node hash based reply

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
    // group sender
    char*            group_id;

    char*            msg_subject;
	np_msg_mode_type msg_mode;
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

_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, max_threshold, uint16_t);
_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, retry, uint8_t);
_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, priority, uint8_t);
_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, ttl, double);
_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, msg_mode, np_msg_mode_type);
_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, mep_type, np_msg_mep_type);
_NP_GENERATE_PROPERTY_SETVALUE(np_msgproperty_t, ack_mode, np_msg_ack_type);
_NP_GENERATE_PROPERTY_SETSTR(np_msgproperty_t, group_id);
_NP_GENERATE_PROPERTY_SETSTR(np_msgproperty_t, msg_subject);


#define RETRANSMIT_THREAD_SLEEP 1.0
#define RETRANSMIT_INTERVAL 5

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
#define NP_MSG_INTEREST_REJECT "_NP.MESSAGE.INTEREST.REJECTION"
#define NP_MSG_AVAILABLE "_NP.MESSAGE.AVAILABILITY"
#define NP_MSG_AUTHENTICATION_REQUEST "_NP.MESSAGE.AUTHENTICATE"

// msg header constants
static const char* NP_MSG_HEADER_SUBJECT   = "_np.subj";
static const char* NP_MSG_HEADER_TO        = "_np.to";
static const char* NP_MSG_HEADER_FROM      = "_np.from";
static const char* NP_MSG_HEADER_REPLY_TO  = "_np.r_to";

// msg instructions constants
static const char* NP_MSG_INST_SEND_COUNTER = "_np.sendnr";
static const char* NP_MSG_INST_PART         = "_np.part";
static const char* NP_MSG_INST_PARTS        = "_np.parts";
static const char* NP_MSG_INST_ACK          = "_np.ack";
static const char* NP_MSG_INST_ACK_TO       = "_np.ack_to";
static const char* NP_MSG_INST_SEQ          = "_np.seq";
static const char* NP_MSG_INST_UUID         = "_np.uuid";
static const char* NP_MSG_INST_ACKUUID      = "_np.ackuuid";
static const char* NP_MSG_INST_TTL          = "_np.ttl";
static const char* NP_MSG_INST_TSTAMP       = "_np.tstamp";

// msg handshake constants
static const char* NP_HS_PAYLOAD = "_np.payload";
static const char* NP_HS_SIGNATURE = "_np.signature";

// body constants
static const char* NP_MSG_BODY_JTREE = "_np.jtree";
static const char* NP_MSG_BODY_TEXT = "_np.text";
static const char* NP_MSG_BODY_XML = "_np.xml";

// encrypted message part
static const char* NP_NONCE = "_np.nonce";
static const char* NP_ENCRYPTED = "_np.encrypted";
static const char* NP_SYMKEY = "_np.symkey";

// msg footer constants
static const char* NP_MSG_FOOTER_ALIAS_KEY = "_np.alias_key";
static const char* NP_MSG_FOOTER_GARBAGE = "_np.garbage";


/**
 ** message_init
 ** Initialize messaging subsystem on port and returns the MessageGlobal * which 
 ** contains global state of message subsystem.
 **/
void _np_message_init (np_state_t* state);

/**
 ** compare two msg properties for rb cache management
 **/
int16_t _np_property_comp(const np_msgproperty_t* const prop1, const np_msgproperty_t* const prop2);

/** np_message_register_handler
 ** registers the handler function #func# with the message type #type#,
 ** it also defines the acknowledgment requirement for this type
 **/
void np_message_register_handler (np_state_t *state, np_msgproperty_t* msgprops);

/** np_message_get_handler
 *  return a handler for a given message subject
 **/
np_msgproperty_t* np_message_get_handler (np_state_t *state, np_msg_mode_type msg_mode, const char* subject);


#endif /* _NP_MESSAGE_H_ */
