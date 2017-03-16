//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module neuropil
%{
#include "../include/np_types.h"
#include "../include/neuropil.h"
#include "../include/np_tree.h"
%}

struct np_tree_s
{
};

struct np_tree_elem_s
{
    np_val_t key;
    np_val_t val;
};
typedef struct np_tree_elem_s np_tree_elem_t;

%extend np_tree_s {
    np_tree_s () {
	return make_nptree();
    };
    ~np_tree_s () {
        np_free_tree ($self);
    };

    extern void np_clear_tree ($self);

    extern void tree_insert_str ($self, const char *key, np_val_t val);
    extern void tree_insert_int ($self, int16_t ikey, np_val_t val);
    extern void tree_insert_ulong ($self, uint32_t ulkey, np_val_t val);
    extern void tree_insert_dbl ($self, double dkey, np_val_t val);

    extern void tree_replace_str ($self, const char *key, np_val_t val);
    extern void tree_replace_int ($self, int16_t ikey, np_val_t val);
    extern void tree_replace_ulong ($self, uint32_t ulkey, np_val_t val);
    extern void tree_replace_dbl ($self, double dkey, np_val_t val);

    extern np_tree_elem_t* tree_find_str ($self, const char *key);
    extern np_tree_elem_t* tree_find_int ($self, int16_t ikey);
    extern np_tree_elem_t* tree_find_ulong ($self, uint32_t ikey);
    extern np_tree_elem_t* tree_find_dbl ($self, double dkey);

    extern np_tree_elem_t* tree_find_gte_str ($self, const char *key, uint8_t *found);
    extern np_tree_elem_t* tree_find_gte_int ($self, int16_t ikey, uint8_t *found);
    extern np_tree_elem_t* tree_find_gte_ulong ($self, uint32_t ikey, uint8_t *found);
    extern np_tree_elem_t* tree_find_gte_dbl ($self, double dkey, uint8_t *found);

    extern void tree_del_str ($self, const char *key);
    extern void tree_del_int ($self, const int16_t key);
    extern void tree_del_double ($self, const double key);
    extern void tree_del_ulong ($self, const uint32_t key);
};

extern char* np_create_uuid(const char* str, const uint16_t num);

typedef enum np_msg_mode_enum {
	DEFAULT_MODE = 0,
	INBOUND      = 0x1,
	OUTBOUND     = 0x2,
	ROUTE        = 0x4,
	TRANSFORM    = 0x8
} np_msg_mode_type;

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

typedef enum np_msg_ack_enum {
	ACK_NONE = 0x00, // 0000 0000  - don't ack at all
	ACK_EACHHOP = 0x01, // 0000 0001 - each hop has to send a ack to the previous hop
	ACK_DESTINATION = 0x02, // 0000 0010 - message destination ack to message sender across multiple nodes
	ACK_CLIENT = 0x04,     // 0000 0100 - message to sender ack after/during processing the message on receiver side
} np_msg_ack_type;

struct np_msgproperty_s
{
    // link to node(s) which is/are interested in message exchange
    np_dhkey_t partner_key;
    char*            msg_subject;
    char*            rep_subject;
    char*            msg_audience;
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
    // callback function(s) to invoke when a message is received
    np_usercallback_t user_clb; // external user supplied for inbound
};
extern void np_msgproperty_register(np_msgproperty_t* msgprops);
extern np_msgproperty_t* np_msgproperty_get(np_msg_mode_type msg_mode, const char* subject);

extern void np_mem_newobj(np_obj_enum obj_type, np_obj_t** obj);
extern void np_mem_freeobj(np_obj_enum obj_type, np_obj_t** obj);
extern void np_mem_refobj(np_obj_t* obj);
extern void np_mem_unrefobj(np_obj_t* obj);

typedef enum np_log_e log_type;
enum np_log_e
{
    LOG_NONE       = 0x0000, /* log nothing        */
    LOG_NOMOD      = 0x0000, /*           */

    LOG_ERROR      = 0x0001, /* error messages     */
    LOG_WARN       = 0x0002, /* warning messages   */
    LOG_INFO       = 0x0004, /* info messages      */
    LOG_DEBUG      = 0x0008, /* debugging messages */
    LOG_TRACE      = 0x0010, /* tracing messages   */

    LOG_KEY        = 0x0100, /* debugging messages for key subsystem */
    LOG_NETWORK    = 0x0200, /* debugging messages for network layer */
    LOG_ROUTING    = 0x0400, /* debugging the routing table          */
    LOG_MESSAGE    = 0x0800, /* debugging the message subsystem      */
    LOG_SECURE     = 0x1000, /* debugging the security module        */
    LOG_HTTP       = 0x2000, /* debugging the message subsystem      */
    LOG_AAATOKEN   = 0x4000, /* debugging the message subsystem      */
    LOG_GLOBAL     = 0x8000, /* debugging the global system          */

    LOG_MODUL_MASK = 0xFF00, /* debugging the global system          */
    LOG_NOMOD_MASK = 0x7F00, /* debugging the global system          */
};

extern void np_log_init (const char* filename, uint16_t level);
extern void np_log_setlevel(uint16_t level);
extern void np_log_destroy ();

extern void _np_add_http_callback(const char* path, htp_method method, void* user_args, _np_http_callback_func_t func);
extern void _np_rem_http_callback(const char* path, htp_method method);

extern np_state_t* np_init (char* proto, char* port, np_bool start_http);
extern void np_destroy();

extern void np_enable_realm_master();
extern void np_enable_realm_slave();
extern void np_set_realm_name(const char* realm_name);
extern void np_set_identity(np_aaatoken_t* identity);

extern void np_send_join(const char* node_string);
extern void np_waitforjoin();

extern void np_setauthorizing_cb(np_aaa_func_t join_func);
extern void np_setauthenticate_cb(np_aaa_func_t join_func);
extern void np_setaccounting_cb(np_aaa_func_t join_func);

extern void np_set_listener (np_usercallback_t msg_handler, char* subject);

extern void np_send_text (char* subject, char *data, uint32_t seqnum);
extern void np_send_msg (char* subject, np_tree_t *properties, np_tree_t *body);

extern uint32_t np_receive_text (char* subject, char **data);
extern uint32_t np_receive_msg (char* subject, np_tree_t* properties, np_tree_t* body);

extern void np_start_job_queue(uint8_t pool_size);

typedef np_bool (*np_aaa_func_t) (np_aaatoken_t* aaa_token );
typedef np_bool (*np_usercallback_t) (np_tree_t* msg_properties, np_tree_t* msg_body);
typedef void (*np_callback_t) (np_jobargs_t*);
