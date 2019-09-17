//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
 The structure np_msgproperty_t is used to describe properties of the message exchange itself.
 It is setup by sender and receiver independent of each other.
 It defines attributes like a re-send counter and the type of message exchange.
 A developer should be familiar with the main settings
*/

#ifndef _NP_COMP_MSGPROPERTY_H_
#define _NP_COMP_MSGPROPERTY_H_

#include <stdarg.h>
#include "np_types.h"

#include "np_memory.h"

#include "np_util.h"
#include "np_list.h"

#include "util/np_event.h"
#include "util/np_statemachine.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _NP_URN_PREFIX						"urn:np:"
#define _NP_URN_MSG_PREFIX					"" // TODO: _NP_URN_PREFIX"msg:"
#define _NP_URN_NODE_PREFIX					_NP_URN_PREFIX"node:"
#define _NP_URN_IDENTITY_PREFIX				_NP_URN_PREFIX"id:"

#define _DEFAULT							"_NP.DEFAULT"

static const char* _NP_MSG_ACK                    = "_NP.ACK";
static const char* _NP_MSG_HANDSHAKE              = "_NP.HANDSHAKE";
static const char* _NP_MSG_JOIN_REQUEST           = "_NP.JOIN.REQUEST";
static const char* _NP_MSG_LEAVE_REQUEST          = "_NP.LEAVE.REQUEST";
static const char* _NP_MSG_PING_REQUEST           = "_NP.PING.REQUEST";
static const char* _NP_MSG_PIGGY_REQUEST          = "_NP.NODES.PIGGY";
static const char* _NP_MSG_UPDATE_REQUEST         = "_NP.NODES.UPDATE";
static const char* _NP_MSG_DISCOVER_RECEIVER      = "_NP.MESSAGE.DISCOVER.RECEIVER";
static const char* _NP_MSG_DISCOVER_SENDER        = "_NP.MESSAGE.DISCOVER.SENDER";
static const char* _NP_MSG_AVAILABLE_RECEIVER     =	"_NP.MESSAGE.RECEIVER.LIST";
static const char* _NP_MSG_AVAILABLE_SENDER	      = "_NP.MESSAGE.SENDER.LIST";
static const char* _NP_MSG_AUTHENTICATION_REQUEST =	"_NP.MESSAGE.AUTHENTICATE";
static const char* _NP_MSG_AUTHENTICATION_REPLY   = "_NP.MESSAGE.AUTHENICATION.REPLY";
static const char* _NP_MSG_AUTHORIZATION_REQUEST  = "_NP.MESSAGE.AUTHORIZE";
static const char* _NP_MSG_AUTHORIZATION_REPLY    = "_NP.MESSAGE.AUTHORIZATION.REPLY";
static const char* _NP_MSG_ACCOUNTING_REQUEST     = "_NP.MESSAGE.ACCOUNT";

/**
.. c:type:: np_msg_mode_type

   is a enum which is used to identify your role in the message exchange.
   Use INBOUND when you are a receiver, OUTBOUND when you're the sender.
   Do not worry about sending replies, this is/will be handled internally.

   use the string "mode_type" to alter this value using :c:func:`np_set_mx_properties`

*/
typedef enum np_msg_mode_enum {
    INBOUND      = 0x01,
    OUTBOUND     = 0x02,
    DEFAULT_MODE = 0x03
} NP_API_EXPORT np_msg_mode_type;

/**
.. c:type:: np_msg_mep_type

   Definition of message exchange pattern (MEP) for a exchange.
   We separate the the definition of sender and receiver, plus that we use some extra flags
   Based on the lower level definitions we then define "higher" level of MEP

   use the string "mep_type" to alter this value using :c:func:`np_set_mx_properties`

   SINGLE_[SENDER|RECEIVER]
   refers to a single identity send from a specific np_node_t

   GROUP_[SENDER|RECEIVER]
   refers to a group of np_node_t instances which share the same sending/receiving identity

   ANY_[SENDER|RECEIVER]
   refers to a group of np_node_t instances which do not share the same sending/receiving identity

   The resulting MEP is created by using a | (or) and has to match per subject of a message exchange.
   Note that if one sender uses SINGLE_SENDER and another sender uses GROUP_SENDER, the behaviour is
   as of now undefined. If you plan to use or offer a public message subject, senders should use ANY in case of doubt.
   Only rarely you will want to use SINGLE (e.g. if you plan to have a dedicated channel for a sender), because
   it is reaping you of the benefits of using a message exchange layer in your IT landscape.

   Extra Flags can be:

   FILTER_MSG
   to be implemented: apply a filter before sending/receiving a message. filter will be a callback function returning true or false

   HAS_REPLY
   check reply_to field of the incoming message to send a subject based reply (with more than one receiver)

   STICKY_REPLY
   check reply_to field of the incoming message to send a reply to one specific node

   some more human readable and more "speaking" combinations are:

   ONE_WAY   = SINGLE_SENDER | SINGLE_RECEIVER

   REQ_REP   = ONE_WAY_WITH_REPLY

   PIPELINE  = SINGLE_SENDER | GROUP_RECEVER

   AGGREGATE = SINGLE_SENDER | ANY_RECEIVER | STICKY_REPLY

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
    // ANY to ONE
    ANY_TO_ONE = ANY_SENDER | SINGLE_RECEIVER,
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

} NP_API_EXPORT np_msg_mep_type;

/**
.. c:type:: np_msgcache_policy_type

   defines the local handling of undeliverable messages. Since neuro:pil ha implemented end-to-end encryption,
   the layer has to wait for tokens to arrive before sending (=encrypting) or receiving (=decrypting) messages.
   Until this token is delivered, messages are stored in-memory in a message cache. The size of this in-memory
   cache is determined by setting the msg_threshold value of the np_msgproperty_t structure.

   use the string "policy_type" to alter this value using :c:func:`np_set_mx_properties`

   FIFO - first in first out

   LIFO - first in last out (stack)

   OVERFLOW_REJECT - reject new messages when the limit is reached

   OVERFLOW_PURGE  - purge old messages when the limit is reached

*/

typedef enum np_msgcache_policy_enum {
    UNKNOWN = 0x00,
    FIFO = 0x01,
    LIFO = 0x02,
    OVERFLOW_REJECT = 0x10,
    OVERFLOW_PURGE = 0x20
} NP_API_EXPORT np_msgcache_policy_type;

/**
.. c:type:: np_msg_ack_type

   definition of message acknowledge handling.

   use the string "ack_type" to alter this value using :c:func:`np_set_mx_properties`

   ACK_NONE        - never require a acknowledge

   ACK_DESTINATION - request the sending of a acknowledge when the message has reached the final destination

   ACK_CLIENT      - request the sending of a acknowledge when the message has reached the
   final destination and has been processed correctly (e.g. callback function returning true, see :c:func:`np_set_listener`)

   Please note: acknowledge types can be ORed (|), so you can request the acknowledge when the message receives the final destination
   and when the message has been consumed. We recommend against it because it will flood your network with acknowledges

*/
typedef enum np_msg_ack_enum {
    ACK_NONE		= 0x00, // 0000 0000  - don't ack at all
    ACK_EACHHOP		= 0x01, // 0000 0001 - each hop has to send a ack to the previous hop
    ACK_DESTINATION = 0x02, // 0000 0010 - message destination ack to message sender across multiple nodes
    ACK_CLIENT		= 0x04, // 0000 0100 - message to sender ack after/during processing the message on receiver side
} NP_API_EXPORT np_msg_ack_type;

/**
.. c:type:: np_msgproperty_t

   the structure np_msgproperty is used to define and store message exchange properties.
   When sending a message for a subject this structure is automatically created in the background
   with default reasonable values. You can change your exchange properties on the fly to implement
   a different behaviour.

   use the string "ttl" to alter the time to live of a message using :c:func:`np_set_mx_properties`

   use the string "retry" to alter the resend retries of a message using :c:func:`np_set_mx_properties`

   use the string "max_threshold" to alter the amount of messages that a nodes is willing to receive and
   the cache size of a message using :c:func:`np_set_mx_properties`
*/

struct np_msgproperty_s
{
    /*
    should not become longer than 242 characters
        255 - 13 (urn:np:...)
    */
    char*            msg_subject;
    char*            rep_subject;
    char*            msg_audience;
    np_msg_mode_type mode_type;
    np_msg_mep_type  mep_type;
    np_msg_ack_type  ack_mode;
    double           msg_ttl;
    uint8_t          priority;
    uint8_t          retry; // the # of retries when sending a message

    // The token created for this msgproperty will guaranteed invalidate after token_max_ttl seconds
    uint32_t token_max_ttl;
    // The token created for this msgproperty will guaranteed live for token_min_ttl seconds
    uint32_t token_min_ttl;

    uint16_t  msg_threshold; // current cache size
    uint16_t  max_threshold; // local cache size
    bool is_internal;

    // timestamp for cleanup thread
    double          last_update;
    double          last_tx_update;
    double          last_rx_update;    
    double          last_intent_update;

    // dhkey of node(s)/identities/realms who are interested in message exchange
    np_dhkey_t partner_key;

    // cache which will hold up to max_threshold messages
    np_msgcache_policy_type cache_policy;

    np_tree_t* response_handler;

    np_sll_t(np_message_ptr, msg_cache_in);
    np_sll_t(np_message_ptr, msg_cache_out);

    // callback function(s) to invoke when a message is received
    np_sll_t(np_evt_callback_t, clb_inbound);			// internal neuropil supplied
    np_sll_t(np_evt_callback_t, clb_outbound);			// internal neuropil supplied

    np_sll_t(np_usercallback_ptr, user_receive_clb);	// external user supplied for inbound
    np_sll_t(np_usercallback_ptr, user_send_clb);		// external user supplied for outbound

    TSP(bool, is_acked);
    np_sll_t(np_responsecontainer_on_t, on_ack);
    TSP(bool, is_in_timeout);
    np_sll_t(np_responsecontainer_on_t, on_timeout);
    TSP(bool, is_sent);
    np_sll_t(np_responsecontainer_on_t, on_send);

    TSP(bool, has_reply);
    np_sll_t(np_msgproperty_on_reply_t, on_reply);

    bool unique_uuids_check;
    uint32_t unique_uuids_max;

    np_tree_t* unique_uuids;

    np_message_intent_public_token_t* current_sender_token;
    np_message_intent_public_token_t* current_receive_token;

} NP_API_EXPORT;


_NP_GENERATE_MEMORY_PROTOTYPES(np_msgproperty_t);

/**
 ** msgproperty_init|_destroy
 ** Initialize msgproperty subsystem and register default message types
 ** contains global state of message subsystem.
 **/
NP_API_INTERN
bool _np_msgproperty_init (np_state_t* context);
NP_API_INTERN
void _np_msgproperty_destroy (np_state_t* context);

/**
.. c:function:: void np_msgproperty_register(np_state_t *state, np_msgproperty_t* msgprops)

   users of neuropil should simply use the :c:func:`np_set_mx_property` functions which will
   automatically create and set the values specified.

   registers the msg_property_t structure for neuropil to lookup message exchange properties
   an existing np_msgproperty_t structure will not be replaced

   :param state: the global neuropil :c:type:`np_state_t` structure
   :param msgprops: the np_msgproperty_t structure which should be registered
*/
NP_API_EXPORT
void np_msgproperty_register(np_msgproperty_t* msgprops);

/**
    .. c:function:: np_msgproperty_t* np_msgproperty_get(np_state_t* context, np_state_t *state, np_msg_mode_type msg_mode, const char* subject)

    users of neuropil should simply use the :c:func:`np_set_mx_property` functions which will
    automatically create and set the values specified.

    return the np_msgproperty structure for a subject and :c:type:`np_msg_mode_type`

    :param mode_type: either INBOUND or OUTBOUND (see :c:type:`np_msg_mode_type`)
    :param subject: the subject of the messages that are send
    :returns: np_msgproperty_t structure of NULL if none found
*/
NP_API_INTERN
np_msgproperty_t* _np_msgproperty_get(np_state_t* context, np_msg_mode_type msg_mode, const char* subject);
NP_API_INTERN
np_msgproperty_t* _np_msgproperty_get_or_create(np_state_t* context, np_msg_mode_type mode_type, const char* subject);

/**
    .. c:function:: void np_msgproperty_disable_check_for_unique_uuids(np_msgproperty_t* self)
    .. c:function:: void np_msgproperty_enable_check_for_unique_uuids(np_msgproperty_t* self, uint32_t remembered_uuids)

    enables or disables the functionality of the msg property to only receive unique msgs.

    :param self: the msgproperty to modify
    :param remembered_uuids: the maximum count of uuids remembered
*/
NP_API_INTERN
void _np_msgproperty_job_msg_uniquety(np_msgproperty_t* self);
NP_API_INTERN
void _np_msgproperty_remove_msg_from_uniquety_list(np_msgproperty_t* self, np_message_t* msg_to_remove);
NP_API_INTERN
bool _np_msgproperty_check_msg_uniquety(np_msgproperty_t* self, np_message_t* msg_to_check);

/**
 ** add|check|cleanup sender|receiver msgcache
 **/
NP_API_INTERN
void _np_msgproperty_check_sender_msgcache(np_msgproperty_t* send_prop);
NP_API_INTERN
void _np_msgproperty_check_receiver_msgcache(np_msgproperty_t* recv_prop, np_dhkey_t from);
NP_API_INTERN
void _np_msgproperty_add_msg_to_send_cache(np_msgproperty_t* msg_prop, np_message_t* msg_in);
NP_API_INTERN
void _np_msgproperty_add_msg_to_recv_cache(np_msgproperty_t* msg_prop, np_message_t* msg_in);
NP_API_INTERN
void _np_msgproperty_cleanup_receiver_cache(np_msgproperty_t* msg_prop);
NP_API_INTERN
void _np_msgproperty_cleanup_sender_cache(np_msgproperty_t* msg_prop);

/**
 ** handle treshold breaches
 **/
NP_API_INTERN
void _np_msgproperty_threshold_increase(np_msgproperty_t* self);
NP_API_INTERN
void _np_msgproperty_threshold_decrease(np_msgproperty_t* self);
NP_API_INTERN
bool _np_messsage_threshold_breached(np_msgproperty_t* self);


/**
 ** convert to|from user struct mx_property
 **/
NP_API_INTERN
void np_msgproperty4user(struct np_mx_properties* dest, np_msgproperty_t* src);
NP_API_INTERN
void np_msgproperty_from_user(np_state_t* context, np_msgproperty_t* dest, struct np_mx_properties* src);

NP_API_INTERN
np_dhkey_t _np_msgproperty_dhkey(np_msg_mode_type mode_type, const char* subject);

/**
 ** state machine functions and definitions
 */
NP_API_INTERN
bool __is_msgproperty(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_external_message(np_util_statemachine_t* statemachine, const np_util_event_t event); 
NP_API_INTERN
bool __is_internal_message(np_util_statemachine_t* statemachine, const np_util_event_t event); 

NP_API_INTERN
void __np_set_property(np_util_statemachine_t* statemachine, const np_util_event_t event); 
NP_API_INTERN
void __np_property_update(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_property_check(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_property_handle_in_msg(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_property_handle_out_msg(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
bool __is_payload_encrypted(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_response_handler_set(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_response_event(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
bool __is_intent_authz(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_property_handle_intent(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_property_out_usermsg(np_util_statemachine_t* statemachine, const np_util_event_t event);

/**
 ** create a new message intent token if neccessary
 **/
NP_API_INTERN
void _np_msgproperty_upsert_token(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void np_msgproperty_add_on_reply(np_msgproperty_t* self, np_msgproperty_on_reply_t on_reply);
NP_API_INTERN
void np_msgproperty_remove_on_reply(np_msgproperty_t* self, np_msgproperty_on_reply_t on_reply_to_remove);

NP_API_INTERN
void np_msgproperty_add_on_send(np_msgproperty_t* self, np_responsecontainer_on_t on_send);
NP_API_INTERN
void np_msgproperty_remove_on_send(np_msgproperty_t* self, np_responsecontainer_on_t on_send);
NP_API_INTERN
void np_msgproperty_add_on_timeout(np_msgproperty_t* self, np_responsecontainer_on_t on_timeout);
NP_API_INTERN
void np_msgproperty_remove_on_timeout(np_msgproperty_t* self, np_responsecontainer_on_t on_timeout);
NP_API_INTERN
void np_msgproperty_add_on_ack(np_msgproperty_t* self, np_responsecontainer_on_t on_ack);
NP_API_INTERN
void np_msgproperty_remove_on_ack(np_msgproperty_t* self, np_responsecontainer_on_t on_ack);


#ifdef __cplusplus
}
#endif


#endif /* _NP_COMP_MSGPROPERTY_H_ */
