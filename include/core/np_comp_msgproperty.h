//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#ifndef _NP_COMP_MSGPROPERTY_H_
#define _NP_COMP_MSGPROPERTY_H_

#include <stdarg.h>

#include "neuropil.h"

#include "util/np_bloom.h"
#include "util/np_event.h"
#include "util/np_list.h"
#include "util/np_statemachine.h"

#include "np_dhkey.h"
#include "np_memory.h"
#include "np_types.h"
#include "np_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The component msgproperty is responsible to handle incoming and outgoing
 * messages. it is used as a placeholder for topics and resides in two memory
 * locations: the dhkey of the message subject concatenated with INBOUND, and
 * the dhkey of the message subject concatenated with OUTBOUND. If an event is
 * received, usually a list of registered callbacks is executed, the internal
 * callbacks first, the user supplied callbacks afterwards for incoming
 * mnessages. for outgoing messages the order is reversed: user supplied
 * callbacks first, internal messages callbacks afterwards. internal message
 * subjects are fixed because of the neuropil implementation and cannot be
 * changed.
 *
 * The structure np_msgproperty_conf_t is used to describe properties of the
 * message exchange itself. It is setup by sender and receiver independent of
 * each other. It defines attributes like a re-send counter and the type of
 * message exchange. A developer should be familiar with the main attributes and
 * settings
 */

#define _NP_URN_PREFIX           "urn:np"
#define _NP_URN_MSG_PREFIX       "" // TODO: _NP_URN_PREFIX"msg:"
#define _NP_URN_NODE_PREFIX      _NP_URN_PREFIX ":node"
#define _NP_URN_IDENTITY_PREFIX  _NP_URN_PREFIX ":id"
#define _NP_URN_INTENT_PREFIX    _NP_URN_PREFIX ":intent"
#define _NP_URN_HANDSHAKE_PREFIX _NP_URN_PREFIX ":hs"

static const char *_DEFAULT = "_NP.DEFAULT"; // 12
static const char *_FORWARD = "_NP.FORWARD"; // 12

static const char *_NP_MSG_ACK              = "_NP.ACK";              // 8
static const char *_NP_MSG_HANDSHAKE        = "_NP.HANDSHAKE";        // 14
static const char *_NP_MSG_JOIN_REQUEST     = "_NP.JOIN.REQUEST";     // 17
static const char *_NP_MSG_LEAVE_REQUEST    = "_NP.LEAVE.REQUEST";    // 18
static const char *_NP_MSG_PING_REQUEST     = "_NP.PING.REQUEST";     // 17
static const char *_NP_MSG_PIGGY_REQUEST    = "_NP.NODES.PIGGY";      // 16
static const char *_NP_MSG_UPDATE_REQUEST   = "_NP.NODES.UPDATE";     // 17
static const char *_NP_MSG_PHEROMONE_UPDATE = "_NP.PHEROMONE.UPDATE"; // 21
static const char *_NP_MSG_AVAILABLE_RECEIVER =
    "_NP.MESSAGE.RECEIVER.TOKEN";                                         // 27
static const char *_NP_MSG_AVAILABLE_SENDER = "_NP.MESSAGE.SENDER.TOKEN"; // 25

static const char *_NP_MSG_AUTHENTICATION_REQUEST =
    "_NP.MESSAGE.AUTHENTICATE"; // 25
static const char *_NP_MSG_AUTHENTICATION_REPLY =
    "_NP.MESSAGE.AUTHENICATION.REPLY"; // 32
static const char *_NP_MSG_AUTHORIZATION_REQUEST =
    "_NP.MESSAGE.AUTHORIZE"; // 22
static const char *_NP_MSG_AUTHORIZATION_REPLY =
    "_NP.MESSAGE.AUTHORIZATION.REPLY";                                 // 32
static const char *_NP_MSG_ACCOUNTING_REQUEST = "_NP.MESSAGE.ACCOUNT"; // 20

/**
.. c:type:: np_msg_mode_type

   is a enum which is used to identify your role in the message exchange.
   Use INBOUND when you are a receiver, OUTBOUND when you're the sender.
   Do not worry about sending replies, this is/will be handled internally.

   use the string "mode_type" to alter this value using
:c:func:`np_set_mx_properties`

*/
typedef enum np_msg_mode_enum {
  WIRE_FORMAT  = 0x00,
  INBOUND      = 0x01,
  OUTBOUND     = 0x02,
  DEFAULT_MODE = 0x03
} NP_API_EXPORT np_msg_mode_type;

/**
.. c:type:: np_msg_mep_type

   Definition of message exchange pattern (MEP) for a exchange.
   We separate the the definition of sender and receiver, plus that we use some
extra flags Based on the lower level definitions we then define "higher" level
of MEP

   use the string "mep_type" to alter this value using
:c:func:`np_set_mx_properties`

   SINGLE_[SENDER|RECEIVER]
   refers to a single identity send from a specific np_node_t

   GROUP_[SENDER|RECEIVER]
   refers to a group of np_node_t instances which share the same
sending/receiving identity

   ANY_[SENDER|RECEIVER]
   refers to a group of np_node_t instances which do not share the same
sending/receiving identity

   The resulting MEP is created by using a | (or) and has to match per subject
of a message exchange. Note that if one sender uses SINGLE_SENDER and another
sender uses GROUP_SENDER, the behaviour is as of now undefined. If you plan to
use or offer a public message subject, senders should use ANY in case of doubt.
   Only rarely you will want to use SINGLE (e.g. if you plan to have a dedicated
channel for a sender), because it is reaping you of the benefits of using a
message exchange layer in your IT landscape.

   Extra Flags can be:

   FILTER_MSG
   to be implemented: apply a filter before sending/receiving a message. filter
will be a callback function returning true or false

   HAS_REPLY
   check reply_to field of the incoming message to send a subject based reply
(with more than one receiver)

   STICKY_REPLY
   check reply_to field of the incoming message to send a reply to one specific
node

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
  SINGLE_RECEIVER =
      0x001, // - to   one  communication // sender has single identity
  GROUP_RECEIVER =
      0x002, // - to   many communication // receiver has same identity
  ANY_RECEIVER =
      0x004, // - to   many communication // receiver is a set of identities
  SINGLE_SENDER =
      0x010, // - one  to   communication   // sender has a single identity
  GROUP_SENDER =
      0x020, // - many to   communication // sender share the same identity
  ANY_SENDER =
      0x040, // - many to   communication // sender is a set of identities
  // add-on message processing instructions
  FILTER_MSG = 0x100,   // filter a message with a given callback function (?)
  HAS_REPLY  = 0x200,   // check reply_to field of the incoming message for a
                        // subject hash based reply
  STICKY_REPLY = 0x300, // check reply_to field of the incoming message for a
                        // node hash based reply

  // possible combinations
  // ONE to ONE
  ONE_WAY = SINGLE_SENDER | SINGLE_RECEIVER,
  // ONE_WAY_WITH_REPLY = ONE_WAY | HAS_REPLY, // not possible, only one single
  // sender
  ONE_WAY_WITH_REPLY = ONE_WAY | STICKY_REPLY,
  // ONE to GROUP
  ONE_TO_GROUP   = SINGLE_SENDER | GROUP_RECEIVER,
  O2G_WITH_REPLY = ONE_TO_GROUP | STICKY_REPLY,
  // ONE to ANY
  ONE_TO_ANY     = SINGLE_SENDER | ANY_RECEIVER,
  O2A_WITH_REPLY = ONE_TO_ANY | STICKY_REPLY,
  // GROUP to GROUP
  GROUP_TO_GROUP   = GROUP_SENDER | GROUP_RECEIVER,
  G2G_WITH_REPLY   = GROUP_TO_GROUP | HAS_REPLY,
  G2G_STICKY_REPLY = G2G_WITH_REPLY | STICKY_REPLY,
  // ANY to ANY
  ANY_TO_ANY       = ANY_SENDER | ANY_RECEIVER,
  A2A_WITH_REPLY   = ANY_TO_ANY | HAS_REPLY,
  A2A_STICKY_REPLY = A2A_WITH_REPLY | STICKY_REPLY,
  // GROUP to ANY
  GROUP_TO_ANY     = GROUP_SENDER | ANY_RECEIVER,
  G2A_WITH_REPLY   = GROUP_TO_ANY | HAS_REPLY,
  G2A_STICKY_REPLY = G2A_WITH_REPLY | STICKY_REPLY,
  // ANY to ONE
  ANY_TO_ONE = ANY_SENDER | SINGLE_RECEIVER,
  // ANY to GROUP
  ANY_TO_GROUP     = ANY_SENDER | GROUP_RECEIVER,
  A2G_WITH_REPLY   = ANY_TO_GROUP | HAS_REPLY,
  A2G_STICKY_REPLY = A2G_WITH_REPLY | STICKY_REPLY,

  // human readable and more "speaking" combinations
  REQ_REP = ONE_WAY_WITH_REPLY, // - allows to build clusters of stateless
                                // services to process requests
  PIPELINE = ONE_TO_GROUP,      // - splits up messages to a set of nodes / load
                                // balancing among many destinations
  AGGREGATE = O2A_WITH_REPLY, // - aggregates messages from multiple sources and
                              // them among many destinations
  MULTICAST = GROUP_TO_GROUP | FILTER_MSG,
  BROADCAST = ONE_TO_ANY | GROUP_TO_ANY,
  INTERVIEW = A2G_WITH_REPLY,
  BUS       = ANY_TO_ANY,
  SURVEY    = A2A_STICKY_REPLY,
  PUBSUB    = BUS | FILTER_MSG,

} NP_API_EXPORT np_msg_mep_type;

/**
.. c:type:: np_msgcache_policy_type

   defines the local handling of undeliverable messages. Since neuropil has
implemented end-to-end encryption, the layer has to wait for tokens to arrive
before sending (=encrypting) or receiving (=decrypting) messages. Until tokens
are delivered, messages are stored in-memory in a message cache. The size of
this in-memory cache is determined by setting the msg_threshold value of the
np_msgproperty_conf_t structure.

   use the string "policy_type" to alter this value using
:c:func:`np_set_mx_properties`

   FIFO - first in first out

   LIFO - first in last out (stack)

   OVERFLOW_REJECT - reject new messages when the limit is reached

   OVERFLOW_PURGE  - purge old messages when the limit is reached

*/

typedef enum np_msgcache_policy_enum {
  UNKNOWN         = 0x00,
  FIFO            = 0x01,
  LIFO            = 0x02,
  OVERFLOW_REJECT = 0x10,
  OVERFLOW_PURGE  = 0x20
} NP_API_EXPORT np_msgcache_policy_type;

/**
.. c:type:: np_msg_ack_type

   definition of message acknowledge handling.

   use the string "ack_type" to alter this value using
:c:func:`np_set_mx_properties`

   ACK_NONE        - never require a acknowledge

   ACK_DESTINATION - request the sending of a acknowledge when the message has
reached the final destination

   ACK_CLIENT      - request the sending of a acknowledge when the message has
reached the final destination and has been processed correctly (e.g. callback
function returning true, see :c:func:`np_set_listener`)

   Please note: acknowledge types can be ORed (|), so you can request the
acknowledge when the message receives the final destination and when the message
has been consumed. We recommend against it because it will flood your network
with acknowledges

*/
typedef enum np_msg_ack_enum {
  ACK_NONE        = 0x00, // 0000 0000  - don't ack at all
  ACK_DESTINATION = 0x01, // 0000 0010 - message destination ack to message
                          // sender across multiple nodes
  ACK_CLIENT = 0x02,      // 0000 0100 - message to sender ack after/during
                          // processing the message on receiver side
} NP_API_EXPORT np_msg_ack_type;

/**
.. c:type:: np_msgproperty_conf_t

   the structure np_msgproperty is used to define and store message exchange
properties. When sending a message for a subject this structure is automatically
created in the background with default reasonable values. You can change your
exchange properties on the fly to implement a different behaviour.

   use the string "ttl" to alter the time to live of a message using
:c:func:`np_set_mx_properties`

   use the string "retry" to alter the resend retries of a message using
:c:func:`np_set_mx_properties`

   use the string "max_threshold" to alter the amount of messages that a nodes
is willing to receive and the cache size of a message using
:c:func:`np_set_mx_properties`
*/

struct np_msgproperty_conf_s {
  /*
  should not become longer than 242 characters
      255 - 13 (urn:np:...)
  */
  char *msg_subject;
  char *rep_subject;

  // char*            msg_audience;
  np_msg_mode_type mode_type;
  np_msg_mep_type  mep_type;
  np_msg_ack_type  ack_mode;
  double           msg_ttl;
  uint8_t          priority;
  uint8_t          retry; // the # of retries when sending a message

  // The token created for this msgproperty will guaranteed invalidate after
  // token_max_ttl seconds
  uint32_t token_max_ttl;
  // The token created for this msgproperty will guaranteed live for
  // token_min_ttl seconds
  uint32_t token_min_ttl;

  // cache which will hold up to max_threshold messages
  np_msgcache_policy_type cache_policy;
  uint16_t                cache_size;

  uint32_t max_threshold; // local threshhold size

  bool unique_uuids_check;

  // internal message subject
  bool                     is_internal;
  enum np_mx_audience_type audience_type;
  np_dhkey_t               audience_id;

  np_dhkey_t reply_dhkey; // blake2b hash of the "rep_subject", in case of user
                          // supplied np_subject the other way round

  np_dhkey_t subject_dhkey; // blake2b hash of the 'msg_subject'
  // np_dhkey_t       subject_dhkey_wire; // blake2b hash of 'msg_subject' and
  // 'audience' (if set, and depending on audience_type)
  np_dhkey_t subject_dhkey_in;  // combination of 'final_subject_dhkey' and
                                // 'local_rx' // internal only
  np_dhkey_t subject_dhkey_out; // combination of 'final_subject_dhkey' and
                                // 'local_tx' // internal only

} NP_API_EXPORT;

/**
 * runtime section of the np_msgproperty_conf_t structure
 * based on the settings above the following field are required during runtime
 * to store messages callbacks, calculate the runtime np_dhkey_t values and to
 * store teh actual attributes
 */
struct np_msgproperty_run_s {
  // authorization callback for this specific subject
  np_aaa_callback authorize_func;
  // the fingerprint of the currently used token
  np_dhkey_t current_fp;
  // timestamp for cleanup thread
  double last_update;
  // user settable properties share the same property, thus we have to
  // differentiate between tx and rx
  double last_intent_update;
  double last_pheromone_update;

  uint32_t msg_threshold; // current threshold size

  np_dll_t(np_message_ptr, msg_cache);

  // callback function(s) to invoke when a message is received
  np_sll_t(np_evt_callback_t, callbacks); // internal neuropil supplied
  np_sll_t(np_usercallback_ptr,
           user_callbacks); // external user supplied for inbound

  TSP(bool, has_reply);
  np_sll_t(np_msgproperty_on_reply_t, on_reply);

  uint32_t unique_uuids_max;

  np_tree_t *response_handler;    // handler for ack messages
  np_tree_t *redelivery_messages; // storage for redelivery of messages
  np_tree_t *unique_uuids;        // uuid check incoming messages

  // a set of attributes for this data channel
  np_attributes_t attributes;
  // a set of required attributes / policy for this data channel
  np_bloom_t *required_attributes_policy;

} NP_API_EXPORT;

_NP_GENERATE_MEMORY_PROTOTYPES(np_msgproperty_conf_t);
_NP_GENERATE_MEMORY_PROTOTYPES(np_msgproperty_run_t);

/**
 ** msgproperty_init|_destroy
 ** Initialize msgproperty subsystem and register default message types
 ** contains global state of message subsystem.
 **/
NP_API_INTERN
bool _np_msgproperty_init(np_state_t *context);
NP_API_INTERN
void _np_msgproperty_destroy(np_state_t *context);

/**
.. c:function:: void np_msgproperty_register(np_state_t *state,
np_msgproperty_conf_t* msgprops)

   users of neuropil should simply use the :c:func:`np_set_mx_property`
functions which will automatically create and set the values specified.

   registers the msg_property_t structure for neuropil to lookup message
exchange properties an existing np_msgproperty_conf_t structure will not be
replaced

   :param state: the global neuropil :c:type:`np_state_t` structure
   :param msgprops: the np_msgproperty_conf_t structure which should be
registered
*/
NP_API_EXPORT
void np_msgproperty_register(np_msgproperty_conf_t *msgprops);

/**
    .. c:function:: np_msgproperty_conf_t* np_msgproperty_get(np_state_t*
   context, np_state_t *state, np_msg_mode_type msg_mode, const char* subject)

    users of neuropil should simply use the :c:func:`np_set_mx_property`
   functions which will automatically create and set the values specified.

    return the np_msgproperty structure for a subject and
   :c:type:`np_msg_mode_type`

    :param mode_type: either INBOUND or OUTBOUND (see
   :c:type:`np_msg_mode_type`) :param subject: the subject of the messages that
   are send :returns: np_msgproperty_conf_t structure of NULL if none found
*/
NP_API_INTERN
np_msgproperty_conf_t *_np_msgproperty_conf_get(np_state_t      *context,
                                                np_msg_mode_type msg_mode,
                                                np_dhkey_t       subject);
NP_API_INTERN
np_msgproperty_conf_t *_np_msgproperty_get_or_create(np_state_t      *context,
                                                     np_msg_mode_type mode_type,
                                                     np_dhkey_t       subject);
NP_API_INTERN
np_msgproperty_run_t *_np_msgproperty_run_get(np_state_t      *context,
                                              np_msg_mode_type mode_type,
                                              np_dhkey_t       subject);

/**
    .. c:function:: void
   np_msgproperty_disable_check_for_unique_uuids(np_msgproperty_conf_t* self)
    .. c:function:: void
   np_msgproperty_enable_check_for_unique_uuids(np_msgproperty_conf_t* self,
   uint32_t remembered_uuids)

    enables or disables the functionality of the msg property to only receive
   unique msgs.

    :param self: the msgproperty to modify
    :param remembered_uuids: the maximum count of uuids remembered
*/
// NP_API_INTERN
// void _np_msgproperty_job_msg_uniquety(np_msgproperty_run_t* self);
NP_API_INTERN
void _np_msgproperty_remove_msg_from_uniquety_list(np_msgproperty_run_t *self,
                                                   np_message_t *msg_to_remove);
NP_API_INTERN
void _np_msgproperty_job_msg_uniquety(np_msgproperty_conf_t *self_conf,
                                      np_msgproperty_run_t  *self_run);
NP_API_INTERN
bool _np_msgproperty_check_msg_uniquety(np_msgproperty_conf_t *self_conf,
                                        np_msgproperty_run_t  *self_run,
                                        np_message_t          *msg_to_check);

// void _np_msgproperty_job_msg_uniquety(np_msgproperty_conf_t* self_conf,
// np_msgproperty_run_t* self_run); bool
// _np_msgproperty_check_msg_uniquety(np_msgproperty_run_t* self, np_message_t*
// msg_to_check); NP_API_INTERN bool
// _np_msgproperty_check_msg_uniquety_out(np_msgproperty_run_t* self,
// np_message_t* msg_to_check);

/**
 ** add|check|cleanup sender|receiver msgcache
 **/
// NP_API_INTERN
// void _np_msgproperty_check_sender_msgcache(np_msgproperty_run_t* send_prop);
NP_API_INTERN
void __np_property_add_msg_to_cache(np_util_statemachine_t *statemachine,
                                    const np_util_event_t   event);
NP_API_INTERN
void _np_msgproperty_check_msgcache(np_util_statemachine_t *statemachine,
                                    NP_UNUSED const np_util_event_t event);
NP_API_INTERN
void _np_msgproperty_check_msgcache_for(np_util_statemachine_t *statemachine,
                                        const np_util_event_t   event);
NP_API_INTERN
void _np_msgproperty_cleanup_cache(np_util_statemachine_t         *statemachine,
                                   NP_UNUSED const np_util_event_t event);

/**
 ** check redelivery of already encrypted messages
 **/
NP_API_INTERN
void __np_msgproperty_redeliver_messages(np_util_statemachine_t *statemachine,
                                         const np_util_event_t   event);

/**
 ** handle treshold breaches
 **/
/*
NP_API_INTERN
void _np_msgproperty_threshold_increase(np_msgproperty_conf_t* self_conf,
np_msgproperty_run_t* self); NP_API_INTERN void
_np_msgproperty_threshold_decrease(np_msgproperty_conf_t* self_conf,
np_msgproperty_run_t* self); NP_API_INTERN bool
_np_msgproperty_threshold_breached(np_msgproperty_conf_t* self_conf,
np_msgproperty_run_t* self);
*/

/**
 ** temporarily disable / enable message intent token exchange
 **/
void __np_property_lifecycle_set(np_util_statemachine_t *statemachine,
                                 const np_util_event_t   event);
bool __is_msgproperty_lifecycle_disable(np_util_statemachine_t *statemachine,
                                        const np_util_event_t   event);
bool __is_msgproperty_lifecycle_enable(np_util_statemachine_t *statemachine,
                                       const np_util_event_t   event);

/**
 ** convert to|from user struct mx_property
 **/
NP_API_INTERN
void np_msgproperty4user(struct np_mx_properties *dest,
                         np_msgproperty_conf_t   *src);
NP_API_INTERN
void np_msgproperty_from_user(np_state_t              *context,
                              np_msgproperty_conf_t   *dest,
                              struct np_mx_properties *src);

NP_API_INTERN
np_dhkey_t _np_msgproperty_dhkey(np_msg_mode_type mode_type,
                                 const char      *subject);
NP_API_INTERN
np_dhkey_t _np_msgproperty_tweaked_dhkey(np_msg_mode_type mode_type,
                                         np_dhkey_t       subject_dhkey);

/**
 ** state machine functions and definitions
 */
NP_API_INTERN
bool __is_msgproperty(np_util_statemachine_t *statemachine,
                      const np_util_event_t   event);
NP_API_INTERN
bool __is_external_message(np_util_statemachine_t *statemachine,
                           const np_util_event_t   event);
NP_API_INTERN
bool __is_internal_message(np_util_statemachine_t *statemachine,
                           const np_util_event_t   event);
NP_API_INTERN
bool __is_no_token_available(np_util_statemachine_t *statemachine,
                             const np_util_event_t   event);
NP_API_INTERN
bool __is_sender_token_available(np_util_statemachine_t *statemachine,
                                 const np_util_event_t   event);
NP_API_INTERN
bool __is_receiver_token_available(np_util_statemachine_t *statemachine,
                                   const np_util_event_t   event);

NP_API_INTERN
void __np_set_property(np_util_statemachine_t *statemachine,
                       const np_util_event_t   event);
NP_API_INTERN
void __np_property_update(np_util_statemachine_t *statemachine,
                          const np_util_event_t   event);
NP_API_INTERN
void __np_property_check(np_util_statemachine_t *statemachine,
                         const np_util_event_t   event);
NP_API_INTERN
void __np_property_handle_in_msg(np_util_statemachine_t *statemachine,
                                 const np_util_event_t   event);
NP_API_INTERN
void __np_property_handle_out_msg(np_util_statemachine_t *statemachine,
                                  const np_util_event_t   event);

NP_API_INTERN
bool __is_payload_encrypted(np_util_statemachine_t *statemachine,
                            const np_util_event_t   event);

NP_API_INTERN
void __np_response_handler_set(np_util_statemachine_t *statemachine,
                               const np_util_event_t   event);
NP_API_INTERN
bool __is_response_event(np_util_statemachine_t *statemachine,
                         const np_util_event_t   event);

NP_API_INTERN
void __np_property_redelivery_set(np_util_statemachine_t *statemachine,
                                  const np_util_event_t   event);
NP_API_INTERN
bool __is_message_redelivery_event(np_util_statemachine_t *statemachine,
                                   const np_util_event_t   event);

NP_API_INTERN
bool __is_intent_authz(np_util_statemachine_t *statemachine,
                       const np_util_event_t   event);
NP_API_INTERN
void __np_property_handle_intent(np_util_statemachine_t *statemachine,
                                 const np_util_event_t   event);
NP_API_INTERN
void __np_property_out_usermsg(np_util_statemachine_t *statemachine,
                               const np_util_event_t   event);

/**
 ** create a new message intent token if neccessary
 **/
NP_API_INTERN
void _np_msgproperty_upsert_token(np_util_statemachine_t *statemachine,
                                  const np_util_event_t   event);

#ifdef __cplusplus
}
#endif

#endif /* _NP_COMP_MSGPROPERTY_H_ */
