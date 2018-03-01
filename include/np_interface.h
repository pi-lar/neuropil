//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version was taken from chimera project, but heavily modified
/**
neuropil.h is the entry point to use the neuropil messaging library.
It defines all user centric functions and hides the complexity of the double encryption layer.
It should contain all required functions to send or receive messages.

*/

#ifndef _NP_INTERFACE_H_
#define _NP_INTERFACE_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif
	// Protocol constants
	enum {
		NP_SECRET_BYTES = 32,
		NP_PUBLIC_BYTES = 32,
		NP_FINGERPRINT_BYTES = 32
	}

	// Implementation defined limits
	#define NP_EXTENSION_BYTES (10*1024)
	#define NP_EXTENSION_MAX (NP_EXTENSION_BYTES-1)

	enum np_error {
		np_ok = 0,
		np_invalid_input,
		np_invalid_input_size,
		np_invalid_operation,
		// ...
	};

	typedef uint8_t np_id[NP_FINGERPRINT_BYTES];
	// If length is -1 then string is expected to be null-terminated.
	// char* is the appropriate type because it is the type of a string
	// and can also describe an array of bytes. (sizeof char == 1)
	void np_get_id(np_id* id, char* string, int length);

	struct np_token {
		np_id realm, issuer, subject, audience;		
		double issued_at, not_before, expires_at;
		uint8_t extensions[NP_EXTENSION_BYTES];
		size_t extension_length;			
		uint8_t public_key[NP_PUBLIC_BYTES],
                        secret_key[NP_SECRET_BYTES];
	};

	typedef void np_context;
	np_context* np_new_context(uint8_t n_threads);

	enum np_error np_listen(np_context* ac, char* protocol, char* host, uint16_t port);

	// secret_key is nullable
	struct np_token *np_new_identity(void* ac, double expires_at, uint8_t* (secret_key[SECRET_KEY_BYTES]));

	enum np_error np_set_identity(np_context* ac, struct np_token identity);

	// Get “connect string”. Signals error if connect string is unavailable (i.e.,
	// no listening interface is configured.)
	enum np_error np_get_address(void* ac, char* address, uint32_t max);

	enum np_error np_join(np_context* ac, char* address);

	enum np_error np_send(np_context* ac, uint8_t* message, size_t length, np_id* subject);

	typedef bool (*np_receive_callback)(uint8_t* message, size_t length);
	enum np_error np_receive(np_context* ac, np_receive_callback callback);

	typedef bool (*np_aaa_callback)(struct np_token* aaa_token);
	enum np_error np_authenticate(np_context* ac, np_aaa_callback callback);
	enum np_error np_authorize(np_context* ac, np_id subject, np_aaa_callback callback);

	// duration == 0 => process pending events and exit
	enum np_error np_run(np_context* ac, double duration);

	/**
	.. c:type:: np_mx_pattern

	Definition of message exchange pattern for a subject.
	We separate the the definition of sender and receiver, plus that we use some extra flags.
	Based on the lower level definitions we then define "higher" levels of patterns.

	use the string "mep_type" to alter this value using :c:func:`np_set_mx_properties`

	SINGLE_[SENDER|RECEIVER]
	refers to a single identity send from a specific np_node_t

	GROUP_[SENDER|RECEIVER]
	refers to a group of np_node_t instances which share the same sending/receiving identity

	ANY_[SENDER|RECEIVER]
	refers to a group of np_node_t instances which do not share the same sending/receiving identity

	The resulting pattern is created by using a | (or) and has to match per subject of a message exchange.
	Note that if one sender uses SINGLE_SENDER and another sender uses GROUP_SENDER, the behaviour is
	as of now undefined. If you plan to use or offer a public message subject, senders should use ANY in case of doubt.
	Only rarely you will want to use SINGLE (e.g. if you plan to have a dedicated channel for a sender), because
	it is reaping you of the benefits of using a message exchange layer in your IT landscape.

	Extra Flags can be:

	FILTER_MSG
	to be implemented: apply a filter before sending/receiving a message. filter will be a callback function returning TRUE or FALSE

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
	enum np_mx_pattern {
		NP_MX_DEFAULT_TYPE = 0x000,
		// filter mep by type
		NP_MX_RECEIVER_MASK = 0x00F,
		NP_MX_SENDER_MASK = 0x0F0,
		NP_MX_FILTER_MASK = 0xF00,
		// base pattern for communication exchange
		NP_MX_SINGLE_RECEIVER = 0x001,      // - to   one  communication // sender has single identity
		NP_MX_GROUP_RECEIVER = 0x002,       // - to   many communication // receiver has same identity
		NP_MX_ANY_RECEIVER = 0x004,         // - to   many communication // receiver is a set of identities
		NP_MX_SINGLE_SENDER = 0x010,        // - one  to   communication   // sender has a single identity
		NP_MX_GROUP_SENDER = 0x020,         // - many to   communication // sender share the same identity
		NP_MX_ANY_SENDER = 0x040,           // - many to   communication // sender is a set of identities
		// add-on message processing instructions
		NP_MX_FILTER_MSG = 0x100,           // filter a message with a given callback function (?)
		NP_MX_HAS_REPLY = 0x200,            // check reply_to field of the incoming message for a subject hash based reply
		NP_MX_STICKY_REPLY = 0x300,         // check reply_to field of the incoming message for a node hash based reply

		// possible combinations
		// ONE to ONE
		NP_MX_ONE_WAY = NP_MX_SINGLE_SENDER | NP_MX_SINGLE_RECEIVER,
		// ONE_WAY_WITH_REPLY = ONE_WAY | HAS_REPLY, // not possible, only one single sender
		NP_MX_ONE_WAY_WITH_REPLY = NP_MX_ONE_WAY | NP_MX_STICKY_REPLY,
		// ONE to GROUP
		NP_MX_ONE_TO_GROUP = NP_MX_SINGLE_SENDER | NP_MX_GROUP_RECEIVER,
		NP_MX_O2G_WITH_REPLY = NP_MX_ONE_TO_GROUP | NP_MX_STICKY_REPLY,
		// ONE to ANY
		NP_MX_ONE_TO_ANY = NP_MX_SINGLE_SENDER | NP_MX_ANY_RECEIVER,
		NP_MX_O2A_WITH_REPLY = NP_MX_ONE_TO_ANY | NP_MX_STICKY_REPLY,
		// GROUP to GROUP
		NP_MX_GROUP_TO_GROUP = NP_MX_GROUP_SENDER | NP_MX_GROUP_RECEIVER,
		NP_MX_G2G_WITH_REPLY = NP_MX_GROUP_TO_GROUP | NP_MX_HAS_REPLY,
		NP_MX_G2G_STICKY_REPLY = NP_MX_G2G_WITH_REPLY | NP_MX_STICKY_REPLY,
		// ANY to ANY
		NP_MX_ANY_TO_ANY = NP_MX_ANY_SENDER | NP_MX_ANY_RECEIVER,
		NP_MX_A2A_WITH_REPLY = NP_MX_ANY_TO_ANY | NP_MX_HAS_REPLY,
		NP_MX_A2A_STICKY_REPLY = NP_MX_A2A_WITH_REPLY | NP_MX_STICKY_REPLY,
		// GROUP to ANY
		NP_MX_GROUP_TO_ANY = NP_MX_GROUP_SENDER | NP_MX_ANY_RECEIVER,
		NP_MX_G2A_WITH_REPLY = NP_MX_GROUP_TO_ANY | NP_MX_HAS_REPLY,
		NP_MX_G2A_STICKY_REPLY = NP_MX_G2A_WITH_REPLY | NP_MX_STICKY_REPLY,
		// ANY to ONE
		NP_MX_ANY_TO_ONE = NP_MX_ANY_SENDER | NP_MX_SINGLE_RECEIVER,
		// ANY to GROUP
		NP_MX_ANY_TO_GROUP = NP_MX_ANY_SENDER | NP_MX_GROUP_RECEIVER,
		NP_MX_A2G_WITH_REPLY = NP_MX_ANY_TO_GROUP | NP_MX_HAS_REPLY,
		NP_MX_A2G_STICKY_REPLY = NP_MX_A2G_WITH_REPLY | NP_MX_STICKY_REPLY,

		// human readable and more "speaking" combinations
		NP_MX_REQ_REP = NP_MX_ONE_WAY_WITH_REPLY, // - allows to build clusters of stateless services to process requests
		NP_MX_PIPELINE = NP_MX_ONE_TO_GROUP,       // - splits up messages to a set of nodes / load balancing among many destinations
		NP_MX_AGGREGATE = NP_MX_O2A_WITH_REPLY,     // - aggregates messages from multiple sources and them among many destinations
		NP_MX_MULTICAST = NP_MX_GROUP_TO_GROUP | NP_MX_FILTER_MSG,
		NP_MX_BROADCAST = NP_MX_ONE_TO_ANY | NP_MX_GROUP_TO_ANY,
		NP_MX_INTERVIEW = NP_MX_A2G_WITH_REPLY,
		NP_MX_BUS = NP_MX_ANY_TO_ANY,
		NP_MX_SURVEY = NP_MX_A2A_STICKY_REPLY,
		NP_MX_PUBSUB = NP_MX_BUS | NP_MX_FILTER_MSG,
	};

	/**
	.. c:type:: np_mx_cache_policy

	defines the local handling of undeliverable messages. Since neuro:pil ha implemented end-to-end encryption,
	the layer has to wait for tokens to arrive before sending (=encrypting) or receiving (=decrypting) messages.
	Until this token is delivered, messages are stored in-memory in a message cache. The size of this in-memory
	cache is determined by setting the msg_threshold value of the np_msgproperty_t structure.

	use the string "policy_type" to alter this value using :c:func:`np_set_mx_properties`

	FIFO - first in first out

	FILO - first in last out (stack)

	OVERFLOW_REJECT - reject new messages when the limit is reached

	OVERFLOW_PURGE  - purge old messages when the limit is reached

	*/
	enum np_mx_cache_policy {
		NP_MX_UNKNOWN = 0x00,
		NP_MX_FIFO = 0x01,
		NP_MX_FILO = 0x02,
		NP_MX_OVERFLOW_REJECT = 0x10,
		NP_MX_OVERFLOW_PURGE = 0x20
	};

	/**
	.. c:type:: np_mx_ackmode

	definition of message acknowledge handling.

	use the string "ack_type" to alter this value using :c:func:`np_set_mx_properties`

	ACK_NONE        - never require a acknowledge

	ACK_DESTINATION - request the sending of a acknowledge when the message has reached the
	final destination

	ACK_CLIENT      - request the sending of a acknowledge when the message has reached the
	final destination and has been processed correctly (e.g. callback function returning TRUE, see :c:func:`np_set_listener`)

	Please note: acknowledge types can be ORed (|), so you can request the acknowledge between each hop and the acknowledge
	when the message receives the final destination. We recommend against it because it will flood your network with acknowledges

	*/
	enum np_mx_ackmode {
		NP_MX_ACK_NONE = 0x00,
		NP_MX_ACK_DESTINATION = 0x02,
		NP_MX_ACK_CLIENT = 0x04,
	};

	struct np_mx_properties {
		np_id reply_subject;
		enum np_mx_ackmode ackmode;
		enum np_mx_pattern pattern;
		enum np_mx_cache_policy cache_policy;
		uint16_t max_parallel; // ex threshold
		uint8_t max_retry;
		// The token created for this msgproperty will guaranteed invalidate after token_max_ttl seconds
		uint32_t max_ttl;
		// The token created for this msgproperty will guaranteed live for token_min_ttl seconds
		uint32_t min_ttl;
		bool unique_uuids_check;
	};

	enum np_error np_set_mx_properties(np_context* ac, np_id subject, struct np_mx_properties properties);
	
#ifdef __cplusplus
}
#endif

#endif /* _NP_INTERFACE_H_ */
