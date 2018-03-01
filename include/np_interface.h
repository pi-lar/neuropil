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

//#include <np_intern.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NP_EXTENSION_BYTES (10*1024)
#define NP_SECRET_BYTES (4096)
#define NP_PUBLIC_BYTES (999)
#define NP_FINGERPRINT_BYTES (64)

	enum np_error {
		np_error_none = 0,
		np_error_invalid_input,
		np_error_invalid_input_size,
		np_error_wrong_process_order,
	};

	typedef void np_application_context;
	typedef uint8_t np_id[NP_FINGERPRINT_BYTES];

	np_application_context* np_build_application_context(uint8_t prefered_no_of_threads);
	void np_get_id(np_id* out, unsigned char* data, uint32_t data_size);
	enum np_error np_get_address(np_application_context* ac, unsigned char* buffer, uint32_t buffer_size);

	enum np_ip_port_type {
		np_ip_port_type_udp,
		np_ip_port_type_tcp
	};
	enum np_connection_type {
		np_connection_type_ip4,
		np_connection_type_ip6
	};

	typedef struct np_connection_ip6 {
		uint8_t ip_v4[16];
		uint16_t ip_port;
		enum ip_port_type ip_port_type;
	} np_connection_ip6;

	typedef struct np_connection_ip4 {
		uint8_t ip_v4[4];
		uint16_t ip_port;
		enum ip_port_type ip_port_type;
	} np_connection_ip4;

	typedef struct np_connection {
		np_id hash;
		union {
			np_connection_ip4 ip4;
			np_connection_ip6 ip6;
		};
		enum np_connection_type connection_type;
	} np_connection;

	enum np_error  np_send_data(np_application_context* ac, void* data, uint32_t size, np_id subject);

	enum np_error np_connect(np_application_context* ac, struct np_connection c);
	enum np_error np_connect_to(np_application_context* ac, char* connection_str);

	enum np_error np_listen(np_application_context* ac, struct np_connection on);
	enum np_error np_listen_on(np_application_context* ac, char* on);

	typedef struct np_token {
		np_id realm, issuer, subject, audience;
		double issued_at, not_before, expires_at;
		uint8_t extension_bytes[NP_EXTENSION_BYTES],
			public_key[NP_PUBLIC_BYTES],
			secret_key[NP_SECRET_BYTES];
		uint32_t extension_length;
	} np_token;

	enum np_error  np_set_identity(np_application_context* ac, struct np_token ident);

	// duration == 0 => run infinite
	enum np_error  np_run(np_application_context* ac, uint32_t duration);

	typedef bool(*np_receive_callback) (void* data, uint32_t data_size);
	enum np_error  np_add_on_receive(np_application_context* ac, np_receive_callback clb);
	uint32_t np_pull_data(np_application_context* ac, char * subject, void* buffer, uint32_t buffer_size);

	/**
	.. c:type:: np_mx_mep_type

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
	enum np_mx_mep_type {
		np_mx_mep_type_DEFAULT_TYPE = 0x000,
		// filter mep by type
		np_mx_mep_type_RECEIVER_MASK = 0x00F,
		np_mx_mep_type_SENDER_MASK = 0x0F0,
		np_mx_mep_type_FILTER_MASK = 0xF00,
		// base pattern for communication exchange
		np_mx_mep_type_SINGLE_RECEIVER = 0x001,      // - to   one  communication // sender has single identity
		np_mx_mep_type_GROUP_RECEIVER = 0x002,       // - to   many communication // receiver has same identity
		np_mx_mep_type_ANY_RECEIVER = 0x004,         // - to   many communication // receiver is a set of identities
		np_mx_mep_type_SINGLE_SENDER = 0x010,        // - one  to   communication   // sender has a single identity
		np_mx_mep_type_GROUP_SENDER = 0x020,         // - many to   communication // sender share the same identity
		np_mx_mep_type_ANY_SENDER = 0x040,           // - many to   communication // sender is a set of identities
		// add-on message processing instructions
		np_mx_mep_type_FILTER_MSG = 0x100,           // filter a message with a given callback function (?)
		np_mx_mep_type_HAS_REPLY = 0x200,            // check reply_to field of the incoming message for a subject hash based reply
		np_mx_mep_type_STICKY_REPLY = 0x300,         // check reply_to field of the incoming message for a node hash based reply

		// possible combinations
		// ONE to ONE
		np_mx_mep_type_ONE_WAY = np_mx_mep_type_SINGLE_SENDER | np_mx_mep_type_SINGLE_RECEIVER,
		// ONE_WAY_WITH_REPLY = ONE_WAY | HAS_REPLY, // not possible, only one single sender
		np_mx_mep_type_ONE_WAY_WITH_REPLY = np_mx_mep_type_ONE_WAY | np_mx_mep_type_STICKY_REPLY,
		// ONE to GROUP
		np_mx_mep_type_ONE_TO_GROUP = np_mx_mep_type_SINGLE_SENDER | np_mx_mep_type_GROUP_RECEIVER,
		np_mx_mep_type_O2G_WITH_REPLY = np_mx_mep_type_ONE_TO_GROUP | np_mx_mep_type_STICKY_REPLY,
		// ONE to ANY
		np_mx_mep_type_ONE_TO_ANY = np_mx_mep_type_SINGLE_SENDER | np_mx_mep_type_ANY_RECEIVER,
		np_mx_mep_type_O2A_WITH_REPLY = np_mx_mep_type_ONE_TO_ANY | np_mx_mep_type_STICKY_REPLY,
		// GROUP to GROUP
		np_mx_mep_type_GROUP_TO_GROUP = np_mx_mep_type_GROUP_SENDER | np_mx_mep_type_GROUP_RECEIVER,
		np_mx_mep_type_G2G_WITH_REPLY = np_mx_mep_type_GROUP_TO_GROUP | np_mx_mep_type_HAS_REPLY,
		np_mx_mep_type_G2G_STICKY_REPLY = np_mx_mep_type_G2G_WITH_REPLY | np_mx_mep_type_STICKY_REPLY,
		// ANY to ANY
		np_mx_mep_type_ANY_TO_ANY = np_mx_mep_type_ANY_SENDER | np_mx_mep_type_ANY_RECEIVER,
		np_mx_mep_type_A2A_WITH_REPLY = np_mx_mep_type_ANY_TO_ANY | np_mx_mep_type_HAS_REPLY,
		np_mx_mep_type_A2A_STICKY_REPLY = np_mx_mep_type_A2A_WITH_REPLY | np_mx_mep_type_STICKY_REPLY,
		// GROUP to ANY
		np_mx_mep_type_GROUP_TO_ANY = np_mx_mep_type_GROUP_SENDER | np_mx_mep_type_ANY_RECEIVER,
		np_mx_mep_type_G2A_WITH_REPLY = np_mx_mep_type_GROUP_TO_ANY | np_mx_mep_type_HAS_REPLY,
		np_mx_mep_type_G2A_STICKY_REPLY = np_mx_mep_type_G2A_WITH_REPLY | np_mx_mep_type_STICKY_REPLY,
		// ANY to ONE
		np_mx_mep_type_ANY_TO_ONE = np_mx_mep_type_ANY_SENDER | np_mx_mep_type_SINGLE_RECEIVER,
		// ANY to GROUP
		np_mx_mep_type_ANY_TO_GROUP = np_mx_mep_type_ANY_SENDER | np_mx_mep_type_GROUP_RECEIVER,
		np_mx_mep_type_A2G_WITH_REPLY = np_mx_mep_type_ANY_TO_GROUP | np_mx_mep_type_HAS_REPLY,
		np_mx_mep_type_A2G_STICKY_REPLY = np_mx_mep_type_A2G_WITH_REPLY | np_mx_mep_type_STICKY_REPLY,

		// human readable and more "speaking" combinations
		np_mx_mep_type_REQ_REP = np_mx_mep_type_ONE_WAY_WITH_REPLY, // - allows to build clusters of stateless services to process requests
		np_mx_mep_type_PIPELINE = np_mx_mep_type_ONE_TO_GROUP,       // - splits up messages to a set of nodes / load balancing among many destinations
		np_mx_mep_type_AGGREGATE = np_mx_mep_type_O2A_WITH_REPLY,     // - aggregates messages from multiple sources and them among many destinations
		np_mx_mep_type_MULTICAST = np_mx_mep_type_GROUP_TO_GROUP | np_mx_mep_type_FILTER_MSG,
		np_mx_mep_type_BROADCAST = np_mx_mep_type_ONE_TO_ANY | np_mx_mep_type_GROUP_TO_ANY,
		np_mx_mep_type_INTERVIEW = np_mx_mep_type_A2G_WITH_REPLY,
		np_mx_mep_type_BUS = np_mx_mep_type_ANY_TO_ANY,
		np_mx_mep_type_SURVEY = np_mx_mep_type_A2A_STICKY_REPLY,
		np_mx_mep_type_PUBSUB = np_mx_mep_type_BUS | np_mx_mep_type_FILTER_MSG,
	};

	/**
	.. c:type:: np_mx_cache_policy_type

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
	enum np_mx_cache_policy_type {
		np_mx_cache_policy_type_UNKNOWN = 0x00,
		np_mx_cache_policy_type_FIFO = 0x01,
		np_mx_cache_policy_type_FILO = 0x02,
		np_mx_cache_policy_type_OVERFLOW_REJECT = 0x10,
		np_mx_cache_policy_type_OVERFLOW_PURGE = 0x20
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
		np_mx_ackmode_ACK_NONE = 0x00, 			
		np_mx_ackmode_ACK_DESTINATION = 0x02, 	
		np_mx_ackmode_ACK_CLIENT = 0x04, 	  	
	};

	typedef struct np_message_exchange {
		np_id reply_subject;
		enum np_mx_ackmode ackmode;
		enum np_mx_mep_type mep;
		enum np_mx_cache_policy_type cache_policy;
		uint16_t max_parallel; // ex threshold
		uint8_t max_retry;
		// The token created for this msgproperty will guaranteed invalidate after token_max_ttl seconds
		uint32_t max_ttl;
		// The token created for this msgproperty will guaranteed live for token_min_ttl seconds
		uint32_t min_ttl;
		bool unique_uuids_check;
	} np_message_exchange;

	enum np_error  np_register_subject(np_application_context* c, np_id subject, struct np_message_exchange exchange_config);

	typedef bool(*np_authenticate_callback) (struct np_token token);
	enum np_error  np_authenticate(np_application_context* ac, np_authenticate_callback clb);
	struct np_token np_pull_authenticate(np_application_context* ac);

	typedef bool(*np_authorize_callback) (struct np_token token);
	enum np_error  np_authorize(np_application_context* ac, np_id subject, np_authorize_callback clb);
	struct np_token np_pull_authorize(np_application_context* ac, np_id subject);

#ifdef __cplusplus
}
#endif

#endif /* _NP_INTERFACE_H_ */
