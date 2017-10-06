//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version was taken from chimera project, but heavily modified
/**
neuropil.h is the entry point to use the neuropil messaging library.
It defines all user centric functions and hides the complexity of the double encryption layer.
It should contain all required functions to send or receive messages.

*/

#ifndef _NEUROPIL_H_
#define _NEUROPIL_H_

#include <pthread.h>

#include "np_types.h"
#include "np_list.h"

#define NEUROPIL_RELEASE	"neuropil 0.4.0"
#define NEUROPIL_COPYRIGHT	"copyright (C)  2016-2017 neuropil.org, Cologne, Germany"
#define NEUROPIL_TRADEMARK  "trademark (TM) 2016-2017 pi-lar GmbH, Cologne, Germany"

#ifdef __cplusplus
extern "C" {
#endif

/** \toggle_keepwhitespaces  */

/**
.. c:type:: np_state_t

   np_state_t is a structure which contains links to the various subsystems of the library
   Users should only need to call :c:func:`np_init` to initialize the neuropil messaging layer.
   No direct access to this structure is required.

*/
struct np_state_s
{
	// reference to the physical node / key
	np_key_t* my_node_key;

	// reference to main identity on this node
	np_key_t* my_identity;
	char* realm_name;

	np_tree_t *msg_tokens;
	np_tree_t* msg_part_cache;

	pthread_attr_t attr;
	pthread_t* thread_ids;

	np_sll_t(np_thread_ptr, threads);

	int thread_count;

	np_bool enable_realm_master; // act as a realm master for other nodes or not
	np_bool enable_realm_slave; // act as a realm salve and ask master for aaatokens

	np_aaa_func_t  authenticate_func; // authentication callback
	np_aaa_func_t  authorize_func;    // authorization callback
	np_aaa_func_t  accounting_func;   // really needed ?
} NP_API_INTERN;


/**
.. c:function:: np_state_t* np_init(char* protocol, char* port, np_bool start_http, char* hostname)

   Initializes the neuropil library and instructs to listen on the given port. Protocol is a string defining
   the IP protocol to use (tcp/udp/ipv4/ipv6/...), right now only udp is implemented

   :param port: the port to listen on, default is 3141
   :param proto: the default value for the protocol "udp6", which is UDP | IPv6
   :param hostname: (optional) The hostname to bind on. If not provided will be received via gethostname()
   :return: the np_state_t* which contains global state of different np sub modules or NULL on failure

*/
NP_API_EXPORT
np_state_t* np_init (char* proto, char* port, char* hostname);

/**
.. c:function:: np_state_t* np_destroy()

   stops the internal neuropil event loop and shuts down the thread pool.

*/
NP_API_EXPORT
void np_destroy();

// function to get the global state variable
NP_API_INTERN
np_state_t* _np_state();

/**
.. c:function:: void np_enable_realm_master()

   Manually set the realm and enable this node to act as a master for it.
   This will add the appropiate message callback required to handle AAA request
   send by other nodes.

*/
NP_API_EXPORT
void np_enable_realm_master();

/**
.. c:function:: void np_enable_realm_salve()

   Manually set the realm and enable this node to act as a slave in it.
   This will exchange the default callbacks (accept all) with callbacks that
   forwards tokens to the realm master.

*/
NP_API_EXPORT
void np_enable_realm_slave();

/**
.. c:function:: void np_set_realm_name(const char* realm_name)

   Manually set the realm name this node belongs to.
   This will create new dh-key and re-setup some internal structures and must be called
   after initializing with np_init and before starting the job queue

   :param realm_name: the name of the realm to act as a master for

*/
NP_API_EXPORT
void np_set_realm_name(const char* realm_name);


/**
.. c:function:: void np_set_identity(np_state_t* state, np_aaatoken_t* identity)

   Manually set the identity which is used to send and receive messages.
   This identity is independent of the core node key (which is used to build the infrastructure)

   :param state: the previously initialized :c:type:`np_state_t` structure
   :param identity: a valid :c:type:`np_aaatoken_t` structure

*/
NP_API_EXPORT
void np_set_identity(np_aaatoken_t* identity);

/**
.. c:function:: np_send_join(np_key_t* node_key);

   send a join message to another node and request to enter his network.

   :param node_key_string: the node string to which the join request is send

   see also :ref:`to_join_or_to_be_joined`

*/
NP_API_EXPORT
void np_send_join(const char* node_string);

/**
  .. c:function:: np_send_wildcard_join(np_key_t* node_key);

  Takes a node connection string and tries to connect to any node available on the other end.
  node_string should not contain a hash value (nor the trailing: character).
  Example: np_send_wildcard_join("udp4:example.com:1234");

  :param node_key_string: the node string to which the join request is send

  see also :ref:`to_join_or_to_be_joined`

 */
NP_API_EXPORT
void np_send_wildcard_join(const char* node_string);


/**
.. c:function:: np_waitforjoin()

   wait until the node has successfully joined a network.
   Sending messages if the node has not joined a network is futile
   see also :ref:`to_join_or_to_be_joined`

*/
NP_API_EXPORT
void np_waitforjoin();

/**
.. c:function:: void np_set[aaa]_cb(np_aaa_func_t join_func)
.. c:function:: void np_setauthorizing_cb
.. c:function:: void np_setauthenticate_cb
.. c:function:: void np_setaccounting_cb

   set callback function which will be called whenever authorization, authentication or account is required
   it is up to the user to define storage policies/rules for passed tokens

   :param aaa_func: a function pointer to a np_aaa_func_t function

*/
NP_API_EXPORT
void np_setauthorizing_cb(np_aaa_func_t join_func);

NP_API_EXPORT
void np_setauthenticate_cb(np_aaa_func_t join_func);

NP_API_EXPORT
void np_setaccounting_cb(np_aaa_func_t join_func);

/**
.. c:function:: void np_add_receive_listener(np_usercallback_t msg_handler, char* subject)

   register an message callback handler for a subject. The callback is called when a message arrives.
   The callback function should return TRUE if the message was processed successfully, FALSE otherwise.
   Returning FALSE will inhibit the sending of the ack and may lead to another re-delivery of the message

   :param msg_handler: a function pointer to a np_usercallback_t function
   :param subject: the message subject the handler should be called for

*/
NP_API_EXPORT
void np_add_receive_listener (np_usercallback_t msg_handler, char* subject);

/**
.. c:function:: void np_add_send_listener(np_usercallback_t msg_handler, char* subject)

register an message callback handler for a subject. The callback is called when a message will be send.
The callback function should return TRUE if the message should be send, FALSE otherwise.

:param msg_handler: a function pointer to a np_usercallback_t function
:param subject: the message subject the handler should be called for

*/
NP_API_EXPORT
void np_add_send_listener(np_usercallback_t msg_handler, char* subject);

/**
.. c:function:: void np_send_text(char* subject, char *data, uint32_t seqnum)

   Send a message of a specific subject to the receiver containing the string data

   :param subject: the subject the data should be send to
   :param data: the message text that should be send
   :param seqnum: a sequence number which will be stored in the message properties
   :param targetDhkey: (optional/nullable) a dhkey hash to define a specific receiver node

*/
NP_API_EXPORT
void np_send_text    (char* subject, char *data, uint32_t seqnum, char* targetDhkey);

/**
.. c:function:: void np_send_msg(char* subject, np_tree_t *properties, np_tree_t *body)

   Send a message of a specific subject to the receiver containing properties and body structure.
   Passed in properties and body data structures will be freed when the message has been send.

   :param subject: the subject the data should be send to
   :param properties: a tree (np_tree_t) structure containing the properties of a message
   :param body: a tree (np_tree_t) structure containing the body of a message
   :param target_key: (optional/nullable) a dhkey to define a specific receiver node

*/
NP_API_EXPORT
void np_send_msg    (char* subject, np_tree_t *properties, np_tree_t *body, np_dhkey_t* target_key);

/**
.. c:function:: uint32_t np_receive_text(char* subject, char **data)

   Receive a message of a specific subject.

   :param subject: the subject the data should be send to
   :param data: the message text that should be send
   :return: the sequence number that has been used to send the message or 0 on error

*/
NP_API_EXPORT
uint32_t np_receive_text (char* subject, char **data);

/**
.. c:function:: uint32_t np_receive_msg(char* subject, np_tree_t* properties, np_tree_t* body)

   Receive a message of a specific subject.

   :param subject: the subject the data should be received from
   :param properties: a tree (np_tree_t) structure containing the properties of the message
   :param body: a tree (np_tree_t) structure containing the body of the message
   :return: FALSE on error, TRUE on success

*/
NP_API_EXPORT
uint32_t np_receive_msg (char* subject, np_tree_t* properties, np_tree_t* body);

/**
.. c:function:: void np_set_mx_properties(char* subject, const char* key, np_treeval_t value)

   Set properties of a message exchange for a given by subject.
   Using this function the message exchange for a subject can be altered on the fly without interruption.
   For a complete list of mx properties can be found in :c:type:`np_msgproperty_t`
   Usage of this function will create a default np_msgproperty_t structure for you.

   :param subject: the subject the data should be send to
   :param key: the identifier for which a value should be set
   :param value: the value which should be set

*/
void np_set_mx_property(char* subject, const char* key, np_treeval_t value);

/**
.. c:function:: void np_rem_mx_properties(char* subject, const char* key)

   Removes a property of a message exchange for a given by subject.
   Using this function the message exchange for a subject can be altered on the fly without interruption.
   For a complete list of mx properties can be found in message.h.
   Please note that only a limited subset of properties can be removed, most MX properties
   should be modified by np_set_mx_properties.

   :param subject: the subject the data should be send to
   :param key: the identifier for which a value should be removed

*/
void np_rem_mx_property(char* subject, const char* key);

/**
.. c:function:: char*  np_get_connection_string()

   Convenience function to build the current connection string for the node.

*/
NP_API_EXPORT
char* np_get_connection_string();

/**
.. c:function:: char*  np_get_connection_string_from(np_key_t* node_key, char* hash)

   Convenience function to build the connection string for any node key.
   :param node_key: the np_key_t to build the connection string for
   :param includeHash: Include the hash into the connection string

*/
NP_API_EXPORT
char* np_get_connection_string_from(np_key_t* node_key, np_bool includeHash);

NP_API_INTERN
char* _np_build_connection_string(char* hash, char* protocol, char*dns_name, char* port, np_bool includeHash);

/**
.. c:function:: void np_start_job_queue(np_state_t* state, uint8_t pool_size)

   Start processing of messages within the neuropil subsystem

   :param pool_size: the number of threads that should compete for tasks

*/
NP_API_EXPORT
void np_start_job_queue(uint8_t pool_size);

/**
.. c:function:: void _np_ping(np_key_t* key)

   Sends a ping message to a key. Can be used to check the connectivity to a node
   The ping message is acknowledged in network layer. This function is mainly used by the neuropil subsystem.
   All it does is updating the internal np_node_t statistics to prevent possible np_node_t purging from the cache.
   In case of doubt: do not use it.

   :param key: the np_key_t where the ping should be send to

*/
NP_API_INTERN
void _np_ping(np_key_t* key);

NP_API_INTERN
void _np_send_ack(np_message_t* in_msg);


#ifdef __cplusplus
}
#endif

#endif /* _NEUROPIL_H_ */
