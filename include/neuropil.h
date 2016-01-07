/**
neuropil.h is the entry point for using the neuropil library.

It defines all user centric functions whcih hide the complexity of the double encryption layer.
It should contain all required functions to send or receive messages.
Original version is based on the chimera project (MIT licensed), but mostly renamed and heavily modified

copyright 2015 pi-lar GmbH

*/
#ifndef _NEUROPIL_H_
#define _NEUROPIL_H_

#include <pthread.h>

#include "include.h"
#include "np_container.h"
#include "np_key.h"

#ifdef __cplusplus
extern "C" {
#endif

SPLAY_HEAD(spt_key, np_key_s);
SPLAY_PROTOTYPE(spt_key, np_key_s, link, key_comp);

RB_HEAD(rbt_msgproperty, np_msgproperty_s);
RB_PROTOTYPE(rbt_msgproperty, np_msgproperty_s, link, property_comp);

/**
.. c:type:: np_state_t

   The only global structure which contains links to the various subsystems.
   Users should only need to call np_init() to initialize neuropil layer.
*/
struct np_state_s {

	// reference to a private key
	np_key_t* my_node_key;
	// reference to the runtime node
	np_key_t* my_identity;

	// red-black-structure to maintain objects adressable with an hash key
	struct spt_key key_cache; //  = SPLAY_INITIALIZER(&key_cache);
	struct rbt_msgproperty msg_properties;

	np_jtree_t *msg_tokens;
    np_jtree_t* msg_part_cache;

	np_routeglobal_t   *routes;
    np_joblist_t       *jobq;

    pthread_mutex_t lock;
    pthread_attr_t attr;
    pthread_t* thread_ids;

	np_aaa_func_t  authenticate_func; // authentication callback
	np_aaa_func_t  authorize_func;    // authorization callback
	np_aaa_func_t  accounting_func;   // really needed ?
};


/**
.. c:function:: np_state_t* np_init(char* protocol, char* port)

   Initializes neuropil subsystem to listen on the given port. Protocol is a string defining
   the IP protocol to use (tcp/udp/ipv4/ipv6/...)

   :param port: the port to listen on, default is 3141
   :param proto: the default value for the protocol "udp6", which is UDP | IPv6
   :return: the np_state_t* which contains global state of different np sub modules or NULL on failure
*/
np_state_t* np_init (char* proto, char* port);

/**
.. c:function:: void np_set_identity(np_state_t* state, np_aaatoken_t* identity)

   Manually set the identity which is used to send and receive messages.
   This identity is independent of the core node key used to form the infrastructure

   :param state: the previously initialized np_state_t structure
   :param identity: a valid :c:type:np_aaatoken_t structure
*/
void np_set_identity(np_state_t* state, np_aaatoken_t* identity);

/**
.. c:function:: np_waitforjoin(const np_state_t* state)

   wait until the node has successfully joined a network.
   Sending messages if the node has not joined a network is futile
   see also :ref:`to_join_or_to_be_joined`
*/
void np_waitforjoin(const np_state_t* state);

/**
.. c:function:: void np_set[aaa]_cb(np_state_t* state, np_aaa_func_t join_func)
.. c:function:: void np_setauthorizing_cb
.. c:function:: void np_setauthenticate_cb
.. c:function:: void np_setaccounting_cb

   set callback function which will be called whenever authorization, authentication or account is required
   it is up to the user to define storage policies/rules for passed tokens

   :param state: the previously initialized np_state_t structure
   :param aaa_func: a function pointer to a np_aaa_func_t function
*/
void np_setauthorizing_cb(np_state_t* state, np_aaa_func_t join_func);
void np_setauthenticate_cb(np_state_t* state, np_aaa_func_t join_func);
void np_setaccounting_cb(np_state_t* state, np_aaa_func_t join_func);


/**
.. c:function:: void np_set_listener(np_state_t* state, np_usercallback_t msg_handler, char* subject)

   register an message handler for a subject which is called by the np routing layer when a message arrives.
   The callback function should return TRUE if the message was processed successfully, FALSE otherwise.
   Returning FALSE will inhibit the sending of the ack and may lead to another re-delivery of the message

   :param state: the previously initialized np_state_t structure
   :param msg_handler: a function pointer to a np_usercallback_t function
   :param subject: the message subject the handler should be called for
*/
void np_set_listener (np_state_t* state, np_usercallback_t msg_handler, char* subject);

/**
.. c:function:: void np_send_text(np_state_t* state, char* subject, char *data, uint32_t seqnum)

   Send a message of a specific subject to the receiver containing size bytes of data

   :param state: the previously initialized np_state_t structure
   :param subject: the subject the data should be send to
   :param data: the message text that should be send
   :param seqnum: a sequence number shich will be stored in the message properties
*/
void np_send_text    (np_state_t* state, char* subject, char *data, uint32_t seqnum);

/**
.. c:function:: void np_send_msg(np_state_t* state, char* subject, np_jtree_t *properties, np_jtree_t *body)

   Send a message of a specific subject to the receiver containing size bytes of data.
   passed in properties and body data structures will be freed when the message has been send.

   :param state: the previously initialized np_state_t structure
   :param subject: the subject the data should be send to
   :param properties: a tree (np_jtree_t) structure containing the properties of a message
   :param body: a tree (np_jtree_t) structure containing the body of a message
*/
void np_send_msg    (np_state_t* state, char* subject, np_jtree_t *properties, np_jtree_t *body);

/**
.. c:function:: uint32_t np_receive_text(np_state_t* state, char* subject, char **data)

   Receive a message of a specific subject.

   :param state: the previously initialized np_state_t structure
   :param subject: the subject the data should be send to
   :param data: the message text that should be send
   :return: the sequence number that has been used to send the message or 0 on error
*/
uint32_t np_receive_text (np_state_t* state, char* subject, char **data);

/**
.. c:function:: uint32_t np_receive_msg(np_state_t* state, char* subject, np_jtree_t* properties, np_jtree_t* body)

   Receive a message of a specific subject.

   :param state: the previously initialized np_state_t structure
   :param subject: the subject the data should be send to
   :param properties: a tree (np_jtree_t) structure containing the properties of the message
   :param body: a tree (np_jtree_t) structure containing the body of the message
   :return: the sequence number that has been used to send the message or 0 on error
*/
uint32_t np_receive_msg (np_state_t* state, char* subject, np_jtree_t* properties, np_jtree_t* body);

/**
.. c:function:: void np_set_mx_properties(np_state_t* state, char* subject, const char* key, np_jval_t value)

   Set properties of a message exchange for a given by subject.
   Using this function the message exchange for a subject can be altered on the fly without interuption.
   For a complete list of mx properties can be found in message.h

   :param state: the previously initialized np_state_t structure
   :param subject: the subject the data should be send to
   :param key: the identifier for which a value should be set
   :param value: the value which should be set
*/
void np_set_mx_property(np_state_t* state, char* subject, const char* key, np_jval_t value);

/**
.. c:function:: void np_rem_mx_properties(np_state_t* state, char* subject, const char* key)

   Removes a property of a message exchange for a given by subject.
   Using this function the message exchange for a subject can be altered on the fly without interuption.
   For a complete list of mx properties can be found in message.h.
   Please note that only a limited subset of proerties can be removed, most MX properties
   should be modified by np_set_mx_properties.

   :param state: the previously initialized np_state_t structure
   :param subject: the subject the data should be send to
   :param key: the identifier for which a value should be removed
*/
void np_rem_mx_property(np_state_t* state, char* subject, const char* key);

/**
.. c:function:: void np_start_job_queue(np_state_t* state, uint8_t pool_size)

   Start processing of messages withing the neuropil subsystem

   :param state: the previously initialized np_state_t structure
   :param pool_size: the number of threads that should compete for tasks
*/
void np_start_job_queue(np_state_t* state, uint8_t pool_size);

/**
.. c:function:: void _np_ping(np_state_t* state, np_key_t* key)

   Sends a ping message to a key. Can be used to check the connectivity to a node
   The ping message is acknowledged in network layer. This function is mainly used by the neuropil subsystem.
   All it does is updating the internal np_node_t statistics to prevent possible np_node_t purging from the cache.
   In case of doubt: do not use it.

   :param state: the previously initialized np_state_t structure
   :param key: the np_key_t where the ping should be send to
*/
void _np_ping(np_state_t* state, np_key_t* key);

void _np_send_ack(np_state_t* state, np_message_t* in_msg);


#ifdef __cplusplus
}
#endif

#endif /* _NEUROPIL_H_ */
