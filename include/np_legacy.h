//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version was taken from chimera project, but heavily modified
/**
np_legacy.h is the entry point to use the neuropil messaging library.
It defines all user centric functions and hides the complexity of the double encryption layer.
It should contain all required functions to send or receive messages.

*/

#ifndef _NEUROPIL_H_
#define _NEUROPIL_H_

#include <assert.h>
#ifdef NP_BENCHMARKING
#include <math.h>
#endif
#include <float.h>

#include <pthread.h>


#include "np_constants.h"
#include "np_settings.h"

#include "neuropil.h"

#include "np_types.h"
#include "np_list.h"
#include "np_memory.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "map.h"
#include "np_scache.h"

#include "core/np_comp_msgproperty.h"


#ifdef __cplusplus
extern "C" {
#endif
#define np_ctx_by_memory(c)				\
        np_memory_get_context((void*)c)
#define np_ctx_decl(b)				\
        np_state_t* context = (b)
#define np_ctx_memory(a)				\
        np_ctx_decl(np_ctx_by_memory(a));


#define NP_CTX_MODULES route, memory, threads, events, statistics, keycache, http, sysinfo, log, jobqueue, shutdown, bootstrap, time, msgproperties

/**
\toggle_keepwhitespaces
*/
#define np_module_struct(m) struct CONCAT(np_, CONCAT(m, _module_s))
#define np_module_type(m) CONCAT(np_, CONCAT(m, _module_t))

#define np_module_typedef(m) typedef np_module_struct(m) np_module_type(m);

#define np_module_member_name(m) CONCAT(np_module_, m)
#define np_module_member(m) np_module_type(m) * np_module_member_name(m);

#define np_module_var(m) np_module_struct(m) * _module = np_module(m);

#define np_module_malloc(m) 														\
        np_module_struct(m) * _module = calloc(1, sizeof(np_module_struct(m)));		\
        _module->context = context;													\
        context->np_module_member_name(m) = _module

#define np_module_free(m) 														    \
        free(context->np_module_member_name(m));                                    \
        context->np_module_member_name(m) = NULL

#define np_module(m) (context->np_module_member_name(m))
#define np_module_initiated(m) (context->np_module_member_name(m) != NULL)

#define np_ctx_cast(ac)				\
    assert(ac != NULL);				\
    np_state_t* context = ac;		\


MAP(np_module_typedef, NP_CTX_MODULES);

/**
.. c:type:: np_state_t

   np_state_t is a structure which contains links to the various subsystems of the library
   Users should only need to call :c:func:`np_init` to initialize the neuropil messaging layer.
   No direct access to this structure is required.

*/
struct np_state_s
{
    TSP(enum np_status, status);
    struct np_settings* settings;
    //void* modules[np_modules_END];
    MAP(np_module_member, NP_CTX_MODULES)


    // reference to the physical node / key
    np_key_t* my_node_key;

    // reference to main identity on this node
    np_key_t* my_identity;
    char* realm_name;

    np_tree_t *msg_tokens;
    np_tree_t* msg_part_cache;

    int thread_count;

    bool enable_realm_server; // act as a realm server for other nodes or not
    bool enable_realm_client; // act as a realm client and ask server for aaatokens


    np_aaa_callback authenticate_func; // authentication callback
    np_aaa_callback authorize_func;    // authorization callback
    np_aaa_callback accounting_func;   // really needed ?

    void* userdata;
} NP_API_INTERN;



/**
.. c:function:: void np_enable_realm_server()

   Manually set the realm and enable this node to act as a server for it.
   This will add the appropiate message callback required to handle AAA request
   send by other nodes.

*/
NP_API_EXPORT
void np_enable_realm_server(np_context*ac);

/**
.. c:function:: void np_enable_realm_client()

   Manually set the realm and enable this node to act as a client in it.
   This will exchange the default callbacks (accept all) with callbacks that
   forwards tokens to the realm server.

*/
NP_API_EXPORT
void np_enable_realm_client(np_context*ac);

/**
.. c:function:: void np_set_realm_name(const char* realm_name)

   Manually set the realm name this node belongs to.
   This will create new dh-key and re-setup some internal structures and must be called
   after initializing with np_init and before starting the job queue

   :param realm_name: the name of the realm to act as a server for

*/
NP_API_EXPORT
void np_set_realm_name(np_context*ac, const char* realm_name);


/**
.. c:function:: void _np_set_identity(np_state_t* state, np_aaatoken_t* identity)

   Manually set the identity which is used to send and receive messages.
   This identity is independent of the core node key (which is used to build the infrastructure)

   :param state: the previously initialized :c:type:`np_state_t` structure
   :param identity: a valid :c:type:`np_aaatoken_t` structure

*/
NP_API_INTERN
void _np_set_identity(np_context*ac, np_aaatoken_t* identity);

/**
.. c:function:: np_send_join(np_key_t* node_key);

   send a join message to another node and request to enter his network.

   :param node_key_string: the node string to which the join request is send

   see also :ref:`to_join_or_to_be_joined`

*/
NP_API_EXPORT
void np_send_join(np_context*ac, const char* node_string);

/**
  .. c:function:: np_send_wildcard_join(np_key_t* node_key);

  Takes a node connection string and tries to connect to any node available on the other end.
  node_string should not contain a hash value (nor the trailing: character).
  Example: np_send_wildcard_join("udp4:example.com:1234");

  :param node_key_string: the node string to which the join request is send

  see also :ref:`to_join_or_to_be_joined`

 */
NP_API_EXPORT
void np_send_wildcard_join(np_context*ac, const char* node_string);


/**
.. c:function:: np_waitforjoin()

   wait until the node has successfully joined a network.
   Sending messages if the node has not joined a network is futile
   see also :ref:`to_join_or_to_be_joined`

*/
NP_API_EXPORT
void np_waitforjoin(np_context*ac);

/**
.. c:function:: void np_add_receive_listener(np_usercallback_t msg_handler, char* subject)

   register an message callback handler for a subject. The callback is called when a message arrives.
   The callback function should return true if the message was processed successfully, false otherwise.
   Returning false will inhibit the sending of the ack and may lead to another re-delivery of the message

   :param msg_handler: a function pointer to a np_usercallback_t function
   :param subject: the message subject the handler should be called for

*/
NP_API_EXPORT
void np_add_receive_listener (np_context* ac, np_usercallbackfunction_t msg_handler_fn, void* msg_handler_localdata, const char* subject);

/**
.. c:function:: void np_add_send_listener(np_usercallback_t msg_handler, char* subject)

   register an message callback handler for a subject. The callback is called when a message will be send.
   The callback function should return true if the message should be send, false otherwise.

   :param msg_handler: a function pointer to a np_usercallback_t function
   :param subject: the message subject the handler should be called for

*/
NP_API_EXPORT
void np_add_send_listener(np_context*ac, np_usercallbackfunction_t msg_handler_fn, void* msg_handler_localdata, const char* subject);
 
/**
.. c:function:: void np_send_msg(char* subject, np_tree_t *properties, np_tree_t *body)

   Send a message of a specific subject to the receiver containing properties and body structure.
   Passed in properties and body data structures will be freed when the message has been send.

   :param subject: the subject the data should be send to
   :param body: a tree (np_tree_t) structure containing the body of a message
   :param target_key: (optional/nullable) a dhkey to define a specific receiver node

*/
NP_API_EXPORT
void np_send_msg (np_context*ac, const char* subject, np_tree_t *body, np_dhkey_t* target_key);
 
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
void np_set_mx_property(np_context*ac, char* subject, const char* key, np_treeval_t value);

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
void np_rem_mx_property(np_context*ac, char* subject, const char* key);

/**
.. c:function:: char*  np_get_connection_string()

   Convenience function to build the current connection string for the node.

*/
NP_API_EXPORT
char* np_get_connection_string(np_context*ac);

/**
.. c:function:: char*  np_get_connection_string_from(np_key_t* node_key, char* hash)

   Convenience function to build the connection string for any node key.
   :param node_key: the np_key_t to build the connection string for
   :param includeHash: Include the hash into the connection string

*/
NP_API_EXPORT
char* np_get_connection_string_from(np_key_t* node_key, bool includeHash);

NP_API_EXPORT
char* np_build_connection_string(char* hash, char* protocol, char*dns_name, char* port, bool includeHash);

/**
.. c:function:: void _np_ping_send(np_state_t* context, np_key_t* key)

   Sends a ping message to a key. Can be used to check the connectivity to a node
   The ping message is acknowledged in network layer. This function is mainly used by the neuropil subsystem.
   All it does is updating the internal np_node_t statistics to prevent possible np_node_t purging from the cache.
   In case of doubt: do not use it.

   :param key: the np_key_t where the ping should be send to
*/
NP_API_INTERN
void _np_ping_send(np_state_t* context, np_key_t* key);


NP_API_INTERN
void _np_send_ack(const np_message_t * const msg_to_ack, enum np_msg_ack_enum type);

#define np_time_now() _np_time_now(context)
NP_API_PROTEC
double _np_time_now(np_state_t* context);

NP_API_PROTEC
double np_time_sleep(double sleeptime);

NP_API_INTERN
np_message_t* _np_send_simple_invoke_request_msg(np_key_t* target, const char* type);

NP_API_EXPORT
void np_send_response_msg(np_context*ac, np_message_t* original, np_tree_t *body);

NP_API_INTERN
np_message_t* _np_prepare_msg(np_state_t *context, const char* subject, np_tree_t *body, np_dhkey_t* target_key);

NP_API_INTERN
void _np_context_create_new_nodekey(np_context* ac, np_node_t* base);

NP_API_INTERN
bool _np_default_authorizefunc(np_context*ac, struct np_token* token);

NP_API_INTERN
bool _np_default_authenticatefunc(np_context*ac, struct  np_token* token);

NP_API_INTERN
bool _np_default_accountingfunc(np_context*ac, struct  np_token* token);

#ifdef __cplusplus
}
#endif

#endif /* _NEUROPIL_H_ */
