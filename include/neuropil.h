//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

/* neuropil API v2 */

#ifndef _NP_INTERFACE_H_
#define _NP_INTERFACE_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NEUROPIL_RELEASE	"neuropil_0.7.1"

#define NEUROPIL_COPYRIGHT	"copyright (C)  2016-2018 neuropil.org, Cologne, Germany"
#define NEUROPIL_TRADEMARK  "trademark (TM) 2016-2018 pi-lar GmbH, Cologne, Germany"


    /* just in case NULL is not defined */
#ifndef NULL
#define NULL (void*)0
#endif

    //
    // int __attribute__((overloadable)) square(int);

#if defined(__APPLE__) && defined(__MACH__)
    #define NP_ENUM __attribute__ ((flag_enum))
#else
    #define NP_ENUM 
#endif

#define NP_CONST __attribute__ ((const))
#define NP_PURE  __attribute__ ((pure))

#ifndef NP_PACKED
#define NP_PACKED(x)  __attribute__ ((packed, aligned(x)))
#endif
#define NP_DEPRECATED __attribute__ ((deprecated("!!! DEPRECATED !!!")))


#if defined(TEST_COMPILE) || defined(DEBUG)
#define NP_UNUSED     __attribute__ ((unused))
#define NP_API_HIDDEN __attribute__ ((visibility ("default")))
#define NP_API_PROTEC __attribute__ ((visibility ("default")))
#define NP_API_INTERN __attribute__ ((visibility ("default")))
#else
#ifndef NP_UNUSED
#define NP_UNUSED     __attribute__ ((unused))
#endif
#ifndef NP_API_PROTEC
#define NP_API_PROTEC __attribute__ ((visibility ("default")))
#endif
#ifndef NP_API_HIDDEN
#define NP_API_HIDDEN __attribute__ ((visibility ("default")))
#endif
#ifndef NP_API_INTERN
#define NP_API_INTERN __attribute__ ((visibility ("default")))
#endif
#endif

#ifndef NP_API_EXPORT
#define NP_API_EXPORT __attribute__ ((visibility ("default")))
#endif


    // Protocol constants
    enum {
        NP_SECRET_KEY_BYTES = 32U + 32U,
        NP_PUBLIC_KEY_BYTES = 32U,
        NP_FINGERPRINT_BYTES = 32U,
        NP_UUID_BYTES = 37U
    } NP_ENUM;

    // Implementation defined limits
    #define NP_EXTENSION_BYTES (10*1024)
    #define NP_EXTENSION_MAX (NP_EXTENSION_BYTES-1)

    enum np_status {
        np_error = 0,
        np_uninitialized,
        np_running,
        np_stopped,
        np_shutdown,		
    } NP_ENUM;

    enum np_error {
        np_ok = 0,
        np_not_implemented,
        np_network_error,
        np_invalid_argument,
        np_invalid_operation,
        np_startup
        // ...
    } NP_ENUM;

    static const char* np_error_str[] = {
        "",
        "operation is not implemented",
        "could not init network",
        "argument is invalid",
        "operation is currently invalid",
        "insufficient memory",
        "startup error. See log for more details"
    };
    
    typedef void np_context;    

    typedef uint8_t np_id[NP_FINGERPRINT_BYTES];
    
    // If length is 0 then string is expected to be null-terminated.
    // char* is the appropriate type because it is the type of a string
    // and can also describe an array of bytes. (sizeof char == 1)
    void np_get_id(np_context * context, np_id* id, char* string, size_t length);

    struct np_token {
        char uuid[NP_UUID_BYTES];
        char subject[255]; // todo: has to be np_id
        char issuer[65]; // todo: has to be np_id		
        char realm[255]; // todo: has to be np_id		
        char audience[255]; // todo: has to be np_id		

        double  issued_at, not_before, expires_at;

        uint8_t extensions[NP_EXTENSION_BYTES];
        size_t  extension_length;
        uint8_t public_key[NP_PUBLIC_KEY_BYTES],
                secret_key[NP_SECRET_KEY_BYTES];
    } NP_PACKED(1);
    
    struct np_message {
        char uuid[NP_UUID_BYTES];
        np_id from; 
        np_id subject;		
        double received_at;
        uint8_t * data;
        size_t data_length;
    };
        
    struct np_settings {
        uint32_t n_threads;
        char log_file[256];
        uint32_t log_level;
        // ...
    };

    NP_API_EXPORT
    struct np_settings * np_default_settings(struct np_settings *settings);

    NP_API_EXPORT
    np_context* np_new_context(struct np_settings *settings);

    // secret_key is nullable
    NP_API_EXPORT
    struct np_token np_new_identity(np_context* ac, double expires_at, uint8_t* secret_key[NP_SECRET_KEY_BYTES]);

    NP_API_EXPORT
    enum np_error   np_use_identity(np_context* ac, struct np_token identity);



    NP_API_EXPORT
    enum np_error np_listen(np_context* ac, char* protocol, char* host, uint16_t port);

    // Get “connect string”. Signals error if connect string is unavailable (i.e.,
    // no listening interface is configured.)
    NP_API_EXPORT
    enum np_error np_get_address(np_context* ac, char* address, uint32_t max);

    NP_API_EXPORT
    enum np_error np_join(np_context* ac, char* address);

    NP_API_EXPORT
    enum np_error np_send(np_context* ac, char* subject, uint8_t* message, size_t length);
    
    typedef bool (*np_receive_callback)(np_context* ac, struct np_message* message);

    // There can be more than one receive callback, hence "add".
    NP_API_EXPORT
    enum np_error np_add_receive_cb(np_context* ac, char* subject, np_receive_callback callback);

    typedef bool (*np_aaa_callback)(np_context* ac, struct np_token* aaa_token);
    NP_API_EXPORT
    enum np_error np_set_authenticate_cb(np_context* ac, np_aaa_callback callback);
    NP_API_EXPORT
    enum np_error np_set_authorize_cb(np_context* ac, np_aaa_callback callback);
    NP_API_EXPORT
    enum np_error np_set_accounting_cb(np_context* ac, np_aaa_callback callback);
    

    // duration: 0 => process pending events and return
    //           N => process events for up to N seconds and return
    NP_API_EXPORT
    enum np_error np_run(np_context* ac, double duration);

    //enum np_mx_pattern      { NP_MX_BROADCAST, NP_MX_ANY, NP_MX_ONE_WAY, NP_MX_REQ_REP, /* ... */ } NP_ENUM;
    enum np_mx_cache_policy { NP_MX_FIFO_REJECT, NP_MX_FIFO_PURGE, NP_MX_LIFO_REJECT, NP_MX_LIFO_PURGE } NP_ENUM;
    enum np_mx_ackmode      { NP_MX_ACK_NONE, NP_MX_ACK_DESTINATION, NP_MX_ACK_CLIENT } NP_ENUM;

    struct np_mx_properties {
        char reply_subject[255];
        enum np_mx_ackmode ackmode;
        //enum np_mx_pattern pattern;  will be added later on
        enum np_mx_cache_policy cache_policy;
        uint32_t max_parallel, max_retry;
        double intent_ttl, intent_update_after;
        double message_ttl;
    };

    NP_API_EXPORT
    struct np_mx_properties np_get_mx_properties(np_context* ac, char* subject);
    NP_API_EXPORT
    enum np_error np_set_mx_properties(np_context* ac, char* subject, struct np_mx_properties properties);
    NP_API_EXPORT
    void np_set_userdata(np_context * ac, void* userdata);
    NP_API_EXPORT
    void* np_get_userdata(np_context * ac);
    

    NP_API_EXPORT
        enum np_error np_send_to(np_context* ac, char* subject, uint8_t* message, size_t length, np_id * target);
    NP_API_EXPORT
        bool np_has_joined(np_context * ac);		
    NP_API_EXPORT
        enum np_status np_get_status(np_context* ac);
    NP_API_EXPORT
        bool np_has_receiver_for(np_context*ac, char * subject);	
    NP_API_EXPORT
        void np_id2str(const np_id k, char* key_string);
    NP_API_EXPORT
        void np_str2id(const char* key_string, np_id* k);


#ifdef __cplusplus
}
#endif

#endif /* _NP_INTERFACE_H_ */

/**

\toggle_keepwhitespaces 

.. raw:: html

   <style>dl.member { margin-left: 2em; }</style>

*/

/**

--------------
Initialization
--------------

.. c:function:: np_context* np_new_context(struct np_settings *settings)

   Creates a new neuropil application context.

   :param settings:
       a :c:type:`np_settings` structure used to configure the application
       context.
   :return:
       a pointer to the newly created application context.

.. c:type:: void np_context

   An opaque object that denotes a neuropil application context.

.. c:function:: void np_default_settings(struct np_settings *settings)

   Initializes a :c:type:`np_settings` structure to the default settings.

   :param settings:
       a pointer to the :c:type:`np_settings` structure to be initialized.

.. c:type:: struct np_settings

   The :c:type:`np_settings` structure holds various run-time preferences
   available to neuropil.

.. c:member:: uint32_t n_threads

   Controls the maximum number of threads used by neuropil at any given time.
   The default is 3.

.. c:member:: char[256] log_file

   Pathname of a file that neuropil will log to. The default is a ``"<timestamp>_neuropil.log"``
   where timestamp is a decimal millisecond UNIX timestamp.


------------------
Identity management
------------------

.. c:function:: struct np_token *np_new_identity(np_context* ac, double expires_at, uint8_t* (secret_key[NP_SECRET_KEY_BYTES]))

   Creates a new neuropil identity.

   :param ac:
       a neuropil application context.
   :param expires_at:
       expiry date of the identity in seconds since the Unix epoch.
   :param secret_key:
       a pointer to the secret key used by the identity. If `NULL` is supplied a
       random key is generated.
   :return:
       an *identity token*.

.. c:function:: enum np_error np_set_identity(np_context* ac, struct np_token identity)

   Sets the identity used by the neuropil node.

   :param ac:
       a neuropil application context.
   :param identity:
       the *identity* to use.
   :return:
       :c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    *Identity* is no longer valid, or uses an insecure key.
   :c:data:`np_invalid_operation`   The application is in use (can not change the identity at run-time.)
   ===============================  ===========================================

-----------
Starting up
-----------

.. c:function:: enum np_error np_listen(np_context* ac, char* protocol, char* host, uint16_t port)

   Binds a neuropil application context to a listening address.

   :param ac:
       a neuropil application context.
   :param protocol:
       a string denoting the underlying protocol to be used. Currently, only
       `"udp4"` is supported.
   :param host:
       the hostname to listen on. I.e., `"localhost"` to listen on the loopback
       interface.
   :param port:
       the port to listen on. If *port* is zero, the default port 3141 is used.
   :return:
       :c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    *Host* could not be resolved.
   :c:data:`np_invalid_operation`   No identity is set for the application context.
   ===============================  ===========================================

.. c:function:: enum np_error np_get_address(np_context* ac, char* address, uint32_t max)

   Gets the absolute address of the neuropil node within the overlay network.

   :param ac:
       a neuropil application context.
   :param address:
       a pointer to the address string to be written to.
   :param max:
       the size in bytes of *address*. Should be large enough to hold the
       resulting address string. The required space depends on the node’s host
       name (i.e., 1000 bytes should be more than enough for most uses.)
   :return:
       :c:data:`np_ok` on success.
       
   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    *Address* is not large enough to hold the address string.
   :c:data:`np_invalid_operation`   No listening address is bound for the application context. (Call :c:func:`np_listen` first.)
   ===============================  ===========================================

.. c:function:: enum np_error np_join(np_context* ac, char* address)

   Adds a bootstrap node to be used by this node to join the neuropil network.

   :param ac:
       a neuropil application context.
   :param address:
       a string that denotes an absolute address as obtained by
       :c:func:`np_get_address`.
   :return:
       :c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    *Address* is malformed.
   ===============================  ===========================================

------------------------------
Sending and receiving messages
------------------------------

.. c:function:: enum np_error np_send(np_context* ac, char* subject, uint8_t* message, size_t length)

   Sends a message on a given subject.

   :param ac:
       a neuropil application context.
   :param subject:
       the subject to send on.
   :param message:
       a pointer to a buffer containing the message to be sent. The message
       could be, for instance, encoded using `MessagePack <https://msgpack.org/>`_.
   :param length:
       the length of *message* in bytes.
   :return:
       :c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    *Length* exceeds the maximum message size supported by this implementation.
   ===============================  ===========================================

.. c:function:: enum np_error np_add_receive_cb(np_context* ac, char* subject, np_receive_callback callback)

   Adds a callback to be executed when receiving a message on a given subject.
   It is possible to add more than one receive callback for a given subject, in
   which case they are run in the order in which they were added.

   :param ac:
       a neuropil application context.
   :param subject:
       the subject to receive on.
   :param callback:
       a pointer to a function of type :c:type:`np_receive_callback` that
       denotes the callback to be added.
   :return:
       :c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_operation`   The maximum number of receive callbacks supported by the implementation for the given subject is exceeded.
   ===============================  ===========================================

.. c:function:: bool (*np_receive_callback)(struct np_message *message)

   Receive callback function type to be implemented by neuropil applications. A
   message receipt is considered to be acknowledged if all receive callbacks
   associated with the subject returned (:c:data:`true`). Once a receive
   callback returns (:c:data:`false`), the message is considered rejected and
   no further callbacks for the subject are executed.

   :param message:
       a pointer to a :c:type:`np_message` structure.
   :return:
       a boolean that indicates if the receipt was acknowledged
       (:c:data:`true`) or rejected (:c:data:`false`.)

.. c:type:: struct np_message

   Structure that holds a received message and some metadata about that
   message.

.. c:member:: uint8_t *data

   A pointer to a buffer that contains the received message.

.. c:member:: size_t data_length

   The length of *data* in bytes.

.. c:member:: char[NP_UUID_BYTES] uuid

   A universally unique identifier for the message.

.. c:member:: np_id from

   The identity fingerprint of the message.

.. c:member:: np_id subject

   The fingerprint of the message subject.

.. c:member:: double received_at

   Unix timestamp that denotes the time the message was received.

.. c:function:: enum np_error np_set_mx_properties(np_context* ac, char* subject, struct np_mx_properties properties)

   Configure message exchange semantics for a given subject. The default is
   best-effort message delivery without any attempt at retransmission and if
   delivered messages are guaranteed to be delivered once only.

   :param ac:
       a neuropil application context.
   :param subject:
       the subject to configure message exchange semantics on.
   :param properties:
       a pointer to a :c:type:`np_mx_properties` structure that describes the
       semantics to be applied.
   :return:
       :c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    The *properties* structure is invalid.
   ===============================  ===========================================

.. c:type:: struct np_mx_properties

   Structure that defines message the exchange semantics for a given subject.

.. c:member:: enum np_mx_ackmode ackmode

   Acknowledgement strategy used in message exchange. The default is
   :c:data:`NP_MX_ACK_NONE` (i.e., fire and forget.)

.. c:member:: enum np_mx_cache_policy cache_policy

   Cache policy used for queuing inbound messages. The default is
   :c:data:`NP_MX_FIFO_REJECT` (i.e., messages are delivered first in, first
   out, and messages that would overflow the queue will be rejected.)

.. c:member:: uint32_t max_parallel

   The maximum number of outbound messages that may be in-flight at a given
   moment. The default is one.

.. c:member:: uint32_t max_retry

   The maximum number of times a message will be resent after it has been
   rejected. The default is zero.

.. c:member:: double intent_ttl
.. c:member:: double intent_update_after

   The duration of validity of issued message intents and the duration after
   which message intents are to be refreshed in seconds.
   :c:data:`Intent_update_after` should always be less than
   :c:data:`intent_ttl`. This setting impacts the fail-over latency between
   receivers leaving and joining the network. Senders will remain unaware of
   new receivers for up to :c:data:`intent_update_after` seconds.

   The default for :c:data:`intent_ttl` is 30 seconds. The default for
   :c:data:`intent_update_after` is 20 seconds

.. c:member:: double message_ttl

   Maximum duration for individual message delivery in seconds. The default is
   20 seconds.

.. c:member:: bool once_only

   Boolean that indicates if messages should be ensured to be delivered once
   only. If this is :c:data:`false` duplicate messages may be delivered to the
   application. The default is :c:data:`true`.

.. c:type:: enum np_mx_cache_policy

   ===============================  ===========================================
   Mode                             Description
   ===============================  ===========================================
   :c:data:`NP_MX_FIFO_REJECT`      Messages are delivered in FIFO order, excessive messages are rejected.
   :c:data:`NP_MX_FIFO_PURGE`       Messages are delivered in FIFO order, excessive messages are silently discarded.
   :c:data:`NP_MX_LIFO_REJECT`      Messages are delivered in LIFO order, excessive messages are rejected.
   :c:data:`NP_MX_LIFO_PURGE`       Messages are delivered in LIFO order, excessive messages are silently discarded.
   ===============================  ===========================================

.. c:type:: enum np_mx_ackmode

   ===============================  ===========================================
   Mode                             Description
   ===============================  ===========================================
   :c:data:`NP_MX_ACK_NONE`         Message transmissions need not be acknowledged to be considered successful.
   :c:data:`NP_MX_ACK_DESTINATION`  Message transmissions need to be acknowledged by destination node to be considered successful.
   :c:data:`NP_MX_ACK_CLIENT`       Message transmissions need to be acknowledged by a receive callback to be considered successful.
   ===============================  ===========================================

--------------------------------
Authentication and authorization
--------------------------------

.. c:function:: enum np_error np_set_authorize_cb(np_context* ac, np_aaa_callback callback)

   Sets the authorization callback used to control access to message exchanges.
   The provided *callback* is responsible for judging whether the identity that
   issued a given token is permitted to exchange messages over a given subject.
   If no authorization callback is set all message exchanges will be rejected.

   :param ac:
       a neuropil application context.
   :param callback:
       a pointer to a function of type :c:type:`np_aaa_callback` that
       denotes the callback to be set.
   :return:
       :c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_operation`   An authorization callback has already been set for this application context.
   ===============================  ===========================================

.. c:function:: enum np_error np_set_authenticate_cb(np_context* ac, np_aaa_callback callback)

   Sets an additional authentication callback used to authenticate nodes. Such
   a callback can be used to extend the authentication provided by neuropil to
   further validate tokens based on application extensions. If no such callback
   is set only standard neuropil authentication is performed. Note that
   authenticated nodes are permitted to join the overlay network.

   :param ac:
       a neuropil application context.
   :param callback:
       a pointer to a function of type :c:type:`np_aaa_callback` that denotes
       the callback to be set.
   :return:
       :c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_operation`   An additional authentication *callback* has already been set for this application context.
   ===============================  ===========================================

.. c:function:: bool (*np_aaa_callback)(struct np_token* aaa_token)

   AAA callback function type to be implemented by neuropil applications. These
   functions are to inspect and verify the contents of the *aaa_token* they are
   provided and either accept or reject the token.

   :param aaa_token:
       a pointer to a :c:type:`np_token` structure to be verified.
   :return:
       a boolean that indicates if the token was accepted (:c:data:`true`) or
       rejected (:c:data:`false`.)

------
Tokens
------

.. c:type:: struct np_token

   A record used for authentication, authorization and accounting purposes.
   When :c:type:`np_token` records are transmitted or received over the network
   they are accompanied by a cryptographic signature that must match the
   token’s :c:member:`public_key` field. Tokens received through the neuropil
   API are guaranteed to be authentic: i.e., their integrity is validated.
   Applications are responsible to verify the issuer of a given token as
   denoted by the :c:member:`public_key`.

.. c:member:: np_id realm

   Optionally, tokens can specify a third party authority that governs the
   validity of tokens in a *realm*.

.. c:member:: np_id issuer

   The fingerprint of the *identity* that issued the token.

.. c:member:: char[255] subject

   A subject that denotes the token’s purpose.

.. c:member:: np_id audience

   A fingerprint that denotes the intended audience of the token.

.. c:member:: double issued_at
.. c:member:: double not_before
.. c:member:: double expires_at

   Timestamps encoded as `Unix time <https://en.wikipedia.org/wiki/Unix_time>`_
   in seconds that denote issue date and validity duration of the token. These
   validity periods are validated by neuropil.

.. c:member:: uint8_t[] extensions
.. c:member:: size_t extension_length

   A buffer of extension data of :c:member:`extension_length` bytes represented
   as a `MessagePack <https://msgpack.org/>`_ encoded map.

.. c:member:: uint8_t[NP_PUBLIC_KEY_BYTES] public_key
.. c:member:: uint8_t[NP_SECRET_KEY_BYTES] secret_key

   The key pair associated with the token. Foreign tokens have the
   :c:member:`secret_key` unset (all zero).

------------
Fingerprints
------------

.. c:function:: void np_get_id(np_id* id, char* string, size_t length)

   Computes the fingerprint (or overlay address) of a serialized object.

   :param id:
       a pointer to the :c:type:`np_id` to be written.
   :param string:
       the data to be hashed.
   :param length:
       the length of the input data in bytes. If *length* is zero, *string* is
       expected to be a zero-terminated string.

   :c:func:`np_get_id` constructs fingerprints by means of a cryptographic,
   one-way hash function. Hence, fingerprints are unique, unforgeable object
   identities. Given an object, any party can compute its unique fingerprint,
   but no party is able to forge an object that hashes to a particular
   fingerprint.

.. c:type:: uint8_t[NP_FINGERPRINT_BYTES] np_id

   The type :c:type:`np_id` denotes both a fingerprint and a virtual address in
   the overlay network implemented by neuropil. It is represented as a
   consecutive array of :c:data:`NP_FINGERPRINT_BYTES` bytes.

------------------------
Running your application
------------------------

.. c:function:: enum np_error np_run(np_context* ac, double duration)

   Runs the neuropil event loop for a given application context for a specified
   *duration*. During the execution of the event loop incoming and outgoing
   messages are transmitted and received, and the associated callbacks are
   executed.

   :param ac:
       a neuropil application context.
   :param duration:
       the duration in seconds allotted to execute the event loop. If
       *duration* is zero :c:func:`np_run` will return as soon as it has
       processed all outstanding events.
   :return:
       :c:data:`np_ok` on success.

----------------
Detecting errors
----------------

.. c:type:: enum np_error

   This type denotes the set of status codes returned by various functions in
   the neuropil API. Possible values include:

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_ok`                  The operation was successful (no error occurred.)
   :c:data:`np_invalid_argument`    The operation failed because of an invalid argument.
   :c:data:`np_invalid_operation`   The operation is not permitted at this time.
   ===============================  ===========================================

   In order to accurately interpret error codes refer to the documentation of
   the specific function in question.

---------
Constants
---------

.. c:var:: size_t NP_SECRET_KEY_BYTES
.. c:var:: size_t NP_PUBLIC_KEY_BYTES

   Constants that denote the lengths in bytes of the private and public key
   parts used by neuropil, as found in :c:type:`np_token`.

.. c:var:: size_t NP_FINGERPRINT_BYTES

   Constant that denotes length in bytes of both *fingerprints* and virtual
   addresses in the overlay network implemented by neuropil. Specifically, this
   is the size of :c:type:`np_id`.

.. c:var:: size_t NP_UUID_BYTES

   Constant that denotes the length in bytes of message UUID_s.

.. _UUID: https://en.wikipedia.org/wiki/Universally_unique_identifier 

*/

