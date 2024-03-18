//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

/* neuropil API v2 */

#ifndef _NP_INTERFACE_H_
#define _NP_INTERFACE_H_

#ifndef _NP_DO_NOT_USE_DEFAULT_H_FILES

#ifdef DEBUG
#include <execinfo.h>
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define NEUROPIL_RELEASE "neuropil_0.13.0"

#define NEUROPIL_COPYRIGHT                                                     \
  "copyright (C) 2016-2024 neuropil.org, Cologne, Germany"
#define NEUROPIL_TRADEMARK                                                     \
  "trademark (TM) 2016-2024 pi-lar GmbH, Cologne, Germany"

/* just in case NULL is not defined */
#ifndef NULL
#define NULL (void *)0
#endif

//
// int __attribute__((overloadable)) square(int);

#ifndef NP_CONST_ENUM
#if defined(__APPLE__) && defined(__MACH__)
#define NP_CONST_ENUM __attribute__((enum_extensibility(closed), flag_enum))
#else
#define NP_CONST_ENUM
#endif
#endif

#ifndef NP_ENUM
#if defined(__APPLE__) && defined(__MACH__)
#define NP_ENUM __attribute__((flag_enum))
#else
#define NP_ENUM
#endif
#endif

#define NP_CONST __attribute__((const))
#define NP_PURE  __attribute__((pure))

#ifndef NP_PACKED
#define NP_PACKED(x) __attribute__((packed, aligned(x)))
#endif

#define NP_DEPRECATED __attribute__((deprecated("!!! DEPRECATED !!!")))

#if defined(TEST_COMPILE) || defined(DEBUG)
#define NP_UNUSED     __attribute__((unused))
#define NP_API_HIDDEN __attribute__((visibility("default")))
#define NP_API_PROTEC __attribute__((visibility("default")))
#define NP_API_INTERN __attribute__((visibility("default")))
#else
#ifndef NP_UNUSED
#define NP_UNUSED __attribute__((unused))
#endif
#ifndef NP_API_PROTEC
#define NP_API_PROTEC __attribute__((visibility("default")))
#endif
#ifndef NP_API_HIDDEN
#define NP_API_HIDDEN __attribute__((visibility("default")))
#endif
#ifndef NP_API_INTERN
#define NP_API_INTERN __attribute__((visibility("default")))
#endif
#endif

#ifndef NP_API_EXPORT
#define NP_API_EXPORT __attribute__((visibility("default")))
#endif

// Protocol constants

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wflag-enum"
// in c99 enum is an int -->
// it is safe for use to disable this warning for the enum np_limits
enum np_limits {
  NP_SECRET_KEY_BYTES  = 64,
  NP_SIGNATURE_BYTES   = 64,
  NP_PUBLIC_KEY_BYTES  = 32,
  NP_FINGERPRINT_BYTES = 32,
  NP_UUID_BYTES        = 37,
  NP_EXTENSION_BYTES   = 10240,
} NP_CONST_ENUM;

#pragma clang diagnostic pop

enum np_status {
  np_error = 0,
  np_uninitialized,
  np_running,
  np_stopped,
  np_shutdown,
} NP_CONST_ENUM;

enum np_return {
  np_ok = 0,
  np_operation_failed,
  np_unknown_error,
  np_not_implemented,
  np_network_error,
  np_invalid_argument,
  np_invalid_operation,
  np_out_of_memory,
  np_startup,
} NP_CONST_ENUM;

NP_API_EXPORT
const char *np_error_str(enum np_return e);

struct version_t {
  uint8_t major;
  uint8_t minor;
  uint8_t patch;
} NP_PACKED(1);

typedef void np_context;

typedef unsigned char np_id[NP_FINGERPRINT_BYTES];
typedef unsigned char np_attributes_t[NP_EXTENSION_BYTES];
typedef unsigned char np_signature_t[NP_SIGNATURE_BYTES];

typedef np_id np_subject;

// If length is 0 then string is expected to be null-terminated.
// char* is the appropriate type because it is the type of a string
// and can also describe an array of bytes. (sizeof char == 1)
void np_get_id(np_id(*id), const char *string, size_t length);
// reentrant version fo np_get_id. the subject_id will not be overwrittem, but
// will ba used as a base hash value otherwise the same as np_get_id
enum np_return np_generate_subject(np_subject(*subject_id),
                                   const char *subject,
                                   size_t      length);

enum np_return np_regenerate_subject(np_context      *ac,
                                     char            *subject_buffer,
                                     size_t           buffer_length,
                                     const np_subject subject);

struct np_log_entry {
  char  *string;
  size_t string_length;
  double timestamp;
  char   level[20];
} NP_PACKED(1);

typedef void (*np_log_write_callback)(np_context         *ac,
                                      struct np_log_entry entry);

struct np_token {
  char          uuid[NP_UUID_BYTES];
  char          subject[255];
  np_id         issuer;
  np_id         realm;
  np_id         audience;
  double        issued_at, not_before, expires_at;
  unsigned char public_key[NP_PUBLIC_KEY_BYTES],
      secret_key[NP_SECRET_KEY_BYTES];
  np_signature_t signature;

  np_attributes_t attributes;
  np_signature_t  attributes_signature;
} NP_PACKED(1);

struct np_message {
  char            uuid[NP_UUID_BYTES];
  np_id           from;
  np_subject      subject;
  double          received_at;
  unsigned char  *data;
  size_t          data_length;
  np_attributes_t attributes;
} NP_PACKED(1);

struct np_settings {
  uint32_t              n_threads;
  char                  log_file[256];
  uint32_t              log_level;
  uint8_t               leafset_size;
  np_log_write_callback log_write_fn;
  uint16_t              jobqueue_size;
  uint16_t              max_msgs_per_sec;
  // ...
} NP_PACKED(1);

NP_API_EXPORT
struct np_settings *np_default_settings(struct np_settings *settings);

NP_API_EXPORT
np_context *np_new_context(struct np_settings *settings);

// secret_key is nullable
NP_API_EXPORT
struct np_token
np_new_identity(np_context *ac,
                double      expires_at,
                unsigned char (*secret_key)[NP_SECRET_KEY_BYTES]);

NP_API_EXPORT
enum np_return np_use_identity(np_context *ac, struct np_token identity);

NP_API_EXPORT
enum np_return np_use_token(np_context *ac, struct np_token token);

NP_API_EXPORT
enum np_return
np_sign_identity(np_context *ac, struct np_token *identity, bool self_sign);

// NP_API_EXPORT
// enum np_return np_verify_fingerprint(np_context* ac, struct np_token*
// identity, bool self_sign);

NP_API_EXPORT
enum np_return np_token_fingerprint(np_context     *ac,
                                    struct np_token identity,
                                    bool            include_attributes,
                                    np_id(*id));

NP_API_EXPORT
enum np_return np_listen(np_context *ac,
                         const char *protocol,
                         const char *host,
                         uint16_t    port,
                         const char *dns_name);
NP_API_EXPORT
enum np_return np_node_fingerprint(np_context *ac, np_id(*id));

// Get “connect string”. Signals error if connect string is unavailable (i.e.,
// no listening interface is configured.)
NP_API_EXPORT
enum np_return np_get_address(np_context *ac, char *address, uint32_t max);

NP_API_EXPORT
enum np_return np_join(np_context *ac, const char *address);

typedef bool (*np_aaa_callback)(np_context *ac, struct np_token *aaa_token);
NP_API_EXPORT
enum np_return np_set_authenticate_cb(np_context *ac, np_aaa_callback callback);
NP_API_EXPORT
enum np_return np_set_authorize_cb(np_context *ac, np_aaa_callback callback);
NP_API_EXPORT
enum np_return np_set_accounting_cb(np_context *ac, np_aaa_callback callback);

// duration: 0 => process pending events and return
//           N => process events for up to N seconds and return
NP_API_EXPORT
enum np_return np_run(np_context *ac, double duration);

// enum np_mx_pattern        { NP_MX_BROADCAST, NP_MX_ONE_WAY, /* NP_MX_REQ_REP,
// ... */ } NP_ENUM;
enum np_mx_role { NP_MX_PROVIDER, NP_MX_CONSUMER, NP_MX_PROSUMER } NP_ENUM;
enum np_mx_cache_policy {
  NP_MX_FIFO_REJECT,
  NP_MX_FIFO_PURGE,
  NP_MX_LIFO_REJECT,
  NP_MX_LIFO_PURGE
} NP_ENUM;
enum np_mx_ackmode {
  NP_MX_ACK_NONE,
  NP_MX_ACK_DESTINATION,
  NP_MX_ACK_CLIENT
} NP_ENUM;
enum np_mx_audience_type {
  NP_MX_AUD_PUBLIC,
  NP_MX_AUD_VIRTUAL,
  NP_MX_AUD_PROTECTED,
  NP_MX_AUD_PRIVATE
} NP_ENUM;

struct np_mx_properties {
  // char msg_subject[255] NP_PACKED(1);
  enum np_mx_role    role;
  enum np_mx_ackmode ackmode;

  // enum np_mx_pattern pattern;  will be added later on
  np_subject reply_id NP_PACKED(1);

  enum np_mx_audience_type audience_type;
  np_id audience_id        NP_PACKED(1);

  enum np_mx_cache_policy cache_policy;
  uint16_t                cache_size;
  uint8_t                 max_parallel, max_retry;

  double intent_ttl, intent_update_after;
  double message_ttl;

} NP_PACKED(1);

NP_API_EXPORT
struct np_mx_properties np_get_mx_properties(np_context      *ac,
                                             const np_subject id);
NP_API_EXPORT
enum np_return np_set_mx_properties(np_context             *ac,
                                    const np_subject        id,
                                    struct np_mx_properties properties);
NP_API_EXPORT
enum np_return np_set_mx_authorize_cb(np_context      *ac,
                                      const np_subject id,
                                      np_aaa_callback  callback);
NP_API_EXPORT
enum np_return np_mx_properties_enable(np_context *ac, const np_subject id);
NP_API_EXPORT
enum np_return np_mx_properties_disable(np_context *ac, const np_subject id);

NP_API_EXPORT
enum np_return np_send(np_context          *ac,
                       np_subject           subject,
                       const unsigned char *message,
                       size_t               length);
NP_API_EXPORT
enum np_return np_send_to(np_context          *ac,
                          np_subject           subject,
                          const unsigned char *message,
                          size_t               length,
                          np_id(*target));

typedef bool (*np_receive_callback)(np_context *ac, struct np_message *message);

// There can be more than one receive callback, hence "add".
NP_API_EXPORT
enum np_return np_add_receive_cb(np_context         *ac,
                                 np_subject          subject,
                                 np_receive_callback callback);

NP_API_EXPORT
void np_set_userdata(np_context *ac, void *userdata);
NP_API_EXPORT
void *np_get_userdata(np_context *ac);

NP_API_EXPORT
bool np_has_joined(np_context *ac);
NP_API_EXPORT
enum np_status np_get_status(np_context *ac);
NP_API_EXPORT
bool np_has_receiver_for(np_context *ac, np_subject subject);
NP_API_EXPORT
char *np_id_str(char str[65], const np_id id);
NP_API_EXPORT
void np_str_id(np_id(*id), const char str[65]);

NP_API_EXPORT
void np_destroy(np_context *ac, bool gracefully);

// a general callback just taking the context as an argument
typedef void (*np_callback)(np_context *ac);

NP_API_EXPORT
enum np_return np_add_shutdown_cb(np_context *ac, np_callback callback);
//  NP_API_EXPORT
//      enum np_return np_add_periodic_cb(np_context* ac, np_callback callback,
//      double start_time, uint16_t interval);

NP_API_EXPORT
bool np_id_equals(np_id first, np_id second);

NP_API_EXPORT
uint32_t np_get_route_count(np_context *ac);
#ifdef __cplusplus
}
#endif

#endif /* _NP_INTERFACE_H_ */

/**

.. raw:: html

   <style>dl.member { margin-left: 2em; }</style>

*/

/**

Initialization
--------------

.. c:type:: void np_context

   An opaque object that denotes a neuropil application context.


.. c:function:: np_context* np_new_context(struct np_settings *settings)

   Creates a new neuropil application context.

   :param settings:  a :c:type:`np_settings` structure used to configure the
application context. :return:          a pointer to the newly created
application context.


.. c:type:: void np_subject

   An blake2b obfuscated message subject to transport data


.. c:function:: void np_default_settings(struct np_settings *settings)

   Initializes a :c:type:`np_settings` structure to the default settings.

   :param settings:         a pointer to the :c:type:`np_settings` structure to
be initialized.


.. c:struct:: np_settings

   The :c:type:`np_settings` structure holds various run-time preferences
   available to neuropil.

.. c:member:: uint32_t n_threads

   Controls the maximum number of threads used by neuropil at any given time.
   The default is 3.

.. c:member:: char log_file[256]

   Pathname of a file that neuropil will log to. The default is a
``"<timestamp>_neuropil.log"`` where timestamp is a decimal millisecond UNIX
timestamp.

.. c:member:: uint8_t leafset_size

   specifies the size of the leafset table (DHT entries near to our own hash
value)

.. c:member:: uint16_t jobqueue_size

   The size of the internally used jobqueue. The default is 512 entries,
depending on the number of threads this should be sufficient for many use cases.
High throuput cloud nodes could need larger jobqueues.



Identity management
-------------------

.. c:function:: struct np_token *np_new_identity(np_context* ac, double
expires_at, uint8_t secret_key[NP_SECRET_KEY_BYTES])

   Creates a new neuropil identity.

   :param ac:         a neuropil application context.
   :param expires_at: expiry date of the identity in seconds since the Unix
epoch. :param secret_key: the secret key used by the identity. If `NULL` is
supplied a random key is generated. :return:        an *identity token*.


.. c:function:: enum np_return np_set_identity(np_context* ac, struct np_token
identity)

   Sets the identity used by the neuropil node.

   :param ac:       a neuropil application context.
   :param identity: the *identity* to use.
   :return:        :c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    *Identity* is no longer valid, or uses an
insecure key. :c:data:`np_invalid_operation`   The application is in use (can
not change the identity at run-time.)
   ===============================  ===========================================


.. c:function:: struct np_token *np_use_identity(np_context* ac, struct np_token
identity)

   imports an identity into the running process and uses it as it's own identity

   :param ac:         a neuropil application context.
   :param identity: a valid token structure which should be used as the
identity. The secret key must be present, otherwise the operation has no effect


.. c:function:: struct np_token *np_use_token(np_context* ac, struct np_token
token)

   imports an token into the running process and uses it. The imported token can
be a node, an different identity, a message intent token or an accounting token.
The library with set the status of the token to AUTHENTICATED and AUTHORIZED, as
the user requested to import the token

   :param ac:         a neuropil application context.
   :param identity: a valid token structure which should be used as the
identity. The secret key must not be present. If the token is not valid (i.e.
expired, signature broken), then it will be rejected


Starting up
-----------

.. c:function:: enum np_return np_listen(np_context* ac, const char* protocol,
const char* host, uint16_t port, const char * dns_name)

   Binds a neuropil application context to a listening address.

   :param ac: a neuropil application context.
   :param protocol: a string denoting the underlying protocol to be used.
Currently, only `"udp4"` is supported. :param host: the hostname to listen on.
I.e., `"localhost"` to listen on the loopback interface. :param port: the port
to listen on. If *port* is zero, the default port 3141 is used. :param dns_name:
the dns name to publish, same as hostname if NULL. :return: :c:data:`np_ok` on
success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    *Host* could not be resolved.
   :c:data:`np_invalid_operation`   No identity is set for the application
context.
   ===============================  ===========================================


.. c:function:: enum np_return np_get_address(np_context* ac, char* address,
uint32_t max)

   Gets the absolute address of the neuropil node within the overlay network.

   :param ac: a neuropil application context.
   :param address: a pointer to the address string to be written to.
   :param max: the size in bytes of *address*. Should be large enough to hold
the resulting address string. The required space depends on the node’s host name
(i.e., 1000 bytes should be more than enough for most uses.) :return:
:c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    *Address* is not large enough to hold the
address string. :c:data:`np_invalid_operation`   No listening address is bound
for the application context. (Call :c:func:`np_listen` first.)
   ===============================  ===========================================


.. c:function:: enum np_return np_join(np_context* ac, const char* address)

   Adds a bootstrap node to be used by this node to join the neuropil network.

   :param ac:         a neuropil application context.
   :param address:    a string that denotes an absolute address as obtained by
:c:func:`np_get_address`. :return:           :c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    *Address* is malformed.
   ===============================  ===========================================


Sending and receiving messages
------------------------------


.. c:function:: enum np_return np_generate_subject(np_subject subject, const
char* text, size_t length)

   Creates the binary representation of a message subject. This is an re-entrant
version, using the same subject field will use the existing np_subject as a seed
for the text.

   :param subject:  the final np_subject field that can be used in later calls
to the library :param text:     the text that the subject should be based on
   :param length:   the length of *text* in bytes.
   :return:         :c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    *Length* exceeds the maximum message size
supported by this implementation.
   ===============================  ===========================================


.. c:function:: enum np_return np_send(np_context* ac, np_subject subject, const
uint8_t* message, size_t length)

   Sends a message on a given subject.

   :param ac:       a neuropil application context.
   :param subject:  the subject to send on.
   :param message:  a pointer to a buffer containing the message to be sent. The
message could be, for instance, encoded using `MessagePack
<https://msgpack.org/>`_. :param length:   the length of *message* in bytes.
   :return:         :c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    *Length* exceeds the maximum message size
supported by this implementation.
   ===============================  ===========================================


.. c:function:: enum np_return np_add_receive_cb(np_context* ac, np_subject
subject, np_receive_callback callback)

   Adds a callback to be executed when receiving a message on a given subject.
   It is possible to add more than one receive callback for a given subject, in
   which case they are run in the order in which they were added.

   :param ac:        a neuropil application context.
   :param subject:   the subject to receive on.
   :param callback:  a pointer to a function of type
:c:type:`np_receive_callback` that denotes the callback to be added. :return:
:c:data:`np_ok` on success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_operation`   The maximum number of receive callbacks
supported by the implementation for the given subject is exceeded.
   ===============================  ===========================================


.. c:function:: bool np_receive_callback(struct np_message *message)

   Receive callback function type to be implemented by neuropil applications. A
   message receipt is considered to be acknowledged if all receive callbacks
   associated with the subject returned (:c:data:`true`). Once a receive
   callback returns (:c:data:`false`), the message is considered rejected and
   no further callbacks for the subject are executed.

   :param message: a pointer to a :c:type:`np_message` structure.
   :return:        a boolean that indicates if the receipt was acknowledged
(:c:data:`true`) or rejected (:c:data:`false`.)


.. c:struct:: np_message

   Structure that holds a received message and some metadata about that
   message.

.. c:member:: uint8_t *data

   A pointer to a buffer that contains the received message.

.. c:member:: size_t data_length

   The length of *data* in bytes.

.. c:member:: char uuid[NP_UUID_BYTES]

   A universally unique identifier for the message.

.. c:member:: np_id from

   The identity fingerprint of the message.

.. c:member:: np_id subject

   The fingerprint of the message subject.

.. c:member:: double received_at

   Unix timestamp that denotes the time the message was received.


.. c:function:: enum np_return np_set_mx_properties(np_context* ac, const char*
subject, struct np_mx_properties properties)

   Configure message exchange semantics for a given subject. The default is
   best-effort message delivery without any attempt at retransmission and if
   delivered messages are guaranteed to be delivered once only.

   :param ac:          a neuropil application context.
   :param subject:     the subject to configure message exchange semantics on.
   :param properties:  a pointer to a :c:type:`np_mx_properties` structure that
describes the semantics to be applied. :return:            :c:data:`np_ok` on
success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_argument`    The *properties* structure is invalid.
   ===============================  ===========================================


.. c:struct:: np_mx_properties

   Structure that defines message the exchange semantics for a given subject.

.. c:member:: np_mx_ackmode ackmode

   Acknowledgement strategy used in message exchange. The default is
   :c:data:`NP_MX_ACK_NONE` (i.e., fire and forget.)

.. c:member:: np_mx_role role

   role of the node for this data transfer. The default is not set. When calling
:c:type:`np_send` the library creates the role of :c:data:`NP_MX_PROVIDER`, if
calling :c:type:`np_add_receive_cb` the role :c:data:`NP_MX_CONSUMER` is used

.. c:member:: np_mx_audience_type audience_type

   the intended audience for this data transfer. see
:c:type:`np_mx_audience_type` for the specific meaning of each. The default is
:c:data:`NP_MX_AUD_PUBLIC`

.. c:member:: np_mx_cache_policy cache_policy

   Cache policy used for queuing inbound messages. The default is
   :c:data:`NP_MX_FIFO_REJECT` (i.e., messages are delivered first in, first
   out, and messages that would overflow the queue will be rejected.)

.. c:member:: uint8_t max_parallel

   The maximum number of outbound messages that may be in-flight at a given
   moment. The default is one.

.. c:member:: uint8_t max_retry

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


.. c:enum:: np_mx_cache_policy

   ===============================  ===========================================
   Mode                             Description
   ===============================  ===========================================
   :c:data:`NP_MX_FIFO_REJECT`      Messages are delivered in FIFO order,
excessive messages are rejected. :c:data:`NP_MX_FIFO_PURGE`       Messages are
delivered in FIFO order, excessive messages are silently discarded.
   :c:data:`NP_MX_LIFO_REJECT`      Messages are delivered in LIFO order,
excessive messages are rejected. :c:data:`NP_MX_LIFO_PURGE`       Messages are
delivered in LIFO order, excessive messages are silently discarded.
   ===============================  ===========================================


.. c:enum:: np_mx_ackmode

   ===============================  ===========================================
   Mode                             Description
   ===============================  ===========================================
   :c:data:`NP_MX_ACK_NONE`         Message transmissions need not be
acknowledged to be considered successful. :c:data:`NP_MX_ACK_DESTINATION`
Message transmissions need to be acknowledged by destination node to be
considered successful. :c:data:`NP_MX_ACK_CLIENT`       Message transmissions
need to be acknowledged by a receive callback to be considered successful.
   ===============================  ===========================================


.. c:enum:: np_mx_role

   ===============================  ===========================================
   Mode                             Description
   ===============================  ===========================================
   :c:data:`NP_MX_PROVIDER`         node is the sender of messages
   :c:data:`NP_MX_CONSUMER`         node is the receiver of messages
   :c:data:`NP_MX_PROSUMER`         node will send an receiver messages on this
subject
   ===============================  ===========================================


.. c:enum:: np_mx_audience_type

   ===============================  ===========================================
   Mode                             Description
   ===============================  ===========================================
   :c:data:`NP_MX_AUD_PUBLIC`       public data channel, everybody can subscribe
to :c:data:`NP_MX_AUD_VIRTUAL`      virtual data channel, only token will be
exchanged :c:data:`NP_MX_AUD_PROTECTED`    protected data channel, audience_id
identifies the mutual peer :c:data:`NP_MX_AUD_PRIVATE`      private data
channel, subject obfuscated with np_generate_subject
   ===============================  ===========================================


Authentication and authorization
--------------------------------


.. c:function:: enum np_return np_set_authorize_cb(np_context* ac,
np_aaa_callback callback)

   Sets the authorization callback used to control access to message exchanges.
   The provided *callback* is responsible for judging whether the identity that
   issued a given token is permitted to exchange messages over a given subject.
   If no authorization callback is set all message exchanges will be rejected.

   :param ac:        a neuropil application context.
   :param callback:  a pointer to a function of type :c:type:`np_aaa_callback`
that denotes the callback to be set. :return:          :c:data:`np_ok` on
success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_operation`   An authorization callback has already been
set for this application context.
   ===============================  ===========================================


.. c:function:: enum np_return np_set_authenticate_cb(np_context* ac,
np_aaa_callback callback)

   Sets an additional authentication callback used to authenticate nodes. Such
   a callback can be used to extend the authentication provided by neuropil to
   further validate token based on application extensions. If no such callback
   is set only standard neuropil authentication is performed. Note that
   authenticated nodes are permitted to join the overlay network.

   :param ac:        a neuropil application context.
   :param callback:  a pointer to a function of type :c:type:`np_aaa_callback`
that denotes the callback to be set. :return:          :c:data:`np_ok` on
success.

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_invalid_operation`   An additional authentication *callback* has
already been set for this application context.
   ===============================  ===========================================


.. c:function:: bool np_aaa_callback(struct np_token* aaa_token)

   AAA callback function type to be implemented by neuropil applications. These
   functions are to inspect and verify the contents of the *aaa_token* they are
   provided and either accept or reject the token.

   :param aaa_token: a pointer to a :c:type:`np_token` structure to be verified.
   :return:          a boolean that indicates if the token was accepted
(:c:data:`true`) or rejected (:c:data:`false`.)


Token
-----


.. c:struct:: np_token

   A record used for authentication, authorization and accounting purposes.
   When :c:type:`np_token` records are transmitted or received over the network
   they are accompanied by a cryptographic signature that must match the
   token’s :c:member:`public_key` field. A token received through the neuropil
   API are guaranteed to be authentic: i.e., their integrity is validated.
   Applications are responsible to verify the issuer of a given token as
   denoted by the :c:member:`public_key`.

.. c:member:: np_id realm

   Optionally, token can specify a third party authority that governs the
   validity of token in a *realm*.

.. c:member:: np_id issuer

   The fingerprint of the *identity* that issued the token.

.. c:member:: char subject[255]

   A subject that denotes the token’s purpose.

.. c:member:: np_id audience

   A fingerprint that denotes the intended audience of the token.

.. c:member:: double issued_at
.. c:member:: double not_before
.. c:member:: double expires_at

   Timestamps encoded as `Unix time <https://en.wikipedia.org/wiki/Unix_time>`_
   in seconds that denote issue date and validity duration of the token. These
   validity periods are validated by neuropil.

.. c:member:: uint8_t extensions[]
.. c:member:: size_t extension_length

   A buffer of extension data of :c:member:`extension_length` bytes represented
   as a `MessagePack <https://msgpack.org/>`_ encoded map.

.. c:member:: uint8_t public_key[NP_PUBLIC_KEY_BYTES]
.. c:member:: uint8_t secret_key[NP_SECRET_KEY_BYTES]

   The key pair associated with the token. Foreign token have the
   :c:member:`secret_key` unset (all zero).


Fingerprints
------------


.. c:function:: void np_get_id(np_id (*id), char* string, size_t length)

   Computes the fingerprint (or overlay address) of a serialized object.

   :param id:         a :c:type:`np_id` to be written.
   :param string:         the data to be hashed.
   :param length:         the length of the input data in bytes. If *length* is
zero, *string* is expected to be a zero-terminated string.

   :c:func:`np_get_id` constructs fingerprints by means of a cryptographic,
   one-way hash function. Hence, fingerprints are unique, unforgeable object
   identities. Given an object, any party can compute its unique fingerprint,
   but no party is able to forge an object that hashes to a particular
   fingerprint.


.. c:type:: uint8_t np_id[NP_FINGERPRINT_BYTES]

   The type :c:type:`np_id` denotes both a fingerprint and a virtual address in
   the overlay network implemented by neuropil. It is represented as a
   consecutive array of :c:data:`NP_FINGERPRINT_BYTES` bytes.


Running your application
------------------------


.. c:function:: enum np_return np_run(np_context* ac, double duration)

   Runs the neuropil event loop for a given application context for a specified
   *duration*. During the execution of the event loop incoming and outgoing
   messages are transmitted and received, and the associated callbacks are
   executed.

   :param ac:       a neuropil application context.
   :param duration: the duration in seconds allotted to execute the event loop.
If *duration* is zero :c:func:`np_run` will return as soon as it has processed
all outstanding events. :return:          :c:data:`np_ok` on success.


Detecting errors
----------------

.. c:enum:: np_return

   This type denotes the set of status codes returned by various functions in
   the neuropil API. Possible values include:

   ===============================  ===========================================
   Status                           Meaning
   ===============================  ===========================================
   :c:data:`np_ok`                  The operation was successful (no error
occurred.) :c:data:`np_invalid_argument`    The operation failed because of an
invalid argument. :c:data:`np_invalid_operation`   The operation is not
permitted at this time.
   ===============================  ===========================================

   In order to accurately interpret error codes refer to the documentation of
   the specific function in question.


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
