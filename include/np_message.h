//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_MESSAGE_H_
#define _NP_MESSAGE_H_

#include <stdarg.h>

#include "util/np_list.h"

#include "np_memory.h"
#include "np_messagepart.h"
#include "np_threads.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

enum np_e2e_messagestate_s {
  msgstate_unknown,
  msgstate_raw,
  msgstate_binary,
  msgstate_chunked,
};

enum np_msg_flags {
  msg_ack_none   = 0x0001,
  msg_ack_client = 0x0002,
  msg_ack_dest   = 0x0004,
  msg_type_start = 0x0010,
  msg_type_chunk = 0x0020,
  msg_type_end   = 0x0040,
};

struct np_e2e_message_s {
  // internal bookkeeping fields
  // TSP(np_thread_ptr, owner);
  double   send_at;
  double   redelivery_at;
  uint16_t msg_chunk_counter; // count the number of received chunks

  enum np_e2e_messagestate_s state;

  // pointers to header values
  unsigned char *nonce;
  unsigned char *mac_e;
  unsigned char *uuid;
  np_dhkey_t    *subject;
  np_dhkey_t    *audience;
  double        *tstamp;
  uint32_t      *ttl;
  uint16_t      *parts; // is actually only uint24_t, see next comment
  uint16_t      *msg_flags;

  // attributes and message body ...
  np_attributes_t msg_attributes;
  void           *msg_body;
  // ... will be transformed in to a binary message ...
  unsigned char *binary_message;
  size_t         binary_length;
  // ... will be transformed into chunks of 1024bit size
  struct np_n2n_messagepart_s **msg_chunks;
};

_NP_GENERATE_MEMORY_PROTOTYPES(np_message_t)

/** message_create / free:
 ** creates the message to the destination #dest# the message format would be
 *like:
 ** deletes the message and corresponding structures
 **
 **/
NP_API_INTERN
void _np_message_create(struct np_e2e_message_s *msg,
                        np_dhkey_t               to,
                        np_dhkey_t               from,
                        np_dhkey_t               subject,
                        np_tree_t               *the_data);

NP_API_INTERN
enum np_return _np_message_add_chunk(struct np_e2e_message_s     *msg,
                                     struct np_n2n_messagepart_s *raw_message,
                                     uint16_t *count_of_chunks);

NP_API_INTERN
bool np_message_clone(struct np_e2e_message_s *copy_of_message,
                      struct np_e2e_message_s *message);

NP_API_INTERN
enum np_return _np_message_encrypt_payload(struct np_e2e_message_s *msg,
                                           np_crypto_session_t *crypto_session);
NP_API_INTERN
enum np_return _np_message_decrypt_payload(struct np_e2e_message_s *msg,
                                           np_crypto_session_t *crypto_session);

// (de-) serialize a message to a binary stream using message pack (cmp.h)
NP_API_INTERN
bool _np_message_serialize_chunked(np_state_t              *context,
                                   struct np_e2e_message_s *msg);

NP_API_INTERN
bool _np_message_deserialize_header_and_instructions(
    void *buffer, struct np_n2n_messagepart_s *n2n_message);

NP_API_INTERN
enum np_return
np_messagepart_clone(np_state_t                  *context,
                     struct np_n2n_messagepart_s *cloned_messegepart,
                     struct np_n2n_messagepart_s *to_clone);

NP_API_INTERN
bool _np_message_deserialize_chunks(struct np_e2e_message_s *msg);

NP_API_INTERN
void _np_message_setbody(struct np_e2e_message_s *msg, np_tree_t *body);

NP_API_INTERN
bool _np_message_readbody(struct np_e2e_message_s *msg);

NP_API_INTERN
double _np_message_get_expiry(const struct np_e2e_message_s *const self);
NP_API_INTERN
bool _np_message_is_expired(const struct np_e2e_message_s *const msg_to_check);

NP_API_INTERN
np_dhkey_t *
_np_message_get_sessionid(const struct np_e2e_message_s *const self);

NP_API_INTERN
void _np_message_add_response_handler(
    const struct np_e2e_message_s *self,
    const np_util_event_t          event,
    bool                           use_destination_from_header_to_field);

// msg header constants
static const char *_NP_MSG_HEADER_TARGET  = "_np.target";
static const char *_NP_MSG_HEADER_SUBJECT = "_np.subj";
static const char *_NP_MSG_HEADER_TO      = "_np.to";
static const char *_NP_MSG_HEADER_FROM    = "_np.from";

// msg instructions constants
static const char *_NP_MSG_INST_SEND_COUNTER  = "_np.sendnr";
static const char *_NP_MSG_INST_PARTS         = "_np.parts";
static const char *_NP_MSG_INST_ACK           = "_np.ack";
static const char *_NP_MSG_INST_ACK_TO        = "_np.ack_to";
static const char *_NP_MSG_INST_SEQ           = "_np.seq";
static const char *_NP_MSG_INST_UUID          = "_np.uuid";
static const char *_NP_MSG_INST_RESPONSE_UUID = "_np.response_uuid";
static const char *_NP_MSG_INST_TTL           = "_np.ttl";
static const char *_NP_MSG_INST_TSTAMP        = "_np.tstamp";

// msg extension constants
static const char *_NP_MSG_EXTENSIONS_SESSION = "_np.session";

// msg handshake constants
static const char *NP_HS_PAYLOAD   = "_np.payload";
static const char *NP_HS_SIGNATURE = "_np.signature";
static const char *NP_HS_PRIO      = "_np.hs.priority";
static const char *NP_NW_MAX_MSGS_PER_SEC =
    "_np.network.default_max_msgs_per_sec";
// body constants
static const char *NP_MSG_BODY_TEXT = "_np.text";
static const char *NP_MSG_BODY_XML  = "_np.xml";

#ifdef __cplusplus
}
#endif

#endif /* _NP_MESSAGE_H_ */
