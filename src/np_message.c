//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "np_message.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "event/ev.h"
#include "inttypes.h"
#include "sodium.h"
#include "tree/tree.h"

#include "neuropil_log.h"

#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"
#include "util/np_serialization.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_constants.h"
#include "np_dendrit.h"
#include "np_eventqueue.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_network.h"
#include "np_node.h"
#include "np_responsecontainer.h"
#include "np_settings.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_types.h"
#include "np_util.h"

// NP_DLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_message_ptr);

NP_DLL_GENERATE_IMPLEMENTATION(np_message_ptr);

static const size_t _msg_header_uuid_bytes  = NP_UUID_BYTES;
static const size_t _msg_header_dhkey_bytes = NP_FINGERPRINT_BYTES;
static const size_t _msg_header_time_bytes  = sizeof(double);
static const size_t _msg_header_ttl_bytes   = sizeof(uint32_t);
static const size_t _msg_header_parts_bytes = sizeof(uint16_t);
static const size_t _msg_header_flags_bytes = sizeof(uint16_t);

void __set_header_pointer(struct np_e2e_message_s *message) {

  size_t byte_position = 0;
  message->nonce       = &message->binary_message[byte_position];
  byte_position += MSG_NONCE_SIZE;

  message->mac_e = &message->binary_message[byte_position];
  byte_position += MSG_MAC_SIZE;

  message->subject = (np_dhkey_t *)&message->binary_message[byte_position];
  byte_position += _msg_header_dhkey_bytes;

  message->audience = (np_dhkey_t *)&message->binary_message[byte_position];
  byte_position += _msg_header_dhkey_bytes;

  message->uuid = &message->binary_message[byte_position];
  byte_position += _msg_header_uuid_bytes;

  message->tstamp = (double *)&message->binary_message[byte_position];
  byte_position += _msg_header_time_bytes;

  message->ttl = (uint32_t *)&message->binary_message[byte_position];
  byte_position += _msg_header_ttl_bytes;

  message->parts = (uint16_t *)&message->binary_message[byte_position];
  byte_position += _msg_header_parts_bytes;

  message->msg_flags = (uint16_t *)&message->binary_message[byte_position];
  // byte_position += _msg_header_flags_bytes;
}

void _np_message_t_new(np_state_t       *context,
                       NP_UNUSED uint8_t type,
                       NP_UNUSED size_t  size,
                       void             *msg) {
  struct np_e2e_message_s *msg_tmp = (struct np_e2e_message_s *)msg;

  msg_tmp->subject   = NULL;
  msg_tmp->audience  = NULL;
  msg_tmp->uuid      = NULL;
  msg_tmp->tstamp    = NULL;
  msg_tmp->ttl       = NULL;
  msg_tmp->parts     = NULL;
  msg_tmp->msg_flags = NULL;
  msg_tmp->mac_e     = NULL;
  msg_tmp->nonce     = NULL;

  msg_tmp->msg_chunks = NULL;

  msg_tmp->send_at = msg_tmp->redelivery_at = 0.0;
  msg_tmp->state                            = msgstate_unknown;
}

// destructor of np_message_t
void _np_message_t_del(np_state_t       *context,
                       NP_UNUSED uint8_t type,
                       NP_UNUSED size_t  size,
                       void             *data) {
  struct np_e2e_message_s *msg = (struct np_e2e_message_s *)data;

  log_debug(LOG_MEMORY | LOG_DEBUG, msg->uuid, "msg freeing memory");

  if (msg->msg_chunks != NULL) {
    assert(msg->state == msgstate_chunked);
    for (uint16_t i = 0; i < *msg->parts; i++) {
      np_unref_obj(np_messagepart_t,
                   msg->msg_chunks[i],
                   ref_message_messagepart);
    }
    free(msg->msg_chunks);
    msg->msg_chunks = NULL;
  }
  if (msg->msg_body != NULL) {
    assert(msg->state == msgstate_raw);
    np_tree_free(msg->msg_body);
    msg->msg_body = NULL;
  }
  if (msg->binary_message != NULL) {
    // we have at least one 1024 block in a message
    free(msg->binary_message);
  }
}

static void _np_message_calculate_chunking(struct np_e2e_message_s *msg) {
  np_ctx_memory(msg);

  assert(msg->state == msgstate_binary);

  uint32_t fixed_header_bytes = MSG_HEADER_SIZE + MSG_NONCE_SIZE + MSG_MAC_SIZE;
  // (binary_length - fixed_header_bytes) is already a multiple of
  // (MSG_CHUNK_SIZE_1024 - fixed_size)
  uint32_t chunks = ((uint16_t)(msg->binary_length - fixed_header_bytes) /
                     (MSG_CHUNK_SIZE_1024 - fixed_header_bytes));

  log_info(LOG_INFO, msg->uuid, "required message chunks: %" PRId32, chunks);

  if (chunks > UINT16_MAX) {
    log_error(msg->uuid,
              "%s",
              "message size too large, cutting off part of the message");
    *msg->parts = UINT16_MAX;
  } else {
    *msg->parts = chunks;
  }
}

enum np_return _np_message_add_chunk(struct np_e2e_message_s     *msg,
                                     struct np_n2n_messagepart_s *n2n_message,
                                     uint16_t *count_of_chunks) {

  np_ctx_memory(msg);

  assert(msg != NULL);
  assert(n2n_message != NULL);
  assert(msg->state == msgstate_unknown || msg->state == msgstate_chunked);

  msg->state = msgstate_chunked;

  np_ref_obj(np_messagepart_t, n2n_message, ref_message_messagepart);

  if (msg->msg_chunks == NULL) {
    msg->msg_chunks    = calloc(*n2n_message->e2e_msg_part.parts,
                             sizeof(struct np_n2n_messagepart_s *));
    msg->msg_chunks[0] = n2n_message;
    msg->msg_chunk_counter++;
    *count_of_chunks = msg->msg_chunk_counter;

    msg->subject   = n2n_message->e2e_msg_part.subject;
    msg->audience  = n2n_message->e2e_msg_part.audience;
    msg->uuid      = n2n_message->e2e_msg_part.uuid;
    msg->tstamp    = n2n_message->e2e_msg_part.tstamp;
    msg->ttl       = n2n_message->e2e_msg_part.ttl;
    msg->parts     = n2n_message->e2e_msg_part.parts;
    msg->msg_flags = n2n_message->e2e_msg_part.msg_flags;
    msg->mac_e     = n2n_message->e2e_msg_part.mac_e;
    msg->nonce     = n2n_message->e2e_msg_part.nonce;
    log_msg(LOG_INFO,
            msg->uuid,
            "message base chunk (%" PRIu32 " / %" PRIu16 ") now in list",
            n2n_message->seq,
            *((uint16_t *)n2n_message->e2e_msg_part.mac_e));

    return np_ok;
  }

  int8_t cmp_result = sodium_compare(n2n_message->e2e_msg_part.mac_e,
                                     msg->mac_e,
                                     sizeof(uint16_t));

  struct np_n2n_messagepart_s *tmp = NULL;

  if (cmp_result == 0) {
    log_msg(LOG_INFO,
            msg->uuid,
            "message base chunk (%" PRIu32 " / %" PRIu16
            ") already present in list, ignoring",
            n2n_message->seq,
            *((uint16_t *)n2n_message->e2e_msg_part.mac_e));
    *count_of_chunks = msg->msg_chunk_counter;
    np_memory_unref_obj(context, n2n_message, ref_message_messagepart);
    return np_operation_failed;

  } else if (cmp_result < 0) {
    tmp                = msg->msg_chunks[0];
    msg->msg_chunks[0] = n2n_message;

    msg->subject  = msg->msg_chunks[0]->e2e_msg_part.subject;
    msg->audience = msg->msg_chunks[0]->e2e_msg_part.audience;
    msg->uuid     = msg->msg_chunks[0]->e2e_msg_part.uuid;
    msg->tstamp   = msg->msg_chunks[0]->e2e_msg_part.tstamp;
    msg->ttl      = msg->msg_chunks[0]->e2e_msg_part.ttl;
    msg->parts    = msg->msg_chunks[0]->e2e_msg_part.parts;
    msg->mac_e    = msg->msg_chunks[0]->e2e_msg_part.mac_e;
    msg->nonce    = msg->msg_chunks[0]->e2e_msg_part.nonce;
    // re-insert old
    _np_message_add_chunk(msg, tmp, count_of_chunks);
    np_memory_unref_obj(context, tmp, ref_message_messagepart);

  } else {

    uint16_t chunk_index_new = 0;

    memcpy(&chunk_index_new, n2n_message->e2e_msg_part.mac_e, sizeof(uint16_t));
    log_debug(LOG_MESSAGE,
              msg->uuid,
              "message part %" PRIu32 " contained message chunk (%" PRIu16 ")",
              n2n_message->seq,
              chunk_index_new);

    sodium_sub((unsigned char *)&chunk_index_new, msg->mac_e, sizeof(uint16_t));

    log_debug(LOG_MESSAGE,
              msg->uuid,
              "message part %" PRIu32 " contained message chunk (%" PRIu16 ")",
              n2n_message->seq,
              chunk_index_new);

    if (msg->msg_chunks[chunk_index_new] != NULL) {

      if (0 == memcmp(n2n_message->e2e_msg_part.mac_e,
                      msg->msg_chunks[chunk_index_new]->e2e_msg_part.mac_e,
                      MSG_MAC_SIZE)) {
        // ignore new
        log_debug(LOG_MESSAGE,
                  msg->uuid,
                  "message chunk (%" PRIu32
                  ") already present in list, ignoring",
                  n2n_message->seq);
        *count_of_chunks = msg->msg_chunk_counter;
        np_memory_unref_obj(context, n2n_message, ref_message_messagepart);
        return np_operation_failed;

      } else {
        // insert new
        tmp                              = msg->msg_chunks[chunk_index_new];
        msg->msg_chunks[chunk_index_new] = n2n_message;
        // re-insert old
        _np_message_add_chunk(msg, tmp, count_of_chunks);
        np_memory_unref_obj(context, tmp, ref_message_messagepart);
      }

    } else {
      // insert new
      log_debug(LOG_MESSAGE,
                msg->uuid,
                "message chunk (%" PRIu32
                ") inserting as new element into list",
                n2n_message->seq);
      msg->msg_chunk_counter++;
      msg->msg_chunks[chunk_index_new] = n2n_message;
    }
  }
  *count_of_chunks = msg->msg_chunk_counter;
  return (np_ok);
}

double _np_message_get_expiry(const struct np_e2e_message_s *const self) {
  np_ctx_memory(self);

  double now = np_time_now();

  double tstamp = 0.0;
  memcpy(&tstamp, self->tstamp, sizeof(double));

  uint32_t ttl = 0;
  memcpy(&ttl, self->ttl, sizeof(uint32_t));

  if (tstamp > now) {
    // timestap of msg is in the future.
    // this is not possible and may indecate
    // a faulty date/time setup on the client
    log_msg(LOG_WARNING,
            NULL,
            "Detected faulty timestamp for message. Setting to now. "
            "(timestamp: %f, now: %f, diff: %f sec)",
            tstamp,
            now,
            tstamp - now);
  }

  return (tstamp + ttl);
}

bool _np_message_is_expired(const struct np_e2e_message_s *const self) {
  np_ctx_memory(self);
  bool   ret = false;
  double now = np_time_now();

  double remaining_ttl = _np_message_get_expiry(self) - now;
  ret                  = remaining_ttl <= 0;

#ifdef DEBUG
  double tstamp = 0.0;
  memcpy(&tstamp, self->tstamp, sizeof(double));

  uint32_t ttl = 0;
  memcpy(&ttl, self->ttl, sizeof(uint32_t));

  log_debug(LOG_MESSAGE,
            self->uuid,
            "messsage expiry check: now: %f, msg_ttl: %" PRIu32
            ", msg_ts: %f, "
            "remaining_ttl: %f",
            now,
            ttl,
            tstamp,
            remaining_ttl);
#endif

  return ret;
}

bool _np_message_serialize_chunked(np_state_t              *context,
                                   struct np_e2e_message_s *msg) {

  assert(msg->state == msgstate_binary);
  assert(msg->msg_chunks == NULL);

  bool ret_val = false;

  uint16_t i = 0;

  unsigned char *bin_header_pointer =
      msg->binary_message + MSG_NONCE_SIZE + MSG_MAC_SIZE;
  unsigned char *bin_body_ptr =
      msg->binary_message + MSG_NONCE_SIZE + MSG_MAC_SIZE + MSG_HEADER_SIZE;

  uint16_t chunk_bytes =
      (MSG_CHUNK_SIZE_1024 - MSG_NONCE_SIZE - MSG_MAC_SIZE - MSG_HEADER_SIZE);

  msg->msg_chunks = calloc(*msg->parts, sizeof(struct np_n2n_messagepart_s *));

  // TODO: do this serialization in parallel in background
  while (i < *msg->parts) {

    np_new_obj(np_messagepart_t, msg->msg_chunks[i], ref_message_messagepart);

    msg->msg_chunks[i]->e2e_msg_part.nonce = msg->nonce;
    msg->msg_chunks[i]->e2e_msg_part.mac_e = msg->mac_e;

    msg->msg_chunks[i]->e2e_msg_part.msg_header = bin_header_pointer;
    msg->msg_chunks[i]->e2e_msg_part.subject    = msg->subject;
    msg->msg_chunks[i]->e2e_msg_part.audience   = msg->audience;
    msg->msg_chunks[i]->e2e_msg_part.tstamp     = msg->tstamp;
    msg->msg_chunks[i]->e2e_msg_part.ttl        = msg->ttl;
    msg->msg_chunks[i]->e2e_msg_part.uuid       = msg->uuid;
    msg->msg_chunks[i]->e2e_msg_part.parts      = msg->parts;
    msg->msg_chunks[i]->e2e_msg_part.msg_flags  = msg->msg_flags;

    msg->msg_chunks[i]->e2e_msg_part.msg_body = bin_body_ptr;

    msg->msg_chunks[i]->hop_count    = 0;
    msg->msg_chunks[i]->chunk_offset = i;

    /// TODO: ensure endianess of header values
    /// TODO: add instruction values and ensure endianess of instructions
    /// values

    bin_body_ptr += chunk_bytes;
    i++;
  }

  ret_val    = true;
  msg->state = msgstate_chunked;

  log_debug(LOG_SERIALIZATION,
            msg->uuid,
            "message chunked into %" PRIu16 " parts",
            *msg->parts);

  return (ret_val);
}

bool _np_message_deserialize_header_and_instructions(
    void *buffer, struct np_n2n_messagepart_s *n2n_msg) {
  np_ctx_memory(buffer);

  assert(buffer != NULL);

  n2n_msg->msg_chunk = buffer;
  np_ref_obj(BLOB_1024, buffer, ref_obj_usage);

  uint16_t buffer_index = 0;
  memcpy(n2n_msg->mac_n, &buffer[buffer_index], MSG_MAC_SIZE);
  buffer_index += MSG_MAC_SIZE;
  memcpy(&n2n_msg->seq, &buffer[buffer_index], sizeof(uint32_t));
  buffer_index += sizeof(uint32_t);
  memcpy(&n2n_msg->hop_count, &buffer[buffer_index], sizeof(uint16_t));
  buffer_index += sizeof(uint16_t);

  n2n_msg->e2e_msg_part.mac_e = &buffer[buffer_index];
  buffer_index += MSG_MAC_SIZE;

  n2n_msg->e2e_msg_part.msg_header = &buffer[buffer_index];

  n2n_msg->e2e_msg_part.subject = (np_dhkey_t *)&buffer[buffer_index];
  buffer_index += _msg_header_dhkey_bytes;
  n2n_msg->e2e_msg_part.audience = (np_dhkey_t *)&buffer[buffer_index];
  buffer_index += _msg_header_dhkey_bytes;
  n2n_msg->e2e_msg_part.uuid = (unsigned char *)&buffer[buffer_index];
  buffer_index += _msg_header_uuid_bytes;
  n2n_msg->e2e_msg_part.tstamp = (double *)&buffer[buffer_index];
  buffer_index += _msg_header_time_bytes;
  n2n_msg->e2e_msg_part.ttl = (uint32_t *)&buffer[buffer_index];
  buffer_index += _msg_header_ttl_bytes;
  n2n_msg->e2e_msg_part.parts = (uint16_t *)&buffer[buffer_index];
  buffer_index += _msg_header_parts_bytes;
  n2n_msg->e2e_msg_part.msg_flags = (uint16_t *)&buffer[buffer_index];
  buffer_index += _msg_header_flags_bytes;

  assert(buffer_index ==
         MSG_INSTRUCTIONS_SIZE + MSG_MAC_SIZE + MSG_HEADER_SIZE);
  n2n_msg->e2e_msg_part.msg_body = &buffer[buffer_index];

  buffer_index +=
      MSG_CHUNK_SIZE_1024 - MSG_NONCE_SIZE - MSG_MAC_SIZE - MSG_HEADER_SIZE;

  n2n_msg->e2e_msg_part.nonce = &buffer[buffer_index];
  buffer_index += MSG_NONCE_SIZE;

  assert(buffer_index == MSG_INSTRUCTIONS_SIZE + MSG_CHUNK_SIZE_1024);

  return true;
}

enum np_return
np_messagepart_clone(np_state_t                  *context,
                     struct np_n2n_messagepart_s *cloned_messegepart,
                     struct np_n2n_messagepart_s *to_clone) {

  char *new_blob = NULL;
  np_new_obj(BLOB_1024, new_blob);
  memcpy(new_blob,
         to_clone->msg_chunk,
         MSG_CHUNK_SIZE_1024 + MSG_INSTRUCTIONS_SIZE);

  _np_message_deserialize_header_and_instructions(new_blob, cloned_messegepart);
  np_unref_obj(BLOB_1024, new_blob, ref_obj_creation);

  cloned_messegepart->is_forwarded_part = to_clone->is_forwarded_part;
  cloned_messegepart->hop_count         = to_clone->hop_count;

  return (np_ok);
}

bool _np_message_deserialize_chunks(struct np_e2e_message_s *msg) {
  np_ctx_memory(msg);

  assert(msg->state == msgstate_chunked);
  assert(msg->msg_chunks != NULL);

  uint16_t msg_parts = *msg->msg_chunks[0]->e2e_msg_part.parts;
  assert(msg_parts > 0);

  uint16_t fixed_header_bytes = MSG_NONCE_SIZE + MSG_MAC_SIZE + MSG_HEADER_SIZE;
  uint16_t chunk_bytes        = MSG_CHUNK_SIZE_1024 - fixed_header_bytes;

  size_t message_size = chunk_bytes * msg_parts;

  msg->binary_length =
      message_size + fixed_header_bytes; // new_size * (MSG_CHUNK_SIZE_1024 -
                                         // fixed_header_bytes);
  msg->binary_message = realloc(msg->binary_message, msg->binary_length);
  if (msg->binary_message == NULL) return false; //  np_out_of_memory;

  void *body_ptr = msg->binary_message;

  for (uint16_t i = 0; i < msg_parts; i++) {
    if (msg->msg_chunks[i] == NULL) return false;

    if (i == 0) {
      memcpy(body_ptr, msg->msg_chunks[i]->e2e_msg_part.nonce, MSG_NONCE_SIZE);
      body_ptr += MSG_NONCE_SIZE;
      memcpy(body_ptr, msg->msg_chunks[i]->e2e_msg_part.mac_e, MSG_MAC_SIZE);
      body_ptr += MSG_MAC_SIZE;
      memcpy(body_ptr,
             msg->msg_chunks[i]->e2e_msg_part.msg_header,
             MSG_HEADER_SIZE);
      body_ptr += MSG_HEADER_SIZE;
      __set_header_pointer(msg);
    }
    memcpy(body_ptr, msg->msg_chunks[i]->e2e_msg_part.msg_body, chunk_bytes);
    body_ptr += chunk_bytes;
  }

  if (msg->msg_chunks != NULL) {
    for (uint16_t i = 0; i < msg_parts; i++) {
      np_unref_obj(np_messagepart_t,
                   msg->msg_chunks[i],
                   ref_message_messagepart);
    }
    free(msg->msg_chunks);
    msg->msg_chunks = NULL;
  }

  msg->state = msgstate_binary;
  return true;
}

bool _np_message_readbody(struct np_e2e_message_s *msg) {
  np_ctx_memory(msg);
  bool ret = true;

  assert(msg->state == msgstate_binary);
  assert(msg->binary_message != NULL);

  if (msg->msg_body != NULL) np_tree_free(msg->msg_body);

  msg->msg_body = np_tree_create();
  msg->state    = msgstate_raw;

  np_deserialize_buffer_t body_deserializer = {
      ._target_tree = msg->msg_body,
      ._buffer =
          &msg->binary_message[MSG_NONCE_SIZE + MSG_MAC_SIZE + MSG_HEADER_SIZE],
      ._buffer_size = msg->binary_length,
      ._bytes_read  = 0,
      ._error       = 0};
  np_serializer_read_map(context, &body_deserializer, msg->msg_body);

  if (body_deserializer._error != 0) {
    msg->state = msgstate_binary;
    np_tree_free(msg->msg_body);
    msg->msg_body = NULL;
    ret           = false;
  }
  return ret;
}

/**
 ** message_create:
 ** creates the message to the destination #dest# the message format would be
 *like:
 **  [ type ] [ size ] [ key ] [ data ]. It return the created message
 *structure.
 */
void _np_message_create(struct np_e2e_message_s *msg,
                        np_dhkey_t               to,
                        np_dhkey_t               from,
                        np_dhkey_t               subject,
                        np_tree_t               *the_data) {
  np_ctx_memory(msg);

  assert(msg->state == msgstate_unknown);

  size_t fixed_header_bytes = MSG_NONCE_SIZE + MSG_MAC_SIZE + MSG_HEADER_SIZE;

  size_t object_size = 0;
  if (the_data != NULL) {
    object_size += np_tree_get_byte_size(the_data);
  }

  size_t new_size = object_size / (MSG_CHUNK_SIZE_1024 - fixed_header_bytes);
  new_size = (object_size % (MSG_CHUNK_SIZE_1024 - fixed_header_bytes) == 0)
                 ? new_size
                 : new_size + 1;

  msg->binary_length = new_size * (MSG_CHUNK_SIZE_1024 - fixed_header_bytes) +
                       fixed_header_bytes;
  msg->binary_message = realloc(msg->binary_message, msg->binary_length);
  if (msg->binary_message == NULL) return; // np_out_of_memory;

  __set_header_pointer(msg);

  _np_dhkey_assign(msg->subject, &subject);
  _np_dhkey_assign(msg->audience, &to);

  np_uuid_create("urn:np:message:generate_message_id", 32564, &msg->uuid);

  msg->redelivery_at = msg->send_at = np_time_now();
  memcpy(msg->tstamp, &msg->send_at, sizeof(double));

  // derived message data from the msgproperty
  np_msgproperty_conf_t *out_prop =
      _np_msgproperty_conf_get(context, OUTBOUND, subject);

  // default message ttl
  uint32_t msg_ttl = MSGPROPERTY_DEFAULT_MSG_TTL;
  if (out_prop != NULL) msg_ttl = out_prop->msg_ttl / (out_prop->retry + 1);
  if (msg_ttl == 0)
    log_error(msg->uuid,
              "%s",
              "message time-to-live is 0, check your retry/ttl settings! "
              "(setting it now to 1s)");
  if (msg_ttl == 0) msg_ttl = 1;
  memcpy(msg->ttl, &msg_ttl, sizeof(uint32_t));

  // insert msg acknowledgement indicator
  enum np_msg_flags msg_flags = 0x0000;
  if (out_prop != NULL && FLAG_CMP(out_prop->ack_mode, ACK_DESTINATION)) {
    msg_flags |= msg_ack_dest;
  } else if (out_prop != NULL && FLAG_CMP(out_prop->ack_mode, ACK_CLIENT)) {
    msg_flags |= msg_ack_client;
  } else {
    msg_flags |= msg_ack_none;
  }
  memcpy(msg->msg_flags, &msg_flags, sizeof(uint16_t));

  msg->state = msgstate_raw;

  if (the_data != NULL) {
    struct np_serialize_buffer_s buffer = {
        ._target_buffer = &msg->binary_message[MSG_NONCE_SIZE + MSG_MAC_SIZE +
                                               MSG_HEADER_SIZE],
        ._buffer_size   = msg->binary_length - MSG_NONCE_SIZE - MSG_MAC_SIZE -
                        MSG_HEADER_SIZE,
        ._tree          = the_data,
        ._bytes_written = 0,
        ._error         = 0};
    np_serializer_write_map(context, &buffer, the_data);
    size_t padding = msg->binary_length - buffer._bytes_written -
                     MSG_NONCE_SIZE - MSG_MAC_SIZE - MSG_HEADER_SIZE;
    // TODO: use sodium_pad
    randombytes_buf(
        &msg->binary_message[buffer._bytes_written + MSG_NONCE_SIZE +
                             MSG_MAC_SIZE + MSG_HEADER_SIZE],
        padding);
    msg->state = msgstate_binary;
    _np_message_calculate_chunking(msg);
  } else {
    *msg->parts = 1;
  }
}

inline void _np_message_setbody(struct np_e2e_message_s *msg,
                                np_tree_t               *new_body) {

  np_ctx_memory(msg);

  assert(msg->state == msgstate_raw);

  size_t fixed_header_bytes = MSG_NONCE_SIZE + MSG_MAC_SIZE + MSG_HEADER_SIZE;

  size_t object_size = 0;
  object_size += np_tree_get_byte_size(new_body);

  size_t new_size = object_size / (MSG_CHUNK_SIZE_1024 - fixed_header_bytes);
  new_size = (object_size % (MSG_CHUNK_SIZE_1024 - fixed_header_bytes) == 0)
                 ? new_size
                 : new_size + 1;

  size_t new_length = new_size * (MSG_CHUNK_SIZE_1024 - fixed_header_bytes) +
                      fixed_header_bytes;

  if (new_length != msg->binary_length) {
    msg->binary_length  = new_length;
    msg->binary_message = realloc(msg->binary_message, msg->binary_length);
  }
  __set_header_pointer(msg);

  struct np_serialize_buffer_s buffer = {
      ._target_buffer =
          &msg->binary_message[MSG_NONCE_SIZE + MSG_MAC_SIZE + MSG_HEADER_SIZE],
      ._buffer_size =
          msg->binary_length - MSG_NONCE_SIZE - MSG_MAC_SIZE - MSG_HEADER_SIZE,
      ._tree          = new_body,
      ._bytes_written = 0,
      ._error         = 0};
  np_serializer_write_map(context, &buffer, new_body);
  if (buffer._error != 0) {
    return /*np_operation_failed*/;
  }

  size_t padding = msg->binary_length - buffer._bytes_written - MSG_NONCE_SIZE -
                   MSG_MAC_SIZE - MSG_HEADER_SIZE;
  // TODO: use sodium_pad
  randombytes_buf(&msg->binary_message[buffer._bytes_written + MSG_NONCE_SIZE +
                                       MSG_MAC_SIZE + MSG_HEADER_SIZE],
                  padding);
  msg->state = msgstate_binary;

  if (msg->msg_body != NULL) {
    np_tree_free(msg->msg_body);
    msg->msg_body = NULL;
  }

  _np_message_calculate_chunking(msg);
};

bool np_message_clone(struct np_e2e_message_s *copy_of_message,
                      struct np_e2e_message_s *message) {

  assert(message->state == msgstate_binary);

  copy_of_message->send_at       = message->send_at;
  copy_of_message->redelivery_at = message->redelivery_at;
  copy_of_message->binary_length = message->binary_length;
  copy_of_message->state         = message->state;

  copy_of_message->binary_message = malloc(message->binary_length);
  memcpy(copy_of_message->binary_message,
         message->binary_message,
         message->binary_length);

  __set_header_pointer(copy_of_message);

  return true;
}

enum np_return
_np_message_encrypt_payload(struct np_e2e_message_s *msg,
                            np_crypto_session_t     *crypto_session) {
  np_ctx_memory(msg);

  assert(msg->state == msgstate_binary);

  randombytes_buf((void *)msg->nonce, MSG_NONCE_SIZE);

  int ret = np_crypto_session_encrypt(
      context,
      crypto_session,
      // out 1: encrypted message
      &msg->binary_message[MSG_NONCE_SIZE + MSG_MAC_SIZE + MSG_HEADER_SIZE],
      msg->binary_length - MSG_NONCE_SIZE - MSG_MAC_SIZE - MSG_HEADER_SIZE,
      // out 2: MAC
      &msg->binary_message[MSG_NONCE_SIZE],
      MSG_MAC_SIZE,
      // in 1: text to encrypt
      &msg->binary_message[MSG_NONCE_SIZE + MSG_MAC_SIZE + MSG_HEADER_SIZE],
      msg->binary_length - MSG_NONCE_SIZE - MSG_MAC_SIZE - MSG_HEADER_SIZE,
      // in 2: additional data to sign
      &msg->binary_message[MSG_NONCE_SIZE + MSG_MAC_SIZE],
      MSG_HEADER_SIZE,
      // in 3: nonce
      msg->nonce);

  if (ret < 0) {
    return (np_operation_failed);
  }
  return np_ok;

  // // add encryption details to the message
  // np_tree_insert_str(
  //     msg->body,
  //     NP_NONCE,
  //     np_treeval_new_bin(nonce,
  //     crypto_aead_chacha20poly1305_IETF_NPUBBYTES));
}

enum np_return
_np_message_decrypt_payload(struct np_e2e_message_s *msg,
                            np_crypto_session_t     *crypto_session) {
  np_ctx_memory(msg);

  assert(msg->state == msgstate_binary);

  int ret = np_crypto_session_decrypt(
      context,
      crypto_session,
      // IN 1: text to decrypt
      &msg->binary_message[MSG_NONCE_SIZE + MSG_MAC_SIZE + MSG_HEADER_SIZE],
      msg->binary_length - MSG_NONCE_SIZE - MSG_MAC_SIZE - MSG_HEADER_SIZE,
      // IN 1: MAC
      &msg->binary_message[MSG_NONCE_SIZE],
      MSG_MAC_SIZE,
      // OUT 1: the decrypted text
      &msg->binary_message[MSG_NONCE_SIZE + MSG_MAC_SIZE + MSG_HEADER_SIZE],
      msg->binary_length - MSG_NONCE_SIZE - MSG_MAC_SIZE - MSG_HEADER_SIZE,
      // IN 4: additional protected data
      &msg->binary_message[MSG_NONCE_SIZE + MSG_MAC_SIZE],
      MSG_HEADER_SIZE,
      // IN 4: NONCE
      msg->nonce);

  if (ret < 0) {
    log_msg(LOG_ERROR, NULL, "decryption of message payload failed");
    return (np_operation_failed);
  }

  return (np_ok);
}

void _np_message_add_response_handler(
    const struct np_e2e_message_s *self,
    const np_util_event_t          event,
    bool                           use_destination_from_header_to_field) {
  np_ctx_memory(self);

  np_responsecontainer_t *rh = NULL;
  np_new_obj(np_responsecontainer_t, rh, FUNC);

  // TODO: more efficient, please ...
  memcpy(rh->uuid, self->uuid, NP_UUID_BYTES);
  if (use_destination_from_header_to_field) {
    // in case of n2n messages
    rh->dest_dhkey = *self->audience;
  } else {
    // in case of e2e messages
    rh->msg_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, *self->subject);
  }
  np_msgproperty_conf_t *out_prop =
      _np_msgproperty_conf_get(context, OUTBOUND, *self->subject);

  memcpy(&rh->send_at, self->tstamp, sizeof(double));
  if (out_prop != NULL) rh->expires_at = rh->send_at + out_prop->msg_ttl;
  else rh->expires_at = rh->send_at + MSGPROPERTY_DEFAULT_MSG_TTL;
  rh->received_at = 0.0;

  np_dhkey_t      ack_dhkey = _np_msgproperty_dhkey(INBOUND, _NP_MSG_ACK);
  np_util_event_t rh_event  = {.user_data    = rh,
                               .target_dhkey = ack_dhkey,
                               .type         = (evt_internal | evt_response)};
  _np_event_runtime_add_event(context, event.current_run, ack_dhkey, rh_event);
}

np_dhkey_t *
_np_message_get_sessionid(const struct np_e2e_message_s *const self) {

  np_ctx_memory(self);
  ASSERT(self != NULL, "Cannot operate on not initialised message");

  return self->audience;
}
