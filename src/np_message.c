//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
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

NP_DLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_message_ptr);
NP_DLL_GENERATE_IMPLEMENTATION(np_message_ptr);

static const size_t msg_chunk_size =
    MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40;

void _np_message_t_new(np_state_t       *context,
                       NP_UNUSED uint8_t type,
                       NP_UNUSED size_t  size,
                       void             *msg) {
  log_trace_msg(LOG_TRACE | LOG_MESSAGE,
                "start: void _np_message_t_new(void* msg){");
  np_message_t *msg_tmp = (np_message_t *)msg;

  // char mutex_str[64];
  // snprintf(mutex_str, 63, "%s", "urn:np:message:msg_chunks");
  // _np_threads_mutex_init(context, &msg_tmp->msg_chunks_lock, mutex_str);
  TSP_INIT(msg_tmp->msg_chunks);
  pll_init(np_messagepart_ptr, msg_tmp->msg_chunks);

  msg_tmp->uuid = np_uuid_create("msg", 0, NULL);

  log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
                "creating uuid %s for new msg",
                msg_tmp->uuid);

  msg_tmp->header         = np_tree_create();
  msg_tmp->instructions   = np_tree_create();
  msg_tmp->body           = np_tree_create();
  msg_tmp->footer         = np_tree_create();
  msg_tmp->send_at        = 0;
  msg_tmp->no_of_chunks   = 1;
  msg_tmp->is_single_part = false;

  msg_tmp->bin_body   = NULL;
  msg_tmp->bin_footer = NULL;
  msg_tmp->bin_static = NULL;

  msg_tmp->submit_type      = np_message_submit_type_ROUTE;
  msg_tmp->decryption_token = NULL;
}

/*
    May allow the system to use the incomming buffer directly
    to populate the tree stuctures (header/body/...)
*/
void _np_message_mark_as_incomming(np_message_t *msg) {

  msg->header->attr.in_place       = false;
  msg->instructions->attr.in_place = false;

  msg->body->attr.in_place   = true;
  msg->footer->attr.in_place = true;
}

// destructor of np_message_t
void _np_message_t_del(np_state_t       *context,
                       NP_UNUSED uint8_t type,
                       NP_UNUSED size_t  size,
                       void             *data) {
  log_trace_msg(LOG_TRACE | LOG_MESSAGE,
                "start: void _np_message_t_del(void* data){");
  np_message_t *msg = (np_message_t *)data;

  log_debug_msg(LOG_MEMORY | LOG_DEBUG, "msg (%s) freeing memory", msg->uuid);

  // np_unref_obj(np_msgproperty_t, msg->msg_property,
  // ref_message_msg_property);

  np_unref_obj(np_aaatoken_t,
               msg->decryption_token,
               "np_message_t.decryption_token");

  np_tree_free(msg->header);
  np_tree_free(msg->instructions);
  np_tree_free(msg->body);
  np_tree_free(msg->footer);

  TSP_SCOPE(msg->msg_chunks) {
    if (msg->msg_chunks != NULL) {
      pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
      while (NULL != iter) {
        np_messagepart_ptr current_part = iter->val;
        np_unref_obj(np_messagepart_t, current_part, ref_message_messagepart);
        pll_next(iter);
      }
      pll_free(np_messagepart_ptr, msg->msg_chunks);
    }
  }

  if (msg->bin_static != NULL) {
    np_unref_obj(np_messagepart_t, msg->bin_static, ref_message_bin_static);
  }

  free(msg->bin_body);
  free(msg->bin_footer);

  msg->bin_body   = NULL;
  msg->bin_footer = NULL;
  msg->bin_static = NULL;

  TSP_DESTROY(msg->msg_chunks);
  // _np_threads_mutex_destroy(context, &msg->msg_chunks_lock);
  free(msg->uuid);
}

void _np_message_calculate_chunking(np_message_t *msg) {
  np_ctx_memory(msg);

  // TODO: message part split-up informations
  uint32_t header_size = (msg->header == NULL ? 0 : msg->header->byte_size);
  uint32_t instructions_size =
      (msg->instructions == NULL ? 0 : msg->instructions->byte_size);
  uint32_t fixed_size = MSG_ARRAY_SIZE + MSG_ENCRYPTION_BYTES_40 +
                        MSG_PAYLOADBIN_SIZE + header_size + instructions_size;

  uint32_t body_size    = (msg->body == NULL ? 0 : msg->body->byte_size);
  uint32_t footer_size  = (msg->footer == NULL ? 0 : msg->footer->byte_size);
  uint32_t payload_size = body_size + footer_size;

  uint32_t chunks =
      ((uint32_t)(payload_size) / (MSG_CHUNK_SIZE_1024 - fixed_size)) + 1;

  log_debug_msg(LOG_MESSAGE,
                "(msg: %s) Message serialisation sizes:"
                "  payload: %6" PRIu32 " [ body: %6" PRIu32
                " + footer: %6" PRIu32 "] fixed: %4" PRIu32
                " [ header: %4" PRIu32 " + instructions: %4" PRIu32
                " ] payload + fixed: %6" PRIu32 " chunks: %3" PRIu32,
                msg->uuid,
                payload_size,
                body_size,
                footer_size,
                fixed_size,
                header_size,
                instructions_size,
                payload_size + fixed_size,
                chunks);

  msg->no_of_chunks = chunks;
}

double _np_message_get_expiery(const np_message_t *const self) {
  np_ctx_memory(self);
  double now = np_time_now();
  double ret = now;
  ASSERT(self->instructions != NULL, "Cannot have a null tree");
  CHECK_STR_FIELD(self->instructions, _NP_MSG_INST_TTL, msg_ttl);
  CHECK_STR_FIELD(self->instructions, _NP_MSG_INST_TSTAMP, msg_tstamp);

  double tstamp = msg_tstamp.value.d;

  if (tstamp > now) {
    // timestap of msg is in the future.
    // this is not possible and may indecate
    // a faulty date/time setup on the client
    log_msg(LOG_WARNING,
            "Detected faulty timestamp for message. Setting to now. "
            "(timestamp: %f, now: %f, diff: %f sec)",
            tstamp,
            now,
            tstamp - now);
    // msg_tstamp.value.d = tstamp = now;
  }
  ret = (tstamp + msg_ttl.value.d);

__np_cleanup__:

  return ret;
}

bool _np_message_is_expired(const np_message_t *const self) {
  np_ctx_memory(self);
  bool   ret = false;
  double now = np_time_now();

#ifdef DEBUG
  CHECK_STR_FIELD(self->instructions, _NP_MSG_INST_TTL, msg_ttl);
  CHECK_STR_FIELD(self->instructions, _NP_MSG_INST_TSTAMP, msg_tstamp);
  double tstamp = msg_tstamp.value.d;
#endif

  double remaining_ttl = _np_message_get_expiery(self) - now;
  ret                  = remaining_ttl <= 0;

  log_debug(LOG_MESSAGE,
            "(msg: %s) expiry check: now: %f, msg_ttl: %f, msg_ts: %f, "
            "remaining_ttl: %f",
            self->uuid,
            now,
            msg_ttl.value.d,
            tstamp,
            remaining_ttl);

#ifdef DEBUG
__np_cleanup__ : {}
#endif

  return ret;
}

bool _np_message_serialize_header_and_instructions(np_state_t   *context,
                                                   np_message_t *msg) {
  // cmp_ctx_t          cmp;
  np_messagepart_ptr part = NULL;

  TSP_SCOPE(msg->msg_chunks) {
    assert(msg->msg_chunks != NULL);
    pll_iterator(np_messagepart_ptr) first = pll_first(msg->msg_chunks);
    assert(first != NULL);
    part = first->val;
    assert(part != NULL);
  }
  // we simply override the header and instructions part for a single part
  // message here, the byte size should be the same as before
  // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the header (size %hd)",
  // msg->header->size);
  size_t header_size = np_tree_get_byte_size(msg->header);
  // np_serializer_add_map_bytesize(msg->header, &header_size);
  np_serialize_buffer_t header_serializer = {._tree          = msg->header,
                                             ._target_buffer = part->msg_part,
                                             ._buffer_size   = header_size,
                                             ._bytes_written = 0,
                                             ._error         = 0};
  np_serializer_write_map(context, &header_serializer, msg->header);
  log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
                "serialized the header (size %" PRIu32 ")",
                msg->header->byte_size);

  // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the instructions (size
  // %hd)", msg->header->size);
  size_t instruction_size = np_tree_get_byte_size(msg->instructions);
  // np_serializer_add_map_bytesize(msg->instructions, &instruction_size);
  np_serialize_buffer_t instruction_serializer = {
      ._tree          = msg->instructions,
      ._target_buffer = &part->msg_part[header_serializer._bytes_written],
      ._buffer_size   = instruction_size,
      ._bytes_written = 0,
      ._error         = 0};

  np_serializer_write_map(context, &instruction_serializer, msg->instructions);
  log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
                "serialized the instructions (size %" PRIu32 ")",
                msg->instructions->byte_size);

  return (true);
}

bool _np_message_serialize_chunked(np_state_t *context, np_message_t *msg) {
  NP_PERFORMANCE_POINT_START(message_serialize_chunked);
  log_trace_msg(LOG_TRACE | LOG_MESSAGE,
                "start: bool _np_message_serialize_chunked(...){");

  np_ref_obj(np_message_t, msg);

  bool ret_val = false;

  np_tree_insert_str(msg->instructions,
                     _NP_MSG_INST_UUID,
                     np_treeval_new_s(msg->uuid));

  TSP_SCOPE(msg->msg_chunks) {
    // clean up any old chunking
    if (0 < pll_size(msg->msg_chunks)) {
      pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
      while (NULL != iter) {
        np_messagepart_ptr current_part = iter->val;
        np_unref_obj(np_messagepart_t, current_part, ref_message_messagepart);
        pll_next(iter);
      }
      pll_clear(np_messagepart_ptr, msg->msg_chunks);
    }
  }

  // TODO: optimize, more streaming
  // target is an array of 1024 byte size target buffers
  uint16_t i = 0;

  void *bin_header = NULL;

  void *bin_instructions = NULL;

  void *bin_body     = NULL;
  void *bin_body_ptr = NULL;
  bool  body_done    = false;

  size_t header_size = np_tree_get_byte_size(msg->header);
  // np_serializer_add_map_bytesize(msg->header, &header_size);
  size_t instruction_size = np_tree_get_byte_size(msg->instructions);
  // np_serializer_add_map_bytesize(msg->instructions, &instruction_size);
  size_t bin_body_size = np_tree_get_byte_size(msg->body);
  // np_serializer_add_map_bytesize(msg->body, &bin_body_size);
  size_t bin_footer_size = np_tree_get_byte_size(msg->footer);
  // np_serializer_add_map_bytesize(msg->footer, &bin_footer_size);

  uint16_t max_chunk_size = (MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40);
  // log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
  // "-----------------------------------------------------" );

  np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[0] =
      msg->no_of_chunks;

  uint16_t current_chunk_size = 0;

  // TODO: do this serialization in parallel in background
  while (i < msg->no_of_chunks) {
    np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)
        ->val.value.a2_ui[1] = i + 1;

    np_messagepart_t *part;
    np_new_obj(np_messagepart_t, part);

    part->header       = msg->header;
    part->instructions = msg->instructions;
    part->part         = i + 1;

    np_new_obj(BLOB_984_RANDOMIZED, part->msg_part);
    void *msg_part_ptr = part->msg_part;

    if (NULL == bin_header) { // TODO: optimize memory handling and allocate
                              // memory during serialization
      bin_header = malloc(header_size);
      CHECK_MALLOC(bin_header);
      memset(bin_header, 0, header_size);
      np_serialize_buffer_t header_serializer = {._tree          = msg->header,
                                                 ._target_buffer = bin_header,
                                                 ._buffer_size   = header_size,
                                                 ._bytes_written = 0,
                                                 ._error         = 0};
      np_serializer_write_map(context, &header_serializer, msg->header);
      log_trace_msg(LOG_MESSAGE,
                    "header serialization result : %hd %u",
                    header_serializer._bytes_written,
                    header_serializer._error);
    }

    log_trace_msg(LOG_MESSAGE, "copying the header (size %hd)", header_size);
    memcpy(msg_part_ptr, bin_header, header_size);
    msg_part_ptr += header_size;

    // reserialize the instructions into every chunk (_NP_MSG_INST_PARTS has
    // changed)
    {
      char bin_instructions[instruction_size];
      CHECK_MALLOC(bin_instructions);

      memset(bin_instructions, 0, instruction_size);
      // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "serializing the
      // instructions (size %hd)", msg->properties->size);
      np_serialize_buffer_t instruction_serializer = {
          ._tree          = msg->instructions,
          ._target_buffer = bin_instructions,
          ._buffer_size   = instruction_size,
          ._bytes_written = 0,
          ._error         = 0};
      np_serializer_write_map(context,
                              &instruction_serializer,
                              msg->instructions);

      log_debug_msg(LOG_MESSAGE,
                    "copying the instructions (size %hd) %hd %u",
                    msg->instructions->byte_size,
                    instruction_serializer._bytes_written,
                    instruction_serializer._error);
      memcpy(msg_part_ptr,
             bin_instructions,
             instruction_serializer._bytes_written);
      msg_part_ptr += instruction_serializer._bytes_written;

      // update current chunk size
      current_chunk_size = msg_part_ptr - part->msg_part;
    }

    if (NULL == bin_body) {
      // TODO: optimize memory handling and allocate memory during serialization
      bin_body = malloc(bin_body_size + bin_footer_size);
      CHECK_MALLOC(bin_body);

      bin_body_ptr = bin_body;
      memset(bin_body, 0, bin_body_size);
      // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the body (size
      // %hd)", msg->properties->size);
      np_serialize_buffer_t body_serializer = {._tree          = msg->body,
                                               ._target_buffer = &bin_body[0],
                                               ._buffer_size   = bin_body_size,
                                               ._bytes_written = 0,
                                               ._error         = 0};
      np_serializer_write_map(context, &body_serializer, msg->body);

      log_debug_msg(LOG_MESSAGE,
                    "serializing the body (size %hd) ",
                    body_serializer._bytes_written);
      np_serialize_buffer_t footer_serializer = {
          ._tree          = msg->footer,
          ._target_buffer = &bin_body[body_serializer._bytes_written],
          ._buffer_size   = bin_footer_size,
          ._bytes_written = 0,
          ._error         = 0};
      np_serializer_write_map(context, &footer_serializer, msg->footer);
      log_debug_msg(LOG_MESSAGE,
                    "serializing the footer (size %hd) ",
                    footer_serializer._bytes_written);
    }

    log_trace_msg(LOG_MESSAGE,
                  "before body: space left in chunk: %hd / %hd ",
                  (max_chunk_size - current_chunk_size),
                  current_chunk_size);

    if (0 < (max_chunk_size - current_chunk_size) && false == body_done) {
      uint32_t left_body_size =
          bin_body_size + bin_footer_size - (bin_body_ptr - bin_body);
      uint32_t possible_size = max_chunk_size - current_chunk_size;
      if (possible_size >= left_body_size) {
        log_trace_msg(LOG_MESSAGE,
                      "writing last body part (size %hd)",
                      left_body_size);
        memcpy(msg_part_ptr, bin_body_ptr, left_body_size);
        msg_part_ptr += left_body_size;
        bin_body_ptr += left_body_size;
        body_done = true;
        log_trace_msg(LOG_MESSAGE, "wrote all body (size %hd) ", bin_body_size);
      } else {
        memcpy(msg_part_ptr, bin_body_ptr, possible_size);
        msg_part_ptr += possible_size;
        bin_body_ptr += possible_size;
        log_trace_msg(LOG_MESSAGE,
                      "writing body part (size %hd) ",
                      possible_size);
      }
    } else {
      memcpy(msg_part_ptr, bin_body_ptr, 0);
      msg_part_ptr += 0;
      // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "copying empty tree (size
      // %hd)", empty_tree->byte_size);
      // memcpy(cmp.buf, bin_empty, empty_tree->byte_size);
    }
    current_chunk_size = msg_part_ptr - part->msg_part;

    // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "after footer: space left in
    // chunk: %hd / %hd",
    //  		(max_chunk_size - current_chunk_size),
    //  current_chunk_size );
    i++;

    // insert new
    TSP_SCOPE(msg->msg_chunks) {

      np_ref_obj(np_messagepart_t, part, ref_message_messagepart);
      if (false == pll_insert(np_messagepart_ptr,
                              msg->msg_chunks,
                              part,
                              false,
                              _np_messagepart_cmp)) {
        np_unref_obj(np_messagepart_t, part, ref_message_messagepart);
        np_unref_obj(BLOB_984_RANDOMIZED, part->msg_part, ref_obj_creation);

        // new entry is rejected (already present)
        log_msg(LOG_WARNING,
                "Msg part was rejected in _np_message_serialize_chunked");
      }
    }
    np_unref_obj(np_messagepart_t, part, ref_obj_creation);
    // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "-------------------------" );
  }
  ret_val = true;
  // log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
  // "-----------------------------------------------------" );

  log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
                "(msg: %s) chunked into %" PRIu32
                " parts (calculated no of chunks: %" PRIu16 ")",
                msg->uuid,
                pll_size(msg->msg_chunks),
                msg->no_of_chunks);

  // __np_cleanup__:
  if (NULL != bin_body) free(bin_body);
  if (NULL != bin_instructions) free(bin_instructions);
  if (NULL != bin_header) free(bin_header);

  np_unref_obj(np_message_t, msg, FUNC);

  NP_PERFORMANCE_POINT_END(message_serialize_chunked);
  return (ret_val);
}

bool _np_message_deserialize_header_and_instructions(np_message_t *msg,
                                                     void         *buffer) {
  np_ctx_memory(msg);

  if (buffer == NULL) return false;

  bool ret = false;
  if (msg->bin_static == NULL) {
    np_deserialize_buffer_t header_deserializer = {._target_tree = msg->header,
                                                   ._buffer      = buffer,
                                                   ._buffer_size =
                                                       msg_chunk_size,
                                                   ._bytes_read = 0,
                                                   ._error      = 0};
    np_serializer_read_map(context, &header_deserializer, msg->header);

    if (header_deserializer._error == 0) {
      msg->header->attr.immutable = false;

      // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "deserializing msg
      // instructions");
      size_t remaining_bytes = msg_chunk_size - header_deserializer._bytes_read;
      np_deserialize_buffer_t instruction_deserializer = {
          ._target_tree = msg->instructions,
          ._buffer      = &buffer[header_deserializer._bytes_read],
          ._buffer_size = remaining_bytes,
          ._bytes_read  = 0,
          ._error       = 0,
      };
      np_serializer_read_map(context,
                             &instruction_deserializer,
                             msg->instructions);

      if (instruction_deserializer._error == 0) {

        msg->instructions->attr.immutable = false;
        // TODO: check if the complete buffer was read (byte count match)
        np_tree_elem_t *_parts =
            np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS);
        if (NULL != _parts) {
          msg->no_of_chunks = _parts->val.value.a2_ui[0];
          msg->no_of_chunk  = _parts->val.value.a2_ui[1];
        } else {
          log_debug_msg(
              LOG_MESSAGE | LOG_DEBUG,
              "_NP_MSG_INST_PARTS not available in msgs instruction tree");
        }
        msg->is_single_part = true;

        if (_parts == NULL || 0 == msg->no_of_chunks ||
            msg->no_of_chunk > msg->no_of_chunks) {
          log_msg(LOG_WARNING,
                  "no parts indicator (%p), no_of_chunks (%" PRIu16
                  ") or no_of_chunk (%" PRIu16
                  ") zero while deserializing message.",
                  _parts,
                  msg->no_of_chunks,
                  msg->no_of_chunk);
        } else {

          np_messagepart_ptr part;
          np_new_obj(np_messagepart_t, part);

          part->header       = msg->header;
          part->instructions = msg->instructions;
          part->part         = msg->no_of_chunk;
          part->msg_part     = buffer;

          bool msgpart_added = false;
          np_ref_obj(np_messagepart_t, part, ref_message_messagepart);

          TSP_SCOPE(msg->msg_chunks) {
            // insert new
            msgpart_added = pll_insert(np_messagepart_ptr,
                                       msg->msg_chunks,
                                       part,
                                       false,
                                       _np_messagepart_cmp);
          }

          if (!msgpart_added) {
            np_unref_obj(np_messagepart_t, part, ref_message_messagepart);
            // new entry is rejected (already present)
            log_warn(LOG_MESSAGE,
                     "Msg part was rejected in "
                     "_np_message_deserialize_header_and_instructions");
          }

          if (msg->bin_static != NULL) {
            np_unref_obj(np_messagepart_t,
                         msg->bin_static,
                         ref_message_bin_static);
          }
          ref_replace_reason(np_messagepart_t,
                             part,
                             ref_obj_creation,
                             ref_message_bin_static);
          np_ref_obj(BLOB_984_RANDOMIZED, part->msg_part, ref_obj_creation);

          msg->bin_static = part;

          CHECK_STR_FIELD(msg->instructions, _NP_MSG_INST_UUID, msg_uuid);
          ASSERT(msg_uuid.type == np_treeval_type_char_ptr,
                 " type is incorrectly set to: %" PRIu8,
                 msg_uuid.type);
          log_trace(LOG_MESSAGE,
                    "(msg:%s) reset uuid to %s",
                    msg->uuid,
                    np_treeval_to_str(msg_uuid, NULL));
          char *old = msg->uuid;
          msg->uuid = strdup(np_treeval_to_str(msg_uuid, NULL));
          free(old);

          log_debug(LOG_MESSAGE,
                    "(msg:%s) received message part: %d / %d",
                    msg->uuid,
                    msg->no_of_chunk,
                    msg->no_of_chunks);

          ret = true;
          goto __np_wo_error;

        __np_cleanup__:
          log_error("Message did not contain a UUID");

        __np_wo_error:;
        }
      }
    }
    // }
    // }
  }
  return ret;
}

bool _np_message_deserialize_chunked(np_message_t *msg) {
  np_ctx_memory(msg);
  bool ret = true;

  if (msg->bin_body != NULL) {
    free(msg->bin_body);
    msg->bin_body = NULL;
  }

  // void    *bin_body_ptr = NULL;
  uint32_t size_body = 0;

  if (msg->bin_static == NULL) {
    np_messagepart_ptr part = NULL;
    TSP_SCOPE(msg->msg_chunks) { part = pll_first(msg->msg_chunks)->val; }
    if (part) {
      ret =
          _np_message_deserialize_header_and_instructions(msg, part->msg_part);
    } else {
      ret = false;
    }
  }

  TSP_SCOPE(msg->msg_chunks) {
    pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
    np_messagepart_ptr current_chunk      = NULL;

    while (ret && NULL != iter) {
      current_chunk = iter->val;
      log_debug_msg(LOG_MESSAGE,
                    "(msg:%s) now working on msg part %d",
                    msg->uuid,
                    current_chunk->part);

      size_t header_size = np_tree_get_byte_size(msg->header);
      // np_serializer_add_map_bytesize(msg->header, &header_size);
      size_t instructions_size = np_tree_get_byte_size(msg->instructions);
      // np_serializer_add_map_bytesize(msg->instructions,
      // &instructions_size);
      uint16_t size_body_add = msg_chunk_size - header_size - instructions_size;

      log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
                    "(msg:%s) adding body part size %u",
                    msg->uuid,
                    size_body_add);

      msg->bin_body = realloc(msg->bin_body, size_body + size_body_add);
      // uint16_t start_pos_in_msg_part = MSG_CHUNK_SIZE_1024 -
      // MSG_ENCRYPTION_BYTES_40 - size_body_add;
      memcpy(msg->bin_body + size_body,
             current_chunk->msg_part + header_size + instructions_size,
             size_body_add);

      size_body += size_body_add;
      iter->val = NULL;
      np_unref_obj(np_messagepart_t, current_chunk, ref_message_messagepart);
      pll_next(iter);
    }

    log_debug_msg(LOG_MESSAGE,
                  "(msg:%s) combined all %" PRIu32 " chunks",
                  msg->uuid,
                  msg->no_of_chunks);

    if (ret && NULL != msg->bin_body) {
      log_debug_msg(LOG_MESSAGE,
                    "(msg:%s) deserializing msg body %u",
                    msg->uuid,
                    size_body);
      np_deserialize_buffer_t body_deserializer = {._target_tree = msg->body,
                                                   ._buffer = msg->bin_body,
                                                   ._buffer_size = size_body,
                                                   ._bytes_read  = 0,
                                                   ._error       = 0};
      np_serializer_read_map(context, &body_deserializer, msg->body);

      if (body_deserializer._error != 0) {
        ret = false;
      }
      // TODO: check if the complete buffer was read (byte count match)

      log_debug_msg(LOG_MESSAGE,
                    "(msg:%s) deserializing msg footer %u",
                    msg->uuid,
                    size_body - body_deserializer._bytes_read);

      size_t footer_start  = body_deserializer._bytes_read;
      size_t footer_length = size_body - footer_start;

      np_deserialize_buffer_t footer_deserializer = {
          ._target_tree = msg->footer,
          ._buffer      = &msg->bin_body[footer_start],
          ._buffer_size = footer_length,
          ._bytes_read  = 0,
          ._error       = 0};
      np_serializer_read_map(context, &footer_deserializer, msg->footer);

      if (footer_deserializer._error != 0) {
        ret = false;
      }
      // TODO: check if the complete buffer was read (byte count match)
    }

    // cleanup of msgparts
    if (ret && pll_size(msg->msg_chunks) > 0) {
      pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
      while (NULL != iter) {
        np_unref_obj(np_messagepart_t, iter->val, ref_message_messagepart);
        pll_next(iter);
      }
      pll_clear(np_messagepart_ptr, msg->msg_chunks);
    }
  }

  /*
  #ifdef DEBUG
      uint16_t fixed_size =
              MSG_ARRAY_SIZE + MSG_ENCRYPTION_BYTES_40 + MSG_PAYLOADBIN_SIZE +
              msg->header->byte_size + msg->instructions->byte_size;
      uint16_t payload_size = msg->properties->byte_size
              + bin_body_size + footer;

      log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "msg (%s) Size of msg
  %"PRIu16" bytes. Size of fixed_size %"PRIu16" bytes. Nr of chunks  %"PRIu16"
  parts", msg->uuid, payload_size, fixed_size, msg->no_of_chunks); #endif
  */
  np_tree_del_str(msg->footer, NP_MSG_FOOTER_GARBAGE);
  msg->is_single_part = false;

  // log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
  // "-----------------------------------------------------" );

  return (ret);
}

/**
 ** message_create:
 ** creates the message to the destination #dest# the message format would be
 *like:
 **  [ type ] [ size ] [ key ] [ data ]. It return the created message
 *structure.
 */
void _np_message_create(np_message_t *msg,
                        np_dhkey_t    to,
                        np_dhkey_t    from,
                        np_dhkey_t    subject,
                        np_tree_t    *the_data) {
  np_ctx_memory(msg);
  // np_message_t* new_msg;
  // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "message ptr: %p %s", msg, subject);

  // in the future: header
  np_tree_insert_str(msg->header,
                     _NP_MSG_HEADER_SUBJECT,
                     np_treeval_new_dhkey(subject));
  np_tree_insert_str(msg->header, _NP_MSG_HEADER_TO, np_treeval_new_dhkey(to));
  np_tree_insert_str(msg->header,
                     _NP_MSG_HEADER_FROM,
                     np_treeval_new_dhkey(from));
  // insert a uuid if not yet present
  np_tree_insert_str(msg->instructions,
                     _NP_MSG_INST_UUID,
                     np_treeval_new_s(msg->uuid));

  // derived message data from the msgproperty
  np_msgproperty_conf_t *out_prop =
      _np_msgproperty_conf_get(context, OUTBOUND, subject);

  // insert timestamp and time-to-live
  double now = np_time_now();
  np_tree_insert_str(msg->instructions,
                     _NP_MSG_INST_TSTAMP,
                     np_treeval_new_d(now));
  if (out_prop != NULL)
    np_tree_insert_str(msg->instructions,
                       _NP_MSG_INST_TTL,
                       np_treeval_new_d(out_prop->msg_ttl));
  else
    np_tree_insert_str(msg->instructions,
                       _NP_MSG_INST_TTL,
                       np_treeval_new_d(5.0));
  msg->redelivery_at = msg->send_at = now;

  // insert msg acknowledgement indicator
  if (out_prop != NULL)
    np_tree_insert_str(msg->instructions,
                       _NP_MSG_INST_ACK,
                       np_treeval_new_ush(out_prop->ack_mode));
  else
    np_tree_insert_str(msg->instructions,
                       _NP_MSG_INST_ACK,
                       np_treeval_new_ush(ACK_NONE));

  // insert message chunking placeholder
  np_tree_insert_str(msg->instructions,
                     _NP_MSG_INST_PARTS,
                     np_treeval_new_iarray(1, 1));

  // in the future: instructions
  // set re-send count to zero if not yet present
  np_tree_insert_str(msg->instructions,
                     _NP_MSG_INST_SEND_COUNTER,
                     np_treeval_new_ush(0));
  // placeholder for incrementing sequence counter
  np_tree_insert_str(msg->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(0));

  if (the_data != NULL) {
    _np_message_setbody(msg, the_data);
  }
  _np_message_trace_info("MSG_CREATE", msg);
}

inline void _np_message_setinstructions(np_message_t *msg,
                                        np_tree_t    *instructions) {
  np_tree_free(msg->instructions);
  msg->instructions = instructions;
};

inline void _np_message_setbody(np_message_t *msg, np_tree_t *body) {
  // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "now setting body before %p",
  // msg->body);
  if (msg->body != NULL) np_tree_free(msg->body);
  msg->body = body;
  // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "now setting body after %p",
  // msg->body);
};

inline void _np_message_setfooter(np_message_t *msg, np_tree_t *footer) {
  np_tree_t *old = msg->footer;
  msg->footer    = footer;
  np_tree_free(old);
};

bool np_message_clone(np_message_t *copy_of_message, np_message_t *message) {
  copy_of_message->send_at        = message->send_at;
  copy_of_message->is_single_part = message->is_single_part;
  copy_of_message->no_of_chunks   = message->no_of_chunks;
  memcpy(copy_of_message->uuid, message->uuid, NP_UUID_BYTES);

  np_tree_free(copy_of_message->header);
  copy_of_message->header = np_tree_clone(message->header);
  np_tree_free(copy_of_message->instructions);
  copy_of_message->instructions = np_tree_clone(message->instructions);
  np_tree_free(copy_of_message->body);
  copy_of_message->body = np_tree_clone(message->body);
  np_tree_free(copy_of_message->footer);
  copy_of_message->footer = np_tree_clone(message->footer);

  return true;
}

void _np_message_encrypt_payload(np_message_t        *msg,
                                 np_crypto_session_t *crypto_session) {
  np_ctx_memory(msg);

  // first encrypt the relevant message part itself
  // unsigned char nonce[crypto_aead_xchacha20poly1305_IETF_NPUBBYTES];
  // randombytes_buf((void *)nonce,
  // crypto_aead_xchacha20poly1305_IETF_NPUBBYTES);
  unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
  randombytes_buf((void *)nonce, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);

  _np_messagepart_encrypt(context, msg->body, nonce, crypto_session);

  // add encryption details to the message
  np_tree_insert_str(
      msg->body,
      NP_NONCE,
      np_treeval_new_bin(nonce, crypto_aead_chacha20poly1305_IETF_NPUBBYTES));
}

bool _np_message_decrypt_payload(np_message_t        *msg,
                                 np_crypto_session_t *crypto_session) {
  np_ctx_memory(msg);
  bool ret = false;

  CHECK_STR_FIELD(msg->body, NP_NONCE, msg_nonce);
  // insert the public-key encrypted encryption key for each receiver of the
  // message

  NP_PERFORMANCE_POINT_START(message_decrypt);

  np_tree_t *decrypted_body = np_tree_create();
  if (false == _np_messagepart_decrypt(context,
                                       msg->body,
                                       msg_nonce.value.bin,
                                       crypto_session,
                                       decrypted_body)) {
    np_tree_free(decrypted_body);
    log_msg(LOG_ERROR, "decryption of message payloads body failed");
  } else {
    np_tree_t *old = msg->body;
    msg->body      = decrypted_body;
    np_tree_free(old);
    ret = true;
  }
  NP_PERFORMANCE_POINT_END(message_decrypt);

__np_cleanup__ : {}

  return (ret);
}

np_dhkey_t *_np_message_get_subject(const np_message_t *const self) {
  // np_ctx_memory(msg);
  np_dhkey_t *ret = NULL;
  // if (self->msg_property != NULL) {
  //     ret = self->msg_property->msg_subject;
  // }
  if (self->header != NULL) {
    np_tree_elem_t *ele =
        np_tree_find_str(self->header, _NP_MSG_HEADER_SUBJECT);
    if (ele != NULL) {
      ret = &ele->val.value.dhkey;
    }
  }
  return ret;
}

void _np_message_add_response_handler(
    const np_message_t   *self,
    const np_util_event_t event,
    bool                  use_destination_from_header_to_field) {
  np_ctx_memory(self);

  np_responsecontainer_t *rh = NULL;
  np_new_obj(np_responsecontainer_t, rh, FUNC);

  // TODO: more efficient, please ...
  memcpy(rh->uuid, self->uuid, NP_UUID_BYTES);
  if (use_destination_from_header_to_field) {
    rh->dest_dhkey =
        np_tree_find_str(self->header, _NP_MSG_HEADER_TO)->val.value.dhkey;
  } else {
    rh->msg_dhkey = _np_msgproperty_tweaked_dhkey(
        OUTBOUND,
        np_tree_find_str(self->header, _NP_MSG_HEADER_SUBJECT)
            ->val.value.dhkey);
  }
  rh->send_at =
      np_tree_find_str(self->instructions, _NP_MSG_INST_TSTAMP)->val.value.d;
  rh->expires_at =
      rh->send_at +
      np_tree_find_str(self->instructions, _NP_MSG_INST_TTL)->val.value.d;
  rh->received_at = 0.0;

  np_dhkey_t      ack_dhkey = _np_msgproperty_dhkey(INBOUND, _NP_MSG_ACK);
  np_util_event_t rh_event  = {.user_data    = rh,
                               .target_dhkey = ack_dhkey,
                               .type         = (evt_internal | evt_response)};
  _np_event_runtime_add_event(context, event.current_run, ack_dhkey, rh_event);
}

np_dhkey_t *_np_message_get_sessionid(const np_message_t *const self) {
  np_ctx_memory(self);

  ASSERT(self != NULL, "Cannot operate on not initialised message");
  ASSERT(self->header != NULL,
         "Cannot operate on not initialised message %s",
         self->uuid);

  np_dhkey_t     *ret = NULL;
  np_tree_elem_t *ele = np_tree_find_str(self->header, _NP_MSG_HEADER_TO);
  if (ele != NULL) {
    ret = &ele->val.value.dhkey;
  }
  return ret;
}

np_dhkey_t _np_message_get_sender(const np_message_t *const self) {
  np_ctx_memory(self);

  ASSERT(self != NULL, "Cannot operate on not initialised message");
  ASSERT(self->header != NULL,
         "Cannot operate on not initialised message %s",
         self->uuid);

  np_dhkey_t      ret = {0};
  np_tree_elem_t *ele = np_tree_find_str(self->header, _NP_MSG_HEADER_FROM);
  if (ele != NULL) {
    return ele->val.value.dhkey;
  }
  return ret;
}

void _np_message_trace_info(char *desc, np_message_t *msg_in) {
#ifdef TRACE
  np_ctx_memory(msg_in);
  char *info_str = NULL;
  info_str       = np_str_concatAndFree(info_str, "MessageTrace_%s", desc);

  bool  free_key, free_value;
  char *key, *value;
  info_str = np_str_concatAndFree(info_str, " Header (");
  np_tree_elem_t *tmp;
  if (msg_in->header != NULL) {
    RB_FOREACH (tmp, np_tree_s, (msg_in->header)) {
      key = np_treeval_to_str(tmp->key, &free_key);
      if (strcmp(key, _NP_MSG_HEADER_SUBJECT) == 0) {
        free_value = true;
        value      = malloc(100);
        np_regenerate_subject(context, value, 100, &tmp->val.value.dhkey);
      } else {
        value = np_treeval_to_str(tmp->val, &free_value);
      }
      info_str = np_str_concatAndFree(info_str, "%s:%s |", key, value);

      if (free_value) free(value);
      if (free_key) free(key);
    }
  }
  info_str = np_str_concatAndFree(info_str, ") Instructions (");
  if (msg_in->instructions != NULL) {
    RB_FOREACH (tmp, np_tree_s, (msg_in->instructions)) {
      key      = np_treeval_to_str(tmp->key, &free_key);
      value    = np_treeval_to_str(tmp->val, &free_value);
      info_str = np_str_concatAndFree(info_str, "%s:%s |", key, value);
      if (free_value) free(value);
      if (free_key) free(key);
    }
  }
  info_str = np_str_concatAndFree(info_str, ")");

  log_trace_msg(LOG_MESSAGE, info_str);
  free(info_str);
#endif
}

bool _np_message_is_internal(np_state_t *context, np_message_t *msg) {
  bool            ret = false;
  np_tree_elem_t *_subject_ele =
      np_tree_find_str(msg->header, _NP_MSG_HEADER_SUBJECT);

  if (_subject_ele != NULL) {
    np_dhkey_t             subject = _subject_ele->val.value.dhkey;
    np_msgproperty_conf_t *property =
        _np_msgproperty_conf_get(context, DEFAULT_MODE, subject);
    if (property != NULL) {
      ret = property->is_internal;
    }
  }

  return ret;
}
