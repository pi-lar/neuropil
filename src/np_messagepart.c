//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "inttypes.h"
#include "sodium.h"
#include "tree/tree.h"

#include "neuropil_log.h"

#include "core/np_comp_msgproperty.h"
#include "util/np_serialization.h"
#include "util/np_tree.h"

#include "np_crypto.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_types.h"
#include "np_util.h"

NP_PLL_GENERATE_IMPLEMENTATION(np_messagepart_ptr);

int8_t _np_messagepart_cmp(const np_messagepart_ptr value1,
                           const np_messagepart_ptr value2) {
  uint16_t part_1 = value1->part; // np_tree_find_str(value1->instructions,
                                  // NP_MSG_INST_PARTS)->val.value.a2_ui[1];
  uint16_t part_2 = value2->part; // np_tree_find_str(value2->instructions,
                                  // NP_MSG_INST_PARTS)->val.value.a2_ui[1];

  np_ctx_memory(value1);
  log_debug(LOG_MESSAGE | LOG_VERBOSE,
            "message part compare %d / %d / %d",
            part_1,
            part_2,
            part_1 - part_2);

  if (part_2 > part_1) return (1);
  if (part_1 > part_2) return (-1);
  return (0);
}

bool _np_messagepart_decrypt(np_state_t          *context,
                             np_tree_t           *source,
                             unsigned char       *enc_nonce,
                             np_crypto_session_t *session,
                             np_tree_t           *target) {
  log_trace_msg(
      LOG_TRACE | LOG_MESSAGE,
      "start: bool _np_messagepart_decrypt(context, np_tree_t* msg_part");

  np_tree_elem_t *enc_msg_part = np_tree_find_str(source, NP_ENCRYPTED);
  if (NULL == enc_msg_part) {
    log_msg(LOG_ERROR, "couldn't find encrypted msg part");
    return (false);
  }
  uint32_t decrypted_size =
      enc_msg_part->val.size - crypto_aead_chacha20poly1305_IETF_ABYTES;
  unsigned char dec_part[decrypted_size];

  int ret = np_crypto_session_decrypt(
      context,
      session,
      &enc_msg_part->val.value.bin[crypto_aead_chacha20poly1305_IETF_ABYTES],
      decrypted_size,
      &enc_msg_part->val.value.bin[0],
      crypto_aead_chacha20poly1305_IETF_ABYTES,
      dec_part,
      decrypted_size,
      NULL,
      0,
      enc_nonce);
  if (ret < 0) {
    log_debug_msg(LOG_ERROR, "couldn't decrypt msg part with session key");
    return (false);
  }

  // Allow deserialisation as the encryption may
  np_deserialize_buffer_t deserializer = {._target_tree = target,
                                          ._buffer      = dec_part,
                                          ._buffer_size = decrypted_size,
                                          ._bytes_read  = 0,
                                          ._error       = 0};
  np_serializer_read_map(context, &deserializer, target);

  // check if the complete buffer was read (byte count match)
  if (deserializer._error != 0) {
    log_debug_msg(LOG_ERROR, "couldn't deserialize msg part after decryption");
    return false;
  }

  return (true);
}

bool _np_messagepart_encrypt(np_state_t          *context,
                             np_tree_t           *msg_part,
                             unsigned char       *nonce,
                             np_crypto_session_t *session) {
  log_trace_msg(LOG_TRACE | LOG_MESSAGE,
                "start: bool _np_messagepart_encrypt(context, np_tree_t* ");

  size_t msg_part_size = np_tree_get_byte_size(msg_part);
  unsigned char
      buffer[msg_part_size + crypto_aead_chacha20poly1305_IETF_ABYTES];
  np_serialize_buffer_t serializer = {._tree          = msg_part,
                                      ._target_buffer = &buffer,
                                      ._buffer_size   = msg_part_size,
                                      ._bytes_written = 0,
                                      ._error         = 0};
  np_serializer_write_map(context, &serializer, msg_part);
  if (serializer._error != 0) {
    log_msg(LOG_ERROR, "couldn't serialize msg part before encryption");
    return false;
  }
  unsigned char
      enc_msg_part[msg_part_size + crypto_aead_chacha20poly1305_IETF_ABYTES];

  int ret = np_crypto_session_encrypt(
      context,
      session,
      &enc_msg_part[crypto_aead_chacha20poly1305_IETF_ABYTES],
      serializer._bytes_written,
      &enc_msg_part[0],
      crypto_aead_chacha20poly1305_IETF_ABYTES,
      buffer,
      msg_part_size,
      NULL,
      0,
      nonce);
  if (ret < 0) {
    return (false);
  }

  _np_tree_replace_all_with_str(
      msg_part,
      NP_ENCRYPTED,
      np_treeval_new_bin(enc_msg_part,
                         msg_part_size +
                             crypto_aead_chacha20poly1305_IETF_ABYTES));

  return (true);
}

void _np_messagepart_t_del(np_state_t       *context,
                           NP_UNUSED uint8_t type,
                           NP_UNUSED size_t  size,
                           void             *nw) {
  log_trace_msg(LOG_TRACE | LOG_MESSAGE,
                "start: void _np_messagepart_t_del(void* nw){");

  np_messagepart_t *part = (np_messagepart_t *)nw;

  if (part->msg_part != NULL) {
    np_unref_obj(BLOB_1024, part->msg_part, ref_obj_creation);
  }

  _np_threads_mutex_destroy(context, &part->work_lock);
}

void _np_messagepart_t_new(np_state_t       *context,
                           NP_UNUSED uint8_t type,
                           NP_UNUSED size_t  size,
                           void             *nw) {
  log_trace_msg(LOG_TRACE | LOG_MESSAGE,
                "start: void _np_messagepart_t_new(void* nw){");
  np_messagepart_t *part = (np_messagepart_t *)nw;

  memset(part->uuid, 0, NP_UUID_BYTES);
  part->msg_part = NULL;
  _np_threads_mutex_init(context, &part->work_lock, "urn:np:msgpart:worklock");
}

char *np_messagepart_printcache(np_state_t *context, bool asOneLine) {
  char *ret      = NULL;
  char *new_line = "\n";
  if (asOneLine == true) {
    new_line = "    ";
  }

  ret = np_str_concatAndFree(ret,
                             "--- Messagepart cache (%" PRIu16 ") ---%s",
                             context->msg_part_cache->size,
                             new_line);
  _LOCK_MODULE(np_message_part_cache_t) {
    np_tree_elem_t *tmp = NULL;

    RB_FOREACH (tmp, np_tree_s, context->msg_part_cache) {
      np_message_t *msg = tmp->val.value.v;

      ret = np_str_concatAndFree(ret,
                                 "%s   received %2" PRIu32 " of %2" PRIu16
                                 " expected parts. msg subject:%s%s",
                                 msg->uuid,
                                 pll_size(msg->msg_chunks),
                                 msg->no_of_chunks,
                                 _np_message_get_subject(msg),
                                 new_line);
    }
  }
  ret = np_str_concatAndFree(ret, "--- Messagepart cache end ---%s", new_line);

  return (ret);
}

void _np_messagepart_trace_info(char *desc, np_messagepart_t *msg_in) {

  np_ctx_memory(msg_in);
  char *info_str = NULL;
  info_str       = np_str_concatAndFree(info_str, "MessagePartTrace_%s", desc);

#ifdef DEBUG
  bool  free_key, free_value;
  char *key, *value;
  info_str = np_str_concatAndFree(info_str, " Header (");
  np_tree_elem_t *tmp;
  if (msg_in->header != NULL) {
    RB_FOREACH (tmp, np_tree_s, (msg_in->header)) {
      key      = np_treeval_to_str(tmp->key, &free_key);
      value    = np_treeval_to_str(tmp->val, &free_value);
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
#else
  info_str = np_str_concatAndFree(info_str,
                                  ": %s / %" PRIu16,
                                  msg_in->uuid,
                                  msg_in->part);
#endif

  log_debug(LOG_MESSAGE, "%s", info_str);
  free(info_str);
}
