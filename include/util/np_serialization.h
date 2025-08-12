//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_SERIALIZATION_H_
#define _NP_SERIALIZATION_H_

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "neuropil_data.h"

#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_settings.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief serialization of a generic tree structure into a binary document
 *
 */
enum np_serialization_error {
  SERIALIZE_OK = 0,
  TARGET_BUFFER_TOO_SMALL,
  ELEMENT_COUNT_MISMATCH,
};

struct np_serialize_buffer_s {
  const np_tree_t *_tree;
  void            *_target_buffer;
  size_t           _buffer_size;
  uint8_t          _error;
  size_t           _bytes_written;
} NP_API_INTERN;
typedef struct np_serialize_buffer_s np_serialize_buffer_t;

struct np_deserialize_buffer_s {
  np_tree_t   *_target_tree;
  const void  *_buffer;
  const size_t _buffer_size;
  uint8_t      _error;
  size_t       _bytes_read;
} NP_API_INTERN;
typedef struct np_deserialize_buffer_s np_deserialize_buffer_t;

NP_API_INTERN
void np_serializer_add_map_bytesize(np_tree_t *tree, size_t *byte_size);
NP_API_INTERN
void np_serializer_write_map(np_state_t            *context,
                             np_serialize_buffer_t *buffer,
                             const np_tree_t       *tree);
NP_API_INTERN
void np_serializer_read_map(np_state_t              *context,
                            np_deserialize_buffer_t *buffer,
                            np_tree_t               *tree);

/**
 * @brief (de-) serialization of a datablock (attributes) into a document
 *
 */
struct np_kv_buffer_s {
  unsigned char *buffer_start; // needs to be the first element
  unsigned char *buffer_end;

  char              key[255];
  enum np_data_type data_type;
  size_t            data_size;
  np_data_value     data;

} NP_API_INTERN;
typedef struct np_kv_buffer_s np_kv_buffer_t;

struct np_datablock_header_s {
  unsigned char *_inner_blob; // has to be first element
  size_t         total_length;
  size_t         used_length;
  uint32_t       object_count;
};
typedef struct np_datablock_header_s np_datablock_header_t;

NP_API_INTERN
enum np_data_return np_serializer_write_object(np_kv_buffer_t *to_write);

NP_API_INTERN
enum np_data_return np_serializer_read_object(np_kv_buffer_t *to_read);

NP_API_INTERN
enum np_data_return np_serializer_calculate_object_size(np_kv_buffer_t kv_pair,
                                                        size_t *object_size);

NP_API_INTERN
enum np_data_return np_serializer_search_object(np_datablock_header_t *block,
                                                char                  *key,
                                                np_kv_buffer_t        *kv_pair,
                                                uint32_t data_magic_no);

NP_API_INTERN
unsigned char *np_skip_datablock_header(np_datablock_header_t *block);

NP_API_INTERN
enum np_data_return
np_serializer_read_datablock_header(np_datablock_header_t *block,
                                    uint32_t               struct_magic_no);

NP_API_INTERN
enum np_data_return
np_serializer_write_datablock_header(np_datablock_header_t *block,
                                     uint32_t               struct_magic_no);

/**
 * @brief (de-) serialization of np_token into a cwt token in binary format
 *
 * @param data
 * @param token
 */
NP_API_INTERN
bool np_serializer_write_nptoken(const struct np_token *token,
                                 void                  *buffer,
                                 size_t                *buffer_length);

NP_API_INTERN
bool np_serializer_read_nptoken(const void      *buffer,
                                size_t          *buffer_length,
                                struct np_token *token);

NP_API_INTERN
bool np_serializer_write_ed25519(
    const unsigned char *sk_value[NP_SECRET_KEY_BYTES],
    const unsigned char *pk_value[NP_PUBLIC_KEY_BYTES],
    bool                 include_secret_key,
    np_id               *identifier,
    void                *buffer,
    size_t              *buffer_length);

NP_API_INTERN
bool np_serializer_read_ed25519(const void    *buffer,
                                size_t        *buffer_length,
                                np_id         *identifier,
                                unsigned char *sk_value[NP_SECRET_KEY_BYTES],
                                unsigned char *pk_value[NP_PUBLIC_KEY_BYTES]);

bool np_serializer_write_encrypted(void                *crypted_buffer,
                                   size_t              *cb_length,
                                   const unsigned char *nonce,
                                   const unsigned char *input_buffer,
                                   size_t               ib_len);

bool np_serializer_read_encrypted(const void    *input_buffer,
                                  size_t        *ib_length,
                                  unsigned char *nonce,
                                  unsigned char *crypted_buffer,
                                  size_t        *cb_len);

#if (defined(DEBUG) && defined(NP_USE_CMP))

#include "msgpack/cmp.h"

// only for debug puposes, test cases need access to these functions
bool __np_buffer_reader(struct cmp_ctx_s *ctx, void *data, size_t limit);
size_t
     __np_buffer_writer(struct cmp_ctx_s *ctx, const void *data, size_t count);
void __np_tree_deserialize_read_type(np_state_t     *context,
                                     np_tree_t      *tree,
                                     cmp_object_t   *obj,
                                     cmp_ctx_t      *cmp,
                                     np_treeval_t   *value,
                                     NP_UNUSED char *key_to_read_for);
void __np_tree_serialize_write_type(np_state_t  *context,
                                    np_treeval_t val,
                                    cmp_ctx_t   *cmp);
#endif

#if (defined(DEBUG) && defined(NP_USE_QCBOR))

#include "qcbor/UsefulBuf.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"

void __np_tree_deserialize_read_type(np_state_t         *context,
                                     np_tree_t          *tree,
                                     QCBORDecodeContext *qcbor_ctx,
                                     np_treeval_t       *value,
                                     NP_UNUSED char     *key_to_read_for);

void __np_tree_serialize_write_type(np_state_t         *context,
                                    np_treeval_t        val,
                                    QCBOREncodeContext *qcbor_ctx);
#endif

#ifdef __cplusplus
}
#endif

#endif // _NP_SERIALIZATION_H_
