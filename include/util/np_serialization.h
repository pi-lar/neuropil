//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
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

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

enum np_serialization_error {
  SERIALIZE_OK = 0,
  TARGET_BUFFER_TOO_SMALL,
  ELEMENT_COUNT_MISMATCH,
};

struct np_serialize_buffer_s {
  const np_tree_t *_tree;
  void            *_target_buffer;
  size_t          *_buffer_size;
  uint8_t          _error;
  size_t           _bytes_written;
} NP_API_INTERN;
typedef struct np_serialize_buffer_s np_serialize_buffer_t;

struct np_deserialize_buffer_s {
  np_tree_t    *_target_tree;
  const void   *_buffer;
  const size_t *_buffer_size;
  uint8_t       _error;
  size_t        _bytes_read;
} NP_API_INTERN;
typedef struct np_deserialize_buffer_s np_deserialize_buffer_t;

NP_API_INTERN
void np_serializer_write_map(np_state_t            *context,
                             np_serialize_buffer_t *buffer,
                             const np_tree_t       *tree);
NP_API_INTERN
void np_serializer_read_map(np_state_t              *context,
                            np_deserialize_buffer_t *buffer,
                            np_tree_t               *tree);

struct np_kv_buffer_s {
  unsigned char *buffer_start; // needs to be the first element
  unsigned char *buffer_end;

  char              key[255];
  enum np_data_type data_type;
  uint32_t          data_size;
  np_data_value     data;

} NP_API_INTERN;
typedef struct np_kv_buffer_s np_kv_buffer_t;

struct np_datablock_header_s {
  unsigned char *_inner_blob; // has to be first element
  uint32_t       total_length;
  uint32_t       used_length;
  uint32_t       object_count;
};
typedef struct np_datablock_header_s np_datablock_header_t;

NP_API_INTERN
enum np_data_return np_serializer_write_object(np_kv_buffer_t *to_write);

NP_API_INTERN
enum np_data_return np_serializer_read_object(np_kv_buffer_t *to_read);

NP_API_INTERN
enum np_data_return np_serializer_calculate_object_size(np_kv_buffer_t kv_pair,
                                                        uint32_t *object_size);

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

#ifdef DEBUG
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

#ifdef __cplusplus
}
#endif

#endif // _NP_SERIALIZATION_H_
