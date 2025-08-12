//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "util/np_cupidbloom.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "np_memory.h"

#define __count_bits(t)                                                        \
  __builtin_popcount(t->_as_ul[0]) + __builtin_popcount(t->_as_ul[1]) +        \
      __builtin_popcount(t->_as_ul[2]) + __builtin_popcount(t->_as_ul[3]) +    \
      __builtin_popcount(t->_as_ul[4]) + __builtin_popcount(t->_as_ul[5]) +    \
      __builtin_popcount(t->_as_ul[6]) + __builtin_popcount(t->_as_ul[7])

#define __calc_table_position(y)                                               \
  _l_index  = y & 0x000000FF;                                                  \
  _lb_index = _l_index >> 5;                                                   \
  _l_index &= 0x0000001F;

#define __merge_data_block(op, t, l, r)                                        \
  t->_as_ul[0] = l->_as_ul[0] op r->_as_ul[0];                                 \
  t->_as_ul[1] = l->_as_ul[1] op r->_as_ul[1];                                 \
  t->_as_ul[2] = l->_as_ul[2] op r->_as_ul[2];                                 \
  t->_as_ul[3] = l->_as_ul[3] op r->_as_ul[3];                                 \
  t->_as_ul[4] = l->_as_ul[4] op r->_as_ul[4];                                 \
  t->_as_ul[5] = l->_as_ul[5] op r->_as_ul[5];                                 \
  t->_as_ul[6] = l->_as_ul[6] op r->_as_ul[6];                                 \
  t->_as_ul[7] = l->_as_ul[7] op r->_as_ul[7];

static inline enum np_return _not_implemented() { return np_not_implemented; }

static inline void _addto_data_block(union np_hkey *data_block,
                                     const uint32_t data_1) {
  uint32_t _l_index  = 0;
  uint8_t  _lb_index = 0;
  __calc_table_position(data_1);
  data_block->_as_ul[_lb_index] |= (1ul << _l_index);
};

bool _check_data_block(const union np_hkey *data_block, const uint32_t data_1) {
  union np_hkey tmp       = {0};
  uint32_t      _l_index  = 0;
  uint8_t       _lb_index = 0;

  __calc_table_position(data_1);
  tmp._as_ul[_lb_index] = data_block->_as_ul[_lb_index] & (1ul << _l_index);

  return (__count_bits((&tmp)) != 0) ? np_ok : np_operation_failed;
}

enum np_return np_cupidbloom_free(struct np_cupidbloom *bloom) {
  return np_cupidtrie_free(&bloom->storage);
}

enum np_return np_cupidbloom_clear(struct np_cupidbloom *bloom) {
  return np_cupidtrie_free(&bloom->storage);
}

enum np_return np_cupidbloom_add(struct np_cupidbloom *bloom,
                                 union np_hkey        *s) {

  enum np_return ret    = np_ok;
  uintptr_t     *target = NULL;

  for (uint8_t i = 0; i < 8 && ret == np_ok; i++) {

    ret = np_cupidtrie_insert(&bloom->storage, &s->_as_us[i << 2], &target);
    union np_hkey *_hkey = (union np_hkey *)*target;
    if (_hkey == NULL) {
      _hkey = calloc(1, sizeof(union np_hkey));
      if (_hkey == NULL) return np_out_of_memory;
      *target = (uintptr_t)_hkey;
    }
    uint32_t tmp = s->_as_ul[i] >> 8; // divide by 256
    _addto_data_block(_hkey,
                      s->_as_ul[i] / tmp); // divide by block position
  }
  return (ret);
}

enum np_return np_cupidbloom_remove(struct np_cupidbloom *bloom,
                                    union np_hkey         id) {
  return np_not_implemented;
}

enum np_return np_cupidbloom_check(struct np_cupidbloom *bloom,
                                   union np_hkey        *s) {
  enum np_return ret    = np_ok;
  uintptr_t     *target = NULL;
  for (uint8_t i = 0; i < 8 && ret == np_ok; i++) {
    ret = np_cupidtrie_find(&bloom->storage, &s->_as_us[i << 2], &target);
    if (np_ok == ret) {
      union np_hkey *_hkey = (union np_hkey *)*target;
      uint32_t       tmp   = s->_as_ul[i] >> 8; // divide by 256
      ret                  = _check_data_block(_hkey, s->_as_ul[i] / tmp);
    }
  };
  return (ret);
}

enum np_return __bf_standard_union(uintptr_t *first, const uintptr_t *other) {
  union np_hkey *_result   = (union np_hkey *)*first;
  union np_hkey *_to_merge = (union np_hkey *)*other;

  if (_result == NULL) {
    _result = calloc(1, sizeof(union np_hkey));
    if (_result == NULL) return np_out_of_memory;
    memcpy(_result, _to_merge, sizeof(union np_hkey));
    *first = (uintptr_t)_result;
    return np_ok;
  }

  __merge_data_block(|, _result, _result, _to_merge);

  if (__count_bits(_result) > 0) return np_ok;
  return np_operation_failed;
}
enum np_return __bf_standard_intersection(uintptr_t       *first,
                                          const uintptr_t *other) {
  union np_hkey *_result   = (union np_hkey *)*first;
  union np_hkey *_to_merge = (union np_hkey *)*other;

  if (_result == NULL) {
    return np_operation_failed;
  }
  __merge_data_block(&, _result, _result, _to_merge);

  if (__count_bits(_result) > 0) return np_ok;
  return np_operation_failed;
}

enum np_return np_cupidbloom_union(struct np_cupidbloom *result,
                                   struct np_cupidbloom *other) {
  return np_cupidtrie_union(&result->storage,
                            &other->storage,
                            __bf_standard_union);
}

enum np_return np_cupidbloom_intersect(struct np_cupidbloom *result,
                                       struct np_cupidbloom *other) {
  return np_cupidtrie_intersect(&result->storage,
                                &other->storage,
                                __bf_standard_intersection);
}

enum np_return np_cupidbloom_decay(struct np_cupidbloom *bloom) {
  return np_not_implemented;
}

enum np_return np_cupidbloom_get_heuristic(struct np_cupidbloom *bloom,
                                           union np_hkey         id,
                                           float                *probability) {
  return np_not_implemented;
}

enum np_return np_cupidbloom_containment(struct np_cupidbloom *first,
                                         struct np_cupidbloom *second,
                                         float                *result) {
  return np_not_implemented;
}

enum np_return np_cupidbloom_similarity(struct np_cupidbloom *first,
                                        struct np_cupidbloom *second,
                                        float                *result) {
  return np_not_implemented;
}

enum np_return np_cupidbloom_serialize(struct np_cupidbloom *filter,
                                       unsigned char       **to,
                                       size_t               *to_size) {
  return np_not_implemented;
}

enum np_return np_cupidbloom_deserialize(struct np_cupidbloom *filter,
                                         unsigned char        *from,
                                         size_t                from_size) {
  return np_not_implemented;
}

enum np_return np_cupidbloom_map_reduce(struct np_cupidbloom   *trie,
                                        struct np_map_reduce_s *mr) {
  return np_not_implemented;
}

enum np_return np_cupidbloom_init(struct np_cupidbloom *bloom) {

  switch (bloom->type) {

  case standard_bf:
  default:
    bloom->storage.key_length = 4;
    bloom->bits_per_block     = 256;
    bloom->max_blocks         = 1 << (4 * bloom->storage.key_length);

    bloom->add                = np_cupidbloom_add;
    bloom->check              = np_cupidbloom_check;
    bloom->build_union        = np_cupidbloom_union;
    bloom->build_intersection = np_cupidbloom_intersect;
    bloom->clear              = np_cupidbloom_clear;
    bloom->free               = np_cupidbloom_free;
    break;
  }
}
