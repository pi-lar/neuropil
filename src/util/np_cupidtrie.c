//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "util/np_cupidtrie.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "np_memory.h"

struct _qp_branch {
  uint32_t         key;
  uint64_t         key_aux;
  union _qp_union *data;
};

struct _qp_leaf {
  uint32_t  key;
  uint8_t  *key_aux;
  uintptr_t data;
};

union _qp_union {
  struct _qp_branch branch;
  struct _qp_leaf   leaf;
};

#define __use_branch_data(idx) idx.data
#define __use_branch_aux(idx)  idx.key_aux

#define __use_branch_key(idx) (idx.key & 0x0000FFFF)
#define __set_branch_key(idx, new_key)                                         \
  (idx.key = (new_key | (idx.key & 0xFFFF0000)))

#define __use_branch_mask(idx) (idx.key >> 16)
#define __set_branch_mask(idx, mask)                                           \
  (idx.key = (((mask) << 16) | (idx.key & 0x0000FFFF)))

#define __use_leaf_data(idx) idx.data
#define __use_leaf_aux(idx)  idx.key_aux
#define __use_leaf_key(idx)  idx.key

#define __idx_shift(idx_key)  ((idx_key & 0x0000FFFE) >> 1)
#define __idx_branch(idx_key) ((idx_key & 0x00000001) >> 0)

#define __idx_create_branch_key(shift, branch) (shift << 1) | (branch << 0)

enum __knybbles {
  MASK_00 = 0x00000000U,
  MASK_01 = 0x00000001U,
  MASK_02 = 0x00000002U,
  MASK_03 = 0x00000004U,
  MASK_04 = 0x00000008U,
  MASK_05 = 0x00000010U,
  MASK_06 = 0x00000020U,
  MASK_07 = 0x00000040U,
  MASK_08 = 0x00000080U,
  MASK_09 = 0x00000100U,
  MASK_10 = 0x00000200U,
  MASK_11 = 0x00000400U,
  MASK_12 = 0x00000800U,
  MASK_13 = 0x00001000U,
  MASK_14 = 0x00002000U,
  MASK_15 = 0x00004000U,
  MASK_16 = 0x00008000U,
};

static uint32_t __mask_table[16] = {
    MASK_01,
    MASK_02,
    MASK_03,
    MASK_04,
    MASK_05,
    MASK_06,
    MASK_07,
    MASK_08,
    MASK_09,
    MASK_10,
    MASK_11,
    MASK_12,
    MASK_13,
    MASK_14,
    MASK_15,
    MASK_16,
};

// static inline uint16_t __extract_nibble(uint8_t* key, uint16_t shift, size_t
// key_length) {
//     uint8_t key_at_pos = *(key + (shift >> 1));
//     uint8_t nibble_shift = ((shift & 0x01) << 2);
//     uint8_t result = ((key_at_pos << nibble_shift) & 0xF0) >> 4;
//     return result;
// }

#define __extract_nibble(key, shift, length)                                   \
  (((*(key + (shift >> 1)) << ((shift & 0x01) << 2)) & 0xF0) >> 4)

#define __key_bitmask(idx, key, length)                                        \
  __mask_table[__extract_nibble(key,                                           \
                                __idx_shift(__use_branch_key(idx)),            \
                                length)]

#define __idx_has_next(idx, bitmask)                                           \
  (__use_branch_mask(idx) & bitmask) == bitmask

#define __idx_next(obj, bitmask)                                               \
  &((union _qp_union *)obj->branch.data)[__builtin_ctz(bitmask)]

static inline void __qpe_set_leaf_index(union _qp_union *qpe,
                                        const uint8_t   *index,
                                        const size_t     length) {
  qpe->leaf.key     = 0;
  qpe->leaf.key_aux = index;
};

// void __qpe_set_branch_key(union _qp_union *qpe, struct _qp_index key) {
//   qpe->branch.index = key;
// };

void __free_qpe(union _qp_union *qpe) {

  if (qpe == NULL) return;

  if (__idx_branch(__use_branch_key(qpe->branch)) == 1UL) {
    __builtin_prefetch(qpe->branch.data);
    uint32_t bm = __use_branch_mask(qpe->branch);
    while (bm > 0) {
      uint16_t pos = __builtin_ctz(bm);
      __free_qpe(__idx_next(qpe, __mask_table[pos]));
      bm ^= __mask_table[pos];
    }
    free(qpe->branch.data);
  }
}

enum np_return __find_qpe(const union _qp_union *qpe,
                          const uint8_t         *key,
                          const size_t           len,
                          uintptr_t            **out) {
  if (qpe == NULL) return (np_operation_failed);

  while (__idx_branch(__use_branch_key(qpe->branch)) == 1UL) {
    __builtin_prefetch(qpe->branch.data);

    uint32_t bm = __key_bitmask(qpe->branch, key, len);
    if (bm == 0) return (np_operation_failed);

    if (!(__idx_has_next(qpe->branch, bm))) return (np_operation_failed);
    else qpe = __idx_next(qpe, bm);
  }

  if (memcmp(__use_leaf_aux(qpe->leaf), key, len) != 0)
    return (np_operation_failed);

  *out = &__use_leaf_data(qpe->leaf);
  return (np_ok);
}

enum np_return __delete_qpe(union _qp_union *qpe,
                            const uint8_t   *key,
                            const size_t     len,
                            uintptr_t      **out) {
  if (qpe == NULL) return (np_invalid_argument);

  union _qp_union **del_qp_branch = NULL; // branch before the element to delete
  uint32_t          del_bm        = 0;
  uint32_t          del_count     = 0;
  while (__idx_branch(__use_branch_key(qpe->branch)) == 1UL) {
    __builtin_prefetch(qpe->branch.data);

    del_count++;
    del_qp_branch =
        realloc(del_qp_branch, del_count * sizeof(union _qp_union *));

    del_bm = __key_bitmask(qpe->branch, key, len);
    if (del_bm == 0) return (np_operation_failed);

    if (!(__idx_has_next(qpe->branch, del_bm))) return (np_operation_failed);
    else {
      del_qp_branch[del_count - 1] = qpe;
      qpe                          = __idx_next(qpe, del_bm);
    }
  }

  if (memcmp(__use_leaf_aux(qpe->leaf), key, len) != 0)
    return (np_operation_failed);

  *out = &__use_leaf_data(qpe->leaf);

  __set_branch_mask(del_qp_branch[del_count - 1]->branch,
                    __use_branch_mask(del_qp_branch[del_count - 1]->branch) ^
                        del_bm);

  for (uint32_t x = del_count; x > 0; x--) {
    if (__use_branch_mask(del_qp_branch[x - 1]->branch) == 0) {
      __free_qpe(del_qp_branch[x - 1]);
      if (x > 1) {
        del_bm = __key_bitmask(del_qp_branch[x - 2]->branch, key, len);
        __set_branch_mask(del_qp_branch[x - 2]->branch,
                          __use_branch_mask(del_qp_branch[x - 2]->branch) ^
                              del_bm);
      }
    }
  }
  free(del_qp_branch);

  return (np_ok);
}

enum np_return __insert_qpe(union _qp_union **qpe,
                            const uint8_t    *new_key,
                            const size_t      length,
                            uintptr_t       **out) {

  // First leaf in an empty tbl?
  if (*qpe == NULL) {
    *qpe = calloc(1, sizeof(union _qp_union));
    if (*qpe == NULL) return np_out_of_memory;
    __qpe_set_leaf_index(*qpe, new_key, length);
    *out = &__use_leaf_data((*qpe)->leaf);
    return (np_ok);
  }

  struct _qp_branch i             = {0};
  union _qp_union  *new_bb_branch = NULL;
  union _qp_union  *tmp           = *qpe;
  union _qp_union  *ins_bb_branch = tmp;
  // Find the most similar leaf node in the trie. We will compare
  // its key with our new key to find the first differing nibble,
  // which can be at a lower index than the point at which we
  // detect a difference.
  // uint16_t indent = 0;
  bool update_shift = true;
  while (__idx_branch(__use_branch_key(tmp->branch)) == 1UL) {
    __builtin_prefetch(tmp->branch.data);
    uint16_t __x0     = __extract_nibble(new_key,
                                     __idx_shift(__use_branch_key(tmp->branch)),
                                     length);
    uint32_t idx_mask = __mask_table[__x0];
    // Even if our key is missing from this branch we need to
    // keep iterating down to a leaf. It doesn't matter which
    // twig we choose since the keys are all the same up to this
    // index. Note that blindly using twigoff(t, b) can cause
    // an out-of-bounds index if it equals twigmax(t).
    // uint s = hastwig(i, b) ? twigoff(i, b) : 0;
    // tmp    = Tbranch_twigs(qpe) + s;
    uint8_t s = __builtin_ctz(__use_branch_mask(tmp->branch));
    if (update_shift && __idx_has_next(tmp->branch, idx_mask)) {
      s             = __x0;
      ins_bb_branch = tmp;
    } else {
      update_shift = false;
    }
    tmp = &((union _qp_union *)tmp->branch.data)[s];
  }
  // Do the keys differ, and if so, where?
  const uint8_t *tmp_key = (uint8_t *)__use_leaf_aux(tmp->leaf);
  uint32_t xor = 0, pos = 0;
  uint16_t shf_bits = 0;

  do {
    xor = *(new_key + pos) ^ *(tmp_key + pos);
    if (xor > 0) shf_bits += __builtin_clz(xor) - 24;
    else shf_bits += 8;
    pos++;
  } while (xor == 0 && pos < length);

  if (xor == 0) {
    *out = &__use_leaf_data(tmp->leaf);
    return (np_ok);
  }

  uint16_t shf = shf_bits >> 2; // / 4

  // We have the branch's byte index; what is its chunk index?
  // uint16_t bit = (off << 3) + __builtin_clz(xor) + 8 - (sizeof(uint32_t) <<
  // 3); uint16_t qo = bit >> 2; // bit / 5 // pay attention to the potential
  // rounding error!
  uint16_t __x1        = __extract_nibble(new_key, shf, length);
  uint32_t new_bitmask = __mask_table[__x1];
  // re-index keys with adjusted offset

  // Prepare the new leaf.
  union _qp_union new_leaf = {0};
  __qpe_set_leaf_index(&new_leaf, new_key, length);

  // Find where to insert a branch or grow an existing branch.
  tmp = ins_bb_branch;

  while (__idx_branch(__use_branch_key(tmp->branch)) == 1UL) {
    __builtin_prefetch(tmp->branch.data);
    i                = tmp->branch;
    uint32_t i_shift = __idx_shift(__use_branch_key(i));

    if (shf == i_shift) goto np_grow_branch;
    if (shf < i_shift) goto np_new_branch;

    uint32_t bitmask = __key_bitmask(i, new_key, length);
    assert(bitmask > 0);
    tmp = __idx_next(tmp, bitmask);
  }

np_new_branch:;
  new_bb_branch = calloc(16, sizeof(union _qp_union));
  if (new_bb_branch == NULL) return np_out_of_memory; // (NULL);

  uint16_t __x2        = __extract_nibble(tmp_key, shf, length);
  uint32_t old_bitmask = __mask_table[__x2];

  memcpy(&new_bb_branch[__x2], tmp, sizeof(union _qp_union));

  __set_branch_key(i, __idx_create_branch_key(shf, 1UL));
  __set_branch_mask(i, new_bitmask | old_bitmask);

  memcpy(&new_bb_branch[__x1], &new_leaf, sizeof(union _qp_union));

  tmp->branch      = i;
  tmp->branch.data = new_bb_branch;
  *out             = &__use_leaf_data(new_bb_branch[__x1].leaf);

  return (np_ok);

np_grow_branch:;
  assert(!(__idx_has_next(i, new_bitmask)));

  memcpy(&tmp->branch.data[__x1], &new_leaf, sizeof(union _qp_union));
  __set_branch_mask(tmp->branch, __use_branch_mask(tmp->branch) | new_bitmask);

  *out = &__use_leaf_data(tmp->branch.data[__x1].leaf);

  return (np_ok);
}

enum np_return __intersect_qpe(union _qp_union **result,
                               union _qp_union *restrict join,
                               const size_t           key_length,
                               cupidtrie_combine_func combine_func) {

  if (*result == NULL) return (np_invalid_argument);
  if (join == NULL) return (np_ok);

  bool intersect_branch =
      (__idx_branch(__use_branch_key(join->branch)) == 1UL) &&
      (__idx_branch(__use_branch_key((*result)->branch)) == 1UL);

  if (intersect_branch && // improve on next line
      (__idx_shift(__use_branch_key(join->branch)) ==
       __idx_shift(__use_branch_key((*result)->branch)))) {
    __builtin_prefetch((void *)join->branch.data);
    __builtin_prefetch((void *)(*result)->branch.data);

    // both qpe structs are of type "branch" and have the same shift level
    // uint32_t _a = __use_branch_mask(join->branch);
    // uint32_t _b = __use_branch_mask((*result)->branch);

    uint32_t intersect_mask =
        __use_branch_mask(join->branch) & __use_branch_mask((*result)->branch);
    uint32_t cleanup_mask =
        intersect_mask ^ __use_branch_mask((*result)->branch);
    uint32_t final_mask = intersect_mask;

    while (intersect_mask > 0) {
      // step down to branches / leaves
      uint16_t         s   = __builtin_ctz(intersect_mask);
      union _qp_union *tmp = __idx_next((*result), __mask_table[s]);
      if (np_ok != __intersect_qpe(&tmp,
                                   __idx_next(join, __mask_table[s]),
                                   key_length,
                                   combine_func)) {
        cleanup_mask |= __mask_table[s];
        final_mask ^= __mask_table[s];
      }
      intersect_mask ^= __mask_table[s];
    }
    // cleanup unused branches / leaves
    while (cleanup_mask > 0) {
      uint16_t s = __builtin_ctz(cleanup_mask);
      __free_qpe(__idx_next((*result), __mask_table[s]));
      cleanup_mask ^= __mask_table[s];
    }

    __set_branch_mask((*result)->branch, final_mask);
    if (final_mask > 0) return np_ok;
    else return np_operation_failed;
  }

  bool intersect_leaf =
      !(__idx_branch(__use_branch_key(join->branch)) == 1UL) &&
      !(__idx_branch(__use_branch_key((*result)->branch)) == 1UL) &&
      (memcmp(__use_leaf_aux((*result)->leaf),
              __use_leaf_aux(join->leaf),
              key_length) == 0);

  if (intersect_leaf) {
    // both qpe structs are of type "leaf" and have the same key
    return combine_func(&__use_leaf_data((*result)->leaf),
                        &__use_leaf_data(join->leaf));
  }

  // either one qp tree is of type branch and the other a leaf,
  // or both are branches and the shift values do not match
  uint16_t result_shift =
      (__idx_branch(__use_branch_key((*result)->branch)) == 1UL)
          ? __idx_shift(__use_branch_key((*result)->branch))
          : 0;
  uint16_t join_shift = (__idx_branch(__use_branch_key(join->branch)) == 1UL)
                            ? __idx_shift(__use_branch_key(join->branch))
                            : 0;

  // deal with situation that one trie element is a leaf, the other a branch
  if (result_shift == 0 || join_shift == 0) {
    if (__idx_branch(__use_branch_key((*result)->branch)) != 1UL) {
      uintptr_t *out = NULL;
      if (np_ok ==
          __find_qpe(join, __use_leaf_aux((*result)->leaf), key_length, &out)) {
        return combine_func(&__use_leaf_data((*result)->leaf), out);
      }
      return np_operation_failed;
    }
    if (__idx_branch(__use_branch_key(join->branch)) != 1UL) {
      uintptr_t *out = NULL;
      if (np_ok ==
          __find_qpe(*result, __use_leaf_aux(join->leaf), key_length, &out)) {
        return combine_func(out, &__use_leaf_data(join->leaf));
      }
      return np_operation_failed;
    }
  }

  if (result_shift < join_shift) {
    // deal with elements that have a higher prefix count in the joining trie
    union _qp_union *tmp = join;
    while (__idx_branch(__use_branch_key(tmp->branch)) == 1UL) {
      uint16_t s = __builtin_ctz(__use_branch_mask(tmp->branch));
      tmp        = __idx_next(tmp, __mask_table[s]);
    }

    uint32_t bm =
        __key_bitmask((*result)->branch, __use_leaf_aux(tmp->leaf), key_length);
    uint32_t cleanup_mask = bm ^ __use_branch_mask((*result)->branch);

    if ((__idx_branch(__use_branch_key((*result)->branch)) == 1UL) &&
        __idx_has_next((*result)->branch, bm)) {
      tmp = __idx_next((*result), bm);
      if (np_ok != __intersect_qpe(&tmp, join, key_length, combine_func)) {
        cleanup_mask |= bm;
      }
    }

    if (__idx_branch(__use_branch_key((*result)->branch)) == 1UL) {
      // cleanup unused branches / leaves
      __set_branch_mask((*result)->branch,
                        __use_branch_mask((*result)->branch) ^ cleanup_mask);
      while (cleanup_mask > 0) {
        uint16_t s = __builtin_ctz(cleanup_mask);
        __free_qpe(__idx_next((*result), __mask_table[s]));
        cleanup_mask ^= __mask_table[s];
      }
    }
    if (__use_branch_mask((*result)->branch) > 0) return np_ok;
    else return np_operation_failed;
  }

  if (result_shift > join_shift) {
    // deal with elements that have a lower prefix count in the joining trie
    union _qp_union *tmp = *result;
    while (__idx_branch(__use_branch_key(tmp->branch)) == 1UL) {
      uint16_t s = __builtin_ctz(__use_branch_mask(tmp->branch));
      tmp        = __idx_next(tmp, __mask_table[s]);
    }

    uint32_t bm =
        __key_bitmask(join->branch, __use_leaf_aux(tmp->leaf), key_length);

    if ((__idx_branch(__use_branch_key(join->branch)) == 1UL) &&
        __idx_has_next(join->branch, bm)) {
      tmp = __idx_next(join, bm);
      if (np_ok != __intersect_qpe(result, tmp, key_length, combine_func)) {
        // if ((__idx_branch(__use_branch_key((*result)->branch)) == 1UL)) {
        __free_qpe(__idx_next((*result), bm));
        __set_branch_mask((*result)->branch,
                          __use_branch_mask((*result)->branch) ^ bm);
        //} else {

        //}
      }
    }
    if ((__idx_branch(__use_branch_key((*result)->branch)) != 1UL) ||
        __use_branch_mask((*result)->branch) > 0)
      return np_ok;
    else return np_operation_failed;
  }

  // both unions represents leaves, and they have different keys
  return np_operation_failed;
}

enum np_return __union_qpe(union _qp_union **result,
                           const union _qp_union *restrict join,
                           const size_t           key_length,
                           cupidtrie_combine_func combine_func) {

  if (join == NULL) return (np_ok);

  bool ret = np_ok;
  if (__idx_branch(__use_branch_key(join->branch)) == 1UL) {
    __builtin_prefetch((void *)join->branch.data);

    uint32_t bm = __use_branch_mask(join->branch);
    while (bm > 0 && ret == np_ok) {
      uint16_t pos = __builtin_ctz(bm);
      ret          = __union_qpe(result,
                        __idx_next(join, __mask_table[pos]),
                        key_length,
                        combine_func);
      bm ^= __mask_table[pos];
    }
  } else {
    uintptr_t *out = NULL;
    ret = __insert_qpe(result, __use_leaf_aux(join->leaf), key_length, &out);
    if (ret == np_ok) ret = combine_func(out, &__use_leaf_data(join->leaf));
  }
  return (ret);
}

// enum np_return np_cupidtrie_init(struct np_cupidtrie *trie,
//                                  uint8_t              key_length) {
//   trie->tree = NULL;
//   // trie->key_length = key_length;
// }

enum np_return
np_cupidtrie_insert(struct np_cupidtrie *trie, uint8_t *key, uintptr_t **data) {

  uint8_t *new_key = key;
  if (trie->alloc_key_memory) {
    new_key = calloc(1, sizeof(uint8_t) * trie->key_length);
    if (new_key == NULL) return np_out_of_memory;
    memcpy(new_key, key, trie->key_length);
  }

  return __insert_qpe(&trie->tree, new_key, trie->key_length, data);
}

enum np_return
np_cupidtrie_find(struct np_cupidtrie *trie, uint8_t *key, uintptr_t **data) {
  return __find_qpe(trie->tree, key, trie->key_length, data);
}

enum np_return np_cupidtrie_update(struct np_cupidtrie   *trie,
                                   uint8_t               *key,
                                   cupidtrie_element_func update) {
  return np_not_implemented;
}

enum np_return
np_cupidtrie_delete(struct np_cupidtrie *trie, uint8_t *key, uintptr_t **data) {
  return __delete_qpe(trie->tree, key, trie->key_length, data);
}

enum np_return np_cupidtrie_union(struct np_cupidtrie   *result,
                                  struct np_cupidtrie   *other,
                                  cupidtrie_combine_func combine_func) {
  assert(result->key_length == other->key_length);
  return __union_qpe(&result->tree,
                     other->tree,
                     result->key_length,
                     combine_func);
}

enum np_return np_cupidtrie_intersect(struct np_cupidtrie   *result,
                                      struct np_cupidtrie   *other,
                                      cupidtrie_combine_func combine_func) {
  assert(result->key_length == other->key_length);
  enum np_return ret = __intersect_qpe(&result->tree,
                                       other->tree,
                                       result->key_length,
                                       combine_func);
  if (ret != np_invalid_argument) return np_ok;
  return ret;
}

enum np_return np_cupidtrie_map_reduce(struct np_cupidtrie    *trie,
                                       struct np_map_reduce_s *mr) {
  return np_not_implemented;
}

enum np_return np_cupidtrie_free(struct np_cupidtrie *trie) {
  __free_qpe((void *)trie->tree);
  trie->tree = NULL;
  // trie->key_length = 0;
}
