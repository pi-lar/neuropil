//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "neuropil.h"

#include "util/np_bloom.h"
#include "util/np_cupidtrie.h"

#ifndef NP_CUPIDBLOOM_H_
#define NP_CUPIDBLOOM_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief np_cupidbloom is based on the concept of qp tries developed by Tony
 * Finch (see https://dotat.at/prog/qp/README.html)
 *
 * We use a struct np_cupidtrie to store the bitarray parts that form the bloom
 * filter. The construction with the qp-trie allows us to define the size of the
 * bloom filter via the key length argument of the np_cupidtrie. Each increase
 * in key lnegth therefore give a 16x bigger bloom filter. Even with a single
 * uint32_t with 4 bytes key length it is easy to store up to 65536 buckets of
 * bitarrays. As we always use a 256-bit array to store bloom values, we can
 * interpret these 256-bits differently for each kind of bloom filter. E.g. a
 * simple bloom filter may use the plain array for its bits, we a A* bloom
 * filter could only use 128-bits for the current values and 128 bit for the old
 * values. We only have to increase the key length to accomodate for the
 * changes.
 *
 * The inner representation will deal with the different kinds of bloom filters.
 * We only use straight forward 256-bit array, but the other bloom filter types
 * can also be integrated into the new structure.
 */

struct np_cupidbloom;

typedef enum np_return (*cupidbloom_add)(struct np_cupidbloom *bloom,
                                         union np_hkey        *s);
typedef enum np_return (*cupidbloom_clear)(struct np_cupidbloom *bloom);
typedef enum np_return (*cupidbloom_check)(struct np_cupidbloom *bloom,
                                           union np_hkey        *s);
typedef enum np_return (*cupidbloom_free)(struct np_cupidbloom *bloom);
typedef enum np_return (*cupidbloom_intersect)(struct np_cupidbloom *result,
                                               struct np_cupidbloom *bloom_l);
typedef enum np_return (*cupidbloom_union)(struct np_cupidbloom *result,
                                           struct np_cupidbloom *bloom_l);

struct np_cupidbloom {
  const enum bloom_filter_type type;
  uint16_t                     bits_per_block;
  size_t                       max_blocks;

  struct np_cupidtrie storage;

  cupidbloom_add       add;
  cupidbloom_check     check;
  cupidbloom_clear     clear;
  cupidbloom_free      free;
  cupidbloom_union     build_union;
  cupidbloom_intersect build_intersection;
};

enum np_return np_cupidbloom_init(struct np_cupidbloom *bloom);
enum np_return np_cupidbloom_free(struct np_cupidbloom *bloom);
enum np_return np_cupidbloom_clear(struct np_cupidbloom *bloom);
enum np_return np_cupidbloom_add(struct np_cupidbloom *bloom, union np_hkey *s);
enum np_return np_cupidbloom_remove(struct np_cupidbloom *bloom,
                                    union np_hkey         id);
enum np_return np_cupidbloom_check(struct np_cupidbloom *bloom,
                                   union np_hkey        *s);
enum np_return np_cupidbloom_union(struct np_cupidbloom *result,
                                   struct np_cupidbloom *other);
enum np_return np_cupidbloom_intersect(struct np_cupidbloom *result,
                                       struct np_cupidbloom *other);
enum np_return np_cupidbloom_decay(struct np_cupidbloom *bloom);
enum np_return np_cupidbloom_get_heuristic(struct np_cupidbloom *bloom,
                                           union np_hkey         id,
                                           float                *probability);
enum np_return np_cupidbloom_containment(struct np_cupidbloom *first,
                                         struct np_cupidbloom *second,
                                         float                *result);
enum np_return np_cupidbloom_similarity(struct np_cupidbloom *first,
                                        struct np_cupidbloom *second,
                                        float                *result);
enum np_return np_cupidbloom_serialize(struct np_cupidbloom *filter,
                                       unsigned char       **to,
                                       size_t               *to_size);
enum np_return np_cupidbloom_deserialize(struct np_cupidbloom *filter,
                                         unsigned char        *from,
                                         size_t                from_size);
/**
 * @brief execute a map / reduce function set on the the trie
 * @param trie the cupidtrie data structure to operate on
 * @param mr the map-reduce data structure that holds compare, map and reduce
 * functions and their arguments
 * @return enum np_return np_ok when the map-reduce was executed successful
 */
enum np_return np_cupidbloom_map_reduce(struct np_cupidbloom   *trie,
                                        struct np_map_reduce_s *mr);

#ifdef __cplusplus
}
#endif

#endif // _NP_CUPIDBLOOM_H_
