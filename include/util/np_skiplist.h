//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef NP_SKIPLIST_H_
#define NP_SKIPLIST_H_

#include <stdbool.h>
#include <stdint.h>

#include "util/np_mapreduce.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Implementation of a skip list
 *
 * TODO:
 *
 */

struct np_skiplist_node_s {
  void *item; // pointer to the entry itself

  bool    sentinel;
  uint8_t _height;

  struct np_skiplist_node_s *
      *_nodes; // pointer to the successor on each skiplist level
};
typedef struct np_skiplist_node_s np_skiplist_node_t;

typedef int8_t (*compare_skiplist_item)(const void *left, const void *right);
typedef int8_t (*select_skiplist_height)(const void *item);
typedef void (*hash_skiplist_item)(const void *item);

struct np_skiplist_s {
  np_skiplist_node_t     root; // the real node list
  compare_skiplist_item  compare_func;
  hash_skiplist_item     hash_func;
  select_skiplist_height pick_height_func;
  size_t                 _num_elements;
};
typedef struct np_skiplist_s np_skiplist_t;

NP_API_EXPORT
void np_skiplist_init(np_skiplist_t        *skiplist,
                      compare_skiplist_item compare_func,
                      hash_skiplist_item    hash_func);
NP_API_EXPORT
size_t np_skiplist_size(np_skiplist_t *skiplist);

NP_API_EXPORT
void np_skiplist_destroy(np_skiplist_t *skiplist);

NP_API_EXPORT
bool np_skiplist_add(np_skiplist_t *skiplist, void *item);
NP_API_EXPORT
bool np_skiplist_remove(np_skiplist_t *skiplist, const void *item);

NP_API_EXPORT
bool np_skiplist_find(const np_skiplist_t *skiplist, void **item);
NP_API_EXPORT
void np_skiplist_map(const np_skiplist_t *skiplist, np_map_reduce_t *mr);
NP_API_EXPORT
void np_skiplist_reduce(np_map_reduce_t *mr);

void np_skiplist_print(const np_skiplist_t *skiplist);

#ifdef __cplusplus
}
#endif

#endif /* NP_SKIPLIST_H_ */
