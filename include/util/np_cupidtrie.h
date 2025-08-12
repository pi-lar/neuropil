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

#include "np_mapreduce.h"

#ifndef NP_CUPIDTRIE_H_
#define NP_CUPIDTRIE_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief np_cupidtrie is based on the concept of qp tries developed by Tony
 * Finch (see https://dotat.at/prog/qp/README.html)
 *
 * In general, a a qp-trie or np_cupidtrie is based on prefix based data
 * structures. The key can be anything that can be splitted into an array of
 * uint8_t. The branches in the trie itself does not store any key, only offset
 * and bitset information. The leaves of the trie contains a pointer to to key,
 * or (if rquested), creates a copy of the key and maintains it.
 *
 * Our implementation deviates from the original implementation in a few parts:
 * - only use 16-bit for storing subtries in order to run on 32-bit systems
 * properly
 * - don't store offset and shift, but only shift value (offset can be
 * re-calculated)
 * - don't realloc the subarray, because it is not good for performance
 * - remember certain subtries for re-use and quickly jump to subtries during
 * inserts
 * - added functionality for building the union and the intersection of two
 * tries
 *
 * hence we named our result "cupidtrie", which is close enough to "qp-trie"
 */
struct np_cupidtrie {
  uint16_t    key_length;
  const void *tree;
  bool        alloc_key_memory;
};

/**
 * @brief the init method initialized the np_cupidtrie data structure
 * Ideally, this function is never used, but you intialize it like this: 'struct
 * np_cupidtrie x = { .tree=NULL, key_length=y };
 * @param trie the cupidtrie data structure to operate on
 * @param key_length the max key length to use, currently restricted to 256
 * elements
 * @param alloc_key_memory indicates whether the keys in the trie should
 * allocate memory
 * @return enum np_return np_ok when the operation was succesful
 */
// enum np_return np_cupidtrie_init(struct np_cupidtrie *trie, uint8_t
// key_length);

/**
 * @brief helper function to act on elements as they are discovered during the
 * operations on the np_cupidtree. cupidtrie_combine_func is used to compare or
 * combine two elements. cupidtrie_element_func is used whenever the operation
 * is acting on a single element.
 */
typedef enum np_return (*cupidtrie_combine_func)(uintptr_t       *left,
                                                 const uintptr_t *right);
typedef enum np_return (*cupidtrie_element_func)(uintptr_t *left);

/**
 * @brief insert an element into the trie
 * @param trie the cupidtrie data structure to operate on
 * @param key a pointer to the key array (uint8_t[...])
 * @param data a pointer to the data block to store your element
 * @return enum np_return when the key did not exists and was inserted
 */
enum np_return
np_cupidtrie_insert(struct np_cupidtrie *trie, uint8_t *key, uintptr_t **data);
/**
 * @brief find an element in the trie
 * @param trie the cupidtrie data structure to operate on
 * @param key a pointer to the key array (uint8_t[...])
 * @param data a pointer to the data block which has been stored
 * @return enum np_ok when the key did exists and was fetched
 */
enum np_return
np_cupidtrie_find(struct np_cupidtrie *trie, uint8_t *key, uintptr_t **data);
/**
 * @brief update an element into the trie
 * @param trie the cupidtrie data structure to operate on
 * @param key a pointer to the key array (uint8_t[...])
 * @param update the update function to handle the actual data update
 * @return enum np_return when the key did not exists and was inserted
 */
enum np_return np_cupidtrie_update(struct np_cupidtrie   *trie,
                                   uint8_t               *key,
                                   cupidtrie_element_func update);
/**
 * @brief delete an element from the trie
 * @param trie the cupidtrie data structure to operate on
 * @param key a pointer to the key array (uint8_t[...])
 * @param data a pointer to the data block to return the deleted data block
 * @return enum np_return when the key did not exists and was inserted
 */
enum np_return
np_cupidtrie_delete(struct np_cupidtrie *trie, uint8_t *key, uintptr_t **data);
/**
 * @brief build the union of two tries
 * @param result a pointer to the trie which should receive the additional
 * values
 * @param other a pointer to the trie which keeps the new values
 * @return enum np_return np_ok if the union was successful
 */
enum np_return np_cupidtrie_union(struct np_cupidtrie   *result,
                                  struct np_cupidtrie   *other,
                                  cupidtrie_combine_func combine);
/**
 * @brief build the intersection of two tries
 * @param result a pointer to the trie which should remove the values not
 * present in both tries
 * @param other a pointer to the trie which has a different value set
 * @return enum np_return np_ok if the union was successful
 */
enum np_return np_cupidtrie_intersect(struct np_cupidtrie   *result,
                                      struct np_cupidtrie   *other,
                                      cupidtrie_combine_func combine);
/**
 * @brief execute a map / reduce function set on the the trie
 * @param trie the cupidtrie data structure to operate on
 * @param mr the map-reduce data structure that holds compare, map and reduce
 * functions and their arguments
 * @return enum np_return np_ok when the map-reduce was executed successful
 */
enum np_return np_cupidtrie_map_reduce(struct np_cupidtrie    *trie,
                                       struct np_map_reduce_s *mr);

/**
 * @brief free the trie structure and all data in it
 * @param trie the cupidtrie data structure to operate on
 * @return enum np_return np_ok when the free was executed
 */
enum np_return np_cupidtrie_free(struct np_cupidtrie *trie);

#ifdef __cplusplus
}
#endif

#endif // _NP_CUPIDTRIE_H_
