//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// neuropil is copyright 2016-2022 by pi-lar GmbH

#ifndef NP_FWK_SEARCH_INDEX_H_
#define NP_FWK_SEARCH_INDEX_H_

#include <stdint.h>

#include "neuropil.h"
#include "neuropil_attributes.h"
#include "neuropil_data.h"

#include "util/np_bloom.h"
#include "util/np_minhash.h"
#include "util/np_tree.h"

#include "np_dhkey.h"

#ifdef __cplusplus
extern "C" {
#endif

struct np_index {

  // np_dhkey_t upper_dhkey;
  np_dhkey_t lower_dhkey;

  // a counting bloom filter to create the 256-bit index
  np_bloom_t *_cbl_index;
  np_bloom_t *_cbl_index_counter;
  float       _octile_values[8];

  // a neuropil bloom filter that represents the intent token
  np_bloom_t *_clk_hash;

  // a flag indicating whether the 'np_index_hash' function has already been
  // called used to make the index "immutable"
  bool is_final;
};

typedef struct np_index np_index_t;

// init lsh data structure
void np_index_init(np_index_t *index);
void np_index_destroy(np_index_t *index);

// push a new minhash entry into the np_index
void np_index_update_with_dhkey(np_index_t *index, np_dhkey_t dhkey);
void np_index_update_with_minhash(np_index_t *index, np_minhash_t *min_hash);

// create the final "search" hash all pushed minhash/dhkey values
void np_index_hash(np_index_t *index);

// compare two np_index entries for adding to a table
int8_t _compare_index_entry_add(const void *old, const void *new);
// compare two np_index entries for searching in a table
int8_t _compare_index_entry_query(const void *old, const void *new);

#ifdef __cplusplus
}
#endif

#endif // NP_FWK_SEARCH_INDEX_H_
