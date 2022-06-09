//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

// inspired and adapted from
// https://github.com/dgryski/go-minhash/blob/master/minwise.go but
// implementation in c99, fixed siphash-2-4 function with added seed
// functionality

#ifndef NP_MINHASH_H_
#define NP_MINHASH_H_

#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sodium.h"
#include "tree/tree.h"

#include "util/np_tree.h"

#include "np_dhkey.h"
#include "np_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * this is the neuropil implemenattion of a minhash signature
 *
 * despite its name, we actually use a min/max signature, meaning that the first
 * half of our signature entries will contain the minimum values, and the second
 * half of the signature the max values.
 *
 * The user is responsible to set the correct size parameter of the minhash data
 * structure (note that the size is an important parameter for the usefulness of
 * the minhash signature and comparing elements). The seed must be set and is
 * used as an additional input to the internal siphash24 function. Using the
 * same seed to compare minhash signatures is of course mandatory. A good source
 * of seed is of course the neuropil np_dhkey_t structure, which internally uses
 * a blake2b hash function.
 *
 * A user may push single entries to the minhash signature, or he may prefer to
 * push a complete tree structure. Using a tree structure has the additional
 * benefit that it is very easy to remove duplicate data entries. It also allows
 * to "shingle" the data entries.
 *
 * TODO: allow k-mer splitting for binary data entries
 *
 */
struct np_minhash_s {
  uint32_t      size;
  unsigned char seed[crypto_shorthash_KEYBYTES * 2];
  uint32_t     *minimums;

  // flags and temp storage for data dependant minhashing scheme
  bool     dd;
  uint32_t dd_pos;
};

typedef struct np_minhash_s np_minhash_t;

// initialize a minhash structure by allocation memory, setting size and copying
// seed to the right place
void np_minhash_init(np_minhash_t    *minhash,
                     const uint32_t   size,
                     bool             data_dependant,
                     const np_dhkey_t seed);
// void np_minhash_init(np_minhash_t* minhash, const uint32_t size, const
// np_dhkey_t seed);
void np_minhash_destroy(np_minhash_t *minhash);

// pushes a new string value to the minhash and the minhash signature
void np_minhash_push(np_minhash_t        *minhash,
                     const unsigned char *bytes,
                     uint16_t             bytes_length);

// push a complete tree structure into the minhash
void np_minhash_push_tree(np_minhash_t    *minhash,
                          const np_tree_t *tree,
                          uint8_t          shingle_size,
                          bool             include_keys);

// extracts the single minimum hash value from the signature
void np_minhash_value(const np_minhash_t *minhash, uint32_t *value);

// stores the minhash signature of a document in an array
// passed array must have the same size as the minhash signature
void np_minhash_signature(const np_minhash_t *minhash, uint32_t *signature[]);

// np_minhash_similarity compares two minhash sets, result is placed in result
void np_minhash_similarity(const np_minhash_t *minhash_1,
                           const np_minhash_t *minhash_2,
                           float              *result);

// np_minhash_merge inserts the signature of minhash_2 into minhash_1 if the
// values are less than in mimhash_1 the merge result is union of two minhash
// signatures
void np_minhash_merge(np_minhash_t *minhash_1, const np_minhash_t *minhash_2);

#ifdef __cplusplus
}
#endif

// Cardinality estimates the cardinality of the set
/*
func (m *MinWise) Cardinality() int {
    // http://www.cohenwang.com/edith/Papers/tcest.pdf
    sum := 0.0
    for _, v := range m.minimums {
        sum += -math.Log(float64(math.MaxUint64-v) / float64(math.MaxUint64))
    }
    return int(float64(len(m.minimums)-1) / sum)
}
*/

#endif // NP_MINHASH_H_
