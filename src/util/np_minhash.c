//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

// inspired and adapted from
// https://github.com/dgryski/go-minhash/blob/master/minwise.go but
// implementation in c99, fixed siphash-2-4 function with added seed
// functionality

#include "util/np_minhash.h"

#include "inttypes.h"
#include "math.h"
#include "sodium.h"
#include "stdbool.h"
#include "stdlib.h"
#include "string.h"

#include "util/np_tree.h"

#include "np_dhkey.h"

// pushes a new string value to the minhash and the minhash signature, but uses
// the data dependant flex scheme
void np_minhash_push_dd_flex(np_minhash_t        *minhash,
                             const unsigned char *bytes,
                             uint16_t             bytes_length) {
  unsigned char sip_hash[crypto_shorthash_BYTES];
  uint64_t      v1 = UINT64_MAX;
  uint64_t      v2 = UINT64_MAX;

  crypto_shorthash_siphash24(sip_hash, bytes, bytes_length, &minhash->seed[0]);
  memcpy(&v1, &sip_hash[0], sizeof(uint64_t));
  crypto_shorthash_siphash24(sip_hash, bytes, bytes_length, &minhash->seed[16]);
  memcpy(&v2, &sip_hash[0], sizeof(uint64_t));

  uint32_t half = minhash->size / 2;
  if (minhash->_dd_pos >= half) {
    minhash->size += minhash->size;
    minhash->_minimums = (uint32_t *)realloc(minhash->_minimums,
                                             sizeof(uint32_t) * minhash->size);
    memmove(&minhash->_minimums[minhash->size / 2],
            &minhash->_minimums[minhash->_dd_pos + half],
            minhash->_dd_pos);
  }

  // uint32_t old_hash_l = minhash->_minimums[minhash->_dd_pos       ];
  // uint32_t old_hash_u = minhash->_minimums[minhash->_dd_pos + half];

  // fprintf(stdout, "..%u->%u:%u..\n", minhash->_dd_pos,
  // minhash->_minimums[minhash->_dd_pos], minhash->_minimums[minhash->_dd_pos +
  // half]);
  uint32_t hash = (uint32_t)((v1 + minhash->mh_mode * v2) & 0xFFFFFFFF);

  minhash->_minimums[minhash->_dd_pos] -= hash;
  minhash->_minimums[minhash->_dd_pos + half] += hash;

  // bool increase_counter = false;
  // if (minhash->_minimums[minhash->_dd_pos] > old_hash_l)
  // {
  //     increase_counter |= true;
  // }
  // if (minhash->_minimums[minhash->_dd_pos + half] < old_hash_u)
  // {
  //     increase_counter &= true;
  // }
  // fprintf(stdout, "..%u->%u:%u..\n", minhash->_dd_pos,
  // minhash->_minimums[minhash->_dd_pos], minhash->_minimums[minhash->_dd_pos +
  // half]); if (increase_counter)
  minhash->_dd_pos++;
}

// pushes a new string value to the minhash and the minhash signature, but uses
// the data dependant fix scheme
void np_minhash_push_dd_fix(np_minhash_t        *minhash,
                            const unsigned char *bytes,
                            uint16_t             bytes_length) {
  unsigned char sip_hash[crypto_shorthash_BYTES];
  uint64_t      v1 = UINT64_MAX;
  uint64_t      v2 = UINT64_MAX;

  crypto_shorthash_siphash24(sip_hash, bytes, bytes_length, &minhash->seed[0]);
  memcpy(&v1, &sip_hash[0], sizeof(uint64_t));
  crypto_shorthash_siphash24(sip_hash, bytes, bytes_length, &minhash->seed[16]);
  memcpy(&v2, &sip_hash[0], sizeof(uint64_t));

  uint16_t half = minhash->size / 2;
  if (minhash->_dd_pos >= half) {
    // fprintf(stdout, "minhash dd is full ...\n");
    return;
  }

  // uint32_t old_hash_l = minhash->_minimums[minhash->_dd_pos       ];
  // uint32_t old_hash_u = minhash->_minimums[minhash->_dd_pos + half];
  // fprintf(stdout, "..%u->%u:%u..\n", minhash->_dd_pos,
  // minhash->_minimums[minhash->_dd_pos], minhash->_minimums[minhash->_dd_pos +
  // half]);

  uint32_t hash_1 = (uint32_t)((v1) & 0xFFFFFFFF);
  uint32_t hash_2 = (uint32_t)((v2) & 0xFFFFFFFF);

  // bool increase_counter = false;
  // if ((minhash->_minimums[minhash->_dd_pos] - hash) > old_hash_l)
  // {
  //     increase_counter |= true;
  // }
  // if ((minhash->_minimums[minhash->_dd_pos + half] + hash) < old_hash_u)
  // {
  //     increase_counter &= true;
  // }
  // fprintf(stdout, "..%u->%u:%u..\n", minhash->_dd_pos,
  // minhash->_minimums[minhash->_dd_pos], minhash->_minimums[minhash->_dd_pos +
  // half]); if (increase_counter)

  if (hash_1 > hash_2) {
    minhash->_minimums[minhash->_dd_pos]        = hash_2;
    minhash->_minimums[minhash->_dd_pos + half] = hash_1;
  } else {
    minhash->_minimums[minhash->_dd_pos]        = hash_1;
    minhash->_minimums[minhash->_dd_pos + half] = hash_2;
  }
  minhash->_dd_pos++;
}

// pushes a new string value to the minhash and the minhash signature, but uses
// the single value scheme
void np_minhash_push_single(np_minhash_t        *minhash,
                            const unsigned char *bytes,
                            uint16_t             bytes_length) {
  unsigned char sip_hash[crypto_shorthash_BYTES];
  uint64_t      v1 = UINT64_MAX;
  uint64_t      v2 = UINT64_MAX;

  crypto_shorthash_siphash24(sip_hash, bytes, bytes_length, &minhash->seed[0]);
  memcpy(&v1, &sip_hash[0], sizeof(uint64_t));
  crypto_shorthash_siphash24(sip_hash, bytes, bytes_length, &minhash->seed[16]);
  memcpy(&v2, &sip_hash[0], sizeof(uint64_t));

  uint16_t half = minhash->size / 2;

  uint32_t min_h   = UINT32_MAX;
  uint32_t max_h   = 0;
  uint16_t min_idx = 0, max_idx = 0 + half;

  for (uint16_t i = 0; i < minhash->size / 2; i++) {
    uint32_t hash = (uint32_t)((v1 + i * v2) & 0xFFFFFFFF);

    min_idx = (hash < min_h && hash < minhash->_minimums[i]) ? i : min_idx;
    min_h   = (hash < min_h && hash < minhash->_minimums[i]) ? hash : min_h;
    max_idx = (hash > max_h && hash > minhash->_minimums[i + half]) ? i + half
                                                                    : max_idx;
    max_h =
        (hash > max_h && hash > minhash->_minimums[i + half]) ? hash : max_h;
  }
  // fprintf(stdout, "min_idx %"PRIu32"\t min_h %"PRIu32"\t max_idx %"PRIu32"\t
  // max_h %"PRIu32" )\n",
  //                 min_idx, min_h, max_idx, max_h);
  // only set when an position has been found
  if (min_h < UINT32_MAX) minhash->_minimums[min_idx] = min_h;
  if (max_h > 0) minhash->_minimums[max_idx] = max_h;
}

// pushes a new string value to the minhash and the minhash signature, but uses
// the multi value scheme
void np_minhash_push_multi(np_minhash_t        *minhash,
                           const unsigned char *bytes,
                           uint16_t             bytes_length) {
  unsigned char sip_hash[crypto_shorthash_BYTES];
  uint64_t      v1 = UINT64_MAX;
  uint64_t      v2 = UINT64_MAX;

  crypto_shorthash_siphash24(sip_hash, bytes, bytes_length, &minhash->seed[0]);
  memcpy(&v1, &sip_hash[0], sizeof(uint64_t));
  crypto_shorthash_siphash24(sip_hash, bytes, bytes_length, &minhash->seed[16]);
  memcpy(&v2, &sip_hash[0], sizeof(uint64_t));

  uint16_t half = minhash->size / 2;

  uint32_t min_h = UINT32_MAX;
  uint32_t max_h = 0;

  for (uint16_t i = 0; i < minhash->size / 2; i++) {
    uint32_t hash = (uint32_t)((v1 + i * v2) & 0xFFFFFFFF);
    min_h = max_h = hash;
    if (min_h < minhash->_minimums[i]) {
      minhash->_minimums[i] = min_h;
    }
    if (max_h > minhash->_minimums[i + half]) {
      minhash->_minimums[i + half] = max_h;
    }
  }
}

// initialize a minhash structure by allocation memory, setting size and copying
// seed to the right place
void np_minhash_init(np_minhash_t        *minhash,
                     const uint16_t       size,
                     enum np_mixhash_mode mode,
                     const np_dhkey_t     seed) {
  assert(size % 2 == 0);

  minhash->mh_mode = mode;
  minhash->_dd_pos = 0;

  switch (minhash->mh_mode) {
  case MIXHASH_DATADEPENDANT_FIX:
    minhash->_push_func = np_minhash_push_dd_fix;
    break;
  case MIXHASH_DATADEPENDANT_FLEX:
    minhash->_push_func = np_minhash_push_dd_flex;
    break;
  case MIXHASH_SINGLE:
    minhash->_push_func = np_minhash_push_single;
    break;
  case MIXHASH_MULTI:
  default:
    minhash->_push_func = np_minhash_push_multi;
    break;
  }
  minhash->size      = size;
  minhash->_minimums = (uint32_t *)calloc(size, sizeof(uint32_t));

  // for (uint16_t i = 0;             i < minhash->size; i++)
  // minhash->_minimums[i] = UINT32_MAX;
  for (uint16_t i = 0; i < minhash->size / 2; i++)
    minhash->_minimums[i] = UINT32_MAX;
  for (uint16_t i = minhash->size / 2; i < minhash->size; i++)
    minhash->_minimums[i] = 0;

  memcpy(&minhash->seed[0], &seed.t[0], sizeof(uint32_t));
  memcpy(&minhash->seed[4], &seed.t[1], sizeof(uint32_t));
  memcpy(&minhash->seed[8], &seed.t[2], sizeof(uint32_t));
  memcpy(&minhash->seed[12], &seed.t[3], sizeof(uint32_t));
  memcpy(&minhash->seed[16], &seed.t[4], sizeof(uint32_t));
  memcpy(&minhash->seed[20], &seed.t[5], sizeof(uint32_t));
  memcpy(&minhash->seed[24], &seed.t[6], sizeof(uint32_t));
  memcpy(&minhash->seed[28], &seed.t[7], sizeof(uint32_t));
}

void np_minhash_destroy(np_minhash_t *minhash) { free(minhash->_minimums); }

// pushes a new string value to the minhash and the minhash signature
void np_minhash_push(np_minhash_t        *minhash,
                     const unsigned char *bytes,
                     uint16_t             bytes_length) {
  minhash->_push_func(minhash, bytes, bytes_length);
}

int __compare_minhash_elements(const void *left, const void *right) {
  uint32_t *lu32 = (uint32_t *)left;
  uint32_t *ru32 = (uint32_t *)right;

  if (*lu32 == *ru32) return 0;
  if (*lu32 > *ru32) return 1;
  if (*lu32 < *ru32) return -1;

  return 0;
}

struct __mh_string {
  char *str;
  bool  freeable;
};

void np_minhash_push_tree(np_minhash_t    *minhash,
                          const np_tree_t *tree,
                          uint8_t          shingle_size,
                          bool             include_keys) {
  ASSERT(shingle_size != 0,
         "requested shingle size must be greater or equal than one");

  uint16_t        i                   = 0;
  np_tree_elem_t *tmp                 = NULL;
  uint8_t         _local_shingle_size = shingle_size;

  // adjustment for sets smaller than the requested shingle size (e.g. a subtree
  // with just 3 key/value pairs, but 5 shingles requested) assert doesn't work
  // because subtree could always have less than required elements
  if (tree->size < _local_shingle_size) _local_shingle_size = tree->size;

  // iterate over keys
  if (true == include_keys) {
    struct __mh_string *key_part =
        calloc(_local_shingle_size, sizeof(struct __mh_string));
    np_tree_t *ctree = (np_tree_t *)tree;

    RB_FOREACH (tmp, np_tree_s, ctree) {
      key_part[_local_shingle_size - 1].str =
          np_treeval_to_str(tmp->key,
                            &key_part[_local_shingle_size - 1].freeable);

      // fprintf(stdout, "%s:xx ", key_part[_local_shingle_size-1].str);
      if (i >= (_local_shingle_size - 1)) {
        unsigned char  substring[512] = {0};
        unsigned char *target         = &substring[0];

        for (uint8_t j = 0; j < _local_shingle_size; j++) {
          strncat(target, key_part[j].str, 512);
        }
        // fprintf(stdout, "mh add: %s\n", substring);
        np_minhash_push(minhash, target, strnlen(target, 512));

        if (key_part[0].freeable) free(key_part[0].str);
      }

      for (uint8_t index = 1; index <= _local_shingle_size - 1; index++) {
        key_part[index - 1] = key_part[index];
        // fprintf(stdout, " t %u -> %s:yy ", index, key_part[index].str);
      }
      i++;
    }
    free(key_part);
  }

  // iterate over values
  i = 0;

  struct __mh_string *val_part =
      calloc(_local_shingle_size, sizeof(struct __mh_string));
  RB_FOREACH (tmp, np_tree_s, (tree)) {
    val_part[_local_shingle_size - 1].str =
        np_treeval_to_str(tmp->val,
                          &val_part[_local_shingle_size - 1].freeable);

    if (i >= (_local_shingle_size - 1)) {
      unsigned char  substring[512] = {0};
      unsigned char *target         = &substring[0];

      if (tmp->val.type == np_treeval_type_jrb_tree) {
        np_minhash_push_tree(minhash,
                             tmp->val.value.tree,
                             _local_shingle_size,
                             include_keys);
      } else {
        for (uint8_t j = 0; j < _local_shingle_size; j++) {
          strncat(target, val_part[j].str, 512);
          // fprintf(stdout, "%d / %s:%s --> %s\n", pos, key_part[j].str,
          // val_part[j].str, target);
        }
        // fprintf(stdout, substring, strnlen(substring, 255));
        np_minhash_push(minhash, target, strnlen((char *)target, 512));
      }
      if (val_part[0].freeable) free(val_part[0].str);
    }

    for (uint8_t index = 1; index <= _local_shingle_size - 1; index++) {
      val_part[index - 1] = val_part[index];
    }
    // fprintf(stdout, "\n");
    // fflush(stdout);
    i++;
  }

  free(val_part);
}

// extracts the single minimum hash value from the signature
void np_minhash_value(const np_minhash_t *minhash, uint32_t *value) {
  *value = UINT32_MAX;
  for (uint16_t i = 0; i < minhash->size; i++) {
    if (minhash->_minimums[i] < *value) *value = minhash->_minimums[i];
  }
}

// stores the minhash signature of a document in an array
// passed array must have the same size as the minhash signature
void np_minhash_signature(const np_minhash_t *minhash, uint32_t *signature[]) {
  memcpy(signature, minhash->_minimums, sizeof(uint32_t) * minhash->size);
}

// np_minhash_similarity compares two minhash sets, result is placed in result
void np_minhash_similarity(const np_minhash_t *minhash_1,
                           const np_minhash_t *minhash_2,
                           float              *result) {
  if (minhash_1->mh_mode != minhash_2->mh_mode) {
    *result = 0.0;
    return;
  }

  uint16_t union_size   = minhash_1->size; // the max number of possible matches
  uint16_t compare_size = minhash_1->size; // the number of elements to compare

  if (minhash_1->mh_mode == MIXHASH_DATADEPENDANT_FLEX) {
    // calculate data dependant flex hashing limits
    // adjust campare size to the lower limit
    compare_size =
        minhash_1->size < minhash_2->size ? minhash_1->size : minhash_2->size;
    // adjust union size to the upper limit
    union_size =
        minhash_1->size < minhash_2->size ? minhash_2->size : minhash_1->size;
  } else {
    if (sizeof(minhash_1->size) != sizeof(minhash_2->size)) {
      *result = 0.0; // not similar at all
      return;
    }
  }

  uint16_t intersect_count = 0;

  for (uint16_t i = 0; i < compare_size; i++) {
    if (minhash_1->mh_mode !=
        MIXHASH_MULTI) { // ignore initial min-max values when dealing with
                         // single hashing
      // they do not add meaningful information to single-hahsing similarity
      if (minhash_1->_minimums[i] == UINT32_MAX ||
          minhash_2->_minimums[i] == UINT32_MAX) {
        if (minhash_1->_minimums[i] == minhash_2->_minimums[i]) union_size--;
        continue;
      }
      if (minhash_1->_minimums[i] == 0 || minhash_2->_minimums[i] == 0) {
        if (minhash_1->_minimums[i] == minhash_2->_minimums[i]) union_size--;
        continue;
      }
    }

    if (minhash_1->_minimums[i] == minhash_2->_minimums[i]) intersect_count++;
  }

  *result = (float)intersect_count / union_size;
}

// np_minhash_merge inserts the signature of minhash_2 into minhash_1 if the
// values are less than in mimhash_1 the merge result is union of two minhash
// signatures
void np_minhash_merge(np_minhash_t *minhash_1, const np_minhash_t *minhash_2) {
  if (sizeof(minhash_1->size) != sizeof(minhash_2->size)) {
    return;
  }
  if (minhash_1->mh_mode != minhash_2->mh_mode) {
    return;
  }

  for (uint16_t i = 0; i < minhash_1->size / 2; i++) {
    if (minhash_2->_minimums[i] < minhash_1->_minimums[i])
      minhash_1->_minimums[i] = minhash_2->_minimums[i];
  }

  for (uint16_t i = minhash_1->size / 2 + 1; i < minhash_1->size; i++) {
    if (minhash_2->_minimums[i] > minhash_1->_minimums[i])
      minhash_1->_minimums[i] = minhash_2->_minimums[i];
  }
}
