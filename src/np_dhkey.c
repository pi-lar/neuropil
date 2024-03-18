//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project
#include "np_dhkey.h"

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ctype.h"
#include "sodium.h"

#include "neuropil_log.h"

#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_aaatoken.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_network.h"
#include "np_node.h"
#include "np_util.h"

static np_dhkey_t __dhkey_min;
static np_dhkey_t __dhkey_half;
static np_dhkey_t __dhkey_max;

NP_SLL_GENERATE_IMPLEMENTATION(np_dhkey_t)

np_dhkey_t _np_dhkey_generate_hash(const unsigned char *data,
                                   size_t               data_size) {
  unsigned char md_value[32] = {0};
  crypto_generichash_blake2b(md_value,
                             NP_FINGERPRINT_BYTES,
                             data,
                             data_size,
                             NULL,
                             0);
  // crypto_hash_sha256(md_value, data, data_size);

  np_dhkey_t kResult = {0};
  memcpy(&kResult.t[0], &md_value[0], 4);
  memcpy(&kResult.t[1], &md_value[4], 4);
  memcpy(&kResult.t[2], &md_value[8], 4);
  memcpy(&kResult.t[3], &md_value[12], 4);
  memcpy(&kResult.t[4], &md_value[16], 4);
  memcpy(&kResult.t[5], &md_value[20], 4);
  memcpy(&kResult.t[6], &md_value[24], 4);
  memcpy(&kResult.t[7], &md_value[28], 4);

  return kResult;
}

enum np_return np_hkey_generate_hash(const unsigned char *data,
                                     const size_t         data_size,
                                     union np_hkey       *out) {
  unsigned char hash_value[32] = {0};
  crypto_generichash_blake2b(out->_as_uc,
                             NP_FINGERPRINT_BYTES,
                             data,
                             data_size,
                             NULL,
                             0);
  // crypto_hash_sha256(md_value, data, data_size);
  return (np_ok);
}

np_dhkey_t np_dhkey_create_from_hash(const char *strOrig) {
  log_trace_msg(
      LOG_TRACE,
      "start: np_dhkey_t np_dhkey_create_from_hash(const char* strOrig){");
  np_dhkey_t kResult = {0};

  // check for correct format of dhkey string
  bool _invalid_format = false;

  if (!_invalid_format) {
    if (64 != strnlen(strOrig, 64)) _invalid_format = true;
  }
  if (!_invalid_format) {
    for (uint8_t i = 0; i < 64 && i < strnlen(strOrig, 64); i++) {
      if (!isxdigit((unsigned char)strOrig[i])) {
        _invalid_format = true;
        break;
      }
    }
  }

  if (!_invalid_format) {
    np_id new_id = {0};
    np_str_id(&new_id, strOrig);
    memcpy(&kResult.t[0], &new_id[0], 4);
    memcpy(&kResult.t[1], &new_id[4], 4);
    memcpy(&kResult.t[2], &new_id[8], 4);
    memcpy(&kResult.t[3], &new_id[12], 4);
    memcpy(&kResult.t[4], &new_id[16], 4);
    memcpy(&kResult.t[5], &new_id[20], 4);
    memcpy(&kResult.t[6], &new_id[24], 4);
    memcpy(&kResult.t[7], &new_id[28], 4);
  }
  return kResult;
}

np_dhkey_t np_dhkey_create_from_hostport(const char *strOrig,
                                         const char *port) {
  char name[256] = {0};
  snprintf(name, 255, "%s:%s", strOrig, port);

  return _np_dhkey_generate_hash(name, strnlen(name, 255));
}

void _np_dhkey_encode(NP_UNUSED np_state_t *context,
                      np_tree_t            *jrb,
                      np_dhkey_t           *key) {
  log_trace_msg(LOG_TRACE,
                "start: void _np_dhkey_encode( context, np_tree_t* jrb, "
                "np_dhkey_t* key){");
  // log_msg(LOG_KEY | LOG_WARNING, "encoding key %0lu %0lu %0lu %0lu",
  // key->t[0], key->t[1], key->t[2], key->t[3]);

  np_tree_insert_str(jrb, "_np.key.0", np_treeval_new_ul(key->t[0]));
  np_tree_insert_str(jrb, "_np.key.1", np_treeval_new_ul(key->t[1]));
  np_tree_insert_str(jrb, "_np.key.2", np_treeval_new_ul(key->t[2]));
  np_tree_insert_str(jrb, "_np.key.3", np_treeval_new_ul(key->t[3]));
  np_tree_insert_str(jrb, "_np.key.4", np_treeval_new_ul(key->t[4]));
  np_tree_insert_str(jrb, "_np.key.5", np_treeval_new_ul(key->t[5]));
  np_tree_insert_str(jrb, "_np.key.6", np_treeval_new_ul(key->t[6]));
  np_tree_insert_str(jrb, "_np.key.7", np_treeval_new_ul(key->t[7]));
}

void _np_dhkey_decode(np_tree_t *jrb, np_dhkey_t *key) {
  log_trace_msg(
      LOG_TRACE,
      "start: void _np_dhkey_decode(np_tree_t* jrb, np_dhkey_t* key){");
  key->t[0] = np_tree_find_str(jrb, "_np.key.0")->val.value.ul;
  key->t[1] = np_tree_find_str(jrb, "_np.key.1")->val.value.ul;
  key->t[2] = np_tree_find_str(jrb, "_np.key.2")->val.value.ul;
  key->t[3] = np_tree_find_str(jrb, "_np.key.3")->val.value.ul;
  key->t[4] = np_tree_find_str(jrb, "_np.key.4")->val.value.ul;
  key->t[5] = np_tree_find_str(jrb, "_np.key.5")->val.value.ul;
  key->t[6] = np_tree_find_str(jrb, "_np.key.6")->val.value.ul;
  key->t[7] = np_tree_find_str(jrb, "_np.key.7")->val.value.ul;
}

void _np_dhkey_assign(np_dhkey_t *k1, const np_dhkey_t *const k2) {
  for (uint8_t i = 0; i < 8; i++)
    k1->t[i] = k2->t[i];
}

bool _np_dhkey_equal(const np_dhkey_t *const k1, const np_dhkey_t *const k2) {
  for (uint8_t i = 0; i < 8; i++)
    if (k1->t[i] != k2->t[i]) return false;
  return true;
}

int8_t _np_dhkey_cmp(const np_dhkey_t *const k1, const np_dhkey_t *const k2) {
  if (k1 == NULL) return -1;
  if (k2 == NULL) return 1;

  for (uint8_t i = 0; i < 8; i++) {
    if (k1->t[i] > k2->t[i]) return (1);
    else if (k1->t[i] < k2->t[i]) return (-1);
  }
  return (0);
}

void _np_dhkey_add(np_dhkey_t             *result,
                   const np_dhkey_t *const op1,
                   const np_dhkey_t *const op2) {
  // we dont care about unsigned integer overflow, since we are adding hashes
  // as we are using uint32_t we always stay in valid data
  // for (uint8_t i = 0; i < 8; i++)
  // {
  result->t[0] = op1->t[0] + op2->t[0];
  result->t[1] = op1->t[1] + op2->t[1];
  result->t[2] = op1->t[2] + op2->t[2];
  result->t[3] = op1->t[3] + op2->t[3];
  result->t[4] = op1->t[4] + op2->t[4];
  result->t[5] = op1->t[5] + op2->t[5];
  result->t[6] = op1->t[6] + op2->t[6];
  result->t[7] = op1->t[7] + op2->t[7];
  // }
}

void _np_dhkey_sub(np_dhkey_t             *result,
                   const np_dhkey_t *const op1,
                   const np_dhkey_t *const op2) {
  for (uint8_t i = 0; i < 8; i++) {
    result->t[i] = op1->t[i] - op2->t[i];
  }
}

void _np_dhkey_and(np_dhkey_t             *result,
                   const np_dhkey_t *const op1,
                   const np_dhkey_t *const op2) {
  // for (uint8_t i = 0; i < 8; i++)
  // {
  result->t[0] = op1->t[0] & op2->t[0];
  result->t[1] = op1->t[1] & op2->t[1];
  result->t[2] = op1->t[2] & op2->t[2];
  result->t[3] = op1->t[3] & op2->t[3];
  result->t[4] = op1->t[4] & op2->t[4];
  result->t[5] = op1->t[5] & op2->t[5];
  result->t[6] = op1->t[6] & op2->t[6];
  result->t[7] = op1->t[7] & op2->t[7];
  // }
}

void _np_dhkey_or(np_dhkey_t             *result,
                  const np_dhkey_t *const op1,
                  const np_dhkey_t *const op2) {
  // for (uint8_t i = 0; i < 8; i++)
  // {
  result->t[0] = op1->t[0] | op2->t[0];
  result->t[1] = op1->t[1] | op2->t[1];
  result->t[2] = op1->t[2] | op2->t[2];
  result->t[3] = op1->t[3] | op2->t[3];
  result->t[4] = op1->t[4] | op2->t[4];
  result->t[5] = op1->t[5] | op2->t[5];
  result->t[6] = op1->t[6] | op2->t[6];
  result->t[7] = op1->t[7] | op2->t[7];
  // }
}

void _np_dhkey_xor(np_dhkey_t             *result,
                   const np_dhkey_t *const op1,
                   const np_dhkey_t *const op2) {
  // for (uint8_t i = 0; i < 8; i++)
  // {
  result->t[0] = op1->t[0] ^ op2->t[0];
  result->t[1] = op1->t[1] ^ op2->t[1];
  result->t[2] = op1->t[2] ^ op2->t[2];
  result->t[3] = op1->t[3] ^ op2->t[3];
  result->t[4] = op1->t[4] ^ op2->t[4];
  result->t[5] = op1->t[5] ^ op2->t[5];
  result->t[6] = op1->t[6] ^ op2->t[6];
  result->t[7] = op1->t[7] ^ op2->t[7];
  // }
}

bool _np_dhkey_init(NP_UNUSED np_state_t *context) {
  uint32_t half = (UINT32_MAX >> 1) + 1;
  for (uint8_t i = 0; i < 8; i++) {
    __dhkey_max.t[i]  = UINT32_MAX;
    __dhkey_half.t[i] = half;
    __dhkey_min.t[i]  = 0;
    log_debug_msg(LOG_KEY | LOG_DEBUG,
                  "dhkey_max[%d] %" PRIu32 " / dhkey_half[%d] %" PRIu32
                  " / dhkey_half[%d] %" PRIu32,
                  i,
                  __dhkey_max.t[i],
                  i,
                  __dhkey_half.t[i],
                  i,
                  __dhkey_min.t[i]);
  }

  return true;
}

void _np_dhkey_destroy(np_state_t *context) {
  // nothing to implement for now
}

np_dhkey_t np_dhkey_min(NP_UNUSED np_state_t *context) {
  log_trace_msg(LOG_TRACE, "start: np_dhkey_t np_dhkey_fmin()  {");
  return __dhkey_min;
};
np_dhkey_t np_dhkey_half(NP_UNUSED np_state_t *context) {
  log_trace_msg(LOG_TRACE, "start: np_dhkey_t np_dhkey_half() {");
  return __dhkey_half;
};
np_dhkey_t np_dhkey_max(NP_UNUSED np_state_t *context) {
  log_trace_msg(LOG_TRACE, "start: np_dhkey_t np_dhkey_fmax()  {");
  return __dhkey_max;
};

// TODO: the distance of two hash keys could be implemented much better
void _np_dhkey_distance(np_dhkey_t             *diff,
                        const np_dhkey_t *const k1,
                        const np_dhkey_t *const k2) {
  int cmp = _np_dhkey_cmp(k1, k2);
  // calculate absolute distance
  if (cmp > 0) {
    _np_dhkey_sub(diff, k1, k2);
  } else {
    _np_dhkey_sub(diff, k2, k1);
  }

  if (_np_dhkey_cmp(&__dhkey_half, diff) < 0)
    _np_dhkey_sub(diff, &__dhkey_max, diff);
}

void _np_dhkey_hamming_distance(uint8_t                *diff,
                                const np_dhkey_t *const x,
                                const np_dhkey_t *const y) {
  *diff = 0;
  // for (uint8_t k = 0; k < 8; ++k)
  // {
  uint32_t val = 0;
  val          = x->t[0] ^ y->t[0];
  *diff += __builtin_popcount(val);
  val = x->t[1] ^ y->t[1];
  *diff += __builtin_popcount(val);
  val = x->t[2] ^ y->t[2];
  *diff += __builtin_popcount(val);
  val = x->t[3] ^ y->t[3];
  *diff += __builtin_popcount(val);
  val = x->t[4] ^ y->t[4];
  *diff += __builtin_popcount(val);
  val = x->t[5] ^ y->t[5];
  *diff += __builtin_popcount(val);
  val = x->t[6] ^ y->t[6];
  *diff += __builtin_popcount(val);
  val = x->t[7] ^ y->t[7];
  *diff += __builtin_popcount(val);

  // Count the number of bits set
  // while (val != 0)
  // {
  //     (*diff)++;
  //     val &= val - 1;
  // }
  // }
}

void _np_dhkey_hamming_distance_each(np_dhkey_t             *diff,
                                     const np_dhkey_t *const x,
                                     const np_dhkey_t *const y) {
  // uint16_t pp_diff = 0;

  // for (uint8_t k = 0; k < 8; ++k) // loops are nice, but slower than direct
  // access
  // {
  uint32_t val = 0;
  val          = x->t[0] ^ y->t[0];
  diff->t[0]   = __builtin_popcount(val);
  val          = x->t[1] ^ y->t[1];
  diff->t[1]   = __builtin_popcount(val);
  val          = x->t[2] ^ y->t[2];
  diff->t[2]   = __builtin_popcount(val);
  val          = x->t[3] ^ y->t[3];
  diff->t[3]   = __builtin_popcount(val);
  val          = x->t[4] ^ y->t[4];
  diff->t[4]   = __builtin_popcount(val);
  val          = x->t[5] ^ y->t[5];
  diff->t[5]   = __builtin_popcount(val);
  val          = x->t[6] ^ y->t[6];
  diff->t[6]   = __builtin_popcount(val);
  val          = x->t[7] ^ y->t[7];
  diff->t[7]   = __builtin_popcount(val);
  // Count the number of bits set
  // while (val != 0)
  // {
  //     pp_diff++;
  //     val &= val - 1;
  // }
  // diff->t[k] = pp_diff;
  // }
}

bool _np_dhkey_between(const np_dhkey_t *const test,
                       const np_dhkey_t *const left,
                       const np_dhkey_t *const right,
                       const bool              includeBounds) {
  bool ret = false;
  log_trace_msg(LOG_TRACE | LOG_KEY, ".start._dhkey_between");

  int8_t comp_lt = _np_dhkey_cmp(left, test);
  int8_t comp_tr = _np_dhkey_cmp(test, right);
  int8_t comp_lr = _np_dhkey_cmp(left, right);

  /* it's on one of the edges */
  if (comp_lt == 0 || comp_tr == 0) {
    ret = includeBounds;
  } else if (comp_lr < 0) {
    // it is a 'default' compare (test has to be between left and right)
    ret = (comp_lt < 0 && comp_tr < 0);
  } else {
    /* it is an 'outer circle' compare:
    min to max builds a circle for all values.
    we search for a value between:
        1) the value on the far right(aka the current left one)
        2) and the value on the far left(aka the current right one)
    */
    ret = (comp_lt < 0 || comp_tr < 0);
    // ret = ( _np_dhkey_cmp(left, test) <= 0 || _np_dhkey_cmp(test, right) <=
    // 0);
  }

  log_trace_msg(LOG_TRACE | LOG_KEY, ".end  ._dhkey_between");
  return (ret);
}

void _np_dhkey_midpoint(np_dhkey_t *mid, const np_dhkey_t *key) {
  log_trace_msg(LOG_TRACE | LOG_KEY, ".start._dhkey_midpoint");
  if (_np_dhkey_cmp(key, &__dhkey_half) < 0)
    _np_dhkey_add(mid, key, &__dhkey_half);
  else _np_dhkey_sub(mid, key, &__dhkey_half);
  // mid->valid = false;
  log_trace_msg(LOG_TRACE | LOG_KEY, ".end  ._dhkey_midpoint");
}

/**
 * @brief calculates the position of the first not matching halfbyte of both
 * @ref np_dhkey_t instances
 *
 * @param[in] a Operand 1
 * @param[in] b Operand 2
 * @return uint16_t Returns a value from 0 - 64 (max is sizeof(np_dhkey_t)*2 and
 * indicates full dhkey matching).
 */
uint16_t _np_dhkey_index(const np_dhkey_t *a, const np_dhkey_t *b) {
  // iterate over each halfbyte of the dhkeys to determine the position of the
  // first difference

  // use uint8_t instead of unsigned char as uint8_t is guaranteed to be 8 bits
  // long
  uint8_t *_pos_a = (uint8_t *)a;
  uint8_t *_pos_b = (uint8_t *)b;

  uint8_t ret = 0;
  for (uint8_t k = 0; k < sizeof(np_dhkey_t); k++) {
    // check heach half byte for a diff
    if ((*_pos_a & 0xf0) != (*_pos_b & 0xf0)) break;
    ret++;
    if ((*_pos_a & 0x0f) != (*_pos_b & 0x0f)) break;
    ret++;
    // move pointers one byte
    _pos_a += 1;
    _pos_b += 1;
  }
  return ret;
}
/*
    Returns a specific position from the dhkey

    param index_of_key: desired index to get the value from
    return: the value of the key at position index_of_key
*/
uint8_t _np_dhkey_hexalpha_at(np_state_t       *context,
                              const np_dhkey_t *key,
                              const int8_t      index_of_key) {
  log_trace_msg(LOG_TRACE | LOG_KEY, ".start._dhkey_hexalpha_at");
  uint8_t answer = 0;
  // const uint8_t tuple_size = 32;			// tuple is defined in
  // np_dhkey_s const uint8_t size_of_element = 4;		// element is 4
  // bit
  const uint8_t elements_in_tuple = 8; // tuple_size / size_of_element; // 8

  uint8_t tuple      = index_of_key / elements_in_tuple; // array index of tuple
  uint8_t tuple_rest = index_of_key % elements_in_tuple; // position in tuple

  char element[4];
  memcpy(&element[0], &key->t[tuple], sizeof(uint32_t));
  log_debug_msg(LOG_KEY | LOG_DEBUG,
                "lookup_pos: %" PRIi8 "-> key[%" PRIu8 "]: %08x ( %" PRIu32
                " / %" PRIu32 " ) mod %" PRIu8,
                index_of_key,
                tuple,
                key->t[tuple],
                key->t[tuple],
                element,
                tuple_rest / 2);
  // shift the bitmask in a way only the desired element is preserved
  memcpy(&answer, element + (tuple_rest / 2), sizeof(uint8_t));
  log_debug_msg(LOG_KEY | LOG_DEBUG,
                "bitmask & key->[%" PRIu8 "]: %" PRIx8 " (%" PRIu8,
                tuple,
                answer,
                tuple_rest);
  // filter with bitmask
  if (tuple_rest % 2 == 0) answer = answer >> 4;
  answer &= 0x0f;
  log_debug_msg(LOG_KEY | LOG_DEBUG,
                "final answer: %" PRIu8 " (%0" PRIx8 ")",
                answer,
                answer);

  log_trace_msg(LOG_TRACE | LOG_KEY, ".end  ._dhkey_hexalpha_at");
  return (uint8_t)answer;
}

void _np_dhkey_str(const np_dhkey_t *k, char *key_string) {
  np_id_str(key_string, *(np_id *)k);
}

void _np_str_dhkey(const char *key_string,
                   np_dhkey_t *k) { // np_str_id(*(np_id*)k, key_string);
  np_str_id((np_id *)k, key_string);
}
