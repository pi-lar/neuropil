//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "util/np_bloom.h"

#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "neuropil.h"
#include "neuropil_log.h"

#include "util/np_pcg_rng.h"
#include "util/np_serialization.h"
#include "util/np_tree.h"

#include "np_log.h"
#include "np_util.h"

// bloom filter based on np_dhkey_t / np_dhkey_t
// we treat the np_dhkey_t as (8 * uint32_t) -> 8 distinct hash values ->
// pobability of false positive approx 1 in 1024 _size of bit array :  256 ->
// max _free_items per bloom filter is  18 _size of bit array :  512 -> max
// _free_items per bloom filter is  35 _size of bit array : 1024 -> max
// _free_items per bloom filter is  70 _size of bit array : 2048 -> max
// _free_items per bloom filter is 140

np_bloom_t *_np_enhanced_bloom_create(size_t bit_size) {
  assert(bit_size % 16 == 0);

  np_bloom_t *enhanced = (np_bloom_t *)calloc(1, sizeof(np_bloom_t));
  enhanced->_type      = standard_bf;
  enhanced->_size      = bit_size;
  enhanced->_d         = 1;

  // enhanced->_bitset_128 =
  //     calloc(enhanced->_num_blocks, sizeof(struct uint128_s *));

  enhanced->_bitset_128_list =
      (struct list_node_s *)malloc(sizeof(struct list_node_s));
  enhanced->_free_items                 = bit_size * enhanced->_d / 16;
  enhanced->_bitset_128_list->sentinel  = true;
  enhanced->_bitset_128_list->prev      = NULL;
  enhanced->_bitset_128_list->value     = calloc(1, sizeof(struct uint128_s));
  enhanced->_bitset_128_list->box_index = -1;
  enhanced->_bitset_128_list_sentinel   = enhanced->_bitset_128_list;
  enhanced->_bitset_128_list->next      = NULL;

  return enhanced;
}

void _np_enhanced_bloom_search(np_bloom_t **bloom, int search_box) {
  np_bloom_t *result = *bloom;
  while ((result->_bitset_128_list->box_index < search_box) &&
         (result->_bitset_128_list->next != NULL)) {
    result->_bitset_128_list = result->_bitset_128_list->next;
  }
  while ((result->_bitset_128_list->box_index > search_box) &&
         (result->_bitset_128_list->prev != NULL)) {
    result->_bitset_128_list = result->_bitset_128_list->prev;
  }
  *bloom = result;
}

void _np_enhanced_bloom_add(np_bloom_t *bloom, np_dhkey_t id) {
  if ((bloom->_free_items) == 0) {
    ABORT("");
  }
  int uint128_box = 0;
  for (int i = 0; i < 8; ++i) {
    // determining which pointer for uint128 to use
    uint128_box = id.t[i] % (UINT32_MAX / 128);
    // if (bloom->_bitset_128[uint128_box] == 0) {
    //   bloom->_bitset_128[uint128_box] = calloc(1, sizeof(struct uint128_s));
    // }

    // determining the local position where a bit shall be set to 1
    uint8_t _local_pos = (id.t[i]) % 128;
    // shifting 128 bit until a 1 is at previously determined local_position
    struct uint128_s    _bitmask       = {0};
    struct list_node_s *bloom_pointer  = bloom->_bitset_128_list;
    bool                inserted_check = false;

    while (uint128_box > bloom_pointer->box_index) {
      if (bloom_pointer->next == NULL) {
        break;
      }
      bloom_pointer = bloom_pointer->next;
    }

    while (uint128_box < bloom_pointer->box_index) {
      if (bloom_pointer->sentinel == true) {
        break;
      }
      bloom_pointer = bloom_pointer->prev;
    }

    if (bloom_pointer->next == NULL) {
      bloom_pointer->next =
          (struct list_node_s *)malloc(sizeof(struct list_node_s));
      bloom_pointer->next->prev = bloom_pointer;
      bloom_pointer             = bloom_pointer->next;
      bloom_pointer->next       = NULL;
      // inserted_check            = true;
    } else {
      bloom_pointer->next->prev =
          (struct list_node_s *)malloc(sizeof(struct list_node_s));
      bloom_pointer->next->prev->prev = bloom_pointer;
      bloom_pointer->next->prev->next = bloom_pointer->next;
      bloom_pointer->next             = bloom_pointer->next->prev;
      bloom_pointer                   = bloom_pointer->next;
    }
    bloom_pointer->box_index = uint128_box;
    bloom_pointer->value     = calloc(1, sizeof(struct uint128_s));
    bloom_pointer->sentinel  = false;

    if (_local_pos < 64) {
      _bitmask.high = (0x8000000000000000 >> (_local_pos));
      bloom_pointer->value->high |= _bitmask.high;
    } else {
      _bitmask.low = (0x8000000000000000 >> (_local_pos - 64));
      bloom_pointer->value->low |= _bitmask.low;
    }
    bloom->_bitset_128_list = bloom_pointer;
  }
  bloom->_free_items--;
}

void _np_enhanced_bloom_free(np_bloom_t *bloom) {

  if (bloom->_bitset_128_list->sentinel != true) {
    bloom->_bitset_128_list = bloom->_bitset_128_list_sentinel;
  }

  while (bloom->_bitset_128_list->next != NULL) {
    bloom->_bitset_128_list = bloom->_bitset_128_list->next;
    free(bloom->_bitset_128_list->prev->value);
    free(bloom->_bitset_128_list->prev);
  }
  free(bloom->_bitset_128_list->value);
  free(bloom->_bitset_128_list);
}

bool _np_enhanced_bloom_check(np_bloom_t *bloom, np_dhkey_t id) {

  int uint128_box = 0;
  for (int i = 0; i < 8; ++i) {
    // determining which box to look at
    uint128_box = id.t[i] % (UINT32_MAX / 128);

    // determining where we expect a 1
    uint8_t _local_pos = (id.t[i]) % 128;
    // shifting 128 bit until a 1 is at previously determined local_position
    struct uint128_s    _bitmask      = {0};
    struct list_node_s *bloom_pointer = bloom->_bitset_128_list;

    // looking for the right box
    while (uint128_box > bloom_pointer->box_index) {
      if (bloom_pointer->next == NULL) {

        break;
      }
      bloom_pointer = bloom_pointer->next;
    }
    while (uint128_box < bloom_pointer->box_index) {
      if (bloom_pointer->sentinel == true) {
        break;
      }
      bloom_pointer = bloom_pointer->prev;
    }
    uint64_t result = 0;

    if (bloom_pointer->box_index != uint128_box) {
      return false;
    } else if (_local_pos < 64) {
      _bitmask.high = (0x8000000000000000 >> (_local_pos));
      bloom_pointer->value->high |= _bitmask.high;
    } else {
      _bitmask.low = (0x8000000000000000 >> (_local_pos - 64));
      bloom_pointer->value->low |= _bitmask.low;
    }
  }
  return (true);
}

int _np_enhanced_bloom_right_intersection(np_bloom_t **p_result,
                                          np_bloom_t **p_first) {
  np_bloom_t *result = *p_result;
  np_bloom_t *first  = *p_first;

  do {
    // if the boxes match, an intersection shall be done for the low and high
    // value bits
    // delete result boxes until it is equal or larger than first box
    struct list_node_s *left_off_node = result->_bitset_128_list->prev;
    while (((result->_bitset_128_list->box_index) <
            (first->_bitset_128_list->box_index)) &&
           result->_bitset_128_list->next != NULL) {
      struct list_node_s *delete = result->_bitset_128_list;

      result->_bitset_128_list       = result->_bitset_128_list->next;
      left_off_node->next            = result->_bitset_128_list;
      result->_bitset_128_list->prev = left_off_node;
      free(delete->value);
      free(delete);
    }
    if ((result->_bitset_128_list->next == NULL) &&
        (result->_bitset_128_list->box_index <
         first->_bitset_128_list->box_index)) {
      result->_bitset_128_list = result->_bitset_128_list->prev;
      free(result->_bitset_128_list->next->value);
      free(result->_bitset_128_list->next);
      result->_bitset_128_list->next = NULL;
    }

    if (result->_bitset_128_list->box_index ==
        first->_bitset_128_list->box_index) {
      int stak_var = result->_bitset_128_list->value->low &
                     first->_bitset_128_list->value->low;
      stak_var += result->_bitset_128_list->value->high &
                  first->_bitset_128_list->value->high;

      result->_bitset_128_list->value->low &=
          first->_bitset_128_list->value->low;
      result->_bitset_128_list->value->high &=
          first->_bitset_128_list->value->high;

      // if afterwards the low and high value bits both are zero, the box is
      // empty and shall be removed
      if ((result->_bitset_128_list->value->low == 0) &&
          (result->_bitset_128_list->value->high == 0)) {
        result->_bitset_128_list       = result->_bitset_128_list->next;
        result->_bitset_128_list->prev = result->_bitset_128_list->prev->prev;
        free(result->_bitset_128_list->prev->next->value);
        free(result->_bitset_128_list->prev->next);
        result->_bitset_128_list->prev->next = result->_bitset_128_list;
      } else if (result->_bitset_128_list->next != NULL) {
        result->_bitset_128_list = result->_bitset_128_list->next;
      }
    }
    // go to the next box in first which is equal or bigger than the current box
    while (((first->_bitset_128_list->box_index) <
            (result->_bitset_128_list->box_index)) &&
           (first->_bitset_128_list->next != NULL)) {
      first->_bitset_128_list = first->_bitset_128_list->next;
    }

  } while ((result->_bitset_128_list->next != NULL) &&
           (first->_bitset_128_list->next != NULL));

  // Rest von Result löschen wenn first am ende ist aber result noch nicht
  struct list_node_s *delete_node;
  delete_node                    = result->_bitset_128_list->next;
  result->_bitset_128_list->next = NULL;
  while (delete_node != NULL) {
    struct list_node_s *delete_this = delete_node;
    delete_node                     = delete_node->next;
    free(delete_this->value);
    free(delete_this);
  }

  *p_result = result;
  *p_first  = first;
  return EXIT_SUCCESS;
}

void _np_enhanced_bloom_clear(np_bloom_t *res) {
  res->_bitset_128_list = res->_bitset_128_list_sentinel->next;

  while (res->_bitset_128_list->next != NULL) {
    res->_bitset_128_list->prev->next = NULL;
    free(res->_bitset_128_list->prev);
    res->_bitset_128_list->prev = NULL;
    free(res->_bitset_128_list->value);
    res->_bitset_128_list = res->_bitset_128_list->next;
  }
  res->_bitset_128_list->prev->next = NULL;
  res->_bitset_128_list->prev       = NULL;
  free(res->_bitset_128_list->value);
  free(res->_bitset_128_list);
  res->_bitset_128_list = res->_bitset_128_list_sentinel;

  res->_free_items = res->_size * res->_d / 16;
}

bool _np_enhanced_bloom_intersect(np_bloom_t *result, np_bloom_t *first) {
  ASSERT(first->_type == standard_bf, "");
  ASSERT(first->_type == result->_type, "");
  ASSERT(first->_size == result->_size, "");
  ASSERT(first->_d == result->_d, "");

  // simplified max elements calculation
  result->_free_items =
      0; // not altered, we cannot further intersect this filter
  if (result->_bitset_128_list_sentinel->next == NULL) {
    result->_free_items = 0;
    return 1;
  }
  if (first->_bitset_128_list_sentinel->next == NULL) {
    _np_enhanced_bloom_clear(result);
    result->_free_items = 0;
    return 1;
  }
  result->_bitset_128_list = result->_bitset_128_list_sentinel->next;
  first->_bitset_128_list  = first->_bitset_128_list_sentinel->next;

  int i = _np_enhanced_bloom_right_intersection(&result, &first);
  return (i == 0) ? true : false;
}

void _np_enhanced_bloom_union(np_bloom_t *result, np_bloom_t *first) {
  ASSERT(first->_type == standard_bf, "");
  ASSERT(first->_type == result->_type, "");
  ASSERT(first->_size == result->_size, "");
  ASSERT(first->_d == result->_d, "");
  ASSERT(first->_num_blocks == result->_num_blocks, "");

  // simplified max elements calculation
  ASSERT(first->_free_items + result->_free_items >= result->_size / 16, "");
  result->_free_items += (first->_free_items - result->_size / 16);

  // go to the sentinel in list for union, only if an element after sentinel
  // exists. if not, abort.
  ASSERT(first->_bitset_128_list_sentinel->next != NULL, "")

  first->_bitset_128_list = first->_bitset_128_list_sentinel->next;

  while (first->_bitset_128_list != NULL) {
    // go to the first node in list

    _np_enhanced_bloom_search(&result, (first->_bitset_128_list->box_index));
    if ((result->_bitset_128_list->box_index) ==
        (first->_bitset_128_list->box_index)) {
      result->_bitset_128_list->value->low |=
          first->_bitset_128_list->value->low;
      result->_bitset_128_list->value->high |=
          first->_bitset_128_list->value->high;
    } else {
      if (result->_bitset_128_list->next == NULL) {
        result->_bitset_128_list->next = malloc(sizeof(struct list_node_s));
        result->_bitset_128_list->next->prev = result->_bitset_128_list;
        result->_bitset_128_list             = result->_bitset_128_list->next;
        result->_bitset_128_list->box_index =
            first->_bitset_128_list->box_index;
        result->_bitset_128_list->sentinel = false;
        result->_bitset_128_list->next     = NULL;
        result->_bitset_128_list->value = calloc(1, sizeof(struct uint128_s));
        result->_bitset_128_list->value->low |=
            first->_bitset_128_list->value->low;
        result->_bitset_128_list->value->high |=
            first->_bitset_128_list->value->high;
      } else {
        result->_bitset_128_list->next->prev =
            malloc(sizeof(struct list_node_s));
        result->_bitset_128_list->next->prev->next =
            result->_bitset_128_list->next;
        result->_bitset_128_list->next->prev->prev = result->_bitset_128_list;
        result->_bitset_128_list->next = result->_bitset_128_list->next->prev;
        result->_bitset_128_list       = result->_bitset_128_list->next;
        result->_bitset_128_list->box_index =
            first->_bitset_128_list->box_index;
        result->_bitset_128_list->sentinel = false;
        result->_bitset_128_list->value = calloc(1, sizeof(struct uint128_s));
        result->_bitset_128_list->value->low |=
            first->_bitset_128_list->value->low;
        result->_bitset_128_list->value->high |=
            first->_bitset_128_list->value->high;
      }
    }
    first->_bitset_128_list = first->_bitset_128_list->next;
  }
  first->_bitset_128_list = first->_bitset_128_list_sentinel->next;
}

np_bloom_t *_np_standard_bloom_create(size_t bit_size) {
  np_bloom_t *res  = (np_bloom_t *)calloc(1, sizeof(np_bloom_t));
  res->_type       = standard_bf;
  res->_size       = bit_size;
  res->_d          = 1;
  res->_p          = 0;
  res->_num_blocks = 1;

  res->_bitset = calloc(1, (bit_size / 8) * res->_d);
  // simplified max elements calculation
  res->_free_items = bit_size * res->_d / 16;
  // real calculation would be (see also:
  // https://hur.st/bloomfilter/?n=&p=1024&m=256&k=8): res->_free_items = ceil(m
  // / (-k / log(1 - exp(log(p) / k)))) res->_free_items = ceil(bloom filter
  // size/ (-hash_funcs / log(1 - exp(log(false positive ) / hash_funcs))))
  // res->_free_items = ceil(bit_size         / (-8          / log(1 -
  // exp(log(1/1024)                     / 8         )))); res->_free_items =
  // ceil(bit_size         / (-8          / log(1 - exp(-3,0102999566 / 8 ))));
  // res->_free_items = ceil(bit_size         / (-8          / log(1 -
  // 0,686404967                                      ))); res->_free_items =
  // ceil(bit_size         / (-8          / -0,5036308247 ));

  return res;
}

void _np_bloom_free(np_bloom_t *bloom) {
  free(bloom->_bitset);
  free(bloom);
}

void _np_standard_bloom_add(np_bloom_t *bloom, np_dhkey_t id) {
  if (bloom->_free_items == 0) {
    ABORT("");
  }

  for (uint8_t k = 0; k < 8; ++k) {
    // log_msg(LOG_DEBUG, "n  : %u\n", _as_number);
    uint32_t _bit_array_pos = id.t[k] % bloom->_size;
    // log_msg(LOG_DEBUG, "bap: %d\n", _bit_array_pos);
    uint32_t _local_pos = (_bit_array_pos) / 8;
    // log_msg(LOG_DEBUG, " lp: %d\n", _local_pos);
    uint8_t _bitmask = (0x80 >> (_bit_array_pos % 8));
    // log_msg(LOG_DEBUG, " bm: %x\n", _bitmask);
    bloom->_bitset[_local_pos] |= _bitmask;
    // #ifdef DEBUG
    // char test_string[65];
    // np_id_str(test_string, &bloom->_bitset[0]);
    // log_msg(LOG_DEBUG, "add  : %s --> pos=%3d (%02x <-> %02x)\n",
    // test_string, _local_pos, _bitmask, bloom->_bitset[_local_pos]);
    // #endif
  }

  // #ifdef DEBUG
  // char test_string[65];
  // np_id_str(test_string, bloom->_bitset);
  // log_msg(LOG_DEBUG, "final: %s\n", test_string);
  // #endif

  bloom->_free_items--;
}

bool _np_standard_bloom_check(np_bloom_t *bloom, np_dhkey_t id) {
  for (uint8_t k = 0; k < 8; ++k) {
    uint32_t _bit_array_pos = id.t[k] % bloom->_size;
    uint32_t _local_pos     = (_bit_array_pos) / 8;
    uint8_t  _bitmask       = (0x80 >> (_bit_array_pos % 8));
    uint8_t  result         = bloom->_bitset[_local_pos] & _bitmask;

    if (0 == result) {
      // #ifdef DEBUG
      // char test_string[65];
      // for (uint16_t i = 0; i < bloom->_size/8; i+=32) {
      // np_id_str(test_string, &bloom->_bitset[i]); log_msg(LOG_DEBUG, "%d:
      // check: %s --> pos=%3d (%02x <-> %02x)\n", i, test_string, _local_pos,
      // _bitmask, bloom->_bitset[_local_pos]);
      // }
      // #endif
      return (false);
    }
  }
  return (true);
}

bool _np_standard_bloom_intersect(np_bloom_t *result, np_bloom_t *first) {
  ASSERT(first->_type == standard_bf, "");
  ASSERT(first->_type == result->_type, "");
  ASSERT(first->_size == result->_size, "");
  ASSERT(first->_d == result->_d, "");
  ASSERT(first->_num_blocks == result->_num_blocks, "");

  // simplified max elements calculation
  result->_free_items =
      0; // not altered, we cannot further intersect this filter
  uint16_t i = 0;
  for (uint16_t k = 0; k < result->_size / 8 * result->_d; ++k) {
    result->_bitset[k] &= first->_bitset[k];
    if (result->_bitset[k] > 0) i++;
  }
  return (i > 0) ? true : false;
}

void _np_standard_bloom_union(np_bloom_t *result, np_bloom_t *first) {
  ASSERT(first->_type == standard_bf, "");
  ASSERT(first->_type == result->_type, "");
  ASSERT(first->_size == result->_size, "");
  ASSERT(first->_d == result->_d, "");
  ASSERT(first->_num_blocks == result->_num_blocks, "");

  // simplified max elements calculation
  ASSERT(first->_free_items + result->_free_items >= result->_size / 16, "");
  result->_free_items += (first->_free_items - result->_size / 16);

  for (uint16_t k = 0; k < result->_size / 8 * result->_d; ++k) {
    result->_bitset[k] |= first->_bitset[k];
  }
}

void _np_standard_bloom_clear(np_bloom_t *res) {
  // res->_type = standard_bf;
  // res->_d = 1;
  // res->_p = 0;
  // res->_num_blocks = 1;
  if (res->_bitset != NULL) free(res->_bitset);
  res->_bitset     = calloc(1, (res->_size / 8) * res->_d);
  res->_free_items = res->_size * res->_d / 16;

  memset(res->_bitset, 0, res->_num_blocks * res->_size * res->_d / 8);
}

np_bloom_t *_np_stable_bloom_create(size_t size, uint8_t d, uint8_t p) {

  assert(size % 2 == 0);

  np_bloom_t *res  = (np_bloom_t *)calloc(1, sizeof(np_bloom_t));
  res->_type       = stable_bf;
  res->_size       = size;
  res->_d          = d;
  res->_p          = p;
  res->_num_blocks = 1;

  np_rng_init(&res->_rng);

  res->_bitset = calloc(1, (size * res->_d) >> 3);
  // simplified max elements calculation
  res->_free_items = (size * res->_d) >> 4;

  return res;
}

void _np_stable_bloom_add(np_bloom_t *bloom, np_dhkey_t id) {

  uint32_t _killed_bits = 0;

  for (uint8_t p = 0; p < bloom->_p * bloom->_d; ++p) {

    uint32_t _as_number = np_rng_next(&bloom->_rng);

    uint32_t _bit_array_pos = _as_number & (bloom->_size - 1);
    uint32_t _local_pos     = (_bit_array_pos * bloom->_d) >> 3;
    uint8_t *_current_val   = &bloom->_bitset[_local_pos];
    if (*_current_val > 0) {
      (*_current_val) = (*_current_val) >> 1;
      _killed_bits++;
    }
  }
  _killed_bits = _killed_bits >> 3;
  while (_killed_bits > 0) {
    bloom->_free_items++;
    _killed_bits = _killed_bits >> 3;
  }

  for (uint8_t k = 0; k < 8; ++k) {
    uint32_t _bit_array_pos = id.t[k] & (bloom->_size - 1);
    uint32_t _local_pos     = (_bit_array_pos * bloom->_d) >> 3;
    uint8_t *_current_val   = &bloom->_bitset[_local_pos];
    (*_current_val) |= ((1 << bloom->_d) - 1);

    // #ifdef DEBUG
    // char test_string[65];
    // for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
    // np_id_str(test_string, &bloom->_bitset[i]);
    // log_msg(LOG_DEBUG, "%3d:   add: %s --> pos=%3d (%02x)\n", i,
    // test_string, _local_pos, bloom->_bitset[_local_pos]);
    // }
    // #endif
  }
  bloom->_free_items--;
}

bool _np_stable_bloom_check(np_bloom_t *bloom, np_dhkey_t id) {
  bool ret = true;

  for (uint8_t k = 0; k < 8; ++k) {
    uint32_t _bit_array_pos = id.t[k] & (bloom->_size - 1);
    uint32_t _local_pos     = (_bit_array_pos * bloom->_d) >> 3;
    uint8_t *_current_val   = &bloom->_bitset[_local_pos];
    if (0 == (*_current_val)) ret = false;
    // #ifdef DEBUG
    // char test_string[65];
    // for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
    //   np_id_str(test_string, &bloom->_bitset[i]);
    // log_msg(LOG_DEBUG, "%3d:   add: %s --> pos=%3d (%02x)\n", i,
    // test_string, _local_pos, bloom->_bitset[_local_pos]);
    // }
    // #endif
  }

  _np_stable_bloom_add(bloom, id);
  return (ret);
}

np_bloom_t *_np_scalable_bloom_create(size_t size) {
  np_bloom_t *res  = (np_bloom_t *)calloc(1, sizeof(np_bloom_t));
  res->_type       = scalable_bf;
  res->_size       = size;
  res->_d          = 1;
  res->_p          = 0;
  res->_num_blocks = 1;

  res->_bitset     = calloc(res->_num_blocks, (size / 8) * res->_d);
  res->_free_items = res->_size / 16;

  return res;
}

void _np_scalable_bloom_add(np_bloom_t *bloom, np_dhkey_t id) {
  if (bloom->_free_items == 0) {
    uint16_t x = (bloom->_size / 8 * bloom->_d) * bloom->_num_blocks;
    bloom->_num_blocks++;
    bloom->_bitset =
        realloc(bloom->_bitset,
                (bloom->_size / 8 * bloom->_d) * bloom->_num_blocks);
    bloom->_free_items += bloom->_size / 16;
    memset(bloom->_bitset + x, 0, bloom->_size / 8 * bloom->_d);
  }
  uint16_t bitset_offset =
      (bloom->_num_blocks - 1) * bloom->_size / 8 * bloom->_d;
  for (uint8_t k = 0; k < 8; ++k) {
    // log_msg(LOG_DEBUG, "n  : %u\n", _as_number);
    uint32_t _bit_array_pos = id.t[k] % bloom->_size;
    // log_msg(LOG_DEBUG, "bap: %d\n", _bit_array_pos);
    uint32_t _local_pos = ((_bit_array_pos) / 8);
    // log_msg(LOG_DEBUG, " lp: %d\n", _local_pos);
    uint8_t _bitmask = (0x80 >> (_bit_array_pos % 8));
    // log_msg(LOG_DEBUG, " bm: %x\n", _bitmask);
    (bloom->_bitset + bitset_offset)[_local_pos] |= _bitmask;
    // #ifdef DEBUG
    // char test_string[65];
    // np_id_str(test_string, &(bloom->_bitset+bitset_offset)[0]);
    // log_msg(LOG_DEBUG, "add  : %s --> pos=%3d (%02x <-> %02x)", test_string,
    // _local_pos, _bitmask, (bloom->_bitset+bitset_offset)[_local_pos]);
    // #endif
  }

  // #ifdef DEBUG
  // char test_string[65];
  // np_id_str(test_string, &(bloom->_bitset+bitset_offset)[0]);
  // log_msg(LOG_DEBUG, "final: %s", test_string);
  // #endif

  bloom->_free_items--;
}

bool _np_scalable_bloom_check(np_bloom_t *bloom, np_dhkey_t id) {
  bool ret_val = true;

  for (uint8_t j = 0; j < bloom->_num_blocks; j++) {
    uint16_t bitset_offset = (j)*bloom->_size / 8 * bloom->_d;
    ret_val                = true;
    for (uint8_t k = 0; k < 8; ++k) {
      uint32_t _bit_array_pos = id.t[k] % bloom->_size;
      uint32_t _local_pos     = (_bit_array_pos) / 8;
      uint8_t  _bitmask       = (0x80 >> (_bit_array_pos % 8));
      uint8_t  result = (bloom->_bitset + bitset_offset)[_local_pos] & _bitmask;

      if (0 == result) {
        // #ifdef DEBUG
        // char test_string[65];
        // for (uint16_t i = 0; i < bloom->_size/8; i+=32) {
        // np_id_str(test_string, &bloom->_bitset[i]); log_msg(LOG_DEBUG, "%d:
        // check: %s --> pos=%3d (%02x <-> %02x)\n", i, test_string, _local_pos,
        // _bitmask, bloom->_bitset[_local_pos]);
        // }
        // #endif
        ret_val = false;
      }
    }
    if (ret_val) return (ret_val);
  }
  return (ret_val);
}

np_bloom_t *_np_decaying_bloom_create(size_t size, uint8_t d, uint8_t p) {
  np_bloom_t *res = (np_bloom_t *)calloc(1, sizeof(np_bloom_t));
  res->_type      = decaying_bf;
  res->_size      = size;

  res->_d = d;
  res->_p = p;

  res->_bitset = calloc(size, res->_d / 8);
  // simplified max elements calculation
  res->_free_items = size * res->_d / 16;
  res->_num_blocks = 1;

  return res;
}

void _np_decaying_bloom_decay(np_bloom_t *bloom) {
  uint32_t _zero_bits = 0;
  for (uint16_t k = 0; k < bloom->_size; k++) {

    if (bloom->_d == 8) {
      uint8_t *_current_val = &bloom->_bitset[k * bloom->_d / 8];
      // if (*_current_val > 0) (*_current_val) = ((*_current_val) - bloom->_p);
      if (*_current_val > 0) {
        (*_current_val) = ((*_current_val) >> bloom->_p);
      }
      if (*_current_val == 0) _zero_bits++;
    } else if (bloom->_d == 16) {
      uint16_t *_current_val = &bloom->_bitset[k * bloom->_d / 8];
      // if (*_current_val > 0) (*_current_val) = ((*_current_val) - bloom->_p);
      if (*_current_val > 0) {
        (*_current_val) = ((*_current_val) >> bloom->_p);
      }
      if (*_current_val == 0) _zero_bits++;
    }
  }
  // adjust for left over bits when calculating free items
  bloom->_free_items = _zero_bits * bloom->_d / 16;

  // #ifdef DEBUG
  // char test_string[65];
  // for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
  // np_id_str(test_string, &bloom->_bitset[i]);
  // log_msg(LOG_DEBUG, "%3d:   age: %s \n", i, test_string);
  // }
  // #endif
}

void _np_decaying_bloom_add(np_bloom_t *bloom, np_dhkey_t id) {
  if (bloom->_free_items == 0) {
    ABORT("");
  }

  for (uint8_t k = 0; k < 8; k++) {
    uint32_t _bit_array_pos = id.t[k] % bloom->_size;
    uint32_t _local_pos     = _bit_array_pos * bloom->_d / 8;
    if (bloom->_d == 8) {
      uint8_t *_current_val = &bloom->_bitset[_local_pos];
      (*_current_val) |= (1 << (bloom->_d - 1));
    } else if (bloom->_d == 16) {
      uint16_t *_current_val = &bloom->_bitset[_local_pos];
      (*_current_val) |= (1 << (bloom->_d - 1));
    }

    // #ifdef DEBUG
    // char test_string[65];
    // for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
    // np_id_str(test_string, &bloom->_bitset[i]);
    // log_msg(LOG_DEBUG, "%3d:   add: %s --> pos=%3d (%02x)\n", i,
    // test_string, _local_pos, bloom->_bitset[_local_pos]);
    // }
    // #endif
  }
  bloom->_free_items--;
}

bool _np_decaying_bloom_check(np_bloom_t *bloom, np_dhkey_t id) {
  bool ret = true;

  for (uint8_t k = 0; k < 8 && ret; k++) {
    uint32_t _bit_array_pos = id.t[k] % bloom->_size;
    uint32_t _local_pos     = _bit_array_pos * bloom->_d / 8;
    if (bloom->_d == 8) {
      uint8_t *_current_val = &bloom->_bitset[_local_pos];
      if (0 == (*_current_val)) ret = false;
    }
    if (bloom->_d == 16) {
      uint16_t *_current_val = &bloom->_bitset[_local_pos];
      if (0 == (*_current_val)) ret = false;
    }
    // #ifdef DEBUG
    // char test_string[65];
    // for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
    //   np_id_str(test_string, &bloom->_bitset[i]); log_msg(LOG_DEBUG, "%3d:
    //   add: %s --> pos=%3d (%02x)\n", i, test_string, _local_pos,
    //   bloom->_bitset[_local_pos]);
    // }
    // #endif
  }
  return (ret);
}

float _np_decaying_bloom_get_heuristic(np_bloom_t *bloom, np_dhkey_t id) {
  float ret = 0.0;

  for (uint8_t k = 0; k < 8; k++) {
    uint32_t _bit_array_pos = id.t[k] % bloom->_size;
    uint32_t _local_pos     = _bit_array_pos * bloom->_d / 8;
    if (bloom->_d == 8) {
      uint8_t *_current_val = &bloom->_bitset[_local_pos];
      if (0 == (*_current_val)) {
        ret = 0.0;
        break;
      }
      uint8_t n = 1;
      while ((*_current_val >> n) > 0)
        n++;
      ret = (ret > ((float)n) / bloom->_d) ? ret : ((float)n) / bloom->_d;
    }
    if (bloom->_d == 16) {
      uint16_t *_current_val = &bloom->_bitset[_local_pos];
      if (0 == (*_current_val)) {
        ret = 0.0;
        break;
      }
      uint8_t n = 1;
      while ((*_current_val >> n) > 0)
        n++;
      ret = ret > ((float)n) / bloom->_d ? ret : ((float)n) / bloom->_d;
    }
    // #ifdef DEBUG
    // char test_string[65];
    // for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
    //   np_id_str(test_string, &bloom->_bitset[i]); log_msg(LOG_DEBUG, "%3d:
    //   add: %s --> pos=%3d (%02x)\n", i, test_string, _local_pos,
    //   bloom->_bitset[_local_pos]);
    // }
    // #endif
  }
  return (ret);
}

// a simple counting bloom filter
np_bloom_t *_np_counting_bloom_create(size_t size, uint8_t d, uint8_t p) {

  np_bloom_t *res = (np_bloom_t *)calloc(1, sizeof(np_bloom_t));
  res->_type      = counting_bf;
  res->_size      = size;

  res->_d = d;
  res->_p = p;

  res->_bitset = calloc(size, res->_d >> 3);
  // simplified max elements calculation
  res->_free_items = size * res->_d >> 4;
  res->_num_blocks = 1;

  return res;
}

void _np_counting_bloom_clear(np_bloom_t *res) {
  memset(res->_bitset, 0, (res->_num_blocks * res->_size * res->_d) >> 3);
  res->_free_items = (res->_size * res->_d) >> 4;
}

void _np_counting_bloom_clear_r(np_bloom_t *res, uint32_t *item_count) {
  uint32_t zeroed_blocks = 1;
  for (size_t k = 0; k < (res->_num_blocks * res->_size * res->_d) >> 3; k++) {
    if (res->_bitset[k] == 1) zeroed_blocks++;
    res->_bitset[k] >>= res->_p;
    *item_count = res->_bitset[k] > *item_count ? res->_bitset[k] : *item_count;
  }

  res->_free_items += (*item_count * zeroed_blocks) << res->_p;
  if (res->_free_items > ((res->_size * res->_d) >> 4))
    res->_free_items = ((res->_size * res->_d) >> 4);
}

void _np_counting_bloom_add(np_bloom_t *bloom, np_dhkey_t id) {
  if (bloom->_free_items == 0) {
    ABORT("");
  }

  for (uint8_t k = 0; k < 8; ++k) {
    uint32_t _bit_array_pos = id.t[k] % bloom->_size;
    uint32_t _local_pos     = _bit_array_pos * bloom->_d >> 3;
    uint8_t *_current_val   = &bloom->_bitset[_local_pos];
    (*_current_val)++;

    // #ifdef DEBUG
    // char test_string[65];
    // for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
    // np_id_str(test_string, &bloom->_bitset[i]);
    // log_msg(LOG_DEBUG, "%3d:   add: %s --> pos=%3d (%02x)\n", i,
    // test_string, _local_pos, bloom->_bitset[_local_pos]);
    // }
    // #endif
  }
  bloom->_free_items--;
}

void _np_counting_bloom_remove(np_bloom_t *bloom, np_dhkey_t id) {
  if (bloom->_free_items == 0) {
    ABORT("");
  }

  for (uint8_t k = 0; k < 8; ++k) {
    uint32_t _bit_array_pos = id.t[k] % bloom->_size;
    uint32_t _local_pos     = _bit_array_pos * bloom->_d >> 3;
    uint8_t *_current_val   = &bloom->_bitset[_local_pos];
    (*_current_val)--;

    // #ifdef DEBUG
    // char test_string[65];
    // for (size_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
    // np_id_str(test_string, &bloom->_bitset[i]);
    // log_msg(LOG_DEBUG, "%3d:   add: %s --> pos=%3d (%02x)\n", i,
    // test_string, _local_pos, bloom->_bitset[_local_pos]);
    // }
    // #endif
  }
  bloom->_free_items++;
}

bool _np_counting_bloom_check(np_bloom_t *bloom, np_dhkey_t id) {
  bool ret = true;

  for (uint8_t k = 0; k < 8; ++k) {
    uint32_t _bit_array_pos = id.t[k] % bloom->_size;
    uint32_t _local_pos     = _bit_array_pos * bloom->_d >> 3;
    uint8_t *_current_val   = &bloom->_bitset[_local_pos];
    if (0 == (*_current_val) || UINT8_MAX == (*_current_val)) ret = false;
    // #ifdef DEBUG
    // char test_string[65];
    // for (size_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
    //   np_id_str(test_string, &bloom->_bitset[i]); log_msg(LOG_DEBUG,
    //   "%3d: add: %s --> pos=%3d (%02x)\n", i, test_string, _local_pos,
    //   bloom->_bitset[_local_pos]);
    // }
    // #endif
  }
  return (ret);
}

void _np_counting_bloom_check_r(np_bloom_t *bloom,
                                np_dhkey_t  id,
                                uint32_t   *count) {

  for (uint8_t k = 0; k < 8; ++k) {
    uint32_t _bit_array_pos = id.t[k] & (bloom->_size - 1);
    uint32_t _local_pos     = _bit_array_pos * bloom->_d >> 3;
    uint8_t *_current_val   = &bloom->_bitset[_local_pos];
    if (0 == (*_current_val) || UINT8_MAX == (*_current_val)) return;

    *count = (*_current_val > *count) ? (*_current_val) : (*count);
    // #ifdef DEBUG
    // char test_string[65];
    // for (size_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
    //   np_id_str(test_string, &bloom->_bitset[i]); log_msg(LOG_DEBUG,
    //   "%3d: add: %s --> pos=%3d (%02x)\n", i, test_string, _local_pos,
    //   bloom->_bitset[_local_pos]);
    // }
    // #endif
  }
}

void _np_counting_bloom_containment(np_bloom_t *first,
                                    np_bloom_t *second,
                                    float      *result) {
  // containment only uses the number of query elements (of first) for the
  // union count
  uint16_t union_count        = 0;
  uint16_t intersection_count = 0; // prevent division by zero in line 773

  for (size_t k = 0; k < first->_num_blocks * first->_size * first->_d / 8;
       k++) {
    union_count += (first->_bitset[k] > 0) ? 1 : 0;

    intersection_count += ((first->_bitset[k] > 0 && second->_bitset[k] > 0) &&
                           (first->_bitset[k] == second->_bitset[k]))
                              ? 1
                              : 0;
  }

  if (union_count > 0) *result = ((float)intersection_count) / union_count;
  else *result = 0.0;

  // fprintf(stdout, "bloom: union: %02d --> intersection: %02d --> result:
  // %f\n", union_count, intersection_count, *result);

  /*
  fprintf(stdout, "%4d:union: %02x%02x --> %02x%02x\n", k,
                  first->_bitset[k  ], first->_bitset[k+1],
                  second->_bitset[k  ], second->_bitset[k+1]);
  */
}

// neuropil bloom filter size calculation:
// p(nbf) = (1-e^(- n/m))^k        // many thanks for the formulas!
// p(nbf) = (1-e^(- n/m))^4        // k = 4 --> four 3dbf per filter
// p(nbf) = (1-e^(-32/m))^4        // n = 32 --> target to insert 32 elements
// per filter p(nbf) = (1-e^(-32/(3*5*7)))^4  // m = X*Y*Z --> 3*5*7 (?) p(nbf)
// = 0,004762637855         // error probablilty would be 4 in 1000, too low
// imho p(nbf) = (1-e^(-32/(3*5*11)))^4 // m = X*Y*Z --> 3*5*11 (?) p(nbf) =
// 0,0009658999622        // better, approx one in 1000 p(nbf) =
// (1-e^(-32/(3*5*13)))^4 // m = X*Y*Z --> 3*5*13 p(nbf) = 0,000524653516 //
// better, approx one in 2000 but still possible to transport
//                                 // one neuropil bf (32 different subjects)
//                                 with one message chunk
// and we use counting (8bits) per position ...

#define SCALE3D_X 3
#define SCALE3D_Y 5
#define SCALE3D_Z 17

#define SCALE3D_FREE_ITEMS 64 // upper limit of items per neuropil bloom filter

np_bloom_t *_np_neuropil_bloom_create() {
  np_bloom_t *res = (np_bloom_t *)calloc(1, sizeof(np_bloom_t));
  res->_type      = neuropil_bf;
  res->_size      = SCALE3D_X * SCALE3D_Y * SCALE3D_Z; // size of each block
  res->_d = 16; // size of counting and aging bit field (1byte aging and 1byte
                // counting)
  res->_p          = 0; //
  res->_num_blocks = 4;

  res->_bitset = calloc(res->_num_blocks, res->_size * res->_d / 8); //
  // simplified max elements calculation
  res->_free_items = SCALE3D_FREE_ITEMS;

  return res;
}

void _np_neuropil_bloom_clear(np_bloom_t *res) {
  res->_type = neuropil_bf;
  res->_size = SCALE3D_X * SCALE3D_Y * SCALE3D_Z; // size of each block
  res->_d = 16; // size of counting and aging bit field (1byte aging and 1byte
                // counting)
  res->_p          = 0;
  res->_num_blocks = 4;

  memset(res->_bitset, 0, res->_num_blocks * res->_size * res->_d / 8);
  res->_free_items = SCALE3D_FREE_ITEMS;
}

void _np_neuropil_bloom_add(np_bloom_t *bloom, np_dhkey_t id) {
  if (bloom->_free_items == 0) {
    ABORT("");
  }

  uint8_t  block_index = 1;
  uint16_t block_size  = (bloom->_size * bloom->_d) / 8;

  for (uint8_t k = 0; k < 8; ++k) {
    uint32_t _bit_array_pos = (id.t[k] % SCALE3D_X + 1) *
                              (id.t[k] % SCALE3D_Y + 1) *
                              (id.t[k] % SCALE3D_Z + 1);
    uint32_t _local_pos =
        (block_index - 1) * block_size + (_bit_array_pos - 1) * 2;
    uint8_t *_current_age   = &bloom->_bitset[_local_pos];
    uint8_t *_current_count = &bloom->_bitset[_local_pos + 1];
    (*_current_age) |= (1 << ((bloom->_d >> 1) - 1));
    // e.g. bloom_d = 16:
    // 16 / 2 = 8 --> 8-bit for each sender/receiver
    // 0000000000000000000000000000001 =>
    // 0000000000000000000000010000000 => 10000000
    // cannot use  a constant because of variable size of d
    (*_current_count)++;

#ifdef DEBUG
    /*char test_string[65];
    for (uint16_t i = (block_index-1)*block_size; i < block_index*block_size;
    i+=32 ) { np_id_str(test_string, &bloom->_bitset[i]); fprintf(stdout, "%3d:
    add: %s --> pos=%3d (%02x%02x)\n", i, test_string, _local_pos,
    bloom->_bitset[_local_pos*2], bloom->_bitset[_local_pos*2+1]);
    }*/
#endif
    if ((k + 1) % 2 == 0) block_index++;
  }
  // fprintf(stdout, "\n");
  bloom->_free_items--;
}

void _np_neuropil_bloom_remove(np_bloom_t *bloom, np_dhkey_t id) {
  if (bloom->_free_items == 0) {
    ABORT("");
  }

  uint8_t  block_index = 1;
  uint16_t block_size  = (bloom->_size * bloom->_d) / 8;

  for (uint8_t k = 0; k < 8; ++k) {
    uint32_t _bit_array_pos = (id.t[k] % SCALE3D_X + 1) *
                              (id.t[k] % SCALE3D_Y + 1) *
                              (id.t[k] % SCALE3D_Z + 1);
    uint32_t _local_pos =
        (block_index - 1) * block_size + (_bit_array_pos - 1) * 2;
    uint8_t *_current_age   = &bloom->_bitset[_local_pos];
    uint8_t *_current_count = &bloom->_bitset[_local_pos + 1];
    (*_current_age)         = (*_current_age) >> 1;
    (*_current_count)--;

#ifdef DEBUG
    /*char test_string[65];
    for (uint16_t i = (block_index-1)*block_size; i < block_index*block_size;
    i+=32 ) { np_id_str(test_string, &bloom->_bitset[i]); fprintf(stdout, "%3d:
    add: %s --> pos=%3d (%02x%02x)\n", i, test_string, _local_pos,
    bloom->_bitset[_local_pos*2], bloom->_bitset[_local_pos*2+1]);
    }*/
#endif
    if ((k + 1) % 2 == 0) block_index++;
  }
  // fprintf(stdout, "\n");
  bloom->_free_items++;
}

bool _np_neuropil_bloom_check(np_bloom_t *bloom, np_dhkey_t id) {
  bool ret = true;

  uint8_t  block_index = 1;
  uint16_t block_size  = (bloom->_size * bloom->_d / 8);

  for (uint8_t k = 0; k < 8; ++k) {
    uint32_t _bit_array_pos =
        ((id.t[k] % SCALE3D_X + 1) * (id.t[k] % SCALE3D_Y + 1) *
         (id.t[k] % SCALE3D_Z + 1));
    uint32_t _local_pos =
        (block_index - 1) * block_size + (_bit_array_pos - 1) * 2;
    uint8_t *_current_age   = &bloom->_bitset[_local_pos];
    uint8_t *_current_count = &bloom->_bitset[_local_pos + 1];

    // check both fields for bit being set
    if (0 == (*_current_age) || 0 == (*_current_count)) ret = false;

#ifdef DEBUG
      /*char test_string[65];
      for (uint16_t i = (block_index-1)*block_size; i < block_index*block_size;
      i+=32 ) { np_id_str(test_string, &bloom->_bitset[i]); fprintf(stdout,
      "%3d: check: %s --> pos=%3d (%02x%02x)\n", i, test_string, _local_pos,
      bloom->_bitset[_local_pos*2], bloom->_bitset[_local_pos*2+1]);
      }*/
#endif
    if ((k + 1) % 2 == 0) block_index++;
  }
#ifdef DEBUG
  // fprintf(stdout, "\n");
#endif
  return (ret);
}

void _np_neuropil_bloom_age_decrement(np_bloom_t *bloom) {
  uint16_t block_size = (bloom->_size * bloom->_d >> 3);
  for (uint16_t k = 0; k < block_size * bloom->_num_blocks; k += 2) {
    uint8_t *_current_age = &bloom->_bitset[k];
    if (*_current_age > bloom->_d >> 1) {
      (*_current_age) -= (bloom->_d >> 1);
      // (*_current_age) = ((*_current_age) >> 1);
    } else {
      (*_current_age) = 0;
    }
  }
}

void _np_neuropil_bloom_age_increment(np_bloom_t *bloom) {
  uint16_t block_size = (bloom->_size * bloom->_d / 8);

  for (uint16_t k = 0; k < block_size * bloom->_num_blocks; k += 2) {
    uint8_t *_current_age = &bloom->_bitset[k];
    if (*_current_age < UINT8_MAX - (bloom->_d >> 1)) {
      (*_current_age) += (bloom->_d >> 1);
      // (*_current_age) = ((*_current_age) >> 1);
    } else {
      (*_current_age) = UINT8_MAX;
    }
  }
}

void _np_neuropil_bloom_count_decrement(np_bloom_t *bloom) {
  if (bloom->_free_items < SCALE3D_FREE_ITEMS) {
    uint16_t block_size = (bloom->_size * bloom->_d / 8);

    for (uint16_t k = 0; k < block_size * bloom->_num_blocks; k += 2) {
      uint8_t *_current_count = &bloom->_bitset[k + 1];
      if (*_current_count > 0) (*_current_count)--;
    }
    bloom->_free_items++;
  }
}

float _np_neuropil_bloom_get_heuristic(np_bloom_t *bloom, np_dhkey_t id) {
  float ret = 1.0;

  uint8_t  block_index = 1;
  uint16_t block_size  = (bloom->_size * bloom->_d / 8);

  for (uint8_t k = 0; k < 8; ++k) {
    uint32_t _bit_array_pos =
        ((id.t[k] % SCALE3D_X + 1) * (id.t[k] % SCALE3D_Y + 1) *
         (id.t[k] % SCALE3D_Z + 1));
    uint32_t _local_pos =
        (block_index - 1) * block_size + (_bit_array_pos - 1) * 2;
    uint8_t _current_age   = bloom->_bitset[_local_pos];
    uint8_t _current_count = bloom->_bitset[_local_pos + 1];

    if (0 == _current_count) {
      ret = 0.0;
      break;
    }
    ret = ret < ((float)_current_age) / (256) ? ret
                                              : ((float)_current_age) / (256);

#ifdef DEBUG
    /*char test_string[65];
    for (uint16_t i = (block_index-1)*block_size; i < block_index*block_size;
    i+=32 ) { np_id_str(test_string, &bloom->_bitset[i]); fprintf(stdout, "%3d:
    check: %s --> pos=%3d (%02x%02x)\n", i, test_string, _local_pos,
    bloom->_bitset[_local_pos*2], bloom->_bitset[_local_pos*2+1]);
    }*/
#endif

    if ((k + 1) % 2 == 0) block_index++;
  }
  return (ret);
}

bool _np_neuropil_bloom_intersect(np_bloom_t *result,
                                  np_bloom_t *to_intersect) {
  ASSERT(result->_type == neuropil_bf, "");
  ASSERT(result->_type == to_intersect->_type, "");
  ASSERT(result->_size == SCALE3D_X * SCALE3D_Y * SCALE3D_Z, "");
  ASSERT(result->_size == to_intersect->_size, "");
  ASSERT(result->_d == to_intersect->_d, "");
  ASSERT(result->_num_blocks == to_intersect->_num_blocks, "");
  ASSERT(to_intersect->_free_items + result->_free_items >= SCALE3D_FREE_ITEMS,
         "");

  result->_free_items =
      0; // an intersection cannot be used for further data addition
  uint16_t i = 0;
  for (uint16_t k = 0; k < result->_num_blocks * result->_size * result->_d / 8;
       k += 2) {
    // result->_bitset[k] &= to_intersect->_bitset[k];
    result->_bitset[k] = result->_bitset[k] > to_intersect->_bitset[k]
                             ? to_intersect->_bitset[k]
                             : result->_bitset[k];
    if ((result->_bitset[k] > 0)) { // only add if an "age" is left
      result->_bitset[k + 1] += to_intersect->_bitset[k + 1];
      i++;
    }
    /*
    fprintf(stdout, "%4d:union: %02x%02x --> %02x%02x\n", k,
                    result->_bitset[k  ], result->_bitset[k+1],
                    to_intersect->_bitset[k  ], to_intersect->_bitset[k+1]);
    */
  }
  return (i > 0) ? true : false;
}

bool _np_neuropil_bloom_intersect_test(np_bloom_t *result,
                                       np_bloom_t *to_intersect) {
  ASSERT(result->_type == neuropil_bf, "");
  ASSERT(result->_type == to_intersect->_type, "");
  ASSERT(result->_size == SCALE3D_X * SCALE3D_Y * SCALE3D_Z, "");
  ASSERT(result->_size == to_intersect->_size, "");
  ASSERT(result->_d == to_intersect->_d, "");
  ASSERT(result->_num_blocks == to_intersect->_num_blocks, "");

  uint16_t i = 0, j = 0;

  for (uint16_t k = 0; k < result->_num_blocks * result->_size * result->_d / 8;
       k += 2) {
    // only test whether to_intersect is contained in result
    if (result->_bitset[k] > 0 &&
        to_intersect->_bitset[k] > 0) { // only add if an "age" is left
      i += to_intersect->_bitset[k + 1];
      if (result->_bitset[k + 1] >= to_intersect->_bitset[k + 1])
        j += to_intersect->_bitset[k + 1];
    }

    if ((result->_bitset[k] > 0 && to_intersect->_bitset[k] == 0) ||
        (result->_bitset[k] == 0 && to_intersect->_bitset[k] > 0)) {
      return false;
    }
    /*
    fprintf(stdout, "%4d:union: %02x%02x --> %02x%02x\n", k,
                    result->_bitset[k  ], result->_bitset[k+1],
                    to_intersect->_bitset[k  ], to_intersect->_bitset[k+1]);
    */
  }

  return (i == j) ? true : false;
}

float _np_neuropil_bloom_intersect_age(np_bloom_t *result,
                                       np_bloom_t *to_intersect) {
  ASSERT(result->_type == neuropil_bf, "type is %" PRIu8, result->_type);
  ASSERT(result->_type == to_intersect->_type,
         "intersect type is %" PRIu8,
         to_intersect->_type);
  ASSERT(result->_size == SCALE3D_X * SCALE3D_Y * SCALE3D_Z,
         " size is %" PRIsizet,
         result->_size);
  ASSERT(result->_size == to_intersect->_size,
         "intersect size is %" PRIsizet,
         to_intersect->_size);
  ASSERT(result->_d == to_intersect->_d, "");
  ASSERT(result->_num_blocks == to_intersect->_num_blocks, "");

  float   ret = 1.0;
  uint8_t i   = 0;

  for (uint16_t k = 0; k < result->_num_blocks * result->_size * result->_d / 8;
       k += 2) {
    // only test whether to_intersect is contained in result
    if (to_intersect->_bitset[k] > 0) {
      i += to_intersect->_bitset[k + 1];
      if (result->_bitset[k] > 0) { // only add if an "age" is left
        ret = (ret < (((float)result->_bitset[k]) / (256)))
                  ? ret
                  : ((float)result->_bitset[k]) / (256);
      } else if (result->_bitset[k] == 0) {
        ret = 0.0;
      }
    }
    /*
    fprintf(stdout, "%4d:union: %02x%02x --> %02x%02x\n", k,
                    result->_bitset[k  ], result->_bitset[k+1],
                    to_intersect->_bitset[k  ], to_intersect->_bitset[k+1]);
    */
  }

  if (i == 0) ret = 0.0;

  return ret;
}

bool _np_neuropil_bloom_intersect_ignore_age(np_bloom_t *result,
                                             np_bloom_t *to_intersect) {
  ASSERT(result->_type == neuropil_bf, "");
  ASSERT(result->_type == to_intersect->_type, "");
  ASSERT(result->_size == SCALE3D_X * SCALE3D_Y * SCALE3D_Z, "");
  ASSERT(result->_size == to_intersect->_size, "");
  ASSERT(result->_d == to_intersect->_d, "");
  ASSERT(result->_num_blocks == to_intersect->_num_blocks, "");
  ASSERT(to_intersect->_free_items + result->_free_items >= SCALE3D_FREE_ITEMS,
         "");

  result->_free_items =
      0; // an intersection cannot be used for further data addition
  uint16_t i = 0;
  for (uint16_t k = 0; k < result->_num_blocks * result->_size * result->_d / 8;
       k += 2) {
    if (result->_bitset[k + 1] > 0 && to_intersect->_bitset[k + 1] > 0)
      result->_bitset[k + 1] += to_intersect->_bitset[k + 1];
    else result->_bitset[k + 1] = 0;
    i++;
  }
  return (i > 0) ? true : false;
}

void _np_neuropil_bloom_union(np_bloom_t *result, np_bloom_t *to_add) {
  ASSERT(result->_type == neuropil_bf, "");
  ASSERT(result->_type == to_add->_type, "");
  ASSERT(result->_size == SCALE3D_X * SCALE3D_Y * SCALE3D_Z, "");
  ASSERT(result->_size == to_add->_size, "");
  ASSERT(result->_d == to_add->_d, "");
  ASSERT(result->_num_blocks == to_add->_num_blocks, "");
  ASSERT(((SCALE3D_FREE_ITEMS - result->_free_items) +
          (SCALE3D_FREE_ITEMS - to_add->_free_items)) <= SCALE3D_FREE_ITEMS,
         "");
  result->_free_items =
      result->_free_items + to_add->_free_items - SCALE3D_FREE_ITEMS;

  for (uint16_t k = 0; k < result->_num_blocks * result->_size * result->_d / 8;
       k += 2) {
    // result->_bitset[k] |= to_add->_bitset[k];
    uint16_t temp      = result->_bitset[k] + to_add->_bitset[k];
    result->_bitset[k] = (temp >= UINT8_MAX) ? UINT8_MAX : (uint8_t)temp;

    result->_bitset[k + 1] += to_add->_bitset[k + 1];
    /*
    fprintf(stdout, "%4d:union: %02x%02x --> %02x%02x\n", k,
                    result->_bitset[k  ], result->_bitset[k+1],
                    to_add->_bitset[k  ], to_add->_bitset[k+1]);
    */
  }
}

void _np_neuropil_bloom_similarity(np_bloom_t *first,
                                   np_bloom_t *second,
                                   float      *result) {
  ASSERT(first->_type == neuropil_bf, "");
  ASSERT(first->_type == second->_type, "");
  ASSERT(first->_size == SCALE3D_X * SCALE3D_Y * SCALE3D_Z, "");
  ASSERT(first->_size == second->_size, "");
  ASSERT(first->_d == second->_d, "");
  ASSERT(first->_num_blocks == second->_num_blocks, "");
  ASSERT(first->_free_items <= SCALE3D_FREE_ITEMS, "");
  ASSERT(second->_free_items <= SCALE3D_FREE_ITEMS, "");

  uint16_t union_count        = 0;
  uint16_t intersection_count = 0; // prevent division by zero in line 773

  for (uint16_t k = 0; k < first->_num_blocks * first->_size * first->_d / 8;
       k += 2) {

    if (first->_bitset[k + 1] > 0 || second->_bitset[k + 1] > 0) {

      union_count += first->_bitset[k + 1] >= second->_bitset[k + 1]
                         ? first->_bitset[k + 1]
                         : 0;
      union_count += first->_bitset[k + 1] < second->_bitset[k + 1]
                         ? second->_bitset[k + 1]
                         : 0;
      if (first->_bitset[k + 1] > 0 && second->_bitset[k + 1] > 0) {
        intersection_count += (first->_bitset[k + 1] >= second->_bitset[k + 1])
                                  ? second->_bitset[k + 1]
                                  : 0;
        intersection_count += (first->_bitset[k + 1] < second->_bitset[k + 1])
                                  ? first->_bitset[k + 1]
                                  : 0;
      }
    }
  }

  if (union_count > 0) *result = ((float)intersection_count) / union_count;
  else *result = 0.0;

  // fprintf(stdout,
  //         "bloom: union: %02d --> intersection: %02d --> result: %f\n",
  //         union_count,
  //         intersection_count,
  //         *result);

  /*
  fprintf(stdout, "%4d:union: %02x%02x --> %02x%02x\n", k,
                  first->_bitset[k  ], first->_bitset[k+1],
                  second->_bitset[k  ], second->_bitset[k+1]);
  */
}

void _np_neuropil_bloom_containment(np_bloom_t *first,
                                    np_bloom_t *second,
                                    bool       *result) {
  // containment only uses the number of query elements (of first) for the
  // union count
  ASSERT(first->_type == neuropil_bf, "");
  ASSERT(first->_type == second->_type, "");
  ASSERT(first->_size == SCALE3D_X * SCALE3D_Y * SCALE3D_Z, "");
  ASSERT(first->_size == second->_size, "");
  ASSERT(first->_d == second->_d, "");
  ASSERT(first->_num_blocks == second->_num_blocks, "");
  ASSERT(first->_free_items <= SCALE3D_FREE_ITEMS, "");
  ASSERT(second->_free_items <= SCALE3D_FREE_ITEMS, "");

  uint16_t second_count = 0;
  uint16_t first_count  = 0; // prevent division by zero in line 773

  for (uint16_t k = 0; k < first->_num_blocks * first->_size * first->_d / 8;
       k += 2) {
    if (second->_bitset[k + 1] > 0) {
      second_count++;
      first_count += (second->_bitset[k + 1] <= first->_bitset[k + 1]) ? 1 : 0;
    }
  }

  *result = (first_count == second_count);

  /*
  fprintf(stdout, "%4d:union: %02x%02x --> %02x%02x\n", k,
                  first->_bitset[k  ], first->_bitset[k+1],
                  second->_bitset[k  ], second->_bitset[k+1]);
  */
}

void _np_neuropil_bloom_serialize(np_bloom_t     *filter,
                                  unsigned char **to,
                                  uint16_t       *to_size) {
  np_tree_t *data = np_tree_create();

  np_tree_insert_int(data, -1, np_treeval_new_ui(filter->_free_items));

  for (uint16_t k = 0; k < filter->_num_blocks * filter->_size * filter->_d / 8;
       k += 2) {
    if ((filter->_bitset[k] > 0) && (filter->_bitset[k + 1] > 0)) {
      np_tree_insert_int(
          data,
          k,
          np_treeval_new_iarray(filter->_bitset[k], filter->_bitset[k + 1]));
    }
  }

  size_t data_length = np_tree_get_byte_size(data);
  // np_serializer_add_map_bytesize(data, &data_length);
  *to      = malloc(data_length);
  *to_size = data_length;
  np_tree2buffer(NULL, data, *to);

  np_tree_free(data);
}

void _np_neuropil_bloom_deserialize(np_bloom_t    *filter,
                                    unsigned char *from,
                                    uint16_t       from_size) {
  np_tree_t *data = np_tree_create();
  np_buffer2tree(NULL, from, from_size, data);

  filter->_free_items = np_tree_find_int(data, -1)->val.value.ui;
  np_tree_del_int(data, -1);

  np_tree_elem_t *iter = RB_MIN(np_tree_s, data);
  while (iter != NULL) {
    uint16_t pos = iter->key.value.ui;
    ASSERT(pos >= 0, "");
    ASSERT(pos < filter->_num_blocks * filter->_size * filter->_d / 8, "");
    filter->_bitset[pos]     = (uint8_t)iter->val.value.a2_ui[0];
    filter->_bitset[pos + 1] = (uint8_t)iter->val.value.a2_ui[1];

    iter = RB_NEXT(np_tree_s, data, iter);
  }
  np_tree_free(data);
}

void _np_neuropil_bloom_compress(np_bloom_t     *filter,
                                 unsigned char **to,
                                 size_t         *to_size) {
  ASSERT(*to_size == 0, "");
  ASSERT(to != NULL, "");
  ASSERT(*to == NULL, "");

  size_t   single_entry_size      = sizeof(uint16_t) + 2 * sizeof(uint8_t);
  uint8_t *_compressed_array      = NULL;
  size_t   _compressed_array_size = *to_size;

  uint16_t k = 0, j = 0;
  for (k = 0; k < filter->_num_blocks * filter->_size * filter->_d / 8;
       k += 2, j++) {
    if ((filter->_bitset[k] > 0) && (filter->_bitset[k + 1] > 0)) {
      _compressed_array_size += single_entry_size;
      _compressed_array = realloc(_compressed_array, _compressed_array_size);

      memcpy(&_compressed_array[_compressed_array_size - 4],
             &j,
             sizeof(uint16_t));
      _compressed_array[_compressed_array_size - 2] = filter->_bitset[k];
      _compressed_array[_compressed_array_size - 1] = filter->_bitset[k + 1];

      // uint16_t* pos = &_compressed_array[_compressed_array_size-4];
      // fprintf(stdout,
      //         " (%d)
      //         (%"PRIu16":%"PRIu8":%"PRIu8":%"PRIu16":%"PRIu8":%"PRIu8")
      //         ...\n", _compressed_array_size, k,   filter->_bitset[k  ],
      //         filter->_bitset[k+1], *pos,
      //         _compressed_array[_compressed_array_size-2],
      //         _compressed_array[_compressed_array_size-1] );
    }
  }

  if (_compressed_array_size < 32) {
    _compressed_array = realloc(_compressed_array, 32);
    memset(_compressed_array + _compressed_array_size,
           0,
           32 - _compressed_array_size);
    _compressed_array_size = 32;
  }

  *to      = _compressed_array;
  *to_size = _compressed_array_size;
}

int _np_neuropil_bloom_cmp(np_bloom_t *a, np_bloom_t *b) {
  int ret = 0;

  ASSERT(a->_type == neuropil_bf, "");
  ASSERT(a->_type == b->_type, "");
  ASSERT(a->_size == SCALE3D_X * SCALE3D_Y * SCALE3D_Z, "");
  ASSERT(a->_size == b->_size, "");
  ASSERT(a->_d == b->_d, "");
  ASSERT(a->_num_blocks == b->_num_blocks, "");

  for (uint16_t k = 0; k < a->_num_blocks * a->_size * a->_d / 8; k += 2) {
    if ((a->_bitset[k + 1] == 0 && b->_bitset[k + 1] > 0) ||
        (b->_bitset[k + 1] == 0 && a->_bitset[k + 1] > 0)) {
      ret = -1;
      break;
    }
  }
  return ret;
}
