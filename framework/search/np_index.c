//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// neuropil is copyright 2016-2022 by pi-lar GmbH
//

#include "search/np_index.h"

void _np_index_simple_update_with_dhkey(np_index_t *index,
                                        np_dhkey_t  test_dhkey) {
  _np_counting_bloom_add(index->_cbl_index, test_dhkey);
  // _np_neuropil_bloom_add(index->_clk_hash, test_dhkey);
}

void _split_minhash_into_bands(np_index_t         *index,
                               const np_minhash_t *minhash,
                               uint8_t             in_bands) {
  ASSERT(in_bands <= (minhash->size / 8),
         "number of bands has to be equal or lower than %u",
         (minhash->size / 8));
  ASSERT(0 == (minhash->size / 8) % in_bands,
         "modulo calculation of number of bands has to be zero");

  uint16_t var_bands = minhash->size / 8 / in_bands;
  uint16_t var_rows  = minhash->size / 8 / var_bands;

  np_dhkey_t _null = {0};
  np_dhkey_t _index_dhkeys[var_bands];

  for (uint8_t i = 0; i < var_bands; i++)
    _np_dhkey_assign(&_index_dhkeys[i], &_null);

  uint16_t _row = 0, _band = 0, _k = 0;
  for (uint16_t j = 0; j < minhash->size; j++) {
    if (j > 0 && 0 == (j % 8)) {
      _band++;
      _k = 0;
    }
    if (_band > 0 && 0 == (_band % var_bands)) {
      _row++;
      _band = 0;
    }
    // fprintf(stdout, "    LSH %u(%u):%u(%u) => %u (%u) to dhkey at %u/%u",
    // _band, var_bands, _row, var_rows, j, minhash->minimums[j], _band, _k);
    _index_dhkeys[_band].t[_k] += minhash->minimums[j];

    _k++;

    if (_row == var_rows - 1 && _k == 8) {
      index->_clk_hash->op.add_cb(index->_clk_hash, _index_dhkeys[_band]);
    }
    // else { fprintf(stdout, "\n"); }
  }

  for (uint8_t i = 0; i < var_bands; i++) {
    for (uint8_t j = 0; j < var_rows; j++) {
      _np_index_simple_update_with_dhkey(index, _index_dhkeys[i]);
    }
    _np_counting_bloom_add(index->_cbl_index_counter, _index_dhkeys[i]);
  }
}

void np_index_init(np_index_t *index) {
  np_dhkey_t _null = {0};
  // _np_dhkey_assign(&index->upper_dhkey, &_null);
  _np_dhkey_assign(&index->lower_dhkey, &_null);

  index->_cbl_index = _np_counting_bloom_create((5 * 17), 8, 0);
  index->_cbl_index->_free_items =
      (5 * 17) * 8 / 2; // the filter is not used as a bloom filter, bu rather a
                        // countmin sketch
  index->_cbl_index_counter = _np_counting_bloom_create((5 * 17), 8, 0);
  index->_cbl_index_counter->_free_items =
      (5 * 17) * 8 / 2; // the filter is not used as a bloom filter, but rather
                        // a countmin sketch

  index->_clk_hash                           = _np_neuropil_bloom_create();
  struct np_bloom_optable_s index_operations = {
      .add_cb       = _np_neuropil_bloom_add,
      .check_cb     = _np_neuropil_bloom_check,
      .clear_cb     = _np_neuropil_bloom_clear,
      .union_cb     = _np_neuropil_bloom_union,
      .intersect_cb = _np_neuropil_bloom_intersect,
  };
  index->_clk_hash->op = index_operations;
}

void np_index_destroy(np_index_t *index) {
  if (index->_cbl_index) _np_bloom_free(index->_cbl_index);
  if (index->_clk_hash) _np_bloom_free(index->_clk_hash);
  if (index->_cbl_index_counter) _np_bloom_free(index->_cbl_index_counter);
}

void np_index_update_with_minhash(np_index_t *index, np_minhash_t *min_hash) {
  uint8_t bands = min_hash->size / 8;
  while (bands > 1) {
    _split_minhash_into_bands(index, min_hash, bands);
    bands = bands >> 1;
  }
}

void np_index_update_with_dhkey(np_index_t *index, np_dhkey_t test_dhkey) {
  _np_counting_bloom_add(index->_cbl_index, test_dhkey);
  _np_counting_bloom_add(index->_cbl_index_counter, test_dhkey);

  _np_neuropil_bloom_add(index->_clk_hash, test_dhkey);
}

// int __compare(uint8_t* first, uint8_t* second)
int __compare(const void *left, const void *right) {
  uint8_t *first  = (uint8_t *)left;
  uint8_t *second = (uint8_t *)right;

  if (*first > *second) return 1;
  if (*first < *second) return -1;
  return 0;
}

int __compare_uint32_t(uint32_t *first, uint32_t *second) {
  if (*first > *second) return 1;
  if (*first < *second) return -1;
  return 0;
}

union np_x24_t {
  uint32_t _as_u32;
  uint8_t  _as_u8a[4];
};

void np_index_hash(np_index_t *index) {
  // np_ctx_memory(index);
  np_bloom_t *counting_bloom = index->_cbl_index;

  uint16_t cb_size = counting_bloom->_size * counting_bloom->_d / 8;
  uint8_t  _cb_values[cb_size];

  // for (uint8_t k = 0; k < cb_size; k++)
  // {
  //     if (index->_cbl_index_counter->_bitset[k] == 1) // only one hit -->
  //     evict this data item from index calculation
  //     {
  //         index->_cbl_index->_bitset[k] = 0;
  //     }
  // }
  // fprintf(stdout, "_cbl_index: \n");
  for (uint8_t k = 0; k < cb_size; k++) {
    uint32_t _local_pos = k;
    _cb_values[k]       = counting_bloom->_bitset[_local_pos];
    // if (k%16 == 0 && k > 0) fprintf(stdout, "\n");
    // fprintf(stdout, "%3u/%2u ", _cb_values[k],
    // index->_cbl_index_counter->_bitset[k]);
  }
  // fprintf(stdout, "\n");

  qsort(_cb_values, cb_size, sizeof(uint8_t), __compare);

  index->_octile_values[1] = ((float)_cb_values[(cb_size * 2 / 16)] +
                              _cb_values[(cb_size * 2 / 16) + 1]) /
                             2;
  index->_octile_values[2] = ((float)_cb_values[(cb_size * 4 / 16)] +
                              _cb_values[(cb_size * 4 / 16) + 1]) /
                             2;
  index->_octile_values[3] = ((float)_cb_values[(cb_size * 6 / 16)] +
                              _cb_values[(cb_size * 6 / 16) + 1]) /
                             2;
  index->_octile_values[4] = ((float)_cb_values[(cb_size * 8 / 16)] +
                              _cb_values[(cb_size * 8 / 16) + 1]) /
                             2;
  index->_octile_values[5] = ((float)_cb_values[(cb_size * 10 / 16)] +
                              _cb_values[(cb_size * 10 / 16) + 1]) /
                             2;
  index->_octile_values[6] = ((float)_cb_values[(cb_size * 12 / 16)] +
                              _cb_values[(cb_size * 12 / 16) + 1]) /
                             2;
  index->_octile_values[7] = ((float)_cb_values[(cb_size * 14 / 16)] +
                              _cb_values[(cb_size * 14 / 16) + 1]) /
                             2;

  // fprintf(stdout, "\nlower  q12.5: %f / %f / %f : q37.5\n",
  // index->_octile_values[1], index->_octile_values[2],
  // index->_octile_values[3]); fprintf(stdout, "median q50.0: %f \n",
  // index->_octile_values[4]); fprintf(stdout, "upper  q62.5: %f / %f / %f :
  // q87.5\n", index->_octile_values[5], index->_octile_values[6],
  // index->_octile_values[7]);

  uint8_t shift   = 29;
  uint8_t counter = 1;

  // fprintf(stdout, "\n");
  // for (uint16_t k = 0; k < cb_size; ++k)
  // {
  //     if (k%8 == 0 && k > 0) fprintf(stdout, "\n");
  //     if (counting_bloom->_bitset[k] > index->_quartile_values[0])
  //         fprintf(stdout, " %10u :", counting_bloom->_bitset[k]);
  //     else
  //         fprintf(stdout, " %10u :", 0);

  // }
  // fprintf(stdout, "\n");

  // alloc 512 bits
  uint16_t _index_value_pos = 0;
  uint8_t  _index_value[32];
  memset(_index_value, 0, 32);

  union np_x24_t _value  = {0};
  uint8_t        _parity = 0;
  for (uint8_t k = 0; k < cb_size; k++) {
    uint32_t _local_pos = k;
    /*
    gray codes, because then the difference between two sections is always just
    one bit 000 <-- ignore, we cannot differentiate between "not present" and
    "low value" 001 = 1 011 = 3 010 = 2 110 = 5 111 = 7 101 = 6 100 = 4
    */

    // fprintf(stdout, "%3u / %3u / ", _local_pos, _index_value_pos);
    if (index->_cbl_index->_bitset[_local_pos] <
        index->_octile_values[1]) { /*_value._as_u32 |= (0x00000000 << shift);
                                       _parity += 0;*/
    } else if (index->_cbl_index->_bitset[_local_pos] <
               index->_octile_values[2]) {
      _value._as_u32 |= (0x00000001 << shift);
      _parity += 1;
    } else if (index->_cbl_index->_bitset[_local_pos] <
               index->_octile_values[3]) {
      _value._as_u32 |= (0x00000002 << shift);
      _parity += 1;
    } else if (index->_cbl_index->_bitset[_local_pos] <
               index->_octile_values[4]) {
      _value._as_u32 |= (0x00000003 << shift);
      _parity += 2;
    } else if (index->_cbl_index->_bitset[_local_pos] <
               index->_octile_values[5]) {
      _value._as_u32 |= (0x00000004 << shift);
      _parity += 1;
    } else if (index->_cbl_index->_bitset[_local_pos] <
               index->_octile_values[6]) {
      _value._as_u32 |= (0x00000005 << shift);
      _parity += 2;
    } else if (index->_cbl_index->_bitset[_local_pos] <
               index->_octile_values[7]) {
      _value._as_u32 |= (0x00000006 << shift);
      _parity += 2;
    } else if (index->_cbl_index->_bitset[_local_pos] >=
               index->_octile_values[7]) {
      _value._as_u32 |= (0x00000007 << shift);
      _parity += 3;
    } else { /* fprintf(stdout, "error calculating bit index value"); */
      abort();
    }

    // gray values
    // if      (index->_cbl_index->_bitset[_local_pos] <
    // index->_octile_values[1]) { /*_value._as_u32 |= (0x00000000 << shift);
    // _parity += 0;*/ } else if (index->_cbl_index->_bitset[_local_pos] <
    // index->_octile_values[2]) { _value._as_u32 |= (0x00000001 << shift);
    // _parity += 1; } else if (index->_cbl_index->_bitset[_local_pos] <
    // index->_octile_values[3]) { _value._as_u32 |= (0x00000003 << shift);
    // _parity += 2; } else if (index->_cbl_index->_bitset[_local_pos] <
    // index->_octile_values[4]) { _value._as_u32 |= (0x00000002 << shift);
    // _parity += 1; } else if (index->_cbl_index->_bitset[_local_pos] <
    // index->_octile_values[5]) { _value._as_u32 |= (0x00000005 << shift);
    // _parity += 2; } else if (index->_cbl_index->_bitset[_local_pos] <
    // index->_octile_values[6]) { _value._as_u32 |= (0x00000007 << shift);
    // _parity += 3; } else if (index->_cbl_index->_bitset[_local_pos] <
    // index->_octile_values[7]) { _value._as_u32 |= (0x00000006 << shift);
    // _parity += 2; } else if (index->_cbl_index->_bitset[_local_pos] >=
    // index->_octile_values[7]) { _value._as_u32 |= (0x00000004 << shift);
    // _parity += 1; } else    { /* fprintf(stdout, "error calculating bit index
    // value"); */ abort(); }

    // fprintf(stdout, "%3u / 0x%08x  ( %3u : %3u ) \n",
    // index->_cbl_index->_bitset[_local_pos], _value._as_u32, shift, _parity);

    if (shift == 8 || k == 84) {
      // fprintf(stdout, "0x%02x%02x%02x%02x\n",
      //                 _value._as_u8a[3], _value._as_u8a[2],
      //                 _value._as_u8a[1], _value._as_u8a[0]
      //         );
      // memcpy(&_index_value[_index_value_pos], &_value, 3*sizeof(uint8_t));
      _index_value[_index_value_pos + 0] = _value._as_u8a[3];
      _index_value[_index_value_pos + 1] = _value._as_u8a[2];

      if (_index_value_pos < 30)
        _index_value[_index_value_pos + 2] = _value._as_u8a[1];

      // fprintf(stdout, "%2u 0x%02x%02x%02x\n", _index_value_pos,
      // _index_value[_index_value_pos+0], _index_value[_index_value_pos+1],
      // _index_value[_index_value_pos+2] );
      _index_value_pos += 3;

      memset(&_value._as_u32, 0, sizeof(uint32_t));

      shift   = 29;
      counter = 1;
    } else {
      shift -= 3;
      counter++;
    }
  }

  if (0 != (_parity % 2)) {
    _index_value[31] |= 0x01;
  }

  // fprintf(stdout, "%02x %02x %02x %02x ... %02x %02x %02x %02x\n",
  //                 _index_value[0], _index_value[1], _index_value[2],
  //                 _index_value[3], _index_value[28], _index_value[29],
  //                 _index_value[30], _index_value[31]
  //                 );

  memcpy(&index->lower_dhkey, &_index_value[0], 32);

  // fprintf(stdout, "%08x %08x %08x %08x %08x %08x %08x %08x\n",
  //                 index->lower_dhkey.t[0], index->lower_dhkey.t[1],
  //                 index->lower_dhkey.t[2], index->lower_dhkey.t[3],
  //                 index->lower_dhkey.t[4], index->lower_dhkey.t[5],
  //                 index->lower_dhkey.t[6], index->lower_dhkey.t[7]
  //                 );

  // memcpy(&index->upper_dhkey, &_index_value[32], 32);
  //         fprintf(stdout, "%08x %08x %08x %08x %08x %08x %08x %08x\n",
  //                         index->upper_dhkey.t[0], index->upper_dhkey.t[1],
  //                         index->upper_dhkey.t[2], index->upper_dhkey.t[3],
  //                         index->upper_dhkey.t[4], index->upper_dhkey.t[5],
  //                         index->upper_dhkey.t[6], index->upper_dhkey.t[7]
  //                         );
}
