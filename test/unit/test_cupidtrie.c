//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <criterion/criterion.h>

#include "../test_macros.c"

#include "neuropil_data.h"

#include "util/np_cupidtrie.h"

#include "np_dhkey.h"

enum np_return combine_func(uintptr_t *left, const uintptr_t *right) {
  return np_ok;
}
enum np_return element_func(uintptr_t *left) { return np_ok; }

TestSuite(np_cupidtrie);

Test(np_cupidtrie,
     _add_remove_check,
     .description =
         "test the addition/substraction of dhkeys to a np_cupidtrie") {

  uint16_t      num_elements = 10000;
  union np_hkey data[num_elements];
  union np_hkey invalid_data[num_elements];
  for (uint16_t i = 0; i < num_elements; i++) {
    char   input_1[256] = {'\0'};
    char   input_2[256] = {'\0'};
    double now          = _np_time_now(NULL);
    snprintf(input_1,
             255,
             "%s:%u:%16.16f",
             "test-string-der-sehr-lang-ist",
             i,
             now);
    snprintf(input_2,
             255,
             "%s:%u:%16.16f",
             "test-string-der-sehr-kurz-ist",
             i,
             now);
    // log_debug(LOG_DEBUG, NULL, "created input uuid: %s", input);
    crypto_generichash_blake2b(data[i]._as_uc,
                               32,
                               (unsigned char *)input_1,
                               256,
                               NULL,
                               0);
    crypto_generichash_blake2b(invalid_data[i]._as_uc,
                               32,
                               (unsigned char *)input_2,
                               256,
                               NULL,
                               0);
  }
  struct np_cupidtrie new_trie = {.tree             = NULL,
                                  .key_length       = 32,
                                  .alloc_key_memory = false};

  double ct_insert_func[num_elements], ct_check_func_valid[num_elements],
      ct_check_func_invalid[num_elements], ct_clear_func[num_elements];

  for (uint16_t i = 0; i < num_elements; i++) {
    uintptr_t *data_ptr = NULL;
    MEASURE_TIME(ct_insert_func,
                 i,
                 np_cupidtrie_insert(&new_trie, data[i]._as_us, &data_ptr));
  }
  CALC_AND_PRINT_STATISTICS("[ 10k ] insert cupidtrie",
                            ct_insert_func,
                            num_elements);

  for (uint16_t i = 0; i < num_elements; i++) {
    uintptr_t *data_ptr = NULL;
    MEASURE_TIME(
        ct_check_func_valid,
        i,
        cr_expect(np_ok ==
                  np_cupidtrie_find(&new_trie, data[i]._as_us, &data_ptr)));
  }
  CALC_AND_PRINT_STATISTICS("[ 10k ] check valid cupidtrie",
                            ct_check_func_valid,
                            num_elements);

  for (uint16_t i = 0; i < num_elements; i++) {
    uintptr_t *data_ptr = NULL;
    MEASURE_TIME(ct_check_func_invalid,
                 i,
                 cr_expect(np_ok != np_cupidtrie_find(&new_trie,
                                                      invalid_data[i]._as_us,
                                                      &data_ptr)));
  }
  CALC_AND_PRINT_STATISTICS("[ 10k ] check invalid cupidtrie",
                            ct_check_func_invalid,
                            num_elements);

  for (uint16_t i = 0; i < num_elements; i++) {
    uintptr_t *data_ptr = NULL;
    MEASURE_TIME(
        ct_clear_func,
        i,
        cr_expect(np_ok ==
                  np_cupidtrie_delete(&new_trie, data[i]._as_us, &data_ptr)));
  }
  CALC_AND_PRINT_STATISTICS("[ 10k ] check clear cupidtrie",
                            ct_clear_func,
                            num_elements);
}

Test(np_cupidtrie,
     union_intersection,
     .description = "test the union/intersection of a np_cupidtrie") {

  uint16_t      num_elements = 10000;
  union np_hkey data[num_elements];
  union np_hkey invalid_data[num_elements];
  for (uint16_t i = 0; i < num_elements; i++) {
    char   input_1[256] = {'\0'};
    char   input_2[256] = {'\0'};
    double now          = _np_time_now(NULL);
    snprintf(input_1,
             255,
             "%s:%u:%16.16f",
             "test-string-der-sehr-lang-ist",
             i,
             now);
    snprintf(input_2,
             255,
             "%s:%u:%16.16f",
             "test-string-der-sehr-kurz-ist",
             i,
             now);
    // log_debug(LOG_DEBUG, NULL, "created input uuid: %s", input);
    crypto_generichash_blake2b(data[i]._as_uc,
                               32,
                               (unsigned char *)input_1,
                               256,
                               NULL,
                               0);
    crypto_generichash_blake2b(invalid_data[i]._as_uc,
                               32,
                               (unsigned char *)input_2,
                               256,
                               NULL,
                               0);
  }
  double ct_intersection_func[num_elements], ct_union_func[num_elements];

  struct np_cupidtrie u_trie = {.tree             = NULL,
                                .key_length       = 32,
                                .alloc_key_memory = false};

  uintptr_t *data_ptr;
  for (uint16_t i = 0; i < num_elements / 100; i++) {
    struct np_cupidtrie tmp_trie = {.tree = NULL, .key_length = 32};
    for (uint16_t j = 0; j < num_elements / 1000; j++) {
      np_cupidtrie_insert(&tmp_trie, data[(i + 1) * j]._as_us, &data_ptr);
    }
    MEASURE_TIME(ct_union_func,
                 i,
                 np_cupidtrie_union(&u_trie, &tmp_trie, combine_func));
    np_cupidtrie_free(&tmp_trie);
  }
  for (uint16_t i = 0; i < num_elements / 100; i++) {
    assert(np_ok == np_cupidtrie_find(&u_trie, data[i]._as_us, &data_ptr));
  }

  np_cupidtrie_free(&u_trie);
  CALC_AND_PRINT_STATISTICS("[ 10k ] check union of  bloom",
                            ct_union_func,
                            num_elements / 100);

  struct np_cupidtrie is_trie = {.tree             = NULL,
                                 .key_length       = 32,
                                 .alloc_key_memory = false};
  for (uint16_t i = 0; i < num_elements; i++) {
    uintptr_t          *data_ptr;
    struct np_cupidtrie tmp_trie = {.tree = NULL, .key_length = 32};
    np_cupidtrie_insert(&tmp_trie, data[i]._as_us, &data_ptr);
    np_cupidtrie_insert(&tmp_trie, data[i + 1]._as_us, &data_ptr);

    np_cupidtrie_insert(&is_trie, data[i]._as_us, &data_ptr);

    MEASURE_TIME(ct_intersection_func,
                 i,
                 np_cupidtrie_intersect(&is_trie, &tmp_trie, combine_func));
    np_cupidtrie_free(&tmp_trie);
    assert(np_ok == np_cupidtrie_find(&is_trie, data[i]._as_us, &data_ptr));
  }
  CALC_AND_PRINT_STATISTICS("[ 10k ] check intersection of  bloom",
                            ct_intersection_func,
                            num_elements);
  np_cupidtrie_free(&is_trie);
}
