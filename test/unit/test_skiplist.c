//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <criterion/criterion.h>
#include <criterion/logging.h>
#include <inttypes.h>
#include <stdlib.h>

#include "../test_macros.c"

#include "util/np_skiplist.h"

#include "np_dhkey.h"

struct sl_item_s {
  uint16_t key;
  double   value;
};

int8_t _compare_hkey(const void *old, const void *new) {
  union np_hkey *it_1 = (union np_hkey *)old;
  union np_hkey *it_2 = (union np_hkey *)new;

  int res = memcmp(it_1->_as_us, it_2->_as_us, 32);
  // fprintf(stdout,
  //         "compare result %0X <-> %0X == %d\n ",
  //         it_1->_as_uc,
  //         it_2->_as_uc,
  //         res);
  return res;
}

int8_t _compare_double(const void *old, const void *new) {
  struct sl_item_s *it_1 = (struct sl_item_s *)old;
  struct sl_item_s *it_2 = (struct sl_item_s *)new;

  // cr_log_info("comparing to : %p (%d) <-> (%d) %p    ", new, it_2->key,
  // it_1->key, old);
  if (it_1 == it_2) return 0;
  if (it_1 == NULL) return 1;
  if (it_2 == NULL) return -1;

  if (it_1->key == it_2->key) return 0;
  else if (it_1->key < it_2->key) return 1;
  else if (it_1->key > it_2->key) return -1;

  return 0;
}

TestSuite(np_skiplist);

Test(np_skiplist,
     np_skiplist_use,
     .description = "test the implementation of a skiplist") {
  np_skiplist_t skiplist;

  np_skiplist_init(&skiplist, _compare_double, NULL);

  struct sl_item_s d_a = {.key = 1, .value = 3.1415};
  struct sl_item_s d_b = {.key = 2, .value = 1.0};
  struct sl_item_s d_c = {.key = 4, .value = 7.4321};
  struct sl_item_s d_d = {.key = 8, .value = 100000000.4};
  struct sl_item_s d_e = {.key = 2, .value = 2.333333333};
  struct sl_item_s d_f = {.key = 3, .value = 3.333333333};
  struct sl_item_s d_g = {.key = 9, .value = 9.333333333};
  struct sl_item_s d_h = {.key = 13, .value = 13.333333333};

  bool ret = true;
  cr_log_info("adding     to : %p (%d)    ", &d_a, d_a.key);
  ret = np_skiplist_add(&skiplist, &d_a);
  cr_expect(ret == true, "expect result of adding an element to be true");
  cr_expect(skiplist._num_elements == 1, "expect the element count to be one");

  cr_log_info("adding     to : %p (%d)    ", &d_b, d_b.key);
  ret = np_skiplist_add(&skiplist, &d_b);
  cr_expect(ret == true, "expect result of adding an element to be true");
  cr_expect(skiplist._num_elements == 2, "expect the element count to be two");

  cr_log_info("adding     to : %p (%d)    ", &d_c, d_c.key);
  ret = np_skiplist_add(&skiplist, &d_c);
  cr_expect(ret == true, "expect result of adding an element to be true");
  cr_expect(skiplist._num_elements == 3, "expect the element count to be tree");

  cr_log_info("adding     to : %p (%d)    ", &d_d, d_d.key);
  ret = np_skiplist_add(&skiplist, &d_d);
  cr_expect(ret == true, "expect result of adding an element to be true");
  cr_expect(skiplist._num_elements == 4, "expect the element count to be four");

  cr_log_info("adding     to : %p (%d)    ", &d_e, d_e.key);
  ret = np_skiplist_add(&skiplist, &d_e);
  cr_expect(ret == false, "expect result of adding an element to be true");
  cr_expect(skiplist._num_elements == 4, "expect the element count to be four");

  cr_log_info("removing from : %p (%d)    ", &d_b, d_b.key);
  ret = np_skiplist_remove(&skiplist, &d_b);
  cr_expect(ret == true, "expect result of removing an element to be true");
  cr_expect(skiplist._num_elements == 3,
            "expect the element count to be three");

  cr_log_info("adding     to : %p (%d)    ", &d_e, d_e.key);
  ret = np_skiplist_add(&skiplist, &d_e);
  cr_expect(ret == true, "expect result of adding an element to be true");
  cr_expect(skiplist._num_elements == 4, "expect the element count to be four");

  struct sl_item_s  d_s        = {.key = 5, .value = 0};
  struct sl_item_s *d_s_result = &d_s;
  cr_log_info("searching for: %p (%d)    ", d_s_result, d_s_result->key);
  ret = np_skiplist_find(&skiplist, (void **)&d_s_result);
  // cr_log_info("returning    : %p (%d)    ", d_s_result, d_s_result->key);
  cr_expect(ret == false, "expect result of adding an element to be false");
  cr_expect(skiplist._num_elements == 4, "expect the element count to be one");
  // if (ret) {
  cr_expect(d_s_result->key == 4, "expect the element key to be ...");
  cr_expect(d_s_result->value == 7.4321, "expect the element value to be ...");
  // }

  d_s_result = &d_d;
  cr_log_info("searching for: %p (%d)    ", d_s_result, d_s_result->key);
  ret = np_skiplist_find(&skiplist, (void **)&d_s_result);
  cr_log_info("returning    : %p (%d)    ", d_s_result, d_s_result->key);
  cr_expect(ret == true, "expect result of finding an element to be true");
  cr_expect(skiplist._num_elements == 4, "expect the element count to be one");
  if (ret) {
    cr_expect(d_s_result->key == d_d.key, "expect the element key to be ...");
    cr_expect(d_s_result->value == d_d.value,
              "expect the element value to be ...");
  }

  cr_log_info("adding     to : %p (%d)    ", &d_f, d_f.key);
  ret = np_skiplist_add(&skiplist, &d_f);
  cr_expect(ret == true, "expect result of adding an element to be true");
  cr_expect(skiplist._num_elements == 5, "expect the element count to be five");

  cr_log_info("adding     to : %p (%d)    ", &d_g, d_g.key);
  ret = np_skiplist_add(&skiplist, &d_g);
  cr_expect(ret == true, "expect result of adding an element to be true");
  cr_expect(skiplist._num_elements == 6, "expect the element count to be six");

  cr_log_info("removing from : %p (%d)    ", &d_g, d_g.key);
  ret = np_skiplist_remove(&skiplist, &d_g);
  cr_expect(ret == true, "expect result of removing an element to be true");
  cr_expect(skiplist._num_elements == 5, "expect the element count to be five");

  cr_log_info("adding     to : %p (%d)    ", &d_h, d_h.key);
  ret = np_skiplist_add(&skiplist, &d_h);
  cr_expect(ret == true, "expect result of adding an element to be true");
  cr_expect(skiplist._num_elements == 6, "expect the element count to be six");

  // np_skiplist_print(&skiplist);
  np_skiplist_destroy(&skiplist);
}

Test(np_skiplist,
     np_skiplist_use_100,
     .description = "test the implementation of a skiplist with 200 elements") {
  np_skiplist_t skiplist;
  np_skiplist_init(&skiplist, _compare_double, NULL);

  uint32_t count = 512;
  double   add_func[count], get_func[count];

  for (uint32_t i = 0; i < count; i++) {
    struct sl_item_s *d_a = malloc(sizeof(struct sl_item_s));
    d_a->key              = rand();
    d_a->value            = 3.1415;

    MEASURE_TIME(add_func, i, { np_skiplist_add(&skiplist, d_a); })
  }

  for (uint32_t i = 0; i < count; i++) {
    struct sl_item_s *d_a = malloc(sizeof(struct sl_item_s));
    d_a->key              = i;

    MEASURE_TIME(get_func, i, { np_skiplist_find(&skiplist, &d_a); });
  }

  CALC_AND_PRINT_STATISTICS("insert into skiplist stats", add_func, count);
  CALC_AND_PRINT_STATISTICS("find in skiplist stats", get_func, count);

  // np_skiplist_print(&skiplist);
  np_skiplist_destroy(&skiplist);
}

// Test(np_skiplist,
//      np_skiplist_perf_10000,
//      .description =
//          "test the addition/substraction of dhkeys to a np_cupidtrie") {

//   uint16_t      num_elements = 10240;
//   union np_hkey data[num_elements];
//   union np_hkey invalid_data[num_elements];
//   for (uint16_t i = 0; i < num_elements; i++) {
//     char   input_1[256] = {'\0'};
//     char   input_2[256] = {'\0'};
//     double now          = _np_time_now(NULL);
//     snprintf(input_1,
//              255,
//              "%s:%u:%16.16f",
//              "test-string-der-sehr-lang-ist",
//              i,
//              now);
//     snprintf(input_2,
//              255,
//              "%s:%u:%16.16f",
//              "test-string-der-sehr-kurz-ist",
//              i,
//              now);
//     // log_debug(LOG_DEBUG, NULL, "created input uuid: %s", input);
//     crypto_generichash_blake2b(data[i]._as_uc,
//                                32,
//                                (unsigned char *)input_1,
//                                256,
//                                NULL,
//                                0);
//     crypto_generichash_blake2b(invalid_data[i]._as_uc,
//                                32,
//                                (unsigned char *)input_2,
//                                256,
//                                NULL,
//                                0);
//   }
//   np_skiplist_t skiplist;
//   np_skiplist_init(&skiplist, _compare_hkey, NULL);

//   double sl_insert_func[num_elements], sl_check_func_valid[num_elements],
//       sl_check_func_invalid[num_elements], sl_clear_func[num_elements];

//   for (uint16_t i = 0; i < num_elements; i++) {
//     MEASURE_TIME(sl_insert_func, i, np_skiplist_add(&skiplist, &data[i]));
//   }
//   CALC_AND_PRINT_STATISTICS("[ new ] insert np_skiplist_t",
//                             sl_insert_func,
//                             num_elements);

//   // np_skiplist_print(&skiplist);
//   for (uint16_t i = 0; i < num_elements; i++) {
//     void *data_ptr = &data[i];
//     MEASURE_TIME(sl_check_func_valid,
//                  i,
//                  cr_expect(true == np_skiplist_find(&skiplist, &data_ptr)));
//   }
//   CALC_AND_PRINT_STATISTICS("[ new ] check valid np_skiplist_t",
//                             sl_check_func_valid,
//                             num_elements);

//   for (uint16_t i = 0; i < num_elements; i++) {
//     void *data_ptr = &invalid_data[i];
//     MEASURE_TIME(sl_check_func_invalid,
//                  i,
//                  cr_expect(false == np_skiplist_find(&skiplist, &data_ptr)));
//   }
//   CALC_AND_PRINT_STATISTICS("[ new ] check invalid np_skiplist_t",
//                             sl_check_func_invalid,
//                             num_elements);
// for (uint16_t i = 0; i < num_elements; i++) {
//   MEASURE_TIME(sl_clear_func,
//                i,
//                cr_expect(true == np_skiplist_remove(&skiplist, &data[i])));
// }
// CALC_AND_PRINT_STATISTICS("[ new ] check clear np_skiplist_t",
//                           sl_clear_func,
//                           num_elements);
// }
