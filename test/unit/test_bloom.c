//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <criterion/criterion.h>
#include <inttypes.h>

#include "../test_macros.c"

#include "neuropil.h"

#include "util/np_bloom.h"

#include "np_util.h"

TestSuite(np_bloom_t);

Test(np_bloom_t,
     _bloom_standard,
     .description = "test the functions of the standard bloom filter") {

  //  char test_string[65];
  np_dhkey_t test1 = np_dhkey_create_from_hostport("test_1", "0");
  //  np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", "0");
  //  np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test3 = np_dhkey_create_from_hostport("test_3", "0");
  //  np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test4 = np_dhkey_create_from_hostport("test_4", "0");
  //  np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test5 = np_dhkey_create_from_hostport("test_5", "0");
  //  np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);

  struct np_bloom_optable_s std_operations = {
      .add_cb       = _np_standard_bloom_add,
      .check_cb     = _np_standard_bloom_check,
      .clear_cb     = NULL,
      .union_cb     = NULL,
      .intersect_cb = NULL,
  };

  //    fprintf(stdout, "###\n");
  //    fprintf(stdout, "### Testing standard bloom filter now\n");
  //    fprintf(stdout, "###\n");

  np_bloom_t *std_bloom = _np_standard_bloom_create(256);
  std_bloom->op         = std_operations;

  std_bloom->op.add_cb(std_bloom, test1);
  std_bloom->op.add_cb(std_bloom, test2);
  std_bloom->op.add_cb(std_bloom, test3);

  cr_expect(true == std_bloom->op.check_cb(std_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == std_bloom->op.check_cb(std_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(false == std_bloom->op.check_cb(std_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  _np_bloom_free(std_bloom);
}

Test(np_bloom_t,
     _bloom_standard_union_intersection,
     .description =
         "test the union/intersection functions of the neuropil bloom filter") {
  //  char test_string[65];
  np_dhkey_t test1 = np_dhkey_create_from_hostport("test_1", "0");
  //  np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", "0");
  //  np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test3 = np_dhkey_create_from_hostport("test_3", "0");
  //  np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test4 = np_dhkey_create_from_hostport("test_4", "0");
  //  np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test5 = np_dhkey_create_from_hostport("test_5", "0");
  //  np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);

  struct np_bloom_optable_s neuropil_operations = {
      .add_cb       = _np_standard_bloom_add,
      .check_cb     = _np_standard_bloom_check,
      .clear_cb     = _np_standard_bloom_clear,
      .union_cb     = _np_standard_bloom_union,
      .intersect_cb = _np_standard_bloom_intersect,
  };

  //    fprintf(stdout, "###\n");
  //    fprintf(stdout, "### Testing neuropil bloom filter now\n");
  //    fprintf(stdout, "###\n");

  np_bloom_t *standard_bloom = _np_standard_bloom_create(512);
  standard_bloom->op         = neuropil_operations;

  np_bloom_t *union_bloom = _np_standard_bloom_create(512);
  union_bloom->op         = neuropil_operations;

  np_bloom_t *test2_bloom = _np_standard_bloom_create(512);
  test2_bloom->op         = neuropil_operations;
  np_bloom_t *test4_bloom = _np_standard_bloom_create(512);
  test4_bloom->op         = neuropil_operations;
  np_bloom_t *test5_bloom = _np_standard_bloom_create(512);
  test5_bloom->op         = neuropil_operations;

  standard_bloom->op.add_cb(standard_bloom, test2);
  standard_bloom->op.add_cb(standard_bloom, test4);
  standard_bloom->op.add_cb(standard_bloom, test5);

  test2_bloom->op.add_cb(test2_bloom, test2);
  test4_bloom->op.add_cb(test4_bloom, test4);
  test5_bloom->op.add_cb(test5_bloom, test5);

  cr_expect(true == standard_bloom->op.check_cb(standard_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(true == standard_bloom->op.check_cb(standard_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(true == standard_bloom->op.check_cb(standard_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  cr_expect(true == test2_bloom->op.check_cb(test2_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(true == test4_bloom->op.check_cb(test4_bloom, test4),
            "expect that the id test4 is     found in bloom filter");
  cr_expect(true == test5_bloom->op.check_cb(test5_bloom, test5),
            "expect that the id test5 is     found in bloom filter");

  cr_expect(32 == union_bloom->_free_items,
            "expect that the number of free_items is 32");

  union_bloom->op.union_cb(union_bloom, test2_bloom);
  cr_expect(31 == union_bloom->_free_items,
            "expect that the number of free_items is 31");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == union_bloom->op.check_cb(union_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(false == union_bloom->op.check_cb(union_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  union_bloom->op.union_cb(union_bloom, test4_bloom);
  cr_expect(30 == union_bloom->_free_items,
            "expect that the number of free_items is 30");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test4),
            "expect that the id test4 is     found in bloom filter");
  cr_expect(false == union_bloom->op.check_cb(union_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  union_bloom->op.union_cb(union_bloom, test5_bloom);
  cr_expect(29 == union_bloom->_free_items,
            "expect that the number of free_items is 29");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test4),
            "expect that the id test4 is     found in bloom filter");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test5),
            "expect that the id test5 is     found in bloom filter");

  np_bloom_t *intersect_bloom = _np_standard_bloom_create(512);
  intersect_bloom->op         = neuropil_operations;
  intersect_bloom->op.union_cb(intersect_bloom,
                               union_bloom); // add a default set

  intersect_bloom->op.intersect_cb(intersect_bloom, test2_bloom);
  cr_expect(0 == intersect_bloom->_free_items,
            "expect that the number of free_items is 0");
  cr_expect(true == intersect_bloom->op.check_cb(intersect_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  intersect_bloom->op.clear_cb(intersect_bloom);
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test2),
            "expect that the id test2 is not found in bloom filter");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test5),
            "expect that the id test5 is not found in bloom filter");
  intersect_bloom->op.union_cb(intersect_bloom,
                               union_bloom); // ... re-add a default set

  np_bloom_t *test1_bloom = _np_standard_bloom_create(512);
  test1_bloom->op         = neuropil_operations;
  standard_bloom->op.add_cb(standard_bloom, test1);

  intersect_bloom->op.intersect_cb(intersect_bloom, test1_bloom);
  cr_expect(0 == intersect_bloom->_free_items,
            "expect that the number of free_items is 0");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test4),
            "expect that the id test4 is     found in bloom filter");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test5),
            "expect that the id test5 is     found in bloom filter");

  _np_bloom_free(union_bloom);
  _np_bloom_free(standard_bloom);
  _np_bloom_free(intersect_bloom);

  _np_bloom_free(test2_bloom);
  _np_bloom_free(test4_bloom);
  _np_bloom_free(test5_bloom);
}

Test(np_bloom_t,
     _bloom_stable,
     .description = "test the functions of the stable bloom filter") {

  //  char test_string[65];
  np_dhkey_t test1 = np_dhkey_create_from_hostport("test_1", "0");
  //  np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", "0");
  //  np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test3 = np_dhkey_create_from_hostport("test_3", "0");
  //  np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test4 = np_dhkey_create_from_hostport("test_4", "0");
  //  np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test5 = np_dhkey_create_from_hostport("test_5", "0");
  //  np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);

  struct np_bloom_optable_s stable_operations = {
      .add_cb       = _np_stable_bloom_add,
      .check_cb     = _np_stable_bloom_check,
      .clear_cb     = NULL,
      .union_cb     = NULL,
      .intersect_cb = NULL,
  };

  //    fprintf(stdout, "###\n");
  //    fprintf(stdout, "### Testing stable bloom filter now\n");
  //    fprintf(stdout, "###\n");

  np_bloom_t *stable_bloom = _np_stable_bloom_create(1024, 8, 16);
  stable_bloom->op         = stable_operations;

  stable_bloom->op.add_cb(stable_bloom, test1);
  stable_bloom->op.add_cb(stable_bloom, test2);
  stable_bloom->op.add_cb(stable_bloom, test3);

  cr_expect(true == stable_bloom->op.check_cb(stable_bloom, test1),
            "expect that the id test1 is     found in bloom filter");
  cr_expect(true == stable_bloom->op.check_cb(stable_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == stable_bloom->op.check_cb(stable_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(false == stable_bloom->op.check_cb(stable_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  uint8_t test_count           = 100;
  uint8_t test_success_counter = test_count;
  for (uint16_t i = 0; i < test_count; i++) {

    np_get_id(&test4, np_uuid_create("test", i, NULL), 36);
    //        np_id_str(test_string, test4); fprintf(stdout, "%s\n",
    //        test_string);
    if (stable_bloom->op.check_cb(stable_bloom, test4)) {
      test_success_counter--;
    }
    if (i % 4)
      cr_expect(true == stable_bloom->op.check_cb(stable_bloom, test2),
                "expect that the id test2 is     found in bloom filter");
  }
  _np_bloom_free(stable_bloom);
  float test_ok = test_success_counter / (float)test_count;
  cr_expect(test_ok > .99,
            "expect that the new element is not found %f%% of time",
            test_ok);
}

Test(np_bloom_t,
     _bloom_scalable,
     .description = "test the functions of the scalable bloom filter") {

  //  char test_string[65];
  np_dhkey_t test1 = np_dhkey_create_from_hostport("test_1", "0");
  //  np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", "0");
  //  np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test3 = np_dhkey_create_from_hostport("test_3", "0");
  //  np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test4 = np_dhkey_create_from_hostport("test_4", "0");
  //  np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test5 = np_dhkey_create_from_hostport("test_5", "0");
  //  np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);

  struct np_bloom_optable_s scale_operations = {
      .add_cb       = _np_scalable_bloom_add,
      .check_cb     = _np_scalable_bloom_check,
      .clear_cb     = NULL,
      .union_cb     = NULL,
      .intersect_cb = NULL,
  };

  //    fprintf(stdout, "###\n");
  //    fprintf(stdout, "### Testing scalable bloom filter now\n");
  //    fprintf(stdout, "###\n");

  np_bloom_t *scale_bloom = _np_scalable_bloom_create(256);
  scale_bloom->op         = scale_operations;

  scale_bloom->op.add_cb(scale_bloom, test1);
  scale_bloom->op.add_cb(scale_bloom, test2);
  scale_bloom->op.add_cb(scale_bloom, test3);

  cr_expect(true == scale_bloom->op.check_cb(scale_bloom, test1),
            "expect that the id test1 is     found in bloom filter");
  cr_expect(true == scale_bloom->op.check_cb(scale_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == scale_bloom->op.check_cb(scale_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(false == scale_bloom->op.check_cb(scale_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  np_dhkey_t test;
  uint8_t    actual_found = 0, actual_not_found = 0;
  for (uint16_t i = 0; i < 100; i++) {
    if (i % 3 || i % 5 || i % 7)
      test =
          np_dhkey_create_from_hostport(np_uuid_create("test", i, NULL), "0");

    //        np_id_str(test_string, test); fprintf(stdout, "%s\n",
    //        test_string);
    actual_not_found += false == scale_bloom->op.check_cb(scale_bloom, test);
    scale_bloom->op.add_cb(scale_bloom, test);
    actual_found += true == scale_bloom->op.check_cb(scale_bloom, test);
  }
  cr_expect(actual_not_found >= 97, "expect that a new element is not found");
  cr_expect(
      actual_found >= 97,
      "expect that a new element is     found in bloom filter after insert");

  actual_found = 0, actual_not_found = 0;

  _np_bloom_free(scale_bloom);
}

Test(np_bloom_t,
     _bloom_decaying,
     .description = "test the functions of the decaying bloom filter") {
  //  char test_string[65];
  np_dhkey_t test1 = np_dhkey_create_from_hostport("test_1", "0");
  //  np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", "0");
  //  np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test3 = np_dhkey_create_from_hostport("test_3", "0");
  //  np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test4 = np_dhkey_create_from_hostport("test_4", "0");
  //  np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test5 = np_dhkey_create_from_hostport("test_5", "0");
  //  np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);

  struct np_bloom_optable_s decay_operations = {
      .add_cb       = _np_decaying_bloom_add,
      .check_cb     = _np_decaying_bloom_check,
      .clear_cb     = NULL,
      .union_cb     = NULL,
      .intersect_cb = NULL,
  };

  //    fprintf(stdout, "###\n");
  //    fprintf(stdout, "### Testing decaying bloom filter now\n");
  //    fprintf(stdout, "###\n");

  np_bloom_t *decaying_bloom = _np_decaying_bloom_create(256, 8, 1);
  decaying_bloom->op         = decay_operations;

  decaying_bloom->op.add_cb(decaying_bloom, test1);
  decaying_bloom->op.add_cb(decaying_bloom, test2);
  decaying_bloom->op.add_cb(decaying_bloom, test3);

  cr_expect(true == decaying_bloom->op.check_cb(decaying_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  for (uint8_t i = 0; i < 10; i++) {

    _np_decaying_bloom_decay(decaying_bloom);

    if (i < 4) {
      //            fprintf(stdout, "%f\n",
      //            _np_decaying_bloom_get_heuristic(decaying_bloom, test1));
      cr_expect(0.5 <= _np_decaying_bloom_get_heuristic(decaying_bloom, test1),
                "checking the probability that a np_id has been found");
    } else {
      //            fprintf(stdout, "%f\n",
      //            _np_decaying_bloom_get_heuristic(decaying_bloom, test1));
      cr_expect(0.5 > _np_decaying_bloom_get_heuristic(decaying_bloom, test1),
                "checking the probability that a np_id has been found");
    }

    if (i < 7) {
      cr_expect(true == decaying_bloom->op.check_cb(decaying_bloom, test2),
                "expect that the id test2 is     found in bloom filter");
      cr_expect(true == decaying_bloom->op.check_cb(decaying_bloom, test1),
                "expect that the id test1 is     found in bloom filter");
      cr_expect(true == decaying_bloom->op.check_cb(decaying_bloom, test3),
                "expect that the id test3 is     found in bloom filter");
      cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test4),
                "expect that the id test4 is not found in bloom filter");
      cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test5),
                "expect that the id test5 is not found in bloom filter");

    } else {
      cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test2),
                "expect that the id test2 is     found in bloom filter");
      cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test1),
                "expect that the id test1 is     found in bloom filter");
      cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test3),
                "expect that the id test3 is     found in bloom filter");
      cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test4),
                "expect that the id test4 is not found in bloom filter");
      cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test5),
                "expect that the id test5 is not found in bloom filter");
    }
  }
  _np_bloom_free(decaying_bloom);
}

Test(np_bloom_t,
     _bloom_neuropil,
     .description = "test the functions of the neuropil bloom filter") {
  //  char test_string[65];
  np_dhkey_t test1 = np_dhkey_create_from_hostport("test_1", "0");
  //  np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", "0");
  //  np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test3 = np_dhkey_create_from_hostport("test_3", "0");
  //  np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test4 = np_dhkey_create_from_hostport("test_4", "0");
  //  np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test5 = np_dhkey_create_from_hostport("test_5", "0");
  //  np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);

  struct np_bloom_optable_s neuropil_operations = {
      .add_cb       = _np_neuropil_bloom_add,
      .check_cb     = _np_neuropil_bloom_check,
      .clear_cb     = NULL,
      .union_cb     = NULL,
      .intersect_cb = NULL,
  };

  //    fprintf(stdout, "###\n");
  //    fprintf(stdout, "### Testing neuropil bloom filter now\n");
  //    fprintf(stdout, "###\n");

  np_bloom_t *neuropil_bloom = _np_neuropil_bloom_create();
  neuropil_bloom->op         = neuropil_operations;

  neuropil_bloom->op.add_cb(neuropil_bloom, test1);
  neuropil_bloom->op.add_cb(neuropil_bloom, test2);
  neuropil_bloom->op.add_cb(neuropil_bloom, test3);

  cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  for (uint8_t i = 0; i < 20; i++) {

    _np_neuropil_bloom_age_decrement(neuropil_bloom);
    // fprintf(stdout, "%f\n", _np_neuropil_bloom_get_heuristic(neuropil_bloom,
    // test1));

    if (i < 4) {
      cr_expect(0.35 <= _np_neuropil_bloom_get_heuristic(neuropil_bloom, test1),
                "checking the probability that a np_id has been found");
    } else {
      cr_expect(0.35 > _np_neuropil_bloom_get_heuristic(neuropil_bloom, test1),
                "checking the probability that a np_id has been found");
    }

    if (i < 15) {
      cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test2),
                "expect that the id test2 is     found in bloom filter");
      cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test1),
                "expect that the id test1 is     found in bloom filter");
      cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test3),
                "expect that the id test3 is     found in bloom filter");
      cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test4),
                "expect that the id test4 is not found in bloom filter");
      cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test5),
                "expect that the id test5 is not found in bloom filter");

    } else {
      cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test2),
                "expect that the id test2 is     found in bloom filter");
      cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test1),
                "expect that the id test1 is     found in bloom filter");
      cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test3),
                "expect that the id test3 is     found in bloom filter");
      cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test4),
                "expect that the id test4 is not found in bloom filter");
      cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test5),
                "expect that the id test5 is not found in bloom filter");
    }
  }

  _np_bloom_free(neuropil_bloom);
}

Test(np_bloom_t,
     _bloom_neuropil_union_intersection,
     .description =
         "test the union/intersection functions of the neuropil bloom filter") {
  //  char test_string[65];
  np_dhkey_t test1 = np_dhkey_create_from_hostport("test_1", "0");
  //  np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", "0");
  //  np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test3 = np_dhkey_create_from_hostport("test_3", "0");
  //  np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test4 = np_dhkey_create_from_hostport("test_4", "0");
  //  np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test5 = np_dhkey_create_from_hostport("test_5", "0");
  //  np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);

  struct np_bloom_optable_s neuropil_operations = {
      .add_cb       = _np_neuropil_bloom_add,
      .check_cb     = _np_neuropil_bloom_check,
      .clear_cb     = _np_neuropil_bloom_clear,
      .union_cb     = _np_neuropil_bloom_union,
      .intersect_cb = _np_neuropil_bloom_intersect,
  };

  //    fprintf(stdout, "###\n");
  //    fprintf(stdout, "### Testing neuropil bloom filter now\n");
  //    fprintf(stdout, "###\n");

  np_bloom_t *neuropil_bloom = _np_neuropil_bloom_create();
  neuropil_bloom->op         = neuropil_operations;

  np_bloom_t *union_bloom = _np_neuropil_bloom_create();
  union_bloom->op         = neuropil_operations;

  np_bloom_t *test2_bloom = _np_neuropil_bloom_create();
  test2_bloom->op         = neuropil_operations;
  np_bloom_t *test4_bloom = _np_neuropil_bloom_create();
  test4_bloom->op         = neuropil_operations;
  np_bloom_t *test5_bloom = _np_neuropil_bloom_create();
  test5_bloom->op         = neuropil_operations;

  neuropil_bloom->op.add_cb(neuropil_bloom, test2);
  neuropil_bloom->op.add_cb(neuropil_bloom, test4);
  neuropil_bloom->op.add_cb(neuropil_bloom, test5);

  test2_bloom->op.add_cb(test2_bloom, test2);
  test4_bloom->op.add_cb(test4_bloom, test4);
  test5_bloom->op.add_cb(test5_bloom, test5);

  cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  cr_expect(true == test2_bloom->op.check_cb(test2_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(true == test4_bloom->op.check_cb(test4_bloom, test4),
            "expect that the id test4 is     found in bloom filter");
  cr_expect(true == test5_bloom->op.check_cb(test5_bloom, test5),
            "expect that the id test5 is     found in bloom filter");

  cr_expect(64 == union_bloom->_free_items,
            "expect that the number of free_items is 64");

  union_bloom->op.union_cb(union_bloom, test2_bloom);
  cr_expect(64 - 1 == union_bloom->_free_items,
            "expect that the number of free_items is 63");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == union_bloom->op.check_cb(union_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(false == union_bloom->op.check_cb(union_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  union_bloom->op.union_cb(union_bloom, test4_bloom);
  cr_expect(64 - 2 == union_bloom->_free_items,
            "expect that the number of free_items is 62");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test4),
            "expect that the id test4 is     found in bloom filter");
  cr_expect(false == union_bloom->op.check_cb(union_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  union_bloom->op.union_cb(union_bloom, test5_bloom);
  cr_expect(64 - 3 == union_bloom->_free_items,
            "expect that the number of free_items is 61");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test4),
            "expect that the id test4 is     found in bloom filter");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test5),
            "expect that the id test5 is     found in bloom filter");

  np_bloom_t *intersect_bloom = _np_neuropil_bloom_create();
  intersect_bloom->op         = neuropil_operations;
  intersect_bloom->op.union_cb(intersect_bloom,
                               union_bloom); // add a default set

  intersect_bloom->op.intersect_cb(intersect_bloom, test2_bloom);
  cr_expect(0 == intersect_bloom->_free_items,
            "expect that the number of free_items is 0");
  cr_expect(true == intersect_bloom->op.check_cb(intersect_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  intersect_bloom->op.clear_cb(intersect_bloom);
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test2),
            "expect that the id test2 is not found in bloom filter");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test5),
            "expect that the id test5 is not found in bloom filter");
  intersect_bloom->op.union_cb(intersect_bloom,
                               union_bloom); // ... re-add a default set

  np_bloom_t *test1_bloom = _np_neuropil_bloom_create();
  test1_bloom->op         = neuropil_operations;
  neuropil_bloom->op.add_cb(neuropil_bloom, test1);

  intersect_bloom->op.intersect_cb(intersect_bloom, test1_bloom);
  cr_expect(0 == intersect_bloom->_free_items,
            "expect that the number of free_items is 0");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test4),
            "expect that the id test4 is     found in bloom filter");
  cr_expect(false == intersect_bloom->op.check_cb(intersect_bloom, test5),
            "expect that the id test5 is     found in bloom filter");

  _np_bloom_free(union_bloom);
  _np_bloom_free(neuropil_bloom);
  _np_bloom_free(intersect_bloom);

  _np_bloom_free(test2_bloom);
  _np_bloom_free(test4_bloom);
  _np_bloom_free(test5_bloom);
}

Test(np_bloom_t,
     _bloom_neuropil_union_similarity,
     .description =
         "test the similarity functions of the neuropil bloom filter") {
  //  char test_string[65];
  np_dhkey_t test1 = np_dhkey_create_from_hostport("test_1", "0");
  //  np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", "0");
  //  np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test3 = np_dhkey_create_from_hostport("test_3", "0");
  //  np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test4 = np_dhkey_create_from_hostport("test_4", "0");
  //  np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test5 = np_dhkey_create_from_hostport("test_5", "0");
  //  np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);

  struct np_bloom_optable_s neuropil_operations = {
      .add_cb       = _np_neuropil_bloom_add,
      .check_cb     = _np_neuropil_bloom_check,
      .clear_cb     = _np_neuropil_bloom_clear,
      .union_cb     = _np_neuropil_bloom_union,
      .intersect_cb = _np_neuropil_bloom_intersect,
  };

  //    fprintf(stdout, "###\n");
  //    fprintf(stdout, "### Testing neuropil bloom filter now\n");
  //    fprintf(stdout, "###\n");

  np_bloom_t *neuropil_bloom     = _np_neuropil_bloom_create();
  neuropil_bloom->op             = neuropil_operations;
  np_bloom_t *union_bloom        = _np_neuropil_bloom_create();
  union_bloom->op                = neuropil_operations;
  np_bloom_t *intersection_bloom = _np_neuropil_bloom_create();
  intersection_bloom->op         = neuropil_operations;
  np_bloom_t *test4_bloom        = _np_neuropil_bloom_create();
  test4_bloom->op                = neuropil_operations;
  np_bloom_t *test5_bloom        = _np_neuropil_bloom_create();
  test5_bloom->op                = neuropil_operations;

  neuropil_bloom->op.add_cb(neuropil_bloom, test2);
  neuropil_bloom->op.add_cb(neuropil_bloom, test4);
  neuropil_bloom->op.add_cb(neuropil_bloom, test5);
  cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  test4_bloom->op.add_cb(test4_bloom, test4);
  cr_expect(true == test4_bloom->op.check_cb(test4_bloom, test4),
            "expect that the id test4 is     found in bloom filter");

  test5_bloom->op.add_cb(test5_bloom, test5);
  cr_expect(true == test5_bloom->op.check_cb(test5_bloom, test5),
            "expect that the id test5 is     found in bloom filter");

  intersection_bloom->op.add_cb(intersection_bloom, test2);
  cr_expect(true == intersection_bloom->op.check_cb(intersection_bloom, test2),
            "expect that the id test2 is     found in bloom filter");

  union_bloom->op.union_cb(union_bloom, test4_bloom);
  union_bloom->op.union_cb(union_bloom, test5_bloom);
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test4),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test5),
            "expect that the id test2 is     found in bloom filter");

  float similarity = 0.0;
  _np_neuropil_bloom_similarity(neuropil_bloom, test4_bloom, &similarity);
  cr_expect_float_eq(8 / 24,
                     similarity,
                     0.5,
                     "expect that the similarity is approx. one third");

  _np_neuropil_bloom_similarity(test4_bloom, neuropil_bloom, &similarity);
  cr_expect_float_eq(8 / 24,
                     similarity,
                     0.5,
                     "expect that the similarity is approx. one third");

  _np_neuropil_bloom_similarity(neuropil_bloom, test5_bloom, &similarity);
  cr_expect_float_eq(8 / 24,
                     similarity,
                     0.5,
                     "expect that the similarity is approx. one third");

  _np_neuropil_bloom_similarity(neuropil_bloom, union_bloom, &similarity);
  cr_expect_float_eq(16 / 24,
                     similarity,
                     1,
                     "expect that the similarity is approx. two third");

  _np_neuropil_bloom_similarity(neuropil_bloom,
                                intersection_bloom,
                                &similarity);
  cr_expect_float_eq(8 / 24,
                     similarity,
                     0.5,
                     "expect that the similarity is approx. two third");

  _np_neuropil_bloom_similarity(union_bloom, intersection_bloom, &similarity);
  cr_expect_float_eq(0 / 24,
                     similarity,
                     0.5,
                     "expect that the similarity is approx. zero");

  _np_bloom_free(union_bloom);
  _np_bloom_free(neuropil_bloom);
  _np_bloom_free(intersection_bloom);

  // _np_bloom_free(test2_bloom);
  _np_bloom_free(test4_bloom);
  _np_bloom_free(test5_bloom);
}

Test(np_bloom_t,
     _bloom_neuropil_union_containment,
     .description =
         "test the containment functions of the neuropil bloom filter") {
  //  char test_string[65];
  np_dhkey_t test1 = np_dhkey_create_from_hostport("test_1", "0");
  //  np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", "0");
  //  np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test3 = np_dhkey_create_from_hostport("test_3", "0");
  //  np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test4 = np_dhkey_create_from_hostport("test_4", "0");
  //  np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test5 = np_dhkey_create_from_hostport("test_5", "0");
  //  np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);

  struct np_bloom_optable_s neuropil_operations = {
      .add_cb       = _np_neuropil_bloom_add,
      .check_cb     = _np_neuropil_bloom_check,
      .clear_cb     = _np_neuropil_bloom_clear,
      .union_cb     = _np_neuropil_bloom_union,
      .intersect_cb = _np_neuropil_bloom_intersect,
  };

  //    fprintf(stdout, "###\n");
  //    fprintf(stdout, "### Testing neuropil bloom filter now\n");
  //    fprintf(stdout, "###\n");

  np_bloom_t *neuropil_bloom     = _np_neuropil_bloom_create();
  neuropil_bloom->op             = neuropil_operations;
  np_bloom_t *union_bloom        = _np_neuropil_bloom_create();
  union_bloom->op                = neuropil_operations;
  np_bloom_t *intersection_bloom = _np_neuropil_bloom_create();
  intersection_bloom->op         = neuropil_operations;
  np_bloom_t *test4_bloom        = _np_neuropil_bloom_create();
  test4_bloom->op                = neuropil_operations;
  np_bloom_t *test5_bloom        = _np_neuropil_bloom_create();
  test5_bloom->op                = neuropil_operations;

  neuropil_bloom->op.add_cb(neuropil_bloom, test2);
  neuropil_bloom->op.add_cb(neuropil_bloom, test4);
  neuropil_bloom->op.add_cb(neuropil_bloom, test5);
  cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test4),
            "expect that the id test4 is not found in bloom filter");
  cr_expect(true == neuropil_bloom->op.check_cb(neuropil_bloom, test5),
            "expect that the id test5 is not found in bloom filter");

  test4_bloom->op.add_cb(test4_bloom, test4);
  cr_expect(true == test4_bloom->op.check_cb(test4_bloom, test4),
            "expect that the id test4 is     found in bloom filter");

  test5_bloom->op.add_cb(test5_bloom, test5);
  cr_expect(true == test5_bloom->op.check_cb(test5_bloom, test5),
            "expect that the id test5 is     found in bloom filter");

  intersection_bloom->op.add_cb(intersection_bloom, test2);
  cr_expect(true == intersection_bloom->op.check_cb(intersection_bloom, test2),
            "expect that the id test2 is     found in bloom filter");

  union_bloom->op.union_cb(union_bloom, test4_bloom);
  union_bloom->op.union_cb(union_bloom, test5_bloom);
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test4),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(true == union_bloom->op.check_cb(union_bloom, test5),
            "expect that the id test2 is     found in bloom filter");

  bool is_contained_in = false;
  _np_neuropil_bloom_containment(neuropil_bloom, test4_bloom, &is_contained_in);
  cr_expect(true == is_contained_in, "expect that the containment is true");

  _np_neuropil_bloom_containment(test4_bloom, neuropil_bloom, &is_contained_in);
  cr_expect(false == is_contained_in, "expect that the containment is true");

  _np_neuropil_bloom_containment(neuropil_bloom, test5_bloom, &is_contained_in);
  cr_expect(true == is_contained_in, "expect that the containment is true");

  _np_neuropil_bloom_containment(neuropil_bloom, union_bloom, &is_contained_in);
  cr_expect(true == is_contained_in, "expect that the containment is true");

  _np_neuropil_bloom_containment(neuropil_bloom,
                                 intersection_bloom,
                                 &is_contained_in);
  cr_expect(true == is_contained_in, "expect that the containment is true");

  _np_neuropil_bloom_containment(union_bloom,
                                 intersection_bloom,
                                 &is_contained_in);
  cr_expect(false == is_contained_in, "expect that the containment is true");

  _np_bloom_free(union_bloom);
  _np_bloom_free(neuropil_bloom);
  _np_bloom_free(intersection_bloom);

  // _np_bloom_free(test2_bloom);
  _np_bloom_free(test4_bloom);
  _np_bloom_free(test5_bloom);
}

Test(np_bloom_t,
     _bloom_neuropil_serialize,
     .description =
         "test the (de-)serialize functions of the neuropil bloom filter") {
  //  char test_string[65];
  np_dhkey_t test1 = np_dhkey_create_from_hostport("test_1", "0");
  //  np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", "0");
  //  np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test3 = np_dhkey_create_from_hostport("test_3", "0");
  //  np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test4 = np_dhkey_create_from_hostport("test_4", "0");
  //  np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
  np_dhkey_t test5 = np_dhkey_create_from_hostport("test_5", "0");
  //  np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);

  struct np_bloom_optable_s neuropil_operations = {
      .add_cb       = _np_neuropil_bloom_add,
      .check_cb     = _np_neuropil_bloom_check,
      .clear_cb     = NULL,
      .union_cb     = NULL,
      .intersect_cb = NULL,
  };

  np_bloom_t *neuropil_bloom_in = _np_neuropil_bloom_create();
  neuropil_bloom_in->op         = neuropil_operations;

  neuropil_bloom_in->op.add_cb(neuropil_bloom_in, test1);
  cr_expect(0.5 == _np_neuropil_bloom_intersect_age(neuropil_bloom_in,
                                                    neuropil_bloom_in),
            "expect the age to be 0.5");

  _np_neuropil_bloom_age_decrement(neuropil_bloom_in);
  cr_expect(0.46875 == _np_neuropil_bloom_intersect_age(neuropil_bloom_in,
                                                        neuropil_bloom_in),
            "expect the age to be 0.46...");
  neuropil_bloom_in->op.add_cb(neuropil_bloom_in, test2);
  cr_expect(0.46875 == _np_neuropil_bloom_intersect_age(neuropil_bloom_in,
                                                        neuropil_bloom_in),
            "expect the age to be 0.46...");

  _np_neuropil_bloom_age_decrement(neuropil_bloom_in);
  neuropil_bloom_in->op.add_cb(neuropil_bloom_in, test4);
  cr_expect(0.4375 == _np_neuropil_bloom_intersect_age(neuropil_bloom_in,
                                                       neuropil_bloom_in),
            "expect the age to be 0.43...");

  cr_expect(true == neuropil_bloom_in->op.check_cb(neuropil_bloom_in, test1),
            "expect that the id test1 is     found in bloom filter");
  cr_expect(true == neuropil_bloom_in->op.check_cb(neuropil_bloom_in, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == neuropil_bloom_in->op.check_cb(neuropil_bloom_in, test3),
            "expect that the id test3 is not found in bloom filter");
  cr_expect(true == neuropil_bloom_in->op.check_cb(neuropil_bloom_in, test4),
            "expect that the id test4 is     found in bloom filter");
  cr_expect(false == neuropil_bloom_in->op.check_cb(neuropil_bloom_in, test5),
            "expect that the id test5 is not found in bloom filter");

  cr_expect(0.5 >= _np_neuropil_bloom_get_heuristic(neuropil_bloom_in, test1),
            "checking the probability that a np_id has been found");
  cr_expect(0.3 <= _np_neuropil_bloom_get_heuristic(neuropil_bloom_in, test1),
            "checking the probability that a np_id has been found");
  cr_expect(0.5 >= _np_neuropil_bloom_get_heuristic(neuropil_bloom_in, test2),
            "checking the probability that a np_id has been found");
  cr_expect(0.35 <= _np_neuropil_bloom_get_heuristic(neuropil_bloom_in, test2),
            "checking the probability that a np_id has been found");
  cr_expect(0.5 == _np_neuropil_bloom_get_heuristic(neuropil_bloom_in, test4),
            "checking the probability that a np_id has been found");

  unsigned char *buffer      = NULL;
  uint16_t       buffer_size = 0;
  _np_neuropil_bloom_serialize(neuropil_bloom_in, &buffer, &buffer_size);

  //        cr_expect(256 >= buffer_size, "expect that the buffer size to be
  //        less than 256 bytes (32*8)"); cr_expect(  4 <= buffer_size, "expect
  //        that the buffer size to be more than   4 bytes (32*8)");

  np_bloom_t *neuropil_bloom_out = _np_neuropil_bloom_create();
  neuropil_bloom_out->op         = neuropil_operations;

  _np_neuropil_bloom_deserialize(neuropil_bloom_out, buffer, buffer_size);

  free(buffer); // not needed anymore

  cr_expect(true == neuropil_bloom_out->op.check_cb(neuropil_bloom_out, test1),
            "expect that the id test1 is     found in bloom filter");
  cr_expect(true == neuropil_bloom_out->op.check_cb(neuropil_bloom_out, test2),
            "expect that the id test2 is     found in bloom filter");
  cr_expect(false == neuropil_bloom_out->op.check_cb(neuropil_bloom_out, test3),
            "expect that the id test3 is not found in bloom filter");
  cr_expect(true == neuropil_bloom_out->op.check_cb(neuropil_bloom_out, test4),
            "expect that the id test4 is     found in bloom filter");
  cr_expect(false == neuropil_bloom_out->op.check_cb(neuropil_bloom_out, test5),
            "expect that the id test5 is not found in bloom filter");

  cr_expect(0.5 >= _np_neuropil_bloom_get_heuristic(neuropil_bloom_in, test1),
            "checking the probability that a np_id has been found");
  cr_expect(0.3 <= _np_neuropil_bloom_get_heuristic(neuropil_bloom_in, test1),
            "checking the probability that a np_id has been found");
  cr_expect(0.5 >= _np_neuropil_bloom_get_heuristic(neuropil_bloom_in, test2),
            "checking the probability that a np_id has been found");
  cr_expect(0.35 <= _np_neuropil_bloom_get_heuristic(neuropil_bloom_in, test2),
            "checking the probability that a np_id has been found");
  cr_expect(0.5 == _np_neuropil_bloom_get_heuristic(neuropil_bloom_in, test4),
            "checking the probability that a np_id has been found");

  cr_expect(neuropil_bloom_out->_free_items == neuropil_bloom_in->_free_items,
            "checking if the number of free items is equal");

  _np_bloom_free(neuropil_bloom_in);
  _np_bloom_free(neuropil_bloom_out);
}
