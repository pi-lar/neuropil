//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "neuropil.h"

#include "util/np_bloom.h"

#include "np_util.h"

#undef cr_expect
#define cr_expect(A, B) assert((A) && B)
int main() {
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
      .add_cb       = _np_enhanced_bloom_add,
      .check_cb     = _np_enhanced_bloom_check,
      .clear_cb     = _np_enhanced_bloom_clear,
      .union_cb     = _np_enhanced_bloom_union,
      .intersect_cb = _np_enhanced_bloom_intersect,
  };

  //    fprintf(stdout, "###\n");
  //    fprintf(stdout, "### Testing neuropil bloom filter now\n");
  //    fprintf(stdout, "###\n");

  np_bloom_t *standard_bloom = _np_enhanced_bloom_create(512);
  standard_bloom->op         = neuropil_operations;

  np_bloom_t *union_bloom = _np_enhanced_bloom_create(512);
  union_bloom->op         = neuropil_operations;

  np_bloom_t *test2_bloom = _np_enhanced_bloom_create(512);
  test2_bloom->op         = neuropil_operations;
  np_bloom_t *test4_bloom = _np_enhanced_bloom_create(512);
  test4_bloom->op         = neuropil_operations;
  np_bloom_t *test5_bloom = _np_enhanced_bloom_create(512);
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

  np_bloom_t *intersect_bloom = _np_enhanced_bloom_create(512);
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

  np_bloom_t *test1_bloom = _np_enhanced_bloom_create(512);
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

  _np_enhanced_bloom_free(union_bloom);
  _np_enhanced_bloom_free(standard_bloom);
  _np_enhanced_bloom_free(intersect_bloom);

  _np_enhanced_bloom_free(test2_bloom);
  _np_enhanced_bloom_free(test4_bloom);
  _np_enhanced_bloom_free(test5_bloom);
}
