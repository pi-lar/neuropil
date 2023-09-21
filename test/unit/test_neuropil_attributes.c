//
// neuropil is copyright 2016-2024 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file
// for details
//
#include <criterion/criterion.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "../test_macros.c"
#include "pthread.h"

#include "neuropil_attributes.h"

#include "util/np_bloom.h"

#include "np_attributes.h"

TestSuite(neuropil_attributes);

Test(neuropil_attributes,
     _check_policiy_bin,
     .description = "test the interaction of policies") {
  unsigned char matching_data[5]       = "55487";
  unsigned char not_matching_data1[6]  = "355487";
  unsigned char not_matching_data2[10] = "5548772435";
  unsigned char not_matching_data3[10] = "7129a75645";
  unsigned char not_matching_data4[10] = "3255487323";

  np_bloom_t *empty_policy = _np_attribute_bloom();

  np_bloom_t *bloom_key_required = _np_attribute_bloom();
  _np_policy_set_key(bloom_key_required, "test_key");

  np_bloom_t *bloom_key_and_matching_value = _np_attribute_bloom();
  _np_policy_set_bin(bloom_key_and_matching_value,
                     "test_key",
                     matching_data,
                     sizeof(matching_data));

  struct np_data_conf conf = {0};
  conf.type                = NP_DATA_TYPE_BIN;

  np_attributes_t attr_block_no_key = {0};
  np_init_datablock(&attr_block_no_key, sizeof(np_attributes_t));

  np_attributes_t attr_block_alternative_key = {0};
  np_init_datablock(&attr_block_alternative_key, sizeof(np_attributes_t));
  strncpy(conf.key, "test_key2", 255);
  conf.data_size = 0;
  cr_expect(np_data_ok == np_set_data(&attr_block_alternative_key,
                                      conf,
                                      (np_data_value){.bin = {0}}),
            "Could not add data to attribute block");

  np_attributes_t attr_block_alternative_key_matching_value = {0};
  np_init_datablock(&attr_block_alternative_key_matching_value,
                    sizeof(np_attributes_t));
  strncpy(conf.key, "test_key2", 255);
  conf.data_size = sizeof(matching_data);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_alternative_key_matching_value,
                            conf,
                            (np_data_value){.bin = matching_data}),
            "Could not add data to attribute block");

  np_attributes_t attr_block_key_matching_value = {0};
  np_init_datablock(&attr_block_key_matching_value, sizeof(np_attributes_t));
  strncpy(conf.key, "test_key", 255);
  conf.data_size = sizeof(matching_data);
  cr_expect(np_data_ok == np_set_data(&attr_block_key_matching_value,
                                      conf,
                                      (np_data_value){.bin = matching_data}),
            "Could not add data to attribute block");

  np_attributes_t attr_block_key_not_matching_value1 = {0};
  np_init_datablock(&attr_block_key_not_matching_value1,
                    sizeof(np_attributes_t));
  strncpy(conf.key, "test_key", 255);
  conf.data_size = sizeof(not_matching_data1);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_key_not_matching_value1,
                            conf,
                            (np_data_value){.bin = not_matching_data1}),
            "Could not add data to attribute block");

  np_attributes_t attr_block_key_not_matching_value2 = {0};
  np_init_datablock(&attr_block_key_not_matching_value2,
                    sizeof(np_attributes_t));
  strncpy(conf.key, "test_key", 255);
  conf.data_size = sizeof(not_matching_data2);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_key_not_matching_value2,
                            conf,
                            (np_data_value){.bin = not_matching_data2}),
            "Could not add data to attribute block");

  np_attributes_t attr_block_key_not_matching_value3 = {0};
  np_init_datablock(&attr_block_key_not_matching_value3,
                    sizeof(np_attributes_t));
  strncpy(conf.key, "test_key", 255);
  conf.data_size = sizeof(not_matching_data3);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_key_not_matching_value3,
                            conf,
                            (np_data_value){.bin = not_matching_data3}),
            "Could not add data to attribute block");

  np_attributes_t attr_block_key_not_matching_value4 = {0};
  np_init_datablock(&attr_block_key_not_matching_value4,
                    sizeof(np_attributes_t));
  strncpy(conf.key, "test_key", 255);
  conf.data_size = sizeof(not_matching_data4);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_key_not_matching_value4,
                            conf,
                            (np_data_value){.bin = not_matching_data4}),
            "Could not add data to attribute block");

  np_attributes_t attr_block_multi_key_not_matching = {0};
  np_init_datablock(&attr_block_multi_key_not_matching,
                    sizeof(np_attributes_t));
  strncpy(conf.key, "test_key1", 255);
  conf.data_size = sizeof(not_matching_data1);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_multi_key_not_matching,
                            conf,
                            (np_data_value){.bin = not_matching_data1}),
            "Could not add data to attribute block");
  strncpy(conf.key, "test_key2", 255);
  conf.data_size = sizeof(not_matching_data2);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_multi_key_not_matching,
                            conf,
                            (np_data_value){.bin = not_matching_data2}),
            "Could not add data to attribute block");
  strncpy(conf.key, "test_key3", 255);
  conf.data_size = sizeof(not_matching_data3);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_multi_key_not_matching,
                            conf,
                            (np_data_value){.bin = not_matching_data3}),
            "Could not add data to attribute block");

  np_attributes_t attr_block_multi_key_1_matching = {0};
  np_init_datablock(&attr_block_multi_key_1_matching, sizeof(np_attributes_t));
  strncpy(conf.key, "test_key", 255);
  conf.data_size = sizeof(matching_data);
  cr_expect(np_data_ok == np_set_data(&attr_block_multi_key_1_matching,
                                      conf,
                                      (np_data_value){.bin = matching_data}),
            "Could not add data to attribute block");
  strncpy(conf.key, "test_key2", 255);
  conf.data_size = sizeof(not_matching_data2);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_multi_key_1_matching,
                            conf,
                            (np_data_value){.bin = not_matching_data2}),
            "Could not add data to attribute block");
  strncpy(conf.key, "test_key3", 255);
  conf.data_size = sizeof(not_matching_data3);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_multi_key_1_matching,
                            conf,
                            (np_data_value){.bin = not_matching_data3}),
            "Could not add data to attribute block");

  np_attributes_t attr_block_multi_key_2_matching = {0};
  np_init_datablock(&attr_block_multi_key_2_matching, sizeof(np_attributes_t));
  strncpy(conf.key, "test_key1", 255);
  conf.data_size = sizeof(not_matching_data1);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_multi_key_2_matching,
                            conf,
                            (np_data_value){.bin = not_matching_data1}),
            "Could not add data to attribute block");
  strncpy(conf.key, "test_key", 255);
  conf.data_size = sizeof(matching_data);
  cr_expect(np_data_ok == np_set_data(&attr_block_multi_key_2_matching,
                                      conf,
                                      (np_data_value){.bin = matching_data}),
            "Could not add data to attribute block");
  strncpy(conf.key, "test_key3", 255);
  conf.data_size = sizeof(not_matching_data3);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_multi_key_2_matching,
                            conf,
                            (np_data_value){.bin = not_matching_data3}),
            "Could not add data to attribute block");

  np_attributes_t attr_block_multi_key_3_matching = {0};
  np_init_datablock(&attr_block_multi_key_3_matching, sizeof(np_attributes_t));
  strncpy(conf.key, "test_key1", 255);
  conf.data_size = sizeof(not_matching_data1);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_multi_key_3_matching,
                            conf,
                            (np_data_value){.bin = not_matching_data1}),
            "Could not add data to attribute block");
  strncpy(conf.key, "test_key2", 255);
  conf.data_size = sizeof(not_matching_data2);
  cr_expect(np_data_ok ==
                np_set_data(&attr_block_multi_key_3_matching,
                            conf,
                            (np_data_value){.bin = not_matching_data2}),
            "Could not add data to attribute block");
  strncpy(conf.key, "test_key", 255);
  conf.data_size = sizeof(matching_data);
  cr_expect(np_data_ok == np_set_data(&attr_block_multi_key_3_matching,
                                      conf,
                                      (np_data_value){.bin = matching_data}),
            "Could not add data to attribute block");

  cr_expect(_np_policy_check_compliance(empty_policy, &attr_block_no_key) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(empty_policy,
                                        &attr_block_alternative_key) == true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(
                empty_policy,
                &attr_block_alternative_key_matching_value) == true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(empty_policy,
                                        &attr_block_key_matching_value) == true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(empty_policy,
                                        &attr_block_key_not_matching_value1) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(empty_policy,
                                        &attr_block_key_not_matching_value2) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(empty_policy,
                                        &attr_block_key_not_matching_value3) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(empty_policy,
                                        &attr_block_key_not_matching_value4) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(empty_policy,
                                        &attr_block_multi_key_not_matching) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(empty_policy,
                                        &attr_block_multi_key_1_matching) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(empty_policy,
                                        &attr_block_multi_key_2_matching) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(empty_policy,
                                        &attr_block_multi_key_3_matching) ==
                true,
            "policy compliance error");

  cr_expect(_np_policy_check_compliance(bloom_key_required,
                                        &attr_block_no_key) == false,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_required,
                                        &attr_block_alternative_key) == false,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(
                bloom_key_required,
                &attr_block_alternative_key_matching_value) == false,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_required,
                                        &attr_block_key_matching_value) == true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_required,
                                        &attr_block_key_not_matching_value1) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_required,
                                        &attr_block_key_not_matching_value2) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_required,
                                        &attr_block_key_not_matching_value3) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_required,
                                        &attr_block_key_not_matching_value4) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_required,
                                        &attr_block_multi_key_not_matching) ==
                false,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_required,
                                        &attr_block_multi_key_1_matching) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_required,
                                        &attr_block_multi_key_2_matching) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_required,
                                        &attr_block_multi_key_3_matching) ==
                true,
            "policy compliance error");

  cr_expect(_np_policy_check_compliance(bloom_key_and_matching_value,
                                        &attr_block_no_key) == false,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_and_matching_value,
                                        &attr_block_alternative_key) == false,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(
                bloom_key_and_matching_value,
                &attr_block_alternative_key_matching_value) == false,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_and_matching_value,
                                        &attr_block_key_matching_value) == true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_and_matching_value,
                                        &attr_block_key_not_matching_value1) ==
                false,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_and_matching_value,
                                        &attr_block_key_not_matching_value2) ==
                false,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_and_matching_value,
                                        &attr_block_key_not_matching_value3) ==
                false,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_and_matching_value,
                                        &attr_block_key_not_matching_value4) ==
                false,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_and_matching_value,
                                        &attr_block_multi_key_not_matching) ==
                false,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_and_matching_value,
                                        &attr_block_multi_key_1_matching) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_and_matching_value,
                                        &attr_block_multi_key_2_matching) ==
                true,
            "policy compliance error");
  cr_expect(_np_policy_check_compliance(bloom_key_and_matching_value,
                                        &attr_block_multi_key_3_matching) ==
                true,
            "policy compliance error");
}

Test(neuropil_attributes,
     merge_attributes,
     .description = "test the merging of attributes") {
  unsigned char matching_data[5]       = "55487";
  unsigned char not_matching_data1[6]  = "355487";
  unsigned char not_matching_data2[10] = "5548772435";
  unsigned char not_matching_data3[10] = "7129a75645";
  unsigned char not_matching_data4[10] = "3255487323";

  struct np_data_conf conf = {0};
  conf.type                = NP_DATA_TYPE_BIN;

  // initialize two datablocks
  np_attributes_t attribute_set_1 = {0};
  np_init_datablock(attribute_set_1, sizeof(np_attributes_t));
  np_attributes_t attribute_set_2 = {0};
  np_init_datablock(attribute_set_2, sizeof(np_attributes_t));

  // add one entry with same key to both sets
  strncpy(conf.key, "test_key1", 255);
  conf.data_size = sizeof(matching_data);
  cr_expect(np_data_ok == np_set_data(attribute_set_1,
                                      conf,
                                      (np_data_value){.bin = matching_data}),
            "Could not add data to attribute block");
  cr_expect(np_data_ok == np_set_data(attribute_set_2,
                                      conf,
                                      (np_data_value){.bin = matching_data}),
            "Could not add data to attribute block");

  // add one entry with different values to both set
  strncpy(conf.key, "test_key2", 255);
  conf.data_size = sizeof(not_matching_data2);
  cr_expect(np_data_ok ==
                np_set_data(attribute_set_1,
                            conf,
                            (np_data_value){.bin = not_matching_data2}),
            "Could not add data to attribute block");
  conf.data_size = sizeof(not_matching_data3);
  cr_expect(np_data_ok ==
                np_set_data(attribute_set_2,
                            conf,
                            (np_data_value){.bin = not_matching_data3}),
            "Could not add data to attribute block");

  // add one entry to only one set
  strncpy(conf.key, "test_key3", 255);
  conf.data_size = sizeof(not_matching_data4);
  cr_expect(np_data_ok ==
                np_set_data(attribute_set_1,
                            conf,
                            (np_data_value){.bin = not_matching_data4}),
            "Could not add data to attribute block");

  // merge the first set into the second set
  np_attributes_t attribute_set_m1 = {0};
  np_init_datablock(attribute_set_m1, sizeof(np_attributes_t));
  cr_expect(np_data_ok == np_merge_data(attribute_set_m1, attribute_set_1),
            "Could not merge data");
  cr_expect(np_data_ok == np_merge_data(attribute_set_m1, attribute_set_2),
            "Could not merge data");

  // check which data has made it
  memset(&conf, 0, sizeof(struct np_data_conf));
  np_data_value val_title = {0};
  cr_expect(np_data_ok ==
                np_get_data(attribute_set_m1, "test_key3", &conf, &val_title),
            "could not fetch value for existing key");
  cr_expect(conf.data_size == sizeof(not_matching_data4),
            "attribute value size is not matching expected value size");
  cr_expect(conf.type == NP_DATA_TYPE_BIN,
            "attribute value size is not matching expected value size");
  cr_expect(memcmp(val_title.bin, not_matching_data4, conf.data_size) == 0,
            "attribute value is not matching expected value");
  memset(&conf, 0, sizeof(struct np_data_conf));

  cr_expect(np_data_ok ==
                np_get_data(attribute_set_m1, "test_key1", &conf, &val_title),
            "could not fetch value for existing key");
  cr_expect(conf.data_size == sizeof(matching_data),
            "attribute value size is not matching expected value size");
  cr_expect(conf.type == NP_DATA_TYPE_BIN,
            "attribute value size is not matching expected value size");
  cr_expect(memcmp(val_title.bin, matching_data, conf.data_size) == 0,
            "attribute value is not matching expected value");
  memset(&conf, 0, sizeof(struct np_data_conf));

  cr_expect(np_data_ok ==
                np_get_data(attribute_set_m1, "test_key2", &conf, &val_title),
            "could not fetch value for existing key");
  cr_expect(conf.data_size == sizeof(not_matching_data3),
            "attribute value size is not matching expected value size");
  cr_expect(conf.type == NP_DATA_TYPE_BIN,
            "attribute value size is not matching expected value size");
  cr_expect(memcmp(val_title.bin, not_matching_data3, conf.data_size) == 0,
            "attribute value is not matching expected value");
  memset(&conf, 0, sizeof(struct np_data_conf));

  // merge the second set into the first set
  // merge the first set into the second set
  np_attributes_t attribute_set_m2 = {0};
  np_init_datablock(attribute_set_m2, sizeof(np_attributes_t));
  cr_expect(np_data_ok == np_merge_data(attribute_set_m2, attribute_set_2),
            "Could not merge data");
  cr_expect(np_data_ok == np_merge_data(attribute_set_m2, attribute_set_1),
            "Could not merge data");

  // check which data has made it
  memset(&conf, 0, sizeof(struct np_data_conf));
  cr_expect(np_data_ok ==
                np_get_data(attribute_set_m2, "test_key3", &conf, &val_title),
            "could not fetch value for existing key");
  cr_expect(conf.data_size == sizeof(not_matching_data4),
            "attribute value size is not matching expected value size");
  cr_expect(conf.type == NP_DATA_TYPE_BIN,
            "attribute value size is not matching expected value size");
  cr_expect(memcmp(val_title.bin, not_matching_data4, conf.data_size) == 0,
            "attribute value is not matching expected value");
  memset(&conf, 0, sizeof(struct np_data_conf));

  cr_expect(np_data_ok ==
                np_get_data(attribute_set_m2, "test_key1", &conf, &val_title),
            "could not fetch value for existing key");
  cr_expect(conf.data_size == sizeof(matching_data),
            "attribute value size is not matching expected value size");
  cr_expect(conf.type == NP_DATA_TYPE_BIN,
            "attribute value size is not matching expected value size");
  cr_expect(memcmp(val_title.bin, matching_data, conf.data_size) == 0,
            "attribute value is not matching expected value");
  memset(&conf, 0, sizeof(struct np_data_conf));

  cr_expect(np_data_ok ==
                np_get_data(attribute_set_m2, "test_key2", &conf, &val_title),
            "could not fetch value for existing key");
  cr_expect(conf.data_size == sizeof(not_matching_data2),
            "attribute value size is not matching expected value size");
  cr_expect(conf.type == NP_DATA_TYPE_BIN,
            "attribute value size is not matching expected value size");
  cr_expect(memcmp(val_title.bin, not_matching_data2, conf.data_size) == 0,
            "attribute value is not matching expected value");
  memset(&conf, 0, sizeof(struct np_data_conf));
}