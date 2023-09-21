//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <criterion/criterion.h>
#include <inttypes.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>

#include "../test_macros.c"
#include "pthread.h"

#include "neuropil_data.h"

TestSuite(neuropil_data);

Test(neuropil_data,
     _check_insert_bin,
     .description =
         "test the serialization and deserialization of a BIN datablock") {
  enum np_data_return tmp_ret;
  struct np_data_conf deserialized_data_conf = {0};
  np_data_value       deserialized_data;

  size_t        datablock_size = 2000;
  unsigned char datablock[datablock_size];

  uint32_t      data_size = 452;
  unsigned char data1[452];
  memset(data1, 'A', data_size);
  unsigned char data2[452];
  memset(data2, 'B', data_size);

  // init datatablock
  cr_assert(np_data_ok ==
                (tmp_ret = np_init_datablock(datablock, datablock_size)),
            "expect initialized datablock. (ret: %" PRIu32 ")",
            tmp_ret);

  // insert TEST with data1
  struct np_data_conf data_conf =
      (struct np_data_conf){.key       = "TEST",
                            .type      = NP_DATA_TYPE_BIN,
                            .data_size = data_size};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf,
                                       (np_data_value){.bin = data1})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_BIN,
            "Expected BIN container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected BIN container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size == data_size,
            "Expected BIN container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == memcmp(deserialized_data.bin,
                        data1,
                        MIN(data_size, deserialized_data_conf.data_size)),
            "Expected BIN data to be the same");
}

Test(neuropil_data,
     _check_insert_int,
     .description =
         "test the serialization and deserialization of an INT datablock") {
  enum np_data_return tmp_ret;
  struct np_data_conf deserialized_data_conf = {0};
  np_data_value       deserialized_data;

  size_t        datablock_size = 2000;
  unsigned char datablock[datablock_size];

  int32_t input = -12399;
  // init datatablock
  cr_assert(np_data_ok ==
                (tmp_ret = np_init_datablock(datablock, datablock_size)),
            "expect initialized datablock. (ret: %" PRIu32 ")",
            tmp_ret);

  // insert TEST with data1
  struct np_data_conf data_conf =
      (struct np_data_conf){.key = "TEST", .type = NP_DATA_TYPE_INT};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf,
                                       (np_data_value){.integer = input})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_INT,
            "Expected INT container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected INT container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size == sizeof(input),
            "Expected INT container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(input == deserialized_data.integer,
            "Expected INT data to be the same. NOT %" PRId32
            " expected: %" PRId32,
            deserialized_data.integer,
            input);
}

Test(neuropil_data,
     _check_insert_str,
     .description =
         "test the serialization and deserialization of an STR datablock") {
  enum np_data_return tmp_ret;
  struct np_data_conf deserialized_data_conf = {0};
  np_data_value       deserialized_data      = {0};

  size_t        datablock_size = 2000;
  unsigned char datablock[datablock_size];

  char *input = "abc";
  // init datatablock
  cr_assert(np_data_ok ==
                (tmp_ret = np_init_datablock(datablock, datablock_size)),
            "expect initialized datablock. (ret: %" PRIu32 ")",
            tmp_ret);

  // insert TEST with data1
  struct np_data_conf data_conf =
      (struct np_data_conf){.key       = "TEST",
                            .type      = NP_DATA_TYPE_STR,
                            .data_size = strnlen(input, 255)};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf,
                                       (np_data_value){.str = input})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_STR,
            "Expected STR container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected STR container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size ==
                sizeof(char) * strnlen(input, 255),
            "Expected STR container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == strncmp(input, deserialized_data.str, 255),
            "Expected STR data to be the same. NOT %s expected: %s",
            deserialized_data.str,
            input);
}

Test(neuropil_data,
     _check_insert_str_overwrite,
     .description =
         "test the serialization and deserialization of an STR datablock") {
  enum np_data_return tmp_ret;
  struct np_data_conf deserialized_data_conf = {0};
  np_data_value       deserialized_data      = {0};

  size_t        datablock_size = 2000;
  unsigned char datablock[datablock_size];

  char *input   = "abc";
  char *input_2 = "defghi";
  // init datatablock
  cr_assert(np_data_ok ==
                (tmp_ret = np_init_datablock(datablock, datablock_size)),
            "expect initialized datablock. (ret: %" PRIu32 ")",
            tmp_ret);

  // insert TEST with data1
  struct np_data_conf data_conf =
      (struct np_data_conf){.key       = "TEST",
                            .type      = NP_DATA_TYPE_STR,
                            .data_size = strnlen(input, 255)};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf,
                                       (np_data_value){.str = input})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  struct np_data_conf data_conf_x =
      (struct np_data_conf){.key       = "TEST_2",
                            .type      = NP_DATA_TYPE_STR,
                            .data_size = strnlen(input_2, 255)};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf_x,
                                       (np_data_value){.str = input_2})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST_2 for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST_2",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_assert(np_data_ok == tmp_ret,
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_STR,
            "Expected STR container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST_2", 6),
            "Expected STR container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size ==
                sizeof(char) * strnlen(input_2, 255),
            "Expected STR container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == strncmp(input_2, deserialized_data.str, 255),
            "Expected STR data to be the same. NOT %s expected: %s",
            deserialized_data.str,
            input_2);

  // check TEST for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_STR,
            "Expected STR container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected STR container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size ==
                sizeof(char) * strnlen(input, 255),
            "Expected STR container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == strncmp(input,
                         deserialized_data.str,
                         deserialized_data_conf.data_size),
            "Expected STR data to be the same. NOT %s expected: %s",
            deserialized_data.str,
            input);

  char *input2 = "LLLLL";

  // insert TEST with data1
  struct np_data_conf data_conf2 =
      (struct np_data_conf){.key       = "TEST",
                            .type      = NP_DATA_TYPE_STR,
                            .data_size = strnlen(input2, 255)};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf2,
                                       (np_data_value){.str = input2})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_STR,
            "Expected STR container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected STR container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size ==
                sizeof(char) * strnlen(input2, 255),
            "Expected STR container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == strncmp(input2,
                         deserialized_data.str,
                         deserialized_data_conf.data_size),
            "Expected STR data to be the same. NOT %s expected: %s",
            deserialized_data.str,
            input2);
  // check TEST_2 for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST_2",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_STR,
            "Expected STR container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST_2", 6),
            "Expected STR container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size ==
                sizeof(char) * strnlen(input_2, 255),
            "Expected STR container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == strncmp(input_2,
                         deserialized_data.str,
                         deserialized_data_conf.data_size),
            "Expected STR data to be the same. NOT %s expected: %s",
            deserialized_data.str,
            input_2);

  char *input3 = "L";
  // insert TEST with data1
  struct np_data_conf data_conf3 =
      (struct np_data_conf){.key       = "TEST",
                            .type      = NP_DATA_TYPE_STR,
                            .data_size = strnlen(input3, 255)};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf3,
                                       (np_data_value){.str = input3})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_STR,
            "Expected STR container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected STR container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size ==
                sizeof(char) * strnlen(input3, 255),
            "Expected STR container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == strncmp(input3,
                         deserialized_data.str,
                         deserialized_data_conf.data_size),
            "Expected STR data to be the same. NOT %s expected: %s",
            deserialized_data.str,
            input2);
  // check TEST_2 for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST_2",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_STR,
            "Expected STR container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST_2", 6),
            "Expected STR container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size ==
                sizeof(char) * strnlen(input_2, 255),
            "Expected STR container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == strncmp(input_2,
                         deserialized_data.str,
                         deserialized_data_conf.data_size),
            "Expected STR data to be the same. NOT %s expected: %s",
            deserialized_data.str,
            input_2);
}

Test(neuropil_data,
     _check_insert_uint,
     .description =
         "test the serialization and deserialization of an UNSIGNED INT "
         "datablock") {
  enum np_data_return tmp_ret;
  struct np_data_conf deserialized_data_conf = {0};
  np_data_value       deserialized_data;

  size_t        datablock_size = 2000;
  unsigned char datablock[datablock_size];

  uint32_t input = 12399;
  // init datatablock
  cr_assert(np_data_ok ==
                (tmp_ret = np_init_datablock(datablock, datablock_size)),
            "expect initialized datablock. (ret: %" PRIu32 ")",
            tmp_ret);

  // insert TEST with data1
  struct np_data_conf data_conf =
      (struct np_data_conf){.key = "TEST", .type = NP_DATA_TYPE_UNSIGNED_INT};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf,
                                       (np_data_value){.integer = input})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_UNSIGNED_INT,
            "Expected uINT container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected uINT container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size == sizeof(input),
            "Expected uINT container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(input == deserialized_data.unsigned_integer,
            "Expected uINT data to be the same. NOT %" PRId32
            " expected: %" PRIu32,
            deserialized_data.integer,
            input);
}

Test(neuropil_data,
     _check_merge,
     .description =
         "test the serialization and deserialization of an UNSIGNED INT "
         "datablock") {
  enum np_data_return tmp_ret;
  struct np_data_conf deserialized_data_conf = {0};
  np_data_value       deserialized_data;

  size_t        datablock_size = 2000;
  unsigned char datablock[datablock_size];

  uint32_t input = 12399;
  // init datatablock
  cr_assert(np_data_ok ==
                (tmp_ret = np_init_datablock(datablock, datablock_size)),
            "expect initialized datablock. (ret: %" PRIu32 ")",
            tmp_ret);

  // insert TEST with data1
  struct np_data_conf data_conf =
      (struct np_data_conf){.key = "TEST", .type = NP_DATA_TYPE_UNSIGNED_INT};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf,
                                       (np_data_value){.integer = input})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  unsigned char datablock2[datablock_size];
  cr_assert(np_data_ok ==
                (tmp_ret = np_init_datablock(datablock2, datablock_size)),
            "expect initialized datablock. (ret: %" PRIu32 ")",
            tmp_ret);

  cr_assert(np_data_ok == (tmp_ret = np_merge_data(datablock2, datablock)),
            "expect successfull merge. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock2,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_UNSIGNED_INT,
            "Expected uINT container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected uINT container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size == sizeof(input),
            "Expected uINT container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(input == deserialized_data.unsigned_integer,
            "Expected uINT data to be the same. NOT %" PRId32
            " expected: %" PRIu32,
            deserialized_data.integer,
            input);
}

Test(neuropil_data,
     _check_merge_overwrite,
     .description =
         "test the serialization and deserialization of an UNSIGNED INT "
         "datablock") {
  enum np_data_return tmp_ret;
  struct np_data_conf deserialized_data_conf = {0};
  np_data_value       deserialized_data;

  size_t        datablock_size = 2000;
  unsigned char datablock[datablock_size];

  uint32_t input  = 12399;
  uint32_t input2 = 99911;
  // init datatablock
  cr_assert(np_data_ok ==
                (tmp_ret = np_init_datablock(datablock, datablock_size)),
            "expect initialized datablock. (ret: %" PRIu32 ")",
            tmp_ret);

  // insert TEST with data1
  struct np_data_conf data_conf =
      (struct np_data_conf){.key = "TEST", .type = NP_DATA_TYPE_UNSIGNED_INT};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf,
                                       (np_data_value){.integer = input})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  unsigned char datablock2[datablock_size];
  cr_assert(np_data_ok ==
                (tmp_ret = np_init_datablock(datablock2, datablock_size)),
            "expect initialized datablock. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock2,
                                       data_conf,
                                       (np_data_value){.integer = input2})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  cr_assert(np_data_ok == (tmp_ret = np_merge_data(datablock2, datablock)),
            "expect successfull merge. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock2,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_UNSIGNED_INT,
            "Expected uINT container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected uINT container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size == sizeof(input),
            "Expected uINT container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(input == deserialized_data.unsigned_integer,
            "Expected uINT data to be the same. NOT %" PRId32
            " expected: %" PRIu32,
            deserialized_data.integer,
            input);
}

Test(neuropil_data,
     _check_multi_insert,
     .description =
         "test the serialization and deserialization of a BIN datablock") {
  enum np_data_return tmp_ret;
  struct np_data_conf deserialized_data_conf = {0};
  np_data_value       deserialized_data;

  size_t        datablock_size = 2000;
  unsigned char datablock[datablock_size];

  uint32_t      data_size = 452;
  unsigned char data1[452];
  memset(data1, 'A', data_size);
  unsigned char data2[452];
  memset(data2, 'B', data_size);

  // init datatablock
  cr_assert(np_data_ok ==
                (tmp_ret = np_init_datablock(datablock, datablock_size)),
            "expect initialized datablock. (ret: %" PRIu32 ")",
            tmp_ret);

  // insert TEST with data1
  struct np_data_conf data_conf =
      (struct np_data_conf){.key       = "TEST",
                            .type      = NP_DATA_TYPE_BIN,
                            .data_size = data_size};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf,
                                       (np_data_value){.bin = data1})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  // insert TEST2 with data2
  struct np_data_conf data_conf2 =
      (struct np_data_conf){.key       = "TEST2",
                            .type      = NP_DATA_TYPE_BIN,
                            .data_size = data_size};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf2,
                                       (np_data_value){.bin = data2})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_BIN,
            "Expected BIN container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected BIN container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size == data_size,
            "Expected BIN container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == memcmp(deserialized_data.bin,
                        data1,
                        MIN(data_size, deserialized_data_conf.data_size)),
            "Expected BIN data to be the same");

  // check TEST2 for data2
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST2",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_BIN,
            "Expected BIN container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST2", 4),
            "Expected BIN container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size == data_size,
            "Expected BIN container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == memcmp(deserialized_data.bin,
                        data2,
                        MIN(data_size, deserialized_data_conf.data_size)),
            "Expected BIN data to be the same");
}

Test(neuropil_data,
     _check_resetting_data,
     .description =
         "test the serialization and deserialization of a BIN datablock") {
  enum np_data_return tmp_ret;
  struct np_data_conf deserialized_data_conf = {0};
  np_data_value       deserialized_data;

  size_t        datablock_size = 2000;
  unsigned char datablock[datablock_size];

  uint32_t      data_size = 452;
  unsigned char data1[452];
  memset(data1, 'A', data_size);
  unsigned char data2[452];
  memset(data2, 'B', data_size);

  // init datatablock
  cr_assert(np_data_ok ==
                (tmp_ret = np_init_datablock(datablock, datablock_size)),
            "expect initialized datablock. (ret: %" PRIu32 ")",
            tmp_ret);

  // insert TEST with data1
  struct np_data_conf data_conf =
      (struct np_data_conf){.key       = "TEST",
                            .type      = NP_DATA_TYPE_BIN,
                            .data_size = data_size};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf,
                                       (np_data_value){.bin = data1})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  // insert TEST2 with data2
  struct np_data_conf data_conf2 =
      (struct np_data_conf){.key       = "TEST2",
                            .type      = NP_DATA_TYPE_BIN,
                            .data_size = data_size};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf2,
                                       (np_data_value){.bin = data2})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  // insert TEST with data2
  struct np_data_conf data_conf3 =
      (struct np_data_conf){.key       = "TEST",
                            .type      = NP_DATA_TYPE_BIN,
                            .data_size = data_size};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf3,
                                       (np_data_value){.bin = data2})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST for data2
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_BIN,
            "Expected BIN container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected BIN container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size == data_size,
            "Expected BIN container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == memcmp(deserialized_data.bin,
                        data2,
                        MIN(data_size, deserialized_data_conf.data_size)),
            "Expected BIN data to be the same");
}

Test(neuropil_data,
     _full_cycle_bin,
     .description =
         "test the serialization and deserialization of a BIN datablock") {
  enum np_data_return tmp_ret;
  struct np_data_conf deserialized_data_conf = {0};
  np_data_value       deserialized_data;

  size_t        datablock_size = 2000;
  unsigned char datablock[datablock_size];

  uint32_t      data_size = 452;
  unsigned char data1[452];
  memset(data1, 'A', data_size);
  unsigned char data2[452];
  memset(data2, 'B', data_size);

  // init datatablock
  cr_assert(np_data_ok ==
                (tmp_ret = np_init_datablock(datablock, datablock_size)),
            "expect initialized datablock. (ret: %" PRIu32 ")",
            tmp_ret);

  // insert TEST with data1
  struct np_data_conf data_conf =
      (struct np_data_conf){.key       = "TEST",
                            .type      = NP_DATA_TYPE_BIN,
                            .data_size = data_size};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf,
                                       (np_data_value){.bin = data1})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_BIN,
            "Expected BIN container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected BIN container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size == data_size,
            "Expected BIN container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == memcmp(deserialized_data.bin,
                        data1,
                        MIN(data_size, deserialized_data_conf.data_size)),
            "Expected BIN data to be the same");

  // insert TEST2 with data2
  struct np_data_conf data_conf1 =
      (struct np_data_conf){.key       = "TEST2",
                            .type      = NP_DATA_TYPE_BIN,
                            .data_size = data_size};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf1,
                                       (np_data_value){.bin = data2})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST2 for data2
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST2",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_BIN,
            "Expected BIN container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST2", 4),
            "Expected BIN container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size == data_size,
            "Expected BIN container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == memcmp(deserialized_data.bin,
                        data2,
                        MIN(data_size, deserialized_data_conf.data_size)),
            "Expected BIN data to be the same");

  // check TEST for data1
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_BIN,
            "Expected BIN container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected BIN container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size == data_size,
            "Expected BIN container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == memcmp(deserialized_data.bin,
                        data1,
                        MIN(data_size, deserialized_data_conf.data_size)),
            "Expected BIN data to be the same");

  // insert TEST with data2
  struct np_data_conf data_conf2 =
      (struct np_data_conf){.key       = "TEST",
                            .type      = NP_DATA_TYPE_BIN,
                            .data_size = data_size};
  cr_assert(np_data_ok ==
                (tmp_ret = np_set_data(datablock,
                                       data_conf2,
                                       (np_data_value){.bin = data2})),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);

  // check TEST for data2
  cr_assert(np_data_ok == (tmp_ret = np_get_data(datablock,
                                                 "TEST",
                                                 &deserialized_data_conf,
                                                 &deserialized_data)),
            "expect inserted data. (ret: %" PRIu32 ")",
            tmp_ret);
  cr_expect(deserialized_data_conf.type == NP_DATA_TYPE_BIN,
            "Expected BIN container not %" PRIu32,
            deserialized_data_conf.type);
  cr_expect(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
            "Expected BIN container key to match. not %s",
            deserialized_data_conf.key);
  cr_expect(deserialized_data_conf.data_size == data_size,
            "Expected BIN container size to match. not %" PRIu32,
            deserialized_data_conf.data_size);
  cr_expect(0 == memcmp(deserialized_data.bin,
                        data2,
                        MIN(data_size, deserialized_data_conf.data_size)),
            "Expected BIN data to be the same");
}
