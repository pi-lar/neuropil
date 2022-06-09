//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "../test/test_macros.c"

#include "neuropil_data.h"

#undef cr_expect
#define cr_expect(A, B) assert((A) && B)
int main() {
  enum np_return      tmp_ret;
  struct np_data_conf deserialized_data_conf = {0};
  unsigned char      *deserialized_data      = NULL;

  size_t        datablock_size = 2000;
  unsigned char datablock[datablock_size];
  char          hex_datablock[2 * datablock_size + 1];

  uint32_t      data_size = 452;
  unsigned char data1[452];
  memset(data1, 'A', data_size);
  unsigned char data2[452];
  memset(data2, 'B', data_size);

  // init datatablock
  ASSERT(np_ok == (tmp_ret = np_init_datablock(datablock, datablock_size)),
         "expect initialized datablock. (ret: %" PRIu32 ")",
         tmp_ret);

  // insert TEST with data1
  struct np_data_conf data_conf =
      (struct np_data_conf){.key       = "TEST",
                            .type      = NP_DATA_TYPE_BIN,
                            .data_size = data_size};
  ASSERT(np_ok == (tmp_ret = np_set_data(datablock, data_conf, data1)),
         "expect inserted data. (ret: %" PRIu32 ")",
         tmp_ret);
  // insert TEST2 with data2
  struct np_data_conf data_conf2 =
      (struct np_data_conf){.key       = "TEST2",
                            .type      = NP_DATA_TYPE_BIN,
                            .data_size = data_size};
  ASSERT(np_ok == (tmp_ret = np_set_data(datablock, data_conf2, data2)),
         "expect inserted data. (ret: %" PRIu32 ")",
         tmp_ret);
  // insert TEST with data2
  struct np_data_conf data_conf3 =
      (struct np_data_conf){.key       = "TEST",
                            .type      = NP_DATA_TYPE_BIN,
                            .data_size = data_size};
  ASSERT(np_ok == (tmp_ret = np_set_data(datablock, data_conf3, data2)),
         "expect inserted data. (ret: %" PRIu32 ")",
         tmp_ret);

  // check TEST for data2
  ASSERT(np_ok == (tmp_ret = np_get_data(datablock,
                                         "TEST",
                                         &deserialized_data_conf,
                                         &deserialized_data)),
         "expect inserted data. (ret: %" PRIu32 ")",
         tmp_ret);
  ASSERT(deserialized_data_conf.type == NP_DATA_TYPE_BIN,
         "Expected BIN container not %" PRIu32,
         deserialized_data_conf.type);
  ASSERT(0 == strncmp(deserialized_data_conf.key, "TEST", 4),
         "Expected BIN container key to match. not %s",
         deserialized_data_conf.key);
  ASSERT(deserialized_data_conf.data_size == data_size,
         "Expected BIN container size to match. not %" PRIu32,
         deserialized_data_conf.data_size);
  ASSERT(0 == memcmp(deserialized_data,
                     data2,
                     MIN(data_size, deserialized_data_conf.data_size)),
         "Expected BIN data to be the same");
}
