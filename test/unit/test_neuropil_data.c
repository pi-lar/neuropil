//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdlib.h>
#include <inttypes.h>
#include "pthread.h"

#include <criterion/criterion.h>

#include "neuropil_data.h"

#include "../test_macros.c"


TestSuite(neuropil_data);

Test(neuropil_data, _full_cycle_bin, .description="test the serialization and deserialization of a BIN datablock")
{
    enum np_return tmp_ret;

    size_t datablock_size = 1000; 
    unsigned char datablock[datablock_size];    
    cr_assert(np_ok == (tmp_ret = np_init_datablock(datablock, datablock_size)), "expect initialized datablock. (ret: %"PRIu32")", tmp_ret);    

    size_t data_size = 12;
    unsigned char data[12] = {0x00034fdd2234};
    cr_assert(np_ok == (tmp_ret = np_set_data(datablock, (struct np_data_conf) { .key="TEST", .type=NP_DATA_TYPE_BIN, .size=data_size }, data )), "expect inserted data. (ret: %"PRIu32")", tmp_ret);

    size_t serialized_datablock_size;
    unsigned char * serialized_datablock;
    cr_assert(np_ok == (tmp_ret = np_serialize_datablock(datablock, serialized_datablock, &serialized_datablock_size)), "expect serialized datablock (ret: %"PRIu32")", tmp_ret);

    np_datablock_t * deserialized_datablock;
    cr_assert(np_ok == (tmp_ret = np_deserialize_datablock(deserialized_datablock, serialized_datablock)), "expect deserialized datablock (ret: %"PRIu32")", tmp_ret);

    struct np_data_conf deserialized_data_conf = {0};
    void * deserialized_data;
    cr_assert(np_ok == (tmp_ret = np_get_data  (datablock, "TEST", &deserialized_data_conf, &deserialized_data)), "expect inserted data. (ret: %"PRIu32")", tmp_ret);    
    cr_expect(deserialized_data_conf.type  == NP_DATA_TYPE_BIN,"Expected BIN container");
    cr_expect(strncmp(deserialized_data_conf.key, "TEST", 4),"Expected BIN container key to match");    
    cr_expect(deserialized_data_conf.size  == data_size,"Expected BIN container size to match");
    cr_expect(0 == memcmp(deserialized_data, data, data_size), "Expected BIN data to be the same");

}
 