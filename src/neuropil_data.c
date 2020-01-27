//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "neuropil.h"
#include "neuropil_data.h"

    struct np_datablock {
        uint32_t magic_no;
        struct version_t version;
        uint32_t length;
    } NP_PACKED(1);
    
    enum np_return np_init_datablock(np_datablock_t * block, size_t block_length){
        enum np_return ret = np_not_implemented;
        return ret;
    }
    
    enum np_return np_set_data(np_datablock_t * block, struct np_data_conf data_conf, void * data){
        enum np_return ret = np_not_implemented;
        return ret;
    }
    
    enum np_return np_get_data(np_datablock_t * block, char key[255], struct np_data_conf * out_data_config, unsigned char ** out_data){
        enum np_return ret = np_not_implemented;
        return ret;
    }
    
    enum np_return np_serialize_datablock(np_datablock_t * block, void * out_raw_block, size_t out_raw_block_size){
        enum np_return ret = np_not_implemented;
        return ret;
    }
    
    enum np_return np_deserialize_datablock(np_datablock_t * out_block, void * raw_block){
        enum np_return ret = np_not_implemented;
        return ret;
    }

