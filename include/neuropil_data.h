//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_DATA_H_
#define _NP_DATA_H_

#include "neuropil.h"

#ifdef __cplusplus
extern "C" {
#endif
    #define NP_DATA_MAGIC_NO 2223964591
       
    enum np_data_type {
        NP_DATA_TYPE_MASK                     = 0xFFF000,
        NP_DATA_TYPE_BIN                      = 0x001000,
        NP_DATA_TYPE_INT                      = 0x002000,
        NP_DATA_TYPE_STR                      = 0x003000,
    } NP_CONST_ENUM;

    struct np_data_conf {
        char key[255];
        enum np_data_type type;
        size_t data_size;
    } NP_PACKED(1);
    // value gets appended to np_data instance in datablock

    typedef void np_datablock_t;    

    NP_API_EXPORT
    enum np_return np_init_datablock(np_datablock_t * block, size_t block_length);
    NP_API_EXPORT
    enum np_return np_set_data(np_datablock_t * block, struct np_data_conf data_conf, unsigned char * data);
    NP_API_EXPORT
    enum np_return np_get_data(np_datablock_t * block, char key[255], struct np_data_conf * out_data_config, unsigned char ** out_data);

    // Internal methods
    NP_API_PROTEC
    enum np_return np_serialize_datablock(np_datablock_t * block, void * out_raw_block, size_t out_raw_block_size);
    NP_API_PROTEC
    enum np_return np_deserialize_datablock(np_datablock_t * out_block, void * raw_block);

#ifdef __cplusplus
}
#endif


#endif /* _NP_DATA_H_ */
