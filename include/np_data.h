//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_DATA_INNER_H_
#define _NP_DATA_INNER_H_

#include "neuropil_data.h"
#include "util/np_mapreduce.h"


#ifdef __cplusplus
extern "C" {
#endif
    struct np_data {
        struct np_data_conf conf;
        np_data_value value;
    };
    // Internal methods
    NP_API_PROTEC
    enum np_data_return np_get_data_size(np_datablock_t * block, size_t * out_block_size);
    NP_API_PROTEC
    enum np_data_return np_get_object_count(np_datablock_t * block, uint32_t * count);
    NP_API_PROTEC
    enum np_data_return _np_iterate_data_mapreduce(np_datablock_t * block, np_map_reduce_t * map);
    NP_API_PROTEC
    char* _np_print_datablock(char * buffer, size_t buffer_max_size, np_datablock_t *src);
#ifdef __cplusplus
}
#endif
#endif /* _NP_DATA_INNER_H_ */
