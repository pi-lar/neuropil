//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_DATA_INNER_H_
#define _NP_DATA_INNER_H_

#include "neuropil_data.h"

#ifdef __cplusplus
extern "C" {
#endif
    // Internal methods
    NP_API_PROTEC
    enum np_data_return np_get_data_size(np_datablock_t * block, size_t * out_block_size);
#ifdef __cplusplus
}
#endif
#endif /* _NP_DATA_INNER_H_ */
