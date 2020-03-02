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
    /**
     * @brief Initialises the provided memory allocation as datablock
     * 
     * @param block The memory block provided by the user (malloc'ed )
     * @param block_length The memory block size
     * @return enum np_return 
     */
    enum np_return np_init_datablock(np_datablock_t * block, size_t block_length);
    NP_API_EXPORT
    enum np_return np_set_data(np_datablock_t * block, struct np_data_conf data_conf, unsigned char * data);
    NP_API_EXPORT
    enum np_return np_get_data(np_datablock_t * block, char key[255], struct np_data_conf * out_data_config, unsigned char ** out_data);

    // Internal methods
    NP_API_PROTEC
    enum np_return np_serialize_datablock(np_datablock_t * block, void ** out_raw_block, size_t * out_raw_block_size);
    NP_API_PROTEC
    enum np_return np_deserialize_datablock(np_datablock_t ** out_block, void * raw_block, size_t raw_block_length);

#ifdef __cplusplus
}
#endif
#endif /* _NP_DATA_H_ */

/**

.. c:type:: void np_datablock_t

   An opaque object that denotes a neuropil key/value store.

.. c:function:: enum np_return np_init_datablock(np_datablock_t * block, size_t block_length)

   Creates a new neuropil key value store.

    :param block:        the memoryblock which should be initialized to contain a :c:type:`np_datablock_t`
    :param block_length: a :c:type:`size_t` the size of the block input parameter
    :return:             :c:data:`np_ok` on success

.. c:type:: struct np_data_conf

   The configuration of a single key in an :c:type:`np_datablock_t`

.. c:type:: enum np_data_type

   This type denotes the set of data types relevant for :c:type:`np_datablock_t` key/value elements
   Possible values include:

   ================================================  ===========================================
   Status                                            Meaning
   ================================================  ===========================================
   :c:data:`NP_DATA_TYPE_BIN`                        Define the key to hold binary data in its value container
   :c:data:`NP_DATA_TYPE_INT`                        Define the key to hold an integer in its value container
   :c:data:`NP_DATA_TYPE_STR`                        Define the key to hold a string in its value container (Uses ASCII encoding)
   ================================================  ===========================================

**/
