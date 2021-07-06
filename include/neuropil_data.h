//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project
#ifndef NP_DATA_H_
#define NP_DATA_H_

#include "neuropil.h"

#ifdef __cplusplus
extern "C" {
#endif
    #define NP_DATA_MAGIC_NO 22964591

    enum np_data_return {
        np_data_ok = 0,
        np_key_not_found = 1,
        np_insufficient_memory,
        np_invalid_structure,
        np_invalid_arguments,
        np_could_not_write_magicno,
        np_could_not_write_total_length,
        np_could_not_write_used_length,
        np_could_not_write_object_count,
        np_could_not_write_bin,
        np_could_not_write_str,
        np_could_not_write_int,
        np_could_not_write_uint,
        np_could_not_write_key,
        np_could_not_read_magicno,
        np_could_not_read_total_length,
        np_could_not_read_used_length,
        np_could_not_read_object_count,
        np_could_not_read_object,
        np_could_not_read_key,
    } NP_CONST_ENUM;

    enum np_data_type {
        NP_DATA_TYPE_BIN,
        NP_DATA_TYPE_INT,
        NP_DATA_TYPE_UNSIGNED_INT,
        NP_DATA_TYPE_STR
    } NP_CONST_ENUM;

    struct np_data_conf {
        char key[255];
        enum np_data_type type;
        uint32_t data_size;
    } NP_PACKED(1);
    // value gets appended to np_data instance in datablock

    typedef union {
        unsigned char *bin;
        int32_t  integer;
        uint32_t unsigned_integer;
        char * str;
    } np_data_value;
    typedef unsigned char np_datablock_t;

    NP_API_EXPORT
    /**
     * @brief Initialises the provided memory allocation as datablock
     *
     * @param block The memory block provided by the user (malloc'ed )
     * @param block_length The memory block size
     * @return enum np_data_return
     */
    enum np_data_return np_init_datablock(np_datablock_t * block, uint32_t block_length);
    NP_API_EXPORT
    enum np_data_return np_set_data(np_datablock_t * block, struct np_data_conf data_conf, np_data_value data);
    NP_API_EXPORT
    enum np_data_return np_get_data(np_datablock_t * block, char key[255], struct np_data_conf * out_data_config, np_data_value * out_data);

    NP_API_EXPORT
    /**
     * @brief merges src datablock into dest datablock. overwrites existing keys
     */
    enum np_data_return np_merge_data(np_datablock_t *dest, np_datablock_t *src);

    NP_API_EXPORT
    typedef bool (*np_iterate_data_cb)(struct np_data_conf * out_data_config, np_data_value * out_data, void * userdata);
    NP_API_EXPORT
    enum np_data_return np_iterate_data(np_datablock_t * block, np_iterate_data_cb callback, void * userdata);

#ifdef __cplusplus
}
#endif
#endif /* NP_DATA_H_ */

/**

.. c:type:: void np_datablock_t

   An opaque object that denotes a neuropil key/value store.

.. c:function:: enum np_data_return np_init_datablock(np_datablock_t * block, size_t block_length)

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

.. c:type:: typedef bool (*np_data_iterate_cb)(struct np_data_conf * out_data_config, np_data_value * out_data, void * userdata)

   Callback definition for the :c:function:`np_iterate_data` function

.. c:function:: enum np_data_return np_iterate_data(np_datablock_t * block, np_data_iterate_cb callback, void * userdata)

   Iterates over every :c:type:`np_datablock_t` key/value elements

**/
