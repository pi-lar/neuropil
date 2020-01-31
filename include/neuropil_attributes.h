//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_ATTR_H_
#define _NP_ATTR_H_

#include "neuropil.h"
#include "neuropil_data.h"

#ifdef __cplusplus
extern "C" {
#endif      
        
    enum np_msg_attr_type {
        NP_ATTR_NONE = 0,
        NP_ATTR_USER_MSG,
        NP_ATTR_INTENT,
        NP_ATTR_IDENTITY,              // e.g. used when joining a network
        NP_ATTR_IDENTITY_AND_USER_MSG, // e.g. used to secure the bootstapping process. 
        /**
          Node "A" wants to connect to node "B"
          "B" requests attr key "K1" to be given.  ("K1" is not in JOIN msg)
          Node A registers by realm master "C"
          "C" answers with a attribute "K1" configured for NP_ATTR_IDENTITY_AND_USER_MSG
          "A" now saves "K1" in its identity token (so it can be saved) ("K1" is now in every JOIN msg)
          "A" now preps every user message send with attribute "K1" (for example: SessionID)
        **/

        NP_ATTR_INTENT_AND_USER_MSG,
        NP_ATTR_INTENT_AND_IDENTITY,
        
    } NP_CONST_ENUM;


    NP_API_EXPORT
    enum np_return np_set_ident_attr_bin(struct np_token* ident, enum np_msg_attr_type  inheritance, char key[255], void* bin, size_t bin_length);
    NP_API_EXPORT
    enum np_return np_set_mxp_attr_bin(struct np_mx_properties * prop, enum np_msg_attr_type  inheritance, void* bin, size_t bin_length);            
    
    NP_API_EXPORT
    enum np_return np_get_msg_attr_bin(struct np_message * msg, char key[255], struct np_data_conf ** out_data_config, unsigned char ** out_data);
    //NP_API_EXPORT
    //enum np_return np_get_attr_bin(np_mx_properties * prop, char key[255], struct np_data_conf ** out_data_config, unsigned char ** out_data);
    //NP_API_EXPORT
    //enum np_return np_get_attr_bin(np_token* ident, char key[255], struct np_data_conf ** out_data_config, unsigned char ** out_data);
    

#ifdef __cplusplus
}
#endif
#endif /* _NP_ATTR_H_ */

/**
--------------
Initialization
--------------
.. c:type:: void np_datablock_t

   An opaque object that denotes a neuropil key/value store.

.. c:function:: enum np_return np_init_datablock(np_datablock_t * block, size_t block_length)

   Creates a new neuropil key value store.

    :param block:        the memoryblock which should be initialized to contain a :c:type:`np_datablock_t`
    :param block_length: a :c:type:`size_t` the size of the block input parameter
    :return: :c:data:`np_ok` on success

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
