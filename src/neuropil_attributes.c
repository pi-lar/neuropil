//
// neuropil is copyright 2016-2021 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "msgpack/cmp.h"

#include "neuropil.h"
#include "neuropil_data.h"
#include "neuropil_attributes.h"
#include "np_attributes.h"
#include "np_legacy.h"

np_module_struct(attributes) {
    np_state_t* context;
    np_attributes_t attribute_cache[NP_ATTR_MAX];
};
void _np_attributes_destroy(np_state_t* context){

    //nothing to do
}

bool _np_attributes_init(np_state_t* context)
{
    bool ret = true;
    np_module_malloc(attributes);

    for (int i = 0; i < NP_ATTR_MAX; i++)
    {
        ret = np_ok == np_init_datablock((np_datablock_t*)&_module->attribute_cache[i], sizeof(np_attributes_t));
        if(!ret) break;
    }
    return ret;
}


enum np_data_return np_set_ident_attr_bin(np_context *ac, struct np_token *ident, enum np_msg_attr_type inheritance, char key[255], unsigned char *bin, size_t bin_length)
{
    np_ctx_cast(ac);
    enum np_data_return ret = np_invalid_arguments;

    struct np_data_conf conf = {0};
    conf.data_size = bin_length;
    conf.type = NP_DATA_TYPE_BIN;
    strncpy(conf.key,key,254);
    if(ident!=NULL){
        ret = np_set_data(ident->attributes,conf,(np_data_value){.bin=bin});
    }

    if(inheritance != NP_ATTR_NONE)
        ret = np_set_data(np_module(attributes)->attribute_cache[inheritance],conf,(np_data_value){.bin=bin});

    return ret;
}

enum np_data_return np_set_mxp_attr_bin(np_context *ac, char * subject, enum np_msg_attr_type inheritance, char key[255], unsigned char *bin, size_t bin_length)
{
    np_ctx_cast(ac);
    enum np_data_return ret = np_invalid_arguments;

    struct np_data_conf conf = {0};
    conf.data_size = bin_length;
    conf.type = NP_DATA_TYPE_BIN;
    strncpy(conf.key,key,254);
    if(subject != NULL){
        np_msgproperty_t* property = _np_msgproperty_get_or_create(context, DEFAULT_MODE, subject);
        ret = np_set_data(property->attributes, conf,(np_data_value){.bin=bin});
    }

    if(inheritance != NP_ATTR_NONE)
        ret = np_set_data(np_module(attributes)->attribute_cache[inheritance],conf,(np_data_value){.bin=bin});

    return ret;
}

enum np_data_return np_get_msg_attr_bin(struct np_message *msg, char key[255], struct np_data_conf **out_data_config, unsigned char **out_data)
{
    enum np_data_return ret;

    struct np_data_conf *conf = NULL;
    if(out_data_config != NULL) conf = *out_data_config;
    np_data_value val;
    ret = np_get_data(msg->attributes, key, conf, &val);

    if(out_data != NULL) *out_data = val.bin;

    return ret;
}

enum np_data_return np_get_token_attr_bin(struct np_token * ident, char key[255], struct np_data_conf ** out_data_config, unsigned char ** out_data){
    enum np_data_return ret;

    struct np_data_conf *conf = NULL;
    if(out_data_config != NULL) conf = *out_data_config;
    np_data_value val;
    ret = np_get_data(ident->attributes, key, conf, &val);

    if(out_data != NULL) *out_data = val.bin;

    return ret;
}

np_attributes_t* _np_get_attributes_cache(np_state_t* context, enum np_msg_attr_type cache){
    assert(cache != NP_ATTR_NONE);

    return &np_module(attributes)->attribute_cache[cache];
}
