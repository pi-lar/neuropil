//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include "msgpack/cmp.h"

#include "neuropil.h"
#include "neuropil_data.h"
#include "np_serialization.h"
#include "np_util.h"

enum np_return np_init_datablock(np_datablock_t *block, uint32_t block_length)
{
    if (block_length <= sizeof(uint32_t) * 3)
    {
        return np_invalid_argument;
    }
    memset(block, 0, block_length);
    cmp_ctx_t cmp;
    cmp_init(&cmp, block, NULL, NULL, _np_buffer_writer);
    //_np_buffer_reader, _np_buffer_skipper
    cmp_write_u32(&cmp, NP_DATA_MAGIC_NO);                     // magic_no
    cmp_write_u32(&cmp, block_length);                         // total_length
    cmp_write_u32(&cmp, 3 /*marker */ + 3 * sizeof(uint32_t)); // used_length

    return np_ok;
}
enum np_return np_set_data(np_datablock_t *block, struct np_data_conf data_conf, unsigned char *data)
{
    enum np_return ret = np_invalid_argument;

    cmp_ctx_t cmp;
    cmp_init(&cmp, block, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
    fprintf(stderr, "np_set_data 1 %p\n", cmp.buf);
    uint32_t magic_no = 0;

    if (cmp_read_u32(&cmp, &magic_no) && NP_DATA_MAGIC_NO == magic_no) // magic_no
    {
        fprintf(stderr, "np_set_data 2 %p\n", cmp.buf);
        uint32_t total_length = 0;
        if (!cmp_read_u32(&cmp, &total_length)) // total_length
        {
            ret = np_unknown_error;
        }
        else
        {
            fprintf(stderr, "np_set_data 3 %p\n", cmp.buf);
            uint32_t used_length = 0;
            if (!cmp_read_u32(&cmp, &used_length)) // used_length
            {
                ret = np_unknown_error;
            }
            else
            {
                fprintf(stderr, "np_set_data 4 %p\n", cmp.buf);
                char tmp_key[256] = {0};
                uint8_t tmp_data_type = 0;
                uint32_t tmp_data_size = 0;
                while ((cmp.buf - block) < used_length)
                {
                    cmp_ctx_t pre_read_cmp = cmp;
                    if (!cmp_read_str(&cmp, &tmp_key, 255)) // key
                    {
                        ret = np_unknown_error;
                        break;
                    }
                    if (!cmp_read_u8(&cmp, &tmp_data_type)) // data_type
                    {
                        ret = np_unknown_error;
                        break;
                    }
                    if (tmp_data_type == NP_DATA_TYPE_BIN)
                    {
                        if (!cmp_read_bin_size(&cmp, &tmp_data_size))
                        {
                            ret = np_unknown_error;
                            break;
                        }
                    } // ... other types

                    if (strncmp(tmp_key, data_conf.key, 255) == 0)
                    {
                        // check for space
                        if ((total_length - (used_length - tmp_data_size)) <= data_conf.data_size)
                        {
                            // overwrite data (as in: move remaining data up und add new element)
                            memmove(pre_read_cmp.buf, cmp.buf, used_length - (pre_read_cmp.buf - block));
                            cmp = pre_read_cmp;
                            break;
                        }
                        else
                        {
                            ret = np_insufficient_memory;
                        }
                    }
                }

                // write new value
                if (ret != np_unknown_error && ret != np_insufficient_memory)
                {
                    uint32_t key_len = strnlen(data_conf.key, 255);
                    fprintf(stderr, "np_set_data 5 %p\n", cmp.buf);
                    if (!cmp_write_str(&cmp, data_conf.key, key_len))
                    {
                        ret = np_unknown_error;
                    }
                    else
                    {
                        fprintf(stderr, "np_set_data 6 %p\n", cmp.buf);
                        if (!cmp_write_u32(&cmp, (uint32_t)data_conf.type))
                        {
                            ret = np_unknown_error;
                        }
                        else
                        {
                            fprintf(stderr, "np_set_data 7 %p\n", cmp.buf);
                            if (data_conf.type == NP_DATA_TYPE_BIN)
                            {
                                if (cmp_write_bin32(&cmp, data, data_conf.data_size))
                                {
                                    fprintf(stderr, "np_set_data 8 %p\n", cmp.buf);
                                }
                                else
                                {
                                    ret = np_unknown_error;
                                }
                            } // ... other types
                        }
                    }
                }
                if (ret != np_unknown_error && ret != np_insufficient_memory)
                {
                    unsigned char * overwrite = block + 2 /*marker */ + 2 * sizeof(uint32_t);
                    cmp_ctx_t overwrite_cmp;
                    cmp_init(&overwrite_cmp, overwrite, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);

                    fprintf(stderr, "np_set_data 3.2 %p\n", overwrite_cmp.buf);
                    if (cmp_write_u32(&overwrite_cmp, (cmp.buf - block)))
                    {
                        fprintf(stderr, "np_set_data 4.2 %p\n", overwrite_cmp.buf);
                        ret = np_ok;
                    }
                    else
                    {
                        ret = np_unknown_error;
                    }
                }
            }
        }
    }

    return ret;
}

enum np_return np_get_data(np_datablock_t * block, char key[255], struct np_data_conf * out_data_config, unsigned char ** out_data)
{
    enum np_return ret = np_invalid_argument;

    cmp_ctx_t cmp;
    cmp_init(&cmp, block, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
    fprintf(stderr, "np_get_data 1 %p\n", cmp.buf);
    uint32_t magic_no = 0;

    if (cmp_read_u32(&cmp, &magic_no) && NP_DATA_MAGIC_NO == magic_no) // magic_no
    {
        fprintf(stderr, "np_get_data 2 %p\n", cmp.buf);
        uint32_t total_length = 0;
        if (!cmp_read_u32(&cmp, &total_length)) // total_length
        {
            ret = np_unknown_error;
        }
        else
        {
            fprintf(stderr, "np_get_data 3 %p\n", cmp.buf);
            uint32_t used_length = 0;
            if (!cmp_read_u32(&cmp, &used_length)) // used_length
            {
                ret = np_unknown_error;
            }
            else
            {
                fprintf(stderr, "np_get_data 4 %p\n", cmp.buf);
                char tmp_key[256] = {0};
                uint32_t tmp_data_type = 0;
                uint32_t tmp_data_size = 0;
                ret = np_key_not_found;
                while ((cmp.buf - block) < used_length)
                {
                    cmp_ctx_t pre_read_cmp = cmp;

                    fprintf(stderr, "np_get_data 5 %p\n", cmp.buf);
                    uint32_t tmp_key_size;
                    if (!cmp_read_str(&cmp, tmp_key, &tmp_key_size)) // key
                    {
                        ret = np_unknown_error;
                        break;
                    }

                    fprintf(stderr, "np_get_data 6 %p\n", cmp.buf);
                    if (!cmp_read_u32(&cmp, &tmp_data_type)) // data_type
                    {
                        ret = np_unknown_error;
                        break;
                    }
                    cmp_ctx_t pre_size_read;
                    fprintf(stderr, "np_get_data 7 %p tmp_data_type: %"PRIu32"\n", cmp.buf, tmp_data_type);
                    if (tmp_data_type == NP_DATA_TYPE_BIN)
                    {
                        fprintf(stderr, "np_get_data 7.1 BIN %p\n", cmp.buf);
                        pre_size_read = cmp;
                        if (!cmp_read_bin_size(&cmp, &tmp_data_size))
                        {
                            fprintf(stderr, "np_get_data 7.1 BREAK BIN %p\n", cmp.buf);
                            ret = np_unknown_error;
                            break;
                        }
                        cmp.buf = cmp.buf + tmp_data_size; // skip data

                    } // ... other types
                    fprintf(stderr, "np_get_data 8 %p\n", cmp.buf);

                    if (strncmp(tmp_key, key, 255) == 0)
                    {
                        fprintf(stderr, "np_get_data 9 %p\n", cmp.buf);
                        if (out_data != NULL)
                        {

                            if (tmp_data_type == NP_DATA_TYPE_BIN)
                            {
                                *out_data = malloc(tmp_data_size);
                                if(*out_data == NULL){
                                    ret = np_insufficient_memory;
                                    break;
                                }
                                cmp = pre_size_read;
                                fprintf(stderr, "np_get_data 9.1 BIN %p  *out_data %p\n", cmp.buf, *out_data);

                                if (!cmp_read_bin(&cmp, *out_data, &tmp_data_size))
                                {
                                    fprintf(stderr, "np_get_data 9.1 BREAK BIN %p\n", cmp.buf);
                                    ret = np_unknown_error;
                                    break;
                                }
                            }
                        }
                        fprintf(stderr, "np_get_data 10 %p\n", cmp.buf);

                        out_data_config->data_size = tmp_data_size;
                        out_data_config->type = tmp_data_type;
                        strncpy(out_data_config->key, key, 255);
                        ret = np_ok;
                        break;
                    }
                }
            }
        }
    }
    return ret;
}
