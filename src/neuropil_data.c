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

struct __np_datablock_s
{
    unsigned char *ublock;
    cmp_ctx_t cmp;
    uint32_t total_length;
    uint32_t used_length;
    uint32_t object_count;
};

struct __kv_pair
{
    unsigned char *start_of_object;
    unsigned char *end_of_object;
    char key[255];
    enum np_data_type data_type;
    uint32_t data_size;
    union {
        unsigned char *bin;
        int integer;
        uint32_t unsigned_integer;
        char *str;
    } data;
};

enum np_return np_init_datablock(np_datablock_t *block, uint32_t block_length)
{
    enum np_return ret = np_ok;
    uint32_t overhead =
        sizeof(uint8_t) /*marker+value*/ +                                          // fixarray
        3 * (sizeof(uint8_t) /*marker*/ + sizeof(uint32_t) /*value:->see right*/) + // magic_no + total_length + used_length
        sizeof(uint8_t) /*marker*/ + sizeof(uint32_t) /* value:object_count */      // map32
        ;                                                                           // 21 byte
    if (block_length <= overhead)
    {
        ret = np_invalid_argument;
    }
    else
    {
        memset(block, 0, block_length);
        cmp_ctx_t cmp;
        cmp_init(&cmp, block, NULL, NULL, _np_buffer_writer);
        // fprintf(stderr, "overhead:%" PRIu32 "\n", overhead);

        if (!cmp_write_fixarray(&cmp, 4))
        {
            ret = np_unknown_error;
        }
        else if (!cmp_write_u32(&cmp, NP_DATA_MAGIC_NO)) // magic_no
        {
            ret = np_unknown_error;
        }
        else if (!cmp_write_u32(&cmp, block_length)) // total_length
        {
            ret = np_unknown_error;
        }
        else if (!cmp_write_u32(&cmp, overhead)) // used_length
        {
            ret = np_unknown_error;
        }
        else if (!cmp_write_map32(&cmp, (uint32_t)0)) // object count
        {
            ret = np_unknown_error;
        }
    }
    return ret;
}
enum np_return __read_datablock_fixed(enum np_return *error, struct __np_datablock_s *ret)
{
    uint32_t magic_no, array_size;
    if (!cmp_read_array(&ret->cmp, &array_size) && array_size == 4)
    {
        *error = np_invalid_argument;
    }
    else if (!cmp_read_u32(&ret->cmp, &magic_no) && NP_DATA_MAGIC_NO == magic_no) // magic_no
    {
        *error = np_invalid_argument;
    }
    else if (!cmp_read_u32(&ret->cmp, &ret->total_length)) // total_length
    {
        // fprintf(stderr, "__read_datablock.total_length\n");
        *error = np_unknown_error;
    }
    return *error;
}

struct __np_datablock_s __read_datablock(np_datablock_t *block, enum np_return *error)
{
    *error = np_ok;
    struct __np_datablock_s ret = {0};

    ret.ublock = ((unsigned char *)block);
    cmp_init(&ret.cmp, block, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);

    if (__read_datablock_fixed(error, &ret) != np_ok)
    {
        // fprintf(stderr, "__read_datablock_0\n");
    }
    else if (!cmp_read_u32(&ret.cmp, &ret.used_length)) // used_length
    {
        // fprintf(stderr, "__read_datablock.used_length %" PRIu8 "\n", ret.cmp.error);
        *error = np_unknown_error;
    }
    else if (!cmp_read_map(&ret.cmp, &ret.object_count)) // object_count
    {
        // fprintf(stderr, "__read_datablock.object_count\n");
        *error = np_unknown_error;
    }
    return ret;
}

enum np_return __write_object(cmp_ctx_t *target, struct __kv_pair to_write)
{
    enum np_return ret = np_ok;

    uint8_t key_len = strnlen(to_write.key, 255);

    if (!cmp_write_str(target, to_write.key, key_len))
    {
        // fprintf(stderr, "__write_object.key");
        ret = np_unknown_error;
    }
    else if (to_write.data_type == NP_DATA_TYPE_BIN)
    {
        if (!cmp_write_bin32(target, to_write.data.bin, to_write.data_size))
        {
            // fprintf(stderr, "__write_object.data_size");
            ret = np_unknown_error;
        }
    }
    else if (to_write.data_type == NP_DATA_TYPE_INT)
    {
        if (!cmp_write_s32(target, to_write.data.integer))
        {
            // fprintf(stderr, "__write_object.data_size");
            ret = np_unknown_error;
        }
    }
    else if (to_write.data_type == NP_DATA_TYPE_UNSIGNED_INT)
    {
        if (!cmp_write_u32(target, to_write.data.unsigned_integer))
        {
            // fprintf(stderr, "__write_object.data_size");
            ret = np_unknown_error;
        }
    }
    else if (to_write.data_type == NP_DATA_TYPE_STR)
    {
        if (!cmp_write_str(target, to_write.data.str, to_write.data_size))
        {
            // fprintf(stderr, "__write_object.data_size");
            ret = np_unknown_error;
        }
    } // ... other types
    else
    {
        ret = np_invalid_argument;
    }
    return ret;
}
struct __kv_pair __read_object(cmp_ctx_t *cmp, enum np_return *error)
{
    struct __kv_pair ret = {0};
    ret.start_of_object = cmp->buf;

    uint32_t key_size = 255;
    if (!cmp_read_str(cmp, ret.key, &key_size)) // key
    {
        // fprintf(stderr, "__read_object.key");
        *error = np_unknown_error;
    }
    else
    {
        cmp_object_t type;
        if (!cmp_read_object(cmp, &type))
        {
            *error = np_unknown_error;
        }
        else if (type.type == CMP_TYPE_BIN32)
        {
            ret.data_type = NP_DATA_TYPE_BIN;
            ret.data_size = type.as.bin_size;
            ret.data.bin = cmp->buf;
            cmp->buf += ret.data_size;
        }
        else if (type.type == CMP_TYPE_FIXSTR || type.type == CMP_TYPE_STR8 || type.type == CMP_TYPE_STR16 || type.type == CMP_TYPE_STR32)
        {
            ret.data_type = NP_DATA_TYPE_STR;
            ret.data_size = type.as.str_size + 1;
            ret.data.str = cmp->buf;
        }
        else if (type.type == CMP_TYPE_SINT32)
        {
            ret.data_type = NP_DATA_TYPE_INT;
            ret.data_size = sizeof(type.as.s32);
            ret.data.integer = type.as.s32;

        }
        else if (type.type == CMP_TYPE_UINT32)
        {
            ret.data_type = NP_DATA_TYPE_UNSIGNED_INT;
            ret.data_size = sizeof(type.as.u32);
            ret.data.integer = type.as.u32;

        } // ... other types
        else
        {
            *error = np_invalid_argument;
        }
    }
    ret.end_of_object = cmp->buf;

    return ret;
}
/**
 * @return unsigned char *  returns the key object start pointer if found
 */
struct __kv_pair __search_for_key(char *key, cmp_ctx_t *cmp, unsigned char *start_buffer, uint32_t max_read, enum np_return *error)
{
    struct __kv_pair ret = {0};
    *error = np_key_not_found;

    unsigned char *pre_read_buf = NULL;
    while ((((unsigned char *)cmp->buf) - start_buffer) < max_read)
    {
        pre_read_buf = cmp->buf;
        struct __kv_pair tmp = __read_object(cmp, error);

        if (*error != np_key_not_found)
        {
            break;
        }
        if (strncmp(tmp.key, key, 255) == 0)
        {
            ret = tmp;
            *error = np_ok;
            break;
        }
    }
    return ret;
}

enum np_return np_set_data(np_datablock_t *block, struct np_data_conf data_conf, unsigned char *data)
{
    enum np_return ret = np_invalid_argument;
    struct __np_datablock_s db = __read_datablock(block, &ret);
    if (ret == np_ok)
    {
        unsigned char *end_of_datablock = db.ublock + db.used_length;

        struct __kv_pair tmp = __search_for_key(data_conf.key, &db.cmp, db.ublock, db.used_length, &ret);

        if (ret == np_ok)
        {
            //  key is already in datablock
            // overwrite data (as in: delete old object und add anew)
            memmove(tmp.start_of_object, tmp.end_of_object, end_of_datablock - tmp.end_of_object);
            db.used_length -= (tmp.end_of_object - tmp.start_of_object); // remove old_object_size;
        }

        if (ret == np_key_not_found || ret == np_ok)
        {
            // check for space in block
            uint32_t new_object_size = sizeof(uint8_t) /*Marker*/ + strnlen(data_conf.key, 255) /*Key*/;
            if (data_conf.type == NP_DATA_TYPE_BIN)
            {
                new_object_size += sizeof(uint8_t) /*Marker*/ + sizeof(uint32_t) /*DataSize*/ + data_conf.data_size /*Data*/;
            } // other data types

            if (new_object_size > (db.total_length - db.used_length))
            {
                ret = np_insufficient_memory;
            }
            else
            {
                // add new object to datablock
                db.cmp.buf = db.ublock + db.used_length;
                struct __kv_pair tmp;
                strncpy(tmp.key, data_conf.key, 255);
                tmp.data_type = data_conf.type;
                tmp.data.bin = data;
                tmp.data_size = data_conf.data_size;
#ifdef DEBUG
                void *old_buf = db.cmp.buf;
#endif
                ret = __write_object(&db.cmp, tmp);

#ifdef DEBUG
                uint32_t actual_new_object_size = db.cmp.buf - old_buf;
                assert(actual_new_object_size == new_object_size);
#endif
                // update "used_length"
                if (ret == np_ok)
                {
                    uint32_t new_used_length = (unsigned char *)db.cmp.buf - db.ublock;
                    struct __np_datablock_s overwrite = {0};
                    overwrite.ublock = ((unsigned char *)block);
                    cmp_init(&overwrite.cmp, block, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);

                    if (__read_datablock_fixed(&ret, &overwrite) != np_ok)
                    {
                        // fprintf(stderr, "np_set_data.__read_datablock_fixed\n");
                        ret = np_unknown_error;
                    }
                    else if (!cmp_write_u32(&overwrite.cmp, new_used_length))
                    {
                        // fprintf(stderr, "np_set_data.overwrite_used_length\n");
                        ret = np_unknown_error;
                    }
                    else if (!cmp_write_map32(&overwrite.cmp, db.object_count + 1))
                    {
                        // fprintf(stderr, "np_set_data.overwrite_object_count\n");
                        ret = np_unknown_error;
                    }
                }
            }
        }
    }
    return ret;
}

enum np_return np_get_data(np_datablock_t *block, char key[255], struct np_data_conf *out_data_config, unsigned char **out_data)
{
    enum np_return ret = np_invalid_argument;
    struct __np_datablock_s db = __read_datablock(block, &ret);
    if (ret == np_ok)
    {
        struct __kv_pair tmp = __search_for_key(key, &db.cmp, db.ublock, db.used_length, &ret);

        if (ret == np_ok)
        {
            out_data_config->data_size = tmp.data_size;
            out_data_config->type = tmp.data_type;
            strncpy(out_data_config->key, key, 255);
            if (out_data != NULL)
                *out_data = tmp.data.bin;
        }
    }
    return ret;
}

enum np_return np_get_data_size(np_datablock_t *block, size_t *out_block_size)
{
    enum np_return ret = np_invalid_argument;
    struct __np_datablock_s db = __read_datablock(block, &ret);
    if (ret == np_ok)
    {
        *out_block_size = db.used_length;
    }
    return ret;
}
