//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "neuropil.h"

#include "util/np_mapreduce.h"
#include "util/np_serialization.h"

#include "np_data.h"
#include "np_util.h"

enum np_data_return np_init_datablock(np_datablock_t *block,
                                      uint32_t        block_length) {
  np_datablock_header_t db_header = {._inner_blob  = block,
                                     .total_length = block_length,
                                     .used_length  = 0,
                                     .object_count = 0};
  return np_serializer_write_datablock_header(&db_header, NP_DATA_MAGIC_NO);
}

void __convert_kv_to_conf(struct np_data_conf *dest_conf,
                          np_data_value       *dest_data,
                          np_kv_buffer_t      *src) {
  if (dest_conf != NULL) {
    dest_conf->data_size = src->data_size;
    dest_conf->type      = src->data_type;
    strncpy(dest_conf->key, src->key, strnlen(src->key, 255));
    dest_conf->key[strnlen(src->key, 255)] = '\0';
  }

  if (dest_data != NULL) {
    if (src->data_type == NP_DATA_TYPE_BIN) {
      dest_data->bin = src->data.bin;
    } else if (src->data_type == NP_DATA_TYPE_INT) {
      dest_data->integer = src->data.integer;
    } else if (src->data_type == NP_DATA_TYPE_UNSIGNED_INT) {
      dest_data->unsigned_integer = src->data.unsigned_integer;
    } else if (src->data_type == NP_DATA_TYPE_STR) {
      dest_data->str = src->data.str;
    } // other types
    else {
      ASSERT(false, "missing implementation");
    }
  }
}

enum np_data_return np_iterate_data(np_datablock_t    *block,
                                    np_iterate_data_cb callback,
                                    void              *userdata) {
  assert(block != NULL);
  assert(callback != NULL);

  enum np_data_return ret = np_could_not_read_object;

  np_datablock_header_t db_header = {._inner_blob = block};
  ret = np_serializer_read_datablock_header(&db_header, NP_DATA_MAGIC_NO);

  if (ret == np_data_ok) {
    uint16_t object_count = 0;

    struct np_data_conf data_conf;
    np_data_value       data_value;

    np_kv_buffer_t container  = {.buffer_start =
                                     np_skip_datablock_header(&db_header)};
    size_t         byte_count = 0;

    while (object_count < db_header.object_count) {

      ret = np_serializer_read_object(&container);
      if (ret == np_data_ok) {
        __convert_kv_to_conf(&data_conf, &data_value, &container);
        if (!callback(&data_conf, &data_value, userdata)) {
          ret = np_invalid_arguments;
          break;
        }
        byte_count += container.buffer_end - container.buffer_start;
        container.buffer_start = container.buffer_end;
        container.buffer_end =
            container.buffer_start + (db_header.used_length - byte_count);
        object_count++;
      } else {
        ret = np_invalid_structure;
        break;
      }
    }
  }
  return ret;
}

enum np_data_return _np_iterate_data_mapreduce(np_datablock_t  *block,
                                               np_map_reduce_t *map) {
  assert(block != NULL);

  enum np_data_return   ret       = np_could_not_read_object;
  np_datablock_header_t db_header = {._inner_blob = block};

  struct np_data data = {0};
  if (ret == np_data_ok) {
    uint16_t object_count = 0;

    np_kv_buffer_t container = {.buffer_start =
                                    np_skip_datablock_header(&db_header)};

    while (object_count < db_header.object_count) {

      ret = np_serializer_read_object(&container);
      if (ret == np_data_ok) {
        __convert_kv_to_conf(&data.conf, &data.value, &container);
        if (!map->map(map, &data)) {
          ret = np_invalid_arguments;
          break;
        }
        container.buffer_start = container.buffer_end;
        object_count++;
      } else {
        break;
      }
    }
  }
  return ret;
}

enum np_data_return np_set_data(np_datablock_t     *block,
                                struct np_data_conf data_conf,
                                np_data_value       data) {
  enum np_data_return   ret       = np_could_not_read_object;
  np_datablock_header_t db_header = {._inner_blob = block};

  ret = np_serializer_read_datablock_header(&db_header, NP_DATA_MAGIC_NO);
  if (ret == np_data_ok) {
    // unsigned char *end_of_datablock = db_header._inner_blob +
    // db_header.used_length;
    np_kv_buffer_t old_container = {.buffer_start = db_header._inner_blob};
    ret                          = np_serializer_search_object(&db_header,
                                      data_conf.key,
                                      &old_container,
                                      NP_DATA_MAGIC_NO);

    size_t old_object_size = 0;

    if (ret == np_data_ok) {
      // key is already in datablock
      assert(old_container.buffer_start != NULL);
      assert(old_container.buffer_end != NULL);
      // overwrite data (as in: delete old object und add anew)
      ret =
          np_serializer_calculate_object_size(old_container, &old_object_size);
    }

    np_kv_buffer_t new_container = {
        .buffer_start = &db_header._inner_blob[db_header.used_length],
        .data         = data,
        .data_size    = data_conf.data_size,
        .data_type    = data_conf.type,
    };
    strncpy(new_container.key, data_conf.key, strnlen(data_conf.key, 255));
    new_container.key[strnlen(data_conf.key, 255)] = '\0';

    size_t new_object_size = 0;
    ret = np_serializer_calculate_object_size(new_container, &new_object_size);

    if (ret == np_key_not_found || ret == np_data_ok) {
      // check for space in block
      size_t available_space =
          (db_header.total_length - db_header.used_length) + old_object_size;
      if (new_object_size > available_space) {
        ret = np_insufficient_memory;
      } else {
        // add new object to datablock
        if (old_object_size > 0) {
          // add at the current position, move remaining block forward/backward
          // a few bits
          new_container.buffer_start    = old_container.buffer_start;
          int32_t  move_delta           = new_object_size - old_object_size;
          uint32_t old_container_offset = old_container.buffer_end - block;
          memmove(old_container.buffer_end + move_delta,
                  old_container.buffer_end,
                  db_header.used_length - old_container_offset);
          db_header.object_count--;
        }
        if (new_object_size > 0) {
          // add to the end of the block
          new_container.buffer_end =
              new_container.buffer_start + new_object_size;
          ret = np_serializer_write_object(&new_container);
          ASSERT(new_object_size ==
                     (new_container.buffer_end - new_container.buffer_start),
                 "object size should be the same");
          db_header.object_count++;
        }
        if (ret == np_data_ok) {
          // update "used_length"
          db_header.used_length =
              db_header.used_length + new_object_size - old_object_size;
          ret = np_serializer_write_datablock_header(&db_header,
                                                     NP_DATA_MAGIC_NO);
        }
      }
    }
  }
  return ret;
}

enum np_data_return np_get_data(np_datablock_t      *block,
                                char                 key[255],
                                struct np_data_conf *out_data_config,
                                np_data_value       *out_data) {

  enum np_data_return   ret       = np_could_not_read_object;
  np_datablock_header_t db_header = {._inner_blob = block};

  // ret = np_serializer_read_datablock_header(&db_header, NP_DATA_MAGIC_NO);
  // if (ret == np_data_ok) {
  // unsigned char *end_of_datablock = db_header._inner_blob +
  // db_header.used_length;
  np_kv_buffer_t old_container = {.buffer_start = db_header._inner_blob};
  ret                          = np_serializer_search_object(&db_header,
                                    key,
                                    &old_container,
                                    NP_DATA_MAGIC_NO);

  if (ret == np_data_ok) {
    __convert_kv_to_conf(out_data_config, out_data, &old_container);
  }
  // }
  return ret;
}

enum np_data_return np_get_data_size(np_datablock_t *block,
                                     size_t         *out_block_size) {
  assert(out_block_size != NULL);
  enum np_data_return   ret       = np_could_not_read_object;
  np_datablock_header_t db_header = {._inner_blob = block};

  ret = np_serializer_read_datablock_header(&db_header, NP_DATA_MAGIC_NO);
  if (ret == np_data_ok) {
    *out_block_size = db_header.used_length;
  } else {
    *out_block_size = 0;
  }
  return ret;
}

enum np_data_return np_get_object_count(np_datablock_t *block,
                                        uint32_t       *count) {
  assert(count != NULL);
  enum np_data_return   ret       = np_could_not_read_object;
  np_datablock_header_t db_header = {._inner_blob = block};

  ret = np_serializer_read_datablock_header(&db_header, NP_DATA_MAGIC_NO);
  if (ret == np_data_ok) {
    *count = db_header.object_count;
  } else {
    *count = 0;
  }
  return ret;
}

enum np_data_return np_merge_data(np_datablock_t *dest, np_datablock_t *src) {
  enum np_data_return ret = np_could_not_read_object;
  if (src != NULL) {
    np_datablock_header_t db_header = {._inner_blob = src};
    ret = np_serializer_read_datablock_header(&db_header, NP_DATA_MAGIC_NO);
    unsigned char *max_buffer_end =
        db_header._inner_blob + db_header.used_length;
    if (ret == np_data_ok) {
      uint16_t       objects_read = 0;
      np_kv_buffer_t kv_pair      = {.buffer_start =
                                         np_skip_datablock_header(&db_header),
                                     .buffer_end = max_buffer_end};
      while (objects_read < db_header.object_count) {
        if (np_data_ok == np_serializer_read_object(&kv_pair)) {

          struct np_data_conf data_cfg;
          np_data_value       data_val;
          __convert_kv_to_conf(&data_cfg, &data_val, &kv_pair);

          ret = np_set_data(dest, data_cfg, data_val);

          if (ret != np_data_ok) break;

          objects_read++;
          kv_pair.buffer_start = kv_pair.buffer_end;
          kv_pair.buffer_end   = max_buffer_end;
        } else {
          ret = np_invalid_structure;
          break;
        }
      }
    }
  }

  return ret;
}

struct _np_print_data_s {
  char  *buffer;
  size_t used;
  size_t buffer_max_size;
};

bool __np_print_datablock_item(struct np_data_conf *out_data_config,
                               np_data_value       *out_data,
                               void                *userdata) {
  bool                     error = false;
  struct _np_print_data_s *tmp   = (struct _np_print_data_s *)userdata;

  size_t max_n = tmp->buffer_max_size - tmp->used;
  size_t n     = 0;
  switch (out_data_config->type) {
  case NP_DATA_TYPE_BIN:
    n = snprintf(tmp->buffer + tmp->used,
                 max_n,
                 "%s:%s:size=%" PRIsizet "; ",
                 out_data_config->key,
                 "BIN",
                 out_data_config->data_size);
    break;
  case NP_DATA_TYPE_INT:
    n = snprintf(tmp->buffer + tmp->used,
                 max_n,
                 "%s:%s:%" PRIi32 "; ",
                 out_data_config->key,
                 "INT",
                 out_data->integer);
    break;
  case NP_DATA_TYPE_STR:
    n = snprintf(tmp->buffer + tmp->used,
                 max_n,
                 "%s:%s:%.*s; ",
                 out_data_config->key,
                 "STR",
                 out_data_config->data_size,
                 out_data->str);
    break;
  case NP_DATA_TYPE_UNSIGNED_INT:
    n = snprintf(tmp->buffer + tmp->used,
                 max_n,
                 "%s:%s:%" PRIu32 "; ",
                 out_data_config->key,
                 "UINT",
                 out_data->unsigned_integer);
    break;

  default:
    break;
  }
  if (n < 0 && n >= max_n) error = true;
  else tmp->used += n;

  return !error && tmp->used <= tmp->buffer_max_size;
}

char *
_np_print_datablock(char *buffer, size_t buffer_max_size, np_datablock_t *src) {
  struct _np_print_data_s tmp = {0};
  tmp.buffer                  = buffer;
  tmp.used                    = 0;
  tmp.buffer_max_size         = buffer_max_size;
  uint32_t count              = 0;
  if (np_data_ok == np_get_object_count(src, &count)) {
    size_t max_n = tmp.buffer_max_size - tmp.used;
    int    n =
        snprintf(tmp.buffer + tmp.used, max_n, "Count:%" PRIu32 "; ", count);
    if (!(n < 0 && n >= max_n)) {
      tmp.used += n;
      np_iterate_data(src, __np_print_datablock_item, &tmp);
    }
  }
  return buffer;
}
