//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "np_util.h"

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "event/ev.h"
#include "parson/parson.h"
#include "sodium.h"
#include "tree/tree.h"

#include "neuropil.h"
#include "neuropil_log.h"

#include "util/np_list.h"
#include "util/np_serialization.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_dhkey.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_message.h"
#include "np_node.h"
#include "np_route.h"
#include "np_threads.h"
#include "np_types.h"

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(char_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(char_ptr);

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_key_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_key_ptr);

char *
np_uuid_create(const char *str, const uint32_t num, unsigned char **buffer) {
  unsigned char *uuid_out = NULL;
  if (buffer == NULL) {
    uuid_out = calloc(1, NP_UUID_BYTES);
    CHECK_MALLOC(uuid_out);
  } else {
    uuid_out = *buffer;
  }
  char input[256] = {0};

  double now = _np_time_now(NULL);
  snprintf(input, 255, "%64s:%010u:%16.16f", str, num, now);

  crypto_generichash_blake2b(uuid_out,
                             16,
                             (unsigned char *)input,
                             256,
                             NULL,
                             0);

  return uuid_out;
}

// TODO: replace with function pointer, same for __np_tree_read_type
// typedef void (*write_type_function)(const np_treeval_t* val, cmp_ctx_t* ctx);
// write_type_function write_type_arr[np_treeval_type_npval_count] = {NULL};
// write_type_arr[np_treeval_type_npval_count] = &write_short_type;
// write_type_arr[np_treeval_type_npval_count] = NULL;

void np_key_ref_list(np_sll_t(np_key_ptr, sll_list),
                     const char *reason,
                     const char *reason_desc) {
  np_state_t *context           = NULL;
  sll_iterator(np_key_ptr) iter = sll_first(sll_list);
  while (NULL != iter) {
    if (context == NULL && iter->val != NULL) {
      context = np_ctx_by_memory(iter->val);
    }
    np_ref_obj(np_key_t, (iter->val), reason, reason_desc);
    sll_next(iter);
  }
}

void np_key_unref_list(np_sll_t(np_key_ptr, sll_list), const char *reason) {
  np_state_t *context           = NULL;
  sll_iterator(np_key_ptr) iter = sll_first(sll_list);
  while (NULL != iter) {

    if (context == NULL && iter->val != NULL) {
      context = np_ctx_by_memory(iter->val);
    }
    np_unref_obj(np_key_t, (iter->val), reason);
    sll_next(iter);
  }
}

void _np_sll_remove_doublettes(np_sll_t(np_key_ptr, list_of_keys)) {
  if (sll_size(list_of_keys) <= 1) return; // no double entries to remove

  sll_iterator(np_key_ptr) iter1 = sll_first(list_of_keys);
  sll_iterator(np_key_ptr) tmp   = NULL;

  do {
    sll_iterator(np_key_ptr) iter2 = sll_get_next(iter1);

    if (NULL == iter2) break;

    do {
      if (0 == _np_dhkey_cmp(&iter1->val->dhkey, &iter2->val->dhkey)) {
        tmp = iter2;
      }
      sll_next(iter2);

      if (NULL != tmp) {
        sll_delete(np_key_ptr, list_of_keys, tmp);
        tmp = NULL;
      }
    } while (NULL != iter2);

    sll_next(iter1);

  } while (NULL != iter1);
}

JSON_Value *np_treeval2json(np_state_t *context, np_treeval_t val) {
  JSON_Value *ret         = NULL;
  bool        free_string = false;
  char       *tmp_str     = NULL;

  switch (val.type) {
  case np_treeval_type_short:
    ret = json_value_init_number(val.value.sh);
    break;
  case np_treeval_type_int:
    ret = json_value_init_number(val.value.i);
    break;
  case np_treeval_type_long:
    ret = json_value_init_number(val.value.l);
    break;
#ifdef x64
  case np_treeval_type_long_long:
    ret = json_value_init_number(val.value.ll);
    break;
#endif
  case np_treeval_type_float:
    ret = json_value_init_number(val.value.f);
    break;
  case np_treeval_type_double:
    ret = json_value_init_number(val.value.d);
    break;
  case np_treeval_type_unsigned_short:
    ret = json_value_init_number(val.value.ush);
    break;
  case np_treeval_type_unsigned_int:
    ret = json_value_init_number(val.value.ui);
    break;
  case np_treeval_type_unsigned_long:
    ret = json_value_init_number(val.value.ul);
    break;
#ifdef x64
  case np_treeval_type_unsigned_long_long:
    ret = json_value_init_number(val.value.ull);
    break;
#endif
  case np_treeval_type_uint_array_2:
    ret = json_value_init_array();
    json_array_append_number(json_array(ret), val.value.a2_ui[0]);
    json_array_append_number(json_array(ret), val.value.a2_ui[1]);
    break;
  case np_treeval_type_jrb_tree:
    ret = np_tree2json(context, val.value.tree);
    break;
    /*
case np_treeval_type_dhkey:
    ret = json_value_init_array();
    json_array_append_number(json_array(ret), val.value.dhkey.t[0]);
    json_array_append_number(json_array(ret), val.value.dhkey.t[1]);
    json_array_append_number(json_array(ret), val.value.dhkey.t[2]);
    json_array_append_number(json_array(ret), val.value.dhkey.t[3]);
    json_array_append_number(json_array(ret), val.value.dhkey.t[4]);
    json_array_append_number(json_array(ret), val.value.dhkey.t[5]);
    json_array_append_number(json_array(ret), val.value.dhkey.t[6]);
    json_array_append_number(json_array(ret), val.value.dhkey.t[7]);
    break;
    */
  default:
    tmp_str = np_treeval_to_str(val, &free_string);
    ret     = json_value_init_string(tmp_str);
    if (free_string == true) {
      free(tmp_str);
    }
    break;
  }
  return ret;
}

void np_tree2buffer(np_state_t *context, np_tree_t *tree, void *buffer) {

  size_t tree_size = np_tree_get_byte_size(tree);
  // np_serializer_add_map_bytesize(tree, &tree_size);
  np_serialize_buffer_t serializer = {._tree          = tree,
                                      ._target_buffer = buffer,
                                      ._buffer_size   = tree_size,
                                      ._bytes_written = 0,
                                      ._error         = 0};
  np_serializer_write_map(context, &serializer, tree);
}

void np_buffer2tree(np_state_t *context,
                    void       *buffer,
                    size_t      buffer_size,
                    np_tree_t  *tree) {
  np_deserialize_buffer_t deserializer = {._target_tree = tree,
                                          ._buffer      = buffer,
                                          ._buffer_size = buffer_size,
                                          ._bytes_read  = 0,
                                          ._error       = 0};
  np_serializer_read_map(context, &deserializer, tree);
}

char *np_dump_tree2char(np_state_t *context, np_tree_t *tree) {
  JSON_Value *tmp  = np_tree2json(context, tree);
  char       *tmp2 = np_json2char(tmp, true);
  free(tmp);
  return tmp2;
}

JSON_Value *np_tree2json(np_state_t *context, np_tree_t *tree) {
  JSON_Value *ret = json_value_init_object();
  JSON_Value *arr = NULL;

  if (NULL != tree) {

    uint16_t i = 0;
    // write jrb tree
    if (0 < tree->size) {
      np_tree_elem_t *tmp      = NULL;
      bool            useArray = false;
      RB_FOREACH (tmp, np_tree_s, tree) {
        char *name = NULL;
        if (np_treeval_type_int == tmp->key.type) {
          useArray = true;
          int size = snprintf(NULL, 0, "%d", tmp->key.value.i);
          name     = malloc(size + 1);
          CHECK_MALLOC(name);

          snprintf(name, size + 1, "%d", tmp->key.value.i);
        } else if (np_treeval_type_double == tmp->key.type) {
          int size = snprintf(NULL, 0, "%f", tmp->key.value.d);
          name     = malloc(size + 1);
          CHECK_MALLOC(name);

          snprintf(name, size + 1, "%f", tmp->key.value.d);
        } else if (np_treeval_type_unsigned_long == tmp->key.type) {
          int size = snprintf(NULL, 0, "%u", tmp->key.value.ul);
          name     = malloc(size + 1);
          CHECK_MALLOC(name);

          snprintf(name, size + 1, "%u", tmp->key.value.ul);
        } else if (np_treeval_type_char_ptr == tmp->key.type) {
          name = strndup(np_treeval_to_str(tmp->key, NULL),
                         strlen(np_treeval_to_str(tmp->key, NULL)));
        } else {
          log_msg(LOG_WARNING,
                  NULL,
                  "unknown key type for serialization. (type: %d)",
                  tmp->key.type);
          continue;
        }

        JSON_Value *value = np_treeval2json(context, tmp->val);

        if (useArray == true) {
          if (NULL == arr) {
            arr = json_value_init_array();
          }

          if (NULL != value) {
            json_array_append_value(json_array(arr), value);
            i++;
          }
        } else {

          if (NULL != name && NULL != value) {
            json_object_set_value(json_object(ret), name, value);
            i++;
          }
        }
        free(name);
      }
    }

    // sanity check and warning message
    if (i != tree->size) {
      log_msg(LOG_WARNING,
              NULL,
              "serialized jrb size map size is %" PRIsizet
              ", but should be %" PRIu16,
              tree->size,
              i);
    }
  }

  if (NULL != arr) {
    json_value_free(ret);
    ret = arr;
  }

  return ret;
}

char *np_json2char(JSON_Value *data, bool prettyPrint) {
  char *ret;
  /*
  size_t json_size ;
  if(prettyPrint){
      json_size = json_serialization_size_pretty(data);
      ret = (char*) malloc(json_size * sizeof(char));
      CHECK_MALLOC(ret);
      json_serialize_to_buffer_pretty(data, ret, json_size);

  }else{
      json_size = json_serialization_size(data);
      ret = (char*) malloc(json_size * sizeof(char));
      CHECK_MALLOC(ret);
      json_serialize_to_buffer(data, ret, json_size);
  }
   */
  if (prettyPrint) {
    ret = json_serialize_to_string_pretty(data);
  } else {
    ret = json_serialize_to_string(data);
  }

  return ret;
}

void np_dump_tree2log(np_state_t *context, log_type category, np_tree_t *tree) {
  if (NULL == tree) {
    log_debug(LOG_DEBUG | category, NULL, "NULL");
  } else {
    char *tmp = np_dump_tree2char(context, tree);
    log_debug(LOG_DEBUG | category, NULL, "%s", tmp);
    json_free_serialized_string(tmp);
  }
}
/*
 * cancats target with source and applys the variable arguments as a string
 * format on source frees target and reasigns it with the new string
 * @param target
 * @param source
 * @return
 */
char *np_str_concatAndFree(char *target, char *source, ...) {

  if (target == NULL) {
    asprintf(&target, "%s", "");
  }
  char   *new_target = NULL;
  char   *tmp        = NULL;
  va_list args;
  va_start(args, source);
  vasprintf(&tmp, source, args);
  va_end(args);

  asprintf(&new_target, "%s%s", target, tmp);

  free(tmp);
  free(target);
  target = new_target;
  // free(source);
  return new_target;
}

bool np_get_local_ip(np_state_t *context, char *buffer, int buffer_size) {

  bool ret = false;

  const char *ext_server = "37.97.143.153"; //"neuropil.io";
  int         dns_port   = 53;

  struct sockaddr_in serv;

  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  if (sock < 0) {
    ret = false;
    log_msg(
        LOG_ERROR,
        NULL,
        "Could not detect local ip. (1) Error: Socket could not be created");
  } else {

    memset(&serv, 0, sizeof(serv));
    serv.sin_family      = AF_INET;
    serv.sin_addr.s_addr = inet_addr(ext_server);
    serv.sin_port        = htons(dns_port);

    int err = connect(sock, (const struct sockaddr *)&serv, sizeof(serv));
    if (err < 0) {
      ret = false;
      log_msg(LOG_ERROR,
              NULL,
              "Could not detect local ip. (2) Error: %s (%d)",
              strerror(errno),
              errno);
    } else {
      struct sockaddr_in name;
      socklen_t          namelen = sizeof(name);
      err = getsockname(sock, (struct sockaddr *)&name, &namelen);

      if (err < 0) {
        ret = false;
        log_msg(LOG_ERROR,
                NULL,
                "Could not detect local ip. (3) Error: %s (%d)",
                strerror(errno),
                errno);
      } else {
        const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, buffer_size);

        if (p == NULL) {
          ret = false;
          log_msg(LOG_ERROR,
                  NULL,
                  "Could not detect local ip. (4) Error: %s (%d)",
                  strerror(errno),
                  errno);
        }
        if (strncmp(buffer, "0.0.0.0", 7) == 0) {
          ret = false;
          log_msg(LOG_ERROR,
                  NULL,
                  "Could not detect local ip. (5) Error: ip result 0.0.0.0");
        } else {
          ret = true;
        }
      }
    }
    close(sock);
  }
  return ret;
}

uint8_t np_util_char_ptr_cmp(char_ptr const a, char_ptr const b) {
  return (uint8_t)strcmp(a, b);
}

char_ptr
_sll_char_remove(np_sll_t(char_ptr, target), char *to_remove, size_t cmp_len) {
  char *ret                   = NULL;
  char *tmp                   = NULL;
  sll_iterator(char_ptr) iter = sll_first(target);
  while (iter != NULL) {
    tmp = (iter->val);
    if (strncmp(tmp, to_remove, cmp_len) == 0) {
      ret = tmp;
      sll_delete(char_ptr, target, iter);
      break;
    }
    sll_next(iter);
  }
  return ret;
}
/*
 * Takes a char pointer list and concatinates it to one string
 */
char *_sll_char_make_flat(np_state_t *context, np_sll_t(char_ptr, target)) {
  char *ret = NULL;

  sll_iterator(char_ptr) iter = sll_first(target);
  uint32_t i                  = 0;
  while (iter != NULL) {
    ret = np_str_concatAndFree(ret, "%" PRIu32 ":\"%s\"->", i, iter->val);
    i++;
    sll_next(iter);
  }
#ifdef DEBUG
  if (sll_size(target) != i) {
    log_msg(LOG_ERROR, NULL, "%s", ret);
    log_msg(LOG_ERROR,
            NULL,
            "Size of original list (%" PRIu32
            ") does not equal the size of the flattend string (items flattend: "
            "%" PRIu32 ").",
            sll_size(target),
            i);
    ABORT("Size of original list (%" PRIu32
          ") does not equal the size of the flattend string (items flattend: "
          "%" PRIu32 ").",
          sll_size(target),
          i);
  }
#endif
  return (ret);
}

/**
 * Returns a part copy of the original list.
 * If amount is negative the part contains the last elements of the original
 * list.
 */
sll_return(char_ptr)
    _sll_char_part(np_sll_t(char_ptr, target), int32_t amount) {

  sll_return(char_ptr) ret;
  sll_init(char_ptr, ret);

  int begin_copy_at = 0;

  if (amount < 0) {
    // get from tail
    amount = amount * -1;
    if (sll_size(target) <= (uint32_t)amount) {
      amount = (int32_t)sll_size(target);
    } else {
      begin_copy_at = (int32_t)sll_size(target) - amount;
    }
  }

  sll_iterator(char_ptr) iter = sll_first(target);
  int i                       = 0;
  while (iter != NULL) {
    if (i >= begin_copy_at) {
      sll_append(char_ptr, ret, iter->val);
    }
    i++;
    sll_next(iter);
  }
  return ret;
}

char *np_util_string_trim_left(char *target) {
  char *ret = target;

  for (size_t i = 0; i < strlen(target); i++) {
    if (!(target[i] == ' ' || target[i] == '\t' || target[i] == '\r' ||
          target[i] == '\n')) {
      ret = &target[i];
      break;
    }
  }

  return ret;
}

char *np_util_stringify_pretty(enum np_util_stringify_e type,
                               void                    *data,
                               char                     buffer[255]) {

  const char *byte_options[] = {"b", "kB", "MB", "GB", "TB", "PB", "?"};

  if (type == np_util_stringify_bytes_per_sec ||
      type == np_util_stringify_bytes) {
    float  bytes     = *((float *)data);
    double to_format = bytes;
    int    i;
    for (i = 0; i < 6; i++) {
      to_format = to_format / 1024;
      if (to_format < 1024) {
        i++;
        break;
      }
    }
    if (type == np_util_stringify_bytes_per_sec) {
      snprintf(buffer, 255, "%5.2f %s/s", to_format, byte_options[i]);
    } else {
      snprintf(buffer, 255, "%5.2f %s", to_format, byte_options[i]);
    }
    // fprintf(stderr, "%f / %f / %s\n", bytes, to_format, buffer);
  } else if (type == np_util_stringify_time_ms) {

    double time = *((double *)data);

    // snprintf(buffer, 254"%+"PRIu32" ms", ceil(time * 1000));
    snprintf(buffer, 254, "%+f ms", time);
  } else {
    strncpy(buffer, "<unknown type>", 15);
  }

  return buffer;
}
