//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "util/np_treeval.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "inttypes.h"
#include "sodium.h"

#include "neuropil_log.h"

#include "util/np_tree.h"

#include "np_dhkey.h"
#include "np_log.h"
#include "np_settings.h"
#include "np_util.h"

np_treeval_t np_treeval_copy_of_val(np_treeval_t from) {

  np_treeval_t to;
  switch (from.type) {
  // length is always 1 (to identify the type) + the length of the type
  case np_treeval_type_short:
    to.type     = np_treeval_type_short;
    to.value.sh = from.value.sh;
    to.size     = sizeof(int8_t);
    break;
  case np_treeval_type_int:
    to.type    = np_treeval_type_int;
    to.value.i = from.value.i;
    to.size    = sizeof(int16_t);
    break;
  case np_treeval_type_long:
    to.type    = np_treeval_type_long;
    to.value.l = from.value.l;
    to.size    = sizeof(int32_t);
    break;
#ifdef x64
  case np_treeval_type_long_long:
    to.type     = np_treeval_type_long_long;
    to.value.ll = from.value.ll;
    to.size     = sizeof(int64_t);
    break;
#endif
  case np_treeval_type_float:
    to.type    = np_treeval_type_float;
    to.value.f = from.value.f;
    to.size    = sizeof(float);
    break;
  case np_treeval_type_double:
    to.type    = np_treeval_type_double;
    to.value.d = from.value.d;
    to.size    = sizeof(double);
    break;
  case np_treeval_type_char_ptr:
    to.type    = np_treeval_type_char_ptr;
    to.value.s = strndup(from.value.s, from.size);
    to.size    = from.size; 
    // log_debug(LOG_DEBUG, NULL, "copy str %s %hd", to.value.s, to.size);
    break;
  case np_treeval_type_special_char_ptr:
    to.type      = np_treeval_type_special_char_ptr;
    to.value.ush = from.value.ush;
    to.size      = sizeof(uint8_t);
    break;
  case np_treeval_type_char:
    to.type    = np_treeval_type_char;
    to.value.c = from.value.c;
    to.size    = sizeof(char);
    break;
  case np_treeval_type_unsigned_char:
    to.type     = np_treeval_type_unsigned_char;
    to.value.uc = from.value.uc;
    to.size     = sizeof(unsigned char);
    break;
  case np_treeval_type_unsigned_short:
    to.type      = np_treeval_type_unsigned_short;
    to.value.ush = from.value.ush;
    to.size      = sizeof(uint8_t);
    break;
  case np_treeval_type_unsigned_int:
    to.type     = np_treeval_type_unsigned_int;
    to.value.ui = from.value.ui;
    to.size     = sizeof(uint16_t);
    break;
  case np_treeval_type_unsigned_long:
    to.type     = np_treeval_type_unsigned_long;
    to.value.ul = from.value.ul;
    to.size     = sizeof(uint32_t);
    break;
#ifdef x64
  case np_treeval_type_unsigned_long_long:
    to.type      = np_treeval_type_unsigned_long_long;
    to.value.ull = from.value.ull;
    to.size      = sizeof(uint64_t);
    break;
#endif
  case np_treeval_type_uint_array_2:
    to.type           = np_treeval_type_uint_array_2;
    to.value.a2_ui[0] = from.value.a2_ui[0];
    to.value.a2_ui[1] = from.value.a2_ui[1];
    to.size           = 2 * sizeof(uint16_t);
    break;
    // 		case np_treeval_type_float_array_2:  byte_size += 1 +
    // 2*sizeof(float); break; 		case np_treeval_type_char_array_8:
    // byte_size += 1 + 8*sizeof(char); break; 		case
    // np_treeval_type_unsigned_char_array_8: byte_size += 1 +8*sizeof(unsigned
    // char); break;
  case np_treeval_type_bin:
    to.type      = np_treeval_type_bin;
    to.value.bin = malloc(from.size);
    CHECK_MALLOC(to.value.bin);
    memcpy(to.value.bin, from.value.bin, from.size);
    to.size = from.size;
    break;
  case np_treeval_type_cose_signed:
  case np_treeval_type_cose_encrypted:
  case np_treeval_type_cwt:
  case np_treeval_type_jrb_tree:
    to.type       = from.type;
    to.size       = from.size;
    to.value.tree = np_tree_clone(from.value.tree);
    break;
  case np_treeval_type_dhkey:
    to.type = np_treeval_type_dhkey;
    memcpy(&to.value.dhkey, &from.value.dhkey, sizeof(np_dhkey_t));
    to.size = sizeof(np_dhkey_t);
    break;
  case np_treeval_type_uuid:
    to.type = np_treeval_type_uuid;
    memcpy(to.value.uuid, from.value.uuid, NP_UUID_BYTES);
    to.size = NP_UUID_BYTES;
    break;
  case np_treeval_type_hash:
    to.type      = np_treeval_type_hash;
    to.value.bin = malloc(from.size);
    CHECK_MALLOC(to.value.bin)

    memcpy(to.value.bin, from.value.bin, from.size);
    to.size = from.size;
    break;
  case np_treeval_type_void:
    to.type    = np_treeval_type_void;
    to.value.v = from.value.v;
    to.size    = from.size;
    break;
  default:
    to.type = np_treeval_type_undefined;
    // log_msg(LOG_WARNING, NULL, "unsupported copy operation for np_treeval
    // type
    // %"PRIu8,from.type);
    break;
  }
  return to;
}
/*
    @param:freeable: returns the information to free or not to free the result
*/
char *np_treeval_to_str(np_treeval_t val, bool *freeable) {

  int   len    = 0;
  char *result = NULL;
  if (freeable != NULL) *freeable = false;
  uint32_t hex_len;
  switch (val.type) {
  // length is always 1 (to identify the type) + the length of the type
  case np_treeval_type_short:
    len = snprintf(NULL, 0, "%d", val.value.sh);
    if (0 < len) {
      result = malloc(len + 1);
      CHECK_MALLOC(result);
      if (freeable != NULL) *freeable = true;
      snprintf(result, len + 1, "%d", val.value.sh);
    }
    break;
  case np_treeval_type_int:
    len = snprintf(NULL, 0, "%d", val.value.i);
    if (0 < len) {
      result = malloc(len + 1);
      CHECK_MALLOC(result);
      if (freeable != NULL) *freeable = true;
      snprintf(result, len + 1, "%d", val.value.i);
    }
    break;
  case np_treeval_type_long:
    len = snprintf(NULL, 0, "%d", val.value.l);
    if (0 < len) {
      result = malloc(len + 1);
      CHECK_MALLOC(result);
      if (freeable != NULL) *freeable = true;
      snprintf(result, len + 1, "%d", val.value.l);
    }
    break;
#ifdef x64
  case np_treeval_type_long_long:
    len = snprintf(NULL, 0, "%" PRIu64, val.value.ll);
    if (0 < len) {
      result = malloc(len + 1);
      CHECK_MALLOC(result);
      if (freeable != NULL) *freeable = true;
      snprintf(result, len + 1, "%" PRIu64, val.value.ll);
    }
    break;
#endif
  case np_treeval_type_float:
    len = snprintf(NULL, 0, "%f", val.value.f);
    if (0 < len) {
      result = malloc(len + 1);
      CHECK_MALLOC(result);
      if (freeable != NULL) *freeable = true;
      snprintf(result, len + 1, "%f", val.value.f);
    }
    break;
  case np_treeval_type_double:
    len = snprintf(NULL, 0, "%f", val.value.d);
    if (0 < len) {
      result = malloc(len + 1);
      CHECK_MALLOC(result);
      if (freeable != NULL) *freeable = true;
      snprintf(result, len + 1, "%f", val.value.d);
    }
    break;
  case np_treeval_type_char_ptr:
    return val.value.s;
    break;
  case np_treeval_type_char:
  case np_treeval_type_unsigned_char:
    return &val.value.c;
    break;
  case np_treeval_type_unsigned_short:
    len = snprintf(NULL, 0, "%u", val.value.ush);
    if (0 < len) {
      result = malloc(len + 1);
      CHECK_MALLOC(result);
      if (freeable != NULL) *freeable = true;
      snprintf(result, len + 1, "%u", val.value.ush);
    }
    break;
  case np_treeval_type_unsigned_int:
    len = snprintf(NULL, 0, "%u", val.value.ui);
    if (0 < len) {
      result = malloc(len + 1);
      CHECK_MALLOC(result);
      if (freeable != NULL) *freeable = true;
      snprintf(result, len + 1, "%u", val.value.ui);
    }
    break;
  case np_treeval_type_unsigned_long:
    len = snprintf(NULL, 0, "%u", val.value.ul);
    if (0 < len) {
      result = malloc(len + 1);
      CHECK_MALLOC(result);
      if (freeable != NULL) *freeable = true;
      snprintf(result, len + 1, "%u", val.value.ul);
    }
    break;
#ifdef x64
  case np_treeval_type_unsigned_long_long:
    len = snprintf(NULL, 0, "%" PRIu64, val.value.ull);
    if (0 < len) {
      result = malloc(len + 1);
      CHECK_MALLOC(result);
      if (freeable != NULL) *freeable = true;
      snprintf(result, len + 1, "%" PRIu64, val.value.ull);
    }
    break;
#endif
  case np_treeval_type_uint_array_2:
    len = snprintf(NULL, 0, "%u,%u", val.value.a2_ui[0], val.value.a2_ui[1]);
    if (0 < len) {
      result = malloc(len + 1);
      CHECK_MALLOC(result);
      if (freeable != NULL) *freeable = true;
      snprintf(result,
               len + 1,
               "%u,%u",
               val.value.a2_ui[0],
               val.value.a2_ui[1]);
    }
    break;
    // 		case np_treeval_type_float_array_2:  byte_size += 1 +
    // 2*sizeof(float); break; 		case np_treeval_type_char_array_8:
    // byte_size += 1 + 8*sizeof(char); break; 		case
    // np_treeval_type_unsigned_char_array_8: byte_size += 1 +8*sizeof(unsigned
    // char); break;
  case np_treeval_type_void:
    return "--> pointer";
    break;
  case np_treeval_type_hash:
  case np_treeval_type_bin:
    hex_len       = val.size * 2 + 1;
    char *hex_str = malloc(hex_len + 2);
    hex_str[0]    = '0';
    hex_str[1]    = 'x';
    if (freeable != NULL) *freeable = true;
    sodium_bin2hex(hex_str + 2, hex_len, val.value.bin, val.size);
    return hex_str;
    break;
  case np_treeval_type_jrb_tree:
    if (freeable != NULL) *freeable = true;
    char           *info_str = NULL;
    np_tree_elem_t *tmp      = NULL;
    bool            free_key, free_value;
    char           *key, *value;
    info_str = np_str_concatAndFree(info_str, "--> SUBTREE: (");
    RB_FOREACH (tmp, np_tree_s, (val.value.tree)) {
      key      = np_treeval_to_str(tmp->key, &free_key);
      value    = np_treeval_to_str(tmp->val, &free_value);
      info_str = np_str_concatAndFree(info_str, "%s:%s |", key, value);
      if (free_value) free(value);
      if (free_key) free(key);
    }
    info_str = np_str_concatAndFree(info_str, ") ");
    return info_str;
    break;
  case np_treeval_type_dhkey:
    result = malloc(65);
    CHECK_MALLOC(result);
    if (freeable != NULL) *freeable = true;
    _np_dhkey_str(&val.value.dhkey, result);
    break;
  case np_treeval_type_uuid:
    result = malloc((2 * NP_UUID_BYTES) + 1);
    CHECK_MALLOC(result);
    if (freeable != NULL) *freeable = true;
    sodium_bin2hex(result,
                   (2 * NP_UUID_BYTES) + 1,
                   val.value.uuid,
                   NP_UUID_BYTES);
    break;
  default:
    return "--> unknown";
    break;
  }
  return result;
}

np_treeval_t np_treeval_new_i(int16_t i) {
  np_treeval_t j;
  j.value.i = i;
  j.type    = np_treeval_type_int;
  j.size    = sizeof(int16_t);
  return j;
}

np_treeval_t np_treeval_new_l(int32_t l) {
  np_treeval_t j;
  j.value.l = l;
  j.type    = np_treeval_type_long;
  j.size    = sizeof(int32_t);
  return j;
}
#ifdef x64
np_treeval_t np_treeval_new_ll(int64_t ll) {
  np_treeval_t j;
  j.value.ll = ll;
  j.type     = np_treeval_type_long_long;
  j.size     = sizeof(int64_t);
  return j;
}
#endif
np_treeval_t np_treeval_new_f(float f) {
  np_treeval_t j;
  j.value.f = f;
  j.type    = np_treeval_type_float;
  j.size    = sizeof(float);
  return j;
}

np_treeval_t np_treeval_new_d(double d) {
  np_treeval_t j;
  j.value.d = d;
  j.type    = np_treeval_type_double;
  j.size    = sizeof(double);
  return j;
}

np_treeval_t np_treeval_new_v(void *v) {
  np_treeval_t j;
  j.value.v = v;
  j.type    = np_treeval_type_void;
  return j;
}

np_treeval_t np_treeval_new_s(char *s) {
  np_treeval_t j;
  j.size    = strlen(s);
  j.value.s = s; // strndup(s, j.size);
  j.type    = np_treeval_type_char_ptr;
  return j;
}

np_treeval_t np_treeval_new_c(char c) {
  np_treeval_t j;
  j.value.c = c;
  j.type    = np_treeval_type_char;
  j.size    = sizeof(char);
  return j;
}

np_treeval_t np_treeval_new_uc(unsigned char uc) {
  np_treeval_t j;
  j.value.uc = uc;
  j.type     = np_treeval_type_unsigned_char;
  j.size     = sizeof(unsigned char);
  return j;
}

np_treeval_t np_treeval_new_sh(int8_t sh) {
  np_treeval_t j;
  j.value.sh = sh;
  j.type     = np_treeval_type_short;
  j.size     = sizeof(int8_t);
  return j;
}

np_treeval_t np_treeval_new_ush(uint8_t ush) {
  np_treeval_t j;
  j.value.ush = ush;
  j.type      = np_treeval_type_unsigned_short;
  j.size      = sizeof(uint8_t);
  return j;
}

np_treeval_t np_treeval_new_ui(uint16_t i) {
  np_treeval_t j;
  j.value.ui = i;
  j.type     = np_treeval_type_unsigned_int;
  j.size     = sizeof(uint16_t);
  return j;
}

np_treeval_t np_treeval_new_ul(uint32_t ul) {
  np_treeval_t j;
  j.value.ul = ul;
  j.type     = np_treeval_type_unsigned_long;
  j.size     = sizeof(uint32_t);
  return j;
}

#ifdef x64
np_treeval_t np_treeval_new_ull(uint64_t ull) {
  np_treeval_t j;
  j.value.ull = ull;
  j.type      = np_treeval_type_unsigned_long_long;
  j.size      = sizeof(uint64_t);
  return j;
}
#endif

np_treeval_t np_treeval_new_bin(void *data, uint32_t ul) {
  np_treeval_t j;

  j.value.bin = data;
  j.size      = ul;
  j.type      = np_treeval_type_bin;

  return j;
}

np_treeval_t np_treeval_new_dhkey(np_dhkey_t dhkey) {
  np_treeval_t j;

  j.value.dhkey = dhkey;
  j.type        = np_treeval_type_dhkey;
  j.size        = sizeof(np_dhkey_t);

  // j.size = sizeof(key);
  // j.size = 1 + ( 4*sizeof(uint64_t) );
  return j;
}

np_treeval_t np_treeval_new_iarray(uint16_t i0, uint16_t i1) {
  np_treeval_t j;
  j.value.a2_ui[0] = i0;
  j.value.a2_ui[1] = i1;
  j.type           = np_treeval_type_uint_array_2;
  j.size           = 2 * sizeof(uint16_t);
  return j;
}

np_treeval_t np_treeval_new_farray(float f0, float f1) {
  np_treeval_t j;
  j.value.farray[0] = f0;
  j.value.farray[1] = f1;
  j.type            = np_treeval_type_float_array_2;
  j.size            = 2 * sizeof(float);
  return j;
}

np_treeval_t np_treeval_new_carray_nt(char *carray) {
  np_treeval_t j;
  uint8_t      i;

  for (i = 0; i < 8 && carray[i] != '\0'; i++) {
    j.value.carray[i] = carray[i];
  }

  if (i < 8) j.value.carray[i] = carray[i];

  j.type = np_treeval_type_char_array_8;

  return j;
}

np_treeval_t np_treeval_new_carray_nnt(char *carray) {
  np_treeval_t j;
  memcpy(j.value.carray, carray, 8);
  j.type = np_treeval_type_unsigned_char_array_8;
  return j;
}

np_treeval_t np_treeval_new_tree(np_tree_t *tree) {
  np_treeval_t j;
  j.value.tree = tree;
  j.type       = np_treeval_type_jrb_tree;
  j.size       = tree->size;
  return j;
}

np_treeval_t np_treeval_new_cose_encrypted(np_tree_t *tree) {
  np_treeval_t j;
  j.value.tree = tree;
  j.type       = np_treeval_type_cose_encrypted;
  j.size       = tree->size;
  return j;
}

np_treeval_t np_treeval_new_cose_signed(np_tree_t *tree) {
  np_treeval_t j;
  j.value.tree = tree;
  j.type       = np_treeval_type_cose_signed;
  j.size       = tree->size;
  return j;
}

np_treeval_t np_treeval_new_cwt(np_tree_t *tree) {
  np_treeval_t j;
  j.value.tree = tree;
  j.type       = np_treeval_type_cwt;
  j.size       = tree->size;
  return j;
}

np_treeval_t np_treeval_new_hash(char *s) {
  np_treeval_t j;

  char *hash = malloc(crypto_generichash_BYTES);
  CHECK_MALLOC(hash);

  crypto_generichash((unsigned char *)hash,
                     sizeof hash,
                     (unsigned char *)s,
                     sizeof(s),
                     NULL,
                     0);

  j.size      = crypto_generichash_BYTES; // strlen(hex_hash);
  j.value.bin = hash;                     // strndup(hex_hash, j.size);
  j.type      = np_treeval_type_hash;

  return j;
}

int16_t np_treeval_i(np_treeval_t j) { return j.value.i; }

int32_t np_treeval_l(np_treeval_t j) { return j.value.l; }
#ifdef x64
int64_t np_treeval_ll(np_treeval_t j) { return j.value.ll; }
#endif
float np_treeval_f(np_treeval_t j) { return j.value.f; }

double np_treeval_d(np_treeval_t j) { return j.value.d; }

void *np_treeval_v(np_treeval_t j) { return j.value.v; }

char *np_treeval_str(np_treeval_t j) { return j.value.s; }

char np_treeval_c(np_treeval_t j) { return j.value.c; }

unsigned char np_treeval_uc(np_treeval_t j) { return j.value.uc; }

int8_t np_treeval_sh(np_treeval_t j) { return j.value.sh; }

uint8_t np_treeval_ush(np_treeval_t j) { return j.value.ush; }

uint16_t np_treeval_ui(np_treeval_t j) { return j.value.ui; }

uint32_t np_treeval_ul(np_treeval_t j) { return j.value.ul; }

#ifdef x64
uint64_t np_treeval_ull(np_treeval_t j) { return j.value.ull; }
#endif

// int16_t* np_treeval_iarray (np_treeval_t j)
//{
//    return j.value.a2_ui;
//}

float *np_treeval_farray(np_treeval_t j) { return j.value.farray; }

char *np_treeval_carray(np_treeval_t j) { return j.value.carray; }

char *np_treeval_h(np_treeval_t j) { return j.value.bin; }

size_t np_treeval_get_byte_size(np_treeval_t ele) {

  size_t   byte_size = 0;
  uint64_t abs_value = 0;

  switch (ele.type) {

#ifdef NP_USE_CMP
  case np_treeval_type_short:
    byte_size += 1 + sizeof(int8_t);
    break;
  case np_treeval_type_int:
    byte_size += 1 + sizeof(int16_t);
    break;
  case np_treeval_type_long:
    byte_size += 1 + sizeof(int32_t);
    break;
#ifdef x64
  case np_treeval_type_long_long:
    byte_size += 1 + sizeof(int64_t);
    break;
#endif
  case np_treeval_type_float:
    byte_size += 1 + sizeof(float);
    break;
  case np_treeval_type_double:
    byte_size += 1 + sizeof(double);
    break;
  case np_treeval_type_char_ptr:
    byte_size += sizeof(uint8_t) /*str marker*/ +
                 sizeof(uint32_t) /*size of str*/ + ele.size /*string*/ +
                 sizeof(char) /*terminator*/;
    break;
  case np_treeval_type_char:
    byte_size += 1 + sizeof(char);
    break;
  case np_treeval_type_unsigned_char:
    byte_size += 1 + sizeof(unsigned char);
    break;
  case np_treeval_type_unsigned_short:
    byte_size += 1 + sizeof(uint8_t);
    break;
  case np_treeval_type_unsigned_int:
    byte_size += 1 + sizeof(uint16_t);
    break;
  case np_treeval_type_unsigned_long:
    byte_size += 1 + sizeof(uint32_t);
    break;
#ifdef x64
  case np_treeval_type_unsigned_long_long:
    byte_size += 1 + sizeof(uint64_t);
    break;
#endif
  case np_treeval_type_uint_array_2:
    byte_size += 1 + 2 * sizeof(uint16_t);
    break;
  case np_treeval_type_float_array_2:
    byte_size += 1 + 2 * sizeof(float);
    break;
  case np_treeval_type_char_array_8:
    byte_size += 1 + 8 * sizeof(char);
    break;
  case np_treeval_type_unsigned_char_array_8:
    byte_size += 1 + 8 * sizeof(unsigned char);
    break;
  case np_treeval_type_void:
    byte_size += 1 + sizeof(void *);
    break;
  case np_treeval_type_bin:
    byte_size += 1 + sizeof(uint32_t) + ele.size;
    break;
  case np_treeval_type_hash:
    byte_size += 1 + sizeof(uint32_t) + sizeof(int8_t) + ele.size;
    break;
  case np_treeval_type_cose_encrypted:
  case np_treeval_type_cose_signed:
  case np_treeval_type_cwt:
  case np_treeval_type_jrb_tree:
    byte_size += sizeof(uint8_t) /*ext32 marker*/ +
                 sizeof(uint32_t) /*size of ext32*/ +
                 sizeof(uint8_t) /*type of ext32*/ + ele.value.tree->byte_size;
    break;
  case np_treeval_type_dhkey:
    byte_size += sizeof(uint8_t) /*ext32 marker*/ +
                 sizeof(uint32_t) /*size of ext32*/ +
                 sizeof(uint8_t) /*type of ext32*/ +
                 (/*size of dhkey*/ 8 * (sizeof(uint8_t) /*uint32 marker*/ +
                                         sizeof(uint32_t) /*uint32 value*/));
    break;
#endif

#ifdef NP_USE_QCBOR

  case np_treeval_type_short:
    byte_size += sizeof(uint8_t) /* int type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */;
    abs_value = ele.value.sh > 0 ? ele.value.sh : -ele.value.sh;
    if (abs_value >= 24) byte_size += sizeof(uint8_t);
    break;
  case np_treeval_type_int:
    byte_size += sizeof(uint8_t) /* int type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */;
    abs_value = ele.value.i > 0 ? ele.value.i : -ele.value.i;
    if (abs_value > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (abs_value >= 24) byte_size += sizeof(uint8_t);
    break;
  case np_treeval_type_long:
    byte_size += sizeof(uint8_t) /* int type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */;
    abs_value = ele.value.l > 0 ? ele.value.l : -ele.value.l;
    if (abs_value > UINT16_MAX) byte_size += sizeof(uint32_t);
    else if (abs_value > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (abs_value >= 24) byte_size += sizeof(uint8_t);
    break;
#ifdef x64
  case np_treeval_type_long_long:
    byte_size += sizeof(uint8_t) /* int type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */;
    abs_value = ele.value.ll > 0 ? ele.value.ll : -ele.value.ll;
    if (abs_value > UINT32_MAX) byte_size += sizeof(uint64_t);
    else if (abs_value > UINT16_MAX) byte_size += sizeof(uint32_t);
    else if (abs_value > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (abs_value >= 24) byte_size += sizeof(uint8_t);
    break;
#endif
  case np_treeval_type_float:
    byte_size += 1 + sizeof(float);
    break;
  case np_treeval_type_double:
    byte_size += 1 + sizeof(double);
    break;
  case np_treeval_type_char_ptr:
    if (ele.size > UINT32_MAX) byte_size += sizeof(uint64_t);
    else if (ele.size > UINT16_MAX) byte_size += sizeof(uint32_t);
    else if (ele.size > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (ele.size >= 24) byte_size += sizeof(uint8_t);
    byte_size += sizeof(uint8_t) /*str marker*/ + ele.size /*string*/;
    break;
  case np_treeval_type_char:
    byte_size += sizeof(uint8_t) + sizeof(char);
    break;
  case np_treeval_type_unsigned_char:
    byte_size += sizeof(uint8_t) + sizeof(unsigned char);
    break;
  case np_treeval_type_unsigned_short:
    byte_size += sizeof(uint8_t) /* int type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */;
    if (ele.value.ush >= 24) byte_size += sizeof(uint8_t);
    break;
  case np_treeval_type_unsigned_int:
    byte_size += sizeof(uint8_t) /* int type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */;
    if (ele.value.i > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (ele.value.i >= 24) byte_size += sizeof(uint8_t);
    break;
  case np_treeval_type_unsigned_long:
    byte_size += sizeof(uint8_t) /* int type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */;
    if (ele.value.ul > UINT16_MAX) byte_size += sizeof(uint32_t);
    else if (ele.value.ul > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (ele.value.ul >= 24) byte_size += sizeof(uint8_t);
    break;
#ifdef x64
  case np_treeval_type_unsigned_long_long:
    byte_size += sizeof(uint8_t) /* int type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */;
    if (ele.value.ull > UINT32_MAX) byte_size += sizeof(uint64_t);
    else if (ele.value.ull > UINT16_MAX) byte_size += sizeof(uint32_t);
    else if (ele.value.ull > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (ele.value.ull >= 24) byte_size += sizeof(uint8_t);
    break;
#endif
  case np_treeval_type_uint_array_2:
    if (ele.value.a2_ui[0] > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (ele.value.a2_ui[0] >= 24) byte_size += sizeof(uint8_t);

    if (ele.value.a2_ui[1] > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (ele.value.a2_ui[1] >= 24) byte_size += sizeof(uint8_t);
    byte_size += sizeof(uint8_t) /* array type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */ + sizeof(uint8_t) +
                 sizeof(uint8_t); /* int tag */
    break;
  case np_treeval_type_float_array_2:
    byte_size += sizeof(uint8_t) + 2 * sizeof(float);
    break;
  case np_treeval_type_char_array_8:
    byte_size += sizeof(uint8_t) + 8 * sizeof(char);
    break;
  case np_treeval_type_unsigned_char_array_8:
    byte_size += sizeof(uint8_t) + 8 * sizeof(unsigned char);
    break;
  case np_treeval_type_void:
    byte_size += sizeof(uint8_t) + sizeof(void *);
    break;
  case np_treeval_type_bin:
    if (ele.size > UINT16_MAX) byte_size += sizeof(uint32_t);
    else if (ele.size > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (ele.size >= 24) byte_size += sizeof(uint8_t);
    byte_size += sizeof(uint8_t) + ele.size;
    break;
  case np_treeval_type_hash:
    byte_size += sizeof(uint8_t) /* array type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */ + sizeof(uint8_t) + ele.size;
    break;
  case np_treeval_type_jrb_tree:
    if (ele.value.tree->size > UINT32_MAX) byte_size += sizeof(uint64_t);
    else if (ele.value.tree->size > UINT16_MAX) byte_size += sizeof(uint32_t);
    else if (ele.value.tree->size > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (ele.value.tree->size >= 24) byte_size += sizeof(uint8_t);
    byte_size += sizeof(uint8_t) /* map type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */ + ele.value.tree->byte_size;
    break;
  case np_treeval_type_dhkey:
    byte_size += sizeof(uint8_t) /* array type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */ +
                 (/*size of dhkey*/ 8 * (sizeof(uint8_t) /* uint32 marker */ +
                                         sizeof(uint32_t) /* uint32 value */));
    break;
  case np_treeval_type_cose_encrypted:
    byte_size += sizeof(uint8_t) + sizeof(uint16_t); // cose encrypted tag
    if (ele.value.tree->size > UINT32_MAX) byte_size += sizeof(uint64_t);
    else if (ele.value.tree->size > UINT16_MAX) byte_size += sizeof(uint32_t);
    else if (ele.value.tree->size > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (ele.value.tree->size >= 24) byte_size += sizeof(uint8_t);
    byte_size += sizeof(uint8_t) /* map type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */ + ele.value.tree->byte_size;
    break;
  case np_treeval_type_cose_signed:
    byte_size += sizeof(uint8_t) + sizeof(uint16_t); // cose signed tag
    if (ele.value.tree->size > UINT32_MAX) byte_size += sizeof(uint64_t);
    else if (ele.value.tree->size > UINT16_MAX) byte_size += sizeof(uint32_t);
    else if (ele.value.tree->size > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (ele.value.tree->size >= 24) byte_size += sizeof(uint8_t);
    byte_size += sizeof(uint8_t) /* map type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */ + ele.value.tree->byte_size;
    break;
  case np_treeval_type_cwt:
    byte_size += sizeof(uint8_t) + sizeof(uint16_t); // cwt tag
    if (ele.value.tree->size > UINT32_MAX) byte_size += sizeof(uint64_t);
    else if (ele.value.tree->size > UINT16_MAX) byte_size += sizeof(uint32_t);
    else if (ele.value.tree->size > UINT8_MAX) byte_size += sizeof(uint16_t);
    else if (ele.value.tree->size >= 24) byte_size += sizeof(uint8_t);
    byte_size += sizeof(uint8_t) /* map type */ + sizeof(uint8_t) +
                 sizeof(uint16_t) /* tag */ + ele.value.tree->byte_size;
    break;

#endif // NP_USE_QCBOR

  default:
    //    log_msg(LOG_ERROR, NULL, "unsupported length calculation for value /
    //    type
    //    %"PRIu8"", ele.type );
    break;
  }

  return byte_size;
}
