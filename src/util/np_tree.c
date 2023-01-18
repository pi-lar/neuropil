//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project
/* Revision 1.2.  Jim Plank */

/* Original code by Jim Plank (plank@cs.utk.edu) */
/* modified for THINK C 6.0 for Macintosh by Chris Bartley */
/* modified for neuropil 2015 pi-lar GmbH Stephan Schwichtenberg */

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sodium.h"

#include "neuropil_log.h"

#include "util/np_serialization.h"
#include "util/np_treeval.h"

#include "np_dhkey.h"
#include "np_log.h"
#include "np_util.h"

RB_GENERATE(np_tree_s, np_tree_elem_s, link, _np_tree_elem_cmp);

// RB_GENERATE_STATIC(np_str_jtree, np_tree_elem_s, link, _np_tree_elem_cmp);
// RB_GENERATE_STATIC(np_int_jtree, np_tree_elem_s, link, _np_tree_elem_cmp);
// RB_GENERATE_STATIC(np_dbl_jtree, np_tree_elem_s, link, _np_tree_elem_cmp);
// RB_GENERATE_STATIC(np_ulong_jtree, np_tree_elem_s, link, _np_tree_elem_cmp);

/*
        Allocates space for a new tree structure.

        :param:in_place: disables the copy of values behaviour for this tree
   (and subtrees)
*/
np_tree_t *np_tree_create() {
  np_tree_t *new_tree = (np_tree_t *)malloc(sizeof(np_tree_t));
  CHECK_MALLOC(new_tree);

  memset(&new_tree->attr, 0, sizeof(np_tree_conf_t));

  new_tree->size      = 0;
  new_tree->rbh_root  = NULL;
  new_tree->byte_size = 0;

  return new_tree;
}

int16_t _np_tree_elem_cmp(const np_tree_elem_t *j1, const np_tree_elem_t *j2) {
  log_trace_msg(LOG_TRACE,
                "start: int16_t _np_tree_elem_cmp(const np_tree_elem_t* j1, "
                "const np_tree_elem_t* j2){");
  assert(NULL != j1);
  assert(NULL != j2);

  np_treeval_t jv1 = j1->key;
  np_treeval_t jv2 = j2->key;

  if (jv1.type == jv2.type) {
    if (jv1.type == np_treeval_type_char_ptr) {
      return strncmp(jv1.value.s, jv2.value.s, strlen(jv1.value.s) + 1);
    } else if (jv1.type == np_treeval_type_double) {
      // log_debug_msg(LOG_DEBUG, "comparing %f - %f = %d",
      // 		jv1.value.d, jv2.value.d, (int16_t)
      // (jv1.value.d-jv2.value.d) );
      double res = jv1.value.d - jv2.value.d;
      if (res < 0) return -1;
      if (res > 0) return 1;
      return 0;
    } else if (jv1.type == np_treeval_type_unsigned_long) {
      return (int16_t)(jv1.value.ul - jv2.value.ul);
    } else if (jv1.type == np_treeval_type_int) {
      return (int16_t)(jv1.value.i - jv2.value.i);
    } else if (jv1.type == np_treeval_type_dhkey) {
      return (int16_t)_np_dhkey_cmp(&jv1.value.dhkey, &jv2.value.dhkey);
    }
  }
  return (((int)jv1.type - (int)jv2.type) > 0);
};

np_tree_elem_t *
np_tree_find_gte_str(np_tree_t *n, const char *key, uint8_t *fnd) {
  assert(n != NULL);
  assert(key != NULL);

  np_tree_elem_t *result = NULL;

  np_treeval_t   search_key  = {.type    = np_treeval_type_char_ptr,
                                .value.s = (char *)key};
  np_tree_elem_t search_elem = {.key = search_key};

  result = RB_NFIND(np_tree_s, n, &search_elem);
  if (NULL != result && 0 == strncmp(result->key.value.s, key, strlen(key))) {
    *fnd = 1;
  } else {
    *fnd = 0;
  }
  return (result);
}

np_tree_elem_t *np_tree_find_str(np_tree_t *n, const char *key) {
  assert(NULL != n);
  assert(NULL != key);

  np_tree_elem_t *ret = NULL;
  if (ret == NULL) {
    np_treeval_t   search_key  = {.type    = np_treeval_type_char_ptr,
                                  .value.s = (char *)key};
    np_tree_elem_t search_elem = {.key = search_key};
    ret                        = RB_FIND(np_tree_s, n, &search_elem);
  }
  return ret;
}

np_tree_elem_t *np_tree_find_gte_int(np_tree_t *n, int16_t ikey, uint8_t *fnd) {
  assert(n != NULL);

  np_tree_elem_t *result = NULL;

  np_treeval_t   search_key  = {.type = np_treeval_type_int, .value.i = ikey};
  np_tree_elem_t search_elem = {.key = search_key};

  result = RB_NFIND(np_tree_s, n, &search_elem);
  if (NULL != result && result->key.value.i == ikey) {
    *fnd = 1;
  } else {
    *fnd = 0;
  }

  return (result);
}

np_tree_elem_t *np_tree_find_int(np_tree_t *n, int16_t key) {
  np_treeval_t   search_key  = {.type = np_treeval_type_int, .value.i = key};
  np_tree_elem_t search_elem = {.key = search_key};
  return (RB_FIND(np_tree_s, n, &search_elem));
}

np_tree_elem_t *np_tree_find_dhkey(np_tree_t *n, np_dhkey_t key) {
  np_treeval_t search_key = {.type = np_treeval_type_dhkey, .value.dhkey = key};
  np_tree_elem_t search_elem = {.key = search_key};
  return (RB_FIND(np_tree_s, n, &search_elem));
}

np_tree_elem_t *
np_tree_find_gte_ulong(np_tree_t *n, uint32_t ulkey, uint8_t *fnd) {
  assert(n != NULL);

  np_tree_elem_t *result = NULL;

  np_treeval_t   search_key  = {.type     = np_treeval_type_unsigned_long,
                                .value.ul = ulkey};
  np_tree_elem_t search_elem = {.key = search_key};

  result = RB_NFIND(np_tree_s, n, &search_elem);
  if (NULL != result && result->key.value.ul == ulkey) {
    *fnd = 1;
  } else {
    *fnd = 0;
  }

  return (result);
}

np_tree_elem_t *np_tree_find_ulong(np_tree_t *n, uint32_t ulkey) {
  np_treeval_t   search_key  = {.type     = np_treeval_type_unsigned_long,
                                .value.ul = ulkey};
  np_tree_elem_t search_elem = {.key = search_key};
  return (RB_FIND(np_tree_s, n, &search_elem));
}

np_tree_elem_t *np_tree_find_gte_dbl(np_tree_t *n, double dkey, uint8_t *fnd) {
  assert(n != NULL);

  np_tree_elem_t *result = NULL;

  np_treeval_t   search_key = {.type = np_treeval_type_double, .value.d = dkey};
  np_tree_elem_t search_elem = {.key = search_key};

  result = RB_NFIND(np_tree_s, n, &search_elem);
  if (NULL != result && result->key.value.d == dkey) {
    *fnd = 1;
  } else {
    *fnd = 0;
  }

  return (result);
}

np_tree_elem_t *np_tree_find_dbl(np_tree_t *n, double dkey) {
  np_treeval_t   search_key = {.type = np_treeval_type_double, .value.d = dkey};
  np_tree_elem_t search_elem = {.key = search_key};
  return (RB_FIND(np_tree_s, n, &search_elem));
}

void _np_tree_cleanup_treeval(np_tree_t *tree, np_treeval_t toclean) {
  if (tree->attr.in_place == false) {
    if (toclean.type == np_treeval_type_char_ptr) free(toclean.value.s);
    if (toclean.type == np_treeval_type_bin) free(toclean.value.bin);
  }
  if (toclean.type == np_treeval_type_jrb_tree) {
    np_tree_free(toclean.value.tree);
  }
}

void np_tree_del_element(np_tree_t *tree, np_tree_elem_t *to_delete) {
  if (to_delete != NULL) {
    RB_REMOVE(np_tree_s, tree, to_delete);

    tree->byte_size -= np_tree_element_get_byte_size(to_delete);
    tree->size--;

    _np_tree_cleanup_treeval(tree, to_delete->key);
    _np_tree_cleanup_treeval(tree, to_delete->val);

    free(to_delete);
  }
}

void __np_tree_immutable_check(np_tree_t *tree) {
  assert(tree->attr.immutable == false &&
         "Tree is not in a state of modification");
}

void np_tree_del_str(np_tree_t *tree, const char *key) {
  __np_tree_immutable_check(tree);
  np_tree_del_element(tree, np_tree_find_str(tree, key));
}

void np_tree_del_int(np_tree_t *tree, const int16_t key) {
  __np_tree_immutable_check(tree);
  np_tree_del_element(tree, np_tree_find_int(tree, key));
}

void np_tree_del_dhkey(np_tree_t *tree, const np_dhkey_t key) {
  __np_tree_immutable_check(tree);
  np_tree_del_element(tree, np_tree_find_dhkey(tree, key));
}

void np_tree_del_double(np_tree_t *tree, const double dkey) {
  __np_tree_immutable_check(tree);
  np_tree_del_element(tree, np_tree_find_dbl(tree, dkey));
}

void np_tree_del_ulong(np_tree_t *tree, const uint32_t key) {
  __np_tree_immutable_check(tree);
  np_tree_del_element(tree, np_tree_find_ulong(tree, key));
}

void np_tree_clear(np_tree_t *n) {
  np_tree_elem_t *iter = RB_MIN(np_tree_s, n);

  while (NULL != iter) {
    np_tree_del_element(n, iter);
    iter = RB_MIN(np_tree_s, n);
  }
}

void np_tree_free(np_tree_t *n) {
  if (NULL != n) {
    if (n->size > 0) {
      np_tree_clear(n);
    }
    free(n);
    n = NULL;
  }
}

void _np_tree_replace_all_with_str(np_tree_t   *n,
                                   const char  *key,
                                   np_treeval_t val) {
  log_trace_msg(LOG_TRACE,
                "start: void _np_tree_replace_all_with_str(np_tree_t* n, const "
                "char* key, np_treeval_t val){");
  np_tree_clear(n);
  np_tree_insert_str(n, key, val);
}

size_t np_tree_get_byte_size(np_tree_t *tree) {
  assert(tree != NULL);
  np_treeval_t tree_val = np_treeval_new_tree(tree);
  //  tree->byte_size = np_treeval_get_byte_size(tree_val);
  return np_treeval_get_byte_size(tree_val);
}

size_t np_tree_element_get_byte_size(np_tree_elem_t *node) {
  log_trace_msg(
      LOG_TRACE,
      "start: uint32_t np_tree_element_get_byte_size(np_tree_elem_t* node){");
  assert(node != NULL);

  size_t byte_size =
      np_treeval_get_byte_size(node->key) + np_treeval_get_byte_size(node->val);

  return byte_size;
}

void np_tree_insert_element(np_tree_t *tree, np_tree_elem_t *ele) {
  __np_tree_immutable_check(tree);
  RB_INSERT(np_tree_s, tree, ele);
  tree->size++;
  tree->byte_size += np_tree_element_get_byte_size(ele);
}

void np_tree_insert_str(np_tree_t *tree, const char *key, np_treeval_t val) {
  assert(tree != NULL);
  assert(key != NULL);

  np_tree_elem_t *found = np_tree_find_str(tree, key);
  if (found == NULL) { // insert new value
    found = (np_tree_elem_t *)malloc(sizeof(np_tree_elem_t));
    CHECK_MALLOC(found);

    if (tree->attr.in_place == true) {
      found->key.value.s = (char *)key;
    } else {
      found->key.value.s = strndup(key, 255);
    }

    found->key.type = np_treeval_type_char_ptr;
    found->key.size = strnlen(found->key.value.s, 255);

    np_tree_set_treeval(tree, found, val);
    np_tree_insert_element(tree, found);
  }
}

void np_tree_insert_int(np_tree_t *tree, int16_t ikey, np_treeval_t val) {
  assert(tree != NULL);

  np_tree_elem_t *found = np_tree_find_int(tree, ikey);

  if (found == NULL) {
    // insert new value
    found = (np_tree_elem_t *)malloc(sizeof(np_tree_elem_t));
    CHECK_MALLOC(found);

    found->key.value.i = ikey;
    found->key.type    = np_treeval_type_int;
    found->key.size    = sizeof(int16_t);
    np_tree_set_treeval(tree, found, val);
    np_tree_insert_element(tree, found);
  }
}

void np_tree_insert_dhkey(np_tree_t *tree, np_dhkey_t key, np_treeval_t val) {
  assert(tree != NULL);

  np_tree_elem_t *found = np_tree_find_dhkey(tree, key);

  if (found == NULL) {
    // insert new value
    found = (np_tree_elem_t *)malloc(sizeof(np_tree_elem_t));
    CHECK_MALLOC(found);

    found->key.value.dhkey = key;
    found->key.type        = np_treeval_type_dhkey;
    found->key.size        = sizeof(np_dhkey_t);
    np_tree_set_treeval(tree, found, val);
    np_tree_insert_element(tree, found);
  }
}

void np_tree_insert_ulong(np_tree_t *tree, uint32_t ulkey, np_treeval_t val) {
  assert(tree != NULL);

  np_tree_elem_t *found = np_tree_find_ulong(tree, ulkey);

  if (found == NULL) {
    // insert new value
    found = (np_tree_elem_t *)malloc(sizeof(np_tree_elem_t));
    CHECK_MALLOC(found);

    found->key.value.ul = ulkey;
    found->key.type     = np_treeval_type_unsigned_long;
    found->key.size     = sizeof(uint32_t);

    np_tree_set_treeval(tree, found, val);
    np_tree_insert_element(tree, found);
  }
}

void np_tree_insert_dbl(np_tree_t *tree, double dkey, np_treeval_t val) {
  assert(tree != NULL);

  np_tree_elem_t *found = np_tree_find_dbl(tree, dkey);

  if (found == NULL) {
    // insert new value
    found = (np_tree_elem_t *)malloc(sizeof(np_tree_elem_t));
    CHECK_MALLOC(found);

    found->key.value.d = dkey;
    found->key.type    = np_treeval_type_double;
    found->key.size    = sizeof(double);

    np_tree_set_treeval(tree, found, val);
    np_tree_insert_element(tree, found);
  } else {
    // log_msg(LOG_WARNING, "not inserting double key (%f) into jtree", dkey );
  }
}

void np_tree_set_treeval(np_tree_t      *tree,
                         np_tree_elem_t *element,
                         np_treeval_t    val) {

  if (tree->attr.in_place == false) {
    element->val = np_treeval_copy_of_val(val);
  } else {
    // memmove(&element->val, &val, sizeof(np_treeval_t));
    // memset(&element->val, &val, sizeof(np_treeval_t));
    memcpy(&element->val, &val, sizeof(np_treeval_t));
  }
}

void np_tree_replace_treeval(np_tree_t      *tree,
                             np_tree_elem_t *element,
                             np_treeval_t    val) {

  __np_tree_immutable_check(tree);
  // free up memory before replacing
  tree->byte_size -= np_tree_element_get_byte_size(element);

  _np_tree_cleanup_treeval(tree, element->val);
  np_tree_set_treeval(tree, element, val);
  tree->byte_size += np_tree_element_get_byte_size(element);
}

void np_tree_replace_str(np_tree_t *tree, const char *key, np_treeval_t val) {
  assert(tree != NULL);
  assert(key != NULL);

  np_tree_elem_t *found = np_tree_find_str(tree, key);

  if (found == NULL) { // insert new value
    np_tree_insert_str(tree, key, val);
  } else {
    np_tree_replace_treeval(tree, found, val);
  }
}

void np_tree_replace_int(np_tree_t *tree, int16_t ikey, np_treeval_t val) {
  assert(tree != NULL);

  np_tree_elem_t *found = np_tree_find_int(tree, ikey);

  if (found == NULL) { // insert new value
    np_tree_insert_int(tree, ikey, val);
  } else {
    np_tree_replace_treeval(tree, found, val);
  }
}

void np_tree_replace_dhkey(np_tree_t *tree, np_dhkey_t key, np_treeval_t val) {
  assert(tree != NULL);

  np_tree_elem_t *found = np_tree_find_dhkey(tree, key);

  if (found == NULL) { // insert new value
    np_tree_insert_dhkey(tree, key, val);
  } else {
    np_tree_replace_treeval(tree, found, val);
  }
}

void np_tree_replace_ulong(np_tree_t *tree, uint32_t ulkey, np_treeval_t val) {
  assert(tree != NULL);

  np_tree_elem_t *found = np_tree_find_ulong(tree, ulkey);

  if (found == NULL) {
    np_tree_insert_ulong(tree, ulkey, val);
  } else {
    np_tree_replace_treeval(tree, found, val);
  }
}

void np_tree_replace_dbl(np_tree_t *tree, double dkey, np_treeval_t val) {
  assert(tree != NULL);

  np_tree_elem_t *found = np_tree_find_dbl(tree, dkey);

  if (found == NULL) {
    // insert new value
    np_tree_insert_dbl(tree, dkey, val);
  } else {
    np_tree_replace_treeval(tree, found, val);
  }
}

void np_tree_copy(np_tree_t *source, np_tree_t *target) {
  np_tree_elem_t *tmp = NULL;

  assert(source != NULL);
  assert(target != NULL);

  RB_FOREACH (tmp, np_tree_s, source) {
    if (tmp->key.type == np_treeval_type_char_ptr)
      np_tree_insert_str(target, tmp->key.value.s, tmp->val);
    else if (tmp->key.type == np_treeval_type_int)
      np_tree_insert_int(target, tmp->key.value.i, tmp->val);
    else if (tmp->key.type == np_treeval_type_double)
      np_tree_insert_dbl(target, tmp->key.value.d, tmp->val);
    else if (tmp->key.type == np_treeval_type_unsigned_long)
      np_tree_insert_ulong(target, tmp->key.value.ul, tmp->val);
    else if (tmp->key.type == np_treeval_type_dhkey)
      np_tree_insert_dhkey(target, tmp->key.value.dhkey, tmp->val);
  }
}

void np_tree_copy_inplace(np_tree_t *source, np_tree_t *target) {
  np_tree_elem_t *tmp = NULL;

  assert(source != NULL);
  assert(target != NULL);

  RB_FOREACH (tmp, np_tree_s, source) {
    if (tmp->key.type == np_treeval_type_char_ptr)
      np_tree_replace_str(target, tmp->key.value.s, tmp->val);
    else if (tmp->key.type == np_treeval_type_int)
      np_tree_replace_int(target, tmp->key.value.i, tmp->val);
    else if (tmp->key.type == np_treeval_type_double)
      np_tree_replace_dbl(target, tmp->key.value.d, tmp->val);
    else if (tmp->key.type == np_treeval_type_unsigned_long)
      np_tree_replace_ulong(target, tmp->key.value.ul, tmp->val);
    else if (tmp->key.type == np_treeval_type_dhkey)
      np_tree_replace_dhkey(target, tmp->key.value.dhkey, tmp->val);
  }
}

np_tree_t *np_tree_clone(np_tree_t *source) {
  log_trace_msg(LOG_TRACE,
                "start: np_tree_t* np_tree_clone(np_tree_t* source) {");

  np_tree_t *ret = np_tree_create();
  memcpy(&ret->attr, &source->attr, sizeof(np_tree_conf_t));
  ret->attr.in_place  = false;
  bool old            = ret->attr.immutable;
  ret->attr.immutable = false;
  np_tree_copy(source, ret);
  ret->attr.immutable = old;
  return ret;
}

unsigned char *np_tree_get_hash(np_tree_t *self) {
  unsigned char           *hash = calloc(1, crypto_generichash_BYTES);
  crypto_generichash_state gh_state;
  crypto_generichash_init(&gh_state, NULL, 0, crypto_generichash_BYTES);

  if (self != NULL && self->size > 0) {
    np_tree_elem_t *iter_tree = NULL;
    char           *tmp;
    unsigned char  *tmp2;
    bool            free_tmp;
    unsigned char  *ptr;
    RB_FOREACH (iter_tree, np_tree_s, self) {
      tmp = np_treeval_to_str(iter_tree->key, &free_tmp);
      crypto_generichash_update(&gh_state, (unsigned char *)tmp, strlen(tmp));
      if (free_tmp) free(tmp);

      if (iter_tree->val.type == np_treeval_type_jrb_tree) {
        tmp2 = np_tree_get_hash(iter_tree->val.value.tree);
        crypto_generichash_update(&gh_state, tmp2, crypto_generichash_BYTES);
        free(tmp2);
      } else {
        if (/*Pointer types*/
            iter_tree->val.type == np_treeval_type_void ||
            iter_tree->val.type == np_treeval_type_bin ||
            iter_tree->val.type == np_treeval_type_char_ptr ||
            iter_tree->val.type == np_treeval_type_char_array_8 ||
            iter_tree->val.type == np_treeval_type_float_array_2 ||
            iter_tree->val.type == np_treeval_type_uint_array_2 ||
            iter_tree->val.type == np_treeval_type_npobj ||
            iter_tree->val.type == np_treeval_type_unsigned_char_array_8) {
          ptr = iter_tree->val.value.bin;
        } else {
          ptr = &iter_tree->val.value.uc;
        }
        crypto_generichash_update(&gh_state, ptr, iter_tree->val.size);
      }
    }
  }

  crypto_generichash_final(&gh_state, hash, crypto_generichash_BYTES);
  return hash;
}

bool np_tree_check_field(np_state_t      *context,
                         np_tree_t       *tree,
                         const char      *field_name,
                         const char      *_NP_MSG_HEADER_SUBJECT,
                         np_tree_elem_t **buffer) {
  bool            ret = true;
  np_tree_elem_t *tmp;
  if (NULL == (tmp = np_tree_find_str(tree, field_name))) {
    ret = false;
    if (NULL != (tmp = np_tree_find_str(tree, _NP_MSG_HEADER_SUBJECT))) {
      log_msg(LOG_WARNING,
              "Missing field \"%s\" in message for \"%s\"",
              field_name,
              np_treeval_to_str(tmp->val, NULL));
    } else {
      log_msg(LOG_WARNING, "Missing field \"%s\" in tree", field_name);
    }
  }
  if (buffer != NULL) *buffer = tmp;
  return ret;
}
