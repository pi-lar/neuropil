//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <criterion/criterion.h>

#include "neuropil_log.h"

#include "util/np_event.h"

#include "np_evloop.h"
#include "np_log.h"
#include "np_util.h"

TestSuite(np_uuid_t);

Test(np_uuid_t,
     _uuid_create,
     .description = "test the creation of unique uuid's") {
  char *uuid[999];
  char  subject[] = "this.is.a.test";

  for (int i = 0; i < 999; i++) {
    uuid[i] = np_uuid_create(subject, i, NULL);

    for (int j = 0; j < i; j++) {
      cr_expect(0 != memcmp(uuid[i], uuid[j], NP_UUID_BYTES),
                "expect the uuid to be unique");
    }
  }
}

Test(np_uuid_t,
     _uuid_np_tree,
     .description = "test the storage of unique uuid's in a np_tree") {

  uint32_t uuid_values[1000];
  char    *uuid[1000];
  char     subject[] = "this.is.a.test";

  np_tree_t *uuid_tree = np_tree_create();

  // test insert of elements
  for (int i = 0; i < 1000; i++) {
    uuid[i]        = np_uuid_create(subject, i, NULL);
    uuid_values[i] = rand();
    np_tree_insert_uuid(uuid_tree, uuid[i], np_treeval_new_ul(uuid_values[i]));
  }
  cr_expect(uuid_tree->size == 1000, "expect the tree to have 999 elements");

  // test finding of elements
  for (int i = 0; i < 1000; i++) {
    np_tree_elem_t *elem = np_tree_find_uuid(uuid_tree, uuid[i]);
    cr_expect(elem != NULL, "expect the element to be part of the np_tree");
    cr_expect(elem->val.value.ul == uuid_values[i],
              "expect the value to be the ones stored");
  }
  cr_expect(uuid_tree->size == 1000, "expect the tree to have 999 elements");

  // test replace of elements
  for (int i = 0; i < 1000; i++) {
    uint32_t old   = uuid_values[i];
    uuid_values[i] = rand();
    np_tree_replace_uuid(uuid_tree, uuid[i], np_treeval_new_ul(uuid_values[i]));
    np_tree_elem_t *elem = np_tree_find_uuid(uuid_tree, uuid[i]);
    cr_expect(elem != NULL, "expect the element to be part of the np_tree");
    cr_expect(elem->val.value.ul == uuid_values[i],
              "expect the value to be the ones stored");
    cr_expect(elem->val.value.ul != old, "expect the value to be different ");
  }
  cr_expect(uuid_tree->size == 1000, "expect the tree to have 999 elements");

  // test delete of elements
  for (int i = 999; i >= 0; i--) {
    np_tree_del_uuid(uuid_tree, uuid[i]);
    np_tree_elem_t *elem = np_tree_find_uuid(uuid_tree, uuid[i]);
    cr_expect(elem == NULL, "expect the element to be removed");
  }
  cr_expect(uuid_tree->size == 0, "expect the tree to have no elements");
}
