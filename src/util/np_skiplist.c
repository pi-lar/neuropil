//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

// implementation is based on:
// http://opendatastructures.org/versions/edition-0.1e/ods-java/4_2_SkiplistSSet_Efficient_.html
// but modified to work for c99 and a shortcut when next elements have already
// been compared

#include "util/np_skiplist.h"

/**
 * Implementation of a skip list
 */

uint8_t __pick_height(uint32_t elements) {
  uint8_t max_height = 1;
  while (elements > 0) {
    max_height++;
    elements >>= 1;
  }

  int32_t  z = random();
  uint32_t k = 0;
  int32_t  m = 1;
  while ((z & m) != 0) {
    k++;
    m <<= 1;
  }
  return (k > max_height) ? max_height : k;
}

void np_skiplist_print(const np_skiplist_t *skiplist) {
  const np_skiplist_node_t *u = &skiplist->root;
  uint8_t                   i = 0;

  fprintf(stdout, "\n                      :");
  for (uint8_t j = 0; j < u->_height; j++) {
    fprintf(stdout, " %14d - ", j);
  }
  fprintf(stdout, "\n");
  while (i < skiplist->_num_elements) {
    fprintf(stdout, "%5d (%14p):", i, u);
    for (uint8_t j = 0; j < u->_height; j++) {
      fprintf(stdout, " %14p - ", u->_nodes[j]);
    }
    fprintf(stdout, "\n");
    u = u->_nodes[0];
    i++;
  }
}

void np_skiplist_init(np_skiplist_t        *skiplist,
                      compare_skiplist_item compare_func,
                      hash_skiplist_item    hash_func) {
  skiplist->_num_elements = 0;

  skiplist->root._height  = 0;
  skiplist->root.item     = NULL;
  skiplist->root.sentinel = true;
  skiplist->root._nodes   = NULL;

  skiplist->compare_func = compare_func;
  skiplist->hash_func    = hash_func;
  // skiplist->root._nodes = calloc(sizeof(np_skiplist_node_t));
  // skiplist->root._spinlock = malloc(sizeof(np_spinlock_t));
}

size_t np_skiplist_size(np_skiplist_t *skiplist) {
  return skiplist->_num_elements;
}

void np_skiplist_destroy(np_skiplist_t *skiplist) {
  np_skiplist_node_t *u   = &skiplist->root;
  np_skiplist_node_t *tmp = NULL;

  // np_skiplist_print(skiplist);

  while (skiplist->_num_elements > 0) {
    tmp = u;
    u   = u->_nodes[0];

    if (false == tmp->sentinel) {
      skiplist->_num_elements--;
      free(tmp->_nodes);
      free(tmp);
    }
  }

  free(skiplist->root._nodes);
}

bool np_skiplist_remove(np_skiplist_t *skiplist, const void *item) {
  bool                removed   = false;
  np_skiplist_node_t *sentinel  = &skiplist->root;
  np_skiplist_node_t *u         = sentinel;
  np_skiplist_node_t *to_remove = NULL;
  int8_t              r         = sentinel->_height;

  int8_t comp = -1;
  while (r > 0) {
    while (NULL != u->_nodes && NULL != u->_nodes[r - 1] &&
           0 > (comp = skiplist->compare_func(u->_nodes[r - 1]->item, item)))
      u = u->_nodes[r - 1];

    do {
      if (NULL != u->_nodes && NULL != u->_nodes[r - 1] && comp == 0) {
        to_remove        = u->_nodes[r - 1];
        u->_nodes[r - 1] = u->_nodes[r - 1]->_nodes[r - 1];
        removed          = true;

        if (u->sentinel && NULL != u->_nodes &&
            NULL == u->_nodes[r - 1]) { // skiplist height has gone down
          sentinel->_nodes[r - 1] = NULL;
          // do not realloc the sentinel node array to avoid memory
          // fragmentation sentinel->_height--; sentinel->_nodes =
          // realloc(sentinel->_nodes,
          // (sentinel->_height)*sizeof(np_skiplist_node_t*));
        }
      }

      // shortcut if the pointer to the next element is the same as in the level
      // above then there is no need to compare again
      r--;
    } while (r > 0 && u->_nodes[r - 1] == u->_nodes[r]);
  }

  if (removed) {
    free(to_remove->_nodes);
    free(to_remove);
    skiplist->_num_elements--;
  }
  // np_skiplist_print(skiplist);
  return removed;
}

bool np_skiplist_find(const np_skiplist_t *skiplist, void **item) {
  bool                      found    = false;
  const np_skiplist_node_t *sentinel = &skiplist->root;
  const np_skiplist_node_t *u        = sentinel;
  int8_t                    r        = sentinel->_height;

  // np_skiplist_print(skiplist);

  int8_t comp = -1;
  while (r > 0) {
    while (NULL != u->_nodes && NULL != u->_nodes[r - 1] &&
           0 > (comp = skiplist->compare_func(u->_nodes[r - 1]->item, *item))) {
      u = u->_nodes[r - 1];
    }
    // shortcut if the pointer to the next element is the same as in the level
    // above then there is no need to compare again
    do {
      r--;
    } while (r > 0 && u->_nodes[r - 1] == u->_nodes[r]);
  }

  if (0 <= comp && NULL != u && NULL != u->_nodes) {
    if (NULL != u->_nodes[0]) *item = u->_nodes[0]->item;
    else *item = u->item;

    if (comp == 0) found = true;
  }
  return found;
}

bool np_skiplist_add(np_skiplist_t *skiplist, void *item) {
  np_skiplist_node_t *sentinel = &skiplist->root;
  np_skiplist_node_t *u        = sentinel;

  uint8_t k =
      __pick_height(skiplist->_num_elements) + 1; // WARNING: height == 0?

  int8_t r = sentinel->_height;

  uint8_t             stack_size = (k > r) ? k : r;
  np_skiplist_node_t *stack[stack_size];

  for (uint8_t i = 0; i < stack_size; i++)
    stack[i] = NULL;
  for (uint8_t i = 0; i < r; i++)
    stack[i] = sentinel->_nodes[i];

  while (r > 0) {
    int8_t comp = 0;
    while (NULL != u->_nodes && NULL != u->_nodes[r - 1] &&
           0 > (comp = skiplist->compare_func(u->_nodes[r - 1]->item, item))) {
      u = u->_nodes[r - 1];
    }

    if (NULL != u->_nodes && NULL != u->_nodes[r - 1] && comp == 0) {
      return false; // element already exists
    }

    do {
      stack[r - 1] = u; // going down, store u
      r--;
    } while (r > 0 && u->_nodes[r - 1] == u->_nodes[r]);
  }

  np_skiplist_node_t *new_skipnode = malloc(sizeof(np_skiplist_node_t));
  new_skipnode->_height            = k;
  new_skipnode->sentinel           = false;
  new_skipnode->item               = item;
  new_skipnode->_nodes =
      (np_skiplist_node_t **)malloc(k * sizeof(np_skiplist_node_t *));
  for (uint8_t i = 0; i < new_skipnode->_height; i++)
    new_skipnode->_nodes[i] = NULL;

  // increasing height of skiplist
  if (sentinel->_height < new_skipnode->_height) {
    sentinel->_nodes =
        (np_skiplist_node_t **)realloc(sentinel->_nodes,
                                       k * sizeof(np_skiplist_node_t *));
    for (uint8_t i = sentinel->_height; i < new_skipnode->_height; i++) {
      sentinel->_nodes[i]      = NULL;
      stack[sentinel->_height] = sentinel;
      sentinel->_height++;
    }
  }

  for (int i = 1; i <= new_skipnode->_height;
       i++) { // set flink pointer values for new node
    if (NULL != stack[i - 1]->_nodes)
      new_skipnode->_nodes[i - 1] = stack[i - 1]->_nodes[i - 1];
    else new_skipnode->_nodes[i - 1] = NULL;
    // correct flink pointer of previous node
    stack[i - 1]->_nodes[i - 1] = new_skipnode;
  }
  skiplist->_num_elements++;

  // np_skiplist_print(skiplist);

  return true;
}

void np_skiplist_map(const np_skiplist_t *skiplist, np_map_reduce_t *mr) {
  const np_skiplist_node_t *sentinel = &skiplist->root;
  const np_skiplist_node_t *u        = sentinel;
  int8_t                    r        = sentinel->_height;

  // np_skiplist_print(skiplist);
  int8_t comp = 0;
  while (r > 0) {
    while (NULL != u->_nodes && NULL != u->_nodes[r - 1] &&
           0 > mr->cmp(mr, u->_nodes[r - 1]->item)) {
      u = u->_nodes[r - 1];
    }
    // shortcut if the pointer to the next element is the same as in the level
    // above then there is no need to compare again
    do {
      r--;
    } while (r > 0 && u->_nodes[r - 1] == u->_nodes[r]);
  }

  bool _continue = mr->map(mr, u->item);
  while (_continue && NULL != u && NULL != u->_nodes) {
    if (u->_nodes[0] == NULL || u->_nodes[0]->item == NULL) _continue = false;
    else _continue = mr->map(mr, u->_nodes[0]->item);
    u = u->_nodes[0];
  }
}

void np_skiplist_reduce(np_map_reduce_t *mr) {
  sll_iterator(void_ptr) iterator = sll_first(mr->map_result);
  while (iterator != NULL) {
    mr->reduce(mr, iterator->val);
    sll_next(iterator);
  }
}
