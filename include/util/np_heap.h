//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project

#ifndef _NP_HEAP_H_
#define _NP_HEAP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/* define some macros */
#define HEAP_LEFT(x)   (2 * x)                /* left child of a node     */
#define HEAP_RIGHT(x)  ((2 * x) + 1)          /* right child of a node    */
#define HEAP_PARENT(x) ((1 == x) ? 1 : x / 2) /* parent of a node         */
#define HEAP_SWAP(TYPE, t, x, y)                                               \
  {                                                                            \
    TYPE##_binheap_node_t t = x;                                               \
    x                       = y;                                               \
    y                       = t;                                               \
  }

#define np_pheap_t(TYPE, NAME) TYPE##_binheap_t *NAME

#define pheap_init(TYPE, heap, size)    heap = TYPE##_binheap_init(size)
#define pheap_insert(TYPE, heap, value) TYPE##_binheap_insert(heap, value)
#define pheap_remove(TYPE, heap, idx)   TYPE##_binheap_remove(heap, idx)
#define pheap_find(TYPE, heap, id)      TYPE##_binheap_find(heap, id)
#define pheap_head(TYPE, heap)          TYPE##_binheap_head(heap)
#define pheap_is_empty(TYPE, heap)      TYPE##_binheap_is_empty(heap)
#define pheap_first(TYPE, heap)         TYPE##_binheap_first(heap)
#define pheap_clear(TYPE, heap)         TYPE##_binheap_clear(heap)
#define pheap_free(TYPE, heap)          TYPE##_binheap_free(heap)

/*
 * define a structure representing an individual node in the heap, and make it a
 * valid type for convenience define a structure representing the heap, and make
 * it a valid type for convenience function prototypes for functions which
 * operate on a binary heap function prototypes for helper functions
 */
#define NP_BINHEAP_GENERATE_PROTOTYPES(TYPE)                                     \
  typedef struct TYPE##_binheap_node_s TYPE##_binheap_node_t;                    \
  struct TYPE##_binheap_node_s {                                                 \
    uint16_t id;                                                                 \
    size_t   priority;                                                           \
    bool     sentinel;                                                           \
    TYPE     data;                                                               \
  };                                                                             \
  typedef struct TYPE##_binheap_s TYPE##_binheap_t;                              \
  struct TYPE##_binheap_s {                                                      \
    uint16_t               count;                                                \
    uint16_t               size;                                                 \
    TYPE##_binheap_node_t *elements;                                             \
  };                                                                             \
  TYPE##_binheap_t *TYPE##_binheap_init(uint16_t max_nodes);                     \
  void              TYPE##_binheap_free(TYPE##_binheap_t *heap);                 \
  void              TYPE##_binheap_clear(TYPE##_binheap_t *heap);                \
  void              TYPE##_binheap_insert(TYPE##_binheap_t *heap, TYPE element); \
  uint16_t          TYPE##_binheap_find(TYPE##_binheap_t *heap, uint16_t id);    \
  TYPE              TYPE##_binheap_remove(TYPE##_binheap_t *heap, uint16_t i);   \
  TYPE              TYPE##_binheap_first(TYPE##_binheap_t *heap);                \
  bool              TYPE##_binheap_is_empty(TYPE##_binheap_t *heap);             \
  TYPE              TYPE##_binheap_head(TYPE##_binheap_t *heap);                 \
  void              TYPE##_binheap_increase_idx_priority(TYPE##_binheap_t *heap, \
                                            uint16_t          i);            \
  void              TYPE##_binheapify(TYPE##_binheap_t *heap, uint16_t i);       \
  bool              TYPE##_binheap_compare_priority(TYPE##_binheap_node_t *i,    \
                                       TYPE##_binheap_node_t *j);   \
  extern bool       TYPE##_compare(TYPE i, TYPE j);                              \
  extern size_t     TYPE##_binheap_get_priority(TYPE element);                   \
  extern uint16_t   TYPE##_binheap_get_id(TYPE element);

/*
 * functions take a heap rooted at the given index and make sure
 * that is conforms to the heap critera. Adapted from Introduction to
 * Algorithms (Cormen, Leiserson, Rivest 1990) page 143 and following
 */
#define NP_BINHEAP_GENERATE_IMPLEMENTATION(TYPE)                               \
  void TYPE##_binheapify(TYPE##_binheap_t *heap, uint16_t i) {                 \
    uint16_t l = HEAP_LEFT(i);                                                 \
    uint16_t r = HEAP_RIGHT(i);                                                \
    uint16_t largest =                                                         \
        ((l <= heap->count &&                                                  \
          TYPE##_compare(heap->elements[l].data, heap->elements[i].data))      \
             ? l                                                               \
             : i);                                                             \
    if (r <= heap->count &&                                                    \
        TYPE##_compare(heap->elements[r].data, heap->elements[largest].data))  \
      largest = r;                                                             \
    if (largest != i) {                                                        \
      HEAP_SWAP(TYPE, tmp, heap->elements[i], heap->elements[largest]);        \
      TYPE##_binheapify(heap, largest);                                        \
    }                                                                          \
  }                                                                            \
  TYPE TYPE##_binheap_first(TYPE##_binheap_t *heap) {                          \
    assert(heap->count > 0);                                                   \
    assert(heap->elements[1].sentinel == false);                               \
    return (heap->elements[1].data);                                           \
  }                                                                            \
  bool TYPE##_binheap_is_empty(TYPE##_binheap_t *heap) {                       \
    return (heap->count == 0);                                                 \
  }                                                                            \
  TYPE TYPE##_binheap_head(TYPE##_binheap_t *heap) {                           \
    assert(heap->count > 0);                                                   \
    assert(heap->elements[1].sentinel == false);                               \
    TYPE ret                    = heap->elements[1].data;                      \
    heap->elements[1]           = heap->elements[heap->count];                 \
    heap->elements[heap->count] = heap->elements[0];                           \
    heap->count--;                                                             \
    TYPE##_binheapify(heap, 1);                                                \
    return (ret);                                                              \
  }                                                                            \
  void TYPE##_binheap_insert(TYPE##_binheap_t *heap, TYPE element) {           \
    assert(heap->count < heap->size);                                          \
    uint16_t i = ++(heap->count);                                              \
    ASSERT(i != 0, "i = %d", i);                                               \
    heap->elements[i].data     = element;                                      \
    heap->elements[i].sentinel = false;                                        \
    heap->elements[i].priority = TYPE##_binheap_get_priority(element);         \
    while (i > 1 && TYPE##_compare(heap->elements[i].data,                     \
                                   heap->elements[HEAP_PARENT(i)].data)) {     \
      HEAP_SWAP(TYPE, tmp, heap->elements[i], heap->elements[HEAP_PARENT(i)]); \
      i = HEAP_PARENT(i);                                                      \
    }                                                                          \
  }                                                                            \
  TYPE TYPE##_binheap_remove(TYPE##_binheap_t *heap, uint16_t i) {             \
    TYPE deleted = {0};                                                        \
    if (i <= heap->count && i >= 1) {                                          \
      deleted = heap->elements[i].data;                                        \
      HEAP_SWAP(TYPE, tmp, heap->elements[i], heap->elements[heap->count]);    \
      heap->count--;                                                           \
      TYPE##_binheapify(heap, i);                                              \
    }                                                                          \
    return (deleted);                                                          \
  }                                                                            \
  void TYPE##_binheap_increase_idx_priority(TYPE##_binheap_t *heap,            \
                                            uint16_t          i) {                      \
    assert(i <= heap->count && i >= 1);                                        \
    heap->elements[i].priority =                                               \
        TYPE##_binheap_get_priority(heap->elements[i].data);                   \
    HEAP_SWAP(TYPE, tmp, heap->elements[i], heap->elements[(heap->count)]);    \
    TYPE##_binheapify(heap, i);                                                \
  }                                                                            \
  TYPE##_binheap_t *TYPE##_binheap_init(uint16_t max_nodes) {                  \
    TYPE##_binheap_t *heap = malloc(sizeof(TYPE##_binheap_t));                 \
    heap->count            = 0;                                                \
    heap->size             = max_nodes;                                        \
    heap->elements =                                                           \
        (TYPE##_binheap_node_t *)calloc(heap->size + 1,                        \
                                        sizeof(TYPE##_binheap_node_t));        \
    heap->elements[0].sentinel = true;                                         \
    return (heap);                                                             \
  }                                                                            \
  void TYPE##_binheap_free(TYPE##_binheap_t *heap) {                           \
    free(heap->elements);                                                      \
    free(heap);                                                                \
  }                                                                            \
  void TYPE##_binheap_clear(TYPE##_binheap_t *heap) {                          \
    memset(heap->elements, 0, heap->size);                                     \
    heap->elements[0].sentinel = true;                                         \
    heap->count                = 0;                                            \
  }                                                                            \
  bool TYPE##_binheap_compare_priority(TYPE##_binheap_node_t *i,               \
                                       TYPE##_binheap_node_t *j) {             \
    if (i->priority < j->priority) return (true);                              \
    else return (false);                                                       \
  }                                                                            \
  uint16_t TYPE##_binheap_find(TYPE##_binheap_t *heap, uint16_t id) {          \
    for (uint16_t i = 1; i <= heap->count; i++)                                \
      if (id == heap->elements[i].id) return (i);                              \
    return (0);                                                                \
  }

#ifdef __cplusplus
}
#endif

#endif // _NP_HEAP_H_
