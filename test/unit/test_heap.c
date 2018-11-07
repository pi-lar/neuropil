//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>

#include "np_heap.h"

#include "../test_macros.c"


bool int_compare(int new_ele, int j) {

    return new_ele < j;
} 

uint16_t int_binheap_get_priority(int ele) {	
    return ele;
}

NP_BINHEAP_GENERATE_PROTOTYPES(int)

NP_BINHEAP_GENERATE_IMPLEMENTATION(int)

TestSuite(np_heap);

Test(np_heap, _np_heap_order, .description = "test the heap order")
{
    int tmp;
    np_pheap_t(int, int_heap);
    pheap_init(int, int_heap,20);

    pheap_insert(int, int_heap, -1);
    pheap_insert(int, int_heap, 0);
    pheap_insert(int, int_heap, 1);

    cr_assert(-1 == (tmp =pheap_first(int, int_heap)),  "Expected -1 but got %d", tmp);
    cr_assert(-1 == (tmp = pheap_head(int, int_heap)),  "Expected -1 but got %d", tmp);
    cr_assert( 0 == (tmp = pheap_first(int, int_heap)), "Expected  0 but got %d", tmp);
    cr_assert( 0 == (tmp = pheap_head(int, int_heap)),  "Expected  0 but got %d", tmp);
    cr_assert( 1 == (tmp = pheap_first(int, int_heap)), "Expected  1 but got %d", tmp);
    cr_assert( 1 == (tmp = pheap_head(int, int_heap)),  "Expected  1 but got %d", tmp);

    pheap_insert(int, int_heap, -1);
    pheap_insert(int, int_heap, 0);
    pheap_insert(int, int_heap, 1);
    pheap_insert(int, int_heap, 0);

    cr_assert(-1 == (tmp = pheap_first(int, int_heap)), "Expected -1 but got %d", tmp);
    cr_assert(-1 == (tmp = pheap_head(int, int_heap)),  "Expected -1 but got %d", tmp);
    cr_assert( 0 == (tmp = pheap_first(int, int_heap)), "Expected  0 but got %d", tmp);
    cr_assert( 0 == (tmp = pheap_head(int, int_heap)),  "Expected  0 but got %d", tmp);
    cr_assert( 0 == (tmp = pheap_first(int, int_heap)), "Expected  0 but got %d", tmp);
    cr_assert( 0 == (tmp = pheap_head(int, int_heap)),  "Expected  0 but got %d", tmp);
    cr_assert( 1 == (tmp = pheap_first(int, int_heap)), "Expected  1 but got %d", tmp);
    cr_assert( 1 == (tmp = pheap_head(int, int_heap)),  "Expected  1 but got %d", tmp);

    pheap_free(int, int_heap);
}