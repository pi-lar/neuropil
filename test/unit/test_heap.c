//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>

#include "np_heap.h"
#include "np_jobqueue.h"
#include "np_types.h"

#include "../test_macros.c"


bool int_compare(int new_ele, int j) {

    return new_ele < j;
} 

uint16_t int_binheap_get_priority(int ele) {	
    return ele;
}

NP_BINHEAP_GENERATE_PROTOTYPES(int);

NP_BINHEAP_GENERATE_IMPLEMENTATION(int);

TestSuite(np_heap);

Test(np_heap, _np_heap_order, .description = "test the heap order")
{
    int tmp;
    np_pheap_t(int, int_heap);
    pheap_init(int, int_heap,20);

    pheap_insert(int, int_heap, -1);
    pheap_insert(int, int_heap, 0);
    pheap_insert(int, int_heap, 1);

    cr_assert(-1 == (tmp = pheap_first(int, int_heap)),  "Expected -1 but got %d", tmp);
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

// already defined in np_jobqueue.h
/*
	bool np_job_t_compare(np_job_t new_ele, np_job_t j) {
		return (new_ele.priority < j.priority);
	}
	uint16_t np_job_t_binheap_get_priority(np_job_t ele) {
		return ele.priority;
	}
	NP_BINHEAP_GENERATE_PROTOTYPES(np_job_t);
	NP_BINHEAP_GENERATE_IMPLEMENTATION(np_job_t);
*/

Test(np_heap, _np_heap_job_t, .description = "test the heap of a np_job_t")
{
    np_job_t tmp;

    np_pheap_t(np_job_t, job_heap);
    pheap_init(np_job_t, job_heap, 128);

    cr_assert ( 0    == job_heap->count, "test that the current count of the job queue is zero");
    cr_assert ( 128  == job_heap->size, "test that the maximum count of the job queue is 128");
    cr_assert ( true == job_heap->elements[0].sentinel, "test that the spare element is tagged as sentinel");

    np_job_t local_jobs[10];
    for (uint8_t i = 0; i < 10; i++)  {
    		local_jobs[i].priority = (double) i;
    		local_jobs[i].exec_not_before_tstamp = 0.0;

    		pheap_insert(np_job_t, job_heap, local_jobs[i]);
    	    cr_assert ( i+1  == job_heap->count, "test that the current count of the job queue has increased");
    	    cr_assert ( 128  == job_heap->size, "test that the maximum count of the job queue is still 128");
    }
    np_job_t test_element = { 0 };

    test_element = pheap_first(np_job_t, job_heap);

    cr_assert (  0.0  == test_element.priority, "test whether the first element has the lowest priority");
    // modifying the returned test element should have no impact on the element in the heap
    test_element.priority = 20.0;
    cr_assert ( 20.0  == test_element.priority, "test whether the modified element has a changed priority");

    test_element = pheap_head(np_job_t, job_heap);
    cr_assert (  0.0   == test_element.priority, "test whether the first element still has the lowest priority");
    cr_assert (  9     == job_heap->count, "test that the current count of the job queue has decreased");

    test_element = pheap_first(np_job_t, job_heap);
    cr_assert ( 0.0   != test_element.priority, "test whether the first element is a different element");
    cr_assert ( 1.0   == test_element.priority, "test whether the first element has the lowest priority");

    test_element = pheap_remove(np_job_t, job_heap, 29);
    cr_assert ( 8     == job_heap->count, "test that the current count of the job queue has decreased");

    test_element = pheap_remove(np_job_t, job_heap, 2);
    cr_assert ( 7     == job_heap->count, "test that the current count of the job queue has decreased");
    cr_assert ( 3.0   == test_element.priority, "test whether the first element has the lowest priority");

    pheap_clear(np_job_t, job_heap);
    cr_assert ( 0     == job_heap->count, "test that the current count of the job queue is zero");

    pheap_free(np_job_t, job_heap);
}

Test(np_heap, _np_heap_job_t_perf, .description = "test the performance heap of a np_job_t")
{
    np_job_t tmp;

    double insert_func[2048], remove_func[ (2048/3+1) ], heap_func[ (2048/5+1) ];
    uint16_t removed = 0;
    uint16_t fetched = 0;

    np_pheap_t(np_job_t, job_heap);
    pheap_init(np_job_t, job_heap, 1024);

    // add random insert / remove / head calls to the heap
    for(uint16_t i = 0; i < 2048; i++)
    {
    		tmp.priority = i * rand() / 1024;
    		tmp.exec_not_before_tstamp = 0.0;

    		MEASURE_TIME(insert_func, i, {
    				pheap_insert(np_job_t, job_heap, tmp);
    		});

    		if ((i % 3) == 0)
    		{   // delete every third argument
    			MEASURE_TIME(remove_func, removed, {
    				tmp = pheap_remove(np_job_t, job_heap, i/3);
    			});
    			removed++;
    		}

    		if ((i % 5) == 0)
    		{
    			MEASURE_TIME(heap_func, fetched, {
    				tmp = pheap_head(np_job_t, job_heap);
    			});
    			fetched++;
    		}
    }

    CALC_AND_PRINT_STATISTICS("insert into job heap stats", insert_func, 2048);
    CALC_AND_PRINT_STATISTICS("remove from job heap stats", remove_func, removed);
    CALC_AND_PRINT_STATISTICS("head   of   job heap stats", heap_func, fetched);

    pheap_clear(np_job_t, job_heap);
    pheap_free(np_job_t, job_heap);
}
