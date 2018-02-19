//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <float.h>
#include <inttypes.h>

#include "sodium.h"
#include "pthread.h"
#include "time.h"

#include <criterion/criterion.h>

#include "np_constants.h"
#include "np_settings.h"
#undef NP_BENCHMARKING
#include "neuropil.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_memory_v2.h"

#include "np_threads.h"
#include "np_types.h"
#include "np_util.h"


typedef struct test_struct
{
	np_obj_t* obj;

	unsigned int i_test;
	char* s_test;
} test_struct_t;


void _test_struct_t_del(NP_UNUSED void* data_ptr)
{
	// printf("destructor test_struct_t_del called");
}

void _test_struct_t_new(NP_UNUSED void* data_ptr)
{
	// printf("constructor test_struct_t_new called");
}

void setup_memory(void)
{
	// int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_MEMORY;
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG;
	np_log_init("test_memory.log", log_level);

	_np_threads_init();
	np_mem_init();
}

void teardown_memory(void)
{
	np_log_destroy();
}

TestSuite(np_memory_t, .init=setup_memory, .fini=teardown_memory);


// TODO: add the appropiate cr_expect() statements to really test the memory chunking
Test(np_memory_t, _memory_create, .description="test the memory allocation routines")
{
	// np_mem_printpool();
	test_struct_t
		*t_obj1 = NULL,
		*t_obj2 = NULL,
		*t_obj3 = NULL,
		*t_obj4 = NULL;

	np_obj_t* obj = NULL;

	{
		np_new_obj(test_struct_t, t_obj1);

		cr_expect(NULL != t_obj1, "expect object to be not null");

		t_obj1->i_test = 1;
		t_obj1->s_test = "dies ist ein test";

		np_ref_obj(test_struct_t, t_obj1,"ref2");
		cr_expect(t_obj1->obj->ref_count == 2, "test whether the reference counter of obj 1 is equal to 2");
	}

	// np_mem_printpool();

	{
		np_new_obj(test_struct_t, t_obj2);

		t_obj2->i_test = 2;
		t_obj2->s_test = "dies ist zwei test";
		cr_expect(t_obj2->obj->ref_count == 1, "test whether the reference counter of obj 2 is equal to 1");
	}

	// np_mem_printpool();

	{
		np_new_obj(test_struct_t, t_obj3);

		t_obj3->i_test = 3;
		t_obj3->s_test = "dies ist drei test";

		cr_expect(t_obj3->obj->ref_count == 1, "test whether the reference counter of obj 3 is equal to 1");
	}
	cr_expect(t_obj3->obj->ref_count == 1, "test whether the reference counter of obj 3 is still equal to 1");

	// np_mem_printpool();
	obj = t_obj3->obj;

	np_unref_obj(test_struct_t, t_obj3,ref_obj_creation);
	cr_expect(t_obj3 == NULL, "test whether the t_obj3 has been deleted");
	cr_expect(obj->ref_count == 0, "test whether the reference counter of former meta obj is zero");
	cr_expect(obj->ptr == NULL,"test whether the ptr of the meta object points to NULL");
	cr_expect(obj->type == np_none_t_e, "test whether the type of the meta obj is none");

	// np_mem_printpool();

	{
		np_new_obj(test_struct_t, t_obj4);
		cr_expect(t_obj4->obj->type == test_struct_t_e, "test whether the obj type is correctly set");

		t_obj4->i_test = 4;
		t_obj4->s_test = "dies ist vier test";
		cr_expect(t_obj4->obj->ref_count == 1, "test whether the reference counter of obj 4 is equal to 1");
	}

	// np_mem_printpool();

	np_unref_obj(test_struct_t, t_obj1,"ref2");
	cr_expect(t_obj1->obj->ref_count == 1, "test whether the reference counter  of obj 1 is equal to 1");
	cr_expect(t_obj1->obj->type == test_struct_t_e, "test whether the meta obj type is set to test_struct_t_e");

	// np_mem_printpool();
	obj = t_obj1->obj;

	np_unref_obj(test_struct_t, t_obj1, ref_obj_creation);

	cr_expect(t_obj1 == NULL, "test whether the t_obj1 has been deleted");
	cr_expect(obj->ref_count == 0, "test whether the reference counter of former meta obj is zero");
	cr_expect(obj->ptr == NULL,"test whether the ptr of the meta object points to NULL");
	cr_expect(obj->type == np_none_t_e, "test whether the type of the meta obj is none");

}

Test(np_memory_t, _memory_reasons, .description = "test the memory reasoning routines")
{
	test_struct_t
		*t_obj1 = NULL;

	np_new_obj(test_struct_t, t_obj1, "test___1");
	cr_assert(NULL != t_obj1, "expect object to be not null");
	cr_assert(1 == t_obj1->obj->ref_count, "expect ref count on object to be 1");
	cr_assert(1 == sll_size(t_obj1->obj->reasons), "expect reason count on object to be 1");
	cr_assert(0 == strncmp("test___1", sll_first(t_obj1->obj->reasons)->val,8), "expect 1. reason object to be test___1");

	np_ref_obj(test_struct_t, t_obj1, "test___1");
	cr_assert(NULL != t_obj1, "expect object to be not null");
	cr_assert(2 == t_obj1->obj->ref_count, "expect ref count on object to be 2");
	cr_assert(2 == sll_size(t_obj1->obj->reasons), "expect reason count on object to be 2");
	cr_assert(0 == strncmp("test___1", sll_first(t_obj1->obj->reasons)->val, 8), "expect 1. reason object to be test___1");
	cr_assert(0 == strncmp("test___1", sll_next_select(sll_first(t_obj1->obj->reasons))->val, 8), "expect 2. reason object to be test___1");

	np_unref_obj(test_struct_t, t_obj1, "test___1"); 
	cr_assert(NULL != t_obj1, "expect object to be not null");
	cr_assert(1 == t_obj1->obj->ref_count, "expect ref count on object to be 1");
	cr_assert(1 == sll_size(t_obj1->obj->reasons), "expect reason count on object to be 1 (but is: %"PRIu32")", sll_size(t_obj1->obj->reasons));
	cr_assert(0 == strncmp("test___1", sll_first(t_obj1->obj->reasons)->val, 8), "expect 1. reason object to be test___1");


	np_ref_obj(test_struct_t, t_obj1, "test___2");
	cr_assert(NULL != t_obj1, "expect object to be not null");
	cr_assert(2 == t_obj1->obj->ref_count, "expect ref count on object to be 2");
	cr_assert(2 == sll_size(t_obj1->obj->reasons), "expect reason count on object to be 2");
	cr_assert(0 == strncmp("test___2", sll_first(t_obj1->obj->reasons)->val, 8), "expect 1. reason object to be test___2");
	cr_assert(0 == strncmp("test___1", sll_next_select(sll_first(t_obj1->obj->reasons))->val, 8), "expect 2. reason object to be test___1");

	np_unref_obj(test_struct_t, t_obj1, "test___1");
	cr_assert(NULL != t_obj1, "expect object to be not null");
	cr_assert(1 == t_obj1->obj->ref_count, "expect ref count on object to be 1");
	cr_assert(1 == sll_size(t_obj1->obj->reasons), "expect reason count on object to be 1");
	cr_assert(0 == strncmp("test___2", sll_first(t_obj1->obj->reasons)->val, 8), "expect 1. reason object to be test___2");


	np_ref_obj(test_struct_t, t_obj1, "test___3");
	cr_assert(NULL != t_obj1, "expect object to be not null");
	cr_assert(2 == t_obj1->obj->ref_count, "expect ref count on object to be 2");
	cr_assert(2 == sll_size(t_obj1->obj->reasons), "expect reason count on object to be 2");
	cr_assert(0 == strncmp("test___3", sll_first(t_obj1->obj->reasons)->val, 8), "expect 1. reason object to be test___3");
	cr_assert(0 == strncmp("test___2", sll_next_select(sll_first(t_obj1->obj->reasons))->val, 8), "expect 2. reason object to be test___2");


	np_unref_obj(test_struct_t, t_obj1, "test___2");
	cr_assert(NULL != t_obj1, "expect object to be not null");
	cr_assert(1 == t_obj1->obj->ref_count, "expect ref count on object to be 1");
	cr_assert(1 == sll_size(t_obj1->obj->reasons), "expect reason count on object to be 1");
	cr_assert(0 == strncmp("test___3", sll_first(t_obj1->obj->reasons)->val, 8), "expect 1. reason object to be test___3");

	// np_unref_obj(test_struct_t, t_obj1, "test___3");
}


Test(np_memory_t, _memory_v2_perf, .description = "test the memory_v2 performance to implement improvements")
{
	np_memory_init();

	uint16_t max_count = 16284;
	// np_memory_types_BLOB_1024
	// np_memory_types_BLOB_984_RANDOMIZED
	double new_time[16284];
	double free_time[16284];
	double clean_time[16284];
	uint16_t clean_index = 0;

	void* memory_blobs[16284] = { 0 };

	double del = 0, add = 0;
	for (uint16_t i=0; i < max_count; i++)
	{
		// random number
		uint32_t random = randombytes_uniform(max_count);

		if (memory_blobs[random] != NULL)
		{
			del++;

			MEASURE_TIME(free_time, i, np_memory_free(memory_blobs[random]) );

			memory_blobs[random] = NULL;
		}

		add++;		
		if (random % 2)
		{
			MEASURE_TIME(new_time, i, memory_blobs[random] = np_memory_new(np_memory_types_BLOB_1024) );
		}
		else
		{
			MEASURE_TIME(new_time, i, memory_blobs[random] = np_memory_new(np_memory_types_BLOB_984_RANDOMIZED) );
		}
		

		if (0 == (i % 99))
		{
			log_debug_msg(LOG_DEBUG | LOG_MEMORY, "Cleanup of memory block requested");
			MEASURE_TIME(clean_time, clean_index, _np_memory_job_memory_management(NULL) );

			clean_index++;
		}
	}

	fprintf(stdout, "###########\n");
	printf("deleted %.0f items, created %.0f items\n", del, add);

	CALC_AND_PRINT_STATISTICS("memory new_time  :", new_time, max_count);
	CALC_AND_PRINT_STATISTICS("memory free_time :", free_time, max_count);
	CALC_AND_PRINT_STATISTICS("memory clean_time:", clean_time, clean_index);
}
