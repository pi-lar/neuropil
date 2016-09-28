/**
 *  neuropil is copyright 2015 by pi-lar GmbH
 **/
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include "pthread.h"
#include <criterion/criterion.h>

#include "np_memory.h"
#include "np_log.h"
#include "neuropil.h"
#include "np_message.h"
#include "np_types.h"

typedef struct test_struct
{
	np_obj_t* obj;

	unsigned int i_test;
	char* s_test;
} test_struct_t;


void _test_struct_t_del(NP_UNUSED void* data_ptr)
{
	printf("destructor test_struct_t_del called");
}

void _test_struct_t_new(NP_UNUSED void* data_ptr)
{
	printf("constructor test_struct_t_new called");
}

void setup_memory(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_MESSAGE;
	np_log_init("test_jrb_impl.log", log_level);

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
	np_mem_printpool();

	test_struct_t *t_obj1, *t_obj2, *t_obj3, *t_obj4;

	{
		np_new_obj(test_struct_t, t_obj1);

		t_obj1->i_test = 1;
		t_obj1->s_test = "dies ist ein test";

		np_ref_obj(test_struct_t, t_obj1);
	}

	np_mem_printpool();

	{
		np_new_obj(test_struct_t, t_obj2);

		t_obj2->i_test = 2;
		t_obj2->s_test = "dies ist zwei test";
	}

	np_mem_printpool();

	{
		np_new_obj(test_struct_t, t_obj3);

		t_obj3->i_test = 3;
		t_obj3->s_test = "dies ist drei test";
	}
	np_mem_printpool();

	np_unref_obj(test_struct_t, t_obj3);

	np_mem_printpool();

	{
		np_new_obj(test_struct_t, t_obj4);

		t_obj4->i_test = 4;
		t_obj4->s_test = "dies ist vier test";
	}

	np_mem_printpool();

	np_unref_obj(test_struct_t, t_obj1);

	np_mem_printpool();

	np_free_obj(test_struct_t, t_obj1);

	printf("\n\n\n");

}
