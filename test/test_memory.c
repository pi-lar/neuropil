//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
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
	// printf("destructor test_struct_t_del called");
}

void _test_struct_t_new(NP_UNUSED void* data_ptr)
{
	// printf("constructor test_struct_t_new called");
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
	// np_mem_printpool();
	test_struct_t
		*t_obj1 = NULL,
		*t_obj2 = NULL,
		*t_obj3 = NULL,
		*t_obj4 = NULL;

	np_obj_t* obj = NULL;

	{
		np_new_obj(test_struct_t, t_obj1);

		t_obj1->i_test = 1;
		t_obj1->s_test = "dies ist ein test";

		np_ref_obj(test_struct_t, t_obj1);
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

	np_unref_obj(test_struct_t, t_obj3);
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

	np_unref_obj(test_struct_t, t_obj1);
	cr_expect(t_obj1->obj->ref_count == 1, "test whether the reference counter  of obj 1 is equal to 1");
	cr_expect(t_obj1->obj->type == test_struct_t_e, "test whether the meta obj type is set to test_struct_t_e");

	// np_mem_printpool();
	obj = t_obj1->obj;

	np_free_obj(test_struct_t, t_obj1);

	cr_expect(t_obj1 == NULL, "test whether the t_obj1 has been deleted");
	cr_expect(obj->ref_count == 0, "test whether the reference counter of former meta obj is zero");
	cr_expect(obj->ptr == NULL,"test whether the ptr of the meta object points to NULL");
	cr_expect(obj->type == np_none_t_e, "test whether the type of the meta obj is none");

}