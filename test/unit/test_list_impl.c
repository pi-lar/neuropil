//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>

#include <stdlib.h>
#include <inttypes.h>

#include "event/ev.h"

#include "np_list.h"
#include "np_dhkey.h"
#include "np_log.h"
#include "np_types.h"

#include "../test_macros.c"

// typedef double* double_ptr;
NP_PLL_GENERATE_PROTOTYPES(double);
NP_PLL_GENERATE_IMPLEMENTATION(double);

typedef np_dhkey_t* np_dhkey_ptr;

NP_SLL_GENERATE_PROTOTYPES(np_dhkey_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_dhkey_ptr);

NP_DLL_GENERATE_PROTOTYPES(np_dhkey_ptr);
NP_DLL_GENERATE_IMPLEMENTATION(np_dhkey_ptr);
 
int8_t compare_double(double d1, double d2)
{
	if (d2 > d1) return 1;
	if (d2 < d1) return -1;
	return 0;
}

TestSuite(np_linked_lists );

Test(np_linked_lists, _test_pll, .description="test the implementation of a priority list")
{
	np_pll_t(double, my_pll_list);
	pll_init(double, my_pll_list);

	double d_a = 3.1415;
	double d_b = 1.0;
	double d_c = 7.4321;
	double d_d = 100000000.4;
	double d_e = 1.333333333;

	cr_expect(NULL == pll_first(my_pll_list), "expect the first element to be NULL");
	cr_expect(NULL == pll_last(my_pll_list),  "expect the last element to be NULL");
	cr_expect(0 == pll_size(my_pll_list), "expect the size of the list to be 0");
	cr_expect(pll_first(my_pll_list) == pll_last(my_pll_list),  "expect the first and last element to be the same");

	pll_insert(double, my_pll_list, d_a, true, compare_double);

	cr_expect(1 == pll_size(my_pll_list), "expect the size of the list to be 1");
	cr_expect(NULL != pll_first(my_pll_list), "expect the first element to exists");
	cr_expect(NULL != pll_last(my_pll_list),  "expect the last element to exists");
	cr_expect(d_a == pll_first(my_pll_list)->val,  "expect the first element to have the inserted value");
	cr_expect(d_a == pll_last(my_pll_list)->val,  "expect the first element to have the inserted value");
	cr_expect(pll_first(my_pll_list) == pll_last(my_pll_list),  "expect the first and last element to be the same");

	pll_insert(double, my_pll_list, d_b, true, compare_double);

	cr_expect(2 == pll_size(my_pll_list), "expect the size of the list to be 2");
	cr_expect(NULL != pll_first(my_pll_list), "expect the first element to exists");
	cr_expect(NULL != pll_last(my_pll_list),  "expect the last element to exists");
	cr_expect(d_b == pll_first(my_pll_list)->val,  "expect the first element to have the inserted value");
	cr_expect(d_a == pll_last(my_pll_list)->val,  "expect the last element to have the old value");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	pll_insert(double, my_pll_list, d_c, true, compare_double);

	cr_expect(3 == pll_size(my_pll_list), "expect the size of the list to be 3");
	cr_expect(NULL != pll_first(my_pll_list), "expect the first element to exists");
	cr_expect(NULL != pll_last(my_pll_list),  "expect the last element to exists");
	cr_expect(d_b == pll_first(my_pll_list)->val,  "expect the first element to have the inserted value");
	cr_expect(d_c == pll_last(my_pll_list)->val,  "expect the last element to have the old value");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	pll_insert(double, my_pll_list, d_d, true, compare_double);

	cr_expect(4 == pll_size(my_pll_list), "expect the size of the list to be 4");
	cr_expect(NULL != pll_first(my_pll_list), "expect the first element to exists");
	cr_expect(NULL != pll_last(my_pll_list),  "expect the last element to exists");
	cr_expect(d_b == pll_first(my_pll_list)->val,  "expect the first element to have the old value");
	cr_expect(d_d == pll_last(my_pll_list)->val,  "expect the first element to have the inserted value");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	pll_insert(double, my_pll_list, d_e, true, compare_double);

	cr_expect(5 == pll_size(my_pll_list), "expect the size of the list to be 5");
	cr_expect(NULL != pll_first(my_pll_list), "expect the first element to exists");
	cr_expect(NULL != pll_last(my_pll_list),  "expect the last element to exists");
	cr_expect(d_b == pll_first(my_pll_list)->val,  "expect the first element to have the old value");
	cr_expect(d_d == pll_last(my_pll_list)->val,  "expect the first element to have the old value");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	pll_insert(double, my_pll_list, d_e, false, compare_double);
	cr_expect(5 == pll_size(my_pll_list), "expect the size of the list to be 5 still");

	double d_tmp_1 = 0.0f;
	pll_iterator(double) d_iterator_1 = pll_first(my_pll_list);
	while (NULL != d_iterator_1) {
		cr_expect(d_tmp_1 < d_iterator_1->val,  "expect the iterator to have a increasing values");
		pll_next(d_iterator_1);
	}

	// pll_free(double, my_pll_list);
	pll_remove(double, my_pll_list, 1.0, compare_double);
	cr_expect(4 == pll_size(my_pll_list), "expect the size of the list to be 4");
	pll_remove(double, my_pll_list, 2.0, compare_double);
	cr_expect(4 == pll_size(my_pll_list), "expect the size of the list to be 4");
	pll_remove(double, my_pll_list, 3.0, compare_double);
	cr_expect(4 == pll_size(my_pll_list), "expect the size of the list to be 4");

	d_tmp_1 = pll_head(double, my_pll_list);
	cr_expect(3 == pll_size(my_pll_list), "expect the size of the list to be 3");
	cr_expect(d_e == d_tmp_1, "expect the value of the first element to be 1.333");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	d_tmp_1 = pll_head(double, my_pll_list);
	cr_expect(2 == pll_size(my_pll_list), "expect the size of the list to be 2");
	cr_expect(d_a == d_tmp_1, "expect the value of the first element to be 3.1415");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	d_tmp_1 = pll_head(double, my_pll_list);
	cr_expect(1 == pll_size(my_pll_list), "expect the size of the list to be 1");
	cr_expect(d_c == d_tmp_1, "expect the value of the first element to be 7.4321");
	cr_expect(pll_first(my_pll_list) == pll_last(my_pll_list),  "expect the first and last element to be the same");

	d_tmp_1 = pll_head(double, my_pll_list);
	cr_expect(0 == pll_size(my_pll_list), "expect the size of the list to be 0");
	cr_expect(NULL == pll_first(my_pll_list), "expect the first element to be NULL");
	cr_expect(NULL == pll_last(my_pll_list),  "expect the last element to be NULL");
	cr_expect(pll_first(my_pll_list) == pll_last(my_pll_list),  "expect the first and last element to be the same");
	cr_expect(d_d == d_tmp_1, "expect the value of the first element to be 100000000.4");

	pll_insert(double, my_pll_list, d_a, true, compare_double);
	pll_insert(double, my_pll_list, d_b, true, compare_double);
	pll_insert(double, my_pll_list, d_c, true, compare_double);
	pll_insert(double, my_pll_list, d_d, true, compare_double);
	pll_insert(double, my_pll_list, d_e, true, compare_double);

	cr_expect(5 == pll_size(my_pll_list), "expect the size of the list to be 5");

	d_tmp_1 = pll_tail(double, my_pll_list);
	cr_expect(4 == pll_size(my_pll_list), "expect the size of the list to be 4");
	cr_expect(d_d == d_tmp_1, "expect the value of the last element to be 100000000.4 7.4321");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	d_tmp_1 = pll_tail(double, my_pll_list);
	cr_expect(3 == pll_size(my_pll_list), "expect the size of the list to be 3");
	cr_expect(d_c == d_tmp_1, "expect the value of the last element to be 7.4321");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	d_tmp_1 = pll_tail(double, my_pll_list);
	cr_expect(2 == pll_size(my_pll_list), "expect the size of the list to be 2");
	cr_expect(d_a == d_tmp_1, "expect the value of the last element to be 3.1415");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	d_tmp_1 = pll_tail(double, my_pll_list);
	cr_expect(1 == pll_size(my_pll_list), "expect the size of the list to be 1");
	cr_expect(NULL != pll_first(my_pll_list), "expect the first element to be not NULL");
	cr_expect(NULL != pll_last(my_pll_list),  "expect the last element to be not NULL");
	cr_expect(d_e == d_tmp_1, "expect the value of the last element to be 1.333333333");
	cr_expect(pll_first(my_pll_list) == pll_last(my_pll_list),  "expect the first and last element to be the same");

	d_tmp_1 = pll_tail(double, my_pll_list);
	cr_expect(0 == pll_size(my_pll_list), "expect the size of the list to be 0");
	cr_expect(NULL == pll_first(my_pll_list), "expect the first element to be NULL");
	cr_expect(NULL == pll_last(my_pll_list),  "expect the last element to be NULL");
	cr_expect(d_b == d_tmp_1, "expect the value of the last element to be 1.0");
	cr_expect(pll_first(my_pll_list) == pll_last(my_pll_list),  "expect the first and last element to be the same");
}


// TestSuite(np_sll_t, .init=setup_list, .fini=teardown_list);

Test(np_linked_lists, _test_sll, .description="test the implementation of a single linked list")
{
	np_dhkey_t key_a, key_b, key_c, key_d, key_e;
	key_a.t[0] = 1; key_a.t[1] = 0; key_a.t[2] = 0; key_a.t[3] = 0;
	key_b.t[0] = 1; key_b.t[1] = 1; key_b.t[2] = 0; key_b.t[3] = 0;
	key_c.t[0] = 0; key_c.t[1] = 0; key_c.t[2] = 1; key_c.t[3] = 0;
	key_d.t[0] = 0; key_d.t[1] = 0; key_d.t[2] = 1; key_d.t[3] = 1;
	key_e.t[0] = 1; key_e.t[1] = 1; key_e.t[2] = 1; key_e.t[3] = 1;

	np_sll_t(np_dhkey_ptr, my_sll_list);
	sll_init(np_dhkey_ptr, my_sll_list);

	cr_expect(NULL == sll_first(my_sll_list), "expect the first element to be NULL");
	cr_expect(NULL == sll_last(my_sll_list),  "expect the last element to be NULL");
	cr_expect(0 == sll_size(my_sll_list), "expect the size of the list to be 0");

	sll_append(np_dhkey_ptr, my_sll_list, &key_a);
	cr_expect(1 == sll_size(my_sll_list), "expect the size of the list to be 1");
	cr_expect(NULL != sll_first(my_sll_list), "expect the first element to exists");
	cr_expect(NULL != sll_last(my_sll_list),  "expect the last element to exists");
	cr_expect(0 == _np_dhkey_cmp(&key_a, sll_first(my_sll_list)->val),  "expect the first element to have the inserted value");
	cr_expect(0 == _np_dhkey_cmp(&key_a, sll_last(my_sll_list)->val),  "expect the first element to have the inserted value");
	cr_expect(sll_first(my_sll_list) == sll_last(my_sll_list),  "expect the first and last element to be the same");

	sll_prepend(np_dhkey_ptr, my_sll_list, &key_b);
	cr_expect(2 == sll_size(my_sll_list), "expect the size of the list to be 2");
	cr_expect(NULL != sll_first(my_sll_list), "expect the first element to exists");
	cr_expect(NULL != sll_last(my_sll_list),  "expect the last element to exists");
	cr_expect(0 == _np_dhkey_cmp(&key_b, sll_first(my_sll_list)->val),  "expect the first element to have the inserted value");
	cr_expect(0 == _np_dhkey_cmp(&key_a, sll_last(my_sll_list)->val),  "expect the last element to have the old value");
	cr_expect(sll_first(my_sll_list) != sll_last(my_sll_list),  "expect the first and last element to be different");

	sll_append(np_dhkey_ptr, my_sll_list, &key_c);
	cr_expect(3 == sll_size(my_sll_list), "expect the size of the list to be 3");
	cr_expect(NULL != sll_first(my_sll_list), "expect the first element to exists");
	cr_expect(NULL != sll_last(my_sll_list),  "expect the last element to exists");
	cr_expect(sll_first(my_sll_list) != sll_last(my_sll_list),  "expect the first and last element to be different");
	cr_expect(0 == _np_dhkey_cmp(&key_b, sll_first(my_sll_list)->val),  "expect the first element to have the old value");
	cr_expect(0 == _np_dhkey_cmp(&key_c, sll_last(my_sll_list)->val),  "expect the last element to have the inserted value");

	sll_prepend(np_dhkey_ptr, my_sll_list, &key_d);
	cr_expect(4 == sll_size(my_sll_list), "expect the size of the list to be 4");
	cr_expect(NULL != sll_first(my_sll_list), "expect the first element to exists");
	cr_expect(NULL != sll_last(my_sll_list),  "expect the last element to exists");
	cr_expect(sll_first(my_sll_list) != sll_last(my_sll_list),  "expect the first and last element to be different");
	cr_expect(0 == _np_dhkey_cmp(&key_d, sll_first(my_sll_list)->val),  "expect the first element to have the inserted value");
	cr_expect(0 == _np_dhkey_cmp(&key_c, sll_last(my_sll_list)->val),  "expect the last element to have the old value");

	sll_append(np_dhkey_ptr, my_sll_list, &key_e);
	cr_expect(5 == sll_size(my_sll_list), "expect the size of the list to be 5");
	cr_expect(NULL != sll_first(my_sll_list), "expect the first element to exists");
	cr_expect(NULL != sll_last(my_sll_list),  "expect the last element to exists");
	cr_expect(sll_first(my_sll_list) != sll_last(my_sll_list),  "expect the first and last element to be different");
	cr_expect(0 == _np_dhkey_cmp(&key_d, sll_first(my_sll_list)->val),  "expect the first element to have the old value");
	cr_expect(0 == _np_dhkey_cmp(&key_e, sll_last(my_sll_list)->val),  "expect the last element to have the inserted value");


	np_dhkey_t* tmp_1;

	// TODO: not working yet
	// sll_iterator(np_dhkey_t) iterator_1;
	// sll_traverse(my_sll_list, iterator_1, tmp_1)
	// {
	// }
	//	sll_rtraverse(my_sll_list, iterator_1, tmp_1) {
	//		printf("v: %"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32"\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);
	//	}

	tmp_1 = sll_head(np_dhkey_ptr, my_sll_list);
	cr_expect(4 == sll_size(my_sll_list), "expect the size of the list to be 4");
	cr_expect(NULL != sll_first(my_sll_list), "expect the first element to exists");
	cr_expect(NULL != sll_last(my_sll_list),  "expect the last element to exists");
	cr_expect(sll_first(my_sll_list) != sll_last(my_sll_list),  "expect the first and last element to be different");
	cr_expect(0 == _np_dhkey_cmp(&key_b, sll_first(my_sll_list)->val),  "expect the first element to have the next value");
	cr_expect(0 == _np_dhkey_cmp(&key_e, sll_last(my_sll_list)->val),  "expect the last element to have the inserted value");
	cr_expect(0 == _np_dhkey_cmp(&key_d, tmp_1),  "expect returned element to the old first one");

	tmp_1 = sll_head(np_dhkey_ptr, my_sll_list);
	cr_expect(3 == sll_size(my_sll_list), "expect the size of the list to be 3");
	cr_expect(NULL != sll_first(my_sll_list), "expect the first element to exists");
	cr_expect(NULL != sll_last(my_sll_list),  "expect the last element to exists");
	cr_expect(sll_first(my_sll_list) != sll_last(my_sll_list),  "expect the first and last element to be different");
	cr_expect(0 == _np_dhkey_cmp(&key_a, sll_first(my_sll_list)->val),  "expect the first element to have the next value");
	cr_expect(0 == _np_dhkey_cmp(&key_e, sll_last(my_sll_list)->val),  "expect the last element to have the inserted value");
	cr_expect(0 == _np_dhkey_cmp(&key_b, tmp_1),  "expect returned element to the old first one");

	tmp_1 = sll_tail(np_dhkey_ptr, my_sll_list);
	cr_expect(2 == sll_size(my_sll_list), "expect the size of the list to be 2");
	cr_expect(NULL != sll_first(my_sll_list), "expect the first element to exists");
	cr_expect(NULL != sll_last(my_sll_list),  "expect the last element to exists");
	cr_expect(sll_first(my_sll_list) != sll_last(my_sll_list),  "expect the first and last element to be different");
	cr_expect(0 == _np_dhkey_cmp(&key_a, sll_first(my_sll_list)->val),  "expect the first element to have the next value");
	cr_expect(0 == _np_dhkey_cmp(&key_c, sll_last(my_sll_list)->val),  "expect the last element to have the inserted value");
	cr_expect(0 == _np_dhkey_cmp(&key_e, tmp_1),  "expect returned element to the old last one");

	tmp_1 = sll_tail(np_dhkey_ptr, my_sll_list);
	cr_expect(1 == sll_size(my_sll_list), "expect the size of the list to be 1");
	cr_expect(NULL != sll_first(my_sll_list), "expect the first element to exists");
	cr_expect(NULL != sll_last(my_sll_list),  "expect the last element to exists");
	cr_expect(sll_first(my_sll_list) == sll_last(my_sll_list),  "expect the first and last element to be the same");
	cr_expect(0 == _np_dhkey_cmp(&key_a, sll_first(my_sll_list)->val),  "expect the first element to have the next value");
	cr_expect(0 == _np_dhkey_cmp(&key_a, sll_last(my_sll_list)->val),  "expect the last element to have the inserted value");
	cr_expect(0 == _np_dhkey_cmp(&key_c, tmp_1),  "expect returned element to the old last one");

	tmp_1 = sll_head(np_dhkey_ptr, my_sll_list);
	cr_expect(0 == sll_size(my_sll_list), "expect the size of the list to be 0");
	cr_expect(NULL == sll_first(my_sll_list), "expect the first element to be NULL");
	cr_expect(NULL == sll_last(my_sll_list),  "expect the last element to be NULL");
	cr_expect(sll_first(my_sll_list) == sll_last(my_sll_list),  "expect the first and last element to be the same");
	cr_expect( 0 == _np_dhkey_cmp(&key_a, tmp_1),  "expect returned element to the old last one");

	tmp_1 = sll_head(np_dhkey_ptr, my_sll_list);
	cr_expect(0 == sll_size(my_sll_list), "expect the size of the list to be 0");
	cr_expect(NULL == sll_first(my_sll_list), "expect the first element to be NULL");
	cr_expect(NULL == sll_last(my_sll_list),  "expect the last element to be NULL");
	cr_expect(sll_first(my_sll_list) == sll_last(my_sll_list),  "expect the first and last element to be the same");
	cr_expect(-1 == _np_dhkey_cmp(NULL, tmp_1),  "expect returned element to be NULL and campare NULLs should return -1");
	cr_expect(-1 == _np_dhkey_cmp(tmp_1, NULL),  "expect returned element to be NULL and campare NULLs should return -1");

	sll_append(np_dhkey_ptr, my_sll_list, &key_a);
	sll_append(np_dhkey_ptr, my_sll_list, &key_b);
	sll_append(np_dhkey_ptr, my_sll_list, &key_c);
	sll_append(np_dhkey_ptr, my_sll_list, &key_d);
	sll_append(np_dhkey_ptr, my_sll_list, &key_e);
	cr_expect(5 == sll_size(my_sll_list), "expect the size of the list to be 5");

	sll_clear(np_dhkey_ptr, my_sll_list);
	cr_expect(0 == sll_size(my_sll_list), "expect the size of the list to be 0");
	cr_expect(NULL != my_sll_list, "expect the size sll_list to be not NULL");

	sll_free(np_dhkey_ptr, my_sll_list);
	cr_expect(NULL == my_sll_list, "expect the sll_list to be NULL");
}

// TestSuite(np_dll_t, .init=setup_list, .fini=teardown_list);

Test(np_linked_lists, _test_dll, .description="test the implementation of a double linked list")
{
	np_dhkey_t key_a, key_b, key_c, key_d, key_e;
	key_a.t[0] = 1; key_a.t[1] = 0; key_a.t[2] = 0; key_a.t[3] = 0;
	key_b.t[0] = 1; key_b.t[1] = 1; key_b.t[2] = 0; key_b.t[3] = 0;
	key_c.t[0] = 0; key_c.t[1] = 0; key_c.t[2] = 1; key_c.t[3] = 0;
	key_d.t[0] = 0; key_d.t[1] = 0; key_d.t[2] = 1; key_d.t[3] = 1;
	key_e.t[0] = 1; key_e.t[1] = 1; key_e.t[2] = 1; key_e.t[3] = 1;

	np_dll_t(np_dhkey_ptr, my_dll_list);
	dll_init(np_dhkey_ptr, my_dll_list);

	bool printPointer = false;
	if(printPointer == true) printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_prepend(np_dhkey_ptr, my_dll_list, &key_a);
	if(printPointer == true) printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_append(np_dhkey_ptr, my_dll_list, &key_b);
	if(printPointer == true) printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_prepend(np_dhkey_ptr, my_dll_list, &key_c);
	if(printPointer == true) printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_append(np_dhkey_ptr, my_dll_list, &key_d);
	if(printPointer == true) printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_prepend(np_dhkey_ptr, my_dll_list, &key_e);
	if(printPointer == true) printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	np_dhkey_t* tmp_2;
//		dll_iterator(np_dhkey_t) iterator_2;
//		dll_traverse(my_dll_list, iterator_2, tmp_2) {
//			if(printPointer == true) printf("p: %p (%p) -> v: %"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32"\n", iterator_2, iterator_2->flink, tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);
//		}
//
//		dll_rtraverse(my_dll_list, iterator_2, tmp_2) {
//			if(printPointer == true) printf("p: %p (%p) -> v: %"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32"\n", iterator_2, iterator_2->blink, tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);
//		}
	// dll_free(np_dhkey_t, my_dll_list);

	if(printPointer == true) printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_head(np_dhkey_ptr, my_dll_list);
	if(printPointer == true) printf("v: %"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32"\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	if(printPointer == true) printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_head(np_dhkey_ptr, my_dll_list);
	if(printPointer == true) printf("v: %"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32"\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	if(printPointer == true) printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_tail(np_dhkey_ptr, my_dll_list);
	if(printPointer == true) printf("v: %"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32"\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	if(printPointer == true) printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_tail(np_dhkey_ptr, my_dll_list);
	if(printPointer == true) printf("v: %"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32"\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	if(printPointer == true) printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_head(np_dhkey_ptr, my_dll_list);
	if(printPointer == true) printf("v: %"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32"\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	if(printPointer == true) printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_head(np_dhkey_ptr, my_dll_list);

	if (tmp_2) {
		if(printPointer == true) printf("v: %"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32"\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);
		if(printPointer == true) printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));
	} else {
		if(printPointer == true) printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));
		if(printPointer == true) printf("dll_list returned NULL element\n");
	}
}
Test(np_linked_lists, _test_sll_delete, .description = "test the delete implementation of a single linked list")
{
	np_dhkey_t key_a, key_b, key_c, key_d, key_e;
	key_a.t[0] = 1; key_a.t[1] = 0; key_a.t[2] = 0; key_a.t[3] = 0;	   key_a.t[4] = 0; key_a.t[5] = 0; key_a.t[6] = 0; key_a.t[7] = 0;
	key_b.t[0] = 1; key_b.t[1] = 1; key_b.t[2] = 0; key_b.t[3] = 0;	   key_b.t[4] = 0; key_b.t[5] = 0; key_b.t[6] = 0; key_b.t[7] = 0;
	key_c.t[0] = 0; key_c.t[1] = 0; key_c.t[2] = 1; key_c.t[3] = 0;	   key_c.t[4] = 0; key_c.t[5] = 0; key_c.t[6] = 0; key_c.t[7] = 0;
	key_d.t[0] = 0; key_d.t[1] = 0; key_d.t[2] = 1; key_d.t[3] = 1;	   key_d.t[4] = 1; key_d.t[5] = 1; key_d.t[6] = 1; key_d.t[7] = 1;
	key_e.t[0] = 1; key_e.t[1] = 1; key_e.t[2] = 1; key_e.t[3] = 1;	   key_e.t[4] = 1; key_e.t[5] = 1; key_e.t[6] = 1; key_e.t[7] = 1;

	np_sll_t(np_dhkey_ptr, my_sll_list);
	sll_init(np_dhkey_ptr, my_sll_list);

	cr_assert(NULL == sll_first(my_sll_list), "expect the first element to be NULL");
	cr_assert(NULL == sll_last(my_sll_list), "expect the last element to be NULL");
	cr_assert(0 == sll_size(my_sll_list), "expect the size of the list to be 0");

	sll_append(np_dhkey_ptr, my_sll_list, &key_a);
	sll_append(np_dhkey_ptr, my_sll_list, &key_b);
	sll_append(np_dhkey_ptr, my_sll_list, &key_c);

	sll_iterator(np_dhkey_ptr)  to_del = sll_next_select(sll_first(my_sll_list));

	cr_assert(&key_b == to_del->val, "expect the delete element to be key b");
	cr_assert(&key_a == sll_first(my_sll_list)->val, "expect the first element to be key a");
	cr_assert(&key_c == sll_last(my_sll_list)->val, "expect the first element to be key c");
	cr_assert(3 == sll_size(my_sll_list), "expect the size of my list to be 3");

	sll_delete(np_dhkey_ptr, my_sll_list, to_del);

	cr_assert(&key_a == sll_first(my_sll_list)->val, "expect the first element to be key a");
	cr_assert(&key_c == sll_last(my_sll_list)->val, "expect the first element to be key c");
	cr_assert(2 == sll_size(my_sll_list), "expect the size of my list to be 2");	
}