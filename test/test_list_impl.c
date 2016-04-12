#include <criterion/criterion.h>

#include <stdlib.h>

#include "event/ev.h"

#include "np_list.h"
#include "np_key.h"
// #include "np_container.h"
#include "log.h"


NP_PLL_GENERATE_PROTOTYPES(double);
NP_PLL_GENERATE_IMPLEMENTATION(double);

NP_SLL_GENERATE_PROTOTYPES(np_dhkey_t);
NP_SLL_GENERATE_IMPLEMENTATION(np_dhkey_t);

void setup_list(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE;
	log_init("test_list.log", log_level);
}

void teardown_list(void)
{
	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_run(EV_A_ EVRUN_NOWAIT);
}

int8_t compare_double(double d1, double d2)
{
	if (d2 > d1) return 1;
	if (d2 < d1) return -1;
	return 0;
}

TestSuite(np_pll_t, .init=setup_list, .fini=teardown_list);

Test(np_pll_t, _test_pll, .description="test the implementation of a priority list")
{
	np_pll_t(double, my_pll_list);
	pll_init(double, my_pll_list, compare_double);

	double d_a = 3.1415;
	double d_b = 1.0;
	double d_c = 7.4321;
	double d_d = 100000000.4;
	double d_e = 1.333333333;

	cr_expect(NULL == pll_first(my_pll_list), "expect the first element to be NULL");
	cr_expect(NULL == pll_last(my_pll_list),  "expect the last element to be NULL");
	cr_expect(0 == pll_size(my_pll_list), "expect the size of the list to be 0");

	pll_insert(double, my_pll_list, d_a, TRUE);

	cr_expect(1 == pll_size(my_pll_list), "expect the size of the list to be 1");
	cr_expect(NULL != pll_first(my_pll_list), "expect the first element to exists");
	cr_expect(NULL != pll_last(my_pll_list),  "expect the last element to exists");
	cr_expect(d_a == pll_first(my_pll_list)->val,  "expect the first element to have the inserted value");
	cr_expect(d_a == pll_last(my_pll_list)->val,  "expect the first element to have the inserted value");
	cr_expect(pll_first(my_pll_list) == pll_last(my_pll_list),  "expect the first and last element to be the same");

	pll_insert(double, my_pll_list, d_b, TRUE);

	cr_expect(2 == pll_size(my_pll_list), "expect the size of the list to be 2");
	cr_expect(NULL != pll_first(my_pll_list), "expect the first element to exists");
	cr_expect(NULL != pll_last(my_pll_list),  "expect the last element to exists");
	cr_expect(d_b == pll_first(my_pll_list)->val,  "expect the first element to have the inserted value");
	cr_expect(d_a == pll_last(my_pll_list)->val,  "expect the last element to have the old value");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	pll_insert(double, my_pll_list, d_c, TRUE);

	cr_expect(3 == pll_size(my_pll_list), "expect the size of the list to be 3");
	cr_expect(NULL != pll_first(my_pll_list), "expect the first element to exists");
	cr_expect(NULL != pll_last(my_pll_list),  "expect the last element to exists");
	cr_expect(d_b == pll_first(my_pll_list)->val,  "expect the first element to have the inserted value");
	cr_expect(d_c == pll_last(my_pll_list)->val,  "expect the last element to have the old value");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	pll_insert(double, my_pll_list, d_d, TRUE);

	cr_expect(4 == pll_size(my_pll_list), "expect the size of the list to be 4");
	cr_expect(NULL != pll_first(my_pll_list), "expect the first element to exists");
	cr_expect(NULL != pll_last(my_pll_list),  "expect the last element to exists");
	cr_expect(d_b == pll_first(my_pll_list)->val,  "expect the first element to have the old value");
	cr_expect(d_d == pll_last(my_pll_list)->val,  "expect the first element to have the inserted value");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	pll_insert(double, my_pll_list, d_e, TRUE);

	cr_expect(5 == pll_size(my_pll_list), "expect the size of the list to be 5");
	cr_expect(NULL != pll_first(my_pll_list), "expect the first element to exists");
	cr_expect(NULL != pll_last(my_pll_list),  "expect the last element to exists");
	cr_expect(d_b == pll_first(my_pll_list)->val,  "expect the first element to have the old value");
	cr_expect(d_d == pll_last(my_pll_list)->val,  "expect the first element to have the old value");
	cr_expect(pll_first(my_pll_list) != pll_last(my_pll_list),  "expect the first and last element to be different");

	pll_insert(double, my_pll_list, d_e, FALSE);
	cr_expect(5 == pll_size(my_pll_list), "expect the size of the list to be 5 still");

	double d_tmp_1 = 0.0f;
	pll_iterator(double) d_iterator_1 = pll_first(my_pll_list);
	while (NULL != d_iterator_1) {
		cr_expect(d_tmp_1 < d_iterator_1->val,  "expect the iterator to have a increasing values");
		pll_next(d_iterator_1);
	}

	// pll_free(double, my_pll_list);
	pll_remove(double, my_pll_list, 1.0);
	cr_expect(4 == pll_size(my_pll_list), "expect the size of the list to be 4");
	pll_remove(double, my_pll_list, 2.0);
	cr_expect(4 == pll_size(my_pll_list), "expect the size of the list to be 4");
	pll_remove(double, my_pll_list, 3.0);
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
}


TestSuite(np_sll_t, .init=setup_list, .fini=teardown_list);

Test(np_sll_t, _test_sll, .description="test the implementation of a single linked list")
{
	np_dhkey_t key_a, key_b, key_c, key_d, key_e;
	key_a.t[0] = 1; key_a.t[1] = 0; key_a.t[2] = 0; key_a.t[3] = 0;
	key_b.t[0] = 1; key_b.t[1] = 1; key_b.t[2] = 0; key_b.t[3] = 0;
	key_c.t[0] = 0; key_c.t[1] = 0; key_c.t[2] = 1; key_c.t[3] = 0;
	key_d.t[0] = 0; key_d.t[1] = 0; key_d.t[2] = 1; key_d.t[3] = 1;
	key_e.t[0] = 1; key_e.t[1] = 1; key_e.t[2] = 1; key_e.t[3] = 1;

	printf("v: %llu.%llu.%llu.%llu\n", key_a.t[0],key_a.t[1],key_a.t[2],key_a.t[3]);
	printf("v: %llu.%llu.%llu.%llu\n", key_b.t[0],key_b.t[1],key_b.t[2],key_b.t[3]);
	printf("v: %llu.%llu.%llu.%llu\n", key_c.t[0],key_c.t[1],key_c.t[2],key_c.t[3]);
	printf("v: %llu.%llu.%llu.%llu\n", key_d.t[0],key_d.t[1],key_d.t[2],key_d.t[3]);
	printf("v: %llu.%llu.%llu.%llu\n", key_e.t[0],key_e.t[1],key_e.t[2],key_e.t[3]);

	np_sll_t(np_dhkey_t, my_sll_list);
	sll_init(np_dhkey_t, my_sll_list);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));

	sll_append(np_dhkey_t, my_sll_list, &key_a);
	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));

	sll_prepend(np_dhkey_t, my_sll_list, &key_b);
	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));

	sll_append(np_dhkey_t, my_sll_list, &key_c);
	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));

	sll_prepend(np_dhkey_t, my_sll_list, &key_d);
	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));

	sll_append(np_dhkey_t, my_sll_list, &key_e);
	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));

	np_dhkey_t* tmp_1;
	// TODO: not working yet
//	sll_iterator(np_dhkey_t) iterator_1;
//	sll_traverse(my_sll_list, iterator_1, tmp_1) {
//		printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);
//	}

//	sll_rtraverse(my_sll_list, iterator_1, tmp_1) {
//		printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);
//	}

	// sll_free(np_dhkey_t, my_sll_list);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	tmp_1 = sll_head(np_dhkey_t, my_sll_list);
	printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	tmp_1 = sll_head(np_dhkey_t, my_sll_list);
	printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	tmp_1 = sll_tail(np_dhkey_t, my_sll_list);
	printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	tmp_1 = sll_tail(np_dhkey_t, my_sll_list);
	printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	tmp_1 = sll_head(np_dhkey_t, my_sll_list);
	printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	tmp_1 = sll_head(np_dhkey_t, my_sll_list);
	if (tmp_1) {
		printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);
		printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	} else {
		printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
		printf("sll_list returned NULL element\n");
	}

	// if you want to run this test:
	// go to np_container.h and np_container.c and
	// uncomment the generator lines for dll_list and np_dhkey_t
/*
	np_dll_t(np_dhkey_t, my_dll_list);
	dll_init(np_dhkey_t, my_dll_list);

	printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_prepend(np_dhkey_t, my_dll_list, &key_a);
	printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_append(np_dhkey_t, my_dll_list, &key_b);
	printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_prepend(np_dhkey_t, my_dll_list, &key_c);
	printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_append(np_dhkey_t, my_dll_list, &key_d);
	printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_prepend(np_dhkey_t, my_dll_list, &key_e);
	printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	np_dhkey_t* tmp_2;
	dll_iterator(np_dhkey_t) iterator_2;
	dll_traverse(my_dll_list, iterator_2, tmp_2) {
		printf("p: %p (%p) -> v: %lu.%lu.%lu.%lu\n", iterator_2, iterator_2->flink, tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);
	}

	dll_rtraverse(my_dll_list, iterator_2, tmp_2) {
		printf("p: %p (%p) -> v: %lu.%lu.%lu.%lu\n", iterator_2, iterator_2->blink, tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);
	}

	// dll_free(np_dhkey_t, my_dll_list);

	printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_head(np_dhkey_t, my_dll_list);
	printf("v: %lu.%lu.%lu.%lu\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_head(np_dhkey_t, my_dll_list);
	printf("v: %lu.%lu.%lu.%lu\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_tail(np_dhkey_t, my_dll_list);
	printf("v: %lu.%lu.%lu.%lu\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_tail(np_dhkey_t, my_dll_list);
	printf("v: %lu.%lu.%lu.%lu\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_head(np_dhkey_t, my_dll_list);
	printf("v: %lu.%lu.%lu.%lu\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_head(np_dhkey_t, my_dll_list);

	if (tmp_2) {
		printf("v: %lu.%lu.%lu.%lu\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);
		printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));
	} else {
		printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));
		printf("dll_list returned NULL element\n");
	}
*/
}
