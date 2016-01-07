#include <stdlib.h>

#include "np_key.h"
#include "np_list.h"

#include "np_container.h"

NP_PLL_GENERATE_PROTOTYPES(double);
NP_PLL_GENERATE_IMPLEMENTATION(double);

int8_t compare_double(double d1, double d2){
	if (d2 > d1) return -1;
	if (d2 < d1) return 1;
	return 0;
}

int main(int argc, char **argv) {

	printf("/*************/\n");
	printf("/* PLL TEST **/\n");
	printf("/*************/\n");

	np_pll_t(double, my_pll_list);
	pll_init(double, my_pll_list, compare_double);

	double d_a = 3.1415;
	double d_b = 1.0;
	double d_c = 7.4321;
	double d_d = 100000000.4;
	double d_e = 1.333333333;

	printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));

	pll_insert(double, my_pll_list, d_a, TRUE);
	printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));

	pll_insert(double, my_pll_list, d_b, TRUE);
	printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));

	pll_insert(double, my_pll_list, d_c, TRUE);
	printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));

	pll_insert(double, my_pll_list, d_d, TRUE);
	printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));

	pll_insert(double, my_pll_list, d_e, TRUE);
	printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));

	double d_tmp_1 = 0.0f;
//	printf("now forward traversing:\n");
	pll_iterator(double) d_iterator_1 = pll_first(my_pll_list);
	while (NULL != d_iterator_1) {
		printf("v: %f  p: %p<-- %p -->%p\n", d_tmp_1, d_iterator_1->blink, d_iterator_1, d_iterator_1->flink);
		pll_next(d_iterator_1);
	}
//	pll_traverse(my_pll_list, d_iterator_1, d_tmp_1) {
//		printf("v: %f  p: %p<-- %p -->%p\n", d_tmp_1, d_iterator_1->blink, d_iterator_1, d_iterator_1->flink);
//	}
//	printf("now backward traversing:\n");
//	pll_iterator(double) d_iterator_2;
//	pll_rtraverse(my_pll_list, d_iterator_2, d_tmp_1) {
//		printf("v: %f\n", d_tmp_1);
//	}

	// pll_free(double, my_pll_list);
	printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));
	pll_remove(double, my_pll_list, 1.0);
	pll_remove(double, my_pll_list, 2.0);
	pll_remove(double, my_pll_list, 3.0);

	printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));
	d_tmp_1 = pll_head(double, my_pll_list);
	printf("v: %f\n", d_tmp_1);

	printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));
	d_tmp_1 = pll_head(double, my_pll_list);
	printf("v: %f\n", d_tmp_1);

	printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));
	d_tmp_1 = pll_head(double, my_pll_list);
	printf("v: %f\n", d_tmp_1);

	printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));
	d_tmp_1 = pll_head(double, my_pll_list);
	if (d_tmp_1) {
		printf("v: %f\n", d_tmp_1);
		printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));
	} else {
		printf("p: %p <-> %p\n", pll_first(my_pll_list), pll_last(my_pll_list));
		printf("pll_list returned NULL element\n");
	}


	printf("/*************/\n");
	printf("/* SLL TEST **/\n");
	printf("/*************/\n");

	np_key_t key_a, key_b, key_c, key_d, key_e;
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

	np_sll_t(np_key_t, my_sll_list);
	sll_init(np_key_t, my_sll_list);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));

	sll_append(np_key_t, my_sll_list, &key_a);
	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));

	sll_prepend(np_key_t, my_sll_list, &key_b);
	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));

	sll_append(np_key_t, my_sll_list, &key_c);
	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));

	sll_prepend(np_key_t, my_sll_list, &key_d);
	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));

	sll_append(np_key_t, my_sll_list, &key_e);
	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));

	np_key_t* tmp_1;
	// TODO: not working yet
//	sll_iterator(np_key_t) iterator_1;
//	sll_traverse(my_sll_list, iterator_1, tmp_1) {
//		printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);
//	}

//	sll_rtraverse(my_sll_list, iterator_1, tmp_1) {
//		printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);
//	}

	// sll_free(np_key_t, my_sll_list);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	tmp_1 = sll_head(np_key_t, my_sll_list);
	printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	tmp_1 = sll_head(np_key_t, my_sll_list);
	printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	tmp_1 = sll_tail(np_key_t, my_sll_list);
	printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	tmp_1 = sll_tail(np_key_t, my_sll_list);
	printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	tmp_1 = sll_head(np_key_t, my_sll_list);
	printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);

	printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	tmp_1 = sll_head(np_key_t, my_sll_list);
	if (tmp_1) {
		printf("v: %llu.%llu.%llu.%llu\n", tmp_1->t[0],tmp_1->t[1],tmp_1->t[2],tmp_1->t[3]);
		printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
	} else {
		printf("p: %p <-> %p\n", sll_first(my_sll_list), sll_last(my_sll_list));
		printf("sll_list returned NULL element\n");
	}

	printf("/*************/\n");
	printf("/* DLL TEST **/\n");
	printf("/*************/\n");
	// if you want to run this test:
	// go to np_container.h and np_container.c and
	// uncomment the generator lines for dll_list and np_key_t
/*
	np_dll_t(np_key_t, my_dll_list);
	dll_init(np_key_t, my_dll_list);

	printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_prepend(np_key_t, my_dll_list, &key_a);
	printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_append(np_key_t, my_dll_list, &key_b);
	printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_prepend(np_key_t, my_dll_list, &key_c);
	printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_append(np_key_t, my_dll_list, &key_d);
	printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	dll_prepend(np_key_t, my_dll_list, &key_e);
	printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));

	np_key_t* tmp_2;
	dll_iterator(np_key_t) iterator_2;
	dll_traverse(my_dll_list, iterator_2, tmp_2) {
		printf("p: %p (%p) -> v: %lu.%lu.%lu.%lu\n", iterator_2, iterator_2->flink, tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);
	}

	dll_rtraverse(my_dll_list, iterator_2, tmp_2) {
		printf("p: %p (%p) -> v: %lu.%lu.%lu.%lu\n", iterator_2, iterator_2->blink, tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);
	}

	// dll_free(np_key_t, my_dll_list);

	printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_head(np_key_t, my_dll_list);
	printf("v: %lu.%lu.%lu.%lu\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_head(np_key_t, my_dll_list);
	printf("v: %lu.%lu.%lu.%lu\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_tail(np_key_t, my_dll_list);
	printf("v: %lu.%lu.%lu.%lu\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_tail(np_key_t, my_dll_list);
	printf("v: %lu.%lu.%lu.%lu\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_head(np_key_t, my_dll_list);
	printf("v: %lu.%lu.%lu.%lu\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);

	printf("%d: p: %p <-> %p\n", dll_size(my_dll_list), dll_first(my_dll_list), dll_last(my_dll_list));
	tmp_2 = dll_head(np_key_t, my_dll_list);

	if (tmp_2) {
		printf("v: %lu.%lu.%lu.%lu\n", tmp_2->t[0],tmp_2->t[1],tmp_2->t[2],tmp_2->t[3]);
		printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));
	} else {
		printf("p: %p <-> %p\n", dll_first(my_dll_list), dll_last(my_dll_list));
		printf("dll_list returned NULL element\n");
	}
*/
}
