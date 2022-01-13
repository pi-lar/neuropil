//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <criterion/criterion.h>
#include <criterion/logging.h>

#include <stdlib.h>
#include <inttypes.h>

#include "util/np_skiplist.h"
#include "np_dhkey.h"

#include "../test_macros.c"

typedef struct sl_item_s {
	uint16_t key;
	double value;
} sl_item_t;

int8_t _compare_double(const void* old, const void* new)
{
	sl_item_t* it_1 = (sl_item_t*)old;
	sl_item_t* it_2 = (sl_item_t*)new;

	cr_log_info("comparing to : %p (%d) <-> (%d) %p    ", new, it_2->key, it_1->key, old);
	if      (it_1 == it_2) return  0;
	if      (it_1 == NULL) return  1;
	if      (it_2 == NULL) return -1;

	if      (it_1->key  ==  it_2->key) return  0;
	else if (it_1->key <    it_2->key) return  1;
	else if (it_1->key    > it_2->key) return -1;

	return 0;
}

TestSuite(np_skiplist);

Test(np_skiplist, np_skiplist_use, .description="test the implementation of a skiplist")
{
	np_skiplist_t skiplist;

	np_skiplist_init(&skiplist, _compare_double);

	sl_item_t d_a = { .key =  1, .value  =         3.1415      };
	sl_item_t d_b = { .key =  2, .value  =         1.0         }; 
	sl_item_t d_c = { .key =  4, .value  =         7.4321      };
	sl_item_t d_d = { .key =  8, .value  = 100000000.4         };
	sl_item_t d_e = { .key =  2, .value  =         2.333333333 };
	sl_item_t d_f = { .key =  3, .value  =         3.333333333 };
	sl_item_t d_g = { .key =  9, .value  =         9.333333333 };
	sl_item_t d_h = { .key = 13, .value =         13.333333333 };

	bool ret = true;
    cr_log_info("adding     to : %p (%d)    ", &d_a, d_a.key);
	ret = np_skiplist_add(&skiplist, &d_a);
	cr_expect(ret == true, "expect result of adding an element to be true");
	cr_expect(skiplist._num_elements == 1, "expect the element count to be one");

    cr_log_info("adding     to : %p (%d)    ", &d_b, d_b.key);
	ret = np_skiplist_add(&skiplist, &d_b);
	cr_expect(ret == true, "expect result of adding an element to be true");
	cr_expect(skiplist._num_elements == 2, "expect the element count to be two");

    cr_log_info("adding     to : %p (%d)    ", &d_c, d_c.key);
	ret = np_skiplist_add(&skiplist, &d_c);
	cr_expect(ret == true, "expect result of adding an element to be true");
	cr_expect(skiplist._num_elements == 3, "expect the element count to be tree");

    cr_log_info("adding     to : %p (%d)    ", &d_d, d_d.key);
	ret = np_skiplist_add(&skiplist, &d_d);
	cr_expect(ret == true, "expect result of adding an element to be true");
	cr_expect(skiplist._num_elements == 4, "expect the element count to be four");

    cr_log_info("adding     to : %p (%d)    ", &d_e, d_e.key);
	ret = np_skiplist_add(&skiplist, &d_e);
	cr_expect(ret == false, "expect result of adding an element to be true");
	cr_expect(skiplist._num_elements == 4, "expect the element count to be four");

    cr_log_info("removing from : %p (%d)    ", &d_b, d_b.key);
	ret = np_skiplist_remove(&skiplist, &d_b);
	cr_expect(ret == true, "expect result of removing an element to be true");
	cr_expect(skiplist._num_elements == 3, "expect the element count to be three");

    cr_log_info("adding     to : %p (%d)    ", &d_e, d_e.key);
	ret = np_skiplist_add(&skiplist, &d_e);
	cr_expect(ret == true, "expect result of adding an element to be true");
	cr_expect(skiplist._num_elements == 4, "expect the element count to be four");

	sl_item_t d_s = { .key = 5, .value = 0 };
	sl_item_t* d_s_result = &d_s;
    cr_log_info("searching for: %p (%d)    ", d_s_result, d_s_result->key);
	ret = np_skiplist_find(&skiplist, (void**) &d_s_result);
    // cr_log_info("returning    : %p (%d)    ", d_s_result, d_s_result->key);
	cr_expect(ret == false, "expect result of adding an element to be false");
	cr_expect(skiplist._num_elements == 4, "expect the element count to be one");
	// if (ret) {
	cr_expect(d_s_result->key   == 4, "expect the element key to be ...");
	cr_expect(d_s_result->value == 7.4321, "expect the element value to be ...");
	// }
	
	d_s_result = &d_d;
    cr_log_info("searching for: %p (%d)    ", d_s_result, d_s_result->key);
	ret = np_skiplist_find(&skiplist, (void**) &d_s_result);
    cr_log_info("returning    : %p (%d)    ", d_s_result, d_s_result->key);
	cr_expect(ret == true, "expect result of finding an element to be true");
	cr_expect(skiplist._num_elements == 4, "expect the element count to be one");
	if (ret) {
		cr_expect(d_s_result->key   == d_d.key, "expect the element key to be ...");
		cr_expect(d_s_result->value == d_d.value, "expect the element value to be ...");
	}

    cr_log_info("adding     to : %p (%d)    ", &d_f, d_f.key);
	ret = np_skiplist_add(&skiplist, &d_f);
	cr_expect(ret == true, "expect result of adding an element to be true");
	cr_expect(skiplist._num_elements == 5, "expect the element count to be five");

    cr_log_info("adding     to : %p (%d)    ", &d_g, d_g.key);
	ret = np_skiplist_add(&skiplist, &d_g);
	cr_expect(ret == true, "expect result of adding an element to be true");
	cr_expect(skiplist._num_elements == 6, "expect the element count to be six");
	
    cr_log_info("removing from : %p (%d)    ", &d_g, d_g.key);
	ret = np_skiplist_remove(&skiplist, &d_g);
	cr_expect(ret == true, "expect result of removing an element to be true");
	cr_expect(skiplist._num_elements == 5, "expect the element count to be five");

    cr_log_info("adding     to : %p (%d)    ", &d_h, d_h.key);
	ret = np_skiplist_add(&skiplist, &d_h);
	cr_expect(ret == true, "expect result of adding an element to be true");
	cr_expect(skiplist._num_elements == 6, "expect the element count to be six");

	np_skiplist_destroy(&skiplist);

}

// TestSuite(np_skiplist_t, .init=setup_list, .fini=teardown_list);
