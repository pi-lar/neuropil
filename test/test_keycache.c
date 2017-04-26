//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>

#include "event/ev.h"

#include "np_list.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "np_log.h"

void setup_keycache(void)
{
	// int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_KEY;
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_KEY;
	np_mem_init();
	np_log_init("test_keycache.log", log_level);

	_np_keycache_init ();
}
void teardown_keycache(void)
{
	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_run(EV_A_ EVRUN_NOWAIT);
}

TestSuite(np_keycache_t, .init=setup_keycache, .fini=teardown_keycache);

Test(np_keycache_t, _np_key_find_create, .description="test the finding/creation of keys")
{
	np_key_t* new_keys[10];
	for (int i=0; i < 9; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i};

		new_keys[i] = _np_key_find_create(key);
	}

	for (int i=0; i < 9; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i };

		np_key_t* new_key = _np_key_find_create(key);
		cr_expect(new_keys[i] == new_key, "expect the key of the same dhkey to be already in the cache");
	}

	for (int i=10; i < 19; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i };

		np_key_t* new_key = _np_key_find_create(key);
		cr_expect(new_keys[i] != new_key, "expect the key to be different to the ones already in the cache");
	}


	clock_t begin = clock();
	for (int i=1000; i < 1999; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i };

		np_key_t* new_key = _np_key_find_create(key);
		cr_expect(NULL != new_key, "expect the key to be different to the ones already in the cache");
	}
	clock_t end = clock();
	double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	log_msg(LOG_INFO | LOG_KEY, "insertion of 999 key's took %f seconds", time_spent);
}

Test(np_keycache_t, _np_key_find, .description="test the finding of keys")
{
	for (int i=20; i < 29; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i };

		np_key_t* new_key = _np_key_find(key);
		cr_expect(NULL == new_key, "expect the key not to be already in the cache");
	}

	for (int i=20; i < 29; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i };

		np_key_t* new_key = _np_key_find_create(key);
		cr_expect(NULL != new_key, "expect the key to be create in the cache");
	}

	for (int i=20; i < 29; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i };

		np_key_t* new_key = _np_key_find(key);
		cr_expect(NULL != new_key, "expect the key to be already in the cache");
	}

	for (int i=1000; i < 1999; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i };
		_np_key_find_create(key);
	}

	clock_t begin = clock();
	for (int i=1000; i < 1999; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i };

		np_key_t* new_key = _np_key_find(key);
		cr_expect(NULL != new_key, "expect the key to be already in the cache");
	}
	clock_t end = clock();
	double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	log_msg(LOG_INFO | LOG_KEY, "lookup of 999 key's took %f seconds", time_spent);
}

// np_key_t* _np_key_remove(np_dhkey_t key);
Test(np_keycache_t, _np_key_remove, .description="test the removal of keys")
{
	np_key_t* new_keys[10];
	for (int i=0; i < 9; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i};

		new_keys[i] = _np_key_find_create(key);
	}

	for (int i=0; i < 9; i++)
	{
		np_key_t* not_in_cache_anymore = NULL;
		np_dhkey_t remove_key = new_keys[i]->dhkey;

		not_in_cache_anymore = _np_key_remove(remove_key);

		cr_expect(NULL != not_in_cache_anymore, "expect remove to return a key");
		cr_expect(new_keys[i] == not_in_cache_anymore, "expect removed key to be the one in array");
		cr_expect(NULL == _np_key_find(remove_key), "expect find to return NULL after removal of key");

		np_key_t* in_cache_again = _np_key_find_create(remove_key);
		cr_expect(NULL != in_cache_again, "expect find_create to return a new key");
		cr_expect(new_keys[i] != in_cache_again, "expect new key to be different than removed one");
	}
}

// char* _key_as_str(np_key_t * key);
Test(np_keycache_t, _key_as_str, .description="test the creation of a string dhkey representation")
{
	np_key_t* new_keys[10];
	for (int i=0; i < 9; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i};

		new_keys[i] = _np_key_find_create(key);
	}

	for (int i=0; i < 9; i++)
	{
		char* test_string = _key_as_str(new_keys[i]);
		cr_expect (64 == strlen(test_string), "expect the length of the dh string to be 65 (without null terminating character)");

		char* test_string_2 = _key_as_str(new_keys[i]);
		cr_expect (test_string == test_string_2, "expect dh string not to change when called a second time");
	}

}

// np_key_t* _np_find_closest_key (np_sll_t(np_key_t, list_of_keys), np_dhkey_t* key);
Test(np_keycache_t, _np_find_closest_key, .description="test the finding of the closest key")
{
	np_key_t* new_keys[10];
	np_sll_t(np_key_t, key_list);
	sll_init(np_key_t, key_list);

	np_dhkey_t dummy_key = { .t[0] = 99, .t[1] = 99, .t[2] = 99, .t[3] = 99};
	np_key_t* found = _np_find_closest_key(key_list, &dummy_key);
	cr_expect(NULL == found, "expecting a NULL result for searching an empty list");

	for (int i=0; i < 9; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i};

		new_keys[i] = _np_key_find_create(key);
		sll_append(np_key_t, key_list, new_keys[i]);
	}

 	found = _np_find_closest_key(key_list, &new_keys[1]->dhkey);
	cr_expect(found = new_keys[1], "expecting the closest key to be the first in an array");
 	found = _np_find_closest_key(key_list, &dummy_key);
	cr_expect(found = new_keys[9], "expecting the closest key to be the last in an array");
}

// void _np_sort_keys_cpm (np_sll_t(np_key_t, node_keys), np_dhkey_t* key);
Test(np_keycache_t, _np_sort_keys_cpm, .description="sort a list of key based on common prefix and key distance")
{
	np_key_t* new_keys[200];
	np_sll_t(np_key_t, key_list);
	sll_init(np_key_t, key_list);

	np_dhkey_t dummy_key = { .t[0] = 99, .t[1] = 99, .t[2] = 99, .t[3] = 99};

	for (int i=0; i < 199; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i};

		new_keys[i] = _np_key_find_create(key);
		sll_append(np_key_t, key_list, new_keys[i]);
	}

	_np_sort_keys_cpm(key_list, &dummy_key);
	cr_expect(0 == _dhkey_comp(&dummy_key, &sll_first(key_list)->val->dhkey), "expect the first key to be the dummy key");

	for (int i=0; i < 199; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i};
		cr_expect(0 == _dhkey_comp(&new_keys[i]->dhkey, &key), "expect the original key to have the same value");
	}
}

// void _np_sort_keys_kd (np_sll_t(np_key_t, list_of_keys), np_dhkey_t* key);
Test(np_keycache_t, _np_sort_keys_kd, .description="sort a list of key based on key distance")
{
	np_key_t* new_keys[200];
	np_sll_t(np_key_t, key_list);
	sll_init(np_key_t, key_list);

	np_dhkey_t dummy_key = { .t[0] = 99, .t[1] = 99, .t[2] = 99, .t[3] = 99};

	for (int i=0; i < 199; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i};

		new_keys[i] = _np_key_find_create(key);
		sll_append(np_key_t, key_list, new_keys[i]);
	}

	_np_sort_keys_kd(key_list, &dummy_key);
	cr_expect(0 == _dhkey_comp(&dummy_key, &sll_first(key_list)->val->dhkey), "expect the first key to be the dummy key");

	for (int i=0; i < 199; i++)
	{
		np_dhkey_t key = { .t[0] = i, .t[1] = i, .t[2] = i, .t[3] = i};
		cr_expect(0 == _dhkey_comp(&new_keys[i]->dhkey, &key), "expect the original key to have the same value");
	}
}

