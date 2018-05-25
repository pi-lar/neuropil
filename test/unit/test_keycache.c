//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>

#include "event/ev.h"

#include "np_list.h"
#include "np_dhkey.h"
#include "np_keycache.h"
#include "np_memory.h"

#include "np_log.h"
#include "np_threads.h"

#include "../test_macros.c"

TestSuite(np_keycache_t);

Test(np_keycache_t, _np_keycache_create, .description = "test the creation of keys")
{
	CTX() {
		np_dhkey_t dhkey;
		dhkey.t[0] = 1;
		dhkey.t[1] = 2;
		dhkey.t[2] = 3;
		dhkey.t[3] = 4;
		dhkey.t[4] = 5;
		dhkey.t[5] = 6;
		dhkey.t[6] = 7;
		dhkey.t[7] = 8;

		np_key_t* key = _np_keycache_create(context, dhkey);

		cr_expect(NULL != key, "expect the key to be not null");

		cr_expect(TRUE == _np_dhkey_equal(&(key->dhkey), &dhkey), "expect the dhkey of the new key to be the same as the source one");
	}
}

Test(np_keycache_t, _np_keycache_find_or_create, .description = "test the finding/creation of keys")
{
	CTX() {
		np_key_t* new_keys[10];
		np_bool err = FALSE;
		for (int i = 0; i < 9; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };

			new_keys[i] = _np_keycache_find_or_create(context, key);
		}

		for (int i = 0; i < 9; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };

			np_key_t* new_key = _np_keycache_find_or_create(context, key);
			err = err || new_keys[i] == new_key;
		}
		cr_expect(err, "expect the key of the same dhkey to be already in the cache");
		err = FALSE;

		for (int i = 10; i < 19; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };

			np_key_t* new_key = _np_keycache_find_or_create(context, key);
			err = err || new_keys[i] != new_key;
		}
		cr_expect(err, "expect the key to be different to the ones already in the cache");
		err = FALSE;


		clock_t begin = clock();
		for (int i = 1000; i < 1999; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };

			np_key_t* new_key = _np_keycache_find_or_create(context, key);
			err = err || NULL != new_key;
		}
		cr_expect(err, "expect the key to be different to the ones already in the cache");
		err = FALSE;

		clock_t end = clock();
		double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		log_msg(LOG_INFO | LOG_KEY, "insertion of 999 key's took %f seconds", time_spent);
	}
}

Test(np_keycache_t, _np_keycache_find, .description = "test the finding of keys")
{
	CTX() {
		np_bool err = FALSE;

		for (int i = 20; i < 29; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };

			np_key_t* new_key = _np_keycache_find(context, key);
			err = err || NULL == new_key;
		}
		cr_expect(err, "expect the key not to be already in the cache");
		err = FALSE;

		for (int i = 20; i < 29; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };

			np_key_t* new_key = _np_keycache_find_or_create(context, key);
			err = err || NULL != new_key;
		}
		cr_expect(err, "expect the key to be create in the cache");
		err = FALSE;

		for (int i = 20; i < 29; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };

			np_key_t* new_key = _np_keycache_find(context, key);
			err = err || NULL != new_key;
		}
		cr_expect(err, "expect the key to be already in the cache");
		err = FALSE;

		for (int i = 1000; i < 1999; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };
			_np_keycache_find_or_create(context, key);
		}

		clock_t begin = clock();
		for (int i = 1000; i < 1999; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };

			np_key_t* new_key = _np_keycache_find(context, key);
			err = err || NULL != new_key;
		}
		clock_t end = clock();
		cr_expect(err, "expect the key to be already in the cache");
		err = FALSE;

		double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		log_msg(LOG_INFO | LOG_KEY, "lookup of 999 key's took %f seconds", time_spent);
	}
}

// np_key_t* _np_keycache_remove(np_dhkey_t key);
Test(np_keycache_t, _np_keycache_remove, .description = "test the removal of keys")
{
	CTX() {
		np_key_t* new_keys[10];
		for (int i = 0; i < 9; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };

			new_keys[i] = _np_keycache_find_or_create(context, key);
		}

		for (int i = 0; i < 9; i++)
		{
			np_key_t* not_in_cache_anymore = NULL;
			np_dhkey_t remove_key = new_keys[i]->dhkey;

			not_in_cache_anymore = _np_keycache_remove(context, remove_key);

			cr_expect(NULL != not_in_cache_anymore, "expect remove to return a key");
			cr_expect(new_keys[i] == not_in_cache_anymore, "expect removed key to be the one in array");
			cr_expect(NULL == _np_keycache_find(context, remove_key), "expect find to return NULL after removal of key");

			np_key_t* in_cache_again = _np_keycache_find_or_create(context, remove_key);
			cr_expect(NULL != in_cache_again, "expect find_create to return a new key");
			cr_expect(new_keys[i] != in_cache_again, "expect new key to be different than removed one");
		}
	}
}

// char* _np_key_as_str(np_key_t * key);
Test(np_keycache_t, _np_key_as_str, .description = "test the creation of a string dhkey representation")
{
	CTX() {
		np_key_t* new_keys[10];
		for (int i = 0; i < 9; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };

			new_keys[i] = _np_keycache_find_or_create(context, key);
		}

		for (int i = 0; i < 9; i++)
		{
			char* test_string = _np_key_as_str(new_keys[i]);
			cr_expect(64 == strlen(test_string), "expect the length of the dh string to be 65 (without null terminating character)");

			char* test_string_2 = _np_key_as_str(new_keys[i]);
			cr_expect(test_string == test_string_2, "expect dh string not to change when called a second time");
		}

	}
}

// np_key_t* _np_keycache_find_closest_key_to (np_sll_t(np_key_ptr, list_of_keys), np_dhkey_t* key);
Test(np_keycache_t, _np_keycache_find_closest_key_to, .description="test the finding of the closest key")
{
	CTX() {
		const int count_of_keys = 10;	//should be below 244
		np_sll_t(np_key_ptr, key_list);
		sll_init(np_key_ptr, key_list);

		np_dhkey_t dummy_key = {
			.t[0] = count_of_keys + 10,
			.t[1] = count_of_keys + 10,
			.t[2] = count_of_keys + 10,
			.t[3] = count_of_keys + 10,
			.t[4] = count_of_keys + 10,
			.t[5] = count_of_keys + 10,
			.t[6] = count_of_keys + 10,
			.t[7] = count_of_keys + 1
		};
		np_dhkey_t nearest_dummy_key = {
			.t[0] = count_of_keys,
			.t[1] = count_of_keys,
			.t[2] = count_of_keys,
			.t[3] = count_of_keys,
			.t[4] = count_of_keys,
			.t[5] = count_of_keys,
			.t[6] = count_of_keys,
			.t[7] = count_of_keys
		};

		np_key_t* found = _np_keycache_find_closest_key_to(context, key_list, &dummy_key);
		cr_expect(NULL == found, "expecting a NULL result for searching an empty list");

		int i;
		// add keys from up and down to add a litte shuffle
		for (i = 0; i < floor(count_of_keys / 2.); i++)
		{
			np_dhkey_t key = {
				.t[0] = i,
				.t[1] = i,
				.t[2] = i,
				.t[3] = i,
				.t[4] = i,
				.t[5] = i,
				.t[6] = i,
				.t[7] = i,
			};

			sll_append(np_key_ptr, key_list, _np_keycache_find_or_create(context, key));
		}
		for (i = count_of_keys; i >= floor(count_of_keys / 2.); i--)
		{
			np_dhkey_t key = {
				.t[0] = i,
				.t[1] = i,
				.t[2] = i,
				.t[3] = i,
				.t[4] = i,
				.t[5] = i,
				.t[6] = i,
				.t[7] = i,
			};

			sll_append(np_key_ptr, key_list, _np_keycache_find_or_create(context, key));
		}

		found = _np_keycache_find_closest_key_to(context, key_list, &dummy_key);

		cr_assert(NULL != found, "expecting to find the closest dhkey");

		cr_expect(0 == _np_dhkey_cmp(&found->dhkey, &nearest_dummy_key), "expecting to receive the closest key but not %s", _np_key_as_str(found));
	}
}

// void _np_keycache_sort_keys_cpm (np_sll_t(np_key_ptr, node_keys), np_dhkey_t* key);
Test(np_keycache_t, _np_keycache_sort_keys_cpm, .description = "sort a list of key based on common prefix and key distance")
{
	CTX() {
		np_key_t* new_keys[200];
		np_sll_t(np_key_ptr, key_list);
		sll_init(np_key_ptr, key_list);

		np_dhkey_t dummy_key = { .t[0] = 99,.t[1] = 99,.t[2] = 99,.t[3] = 99 };

		for (int i = 0; i < 199; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i };

			new_keys[i] = _np_keycache_find_or_create(context, key);
			sll_append(np_key_ptr, key_list, new_keys[i]);
		}

		_np_keycache_sort_keys_cpm(key_list, &dummy_key);
		cr_expect(0 == _np_dhkey_cmp(&dummy_key, &sll_first(key_list)->val->dhkey), "expect the first key to be the dummy key");

		for (int i = 0; i < 199; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i };
			cr_expect(0 == _np_dhkey_cmp(&new_keys[i]->dhkey, &key), "expect the original key to have the same value");
		}
	}
}

// void _np_keycache_sort_keys_kd (np_sll_t(np_key_ptr, list_of_keys), np_dhkey_t* key);
Test(np_keycache_t, _np_keycache_sort_keys_kd, .description = "sort a list of key based on key distance")
{
	CTX() {
		np_key_t* new_keys[200];
		np_sll_t(np_key_ptr, key_list);
		sll_init(np_key_ptr, key_list);

		np_dhkey_t dummy_key = { .t[0] = 99,.t[1] = 99,.t[2] = 99,.t[3] = 99,.t[4] = 99,.t[5] = 99,.t[6] =99,.t[7] = 99};

		for (int i = 0; i < 199; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };

			new_keys[i] = _np_keycache_find_or_create(context, key);
			sll_append(np_key_ptr, key_list, new_keys[i]);
		}

		_np_keycache_sort_keys_kd(key_list, &dummy_key);
		cr_expect(0 == _np_dhkey_cmp(&dummy_key, &sll_first(key_list)->val->dhkey), "expect the first key to be the dummy key");

		for (int i = 0; i < 199; i++)
		{
			np_dhkey_t key = { .t[0] = i,.t[1] = i,.t[2] = i,.t[3] = i,.t[4] = i,.t[5] = i,.t[6] = i,.t[7] = i };
			cr_expect(0 == _np_dhkey_cmp(&new_keys[i]->dhkey, &key), "expect the original key to have the same value");
		}
	}
}