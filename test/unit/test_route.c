//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <assert.h>
#include <inttypes.h>

#include <criterion/criterion.h>
#include <criterion/logging.h>

#include "np_keycache.h"
#include "neuropil_log.h"
#include "np_log.h"
#include "np_memory.h"

#include "np_threads.h"
#include "np_constants.h"

#include "np_route.h"

#include "../test_macros.c"

TestSuite(np_route_t );

Test(np_route_t, _leafset_update, .description = "test the addition/removal of keys into the leafset")
{
	CTX() {
		int16_t keys_in_leafset = 0;
		np_key_t* my_keys[128];

		for (int i = 0; i < 128; i++)
		{
			char str[15];
			sprintf(str, "%0d", i + 1);
			np_dhkey_t my_dhkey = np_dhkey_create_from_hostport( "pi-lar", str);
			np_key_t *insert_key = NULL;
			np_new_obj(np_key_t, insert_key);
			insert_key->dhkey = my_dhkey;
			log_debug_msg(LOG_DEBUG, "created key %s", _np_key_as_str(insert_key));

			my_keys[i] = insert_key;
			np_key_t *added = NULL, *deleted = NULL;
			_np_route_leafset_update(my_keys[i], true, &deleted, &added);

			if (NULL != added)
			{
				cr_expect(0 == _np_dhkey_cmp(&insert_key->dhkey, &added->dhkey), "test whether the new key was added");
				keys_in_leafset++;
			}
			else
			{
				cr_expect(NULL == added, "test whether no new key was added");
				// cr_expect(NULL == deleted, "test whether no new key was deleted");
				log_debug_msg(LOG_DEBUG, "key %s not added to the leafset", _np_key_as_str(insert_key));
			}

			if (NULL != deleted)
			{
				// cr_expect(0 != _np_dhkey_cmp(&insert_key->dhkey, &deleted->dhkey), "test whether a different key was deleted");
				keys_in_leafset--;
			}
		}

		// removing keys from leafset
		for (int i = 0; i < 128; i++)
		{
			np_key_t *added = NULL, *deleted = NULL;
			_np_route_leafset_update(my_keys[i], false, &deleted, &added);
			if (NULL != deleted)
			{
				cr_expect(0 == _np_dhkey_cmp(&my_keys[i]->dhkey, &deleted->dhkey), "test whether the same key was removed");
				keys_in_leafset--;
			}
		}

		cr_expect(0 == keys_in_leafset, "test whether the leafset is empty");
	}
}
// TODO: write more tests for the routing table and leafset arrays
//Test(np_route_t, _leafset_lookup, .description="test the lookup of keys from the leafset")
//{
//
//}
//
Test(np_route_t, _route_create, .description = "test the insert of keys into the routing table")
{
	CTX() {
		uint64_t current_size = 0;

		np_sll_t(np_key_ptr, my_keys);
		sll_init(np_key_ptr, my_keys);


		// TODO: seems to run forever with no check for i :-/ better reduce the loglevel to save my laptop
		np_log_setlevel(context, LOG_ERROR | LOG_WARNING | LOG_ROUTING | LOG_DEBUG | LOG_INFO | LOG_MEMORY);
		// TODO: check whether routing table implementation is correct
		// even with 4M generated dhkeys there are only 55 entries in the table ...
		uint64_t i = 0;
		uint64_t unique_keys = 0;

		for(; i < 4000 /*000*/; i++)
		{
			char tmp_1[33];
			sprintf(tmp_1, "%d", i);

			char tmp_2[33];
			randombytes_buf(tmp_2, 16);
			sodium_bin2hex(tmp_2, 33, (unsigned char*)tmp_2, 16);

			// sprintf(str, "%0d", i);
			np_dhkey_t my_dhkey = np_dhkey_create_from_hostport( tmp_2, tmp_1);

			np_key_t * insert_key = _np_keycache_find(context, my_dhkey);
			if(insert_key == NULL)
			{
				unique_keys++;
				insert_key = _np_keycache_create(context, my_dhkey);
				ref_replace_reason(np_key_t, insert_key, "_np_keycache_create", "_np_keycache_find_or_create");
				np_node_t* new_node = NULL;
				np_new_obj(np_node_t, new_node);
				insert_key->entity_array[2] = new_node;
				sll_append(np_key_ptr, my_keys, insert_key);
			}
			else
			{
				ref_replace_reason(np_key_t, insert_key, "_np_keycache_find", "_np_keycache_find_or_create");
			}

			NP_CAST(insert_key->entity_array[2], np_node_t, node);
			node->latency = ((double)rand()) / 1000;

			np_key_t *added = NULL, *deleted = NULL;
			_np_route_update(insert_key, true, &deleted, &added);

			if (NULL != added)
			{
				cr_expect(0 == _np_dhkey_cmp(&insert_key->dhkey, &added->dhkey), "test whether the new key was added");
				current_size++;
			}

			if (NULL != deleted)
			{
				cr_expect(0 != _np_dhkey_cmp(&insert_key->dhkey, &deleted->dhkey), "test whether a different key was deleted");
				current_size--;
			}

			if ((i % 1000) == 0)
			{
				cr_log_info(
					"routing table has %"PRIu64" of %"PRIu64" (%.0f%%) keys filled by %"PRIu64" inserted keys ",
					current_size, NP_ROUTES_TABLE_SIZE, ((float)current_size / (float) NP_ROUTES_TABLE_SIZE)*100, i);
			}
		}

		cr_log_info(
			"routing table has %"PRIu64" of %"PRIu64" (%.0f%%) keys filled by %"PRIu64" inserted keys ",
			current_size, NP_ROUTES_TABLE_SIZE, ((float)current_size / (float) NP_ROUTES_TABLE_SIZE)*100, i);

		sll_iterator(np_key_ptr) iter = sll_first(my_keys);
		while (NULL != iter)
		{
			// np_unref_obj(np_node_t, iter->val->node, ref_obj_creation);
			np_unref_obj(np_key_t, iter->val, "_np_keycache_find_or_create");
			sll_next(iter);
		}
	}
}
