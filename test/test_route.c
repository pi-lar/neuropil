//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>

#include <criterion/criterion.h>

#include "np_keycache.h"
#include "np_log.h"
#include "np_memory.h"

#include "np_route.h"

void setup_route(void)
{
	np_key_t* me = NULL;

	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING;
	np_log_init("test_route.log", log_level);

	_np_dhkey_init();
	np_mem_init();

	np_dhkey_t my_dhkey = np_dhkey_create_from_hostport("pi-lar", "0");
	np_new_obj(np_key_t, me);
	me->dhkey = my_dhkey;

	_np_route_init(me);
}

void teardown_route(void)
{
	np_log_destroy();
}

TestSuite(np_route_t, .init=setup_route, .fini=teardown_route);

Test(np_route_t, _leafset_update, .description="test the addition/removal of keys into the leafset")
{
	int16_t keys_in_leafset = 0;
	np_key_t* my_keys[128];

	for (int i = 0; i < 128; i++)
	{
		char str[15];
		sprintf(str, "%0d", i+1);
		np_dhkey_t my_dhkey = np_dhkey_create_from_hostport("pi-lar", str);
		np_key_t *insert_key = NULL;
		np_new_obj(np_key_t, insert_key);
		insert_key->dhkey = my_dhkey;
		log_msg(LOG_DEBUG, "created key %s", _np_key_as_str(insert_key));

		my_keys[i] = insert_key;
		np_key_t *added = NULL, *deleted = NULL;
		leafset_update(my_keys[i], TRUE, &deleted, &added);

		if (NULL != added)
		{
			cr_expect(0 == _np_dhkey_comp(&insert_key->dhkey, &added->dhkey), "test whether the new key was added");
			keys_in_leafset++;
		}
		else
		{
			cr_expect(NULL == added, "test whether no new key was added");
			// cr_expect(NULL == deleted, "test whether no new key was deleted");
			log_msg(LOG_DEBUG, "key %s not added to the leafset", _np_key_as_str(insert_key));
		}

		if (NULL != deleted)
		{
			cr_expect(0 != _np_dhkey_comp(&insert_key->dhkey, &deleted->dhkey), "test whether a different key was deleted");
			keys_in_leafset--;
		}
	}

	// removing keys from leafset
	for (int i = 0; i < 128; i++)
	{
		np_key_t *added = NULL, *deleted=NULL;
		leafset_update(my_keys[i], FALSE, &deleted, &added);
		if (NULL != deleted)
		{
			cr_expect(0 == _np_dhkey_comp(&my_keys[i]->dhkey, &deleted->dhkey), "test whether the same key was removed");
			keys_in_leafset--;
		}
	}

	cr_expect(0 == keys_in_leafset , "test whether the leafset is empty");
}
// TODO: write more tests for the routing table and leafset arrays
//Test(np_route_t, _leafset_lookup, .description="test the lookup of keys from the leafset")
//{
//
//}
//
Test(np_route_t, _route_create, .description="test the insert of keys into the routing table")
{
	int routing_table_size = 64*16*3; // keysize * hex * alternatives
	int current_size = 0;

	np_sll_t(np_key_t, my_keys);
	sll_init(np_key_t, my_keys);
	unsigned long i = 0;

	// TODO: seems to run forever with no check for i :-/ better reduce the loglevel to save my laptop
	np_log_setlevel(LOG_ERROR | LOG_WARN | LOG_ROUTING);
	// TODO: check whether routing table implementation is correct
	// even with 4M generated dhkeys there are only 55 entries in the table ...
	while (current_size < routing_table_size &&
			i < 1000000)
	{
		char tmp_1[33];
		randombytes_buf(tmp_1, 16);
		sodium_bin2hex(tmp_1, 33, (unsigned char*) tmp_1, 16);
		char tmp_2[33];
		randombytes_buf(tmp_2, 16);
		sodium_bin2hex(tmp_2, 33, (unsigned char*) tmp_2, 16);

		// sprintf(str, "%0d", i);
		np_dhkey_t my_dhkey = np_dhkey_create_from_hostport(tmp_2, tmp_1);

		np_key_t *insert_key = NULL;
		np_new_obj(np_key_t, insert_key);
		insert_key->dhkey = my_dhkey;

		np_new_obj(np_node_t, insert_key->node);
		insert_key->node->latency = ((double) rand()) / 1000;

		log_msg(LOG_DEBUG, "created key %s", _np_key_as_str(insert_key));

		np_key_t *added=NULL, *deleted=NULL;
		route_update(insert_key, TRUE, &deleted, &added);

		if (NULL != added)
		{
			cr_expect(0 == _np_dhkey_comp(&insert_key->dhkey, &added->dhkey), "test whether the new key was added");
			current_size++;
			sll_append(np_key_t, my_keys, insert_key);
		}
		else
		{
			log_msg(LOG_DEBUG, "key %s not added to the leafset", _np_key_as_str(insert_key));
			np_free_obj(np_node_t, insert_key->node);
			np_free_obj(np_key_t, insert_key);
		}

		if (NULL != deleted)
		{
			cr_expect(0 != _np_dhkey_comp(&insert_key->dhkey, &deleted->dhkey), "test whether a different key was deleted");
			current_size--;

			sll_iterator(np_key_t) iter = sll_first(my_keys);
			while (NULL != iter)
			{
				if (0 == _np_dhkey_comp(&iter->val->dhkey, &deleted->dhkey))
				{
					sll_delete(np_key_t, my_keys, iter);
					break;
				}
				sll_next(iter);
			}

			np_free_obj(np_node_t, deleted->node);
			np_free_obj(np_key_t, deleted);
		}
		log_msg(LOG_INFO, "routing table now contains %d entries / %lu inserted", current_size, i+1);
		i++;
	}
}

//Test(np_route_t, _route_lookup, .description="test the lookup of routing keys from the routing table")
//{
//
//}
