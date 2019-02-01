//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include "np_route.h"

#include "../test/test_macros.c"
#include "../src/np_memory.c"
typedef struct test_struct
{
	unsigned int i_test;
	char* s_test;
} test_struct_t;


#undef cr_expect
#define cr_expect(A,B) assert((A) && B)
int main()
{
	CTX() {
		uint32_t routing_table_size = 64 * 16 * 3; // keysize * hex * alternatives
		uint32_t current_size = 0;

		np_sll_t(np_key_ptr, my_keys);
		sll_init(np_key_ptr, my_keys);
		unsigned long i = 0;

		// TODO: seems to run forever with no check for i :-/ better reduce the loglevel to save my laptop
		np_log_setlevel(context, LOG_ERROR | LOG_WARN | LOG_ROUTING | LOG_DEBUG | LOG_INFO | LOG_MEMORY);
		// TODO: check whether routing table implementation is correct
		// even with 4M generated dhkeys there are only 55 entries in the table ...
		while (current_size < routing_table_size &&
			i < (routing_table_size*5))
		{
			char tmp_1[33];
			randombytes_buf(tmp_1, 16);
			//memset(tmp_1, i, sizeof(i));
			sodium_bin2hex(tmp_1, 33, (unsigned char*)tmp_1, 16);
			char tmp_2[33];
			randombytes_buf(tmp_2, 16);
			sodium_bin2hex(tmp_2, 33, (unsigned char*)tmp_2, 16);

			// sprintf(str, "%0d", i);
			np_dhkey_t my_dhkey = np_dhkey_create_from_hostport( tmp_2, tmp_1);

			np_key_t *insert_key = NULL;
			np_new_obj(np_key_t, insert_key);
			insert_key->dhkey = my_dhkey;
			sll_append(np_key_ptr, my_keys, insert_key);

			np_new_obj(np_node_t, insert_key->node);
			insert_key->node->latency = ((double)rand()) / 1000;

			log_debug_msg(LOG_DEBUG, "created key %s", _np_key_as_str(insert_key));

			np_key_t *added = NULL, *deleted = NULL;
			_np_route_update(insert_key, true, &deleted, &added);

			if (NULL != added)
			{
				cr_expect(0 == _np_dhkey_cmp(&insert_key->dhkey, &added->dhkey), "test whether the new key was added");
				current_size++;
			}
			else
			{
				log_debug_msg(LOG_DEBUG, "key %s not added to the leafset", _np_key_as_str(insert_key));
			}

			if (NULL != deleted)
			{
				cr_expect(0 != _np_dhkey_cmp(&insert_key->dhkey, &deleted->dhkey), "test whether a different key was deleted");
				current_size--;

			}

			log_msg(LOG_ROUTING | LOG_INFO, "routing table now contains %d entries / %lu inserted", current_size, i + 1);
			i++;
		}

		sll_iterator(np_key_ptr) iter = sll_first(my_keys);
		while (NULL != iter)
		{		 
			np_unref_obj(np_node_t, iter->val->node, ref_obj_creation);
			np_unref_obj(np_key_t, iter->val, ref_obj_creation);
			sll_next(iter);
		}


	}
}
