//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>
#include <criterion/logging.h>
#include <inttypes.h>

#include "sodium.h"
#include "event/ev.h"

#include "np_scache.h"
#include "np_log.h"
#include "../test_macros.c"

 
TestSuite(np_scache_t);

Test(np_scache_t, np_simple_cache_insert, .description = "test the addition/retrieval of items to the scache")
{
	CTX() {
		uint32_t cache_size = SIMPLE_CACHE_NR_BUCKETS;
		np_simple_cache_table_t* cache_table = np_cache_init(context);

		// cr_expect(cache_size == (sizeof(cache_table->buckets) / sizeof(np_cache_item_ptr_sll_t)), "expect the size of the bucket list to be %d", cache_size);
		for (int i = 0; i < cache_size; i++) {
			cr_expect(0 == sll_size(cache_table->buckets[i]), "expect the size of the each cache list to be zero");
		}

		uint32_t num_entries = 0;
		uint32_t max_entries = 256;

		for (uint16_t j = 0; j < max_entries; j++) {
			char *key = malloc(sizeof(char) * 32);
			snprintf(key, 32, "%d", j);
			np_simple_cache_insert(context, cache_table, key, key);
			log_msg(LOG_DEBUG, "added new cache entry #%d: %s", j, key);

			for (uint32_t i = 0; i < cache_size; i++) {
				num_entries += sll_size(cache_table->buckets[i]);
			}
			// log_msg(LOG_DEBUG, "cache entries have %d <-> %d should", num_entries, j+1);
			cr_expect(num_entries == (j + 1), "expect the number of entries to be the same as we inserted");
			num_entries = 0;
		}

		// check distribution of hash manually
		for (uint32_t i = 0; i < cache_size; i++) {
			log_msg(LOG_DEBUG, "cache entry list size: %d", sll_size(cache_table->buckets[i]));
		}

		for (uint16_t j = 0; j < max_entries; j++) {
			char *key = malloc(sizeof(char) * 32);
			snprintf(key, 32, "%d", j);

			np_cache_item_t* item = np_simple_cache_get(context, cache_table, key);
			cr_expect(0 == strcmp(item->key, key), "test whether the retrieved key matches the requested key");
			cr_expect(0 == strcmp((char*)item->value, key), "test whether the retrieved value matches the expected value");
		}
	}
}

Test(np_scache_t, np_simple_cache_performance, .description = "test the performance of the simple cache")
{
	CTX() {
		uint32_t cache_size = SIMPLE_CACHE_NR_BUCKETS;
		np_simple_cache_table_t* cache_table = np_cache_init(context);

		uint32_t num_entries = 0;
		uint32_t max_entries = 256;

		double insert_arr[max_entries];
		double retrieve_arr[max_entries];

		for (uint16_t j = 0; j < max_entries; j++) {
			char *key = malloc(sizeof(char) * 1024);
			snprintf(key, 32, "%d", j);
			MEASURE_TIME(insert_arr, j, np_simple_cache_insert(context, cache_table, key, key));
		}

		for (uint16_t j = 0; j < max_entries; j++) {
			char *key = malloc(sizeof(char) * 1024);
			snprintf(key, 32, "%d", j);

			np_cache_item_t* item;

			MEASURE_TIME(retrieve_arr, j, item = np_simple_cache_get(context, cache_table, key));
		}

		cr_log_warn("###########\n");
		CALC_AND_PRINT_STATISTICS("scache insert  : ", insert_arr, max_entries);
		CALC_AND_PRINT_STATISTICS("scache retrieve: ", retrieve_arr, max_entries);
	}
}

