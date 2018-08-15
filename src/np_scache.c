//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// Based upon http://stackoverflow.com/a/1234738

#include <string.h>
#include <stdlib.h>
#include "np_scache.h"
#include "np_list.h"

#include "np_scache.h"

#include "np_threads.h"
#include "np_log.h"
#include "neuropil.h"
#include "inttypes.h"

NP_SLL_GENERATE_IMPLEMENTATION(np_cache_item_ptr);

np_simple_cache_table_t* np_cache_init(np_state_t* context) {

	np_simple_cache_table_t* ret = 
		(np_simple_cache_table_t*)malloc(
		sizeof(np_simple_cache_table_t));
	CHECK_MALLOC(ret);
	_np_threads_mutex_init(context, &ret->lock,"simple cache");

	for (uint32_t i = 0; i < SIMPLE_CACHE_NR_BUCKETS; i++) { 
		sll_init(np_cache_item_ptr, ret->buckets[i]);
	}

	return ret; 
}

np_cache_item_t* np_simple_cache_get(np_state_t* context, np_simple_cache_table_t *table, const char* const key)
{
	log_trace_msg(LOG_TRACE, "start: np_cache_item_t* np_simple_cache_get(np_simple_cache_table_t *table, const char *key){");
	
	assert(NULL != key);

	np_cache_item_t* ret = NULL;
	_LOCK_ACCESS(&table->lock) {

		uint32_t bucket = _np_simple_cache_strhash(key) % SIMPLE_CACHE_NR_BUCKETS;

		np_sll_t(np_cache_item_ptr, bucket_list) = table->buckets[bucket];
		sll_iterator(np_cache_item_ptr) iter = sll_first(bucket_list);
		do
		{
			if(NULL != iter && NULL != iter->val && strcmp(iter->val->key, key) == 0){
				ret =  iter->val;
				break;
			}
		} while (NULL != ( sll_next(iter)) );
	}
	return ret;
}

int np_simple_cache_insert(np_state_t* context, np_simple_cache_table_t *table, const char* const key, void *value) {
	log_trace_msg(LOG_TRACE, "start: int np_simple_cache_insert(context, np_simple_cache_table_t *table, char *key, void *value) {");
	// Contract
	if(NULL == key){
		log_msg(LOG_ERROR, "cache key cannot be NULL!");
		abort();
	}
	// Contract end

	_LOCK_ACCESS(&table->lock){
		uint32_t bucket = _np_simple_cache_strhash(key) % SIMPLE_CACHE_NR_BUCKETS;

		np_sll_t(np_cache_item_ptr, bucket_list) = table->buckets[bucket];
		sll_iterator(np_cache_item_ptr) iter = sll_first(bucket_list);
		do
		{
			if(NULL != iter && NULL != iter->val && strcmp(iter->val->key, key) == 0){
				break;
			}
		} while (NULL != (sll_next(iter)) );

		np_cache_item_t* item;

		if(NULL == iter) {
			item = (np_cache_item_t*) malloc(sizeof (np_cache_item_t));
			CHECK_MALLOC(item);

			if(item < 0){
				log_msg(LOG_ERROR, "cannot allocate memory for np_cache_item");
			}
			sll_append(np_cache_item_ptr, bucket_list, item);
			item->key = strdup(key);
		}else{
			item = iter->val;
		}
		item->value = value;
		item->insert_time = np_time_now();
	}
	return 0;
}

uint32_t _np_simple_cache_strhash(const char* const str) {
	uint32_t hash = 0;
	const char* str_ptr = str;
	for (; *str_ptr; str_ptr++)
		hash = 31 * hash + *str_ptr;
	return hash;
}
