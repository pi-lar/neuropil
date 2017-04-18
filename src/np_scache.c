/*
 * np_scache.c
 *
 *  Created on: 12.04.2017
 *      Author: sklampt
 *
 *      Based upon http://stackoverflow.com/a/1234738
 */

#include <string.h>
#include <stdlib.h>
#include "np_scache.h"
#include "np_threads.h"
#include "np_log.h"
#include "inttypes.h"

void* np_simple_cache_get(struct np_simple_cache_table_t *table,
		const char *key) {

	if(NULL == key){
		log_msg(LOG_ERROR, "cache key cannot be NULL!");
		exit(EXIT_FAILURE);
	}
	unsigned int bucket = _np_simple_cache_strhash(key) % SIMPLE_CACHE_NR_BUCKETS;

	struct np_cache_item *item;
	item = table->buckets[bucket];
	while (item) {
		if (NULL != item->key && strcmp(key, item->key) == 0)
			return item->value;
		item = item->next;
	}

	return NULL;
}
int np_simple_cache_insert(struct np_simple_cache_table_t *table, char *key, void *value) {

	if(NULL == key){
		log_msg(LOG_ERROR, "cache key cannot be NULL!");
		exit(EXIT_FAILURE);
	}

	unsigned int bucket = _np_simple_cache_strhash(key) % SIMPLE_CACHE_NR_BUCKETS;

	struct np_cache_item **tmp;
	struct np_cache_item *item;

	tmp = &table->buckets[bucket];
	while (*tmp) {
		if (strcmp(key, (*tmp)->key) == 0)
			break;
		tmp = &(*tmp)->next;
	}
	if (*tmp) {
		if (table->free_key != NULL)
			table->free_key((*tmp)->key);
		if (table->free_value != NULL)
			table->free_value((*tmp)->value);
		item = *tmp;
	} else {
		item = malloc(sizeof *item);
		if (item == NULL){
			return -1;
		}
		item->next = NULL;
		*tmp = item;
	}
	item->key = key;
	item->value = value;

	return 0;
}

unsigned int _np_simple_cache_strhash(const char *str) {
	uint32_t hash = 0;
	for (; *str; str++)
		hash = 31 * hash + *str;
	return hash;
}
