/*
 * np_scache.h
 *
 *  Created on: 12.04.2017
 *      Author: sklampt
 */

#ifndef NP_SCACHE_H_
#define NP_SCACHE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "neuropil.h"
#include "np_list.h"
#include "np_memory.h"
#include "np_threads.h"

#define SIMPLE_CACHE_NR_BUCKETS 32

struct np_cache_item_s {
    char *key;
    void *value;
    double insert_time;
} NP_API_EXPORT;

typedef struct np_cache_item_s np_cache_item_t;
typedef np_cache_item_t* np_cache_item_ptr;

NP_SLL_GENERATE_PROTOTYPES(np_cache_item_ptr);

struct np_simple_cache_table_s {
    np_sll_t(np_cache_item_ptr, buckets[SIMPLE_CACHE_NR_BUCKETS] );
    np_mutex_t lock;
} NP_API_EXPORT;
typedef struct np_simple_cache_table_s np_simple_cache_table_t;


NP_API_EXPORT
np_simple_cache_table_t* np_cache_init(uint32_t size);

NP_API_EXPORT
np_cache_item_t* np_simple_cache_get(np_simple_cache_table_t* table, const char* const key);

NP_API_EXPORT
int np_simple_cache_insert(np_simple_cache_table_t* table, const char* const key, void *value);

NP_API_INTERN
unsigned int _np_simple_cache_strhash(const char* const str);


#ifdef __cplusplus
}
#endif


#endif /* NP_SCACHE_H_ */
