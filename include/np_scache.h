//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef _NP_SCACHE_H_
#define _NP_SCACHE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "np_types.h"
#include "np_list.h"
#include "np_threads.h"

#define SIMPLE_CACHE_NR_BUCKETS 128

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
np_simple_cache_table_t* np_cache_init(np_state_t* context);
NP_API_EXPORT
void np_cache_destroy(np_state_t* context, np_simple_cache_table_t* cache);


NP_API_EXPORT
np_cache_item_t* np_simple_cache_get(np_state_t* context, np_simple_cache_table_t* table, const char* const key);

NP_API_EXPORT
int np_simple_cache_insert(np_state_t* context, np_simple_cache_table_t* table, const char* const key, void *value);

NP_API_INTERN
unsigned int _np_simple_cache_strhash(const char* const str);


#ifdef __cplusplus
}
#endif


#endif /* NP_SCACHE_H_ */
