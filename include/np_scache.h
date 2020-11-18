//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef NP_SCACHE_H_
#define NP_SCACHE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "sodium.h"

#include "np_list.h"
#include "np_threads.h"

/**
 * Implementation of a simple chaining hash table (aka simple cache -> scache)
 * The table can be split into n buckets, and each bucket holds a list of key value pairs.
 * Each item carries a copy of the key, the pointer of the value, plus an insert time stamp.
 * The user is responsible to clean up the values, copies of the keys will be destroyed.
 * In addition each bucket is protected by a simple spinlock from concurrent access, concurrent
 * access to different buckets is possible.
 * The simple hash table uses the libsodium siphash24 implementation and can be seeded with 
 * random data of crypto_shorthash_KEYBYTES (16 bytes) size.
 * 
 * TODO:
 * - add removal of key entries
 * - use different data structure instead of single linked list
 * - add extraction of contained keys (into a list / also per bucket)
 * - add check whether key exists (per bucket)
 * - dynamic resizing of used bucket size and contents
 *
 */

#define SIMPLE_CACHE_NR_BUCKETS 127 // a prime

struct np_cache_item_s 
{
    char *key;
    void *value;
    double insert_time;
};
typedef struct np_cache_item_s np_cache_item_t;

NP_SLL_GENERATE_PROTOTYPES(np_cache_item_t)

struct np_simple_cache_table_s 
{
    uint16_t _bucket_size;
    unsigned char _seed[crypto_shorthash_KEYBYTES];

    np_sll_t(np_cache_item_t, _bucket);
    np_spinlock_t *_bucket_guard;
};
typedef struct np_simple_cache_table_s np_simple_cache_table_t;

NP_API_EXPORT
void np_cache_init(np_state_t* context, np_simple_cache_table_t* table, const uint16_t size, const unsigned char* seed);

NP_API_EXPORT
void np_cache_destroy(np_state_t* context, np_simple_cache_table_t* cache);

NP_API_EXPORT
bool np_simple_cache_get(np_state_t* context, const np_simple_cache_table_t* table, const char* const key, void** value);

NP_API_EXPORT
bool np_simple_cache_add(np_state_t* context, const np_simple_cache_table_t* table, const char* const key, void *value);

#ifdef __cplusplus
}
#endif


#endif /* NP_SCACHE_H_ */
