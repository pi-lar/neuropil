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

#define SIMPLE_CACHE_NR_BUCKETS 32

NP_API_EXPORT
struct np_cache_item_t {
    char *key;
    void *value;
    struct np_cache_item_t *next;
};
typedef struct np_cache_item_t np_cache_item_t;

NP_API_EXPORT
struct np_simple_cache_table_t {
    struct np_cache_item *buckets[SIMPLE_CACHE_NR_BUCKETS];
    void (*free_key)(char *);
    void (*free_value)(void*);
};
typedef struct np_simple_cache_table_t np_simple_cache_table_t;

NP_API_EXPORT
void* np_simple_cache_get(struct np_simple_cache_table_t* table, const char *key);
NP_API_EXPORT
int np_simple_cache_insert(struct np_simple_cache_table_t* table,char *key, void *value);
NP_API_INTERN
unsigned int _np_simple_cache_strhash(const char *str);

#ifdef __cplusplus
}
#endif


#endif /* NP_SCACHE_H_ */
