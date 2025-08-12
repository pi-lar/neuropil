//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// Based upon http://stackoverflow.com/a/1234738

#include "util/np_scache.h"

#include "inttypes.h"
#include "stdlib.h"

#include "util/np_list.h"

#include "np_legacy.h"
#include "np_log.h"
#include "np_threads.h"
#include "np_util.h"

// start of sll list code generation
int8_t np_cache_item_t_sll_compare_type(np_cache_item_t const a,
                                        np_cache_item_t const b) {
  return memcmp(a.key, b.key, NP_FINGERPRINT_BYTES);
  // return strncmp(a.key, b.key, strnlen(a.key, 255));
}

NP_SLL_GENERATE_IMPLEMENTATION(np_cache_item_t);
// end of sll list code generation

void np_cache_init(np_state_t              *context,
                   np_simple_cache_table_t *table,
                   const uint16_t           size,
                   const unsigned char     *seed) {
  table->_bucket_size = size;
  memcpy(table->_seed, seed, crypto_shorthash_KEYBYTES);

  table->_bucket = calloc(table->_bucket_size, sizeof(np_cache_item_t_sll_t));
  table->_bucket_guard = calloc(table->_bucket_size, sizeof(np_spinlock_t));

  for (uint16_t i = 0; i < table->_bucket_size; i++) {
    np_spinlock_init((&table->_bucket_guard[i]), PTHREAD_PROCESS_PRIVATE);
  }
}

void np_cache_destroy(np_state_t *context, np_simple_cache_table_t *cache) {
  for (uint16_t i = 0; i < cache->_bucket_size; i++) {
    sll_iterator(np_cache_item_t) iter_bucket_item =
        sll_first(&cache->_bucket[i]);
    while (iter_bucket_item != NULL) {
      if (iter_bucket_item->val.key != NULL) {
        free(iter_bucket_item->val.key);
      }
      sll_next(iter_bucket_item);
    }
    sll_clear(np_cache_item_t, &cache->_bucket[i]);
    np_spinlock_destroy(&cache->_bucket_guard[i]);
  }

  free(cache->_bucket);
  free((void *)cache->_bucket_guard);
}

bool np_simple_cache_get(np_state_t                    *context,
                         const np_simple_cache_table_t *table,
                         const char *const              key,
                         void                         **value) {
  ASSERT(key != NULL, "cache key cannot be NULL!");

  bool ret = false;

  unsigned char bucket_hash[crypto_shorthash_BYTES];
  uint64_t      bucket_bigint = 0;
  crypto_shorthash_siphash24(bucket_hash,
                             (const unsigned char *)key,
                             NP_FINGERPRINT_BYTES,
                             table->_seed);
  memcpy(&bucket_bigint, &bucket_hash[0], crypto_shorthash_BYTES);
  uint16_t bucket =
      ((uint16_t)(bucket_bigint) & 0xffff) % (table->_bucket_size);

  // log_debug(LOG_DEBUG, NULL, "cache::get() %d -> %s (%d)", bucket, key,
  // sll_size(&table->_bucket[bucket]));
  np_spinlock_lock(&table->_bucket_guard[bucket]);
  {
    sll_iterator(np_cache_item_t) iter = sll_first(&table->_bucket[bucket]);
    while (NULL != iter) {
      if (NULL != iter->val.key &&
          memcmp(iter->val.key, key, NP_FINGERPRINT_BYTES) == 0) {
        *value = iter->val.value;
        ret    = true;
        break;
      }
      sll_next(iter);
    }
  }
  np_spinlock_unlock(&table->_bucket_guard[bucket]);
  return ret;
}

bool np_simple_cache_add(np_state_t                    *context,
                         const np_simple_cache_table_t *table,
                         const char *const              key,
                         void                          *value) {
  // Contract
  ASSERT(key != NULL, "cache key cannot be NULL!");
  // Contract end

  bool ret = false;

  char *internal_key = malloc((NP_FINGERPRINT_BYTES + 1) * sizeof(char));
  internal_key[NP_FINGERPRINT_BYTES] = '\0';
  memcpy(internal_key, key, NP_FINGERPRINT_BYTES);

  unsigned char bucket_hash[crypto_shorthash_BYTES];
  uint64_t      bucket_bigint = 0;
  crypto_shorthash_siphash24(bucket_hash,
                             (const unsigned char *)internal_key,
                             NP_FINGERPRINT_BYTES,
                             table->_seed);
  memcpy(&bucket_bigint, &bucket_hash[0], crypto_shorthash_BYTES);
  uint16_t bucket =
      ((uint16_t)(bucket_bigint) & 0xffff) % (table->_bucket_size);

  // log_debug(LOG_DEBUG, NULL, "cache::add() %d -> %s (%d)", bucket,
  // internal_key, sll_size(&table->_bucket[bucket]));
  np_spinlock_lock(&table->_bucket_guard[bucket]);
  {
    bool found                         = false;
    sll_iterator(np_cache_item_t) iter = sll_first(&table->_bucket[bucket]);
    while (NULL != iter) {
      if (NULL != iter->val.key &&
          memcmp(iter->val.key, key, NP_FINGERPRINT_BYTES) == 0) {
        found = true;
        break;
      }
      sll_next(iter);
    }

    if (!found) {
      np_cache_item_t item = {.insert_time = np_time_now(),
                              .key         = internal_key,
                              .value       = value};
      sll_append(np_cache_item_t, &table->_bucket[bucket], item);
      ret = true;
    } else {
      free(internal_key);
    }
  }
  np_spinlock_unlock(&table->_bucket_guard[bucket]);
  return ret;
}
