//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "np_memory.h"

#include <assert.h>
#include <float.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#include "sodium.h"

#include "neuropil.h"
#include "neuropil_log.h"

#include "core/np_comp_msgproperty.h"
#include "util/np_list.h"

#include "np_aaatoken.h"
#include "np_constants.h"
#include "np_crypto.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_message.h"
#include "np_messagepart.h"
#include "np_network.h"
#include "np_node.h"
#include "np_responsecontainer.h"
#include "np_settings.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_types.h"
#include "np_util.h"

/*
General workflow:
After you register a type with a known size a container will be created which
contains multiple memory blocks. Every block may contains exactly
count_of_items_per_block items + the configuration for each item. the
configuration of each item is preceeding to the memory of the item itself.

*/

typedef struct np_memory_container_s np_memory_container_t;
typedef struct np_memory_itemconf_s  np_memory_itemconf_t;
typedef np_memory_itemconf_t        *np_memory_itemconf_ptr;

NP_SLL_GENERATE_PROTOTYPES(np_memory_itemconf_ptr);

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_memory_itemconf_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_memory_itemconf_ptr);

np_module_struct(memory) {
  np_state_t            *context;
  np_memory_container_t *__np_memory_container[np_memory_types_MAX_TYPE];
};

struct np_memory_itemstat_s {
  double   time;
  uint32_t itemcount;
};

struct np_memory_container_s {
  np_module_struct(memory) * module;

  enum np_memory_types_e type;

  uint32_t count_of_items_per_block;
  uint32_t min_count_of_items;
  size_t   size_per_item;

  np_memory_on_new           on_new;
  np_memory_on_free          on_free;
  np_memory_on_refresh_space on_refresh_space;

  // np_mutex_t free_items_lock;
  TSP(np_sll_t(np_memory_itemconf_ptr, ), free_items);
  // np_mutex_t refreshed_items_lock;
  TSP(np_sll_t(np_memory_itemconf_ptr, ), refreshed_items);
  // np_mutex_t total_items_lock;
  TSP(np_sll_t(np_memory_itemconf_ptr, ), total_items);
  // np_mutex_t current_in_use_lock;
  TSP(uint32_t, current_in_use);

  bool                        itemstats_full;
  uint32_t                    itemstats_idx;
  struct np_memory_itemstat_s itemstats[10];
};

#define NP_MEMORY_CHECK_MEMORY_REFFING_MAGIC_NO 3223967591

struct np_memory_itemconf_s {
#ifdef NP_MEMORY_CHECK_MAGIC_NO
  uint32_t magic_no;
#endif
  np_memory_container_t *container;

  bool          in_use;
  bool          needs_refresh;
  np_spinlock_t access_lock;

  uint32_t ref_count;
  bool     persistent;
  char     id[NP_UUID_BYTES];
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
  np_sll_t(char_ptr, reasons);
#endif
};

#define NEXT_ITEMCONF(conf, skip)                                              \
  conf = (np_memory_itemconf_t *)(((char *)conf) +                             \
                                  (((skip) + 1) *                              \
                                   ((conf)->block->container->size_per_item +  \
                                    sizeof(np_memory_itemconf_t))));
#define GET_CONF(item)                                                         \
  ((np_memory_itemconf_t *)(((char *)item) - sizeof(np_memory_itemconf_t)))
#define GET_ITEM(config) (((char *)config) + sizeof(np_memory_itemconf_t))

#ifndef NP_MEMORY_CHECK_MAGIC_NO
#define np_check_magic_no(item)
#else
#define np_check_magic_no(item)                                                \
  ASSERT(GET_CONF(item)->magic_no == NP_MEMORY_CHECK_MEMORY_REFFING_MAGIC_NO,  \
         "MAGIC NO of memory item (%p) not satisfied",                         \
         item);
#endif

void __np_memory_delete_item(np_state_t            *context,
                             np_memory_container_t *container,
                             np_memory_itemconf_t  *item_config) {

#if NP_MEMORY_CHECK_MEMORY_REFFING
  if (sll_size(item_config->reasons) > 0) {
    char *flat = _sll_char_make_flat(context, item_config->reasons);
    log_msg(LOG_ERROR | LOG_MEMORY,
            item_config->id,
            "Object of type %s has still reasons on delete: Refs: %" PRIu32
            " reasons:(%s)",
            np_memory_types_str[container->type],
            item_config->ref_count,
            flat);
    free(flat);
  }
  sll_free(char_ptr, item_config->reasons);
#endif

  TSP_DESTROY(item_config->access);
  free(item_config);
}

void _np_memory_container_destroy(np_state_t            *context,
                                  np_memory_container_t *container) {
  sll_free(np_memory_itemconf_ptr, container->free_items);
  TSP_DESTROY(container->free_items);

  sll_free(np_memory_itemconf_ptr, container->refreshed_items);
  TSP_DESTROY(container->refreshed_items);

  sll_free(np_memory_itemconf_ptr, container->total_items);
  TSP_DESTROY(container->total_items);

  TSP_DESTROY(container->current_in_use);

  free(container);
}

#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
bool _np_memory_remove_reason(sll_return(char_ptr) sll, const char *cmp_obj) {
  bool ret                           = false;
  sll_iterator(char_ptr) iter_reason = sll_first(sll);

  while (ret == false && iter_reason != NULL) {
    ret = (0 == strncmp(iter_reason->val, cmp_obj, strlen(cmp_obj)) &&
           0 == strncmp(iter_reason->val + strlen(cmp_obj),
                        _NP_REF_REASON_SEPERATOR_CHAR,
                        _NP_REF_REASON_SEPERATOR_CHAR_LEN))
              ? true
              : false;
    if (ret == true) {
      free(iter_reason->val);
      sll_delete(char_ptr, sll, iter_reason);
      break;
    }
    sll_next(iter_reason);
  }
  return ret;
}
#else
#define _np_memory_remove_reason(a, b)
#endif

void _np_memory_delete_item(np_state_t *context,
                            void       *item,
                            char       *rm_reason,
                            bool        del_container) {
  np_memory_itemconf_t  *item_config = GET_CONF(item);
  np_memory_container_t *container   = item_config->container;

  _np_memory_remove_reason(item_config->reasons, rm_reason);

  sll_remove(np_memory_itemconf_ptr,
             container->free_items,
             item_config,
             np_memory_itemconf_ptr_sll_compare_type);
  sll_remove(np_memory_itemconf_ptr,
             container->refreshed_items,
             item_config,
             np_memory_itemconf_ptr_sll_compare_type);
  sll_remove(np_memory_itemconf_ptr,
             container->total_items,
             item_config,
             np_memory_itemconf_ptr_sll_compare_type);

  __np_memory_delete_item(context, container, item_config);
  if (del_container) {
    if (sll_size(container->total_items) != 0) {
#ifndef NP_MEMORY_CHECK_MEMORY_REFFING
      log_error(NULL,
                "Still has %" PRIu32 " object of type %s in cache",
                sll_size(container->total_items),
                np_memory_types_str[container->type]);
#endif
    }
    _np_memory_container_destroy(context, container);
  }
}

void _np_memory_destroy(np_state_t *context) {
  if (np_module_initiated(memory)) {
    np_module_var(memory);

    for (int type = 0; type < np_memory_types_MAX_TYPE; type++) {

      log_debug(LOG_MEMORY,
                NULL,
                "cleanup of memory elements of type %s",
                np_memory_types_str[type]);

      if (type == np_memory_types_np_thread_t) {
        // threads will be handled expleciet in np_threads_destroy
        continue;
      }
      np_memory_container_t *container = _module->__np_memory_container[type];
      if (container != NULL) {
        np_memory_itemconf_t *item_config;

        while ((item_config = sll_head(np_memory_itemconf_ptr,
                                       container->total_items)) != NULL) {
          if (item_config->in_use) {
            log_warn(LOG_MEMORY,
                     NULL,
                     "Still has a object of type %s in cache. Refs: %" PRIu32,
                     np_memory_types_str[type],
                     item_config->ref_count);
          }
          __np_memory_delete_item(context, container, item_config);
        }
        _np_memory_container_destroy(context, container);
      }
    }

    np_module_free(memory);
  }
}
void np_mem_printpool_reasons(np_state_t *context);

bool np_memory_log(np_state_t *context, NP_UNUSED np_util_event_t event) {

  char *printpool = np_mem_printpool(context, true, false);
  log_info(LOG_EXPERIMENT, NULL, "[memory] %s", printpool);
  free(printpool);
  np_mem_printpool_reasons(context);
}

bool _np_memory_init(np_state_t *context) {
  np_module_malloc(memory);

  for (int i = 0; i < np_memory_types_MAX_TYPE; i++) {
    _module->__np_memory_container[i] = NULL;
  }

#define np_register(type,                                                      \
                    items_per_block,                                           \
                    min_items,                                                 \
                    new_fn,                                                    \
                    free_fn,                                                   \
                    clear_fn)                                                  \
  np_memory_register_type(context,                                             \
                          np_memory_types_np_##type##_t,                       \
                          sizeof(np_##type##_t),                               \
                          items_per_block,                                     \
                          min_items,                                           \
                          new_fn,                                              \
                          free_fn,                                             \
                          clear_fn)
#define np_register_defaultobj(type, count_of_itens_in_block, min_count)       \
  np_register(type,                                                            \
              count_of_itens_in_block,                                         \
              min_count,                                                       \
              _np_##type##_t_new,                                              \
              _np_##type##_t_del,                                              \
              np_memory_clear_space);

  // np_register_defaultobj(message, sizeof(struct np_e2e_message_s), 4, 4);
  np_register_defaultobj(message, 4, 4);
  np_register_defaultobj(key, 4, 4);
  np_register_defaultobj(msgproperty_conf, 4, 4);
  np_register_defaultobj(msgproperty_run, 8, 8);
  np_register_defaultobj(thread, 1, 1);
  np_register_defaultobj(node, 4, 4);
  np_register_defaultobj(network, 4, 4);
  np_register_defaultobj(responsecontainer, 4, 4);
  np_register_defaultobj(messagepart, 4, 20);
  np_register_defaultobj(aaatoken, 4, 4);
  np_register_defaultobj(crypto, 4, 4);
  np_register_defaultobj(crypto_session, 4, 4);

#undef np_register
#undef np_register_defaultobj

  // np_memory_register_type(context, np_memory_types_np_job_t,
  // sizeof(np_job_t), 4, JOBQUEUE_MAX_SIZE, NULL, NULL, np_memory_clear_space);
  // np_memory_register_type(context, np_memory_types_np_jobargs_t,
  // sizeof(np_jobargs_t), 4, JOBQUEUE_MAX_SIZE/2, NULL, NULL,
  // np_memory_clear_space);

  np_memory_register_type(context,
                          np_memory_types_BLOB_1024,
                          MSG_CHUNK_SIZE_1024 + MSG_INSTRUCTIONS_SIZE,
                          8,
                          20,
                          NULL,
                          NULL,
                          np_memory_clear_space);
  // np_memory_register_type(context,
  //                         np_memory_types_BLOB_984_RANDOMIZED,
  //                         MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40,
  //                         4,
  //                         20,
  //                         NULL,
  //                         NULL,
  //                         np_memory_randomize_space);

  return true;
}

bool _np_memory_rtti_check(void *item, enum np_memory_types_e type) {
  if (item != NULL) {
    np_memory_itemconf_t *item_conf = GET_CONF(item);
    return (item_conf->container->type == type);
  }
  return false;
}

void __np_memory_space_increase(np_memory_container_t *container,
                                uint32_t               block_size) {
  assert(block_size < UINT32_MAX);

  np_ctx_decl(container->module->context);
  for (uint32_t j = 0; j < block_size; j++) {
    size_t whole_item_size =
        container->size_per_item + sizeof(np_memory_itemconf_t);

    np_memory_itemconf_t *conf = malloc(whole_item_size);
    CHECK_MALLOC(conf);
    // debugf("adding obj %p \n", conf);

    // conf init
    conf->container     = container;
    conf->in_use        = false;
    conf->needs_refresh = true;
    conf->ref_count     = 0;
    char *tmp           = conf->id;
    np_uuid_create("urn:np:memory:create_memory_container", 0, &tmp);
    log_debug(LOG_MEMORY,
              conf->id,
              "_Inc_    (%" PRIu32 ") object of type '%s'",
              conf->ref_count,
              np_memory_types_str[container->type]);

    conf->persistent = false;
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
    sll_init(char_ptr, conf->reasons);
#endif
#ifdef NP_MEMORY_CHECK_MAGIC_NO
    conf->magic_no = NP_MEMORY_CHECK_MEMORY_REFFING_MAGIC_NO;
#endif
    // char mutex_str[64];
    // snprintf(mutex_str, 63, "%s", "urn:np:memory:config");

    TSP_SCOPE(container->total_items) {
      TSP_INIT(conf->access);
      // {
      //     log_msg(LOG_ERROR,NULL,  "Could not create memory item lock for
      //     container type %"PRIu8, container->type);
      // }
      sll_append(np_memory_itemconf_ptr, container->total_items, conf);
    }
    TSP_SCOPE(container->free_items) {
      sll_append(np_memory_itemconf_ptr, container->free_items, conf);
    }
  }
}

void np_memory_register_type(np_state_t            *context,
                             enum np_memory_types_e type,
                             size_t                 size_per_item,
                             uint32_t               count_of_items_per_block,
                             uint32_t               min_count_of_items,
                             np_memory_on_new       on_new,
                             np_memory_on_free      on_free,
                             np_memory_on_refresh_space on_refresh_space) {
  if (np_module(memory)->__np_memory_container[type] == NULL) {
    np_memory_container_t *container = calloc(1, sizeof(np_memory_container_t));
    CHECK_MALLOC(container);

    container->module         = np_module(memory);
    container->itemstats_idx  = 0;
    container->itemstats_full = false;
    memset(container->itemstats, 0, sizeof(container->itemstats));
    container->size_per_item            = size_per_item;
    container->count_of_items_per_block = count_of_items_per_block;
    container->min_count_of_items       = min_count_of_items;
    container->on_new                   = on_new;
    container->on_free                  = on_free;
    container->on_refresh_space         = on_refresh_space;
    container->type                     = type;

    sll_init(np_memory_itemconf_ptr, container->free_items);
    TSP_INIT(container->free_items);

    sll_init(np_memory_itemconf_ptr, container->refreshed_items);
    TSP_INIT(container->refreshed_items);

    sll_init(np_memory_itemconf_ptr, container->total_items);
    TSP_INIT(container->total_items);

    TSP_INIT(container->current_in_use);

    int i = 0;
    while ((container->count_of_items_per_block * i) <
           container->min_count_of_items) {
      i++;
      __np_memory_space_increase(container,
                                 container->count_of_items_per_block);
    }

    np_module(memory)->__np_memory_container[container->type] = container;
    log_info(LOG_MEMORY,
             NULL,
             "Created memory container (%p) for type %" PRIu8 " at %p",
             container,
             type,
             np_module(memory)->__np_memory_container[container->type]);
    // }
    // else {
    //     log_msg(LOG_ERROR, NULL, "Could not create memory container lock");
    // }
  }
}

void __np_memory_refresh_space(np_memory_itemconf_t *config) {
  assert(config != NULL);
  // bool refreshed = false;
  np_memory_container_t *container = config->container;
  np_ctx_decl(container->module->context);
  void *data = GET_ITEM(config);

  if (config->in_use == false && config->needs_refresh == true) {
    config->ref_count  = 0;
    config->persistent = false;

#if NP_MEMORY_CHECK_MEMORY_REFFING
    char *tmp = config->id;
    np_uuid_create("urn:np:memory:refresh_memory_container", 0, &tmp);
    sll_clear(char_ptr, config->reasons);
#endif
    if (container->on_refresh_space != NULL) {
      container->on_refresh_space(context,
                                  container->type,
                                  container->size_per_item,
                                  data);
    }
    config->needs_refresh = false;
    // refreshed = true;
  }

  // return refreshed;
}

void __np_memory_itemstats_update(np_memory_container_t *container) {
  np_ctx_decl(container->module->context);
  np_spinlock_lock(&container->current_in_use_lock);
  {
    struct np_memory_itemstat_s *itemstat =
        &container->itemstats[container->itemstats_idx];
    itemstat->itemcount = container->current_in_use;
    itemstat->time      = np_time_now();

    container->itemstats_full =
        container->itemstats_full ||
        (container->itemstats_idx + 1) ==
            (sizeof(container->itemstats) / sizeof(container->itemstats[0]));
    container->itemstats_idx =
        ((1 + container->itemstats_idx) %
         (sizeof(container->itemstats) / sizeof(container->itemstats[0])));
  }
  np_spinlock_unlock(&container->current_in_use_lock);
}

double __np_memory_itemstats_get_growth(np_memory_container_t *container) {
  np_ctx_decl(container->module->context);

  double growth   = 0;
  double min_time = DBL_MAX;
  double max_time = 0;
  for (uint32_t i = 0; i < container->itemstats_idx; i++) {
    struct np_memory_itemstat_s itemstat =
        container->itemstats[container->itemstats_idx];
    min_time = fmin(min_time, itemstat.time);
    max_time = fmax(max_time, itemstat.time);
  }
  if (container->itemstats_full) {
    CALC_STATISTICS(
        container->itemstats,
        .itemcount,
        (sizeof(container->itemstats) / sizeof(container->itemstats[0])),
        itemstats_min,
        itemstats_max,
        itemstats_avg,
        itemstats_stddev);
    growth = (container->current_in_use - itemstats_avg) /
             (max_time == min_time ? 1 : max_time - min_time);
  }
  return growth;
}

bool __np_memory_space_decrease_nessecary(np_memory_container_t *container) {
  np_ctx_decl(container->module->context);
  bool ret = false;

  np_spinlock_lock(&container->refreshed_items_lock);
  {
    np_spinlock_lock(&container->current_in_use_lock);
    {
      np_spinlock_lock(&container->free_items_lock);
      {
        double growth = __np_memory_itemstats_get_growth(container);

        uint32_t total_free_space = sll_size(container->free_items) +
                                    sll_size(container->refreshed_items);
        uint32_t total_space_available =
            total_free_space + container->current_in_use;

        ret =
            /*decrease only if we have more then the min threshhold (failsafe)*/
            total_space_available >= (container->min_count_of_items +
                                      container->count_of_items_per_block) &&
            (
                /* decrease if the growth of items is negative for the measured
                   period, the grows is min as great as a block, and the growth
                   size is free*/
                (0 > growth &&
                 fabs(growth) > container->count_of_items_per_block &&
                 total_free_space > fabs(growth)) ||
                /*decrease if we only consume 75% or less of our space*/
                (container->current_in_use <= (total_space_available * 0.75))
                // false
            );
      }
      np_spinlock_unlock(&container->free_items_lock);
    }
    np_spinlock_unlock(&container->refreshed_items_lock);
  }
  np_spinlock_unlock(&container->current_in_use_lock);
  return ret;
}

bool __np_memory_space_increase_nessecary(np_memory_container_t *container) {
  np_ctx_decl(container->module->context);
  bool ret = false;

  np_spinlock_lock(&container->current_in_use_lock);
  {
    np_spinlock_lock(&container->refreshed_items_lock);
    {
      np_spinlock_lock(&container->free_items_lock);
      {
        double growth = __np_memory_itemstats_get_growth(container);

        uint32_t total_free_space = sll_size(container->free_items) +
                                    sll_size(container->refreshed_items);
        uint32_t total_space_available =
            total_free_space + container->current_in_use;

        ret = /*increase only if we have less then 50% free space (failsafe)*/
            total_free_space < (total_space_available * 0.5) &&
            // (
            /* increase if we already consumed more then 90% of the available
               space */
            // container->current_in_use >= (total_space_available * 0.9) ||
            /*increase if the growth of items is positive for the mesured
            period, and the growth is greater then our free space*/
            (0 < growth && growth > total_free_space)
            //     )
            ;
      }
      np_spinlock_unlock(&container->free_items_lock);
    }
    np_spinlock_unlock(&container->refreshed_items_lock);
  }
  np_spinlock_unlock(&container->current_in_use_lock);
  return ret;
}

void __np_memory_space_decrease(np_memory_container_t *container) {
  np_ctx_decl(container->module->context);
  np_memory_itemconf_t *item_config;

  for (uint32_t j = 0; j < container->count_of_items_per_block; j++) {
    // best pick: a free container (not refreshed)
    np_spinlock_lock(&container->free_items_lock);
    {
      item_config = sll_head(np_memory_itemconf_ptr, container->free_items);
    }
    np_spinlock_unlock(&container->free_items_lock);

    if (item_config == NULL) {
      np_spinlock_lock(&container->refreshed_items_lock);
      {
        // second best pick: an refreshed container
        item_config =
            sll_head(np_memory_itemconf_ptr, container->refreshed_items);
      }
      np_spinlock_unlock(&container->refreshed_items_lock);
    }

    if (item_config != NULL) {
      np_spinlock_lock(&item_config->access_lock);
      {
        ASSERT(item_config->in_use == false,
               "can only delete unused memory objects");
      }
      np_spinlock_unlock(&item_config->access_lock);

      np_spinlock_lock(&container->total_items_lock);
      {
        sll_remove(np_memory_itemconf_ptr,
                   container->total_items,
                   item_config,
                   np_memory_itemconf_ptr_sll_compare_type);
      }
      np_spinlock_unlock(&container->total_items_lock);

      __np_memory_delete_item(context, container, item_config);
    } else {
      // removed everything, lists are now empty
      break;
    }
  }
}

void *np_memory_new(np_state_t *context, enum np_memory_types_e type) {

  void                  *ret = NULL;
  np_memory_container_t *container =
      np_module(memory)->__np_memory_container[type];
  ASSERT(container != NULL,
         "Memory container %" PRIu32 " needs to be initialized first.",
         type);

  log_debug(LOG_MEMORY | LOG_DEBUG,
            NULL,
            "Searching for next free current_block for type %" PRIu32,
            type);

  np_memory_itemconf_t *next_config;
  bool                  found = false;

  do {
    next_config = NULL; // init loop condition

    while (next_config == NULL) {
      TSP_SCOPE(container->refreshed_items) {
        // best pick: an already refreshed container
        next_config =
            sll_head(np_memory_itemconf_ptr, container->refreshed_items);

        if (next_config == NULL) {
          // second best pick: a free container
          TSP_SCOPE(container->free_items) {
            next_config =
                sll_head(np_memory_itemconf_ptr, container->free_items);
          }

          // worst case: create a new item
          uint8_t increase_mod = 1;
          while (next_config == NULL) {
            __np_memory_space_increase(
                container,
                increase_mod++); // cannot be in the free items lock due to lock
                                 // order
            TSP_SCOPE(container->free_items) {
              next_config =
                  sll_head(np_memory_itemconf_ptr, container->free_items);
            }
          }

          // second best as we need to refresh the item
          TSP_SCOPE(next_config->access) {
            __np_memory_refresh_space(next_config);
          }
        }
      }
    }
    // now we do have a item space. we need to check if the space is already in
    // use (should not but better play safe)
    TSP_SCOPE(next_config->access) {
      if (next_config->in_use == false) {
        // take free space
        found               = true;
        next_config->in_use = true;
      }
    }
  } while (found == false);

  TSP_SCOPE(container->current_in_use) { container->current_in_use += 1; }

  ret = GET_ITEM(next_config);

  log_debug(LOG_MEMORY,
            next_config->id,
            "_New_    (%" PRIu32 ") object of type '%s'",
            next_config->ref_count,
            np_memory_types_str[container->type]);

  if (container->on_new != NULL)
    container->on_new(context, container->type, container->size_per_item, ret);

  return ret;
}

np_state_t *np_memory_get_context(void *item) {
  assert(item != NULL);
  np_state_t *ret = NULL;
  np_check_magic_no(item);

  np_memory_itemconf_t *config = GET_CONF(item);
  assert(config != NULL);
  assert(config->container != NULL);
  assert(config->container->module != NULL);
  assert(config->container->module->context != NULL);

  ret = config->container->module->context;

  return ret;
}

void np_memory_free(np_state_t *context, void *item) {
  if (item != NULL) {
    np_check_magic_no(item);
    np_memory_itemconf_t  *config    = GET_CONF(item);
    np_memory_container_t *container = config->container;

    bool rm = false;
    TSP_SCOPE(config->access) {
      rm = (config->ref_count == 0 && !config->persistent) && config->in_use;
      if (rm) {
        assert(config->in_use);
        config->in_use = false;

        if (container->on_free != NULL)
          container->on_free(context,
                             container->type,
                             container->size_per_item,
                             item);

        if (container->on_refresh_space != NULL) {
          config->needs_refresh = true;
          TSP_SCOPE(container->free_items) {
            sll_append(np_memory_itemconf_ptr, container->free_items, config);
          }
        } else {
          TSP_SCOPE(container->refreshed_items) {
            sll_append(np_memory_itemconf_ptr,
                       container->refreshed_items,
                       config);
          }
        }
      }
    }
    if (rm) {
      TSP_SCOPE(container->current_in_use) { container->current_in_use -= 1; }
    }
  }
}

void np_memory_clear_space(NP_UNUSED np_state_t *context,
                           NP_UNUSED uint8_t     type,
                           size_t                size,
                           void                 *data) {
  memset(data, 0, size);
}

void np_memory_randomize_space(NP_UNUSED np_state_t *context,
                               NP_UNUSED uint8_t     type,
                               size_t                size,
                               void                 *data) {
  randombytes_buf(data, size);
}

bool _np_memory_job_memory_management(np_state_t               *context,
                                      NP_UNUSED np_util_event_t event) {
  NP_PERFORMANCE_POINT_START(memory_management);
  for (uint8_t memory_type = 0; memory_type < np_memory_types_MAX_TYPE;
       memory_type++) {
    np_memory_container_t *container =
        np_module(memory)->__np_memory_container[memory_type];
    if (container != NULL && container->on_refresh_space != NULL) {
      __np_memory_itemstats_update(container);

      if (__np_memory_space_decrease_nessecary(container)) {
        // debugf("\t__np_memory_space_decrease\n");
        __np_memory_space_decrease(container);
      }
      /*
      else if (__np_memory_space_increase_nessecary(container))
      {
          //debugf("__np_memory_space_increase\n");
          __np_memory_space_increase(container,
      container->count_of_items_per_block);
      }
      */

      uint32_t list_size = 0;
      TSP_SCOPE(container->free_items) {
        list_size = sll_size(container->free_items);
      }

      if (list_size == 0) continue;
      np_memory_itemconf_ptr list_as_array[list_size];

      TSP_SCOPE(container->free_items) {
        for (uint32_t k = list_size; k > 0; k--) {
          list_as_array[k - 1] =
              sll_head(np_memory_itemconf_ptr, container->free_items);
        }
      }

      for (uint32_t k = list_size; k > 0 && k <= list_size; k--) {
        np_memory_itemconf_t *item_config = list_as_array[k - 1];
        if (item_config != NULL) {
          TSP_SCOPE(item_config->access) {
            __np_memory_refresh_space(item_config);
          }

          TSP_SCOPE(container->refreshed_items) {
            sll_append(np_memory_itemconf_ptr,
                       container->refreshed_items,
                       item_config);
          }
        }
      }
    }
  }
  NP_PERFORMANCE_POINT_END(memory_management);

  return true;
}

// increase ref count
void __np_mem_refobj(np_state_t *context, void *item, const char *reason) {
  assert(item != NULL);
  np_check_magic_no(item);
  np_memory_itemconf_t *config = GET_CONF(item);

  {
    if (config->persistent == false) {
      config->ref_count++;
      // log_msg(LOG_DEBUG,NULL, "Referencing object (%p; t: %d)",
      // obj,obj->type);
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
      assert(reason != NULL);
      sll_prepend(char_ptr, config->reasons, strdup(reason));
#endif
    }
  }
}

// decrease ref count
void __np_mem_unrefobj(np_memory_itemconf_t *config, const char *reason) {
  np_ctx_decl(config->container->module->context);

  if (config->persistent == false) {
    if (config->ref_count == 0) {
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
      log_msg(LOG_ERROR | LOG_MEMORY,
              config->id,
              "Unreferencing object ( %p ; t: %d/%s) too often! try to "
              "unref for '%s'. (left reasons(%" PRIu32 "): %s)",
              config,
              config->container->type,
              np_memory_types_str[config->container->type],
              reason,
              config->ref_count,
              _sll_char_make_flat(context, config->reasons));
#else
      log_msg(LOG_ERROR | LOG_MEMORY,
              config->id,
              "Unreferencing object ( %p ; t: %d/%s) too often! try to "
              "unref for '%s'. left reasons(%" PRIu32 ")",
              config,
              config->container->type,
              np_memory_types_str[config->container->type],
              reason,
              config->ref_count);
#endif
      ABORT(
          "Unreferencing object ( %p ; t: %d/%s) too often! try to unref "
          "for '%s'. left reasons(%" PRIu32 ")",
          config,
          config->container->type,
          np_memory_types_str[config->container->type],
          reason,
          config->ref_count);
    }
    config->ref_count--;
  }
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
  bool foundReason = _np_memory_remove_reason(config->reasons, reason);
  if (false == foundReason) {
    char *flat = _sll_char_make_flat(context, config->reasons);
    log_msg(LOG_ERROR | LOG_MEMORY,
            config->id,
            "reason '%s' for dereferencing obj (type:%d/%s reasons(%d): "
            "%s) was not found. ",
            reason,
            config->container->type,
            np_memory_types_str[config->container->type],
            sll_size(config->reasons),
            flat);
    ABORT(
        "reason '%s' for dereferencing obj (type:%d/%s reasons(%d): %s) "
        "was not found. ",
        reason,
        config->container->type,
        np_memory_types_str[config->container->type],
        sll_size(config->reasons),
        flat);
    free(flat);
  }
  char *flat = _sll_char_make_flat(context, config->reasons);
  log_msg(LOG_MEMORY | LOG_DEBUG,
          config->id,
          "_UnRef_  (%" PRIu32 ") object of type '%s' with '%s' (%s)",
          config->ref_count,
          np_memory_types_str[config->container->type],
          reason,
          flat);
  free(flat);
#endif
}

// print the complete object list and statistics
char *np_mem_printpool(np_state_t *context, bool asOneLine, bool extended) {
  char *ret      = NULL;
  char *new_line = "\n";
  if (asOneLine == true) {
    new_line = "    ";
  }

  uint32_t summary[np_memory_types_MAX_TYPE]       = {0};
  uint32_t summary_refs[np_memory_types_MAX_TYPE]  = {0};
  uint32_t summary_total[np_memory_types_MAX_TYPE] = {0};

  if (true == extended) {
    ret =
        np_str_concatAndFree(ret, "--- extended reasons start ---%s", new_line);
  }

  uint32_t tmp = 0;
  for (int memory_type = 0; memory_type < np_memory_types_MAX_TYPE;
       memory_type++) {

    if (np_module(memory)->__np_memory_container[memory_type] == NULL) {
      continue;
    }

    np_memory_container_t *container =
        np_module(memory)->__np_memory_container[memory_type];

    TSP_SCOPE(container->current_in_use) { tmp = container->current_in_use; }
    summary[container->type] = fmax(summary[container->type], tmp);

    uint32_t max = 0;

    TSP_SCOPE(container->total_items) {
      summary_total[container->type] = sll_size(container->total_items);

#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
      sll_iterator(np_memory_itemconf_ptr) iter_items =
          sll_first(container->total_items);
      while (iter_items != NULL) {
        np_memory_itemconf_ptr iter = iter_items->val;
        if (np_spinlock_trylock(&iter->access_lock)) {
          max = fmax(max, iter->ref_count);
          if (true == extended
              //&& iter->ref_count == 1
              &&
              (
                  // true
                  // container->type == np_memory_types_np_node_t ||
                  // container->type == np_memory_types_np_aaatoken_t
                  container->type == np_memory_types_np_messagepart_t ||
                  container->type == np_memory_types_np_message_t
                  // container->type == np_memory_types_BLOB_1024
                  // container->type == np_memory_types_np_responsecontainer_t
                  // container->type == np_memory_types_np_key_t
                  //|| container->type == np_msgproperty_t_e
                  )) {
            if (sll_size(iter->reasons) > 0) {
              ret = np_str_concatAndFree(ret,
                                         "--- remaining reasons for (type: "
                                         "%d/%s, reasons: %d) start ---%s",
                                         memory_type,
                                         np_memory_types_str[memory_type],
                                         sll_size(iter->reasons),
                                         new_line);

              static const uint32_t display_first_X_reasons = 15;
              static const uint32_t display_last_X_reasons  = 15;

              sll_iterator(char_ptr) iter_reasons = sll_first(iter->reasons);
              uint32_t iter_reasons_counter       = 0;
              while (iter_reasons != NULL) {
                if (iter_reasons_counter < display_first_X_reasons) {
                  ret = np_str_concatAndFree(ret,
                                             "\"%s\"%s",
                                             iter_reasons->val,
                                             new_line);
                }

                if ((display_first_X_reasons + display_last_X_reasons) <
                        sll_size(iter->reasons) &&
                    display_first_X_reasons == iter_reasons_counter) {
                  ret = np_str_concatAndFree(
                      ret,
                      "... Skipping %" PRIi32 " reasons ...%s",
                      sll_size(iter->reasons) -
                          (display_first_X_reasons + display_last_X_reasons),
                      new_line);
                }

                if (iter_reasons_counter > display_first_X_reasons &&
                    iter_reasons_counter >= display_first_X_reasons +
                                                sll_size(iter->reasons) -
                                                (display_first_X_reasons +
                                                 display_last_X_reasons)) {
                  ret = np_str_concatAndFree(ret,
                                             "\"%s\"%s",
                                             iter_reasons->val,
                                             new_line);
                }

                iter_reasons_counter++;
                sll_next(iter_reasons);
              }

              /*
              ret = np_str_concatAndFree(ret,
                  "--- remaining reasons for %s (%d/%s) end  ---",
                  iter->id,
                  memory_type,
                  np_memory_types_str[memory_type],
              );
              */
              ret = np_str_concatAndFree(ret, "%s", new_line);
            }
          }
          np_spinlock_unlock(&iter->access_lock);
        }
        sll_next(iter_items);
      }
#endif
    }
    summary_refs[container->type] = max;
  }

  if (true == extended) {
#ifndef NP_MEMORY_CHECK_MEMORY_REFFING
    ret = np_str_concatAndFree(
        ret,
        "NO DATA. Compile with NP_MEMORY_CHECK_MEMORY_REFFING %s",
        new_line);
#endif
    ret =
        np_str_concatAndFree(ret, "--- extended reasons end  ---%s", new_line);
  }

  if (asOneLine)
    ret = np_str_concatAndFree(ret, "--- memory summary---%s", new_line);

  ret = np_str_concatAndFree(ret, "%20s | u./count | max ref", "name");

  for (int memory_type = 0; memory_type < np_memory_types_MAX_TYPE;
       memory_type++) {
    ret = np_str_concatAndFree(ret,
                               "%20s | %3" PRIu32 "/%4" PRIu32 " | %3" PRIu32
                               "%s",
                               np_memory_types_str[memory_type],
                               summary[memory_type],
                               summary_total[memory_type],
                               summary_refs[memory_type],
                               new_line);
  }

  if (asOneLine)
    ret = np_str_concatAndFree(ret, "--- memory end ---%s", new_line);

  return (ret);
}

// print the complete object list and statistics
void np_mem_printpool_reasons(np_state_t *context) {
  uint32_t summary[np_memory_types_MAX_TYPE]       = {0};
  uint32_t summary_refs[np_memory_types_MAX_TYPE]  = {0};
  uint32_t summary_total[np_memory_types_MAX_TYPE] = {0};

  uint32_t tmp;
  for (int memory_type = 0; memory_type < np_memory_types_MAX_TYPE;
       memory_type++) {

    if (np_module(memory)->__np_memory_container[memory_type] == NULL) {
      continue;
    }

    np_memory_container_t *container =
        np_module(memory)->__np_memory_container[memory_type];

    np_spinlock_lock(&container->current_in_use_lock);
    {
      tmp = container->current_in_use;
    }
    np_spinlock_unlock(&container->current_in_use_lock);
    summary[container->type] = fmax(summary[container->type], tmp);

#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
    uint32_t max = 1;

    np_spinlock_lock(&container->total_items_lock);
    {

      {

        summary_total[container->type] = sll_size(container->total_items);
        sll_iterator(np_memory_itemconf_ptr) iter_items =
            sll_first(container->total_items);
        while (iter_items != NULL) {
          np_memory_itemconf_ptr iter = iter_items->val;
          if (np_spinlock_trylock(&iter->access_lock)) {
            max = fmax(max, iter->ref_count);
            if (true
                //&& iter->ref_count != 2
                //&& iter->ref_count != 3
                //&& iter->ref_count != 4
                && (
                       // true
                       //(container->type == np_memory_types_np_node_t &&
                       // container->current_in_use > 50) || (container->type
                       // == np_memory_types_np_aaatoken_t &&
                       // container->current_in_use > 600) ||
                       (container->type == np_memory_types_np_messagepart_t &&
                        container->current_in_use > 200)
                       //(container->type == np_memory_types_np_message_t &&
                       // container->current_in_use > 2000) container->type ==
                       // np_memory_types_np_message_t
                       // container->type == np_memory_types_BLOB_1024
                       // container->type ==
                       // np_memory_types_np_responsecontainer_t
                       //(container->type == np_memory_types_np_key_t  &&
                       // container->current_in_use > 200)
                       //|| container->type == np_msgproperty_t_e
                       )) {
              if (sll_size(iter->reasons) > 0) {
                char *ret = NULL;
                ret       = np_str_concatAndFree(ret,
                                           "--- remaining reasons for (type: "
                                                 "%d/%s, reasons: %d) start ---",
                                           memory_type,
                                           np_memory_types_str[memory_type],
                                           sll_size(iter->reasons));

                static const uint32_t display_first_X_reasons = 15;
                static const uint32_t display_last_X_reasons  = 15;

                sll_iterator(char_ptr) iter_reasons = sll_first(iter->reasons);
                uint32_t iter_reasons_counter       = 0;
                while (iter_reasons != NULL) {
                  if (iter_reasons_counter < display_first_X_reasons) {
                    ret =
                        np_str_concatAndFree(ret, "\"%s\"", iter_reasons->val);
                  }

                  if ((display_first_X_reasons + display_last_X_reasons) <
                          sll_size(iter->reasons) &&
                      display_first_X_reasons == iter_reasons_counter) {
                    ret = np_str_concatAndFree(
                        ret,
                        "... Skipping %" PRIi32 " reasons ...",
                        sll_size(iter->reasons) -
                            (display_first_X_reasons + display_last_X_reasons));
                  }

                  if (iter_reasons_counter > display_first_X_reasons &&
                      iter_reasons_counter >= display_first_X_reasons +
                                                  sll_size(iter->reasons) -
                                                  (display_first_X_reasons +
                                                   display_last_X_reasons)) {
                    ret =
                        np_str_concatAndFree(ret, "\"%s\"", iter_reasons->val);
                  }

                  iter_reasons_counter++;
                  sll_next(iter_reasons);
                }
                log_info(LOG_EXPERIMENT | LOG_MEMORY, NULL, "%s", ret);
                free(ret);
              }
            }
            np_spinlock_unlock(&iter->access_lock);
          }
          sll_next(iter_items);
        }
      }
    }
    np_spinlock_unlock(&container->total_items_lock);
    summary_refs[container->type] = max;
#endif
  }
}

#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
void np_memory_ref_replace_reason(void       *item,
                                  const char *old_reason,
                                  const char *new_reason) {
  if (item != NULL) {
    assert(old_reason != NULL);
    np_memory_itemconf_t *config = GET_CONF(item);
    np_ctx_decl(config->container->module->context);

    np_spinlock_lock(&config->access_lock);
    {
      sll_iterator(char_ptr) iter_reasons = sll_first(config->reasons);
      bool foundReason                    = false;
      while (foundReason == false && iter_reasons != NULL) {
        if (strlen(iter_reasons->val) >=
            strlen(old_reason) + _NP_REF_REASON_SEPERATOR_CHAR_LEN) {
          foundReason =
              0 == strncmp(iter_reasons->val, old_reason, strlen(old_reason));
          char *tmp = iter_reasons->val + strlen(old_reason);
          foundReason &= 0 == strncmp(tmp,
                                      _NP_REF_REASON_SEPERATOR_CHAR,
                                      _NP_REF_REASON_SEPERATOR_CHAR_LEN);
        }

        if (foundReason == true) {
          free(iter_reasons->val);
          sll_delete(char_ptr, config->reasons, iter_reasons);
          break;
        }

        sll_next(iter_reasons);
      }
      if (false == foundReason) {
        char *flat = _sll_char_make_flat(context, config->reasons);
        log_msg(LOG_ERROR | LOG_MEMORY,
                config->id,
                "Reason switch on object (t: %s) \"%s\" to \"%s\" not "
                "possible! Reason not found. (left reasons(%d): %s)",
                np_memory_types_str[config->container->type],
                old_reason,
                new_reason,
                config->ref_count,
                flat);
        ABORT(
            "Reason switch on object (t: %s) \"%s\" to \"%s\" not "
            "possible! Reason not found. (left reasons(%d): %s)",
            np_memory_types_str[config->container->type],
            old_reason,
            new_reason,
            config->ref_count,
            flat);
        free(flat);
      } else {
        _NP_REF_REASON(new_reason, "", reason2)
        sll_prepend(char_ptr,
                    config->reasons,
                    strndup(reason2, strlen(reason2)));
      }
    }
    np_spinlock_unlock(&config->access_lock);
  }
}
#endif

void np_memory_ref_obj(np_state_t *context,
                       void       *item,
                       const char *reason,
                       const char *reason_desc) {
  assert(item != NULL);
  np_check_magic_no(item);

  np_memory_itemconf_t *config = GET_CONF(item);

  _NP_REF_REASON(reason, reason_desc, reason2);
  np_spinlock_lock(&config->access_lock);
  {
    __np_mem_refobj(context, item, reason2);
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
    char *flat = _sll_char_make_flat(context, config->reasons);
    log_msg(LOG_DEBUG | LOG_MEMORY,
            NULL,
            "_Ref_    (%" PRIu32 ") object of type '%s' with '%s' (%s)",
            config->ref_count,
            np_memory_types_str[config->container->type],
            reason,
            flat);
    free(flat);
#endif
  }
  np_spinlock_unlock(&config->access_lock);
}

void *np_memory_waitref_obj(np_state_t *context,
                            void       *item,
                            const char *reason,
                            const char *reason_desc) {
  void *ret = NULL;

  while (ret == NULL) {

    if (item != NULL) {
      np_memory_itemconf_t *config = GET_CONF(item);

      np_spinlock_lock(&config->access_lock);
      {
        np_memory_ref_obj(context, item, reason, reason_desc);
        ret = item;
      }
      np_spinlock_unlock(&config->access_lock);
    } else {
      np_time_sleep(0.0);
    }
  }

  return ret;
}

void *np_memory_tryref_obj(np_state_t *context,
                           void       *item,
                           const char *reason,
                           const char *reason_desc) {
  void *ret = NULL;
  if (item != NULL) {
    np_memory_itemconf_t *config = GET_CONF(item);
    np_spinlock_lock(&config->access_lock);
    {
      _NP_REF_REASON(reason, reason_desc, reason2);
      __np_mem_refobj(context, item, reason2);
      ret = item;
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
      char *flat = _sll_char_make_flat(context, config->reasons);
      log_msg(LOG_DEBUG | LOG_MEMORY,
              config->id,
              "_TryRef_ (%" PRIu32 ") object of type '%s' with '%s' (%s)",
              config->ref_count,
              np_memory_types_str[config->container->type],
              reason,
              flat);
      free(flat);
#endif
    }
    np_spinlock_unlock(&config->access_lock);
  }
  return ret;
}

uint32_t
np_memory_unref_obj(np_state_t *context, void *item, const char *reason) {
  uint32_t ret = 0;
  if (item != NULL) {
    np_check_magic_no(item);
    np_memory_itemconf_t *config = GET_CONF(item);

    np_spinlock_lock(&config->access_lock);
    {
      __np_mem_unrefobj(config, reason);
      ret = config->ref_count + (config->persistent ? 1 : 0);
    }
    np_spinlock_unlock(&config->access_lock);

    np_memory_free(context, item);
  }
  return ret;
}

char *np_memory_get_id(void *item) {
  char *ret = "unknown";
  if (item != NULL) {
    np_memory_itemconf_t *config = GET_CONF(item);
    ret                          = config->id;
  }
  return ret;
}

uint32_t np_memory_get_refcount(void *item) {
  uint32_t ret = 0;
  if (item != NULL) {
    np_memory_itemconf_t *config = GET_CONF(item);
    ret                          = config->ref_count;
  }
  return ret;
}

enum np_memory_types_e np_memory_get_type(void *item) {
  enum np_memory_types_e ret = 0;
  if (item != NULL) {
    np_memory_itemconf_t *config = GET_CONF(item);
    ret                          = config->container->type;
  }
  return ret;
}
