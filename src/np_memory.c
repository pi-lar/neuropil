//
// neuropil is copyright 2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <float.h>
#include <inttypes.h>
#include <math.h>

#include "sodium.h"


#include "neuropil.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_jobqueue.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_list.h"
#include "np_types.h"
#include "np_message.h"
#include "core/np_comp_msgproperty.h"
#include "np_key.h"
#include "np_aaatoken.h"
#include "np_threads.h"
#include "np_node.h"
#include "np_network.h"
#include "np_responsecontainer.h"
#include "np_messagepart.h"
#include "np_crypto.h"
#include "np_statistics.h"
#include "np_memory.h"

#include "np_constants.h"
#include "np_settings.h"

/*
General workflow:
After you register a type with a known size a container will be created which contains multiple memory blocks.
Every block may contains exactly count_of_items_per_block items + the configuration for each item.
the configuration of each item is preceeding to the memory of the item itself.

*/

typedef struct np_memory_container_s np_memory_container_t;
typedef struct np_memory_itemconf_s np_memory_itemconf_t;
typedef np_memory_itemconf_t* np_memory_itemconf_ptr;

NP_SLL_GENERATE_PROTOTYPES(np_memory_itemconf_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_memory_itemconf_ptr);

np_module_struct(memory) {
    np_state_t* context;
    np_memory_container_t* __np_memory_container[np_memory_types_MAX_TYPE];
};

struct np_memory_itemstat_s {
    double time;
    uint32_t itemcount;
};

struct np_memory_container_s
{
    np_module_struct(memory)* module;

    enum np_memory_types_e type;

    uint32_t count_of_items_per_block;
    uint32_t min_count_of_items;
    size_t size_per_item;

    np_memory_on_new on_new;
    np_memory_on_free on_free;
    np_memory_on_refresh_space on_refresh_space;

    np_mutex_t free_items_lock;
    np_sll_t(np_memory_itemconf_ptr, free_items);
    np_mutex_t refreshed_items_lock;
    np_sll_t(np_memory_itemconf_ptr, refreshed_items);

    np_mutex_t total_items_lock;
    np_sll_t(np_memory_itemconf_ptr, total_items);

    np_mutex_t current_in_use_lock;
    uint32_t current_in_use;

    bool itemstats_full;
    uint32_t itemstats_idx;
    struct np_memory_itemstat_s itemstats[10];
};

#define NP_MEMORY_CHECK_MEMORY_REFFING_MAGIC_NO 3223967591
struct np_memory_itemconf_s {
#ifdef NP_MEMORY_CHECK_MAGIC_NO
    uint32_t magic_no;
#endif
    np_memory_container_t* container;

    bool in_use;
    bool needs_refresh;
    np_mutex_t access_lock;

    uint32_t ref_count;
    bool persistent;
    char id[NP_UUID_BYTES];
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
    np_sll_t(char_ptr, reasons);
#endif
};


#define NEXT_ITEMCONF(conf, skip) conf = (np_memory_itemconf_t*) (((char*)conf) + (((skip)+1) * ((conf)->block->container->size_per_item + sizeof(np_memory_itemconf_t))));
#define GET_CONF(item) ((np_memory_itemconf_t*)(((char*)item) - sizeof(np_memory_itemconf_t)))
#define GET_ITEM(config) (((char*)config) + sizeof(np_memory_itemconf_t))

#ifndef NP_MEMORY_CHECK_MAGIC_NO
    #define np_check_magic_no(item)
#else
void np_check_magic_no(void * item) {
    if (GET_CONF(item)->magic_no != NP_MEMORY_CHECK_MEMORY_REFFING_MAGIC_NO) {
        assert(GET_CONF(item)->magic_no == NP_MEMORY_CHECK_MEMORY_REFFING_MAGIC_NO);
        // for release build
        abort();
    };

}
#endif

void __np_memory_delete_item(np_state_t* context, np_memory_container_t* container, np_memory_itemconf_t* item_config) {    
            
#if NP_MEMORY_CHECK_MEMORY_REFFING
    if(sll_size( item_config->reasons) > 0) {
        char * flat = _sll_char_make_flat(context, item_config->reasons);
        log_error("Still has a object of type %s in cache: Refs: %"PRIu32" id:%s reasons:(%s)",np_memory_types_str[container->type], item_config->ref_count, item_config->id, flat);		
        free(flat);
    }
    sll_free(char_ptr, item_config->reasons);
#endif 
    _np_threads_mutex_destroy(context, &item_config->access_lock);
    free(item_config);
}

void _np_memory_container_destroy(np_state_t* context, np_memory_container_t* container ){
        
    sll_free(np_memory_itemconf_ptr, container->free_items);
    _np_threads_mutex_destroy(context, &(container->free_items_lock));
    
    sll_free(np_memory_itemconf_ptr, container->refreshed_items);
    _np_threads_mutex_destroy(context, &(container->refreshed_items_lock));
    
    sll_free(np_memory_itemconf_ptr, container->total_items);
    _np_threads_mutex_destroy(context, &(container->total_items_lock));
    
    _np_threads_mutex_destroy(context, &(container->current_in_use_lock));         
    free(container);
}

#ifdef NP_MEMORY_CHECK_MEMORY_REFFING        
bool _np_memory_remove_reason(sll_return(char_ptr) sll, const char* cmp_obj){
    bool ret = false;
    sll_iterator(char_ptr) iter_reason = sll_first(sll);
    
    while (ret == false && iter_reason != NULL)
    {
        ret = (0 == strncmp(iter_reason->val, cmp_obj, strlen(cmp_obj))
            && 0 == strncmp(iter_reason->val + strlen(cmp_obj), _NP_REF_REASON_SEPERATOR_CHAR, _NP_REF_REASON_SEPERATOR_CHAR_LEN)) ? true : false;
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
#define _np_memory_remove_reason(a,b)
#endif

void _np_memory_delete_item(np_state_t * context, void* item, char* rm_reason, bool del_container){
    np_memory_itemconf_t* item_config = GET_CONF(item);
    np_memory_container_t* container = item_config->container;
    
    _np_memory_remove_reason(item_config->reasons, rm_reason);
        
    sll_remove(np_memory_itemconf_ptr, container->free_items, item_config, np_memory_itemconf_ptr_sll_compare_type);
    sll_remove(np_memory_itemconf_ptr, container->refreshed_items, item_config, np_memory_itemconf_ptr_sll_compare_type);
    sll_remove(np_memory_itemconf_ptr, container->total_items, item_config, np_memory_itemconf_ptr_sll_compare_type);

    __np_memory_delete_item(context, container, item_config);
    if(del_container) {
        if(sll_size(container->total_items) != 0){
            log_error("Still has %"PRIu32" object of type %s in cache", sll_size(container->total_items), np_memory_types_str[container->type]);
            #ifdef NP_MEMORY_CHECK_MEMORY_REFFING        
            sll_iterator(np_memory_itemconf_ptr) leftover_iter = sll_first(container->total_items);
            while(leftover_iter != NULL){                    
                item_config = leftover_iter ->val;
                char * flat = _sll_char_make_flat(context, item_config->reasons);
                log_error("Still has a object of type %s in cache: Refs: %"PRIu32" id:%s reasons:(%s)",np_memory_types_str[container->type], item_config->ref_count, item_config->id, flat);		
                free(flat);
                sll_next(leftover_iter);
            }
            #endif
        }
        _np_memory_container_destroy(context, container );
    }
}

void _np_memory_destroy(np_state_t* context){

    for(int type =0; type < np_memory_types_MAX_TYPE; type++) {

        log_debug(LOG_MEMORY, "cleanup of memory elements of type %s", np_memory_types_str[type]);

        if(type == np_memory_types_np_thread_t) {
            // threads will be handled expleciet in np_threads_destroy
            continue;
        }
        np_memory_container_t* container = np_module(memory)->__np_memory_container[type];
        if (container != NULL) {
            np_memory_itemconf_t* item_config;
           
            while((item_config = sll_head(np_memory_itemconf_ptr, container->total_items)) != NULL)
            {
                if (item_config->in_use) {                    
                    #ifdef NP_MEMORY_CHECK_MEMORY_REFFING        
                        char * flat = _sll_char_make_flat(context, item_config->reasons);
                        log_error("Still has a object of type %s in cache: Refs: %"PRIu32" id:%s reasons:(%s)",np_memory_types_str[type], item_config->ref_count, item_config->id, flat);		
                        free(flat);
                    #else
                        log_error("Still has a object of type %s in cache", np_memory_types_str[type]);
                    #endif

                    /*
                    if (container->on_free != NULL){
                        container->on_free(context, container->type, container->size_per_item, GET_ITEM(item_config));
                        item_config->in_use = false;
                    }
                    */
                }
                __np_memory_delete_item(context, container, item_config);
            }
            _np_memory_container_destroy(context, container);
        }
    }

    np_module_free(memory);
}

bool _np_memory_init(np_state_t* context) 
{
    np_module_malloc(memory);

    for (int i = 0; i < np_memory_types_MAX_TYPE; i++) 
    {
        _module->__np_memory_container[i] = NULL;
    }

#define np_register(type,items_per_block,min_items, new_fn, free_fn, clear_fn ) \
np_memory_register_type(context, np_memory_types_np_##type##_t, sizeof(np_##type##_t), items_per_block, min_items, new_fn, free_fn, clear_fn)
#define np_register_defaultobj(type, count_of_itens_in_block, min_count) np_register(type, count_of_itens_in_block, min_count, _np_##type##_t_new, _np_##type##_t_del, np_memory_clear_space);	

    np_register_defaultobj(message, 4, 4);
    np_register_defaultobj(key, 4, 4);
    np_register_defaultobj(msgproperty, 4, 4);
    np_register_defaultobj(thread, 1, 1);
    np_register_defaultobj(node, 4, 4);
    np_register_defaultobj(network, 4, 4);
    np_register_defaultobj(responsecontainer, 4, 4);
    np_register_defaultobj(messagepart, 4, 20);
    np_register_defaultobj(aaatoken, 4, 4);
    np_register_defaultobj(crypto, 4, 4);

#undef np_register
#undef np_register_defaultobj

    // np_memory_register_type(context, np_memory_types_np_job_t, sizeof(np_job_t), 4, JOBQUEUE_MAX_SIZE, NULL, NULL, np_memory_clear_space);
    // np_memory_register_type(context, np_memory_types_np_jobargs_t, sizeof(np_jobargs_t), 4, JOBQUEUE_MAX_SIZE/2, NULL, NULL, np_memory_clear_space);

    np_memory_register_type(context, np_memory_types_BLOB_1024, MSG_CHUNK_SIZE_1024, 8, 20, NULL, NULL, np_memory_clear_space);
    np_memory_register_type(context, np_memory_types_BLOB_984_RANDOMIZED, MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40, 4, 20, NULL, NULL, np_memory_randomize_space);

    return true;
}

bool _np_memory_rtti_check(void* item, enum np_memory_types_e type) 
{
    if (item) {
        np_memory_itemconf_t* item_conf = GET_CONF(item);
        return (item_conf->container->type == type);
    }
    return false;
}

void __np_memory_space_increase(np_memory_container_t* container, uint32_t block_size) {
    np_ctx_decl(container->module->context);
    for (uint32_t j = 0; j < block_size; j++) {
        size_t  whole_item_size = container->size_per_item + sizeof(np_memory_itemconf_t);

        np_memory_itemconf_t* conf = malloc(whole_item_size);
        CHECK_MALLOC(conf);
        //debugf("adding obj %p \n", conf);
 
        // conf init
        conf->container = container;
        conf->in_use = false;
        conf->needs_refresh = true;
        conf->ref_count = 0;		
        char* tmp  = conf->id;
        np_uuid_create(FUNC, 0, &tmp);
        log_debug_msg(LOG_MEMORY | LOG_DEBUG, "_Inc_    (%"PRIu32") object of type \"%s\" on %s", conf->ref_count, np_memory_types_str[container->type], conf->id);

        conf->persistent = false;
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING		
        sll_init(char_ptr, conf->reasons);
#endif
#ifdef NP_MEMORY_CHECK_MAGIC_NO
        conf->magic_no = NP_MEMORY_CHECK_MEMORY_REFFING_MAGIC_NO;
#endif
        char mutex_str[64];
        snprintf(mutex_str, 63, "%s", "urn:np:memory:config");
        if (_np_threads_mutex_init(context, &(conf->access_lock), mutex_str) != 0) {
            log_msg(LOG_ERROR, "Could not create memory item lock for container type %"PRIu8, container->type);
        }
        _LOCK_ACCESS(&container->free_items_lock) {
            sll_append(np_memory_itemconf_ptr, container->free_items, conf);
        }
        _LOCK_ACCESS(&container->total_items_lock) {
            sll_append(np_memory_itemconf_ptr, container->total_items, conf);
        }
    }
}

void np_memory_register_type(
    np_state_t* context,
    enum np_memory_types_e type,
    size_t size_per_item,
    uint32_t count_of_items_per_block,
    uint32_t min_count_of_items,
    np_memory_on_new on_new,
    np_memory_on_free on_free,
    np_memory_on_refresh_space on_refresh_space
) {
    if (np_module(memory)->__np_memory_container[type] == NULL) {
        np_memory_container_t* container = calloc(1, sizeof(np_memory_container_t));
        CHECK_MALLOC(container);

        container->module = np_module(memory);
        container->itemstats_idx = 0;
        container->itemstats_full = false;
        memset(container->itemstats, 0, sizeof(container->itemstats));
        container->size_per_item = size_per_item;
        container->count_of_items_per_block = count_of_items_per_block;
        container->min_count_of_items = min_count_of_items;
        container->on_new = on_new;
        container->on_free = on_free;
        container->on_refresh_space = on_refresh_space;
        container->type = type;

        sll_init(np_memory_itemconf_ptr, container->free_items);
        char mutex_str[64];
        snprintf(mutex_str, 63, "%s", "urn:np:memory:free_items");
        if (_np_threads_mutex_init(context, &(container->free_items_lock), mutex_str) != 0) {
            log_msg(LOG_ERROR, "Could not create free_items_lock for container type %"PRIu8, container->type);
        }

        snprintf(mutex_str, 63, "%s", "urn:np:memory:refreshed_items");
        sll_init(np_memory_itemconf_ptr, container->refreshed_items);
        if (_np_threads_mutex_init(context, &(container->refreshed_items_lock), mutex_str) != 0) {
            log_msg(LOG_ERROR, "Could not create refreshed_items for container type %"PRIu8, container->type);
        }

        snprintf(mutex_str, 63, "%s", "urn:np:memory:total_items");
        sll_init(np_memory_itemconf_ptr, container->total_items);
        if (_np_threads_mutex_init(context, &(container->total_items_lock), mutex_str) != 0) {
            log_msg(LOG_ERROR, "Could not create total_items for container type %"PRIu8, container->type);
        }

        snprintf(mutex_str, 63, "%s", "urn:np:memory:in_use");
        if (_np_threads_mutex_init(context, &(container->current_in_use_lock), mutex_str) == 0)
        {
            int i = 0;
            while ((container->count_of_items_per_block * i) < container->min_count_of_items)
            {
                i++;
                __np_memory_space_increase(container, container->count_of_items_per_block);
            }

            np_module(memory)->__np_memory_container[container->type] = container;
            log_msg(LOG_MEMORY | LOG_INFO, "Created memory container (%p) for type %"PRIu8" at %p", container, type, np_module(memory)->__np_memory_container[container->type]);
        }
        else {
            log_msg(LOG_ERROR, "Could not create memory container lock");
        }
    }
}

void __np_memory_refresh_space(np_memory_itemconf_t* config) {
    assert(config != NULL);
    // bool refreshed = false;
    np_memory_container_t* container = config->container;
    np_ctx_decl(container->module->context);
    void* data = GET_ITEM(config);

    _LOCK_ACCESS(&config->access_lock) {
        if (config->in_use == false && config->needs_refresh == true) {
            config->ref_count = 0;			
            config->persistent = false;

#if NP_MEMORY_CHECK_MEMORY_REFFING
            char* old;
            char* tmp = old =  config->id;
            np_uuid_create(FUNC, 0, &tmp);
            log_debug_msg(LOG_DEBUG | LOG_MEMORY, "Memory obj %s is now refreshed and changed id to %s", old, tmp);
            sll_clear(char_ptr, config->reasons);
#endif 
            if (container->on_refresh_space != NULL) {
                container->on_refresh_space(context, container->type, container->size_per_item, data);
            }
            config->needs_refresh = false;
            // refreshed = true;
        }
    }
    // return refreshed;
}

void __np_memory_itemstats_update(np_memory_container_t* container) {
    np_ctx_decl(container->module->context);
    _LOCK_ACCESS(&container->current_in_use_lock) {
        struct np_memory_itemstat_s * itemstat = &container->itemstats[container->itemstats_idx];
        itemstat->itemcount = container->current_in_use;
        itemstat->time = np_time_now();

        container->itemstats_full = container->itemstats_full || (container->itemstats_idx + 1) == (sizeof(container->itemstats) / sizeof(container->itemstats[0]));
        container->itemstats_idx = ((1 + container->itemstats_idx) % (sizeof(container->itemstats) / sizeof(container->itemstats[0])));
    }
}

double __np_memory_itemstats_get_growth(np_memory_container_t* container) {
    np_ctx_decl(container->module->context);

    double growth = 0;
    double min_time = DBL_MAX;
    double max_time = 0;
    for (uint32_t i = 0; i < container->itemstats_idx; i++) {
        struct np_memory_itemstat_s itemstat = container->itemstats[container->itemstats_idx];
        min_time = fmin(min_time, itemstat.time);
        max_time = fmax(max_time, itemstat.time);
    }
    if (container->itemstats_full) {

        CALC_STATISTICS(container->itemstats, .itemcount,
            (sizeof(container->itemstats) / sizeof(container->itemstats[0])),
            itemstats_min, itemstats_max, itemstats_avg, itemstats_stddev);


        _LOCK_ACCESS(&container->current_in_use_lock) {
            growth = (container->current_in_use - itemstats_avg) / (max_time == min_time ? 1 : max_time - min_time);
        }
    }
    return growth;
}

bool __np_memory_space_decrease_nessecary(np_memory_container_t* container) {
    np_ctx_decl(container->module->context);
    bool ret = false;

    _LOCK_ACCESS(&container->current_in_use_lock) {
        _LOCK_ACCESS(&container->refreshed_items_lock) {
            _LOCK_ACCESS(&container->free_items_lock) {
                double growth = __np_memory_itemstats_get_growth(container);

                uint32_t total_free_space = sll_size(container->free_items) + sll_size(container->refreshed_items);
                uint32_t total_space_available = total_free_space + container->current_in_use;

                ret =
                    /*decrease only if we have more then the min threshhold (failsafe)*/
                    total_space_available >= (container->min_count_of_items + container->count_of_items_per_block) &&
                    (
                    /* decrease if the growth of items is negative for the mesured period, the grows is min as great as a block, and the growth size is free*/
                    (0 > growth &&
                        fabs(growth) > container->count_of_items_per_block &&
                        total_free_space > fabs(growth)
                        )

                        ||

                        /*decrease if we only consume 50% or less of our space*/
                        //container->current_in_use <= (total_space_available * 0.5)
                        false
                        )
                    ;
            }
        }
    }
    return ret;
}

bool __np_memory_space_increase_nessecary(np_memory_container_t* container) {
    np_ctx_decl(container->module->context);
    bool ret = false;

    _LOCK_ACCESS(&container->refreshed_items_lock) {
        
        _LOCK_ACCESS(&container->current_in_use_lock) {
        
            _LOCK_ACCESS(&container->free_items_lock) {
                double growth = __np_memory_itemstats_get_growth(container);

                uint32_t total_free_space = sll_size(container->free_items) + sll_size(container->refreshed_items);
                uint32_t total_space_available = total_free_space + container->current_in_use;

                ret = /*increase only if we have less then 50% free space (failsafe)*/
                    total_free_space < (total_space_available * 0.5) &&
                    (
                        /* increase if we already consumed more then 90% of the available space */
                        //container->current_in_use >= (total_space_available * 0.9) ||

                        /*increase if the growth of items is positive for the mesured period,
                        and the growth is greater then our free space*/
                    (0 < growth &&  growth > total_free_space)

                        )
                    ;
            }
        }
    }
    return ret;
}

void __np_memory_space_decrease(np_memory_container_t* container) {
    np_ctx_decl(container->module->context);
    np_memory_itemconf_t* item_config;

    for (uint32_t j = 0; j < container->count_of_items_per_block; j++) {
        // best pick: a free container (not refreshed)
        _LOCK_ACCESS(&container->free_items_lock) {
            item_config = sll_head(np_memory_itemconf_ptr, container->free_items);
        }

        if (item_config == NULL) {
            _LOCK_ACCESS(&container->refreshed_items_lock) {
                // second best pick: an refreshed container
                item_config = sll_head(np_memory_itemconf_ptr, container->refreshed_items);
            }
        }
        if (item_config != NULL) {
            _LOCK_ACCESS(&item_config->access_lock) {
                ASSERT(item_config->in_use == false, "can only delete unused memory objects");
            }

            _LOCK_ACCESS(&container->total_items_lock) {
                sll_remove(np_memory_itemconf_ptr, container->total_items, item_config, np_memory_itemconf_ptr_sll_compare_type);
            }
          __np_memory_delete_item(context, container, item_config);
        }
        else {
            // removed everything, lists are now empty
            break;
        }
    }
}

void* np_memory_new(np_state_t* context, enum np_memory_types_e type)
{
    NP_PERFORMANCE_POINT_START(memory_new);
    void* ret = NULL;
    np_memory_container_t* container = np_module(memory)->__np_memory_container[type];
    ASSERT(container != NULL, "Memory container %"PRIu32" needs to be initialized first.", type);

    log_debug_msg(LOG_MEMORY | LOG_DEBUG, "Searching for next free current_block for type %"PRIu32, type);

    np_memory_itemconf_t* next_config;
    bool found = false;

    do {
        next_config = NULL; // init loop condition

        while (next_config == NULL) {
            _LOCK_ACCESS(&container->refreshed_items_lock) {
                // best pick: an already refreshed container
                next_config = sll_head(np_memory_itemconf_ptr, container->refreshed_items);

                if (next_config == NULL) {
                    // second best pick: a free container
                    _LOCK_ACCESS(&container->free_items_lock) {
                        next_config = sll_head(np_memory_itemconf_ptr, container->free_items);

                        if (next_config == NULL) {
                            // worst case: create a new item
                            __np_memory_space_increase(container, 1);
                            next_config = sll_head(np_memory_itemconf_ptr, container->free_items);
                        }
                    }
                    // second best as we need to refresh the item
                    __np_memory_refresh_space(next_config);
                }
            }
        }
        // now we do have a item space. we need to check if the space is already in use (should not but better play safe)
        _LOCK_ACCESS(&next_config->access_lock) {
            if (next_config->in_use == false) {
                // take free space
                found = true;
                next_config->in_use = true;
            }
        }
    } while (found == false);

    _LOCK_ACCESS(&container->current_in_use_lock) {
        container->current_in_use += 1;
    }

    ret = GET_ITEM(next_config);

    log_debug_msg(LOG_MEMORY | LOG_DEBUG, "_New_    (%"PRIu32") object of type \"%s\" on %s", next_config->ref_count, np_memory_types_str[container->type], next_config->id);

    if (container->on_new != NULL)
        container->on_new(context, container->type, container->size_per_item, ret);

    NP_PERFORMANCE_POINT_END(memory_new);
    return ret;
}

np_state_t* np_memory_get_context(void* item) {
    assert(item != NULL);
    np_state_t* ret = NULL;
    np_check_magic_no(item);

    np_memory_itemconf_t* config = GET_CONF(item);
    assert(config != NULL);
    assert(config->container != NULL);
    assert(config->container->module != NULL);
    assert(config->container->module->context != NULL);
    ret = config->container->module->context;
    
    return ret;
}

void np_memory_free(np_state_t*context, void* item) {	
    if (item != NULL) {
        np_check_magic_no(item);
        np_memory_itemconf_t* config = GET_CONF(item);
        np_memory_container_t* container = config->container;

        NP_PERFORMANCE_POINT_START(memory_free);

        bool rm = false;
        _LOCK_ACCESS(&config->access_lock) {

            rm = config->ref_count == 0 && !config->persistent;
            if (rm) {
                config->in_use = false;

                if (container->on_free != NULL)
                    container->on_free(context, container->type, container->size_per_item, item);

                if (container->on_refresh_space != NULL) {
                    config->needs_refresh = true;
                    _LOCK_ACCESS(&container->free_items_lock) {
                        sll_append(np_memory_itemconf_ptr, container->free_items, config);
                    }
                }
                else {
                    _LOCK_ACCESS(&container->refreshed_items_lock) {
                        sll_append(np_memory_itemconf_ptr, container->refreshed_items, config);
                    }
                } 
           }
        }

        if (rm) {
            _LOCK_ACCESS(&container->current_in_use_lock) {
                container->current_in_use -= 1;
            }
        }
        NP_PERFORMANCE_POINT_END(memory_free);
    }
}

void np_memory_clear_space(NP_UNUSED np_state_t* context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* data) {
    memset(data, 0, size);
}

void np_memory_randomize_space(NP_UNUSED np_state_t* context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* data) {
    randombytes_buf(data, size);
}

void _np_memory_job_memory_management(np_state_t* context, NP_UNUSED  np_jobargs_t args) {

    NP_PERFORMANCE_POINT_START(memory_management);
    for (uint8_t memory_type = 0; memory_type < np_memory_types_MAX_TYPE; memory_type++) {
        np_memory_container_t* container = np_module(memory)->__np_memory_container[memory_type];
        if (container != NULL && container->on_refresh_space != NULL) {
            __np_memory_itemstats_update(container);

            if (__np_memory_space_decrease_nessecary(container)) {
                //debugf("\t__np_memory_space_decrease\n");
                __np_memory_space_decrease(container);
            }
            /*
            else if (__np_memory_space_increase_nessecary(container))
            {
                //debugf("__np_memory_space_increase\n");
                __np_memory_space_increase(container, container->count_of_items_per_block);
            }
            */

            uint32_t list_size = 0;
            _LOCK_ACCESS(&container->free_items_lock) {
                list_size = sll_size(container->free_items);
            }
            np_memory_itemconf_ptr list_as_array[list_size];

            _LOCK_ACCESS(&container->free_items_lock)
            {
                for (uint32_t k = list_size; k > 0; k--) {
                    list_as_array[k - 1] = sll_head(np_memory_itemconf_ptr, container->free_items);
                }
            }

            for (uint32_t k = list_size; k > 0 && k <= list_size; k--)
            {
                np_memory_itemconf_t* item_config = list_as_array[k - 1];
                if (item_config != NULL)
                {
                    _LOCK_ACCESS(&item_config->access_lock)
                    {
                        __np_memory_refresh_space(item_config);
                        _LOCK_ACCESS(&container->refreshed_items_lock)
                        {
                            sll_append(np_memory_itemconf_ptr, container->refreshed_items, item_config);
                        }
                    }
                }
            }
        }
    }
    NP_PERFORMANCE_POINT_END(memory_management);
}

// increase ref count
void np_mem_refobj(np_state_t*context, void * item, const char* reason)
{
    assert(item != NULL);
    np_check_magic_no(item);
    np_memory_itemconf_t * config = GET_CONF(item);    

    _LOCK_ACCESS(&config->access_lock) {
        log_trace_msg(LOG_TRACE, "start: void np_mem_refobj(np_obj_t* obj){");
        if (config->persistent == false) {
            config->ref_count++;
            //log_msg(LOG_DEBUG,"Referencing object (%p; t: %d)", obj,obj->type);
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
            assert(reason != NULL);
            sll_prepend(char_ptr, config->reasons, strdup(reason));
#endif
        }
    }
}

// decrease ref count
void np_mem_unrefobj(np_memory_itemconf_t * config, const char* reason)
{	
    np_ctx_decl(config->container->module->context);

    _LOCK_ACCESS(&config->access_lock) {
        if (config->persistent == false) {
            if (config->ref_count == 0) {
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
                log_msg(LOG_ERROR, 
                    "Unreferencing object (%s; t: %d/%s) too often! try to unref for \"%s\". (left reasons(%"PRIu32"): %s)",
                    config->id, config->container->type, np_memory_types_str[config->container->type],reason, config->ref_count,
                    _sll_char_make_flat(context, config->reasons)
                );
#else
                log_msg(LOG_ERROR, "Unreferencing object (%p; t: %d/%s) too often! try to unref for \"%s\". left reasons(%"PRIu32")", 
                    config, config->container->type, np_memory_types_str[config->container->type], reason, config->ref_count);
#endif
                assert(config->ref_count > 0 && "Unreferencing object too often!");
                abort();
            }
            config->ref_count--;
        }
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
        bool foundReason = _np_memory_remove_reason(config->reasons, reason);
        if (false == foundReason) {
            char* flat = _sll_char_make_flat(context, config->reasons);
            log_msg(LOG_ERROR, "reason \"%s\" for dereferencing obj %s (type:%d/%s reasons(%d): %s) was not found. ", reason, config->id, config->container->type, np_memory_types_str[config->container->type], sll_size(config->reasons), flat);
            free(flat);
            abort();
        }
        char * flat = _sll_char_make_flat(context, config->reasons);
        log_debug_msg(LOG_MEMORY | LOG_DEBUG, "_UnRef_  (%"PRIu32") object of type \"%s\" on %s with \"%s\" (%s)", config->ref_count, np_memory_types_str[config->container->type], config->id, reason, flat);
        free(flat);
#endif

    }
}

// print the complete object list and statistics
char* np_mem_printpool(np_state_t* context, bool asOneLine, bool extended)
{
    char* ret = NULL;
    char* new_line = "\n";
    if (asOneLine == true) {
        new_line = "    ";
    }

    uint32_t summary[np_memory_types_MAX_TYPE] = { 0 };
    uint32_t summary_refs[np_memory_types_MAX_TYPE] = { 0 };
    uint32_t summary_total[np_memory_types_MAX_TYPE] = { 0 };

    if (true == extended) {
        ret = np_str_concatAndFree(ret, "--- extended reasons start ---%s", new_line);
    }

    for (int memory_type = 0; memory_type < np_memory_types_MAX_TYPE; memory_type++)
    {
        np_memory_container_t* container = np_module(memory)->__np_memory_container[memory_type];

        summary[container->type] = fmax(summary[container->type], container->current_in_use);
        
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING		
        uint32_t max = 1;
     
        _LOCK_ACCESS(&container->total_items_lock) {
            summary_total[container->type] = sll_size(container->total_items);
            sll_iterator(np_memory_itemconf_ptr) iter_items = sll_first(container->total_items);
            while (iter_items != NULL)
            {
                np_memory_itemconf_ptr iter = iter_items->val;
                _TRYLOCK_ACCESS(&iter->access_lock) {

                    max = fmax(max, iter->ref_count);

                    if (true == extended
                        && (
                            //true
                            //container->type == np_memory_types_np_node_t
                            container->type == np_memory_types_np_key_t
                            //|| container->type == np_msgproperty_t_e
                            )
                        )
                    {
                        if (sll_size(iter->reasons) > 0) {
                            ret = np_str_concatAndFree(ret,
                                "--- remaining reasons for %s (type: %d/%s, reasons: %d) start ---%s", iter->id,
                                memory_type,
                                np_memory_types_str[memory_type],
                                sll_size(iter->reasons), new_line
                            );

                            static const uint32_t display_first_X_reasons = 15;
                            static const uint32_t display_last_X_reasons = 15;

                            sll_iterator(char_ptr) iter_reasons = sll_first(iter->reasons);
                            uint32_t iter_reasons_counter = 0;
                            while (iter_reasons != NULL)
                            {
                                if (iter_reasons_counter < display_first_X_reasons) {
                                    ret = np_str_concatAndFree(ret, "\"%s\"%s", iter_reasons->val, new_line);
                                }

                                if (
                                    (display_first_X_reasons + display_last_X_reasons) < sll_size(iter->reasons)
                                    && display_first_X_reasons == iter_reasons_counter)
                                {
                                    ret = np_str_concatAndFree(ret, "... Skipping %"PRIi32" reasons ...%s", sll_size(iter->reasons) - (display_first_X_reasons + display_last_X_reasons), new_line);
                                }

                                if (
                                    iter_reasons_counter > display_first_X_reasons
                                    && iter_reasons_counter >= display_first_X_reasons + sll_size(iter->reasons) - (display_first_X_reasons + display_last_X_reasons))
                                {
                                    ret = np_str_concatAndFree(ret, "\"%s\"%s", iter_reasons->val, new_line);
                                }

                                iter_reasons_counter++;
                                sll_next(iter_reasons);
                            }
                            ret = np_str_concatAndFree(ret,
                                "--- remaining reasons for %s (%d/%s) end  ---%s",
                                iter->id,
                                memory_type,
                                np_memory_types_str[memory_type],
                                new_line
                            );
                        }
                    }
                }
                sll_next(iter_items);
            }

        }
        summary_refs[container->type] = max;
#endif
    }

    if (true == extended) {
#ifndef NP_MEMORY_CHECK_MEMORY_REFFING
        ret = np_str_concatAndFree(ret, "NO DATA. Compile with NP_MEMORY_CHECK_MEMORY_REFFING %s", new_line);
#endif
        ret = np_str_concatAndFree(ret, "--- extended reasons end  ---%s", new_line);
    }
    
    if(asOneLine)
        ret = np_str_concatAndFree(ret, "--- memory summary---%s", new_line);

    ret = np_str_concatAndFree(ret, "%20s | u./count | max ref%s", "name", new_line);

    for (int memory_type = 0; memory_type < np_memory_types_MAX_TYPE; memory_type++)
    {
        ret = np_str_concatAndFree(ret,
            "%20s | %3"PRIu32"/%4"PRIu32" | %3"PRIu32"%s", 
            np_memory_types_str[memory_type], 
            summary[memory_type], summary_total[memory_type],
            summary_refs[memory_type],
            new_line
        );
    }

    if (asOneLine)
        ret = np_str_concatAndFree(ret, "--- memory end ---%s", new_line);

    return (ret);
}

#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
void np_memory_ref_replace_reason(void* item, const char* old_reason, const char* new_reason)
{
    if (item != NULL) {
        assert(old_reason != NULL);
        np_memory_itemconf_t* config = GET_CONF(item);
        np_ctx_decl(config->container->module->context);

        _LOCK_ACCESS(&config->access_lock) {
            sll_iterator(char_ptr) iter_reasons = sll_first(config->reasons);			
            bool foundReason = false;
            while (foundReason == false && iter_reasons != NULL)
            {	
                if (strlen(iter_reasons->val) >= strlen(old_reason) + _NP_REF_REASON_SEPERATOR_CHAR_LEN) {
                    foundReason = 0 == strncmp(iter_reasons->val, old_reason, strlen(old_reason));
                    char* tmp = iter_reasons->val + strlen(old_reason);
                    foundReason &= 0 == strncmp(tmp,
                        _NP_REF_REASON_SEPERATOR_CHAR, _NP_REF_REASON_SEPERATOR_CHAR_LEN);
                }

                if (foundReason == true) {
                    free(iter_reasons->val);
                    sll_delete(char_ptr, config->reasons, iter_reasons);
                    break;
                }
                
                sll_next(iter_reasons);
            }
            if (false == foundReason)
            {
                char * flat = _sll_char_make_flat(context, config->reasons);
                log_msg(LOG_ERROR,
                    "Reason switch on object (%s; t: %s) \"%s\" to \"%s\" not possible! Reason not found. (left reasons(%d): %s)",
                    config->id, np_memory_types_str[config->container->type], old_reason, new_reason, config->ref_count, flat);
                free(flat);
                abort();
            }
            else {
                _NP_REF_REASON(new_reason, "", reason2)
                    sll_prepend(char_ptr, config->reasons, strndup(reason2, strlen(reason2)));
            }
        }
    }
}
#endif

void np_memory_ref_obj(np_state_t* context, void* item, const char* reason, const char* reason_desc)
{
    assert(item != NULL);
    np_check_magic_no(item);
    np_memory_itemconf_t* config = GET_CONF(item);

    _NP_REF_REASON(reason, reason_desc, reason2);
    _LOCK_ACCESS(&config->access_lock) {
        np_mem_refobj(context, item, reason2); 
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING        
        char * flat = _sll_char_make_flat(context, config->reasons);
        log_debug_msg(LOG_MEMORY | LOG_DEBUG, "_Ref_    (%"PRIu32") object of type \"%s\" on %s with \"%s\" (%s)", config->ref_count, np_memory_types_str[config->container->type], config->id, reason, flat);		
        free(flat);
#endif
    }

}

void* np_memory_waitref_obj(np_state_t* context, void* item, const char* reason, const char* reason_desc) {
    void* ret = NULL;

    while (ret == NULL) {

        if (item != NULL) {
            np_memory_itemconf_t* config = GET_CONF(item);            

            _LOCK_ACCESS(&config->access_lock) {

                np_memory_ref_obj(context, item, reason, reason_desc);
                ret = item;
            }
        }
        else {
            np_time_sleep(NP_SLEEP_MIN);
        }
    }

    return ret;
}

void* np_memory_tryref_obj(np_state_t* context, void* item, const char* reason, const char* reason_desc) {
    void* ret = NULL;
    if (item != NULL) {
        np_memory_itemconf_t* config = GET_CONF(item);

        _LOCK_ACCESS(&config->access_lock) {			
            _NP_REF_REASON(reason, reason_desc, reason2);
            np_mem_refobj(context, item, reason2);
            ret = item;
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING        
            char* flat = _sll_char_make_flat(context, config->reasons);
            log_debug_msg(LOG_MEMORY | LOG_DEBUG, "_TryRef_ (%"PRIu32") object of type \"%s\" on %s with \"%s\" (%s)", config->ref_count, np_memory_types_str[config->container->type], config->id, reason, flat);
            free(flat);
#endif

        }
    }
    return ret;
}

uint32_t np_memory_unref_obj(np_state_t* context, void* item, const char* reason) {
    uint32_t ret = 0;	
    if (item != NULL) {
        np_check_magic_no(item);
        np_memory_itemconf_t* config = GET_CONF(item);        

        _LOCK_ACCESS(&config->access_lock) {
            np_mem_unrefobj(config, reason);
            ret = config->ref_count + (config->persistent ? 1 : 0);
            np_memory_free(context, item);		
        }		
    }
    return ret;
}

char* np_memory_get_id(void * item)
{
    char* ret = "unknown";
    if (item != NULL) {
        np_memory_itemconf_t* config = GET_CONF(item);
        ret = config->id;
    }
    return ret;
}

uint32_t np_memory_get_refcount(void * item) {
    uint32_t ret = 0;
    if (item != NULL) {
        np_memory_itemconf_t* config = GET_CONF(item);
        ret = config->ref_count;
    }
    return ret;
}
uint8_t np_memory_get_type(void * item) {
    uint8_t ret = 0;
    if (item != NULL) {
        np_memory_itemconf_t* config = GET_CONF(item);
        ret = config->container->type;
    }
    return ret;
}
