//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
* header only implementation to manage heap objects
* taking the generating approach using the c preprocessor
*/
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include "sodium.h"

#include "np_memory_v2.h"

#include "neuropil.h"
#include "np_log.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_list.h"
#include "np_constants.h"
#include "np_settings.h"

/*
	General workflow:
	After you register a type with a known size a container will be created which contains multiple memory blocks.
	Every block may contains exactly count_of_items_per_block items + the configuration for each item.
	the configuration of each item is preceeding to the memory of the item itself.

*/
typedef struct np_memory_container_s np_memory_container_t;

typedef struct np_memory_block_s
{
	np_memory_container_t* container;
	uint32_t current_in_use;
	uint32_t last_item;
	np_mutex_t attr_lock;
	void* space;
} np_memory_block_t;

typedef np_memory_block_t*  np_memory_block_ptr;

NP_SLL_GENERATE_PROTOTYPES(np_memory_block_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_memory_block_ptr);

struct np_memory_container_s
{
	uint8_t type;

	uint32_t count_of_items_per_block;
	uint32_t min_count_of_items;
	size_t size_per_item;

	np_memory_on_new on_new;
	np_memory_on_free on_free;
	np_memory_on_refresh_space on_refresh_space;

	np_mutex_t attr_lock;
	uint32_t current_in_use;

	np_mutex_t blocks_lock;
	np_sll_t(np_memory_block_ptr, blocks);
};

typedef struct np_memory_itemconf_ts {
	np_memory_block_t* block;

	np_bool in_use;
	np_bool needs_refresh;
	np_mutex_t access_lock;
} np_memory_itemconf_t;

np_memory_container_t* np_memory_containers[UINT8_MAX] = { 0 };

#define NEXT_ITEMCONF(conf, skip) conf = (np_memory_itemconf_t*) (((char*)conf) + (((skip)+1) * ((conf)->block->container->size_per_item + sizeof(np_memory_itemconf_t))));
#define GET_CONF(item) (((char*)item) - sizeof(np_memory_itemconf_t))
#define GET_ITEM(config) (((char*)config) + sizeof(np_memory_itemconf_t))

void np_memory_init() {
	for (int i = 0; i < np_memory_types_END_TYPES; i++) {
		np_memory_containers[i] = NULL;
	}
	np_memory_register_type(np_memory_types_BLOB_1024, 1024, 4, 4, NULL, NULL, np_memory_clear_space);
	np_memory_register_type(np_memory_types_BLOB_984_RANDOMIZED, 984, 4, 200, NULL, NULL, np_memory_randomize_space);
}

void __np_memory_create_block(np_memory_container_t* container) {
	np_memory_block_t* new_block = calloc(1, sizeof(np_memory_block_t));
	CHECK_MALLOC(new_block);
	new_block->container = container;

	size_t  whole_item_size = container->size_per_item + sizeof(np_memory_itemconf_t);
	size_t container_size = container->count_of_items_per_block * whole_item_size;

	new_block->space = malloc(container_size);
	CHECK_MALLOC(new_block->space);
	new_block->current_in_use = 0;
	new_block->last_item = 0;

	if (_np_threads_mutex_init(&(new_block->attr_lock), "MemoryV2 block attr lock") != 0) {
		log_msg(LOG_ERROR, "Could not create memory item lock for container type %"PRIu8, container->type);
	}

	// BLOCK refresh
	if (container->on_refresh_space != NULL)
		container->on_refresh_space(container->type, container_size, new_block->space);

	np_memory_itemconf_t* next_conf = new_block->space;

	for (uint32_t j = 0; j < container->count_of_items_per_block; j++) {
		// item init
		next_conf->block = new_block;
		next_conf->in_use = FALSE;
		next_conf->needs_refresh = FALSE; // handled the first time for the whole block
		if (_np_threads_mutex_init(&(next_conf->access_lock), "MemoryV2 conf lock") != 0) {
			log_msg(LOG_ERROR, "Could not create memory item lock for container type %"PRIu8, container->type);
		}
		NEXT_ITEMCONF(next_conf, 0)
	}
	_LOCK_ACCESS(&container->blocks_lock) {
		sll_append(np_memory_block_ptr, container->blocks, new_block);
	}
}

void np_memory_register_type(
	uint8_t type,
	size_t size_per_item,
	uint32_t count_of_items_per_block,
	uint32_t min_count_of_items,
	np_memory_on_new on_new,
	np_memory_on_free on_free,
	np_memory_on_refresh_space on_refresh_space
) {
	if (np_memory_containers[type] == NULL) {
		np_memory_container_t* container = calloc(1, sizeof(np_memory_container_t));
		CHECK_MALLOC(container);

		container->size_per_item = size_per_item;
		container->count_of_items_per_block = count_of_items_per_block;
		container->min_count_of_items = min_count_of_items;
		container->on_new = on_new;
		container->on_free = on_free;
		container->on_refresh_space = on_refresh_space;
		container->type = type;
		sll_init(np_memory_block_ptr, container->blocks);

		if (_np_threads_mutex_init(&(container->attr_lock), "MemoryV2 container attr_lock") == 0 &&
			_np_threads_mutex_init(&(container->blocks_lock), "MemoryV2 container blocks_lock") == 0) {
			while ((container->count_of_items_per_block * sll_size(container->blocks)) < container->min_count_of_items)
			{
				__np_memory_create_block(container);
			}

			np_memory_containers[container->type] = container;
			log_msg(LOG_MEMORY | LOG_INFO, "Created memory container (%p) for type %"PRIu8" at %p", container, type, np_memory_containers[container->type]);
		}
		else {
			log_msg(LOG_ERROR, "Could not create memory container lock");
		}
	}
}
void __np_memory_refresh_space(np_memory_itemconf_t* config) {
	np_memory_container_t* container = config->block->container;
	void* data = GET_ITEM(config);

	_LOCK_ACCESS(&config->access_lock) {
		if (config->in_use == FALSE && config->needs_refresh == TRUE) {
			if (container->on_refresh_space != NULL) {
				container->on_refresh_space(container->type, container->size_per_item, data);
			}
			config->needs_refresh = FALSE;
		}
	}
}

void* _np_memory_new_raw(np_memory_container_t* container) {
	void * ret = malloc(container->size_per_item);

	if (container->on_refresh_space != NULL) {
		container->on_refresh_space(container->type, container->size_per_item, ret);
	}

	if (container->on_new != NULL) {
		container->on_new(container->type, container->size_per_item, ret);
	}
	return ret;
}
void _np_memory_free_raw(void* item) {
	free(item);
}

void* np_memory_new(uint8_t type) {
	void* ret = NULL;
	np_memory_container_t* container = np_memory_containers[type];
	ASSERT(container != NULL, "Memory container %"PRIu8" needs to be initialized first.", type);

#if defined(NP_MEMORY_CHECK_MEMORY) && NP_MEMORY_CHECK_MEMORY == 1
	return _np_memory_new_raw(container);
#endif

	log_debug_msg(LOG_MEMORY | LOG_DEBUG, "Searching for next free current_block for type %"PRIu8, type);

	np_memory_itemconf_t* next_config = NULL;

	uint32_t item_idx;
	np_bool found = FALSE;
	uint32_t search_iter_counter = 0;
	np_memory_block_t* current_block;
	sll_iterator(np_memory_block_ptr) iter_blocks;

	// check for space in container
	_LOCK_ACCESS(&container->attr_lock) {
		_LOCK_ACCESS(&container->blocks_lock) {		
			if (container->current_in_use == (sll_size(container->blocks) * container->count_of_items_per_block)) {
				log_debug_msg(LOG_MEMORY | LOG_DEBUG, "Adding new memory block due to missing runtime space (pre loop).");
				__np_memory_create_block(container);
			}
		}

		// get last block (as he has likely some free space)
		iter_blocks = sll_last(container->blocks);
	}

	// get free space in block
	// iterate over blocks
	do {
		current_block = iter_blocks->val;

		if (_np_threads_mutex_trylock(&current_block->attr_lock, __func__) == 0)
		{
			// check itemcount to verify possible free space in block
			if (current_block->current_in_use < current_block->container->count_of_items_per_block) {
				// get best position in block
				_LOCK_ACCESS(&(current_block->attr_lock)) {
					item_idx = 0;
					next_config = current_block->space;
					if (current_block->current_in_use != 0) {
						item_idx = current_block->last_item % container->count_of_items_per_block;
						if(item_idx > 0)
							NEXT_ITEMCONF(next_config, item_idx-1);
					}
				}

				// iterate over space in block
				for (; item_idx < container->count_of_items_per_block; item_idx++)
				{
					// try to get item in block space
					if (_np_threads_mutex_trylock(&next_config->access_lock, __func__) == 0) {
						if (next_config->in_use == FALSE && next_config->needs_refresh == FALSE) {
							// take free space
							found = TRUE;
							next_config->in_use = TRUE;

							_np_threads_mutex_unlock(&next_config->access_lock);
							break;
						}
						_np_threads_mutex_unlock(&next_config->access_lock);
					}
					NEXT_ITEMCONF(next_config, 0)
				}
				search_iter_counter++;
			}

			_np_threads_mutex_unlock(&current_block->attr_lock);
		}
		if (found == FALSE) {
			
			_LOCK_ACCESS(&container->attr_lock) {
				if (search_iter_counter > sll_size(container->blocks) ||  //TODO: Check usage. Maybe remove this condition, may result in massive memory consumption.
					container->current_in_use == (sll_size(container->blocks)*container->count_of_items_per_block)) {
					log_debug_msg(LOG_MEMORY | LOG_DEBUG, "Adding new memory block due to missing runtime space.");
					_LOCK_ACCESS(&container->blocks_lock) {
						iter_blocks = sll_last(container->blocks);
						__np_memory_create_block(container);
					}
				}
			}
			_LOCK_ACCESS(&container->blocks_lock) {			
				// select next block
				if (iter_blocks == NULL || iter_blocks->flink == NULL) {
					iter_blocks = sll_first(container->blocks);
				}
				else {
					sll_next(iter_blocks);
				}
			}
		}
	} while (found == FALSE);	

	_LOCK_ACCESS(&current_block->attr_lock) {
		current_block->last_item = item_idx;
		current_block->current_in_use += 1;
	}
	_LOCK_ACCESS(&container->attr_lock) {
		container->current_in_use += 1;
	}
	ret = GET_ITEM(next_config);

	//log_debug_msg(LOG_DEBUG | LOG_MEMORY, "Found free current_block for type %"PRIu8" at %p", type, ret);
	__np_memory_refresh_space(next_config);

	if (container->on_new != NULL)
		container->on_new(container->type, container->size_per_item, ret);

	return ret;
}

void np_memory_free(void* item) {
#if defined(NP_MEMORY_CHECK_MEMORY) && NP_MEMORY_CHECK_MEMORY == 1
	return _np_memory_free_raw(item);
#endif

	if (item != NULL) {
		np_memory_itemconf_t* config = GET_CONF(item);

		np_memory_container_t* container = config->block->container;

		_LOCK_ACCESS(&config->access_lock) {
			config->in_use = FALSE;
			if (container->on_free != NULL)
				container->on_free(container->type, container->size_per_item, item);

			if(container->on_refresh_space != NULL)
				config->needs_refresh = TRUE;
		}

		_LOCK_ACCESS(&container->attr_lock) {
			container->current_in_use -= 1;
		}

		_LOCK_ACCESS(&config->block->attr_lock) {
			config->block->current_in_use -= 1;
		}
	}
}

void np_memory_clear_space(NP_UNUSED uint8_t type, size_t size, void* data) {
	memset(data, 0, size);
}

void np_memory_randomize_space(NP_UNUSED uint8_t type, size_t size, void* data) {
	randombytes_buf(data, size);
}

void _np_memory_job_memory_management(NP_UNUSED np_jobargs_t* args) {
	for (uint8_t i = 0; i < np_memory_types_END_TYPES; i++) {
		np_memory_container_t* container = np_memory_containers[i];
		if (container != NULL && container->on_refresh_space != NULL) {
			//_LOCK_ACCESS(&container->blocks_lock) 
			{
				//TODO: remove unused/unnecessary blocks

				// refresh items
				sll_iterator(np_memory_block_ptr) iter_blocks = sll_first(container->blocks);
				while (iter_blocks != NULL)
				{
					np_memory_itemconf_t* next_config = iter_blocks->val->space;

					for (uint32_t j = 0; j < container->count_of_items_per_block; j++) {
						if (_np_threads_mutex_trylock(&next_config->access_lock, __func__) == 0)
						{
							__np_memory_refresh_space(next_config);

							_np_threads_mutex_unlock(&next_config->access_lock);
						}
						NEXT_ITEMCONF(next_config, 0)
					}
					sll_next(iter_blocks);
				}
			}
		}
	}
}