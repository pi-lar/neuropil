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
typedef struct
{	
	uint32_t current_in_use;
	uint32_t last_item;
	np_mutex_t lock;
	void* space;
} np_memory_block_t;


typedef struct
{
	uint8_t type;

	uint32_t count_of_items_per_block;
	size_t size_per_item;

	np_memory_on_new on_new;
	np_memory_on_free on_free;
	np_memory_on_refresh_space on_refresh_space;
	
	uint32_t current_in_use;
	uint32_t last_item;
	np_mutex_t lock;
	void* space;
} np_memory_container_t;

typedef struct {
	np_memory_container_t* container;
	np_bool in_use;
	np_bool needs_refresh;
	np_mutex_t lock;
} np_memory_itemconf_t;

np_memory_container_t* np_memory_containers[UINT8_MAX] = { 0 };


#define NEXT_ITEMCONF(conf, skip) conf = (np_memory_itemconf_t*) (((char*)conf) + (((skip)+1) * ((conf)->container->size_per_item + sizeof(np_memory_itemconf_t))));
#define GET_CONF(item) (((char*)item) - sizeof(np_memory_itemconf_t))
#define GET_ITEM(config) (((char*)config) + sizeof(np_memory_itemconf_t))
						 

void np_memory_init() {
	for (int i = 0; i < np_memory_types_END_TYPES; i++) {
		np_memory_containers[i] = NULL;
	}
	np_memory_register_type(np_memory_types_BLOB_1024, 1024, 256, NULL, NULL, np_memory_clear_space);
	np_memory_register_type(np_memory_types_BLOB_984_RANDOMIZED, 984, 1024, NULL, NULL, np_memory_randomize_space);
}

void __np_memory_create_block(np_memory_container_t* container) {
	size_t  whole_item_size = container->size_per_item + sizeof(np_memory_itemconf_t);
	size_t container_size = container->count_of_items_per_block * whole_item_size;

	container->space = malloc(container_size);
	CHECK_MALLOC(container->space);
	container->current_in_use = 0;
	container->last_item = 0;
	
	// BLOCK refresh
	if (container->on_refresh_space != NULL)
		container->on_refresh_space(container->type, container_size, container->space);

	np_memory_itemconf_t* next_conf = container->space;

	for (uint32_t j = 0; j < container->count_of_items_per_block; j++) {			
		next_conf->container = container;
		next_conf->in_use = FALSE;
		next_conf->needs_refresh = FALSE; // handled the first time for the whole block
		if (_np_threads_mutex_init(&(next_conf->lock), "MemoryV2 conf lock") != 0) {
			log_msg(LOG_ERROR, "Could not create memory item lock for container type %"PRIu8, container->type);
		}
		NEXT_ITEMCONF(next_conf, 0)
	}
}

void np_memory_register_type(
	uint8_t type,
	size_t size_per_item,
	uint32_t count_of_items_per_block,
	np_memory_on_new on_new,
	np_memory_on_free on_free,
	np_memory_on_refresh_space on_refresh_space
) {
	np_memory_container_t* container = calloc(1, sizeof(np_memory_container_t));
	CHECK_MALLOC(container);

	container->size_per_item = size_per_item;
	container->count_of_items_per_block = count_of_items_per_block;
	container->on_new = on_new;
	container->on_free = on_free;	
	container->on_refresh_space = on_refresh_space;
	container->type = type;

	if (_np_threads_mutex_init(&(container->lock), "MemoryV2 container lock") == 0) {

		__np_memory_create_block(container);

		np_memory_containers[container->type] = container;
		log_msg(LOG_MEMORY |LOG_INFO, "Created memory container (%p) for type %"PRIu8" at %p", container, type, np_memory_containers[container->type]);
	}
	else {
		log_msg(LOG_ERROR, "Could not create memory container lock");
	}

	
}

void __np_memory_refresh_space(np_memory_itemconf_t* config) {
	np_memory_container_t* container = config->container;
	void* data = GET_ITEM(config);

	_LOCK_ACCESS(&config->lock) {
		if (config->needs_refresh == TRUE) {
			if (container->on_refresh_space != NULL)
				container->on_refresh_space(container->type, container->size_per_item, data);
			config->needs_refresh = FALSE;
		}
	}
}

void* np_memory_new(uint8_t type) {
	void* ret = NULL;
	np_memory_container_t* container = np_memory_containers[type];

	ASSERT(container != NULL, "Memory container %"PRIu8" needs to be initialized first.",type)
	// select next
	np_memory_itemconf_t* next_config = NULL;

	uint32_t item_idx = 0;	
	log_debug_msg(LOG_DEBUG | LOG_MEMORY, "Searching for next free block for type %"PRIu8, type);
	//TODO: deadlock on max_count_of_items set too low. (implement dynamic memory blocks)
	np_bool found = FALSE;
	uint32_t search_iter_counter = 0;
	do{

		// get possible best position to get new unused item
		_LOCK_ACCESS(&(container->lock)) {			
			next_config = container->space;	
			item_idx = container->last_item + 1;
			NEXT_ITEMCONF(next_config, container->last_item)
		}

		do
		{	
			if (_np_threads_mutex_trylock(&next_config->lock) == 0) {

				if (next_config->in_use == FALSE) {
					found = TRUE;
					next_config->in_use = TRUE;

					_np_threads_mutex_unlock(&next_config->lock);
					break;
				}
				_np_threads_mutex_unlock(&next_config->lock);
			}
			
			NEXT_ITEMCONF(next_config, 0)
			item_idx++;						
		} while (item_idx < container->count_of_items_per_block);
	
		if (found == FALSE && search_iter_counter > 1) {
			// create new Block
			np_time_sleep(0.005);
		}	
		search_iter_counter++;
	} while (found == FALSE);

	item_idx = item_idx % container->count_of_items_per_block;
	
	_LOCK_ACCESS(&container->lock) {
		container->last_item = item_idx;
		container->current_in_use += 1;
	}
	ret = GET_ITEM(next_config);

	log_debug_msg(LOG_DEBUG | LOG_MEMORY, "Found free block for type %"PRIu8" at %p", type, ret);
	__np_memory_refresh_space(next_config);

	if (container->on_new != NULL)
		container->on_new(container->type, container->size_per_item, ret);

	return ret;
}

void np_memory_free(void* item) {

	if(item != NULL){
		np_memory_itemconf_t* config = GET_CONF(item);

		np_memory_container_t* container = config->container;

		_LOCK_ACCESS(&config->lock) {
			config->in_use = FALSE;
			if (container->on_free != NULL)
				container->on_free(container->type, container->size_per_item, item);
			config->needs_refresh = TRUE;
		}

		_LOCK_ACCESS(&container->lock) {
	 		container->current_in_use -= 1;
		}
	}
}

void np_memory_clear_space(NP_UNUSED uint8_t type, size_t size, void* data) {
	memset(data, 0, size);
}

void np_memory_randomize_space(NP_UNUSED uint8_t type, size_t size, void* data) {
	randombytes_buf(data, size);
}

void _np_memory_job_refresh_spaces(NP_UNUSED np_jobargs_t* args) {
	for (uint8_t i = 0; i < np_memory_types_END_TYPES; i++) {
		np_memory_container_t* container = np_memory_containers[i];
		if (container != NULL && container->on_refresh_space != NULL) {

			//TODO:  go over block(s)
			np_memory_itemconf_t* next_config = container->space;

			for (uint32_t j = 0; j < container->count_of_items_per_block; j++) {
		
				if(_np_threads_mutex_trylock(&next_config->lock) == 0)
				 {
					if (next_config->in_use == FALSE && next_config->needs_refresh == TRUE)
						__np_memory_refresh_space(next_config);

					_np_threads_mutex_unlock(&next_config->lock);
				}
				NEXT_ITEMCONF(next_config, 0)				
			}
		}
	}
}