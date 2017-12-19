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

typedef struct
{
	uint8_t type;

	void* space;
	uint32_t max_count_of_items;
	size_t size_per_item;
	uint32_t current_in_use;

	np_memory_on_new on_new;
	np_memory_on_free on_free;
	np_memory_on_container_init on_container_init;
	np_memory_on_refresh_space on_refresh_space;

	uint32_t last_item;
	np_mutex_t lock;
} np_memory_container_t;

typedef struct {
	np_memory_container_t* container;
	np_bool in_use;
	np_bool was_used;
	np_mutex_t lock;
} np_memory_item_t;

np_memory_container_t* np_memory_containers[END_TYPES];

void np_memory_init() {
	np_memory_register_type(BLOB_1024, 1024, 512, NULL, NULL, np_memory_clear_space, np_memory_clear_space);
	np_memory_register_type(BLOB_984_RANDOMIZED, 984, 1024, NULL, NULL, np_memory_randomize_space, np_memory_randomize_space);
}

void np_memory_register_type(
	uint8_t type,
	size_t size_per_item,
	uint32_t max_count_of_items,
	np_memory_on_new on_new,
	np_memory_on_free on_free,
	np_memory_on_container_init on_container_init,
	np_memory_on_refresh_space on_refresh_space
) {
	np_memory_container_t* container = calloc(1, sizeof(np_memory_container_t));
	CHECK_MALLOC(container);

	uint32_t container_size = max_count_of_items * (size_per_item + sizeof(np_memory_item_t));
	container->space = malloc(container_size);
	CHECK_MALLOC(container);

	container->size_per_item = size_per_item;
	container->max_count_of_items = max_count_of_items;
	container->on_new = on_new;
	container->on_free = on_free;
	container->on_container_init = on_container_init;
	container->on_refresh_space = on_refresh_space;
	

	_np_threads_mutex_init(&container->lock, "Memory container lock");
	np_memory_item_t* item = container->space;

	for (uint32_t j = 0; j < container->max_count_of_items; j++) {
		item += (container->size_per_item + sizeof(np_memory_item_t));

		_np_threads_mutex_init(&item->lock, "Memory item lock");
	}

	if (container->on_container_init != NULL)
		container->on_container_init(container->type, container->size_per_item, container);

	np_memory_containers[type] = container;
}

void __np_memory_refresh_space(np_memory_item_t* config) {
	np_memory_container_t* container = config->container;
	void* data = config + sizeof(np_memory_item_t);

	_LOCK_ACCESS(&config->lock) {
		if (config->was_used == TRUE) {
			if (container->on_refresh_space != NULL)
				container->on_refresh_space(container->type, container->size_per_item, data);
			config->was_used = FALSE;
		}
	}
}

void* np_memory_new(uint8_t type) {
	void* ret = NULL;
	np_memory_container_t* container = np_memory_containers[type];

	// select next
	np_memory_item_t* next_config = NULL;

	uint32_t i = 0;
	
	//TODO: deadlock on max_count_of_items set too low.
	while (ret == NULL) {
		_LOCK_ACCESS(&container->lock) {
			i = container->last_item;
		}
		do
		{
			next_config = container->space;
			i = i % container->max_count_of_items;
			next_config += i * (container->size_per_item + sizeof(np_memory_item_t));
			i++;

			if (_np_threads_mutex_trylock(&next_config->lock) == 0) {
				
				if (next_config->in_use == FALSE) {
					next_config->in_use = TRUE;

					_np_threads_mutex_unlock(&next_config->lock);
					break;
				}
				_np_threads_mutex_unlock(&next_config->lock);
			}
		} while (i < container->max_count_of_items);
		 
	}
	
	_LOCK_ACCESS(&container->lock) {
		container->last_item = i;
		container->current_in_use += 1;
	}

	ret = next_config + sizeof(np_memory_item_t);

	__np_memory_refresh_space(next_config);

	if (container->on_new != NULL)
		container->on_new(container->type, container->size_per_item, ret);

	next_config->was_used = TRUE;

	return ret;
}

void np_memory_free(void* item) {
	np_memory_item_t* config = item;
	config -= sizeof(np_memory_item_t);

	np_memory_container_t* container = config->container;

	_LOCK_ACCESS(&config->lock) {
		config->in_use = FALSE;
		if (container->on_free != NULL)
			container->on_free(container->type, container->size_per_item, item);
	}

	_LOCK_ACCESS(&container->lock) {
	 	container->current_in_use -= 1;
	}
}

void np_memory_clear_space(uint8_t type, size_t size, void* data) {
	memset(data, 0, size);
}

void np_memory_randomize_space(uint8_t type, size_t size, void* data) {
	randombytes_buf(data, size);
}

void _np_memory_job_refresh_spaces(NP_UNUSED np_jobargs_t* args) {
	for (uint8_t i = 0; i < END_RESERVED_TYPES; i++) {
		np_memory_container_t* container = np_memory_containers[i];
		if (container->on_refresh_space != NULL) {
			np_memory_item_t* next_config = container->space;

			for (uint32_t j = 0; j < container->max_count_of_items; j++) {
				next_config += (container->size_per_item + sizeof(np_memory_item_t));

				_LOCK_ACCESS(&next_config->lock) {
					if (next_config->in_use == FALSE)
						__np_memory_refresh_space(next_config);
				}
			}
		}
	}
}