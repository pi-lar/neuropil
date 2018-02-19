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
#include <float.h>
#include <inttypes.h>
#include <math.h>

#include "sodium.h"

#include "np_memory_v2.h"

#include "neuropil.h"
#include "np_log.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_list.h"
#include "np_types.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_key.h"
#include "np_aaatoken.h"
#include "np_threads.h"
#include "np_node.h"
#include "np_network.h"
#include "np_responsecontainer.h"
#include "np_messagepart.h"


#include "np_constants.h"
#include "np_settings.h"

/*
	General workflow:
	After you register a type with a known size a container will be created which contains multiple memory blocks.
	Every block may contains exactly count_of_items_per_block items + the configuration for each item.
	the configuration of each item is preceeding to the memory of the item itself.

*/

typedef struct np_memory_itemconf_s np_memory_itemconf_t;
typedef np_memory_itemconf_t* np_memory_itemconf_ptr;

NP_SLL_GENERATE_PROTOTYPES(np_memory_itemconf_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_memory_itemconf_ptr);

struct np_memory_itemstat_s {
	double time;
	uint32_t itemcount;
};

typedef struct np_memory_container_s
{
	uint8_t type;

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

	np_mutex_t current_in_use_lock;
	uint32_t current_in_use;

	np_bool itemstats_full;
	uint32_t itemstats_idx;
	struct np_memory_itemstat_s itemstats[10];
} np_memory_container_t;

struct np_memory_itemconf_s {
	np_memory_container_t* container;

	np_bool in_use;
	np_bool needs_refresh;
	np_mutex_t access_lock;
};

np_memory_container_t* np_memory_containers[UINT8_MAX] = { 0 };

#define NEXT_ITEMCONF(conf, skip) conf = (np_memory_itemconf_t*) (((char*)conf) + (((skip)+1) * ((conf)->block->container->size_per_item + sizeof(np_memory_itemconf_t))));
#define GET_CONF(item) ((np_memory_itemconf_t*)(((char*)item) - sizeof(np_memory_itemconf_t)))
#define GET_ITEM(config) (((char*)config) + sizeof(np_memory_itemconf_t))

void np_memory_init() {
	for (int i = 0; i < np_memory_types_END_TYPES; i++) {
		np_memory_containers[i] = NULL;
	}
	np_memory_register_type(np_memory_types_np_message_t, sizeof(np_message_t), 4, 4, NULL, NULL, np_memory_clear_space);
	np_memory_register_type(np_memory_types_np_key_t, sizeof(np_key_t), 4, 4, NULL, NULL, np_memory_clear_space);
	np_memory_register_type(np_memory_types_np_msgproperty_t, sizeof(np_msgproperty_t), 4, 4, NULL, NULL, np_memory_clear_space);
	np_memory_register_type(np_memory_types_np_thread_t, sizeof(np_thread_t), 4, 4, NULL, NULL, np_memory_clear_space);
	np_memory_register_type(np_memory_types_np_node_t, sizeof(np_node_t), 4, 4, NULL, NULL, np_memory_clear_space);
	np_memory_register_type(np_memory_types_np_network_t, sizeof(np_network_t), 4, 4, NULL, NULL, np_memory_clear_space);
	np_memory_register_type(np_memory_types_np_responsecontainer_t, sizeof(np_responsecontainer_t), 4, 4, NULL, NULL, np_memory_clear_space);
	np_memory_register_type(np_memory_types_np_messagepart_t, sizeof(np_messagepart_t), 4, 4, NULL, NULL, np_memory_clear_space);
	np_memory_register_type(np_memory_types_np_aaatoken_t, sizeof(np_aaatoken_t), 4, 4, NULL, NULL, np_memory_clear_space);
	
	
	np_memory_register_type(np_memory_types_BLOB_1024, 1024, 4, 4, NULL, NULL, np_memory_clear_space);
	np_memory_register_type(np_memory_types_BLOB_984_RANDOMIZED, 984, 4, 200, NULL, NULL, np_memory_randomize_space);
	_np_memory_job_memory_management(NULL);
}

void __np_memory_space_increase(np_memory_container_t* container, uint32_t block_size) {
	for (uint32_t j = 0; j < block_size; j++) {
		size_t  whole_item_size = container->size_per_item + sizeof(np_memory_itemconf_t);

		np_memory_itemconf_t* conf = malloc(whole_item_size);
		CHECK_MALLOC(conf);

		// item init
		conf->container = container;
		conf->in_use = FALSE;
		conf->needs_refresh = TRUE;
		if (_np_threads_mutex_init(&(conf->access_lock), "MemoryV2 conf lock") != 0) {
			log_msg(LOG_ERROR, "Could not create memory item lock for container type %"PRIu8, container->type);
		}

		_LOCK_ACCESS(&container->free_items_lock) {
			sll_append(np_memory_itemconf_ptr, container->free_items, conf);
		}
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

		container->itemstats_idx = 0;
		container->itemstats_full = FALSE;
		memset(container->itemstats, 0, sizeof(container->itemstats));
		container->size_per_item = size_per_item;
		container->count_of_items_per_block = count_of_items_per_block;
		container->min_count_of_items = min_count_of_items;
		container->on_new = on_new;
		container->on_free = on_free;
		container->on_refresh_space = on_refresh_space;
		container->type = type;

		sll_init(np_memory_itemconf_ptr, container->free_items);
		if (_np_threads_mutex_init(&(container->free_items_lock), "MemoryV2 container free_items_lock lock") != 0) {
			log_msg(LOG_ERROR, "Could not create free_items_lock for container type %"PRIu8, container->type);
		}
		sll_init(np_memory_itemconf_ptr, container->refreshed_items);
		if (_np_threads_mutex_init(&(container->refreshed_items_lock), "MemoryV2 container refreshed_items lock") != 0) {
			log_msg(LOG_ERROR, "Could not create refreshed_items for container type %"PRIu8, container->type);
		}

		if (_np_threads_mutex_init(&(container->current_in_use_lock), "MemoryV2 container attr_lock") == 0)
		{
			int i = 0;
			while ((container->count_of_items_per_block * i) < container->min_count_of_items)
			{
				i++;
				__np_memory_space_increase(container, container->count_of_items_per_block);
			}

			np_memory_containers[container->type] = container;
			log_msg(LOG_MEMORY | LOG_INFO, "Created memory container (%p) for type %"PRIu8" at %p", container, type, np_memory_containers[container->type]);
		}
		else {
			log_msg(LOG_ERROR, "Could not create memory container lock");
		}
	}
}
np_bool __np_memory_refresh_space(np_memory_itemconf_t* config) {
	np_bool refreshed = FALSE;
	np_memory_container_t* container = config->container;
	void* data = GET_ITEM(config);

	_LOCK_ACCESS(&config->access_lock) {
		if (config->in_use == FALSE && config->needs_refresh == TRUE) {
			if (container->on_refresh_space != NULL) {
				container->on_refresh_space(container->type, container->size_per_item, data);
			}
			config->needs_refresh = FALSE;
			refreshed = TRUE;
		}
	}
	return refreshed;
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

void __np_memory_itemstats_update(np_memory_container_t* container) {
	_LOCK_ACCESS(&container->current_in_use_lock) {
		struct np_memory_itemstat_s * itemstat = &container->itemstats[container->itemstats_idx];
		itemstat->itemcount = container->current_in_use;
		itemstat->time = np_time_now();

		container->itemstats_full = container->itemstats_full || (container->itemstats_idx + 1) == (sizeof(container->itemstats) / sizeof(container->itemstats[0]));
		container->itemstats_idx = ((1 + container->itemstats_idx) % (sizeof(container->itemstats) / sizeof(container->itemstats[0])));
	}
}

double __np_memory_itemstats_get_growth(np_memory_container_t* container) {
	double growth = 0;
	double min_time = DBL_MAX;
	double max_time = 0;
	for (uint32_t i = 0; i < container->itemstats_idx; i++) {
		struct np_memory_itemstat_s itemstat = container->itemstats[container->itemstats_idx];
		min_time = min(min_time, itemstat.time);
		max_time = max(max_time, itemstat.time);
	}
	if (container->itemstats_full) {
		
		CALC_STATISTICS(container->itemstats, .itemcount,
			(sizeof(container->itemstats)/sizeof(container->itemstats[0])),
			itemstats_min, itemstats_max, itemstats_avg, itemstats_stddev);		

		
		_LOCK_ACCESS(&container->current_in_use_lock) {		
			growth = (container->current_in_use - itemstats_avg) / (max_time == min_time ? 1 : max_time - min_time);
		}
	}
	return growth;
}

np_bool __np_memory_space_decrease_nessecary(np_memory_container_t* container) {
	np_bool ret = FALSE;


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
						/*decrease if the growth of items is negative for the mesured period, the grows is min as great as a block, and the growth size is free*/
					(0 > growth &&
						fabs(growth) > container->count_of_items_per_block &&
						total_free_space > fabs(growth)
						)

						||

						/*decrease if we only consume 50% or less of our space*/
						//container->current_in_use <= (total_space_available * 0.5)
						FALSE
						)
					;
			}
		}
	}
	return ret;
}

np_bool __np_memory_space_increase_nessecary(np_memory_container_t* container) {
	np_bool ret = FALSE;

	_LOCK_ACCESS(&container->current_in_use_lock) {
		_LOCK_ACCESS(&container->refreshed_items_lock) {
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
			np_bool del = FALSE;
			_LOCK_ACCESS(&item_config->access_lock) {
				del = item_config->in_use == FALSE;
			}
			if (del) {
				_np_threads_mutex_destroy(&item_config->access_lock);
				free(item_config);
			}
		}
		else {
			break;
		}
	}
}

void* np_memory_new(uint8_t type) {
	NP_PERFORMANCE_POINT_START(memory_new);
	void* ret = NULL;
	np_memory_container_t* container = np_memory_containers[type];
	ASSERT(container != NULL, "Memory container %"PRIu8" needs to be initialized first.", type);

	log_debug_msg(LOG_MEMORY | LOG_DEBUG, "Searching for next free current_block for type %"PRIu8, type);

	np_memory_itemconf_t* next_config;
	np_bool found = FALSE;

	do {
		next_config = NULL; // init loop condition

		while (next_config == NULL) {
			_LOCK_ACCESS(&container->refreshed_items_lock) {
				// best pick: an already refreshed container
				next_config = sll_head(np_memory_itemconf_ptr, container->refreshed_items);

				if (next_config == NULL) {
					// second best pick: a free container
					_TRYLOCK_ACCESS(&container->free_items_lock) {
						next_config = sll_head(np_memory_itemconf_ptr, container->free_items);

						if (next_config == NULL) {
							// worst case: create a new block
							__np_memory_space_increase(container, 1);
							next_config = sll_head(np_memory_itemconf_ptr, container->free_items);
						}

						// second bast as we need to refresh the item
						__np_memory_refresh_space(next_config);													
					}
				}
			}
		}
		// now we do have a item space. we need to check if the space is already in use (should not but better play safe)
		_LOCK_ACCESS(&next_config->access_lock) {
			if (next_config->in_use == FALSE) {
				// take free space
				found = TRUE;
				next_config->in_use = TRUE;
			}
		}
	} while (found == FALSE);

	_LOCK_ACCESS(&container->current_in_use_lock) {
		container->current_in_use += 1;
	}

	//debugf("%"PRIu8": %5"PRIu32" / %5"PRIu32"  \n", container->type, container->current_in_use, sll_size(container->blocks)*container->count_of_items_per_block);

	ret = GET_ITEM(next_config);

	if (container->on_new != NULL)
		container->on_new(container->type, container->size_per_item, ret);

	NP_PERFORMANCE_POINT_END(memory_new);
	return ret;
}

void np_memory_free(void* item) {	
	if (item != NULL) {
		NP_PERFORMANCE_POINT_START(memory_free);
		np_memory_itemconf_t* config = GET_CONF(item);
		np_memory_container_t* container = config->container;

		_LOCK_ACCESS(&config->access_lock) {
			config->in_use = FALSE;

			if (container->on_free != NULL)
				container->on_free(container->type, container->size_per_item, item);

			if (container->on_refresh_space != NULL) {
				config->needs_refresh = TRUE;
			}

			if (config->needs_refresh) {
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

		_LOCK_ACCESS(&container->current_in_use_lock) {
			container->current_in_use -= 1;
		}
		NP_PERFORMANCE_POINT_END(memory_free);
	}	
}

void np_memory_clear_space(NP_UNUSED uint8_t type, size_t size, void* data) {
	memset(data, 0, size);
}

void np_memory_randomize_space(NP_UNUSED uint8_t type, size_t size, void* data) {
	randombytes_buf(data, size);
}

void _np_memory_job_memory_management(NP_UNUSED np_jobargs_t* args) {
	NP_PERFORMANCE_POINT_START(memory_management);
	for (uint8_t memory_type = 0; memory_type < np_memory_types_END_TYPES; memory_type++) {
		np_memory_container_t* container = np_memory_containers[memory_type];
		if (container != NULL && container->on_refresh_space != NULL) {
			__np_memory_itemstats_update(container);
			
			if (__np_memory_space_decrease_nessecary(container)) {
				//debugf("\t__np_memory_space_decrease\n");
				__np_memory_space_decrease(container);
			}
			
			if (__np_memory_space_increase_nessecary(container))
			{
				//debugf("__np_memory_space_increase\n");
				__np_memory_space_increase(container, container->count_of_items_per_block);
			}

			// refresh items
			np_memory_itemconf_ptr * list_as_array;
			uint32_t i = 0;
			_LOCK_ACCESS(&container->free_items_lock)
			{
				list_as_array = malloc(sll_size(container->free_items) * sizeof(np_memory_itemconf_ptr));

				sll_iterator(np_memory_itemconf_ptr) iter_refreshable = sll_first(container->free_items);

				while (iter_refreshable != NULL)
				{
					list_as_array[i] = iter_refreshable->val;
					i++;
					sll_next(iter_refreshable);
				}
				sll_clear(np_memory_itemconf_ptr, container->free_items);
			}
			
			if (i/*count_of_array_size */ > 0) {				
				for (i--; i > 0; i--) // i as index, not as count
				{
					np_memory_itemconf_t* item_config = list_as_array[i];

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