//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_MEMORY_V2_H_
#define _NP_MEMORY_V2_H_

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif
	enum np_memory_types_e {
		np_memory_types_BLOB_1024,
		np_memory_types_BLOB_984_RANDOMIZED,
		np_memory_types_np_message_t,
		np_memory_types_np_msgproperty_t,
		np_memory_types_np_thread_t,
		np_memory_types_np_node_t,
		np_memory_types_np_network_t,
		np_memory_types_np_key_t,
		np_memory_types_np_responsecontainer_t,
		np_memory_types_np_messagepart_t,
		np_memory_types_np_aaatoken_t,		
		
		np_memory_types_test_struct_t,		
		np_memory_types_END_TYPES = 254,
	};

	typedef void(*np_memory_on_new) (uint8_t type, size_t size, void* data);
	typedef void(*np_memory_on_free) (uint8_t type, size_t size, void* data);
	typedef void(*np_memory_on_refresh_space) (uint8_t type, size_t size, void* data);

	void np_memory_init();

	NP_API_EXPORT
		void np_memory_register_type(
			uint8_t type,
			size_t size_per_item,
			uint32_t count_of_items_per_block,
			uint32_t min_count_of_items,
			np_memory_on_new on_new,
			np_memory_on_free on_free,
			np_memory_on_refresh_space on_refresh_space
		);

	NP_API_EXPORT
		void* np_memory_new(uint8_t  type);
	NP_API_EXPORT
		void np_memory_free(void* item);

	NP_API_EXPORT
		void np_memory_clear_space(NP_UNUSED uint8_t type, size_t size, void* data);

	NP_API_EXPORT
		void np_memory_randomize_space(NP_UNUSED uint8_t type, size_t size, void* data);

	NP_API_INTERN
	void _np_memory_job_memory_management(NP_UNUSED np_jobargs_t* args);
#ifdef __cplusplus
}
#endif

#endif // _NP_MEMORY_V2_H_
