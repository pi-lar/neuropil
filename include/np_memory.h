//
// neuropil is copyright 2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_MEMORY_H_
#define _NP_MEMORY_H_

#include "np_types.h"
#include "np_settings.h"
#include "np_constants.h"


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
		np_memory_types_np_job_t,
		np_memory_types_np_jobargs_t,
		np_memory_types_MAX_TYPE
	};

	static const char* np_memory_types_str[] = {
		"BLOB_1024",
		"BLOB_984_RANDOMIZED",
		"message",
		"msgproperty",
		"thread",
		"node",
		"network",
		"key",
		"responsecontainer",
		"messagepart",
		"aaatoken",
		"job",
		"jobargs"
	};

	typedef void(*np_memory_on_new) (np_state_t *context, uint8_t type, size_t size, void* data);
	typedef void(*np_memory_on_free) (np_state_t *context, uint8_t type, size_t size, void* data);
	typedef void(*np_memory_on_refresh_space) (np_state_t *context, uint8_t type, size_t size, void* data);

	bool _np_memory_init(np_state_t* context);

	NP_API_EXPORT
		void np_memory_register_type(
			np_state_t* context,
			enum np_memory_types_e type,
			size_t size_per_item,
			uint32_t count_of_items_per_block,
			uint32_t min_count_of_items,
			np_memory_on_new on_new,
			np_memory_on_free on_free,
			np_memory_on_refresh_space on_refresh_space
		);

	NP_API_EXPORT
		void* np_memory_new(np_state_t* context, enum np_memory_types_e  type);
	NP_API_EXPORT
		void np_memory_free(void* item);

	NP_API_EXPORT
		void np_memory_clear_space(np_state_t* context, uint8_t type, size_t size, void* data);

	NP_API_EXPORT
		void np_memory_randomize_space(np_state_t* context, uint8_t type, size_t size, void* data);

	NP_API_INTERN
		void _np_memory_job_memory_management(np_state_t* context, np_jobargs_t* args);

	NP_API_INTERN
	void np_memory_ref_obj(void* item, char* reason, char* reason_desc);

	NP_API_INTERN
	void* np_memory_tryref_obj(void* item, char* reason, char* reason_desc);

	NP_API_INTERN
	void* np_memory_waitref_obj(void* item, char* reason, char* reason_desc);
	/*
	Returns the context of a memory managed object
	*/
	NP_API_INTERN
		np_state_t* np_memory_get_context(void* item);
	NP_API_INTERN
	void np_memory_ref_replace_reason(void* item, char* old_reason, char* new_reason);
	NP_API_INTERN
	uint32_t np_memory_unref_obj(void* item, char* reason);
	NP_API_INTERN
	void np_mem_refobj(void * item, const char* reason);

	// print the complete object list and statistics
	NP_API_EXPORT
		char* np_mem_printpool(np_state_t* context, bool asOneLine, bool extended);
	NP_API_INTERN
		uint32_t np_memory_get_refcount(void * item);
	NP_API_INTERN
		char* np_memory_get_id(void * item);


	// macro definitions to generate header prototype definitions
#define _NP_GENERATE_MEMORY_PROTOTYPES(TYPE)												\
void _##TYPE##_new(np_state_t * context, uint8_t type, size_t size, void* data);			\
void _##TYPE##_del(np_state_t * context, uint8_t type, size_t size, void* data);			\

	// macro definitions to generate implementation of prototypes
	// empty by design, forces developers to write new and delete callback functions for memory types
#define _NP_GENERATE_MEMORY_IMPLEMENTATION(TYPE)

#define _NP_REF_REASON_SEPERATOR_CHAR "___"
#define _NP_REF_REASON_SEPERATOR_CHAR_LEN 3

#ifdef NP_MEMORY_CHECK_MEMORY_REFFING

#define _NP_REF_REASON(reason, reason_desc, new_reason)																							\
	char new_reason[strlen(reason)+255];	/*255 chars for additional desc data*/																\
	snprintf(new_reason,strlen(reason)+255,"%s%sline:%d_%s",reason,_NP_REF_REASON_SEPERATOR_CHAR,__LINE__, reason_desc == NULL ? "" : reason_desc);



#define ref_replace_reason(TYPE, np_obj, old_reason, new_reason) \
	np_memory_ref_replace_reason(np_obj, old_reason, new_reason);

#else
#define ref_replace_reason(TYPE, np_obj, old_reason, new_reason)

#define _NP_REF_REASON(reason, reason_desc, new_reason)																							\
	char new_reason[0];																										
#endif


#define np_new_obj(...) VFUNC(np_new_obj, __VA_ARGS__)
#define np_new_obj2(TYPE, np_obj) np_new_obj3(TYPE, np_obj, ref_obj_creation)
#define np_new_obj3(TYPE, np_obj, reason) np_new_obj4(TYPE, np_obj, reason,"")
#define np_new_obj4(TYPE, np_obj, reason, reason_desc)                																				\
{                                               																									\
	np_obj = np_memory_new(context, np_memory_types_##TYPE);																						\
	np_ref_obj4(TYPE, np_obj, reason, reason_desc);             																									\
}

	// convenience function like wrappers
#define np_ref_obj(...) VFUNC(np_ref_obj, __VA_ARGS__)
#define np_ref_obj2(TYPE, np_obj) np_ref_obj3(TYPE, np_obj, FUNC)
#define np_ref_obj3(TYPE, np_obj, reason) np_ref_obj4(TYPE, np_obj, reason,"")
#define np_ref_obj4(TYPE, np_obj, reason, reason_desc)              																									\
	np_memory_ref_obj(np_obj, reason, reason_desc) 

#define np_tryref_obj(...) VFUNC(np_tryref_obj, __VA_ARGS__)
#define np_tryref_obj3(TYPE, np_obj, ret) np_tryref_obj4(TYPE, np_obj, ret, container_##__LINE__)
#define np_tryref_obj4(TYPE, np_obj, ret, container) np_tryref_obj5(TYPE, np_obj, ret, container, FUNC)
#define np_tryref_obj5(TYPE, np_obj, ret, container, reason) np_tryref_obj6(TYPE, np_obj, ret,container, reason,"")
#define np_tryref_obj6(TYPE, np_obj, ret, container, reason, reason_desc)															\
TYPE* container = np_memory_tryref_obj(np_obj, reason, reason_desc);																			\
bool ret = container != NULL

#define np_waitref_obj(...) VFUNC(np_waitref_obj, __VA_ARGS__)
#define np_waitref_obj3(TYPE, np_obj, saveTo) np_waitref_obj4(TYPE, np_obj, saveTo, FUNC)
#define np_waitref_obj4(TYPE, np_obj, saveTo, reason) np_waitref_obj5(TYPE, np_obj, saveTo, reason,"")
#define np_waitref_obj5(TYPE, np_obj, saveTo, reason, reason_desc)    																				\
	TYPE* saveTo = (TYPE*) np_memory_waitref_obj(np_obj, reason, reason_desc);																		


#ifdef DEBUG
#define CHECK_MALLOC(obj)		              																			\
{                                             																			\
	assert(NULL != obj &&"Could not allocate memory. Program is now in undefined state and should be shut down.");		\
}
#else
#define CHECK_MALLOC(obj)
#endif
	

#define np_unref_obj(TYPE, np_obj, reason)                																							\
	if(np_memory_unref_obj(np_obj, reason) <= 0) np_obj = NULL


#define np_ref_switch(...) VFUNC(np_ref_switch, __VA_ARGS__)
#define np_ref_switch4(TYPE, old_obj, old_reason, new_obj) np_ref_switch5(TYPE, old_obj, old_reason, new_obj, old_reason)
#define np_ref_switch5(TYPE, old_obj, old_reason, new_obj, new_reason)																				\
{																																					\
	TYPE* tmp_obj = (TYPE*)old_obj;																													\
	np_ref_obj3(TYPE, new_obj, new_reason);																											\
	old_obj = (TYPE*)new_obj;																														\
	np_unref_obj(TYPE, tmp_obj, old_reason);																										\
}

#ifndef NP_MEMORY_CHECK_MEMORY_REFFING
#define ref_replace_reason_sll(TYPE, sll_list, old_reason, new_reason)
#else
#define ref_replace_reason_sll(TYPE, sll_list, old_reason, new_reason)																				\
{																																					\
	_LOCK_MODULE(np_memory_t) {																														\
		sll_iterator(TYPE) iter##__LINE__ = sll_first(sll_list);																					\
		while (NULL != iter##__LINE__ )																												\
		{																																			\
			ref_replace_reason(TYPE, (iter##__LINE__)->val, old_reason, new_reason);																\
			sll_next(iter##__LINE__ );																												\
		}																																			\
	}																																				\
}
#endif



#ifdef __cplusplus
}
#endif

#endif // _NP_MEMORY_H_
