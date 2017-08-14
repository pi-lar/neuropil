//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_MEMORY_H
#define _NP_MEMORY_H

#include <stdint.h>
#include <assert.h>

#include "np_threads.h"
#include "np_types.h"
#include "np_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEBUG
	#define MEMORY_CHECK 
#endif

// macro definitions to generate header prototype definitions
#define _NP_GENERATE_MEMORY_PROTOTYPES(TYPE) \
void _##TYPE##_new(void*); \
void _##TYPE##_del(void*); \

// macro definitions to generate implementation of prototypes
// empty by design, forces developers to write new and delete callback functions for np_obj_* types
#define _NP_GENERATE_MEMORY_IMPLEMENTATION(TYPE)

// enum to identify the correct type of objects
typedef enum np_obj_type
{
	np_none_t_e = 0,
	np_message_t_e,
	np_messagepart_t_e,
	np_node_t_e,
	np_key_t_e,
	np_aaatoken_t_e,
	np_msgproperty_t_e,
	np_http_t_e,
	np_network_t_e,
	test_struct_t_e = 99
} np_obj_enum;

typedef void (*np_dealloc_t) (void* data);
typedef void (*np_alloc_t) (void* data);

/** np_obj_t
 **
 ** void* like wrapper around structures to allow ref counting and null pointer checking
 ** each np_new_obj needs a corresponding np_unref_obj
 ** if other methods would like to claim ownership, they should call np_ref_obj, np_unref_obj
 ** will release the object again (and possible delete it)
 **
 **/
typedef struct np_obj_s np_obj_t;

struct np_obj_s
{
	np_bool freeing;
	char* id;

	np_mutex_t	lock;
	np_obj_enum type;
	int16_t ref_count;
	void* ptr;

	np_dealloc_t del_callback;
	np_alloc_t   new_callback;

	// additional field for memory management
	np_obj_t* next;

	np_bool persistent;
#ifdef MEMORY_CHECK
	np_sll_t(char_ptr, reasons);
#endif
};

/* Macro for overloading macros
 * Use like this if you want to overload foo(a,b) with foo(a,b,c)
 * #define foo(...) VFUNC(foo, __VA_ARGS__)
 * #define foo2(a, b) foo3(a, b, default_c)
 * #define foo3(a, b, c)  <insert_foo_fn>
 *
 * the number after foo in the function has to match the count of function arguments.
 * It is not possible to overload with the same number of arguments
 *
*/
#define __NARG__(...)  __NARG_I_(__VA_ARGS__,__RSEQ_N())
#define __NARG_I_(...) __ARG_N(__VA_ARGS__)
#define __ARG_N( \
	  _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
	 _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
	 _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
	 _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
	 _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
	 _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
	 _61,_62,_63,N,...) N
#define __RSEQ_N() \
	 63,62,61,60,                   \
	 59,58,57,56,55,54,53,52,51,50, \
	 49,48,47,46,45,44,43,42,41,40, \
	 39,38,37,36,35,34,33,32,31,30, \
	 29,28,27,26,25,24,23,22,21,20, \
	 19,18,17,16,15,14,13,12,11,10, \
	 9,8,7,6,5,4,3,2,1,0

// general definition for any function name
#define _VFUNC_(name, n) name##n
#define _VFUNC(name, n) _VFUNC_(name, n)
#define VFUNC(func, ...) _VFUNC(func, __NARG__(__VA_ARGS__)) (__VA_ARGS__)
// Macro overloading macros END

#ifndef MEMORY_CHECK
#define ref_replace_reason(TYPE, np_obj, old_reason, new_reason)
#else
#define ref_replace_reason(TYPE, np_obj, old_reason, new_reason)																			\
{																																			\
	np_obj_t* obj = (np_obj)->obj;																											\
	sll_iterator(char_ptr) iter_reasons = sll_first(obj->reasons);																			\
	np_bool foundReason = FALSE;																											\
	while (foundReason == FALSE && iter_reasons != NULL)																					\
	{																																		\
		assert(old_reason != NULL);																											\
		foundReason = (0 == strcmp(iter_reasons->val, old_reason))? TRUE : FALSE;															\
		if (foundReason == TRUE) {																											\
			free(iter_reasons->val);																										\
			sll_delete(char_ptr, obj->reasons, iter_reasons);																				\
			break;																															\
		}																																	\
		sll_next(iter_reasons);																												\
	}																																		\
	if (FALSE == foundReason)																												\
	{																																		\
		log_msg(LOG_ERROR, "old_reason \"%s\" for reason switch on obj %s (%d) was not found.", old_reason, obj->id, obj->type);			\
		abort();																															\
	}																																		\
	else {																																	\
		sll_prepend(char_ptr, obj->reasons, strndup(new_reason,strlen(new_reason)));														\
	}																																		\
}
#endif

// convenience function like wrappers
#define np_ref_obj(...) VFUNC(np_ref_obj, __VA_ARGS__)
#define np_ref_obj2(TYPE, np_obj) np_ref_obj3(TYPE, np_obj, __func__)
#define np_ref_obj3(TYPE, np_obj, reason)              																													\
{                                             																															\
  _LOCK_MODULE(np_memory_t) {                 																															\
	assert (((TYPE*)np_obj) != NULL);      		      																													\
	assert (((TYPE*)np_obj)->obj != NULL);             																													\
	if (((TYPE*)np_obj)->obj->type != TYPE##_e) log_msg(LOG_ERROR,"np_obj->obj->type = %d != %d",((TYPE*)np_obj)->obj->type, TYPE##_e);									\
	assert (((TYPE*)np_obj)->obj->type == TYPE##_e);   																													\
	log_debug_msg(LOG_MEMORY | LOG_DEBUG,"_Ref_ (%d) object of type \"%s\" on %s",((TYPE*)np_obj)->obj->ref_count,#TYPE, ((TYPE*)np_obj)->obj->id); 					\
	np_mem_refobj(((TYPE*)np_obj)->obj,reason);             																											\
  }																																										\
}

#define np_tryref_obj(...) VFUNC(np_tryref_obj, __VA_ARGS__)
#define np_tryref_obj3(TYPE, np_obj, ret) np_tryref_obj4(TYPE, np_obj, ret,__func__)
#define np_tryref_obj4(TYPE, np_obj, ret, reason)      																													\
	np_bool ret = FALSE;																																				\
	_LOCK_MODULE(np_memory_t) {                 																														\
		if(np_obj != NULL) {      		      																															\
			if((((TYPE*)np_obj)->obj != NULL)) {             																											\
				if (((TYPE*)np_obj)->obj->type != TYPE##_e) {  																											\
					log_msg(LOG_ERROR,"np_obj->obj->type = %d != %d",((TYPE*)np_obj)->obj->type, TYPE##_e);   															\
					assert (((TYPE*)np_obj)->obj->type == TYPE##_e);   																									\
				} else {																																				\
					log_debug_msg(LOG_MEMORY | LOG_DEBUG,"_Ref_ (%d) object of type \"%s\" on %s",((TYPE*)np_obj)->obj->ref_count, #TYPE, ((TYPE*)np_obj)->obj->id); 	\
					np_mem_refobj(((TYPE*)np_obj)->obj,reason);               																							\
					ret = TRUE;																																			\
				}																																						\
			}																																							\
		}																																								\
	}

#define np_waitref_obj(...) VFUNC(np_waitref_obj, __VA_ARGS__)
#define np_waitref_obj3(TYPE, np_obj, saveTo) np_waitref_obj4(TYPE, np_obj, saveTo, __func__)
#define np_waitref_obj4(TYPE, np_obj, saveTo, reason)    																							\
TYPE* saveTo = NULL;																																\
{																																				    \
	TYPE* org = (TYPE* )np_obj ;																												    \
	np_bool ret = FALSE;																															\
	while(ret == FALSE) {                          																									\
		_LOCK_MODULE(np_memory_t) {                 																								\
			if(np_obj != NULL) {      		      																									\
				if((org->obj != NULL)) {             																							    \
					if (org->obj->type != TYPE##_e) {  																							    \
						log_msg(LOG_ERROR,"np_obj->obj->type = %d != %d",org->obj->type, TYPE##_e);   											    \
						assert (org->obj->type == TYPE##_e);   																					    \
					} else {																														\
						log_debug_msg(LOG_MEMORY | LOG_DEBUG,"_Ref_ (%d) object of type \"%s\" on %s",org->obj->ref_count,#TYPE, org->obj->id); 	\
						np_mem_refobj(org->obj,reason);               																				\
						ret = TRUE;																													\
						saveTo = org;						   																					    \
					}																																\
				}																																	\
			}																																		\
		}																																			\
		if(ret == FALSE) ev_sleep(0.005);																											\
	}																																				\
}

#define CHECK_MALLOC(obj)		              			\
{                                             			\
	if(NULL == obj ) {									\
		log_msg(LOG_ERROR,"could not allocate memory");	\
	}													\
	assert(NULL != obj);                               	\
}														\

#define np_unref_obj(TYPE, np_obj, reason)                																					\
{                                                 																							\
	_LOCK_MODULE(np_memory_t) {                   																							\
	  if(NULL != np_obj) {                   	  																							\
		if(np_obj->obj == NULL) log_msg(LOG_ERROR,"ref obj is null");																		\
		assert (np_obj->obj != NULL);         																								\
		if(np_obj->obj->type != TYPE##_e) log_msg(LOG_ERROR,"ref obj is wrong type %d != %d",np_obj->obj->type, TYPE##_e);					\
		assert (np_obj->obj->type == TYPE##_e);     																						\
		if(!np_obj->obj->persistent && np_obj->obj->ptr == NULL) log_msg(LOG_ERROR,"ref obj pointer is null");								\
		assert (np_obj->obj->persistent  || np_obj->obj->ptr != NULL);          															\
		log_debug_msg(LOG_MEMORY | LOG_DEBUG,"_Unref_ (%d) object of type \"%s\" on %s",np_obj->obj->ref_count, #TYPE, np_obj->obj->id); 	\
		np_mem_unrefobj(np_obj->obj, reason);               																				\
		if (NULL != np_obj->obj && np_obj->obj->ref_count <= 0 && np_obj->obj->persistent == FALSE && np_obj->obj->ptr == np_obj) 			\
		{ 																																	\
		  if (np_obj->obj->type != np_none_t_e)     																						\
		  { 																																\
			if (np_obj->obj->freeing != TRUE) 																								\
			{ 																																\
				np_obj->obj->freeing = TRUE;																								\
				log_debug_msg(LOG_MEMORY | LOG_DEBUG,"_Deleting object of type \"%s\" on %s",#TYPE, np_obj->obj->id); 						\
				if(np_obj->obj->del_callback != NULL)   																					\
					np_obj->obj->del_callback(np_obj);    																					\
				np_mem_freeobj(TYPE##_e, &np_obj->obj); 																					\
				np_obj->obj->freeing = FALSE;                																				\
				np_obj->obj->ptr = NULL;                																					\
				np_obj->obj = NULL;                     																					\
				free(np_obj);                           																					\
				np_obj = NULL;                          																					\
			}                          																										\
		 }	 																																\
	   }                                           																							\
	}                                             																							\
  }                                               																							\
}

#define np_ref_switch(...) VFUNC(np_ref_switch, __VA_ARGS__)
#define np_ref_switch4(TYPE, old_obj, old_reason, new_obj) np_ref_switch5(TYPE, old_obj, old_reason, new_obj, old_reason)
#define np_ref_switch5(TYPE, old_obj, old_reason, new_obj, new_reason)	\
{																		\
	TYPE* tmp_obj = (TYPE*)old_obj;										\
	np_ref_obj3(TYPE, new_obj, new_reason);								\
	old_obj = (TYPE*)new_obj;											\
	np_unref_obj(TYPE, tmp_obj, old_reason);							\
}

#define np_new_obj(...) VFUNC(np_new_obj, __VA_ARGS__)
#define np_new_obj2(TYPE, np_obj) np_new_obj3(TYPE, np_obj, "ref_obj_creation")
#define np_new_obj3(TYPE, np_obj, reason)                													\
{                                               															\
  _LOCK_MODULE(np_memory_t) {                   															\
	np_obj = (TYPE*) calloc(1,sizeof(TYPE));											      					\
	CHECK_MALLOC(np_obj);																					\
	np_mem_newobj(TYPE##_e, &np_obj->obj);      															\
	log_debug_msg(LOG_MEMORY | LOG_DEBUG,"Creating_ object of type \"%s\" on %s",#TYPE, np_obj->obj->id); 	\
	np_obj->obj->new_callback = _##TYPE##_new;  															\
	np_obj->obj->del_callback = _##TYPE##_del;  															\
	np_obj->obj->new_callback(np_obj);          															\
	np_obj->obj->ptr = np_obj;																				\
	np_obj->obj->persistent = FALSE;			            												\
	np_mem_refobj(np_obj->obj,reason);                 														\
  }                                             															\
}


#define np_ref_list(...) VFUNC(np_ref_list, __VA_ARGS__)
#define np_ref_list2(TYPE, sll_list) np_ref_list3(TYPE, sll_list, __func__)
#define np_ref_list3(TYPE, sll_list, reason)               		\
{																\
	sll_iterator(TYPE) iter = sll_first(sll_list);				\
	while (NULL != iter)										\
	{															\
		np_ref_obj3(TYPE, (iter->val), reason);					\
		sll_next(iter);											\
	}															\
}

#define np_unref_list(TYPE, sll_list, reason)               	\
{																\
	sll_iterator(TYPE) iter = sll_first(sll_list);				\
	while (NULL != iter)										\
	{															\
		np_unref_obj(TYPE,(iter->val), reason);					\
		sll_next(iter);											\
	}															\
}
/**
 ** following this line: np_memory cache and object prototype definitions
 **
 **/
NP_API_INTERN
void np_mem_init();

NP_API_EXPORT
void np_mem_newobj(np_obj_enum obj_type, np_obj_t** obj);

// np_free - free resources (but not object wrapper) if ref_count is <= 0
// in case of doubt, call np_free. it will not harm ;-)
NP_API_EXPORT
void np_mem_freeobj(np_obj_enum obj_type, np_obj_t** obj);

// increase ref count
NP_API_EXPORT
void np_mem_refobj(np_obj_t* obj,char* reason);

// decrease ref count
NP_API_EXPORT
void np_mem_unrefobj(np_obj_t* obj,char* reason);

// print the complete object list and statistics
NP_API_INTERN
char* np_mem_printpool(np_bool asOneLine);

#ifdef __cplusplus
}
#endif

#endif // _NP_MEMORY_H
