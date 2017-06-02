//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_MEMORY_H
#define _NP_MEMORY_H

#include "stdint.h"

#include "np_threads.h"
#include "np_types.h"
#include "assert.h"

#ifdef __cplusplus
extern "C" {
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
 ** each np_new_obj needs a corresponding np_free_obj
 ** if other methods would like to claim ownership, they should call np_ref_obj, np_unref_obj
 ** will release the object again (and possible delete it)
 **
 **/
typedef struct np_obj_s np_obj_t;

struct np_obj_s
{
	np_obj_enum type;
	int16_t ref_count;
	void* ptr;

	np_dealloc_t del_callback;
	np_alloc_t   new_callback;

	// additional field for memory management
	np_obj_t* next;

	np_bool persistent;
};


// convenience function like wrappers
#define np_ref_obj(TYPE, np_obj)              \
{                                             \
  _LOCK_MODULE(np_memory_t) {                 \
    assert (np_obj != NULL);      		      \
    assert (np_obj->obj != NULL);             \
    if (np_obj->obj->type != TYPE##_e) log_msg(LOG_ERROR,"np_obj->obj->type = %d != %d",np_obj->obj->type, TYPE##_e);   \
    assert (np_obj->obj->type == TYPE##_e);   \
    np_mem_refobj(np_obj->obj);               \
  }                                           \
}

#define CHECK_MALLOC(obj)		              			\
{                                             			\
	if(NULL == obj ) {									\
		log_msg(LOG_ERROR,"could not allocate memory");	\
	}													\
	assert(NULL != obj);                               	\
}														\

#define np_unref_obj(TYPE, np_obj)                \
{                                                 \
  if(NULL != np_obj) {                   	      \
    _LOCK_MODULE(np_memory_t) {                   \
      assert (np_obj->obj != NULL);               \
      assert (np_obj->obj->type == TYPE##_e);     \
      assert (np_obj->obj->ptr != NULL);          \
      np_mem_unrefobj(np_obj->obj);               \
      if (NULL != np_obj->obj && np_obj->obj->ref_count <= 0 && np_obj->obj->persistent == FALSE && np_obj->obj->ptr == np_obj) { \
	    if (np_obj->obj->type != np_none_t_e)     \
	    { 										  \
		  if(np_obj->obj->del_callback != NULL)   \
			np_obj->obj->del_callback(np_obj);    \
		  np_mem_freeobj(TYPE##_e, &np_obj->obj); \
		  np_obj->obj->ptr = NULL;                \
		  np_obj->obj = NULL;                     \
		  free(np_obj);                           \
		  np_obj = NULL;                          \
		}                                         \
	  }                                           \
    }                                             \
  }                                               \
}

#define np_ref_switch(TYPE, old_obj, new_obj) \
{                                             \
	TYPE* tmp_obj = old_obj;                  \
	old_obj = new_obj;                        \
	np_ref_obj(TYPE, new_obj);                \
	np_unref_obj(TYPE, tmp_obj);              \
}

#define np_new_obj(TYPE, np_obj)                \
{                                               \
  _LOCK_MODULE(np_memory_t) {                   \
    np_obj = (TYPE*) malloc(sizeof(TYPE));      \
    CHECK_MALLOC(np_obj);						\
    np_mem_newobj(TYPE##_e, &np_obj->obj);      \
    np_obj->obj->new_callback = _##TYPE##_new;  \
    np_obj->obj->del_callback = _##TYPE##_del;  \
    np_obj->obj->new_callback(np_obj);          \
    np_obj->obj->ptr = np_obj;                  \
    np_obj->obj->persistent = FALSE;            \
    np_mem_refobj(np_obj->obj);                 \
  }                                             \
}


#define np_free_obj(TYPE, np_obj)               \
{                                               \
  _LOCK_MODULE(np_memory_t) {                   \
    np_mem_unrefobj(np_obj->obj);               \
    if (NULL != np_obj->obj && np_obj->obj->ref_count <= 0 && np_obj->obj->persistent == FALSE && np_obj->obj->ptr == np_obj) { \
      if (np_obj->obj->type != np_none_t_e)     \
      {                                         \
        np_obj->obj->del_callback(np_obj);      \
	    np_mem_freeobj(TYPE##_e, &np_obj->obj); \
	    np_obj->obj->ptr = NULL;                \
	    np_obj->obj = NULL;                     \
	    free(np_obj);                           \
	    np_obj = NULL;                          \
      }                                         \
    }                                           \
  }                                             \
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
void np_mem_refobj(np_obj_t* obj);

// decrease ref count
NP_API_EXPORT
void np_mem_unrefobj(np_obj_t* obj);

// print the complete object list and statistics
NP_API_INTERN
void np_mem_printpool();

#ifdef __cplusplus
}
#endif

#endif // _NP_MEMORY_H
