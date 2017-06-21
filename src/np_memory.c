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
#include <pthread.h>

#include "np_memory.h"

#include "np_aaatoken.h"
#include "np_dhkey.h"
#include "np_message.h"
#include "np_node.h"
#include "np_log.h"
#include "np_threads.h"


/** np_obj_pool_t
 **
 ** global object pool to store and handle all heap objects
 **/
typedef struct np_obj_pool_s
{
	uint32_t size;
	np_obj_t* current;
	np_obj_t* first;

	uint32_t available;
	np_obj_t* free_obj;
} np_obj_pool_t;

static np_obj_pool_t* __np_obj_pool_ptr;
static pthread_mutex_t __lock_mutex = PTHREAD_MUTEX_INITIALIZER;

void np_mem_init()
{
	__np_obj_pool_ptr = (np_obj_pool_t*) malloc(sizeof(np_obj_pool_t));
	CHECK_MALLOC(__np_obj_pool_ptr);

	__np_obj_pool_ptr->current = NULL;
	__np_obj_pool_ptr->first = NULL;
	__np_obj_pool_ptr->free_obj = NULL;
	__np_obj_pool_ptr->size = 0;
	__np_obj_pool_ptr->available = 0;
}

void np_mem_newobj(np_obj_enum obj_type, np_obj_t** obj)
{
    if (NULL != __np_obj_pool_ptr->free_obj)
	{
    	__np_obj_pool_ptr->current  = __np_obj_pool_ptr->free_obj;
    	__np_obj_pool_ptr->free_obj = __np_obj_pool_ptr->free_obj->next;
    	__np_obj_pool_ptr->available--;
	}
	else
	{
		__np_obj_pool_ptr->current = (np_obj_t*) malloc (sizeof(np_obj_t) );
		CHECK_MALLOC(__np_obj_pool_ptr->current);

		__np_obj_pool_ptr->size++;
    }

	_np_threads_mutex_init(&__np_obj_pool_ptr->current->lock);
    __np_obj_pool_ptr->current->type = obj_type;
    __np_obj_pool_ptr->current->ref_count = 0;
    __np_obj_pool_ptr->current->next = NULL;
	if (NULL != __np_obj_pool_ptr->first)
	{
		__np_obj_pool_ptr->current->next = __np_obj_pool_ptr->first;
	}
	__np_obj_pool_ptr->first = __np_obj_pool_ptr->current;
	(*obj) = __np_obj_pool_ptr->current;
}

// printf("new  obj %p (type %d ptr %p ref_count %d):(next -> %p)n", np_obj->obj, np_obj->obj->type, np_obj->obj->ptr, np_obj->obj->ref_count, np_obj->obj->next );

void np_mem_freeobj(np_obj_enum obj_type, np_obj_t** obj)
{
	_np_threads_mutex_lock(&(*obj)->lock);

	if (NULL != (*obj) &&
		NULL != (*obj)->ptr &&
		(*obj)->type == obj_type &&
		(*obj)->ref_count <= 0 )
	{
		np_obj_t* obj_tmp = NULL;
		__np_obj_pool_ptr->current = __np_obj_pool_ptr->first;
		while ((*obj) != __np_obj_pool_ptr->current && NULL != __np_obj_pool_ptr->current)
		{
			obj_tmp = __np_obj_pool_ptr->current;
			__np_obj_pool_ptr->current = __np_obj_pool_ptr->current->next;
		}
		if (NULL != obj_tmp) obj_tmp->next = (*obj)->next;
		else __np_obj_pool_ptr->first = __np_obj_pool_ptr->first->next;
		(*obj)->type = np_none_t_e;
	    (*obj)->next = __np_obj_pool_ptr->free_obj;
		_np_threads_mutex_unlock(&(*obj)->lock);
		_np_threads_mutex_destroy(&(*obj)->lock);
		__np_obj_pool_ptr->free_obj = (*obj);
		__np_obj_pool_ptr->available++;
		__np_obj_pool_ptr->current = NULL;

	}else{
		_np_threads_mutex_unlock(&(*obj)->lock);
	}
}

// printf("free obj %p (type %d ptr %p ref_count %d):(next -> %p)n", obj, obj->type, obj->ptr, obj->ref_count, obj->next );

// increase ref count
void np_mem_refobj(np_obj_t* obj)
{
	_np_threads_mutex_lock(&obj->lock);
    obj->ref_count++;
	_np_threads_mutex_unlock(&obj->lock);
}
// decrease ref count
void np_mem_unrefobj(np_obj_t* obj)
{
	_np_threads_mutex_lock(&obj->lock);
    obj->ref_count--;
	_np_threads_mutex_unlock(&obj->lock);
}

// print the complete object list and statistics
void np_mem_printpool()
{
	pthread_mutex_lock(&__lock_mutex);
	printf("\n--- used memory table---\n");
	for (np_obj_t* iter = __np_obj_pool_ptr->first; iter != NULL; iter = iter->next )
	{
		printf("obj %p (type %d ptr %p ref_count %d):(next -> %p)\n", iter, iter->type, iter->ptr, iter->ref_count, iter->next );
	}
	printf("--- free memory table---\n");
	for (np_obj_t* iter = __np_obj_pool_ptr->free_obj; iter != NULL; iter = iter->next )
	{
		printf("obj %p (type %d ptr %p ref_count %d):(next -> %p)\n", iter, iter->type, iter->ptr, iter->ref_count, iter->next );
	}
	printf("--- memory summary---\n");
	printf("first %p, free %p, current %p\n", __np_obj_pool_ptr->first, __np_obj_pool_ptr->free_obj, __np_obj_pool_ptr->current);
	printf("size %d            available %d\n", __np_obj_pool_ptr->size, __np_obj_pool_ptr->available);
	printf("--- memory end---\n");
	pthread_mutex_unlock(&__lock_mutex);
}
