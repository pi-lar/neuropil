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
#include "np_key.h"
#include "np_message.h"
#include "np_messagepart.h"
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

void np_mem_init()
{
    log_msg(LOG_TRACE, "start: void np_mem_init(){");
	__np_obj_pool_ptr = (np_obj_pool_t*) malloc(sizeof(np_obj_pool_t));
	CHECK_MALLOC(__np_obj_pool_ptr);

	__np_obj_pool_ptr->current = NULL;
	__np_obj_pool_ptr->first = NULL;
	__np_obj_pool_ptr->free_obj = NULL;
	__np_obj_pool_ptr->size = 0;
	__np_obj_pool_ptr->available = 0;

	// init cache
	np_messagepart_t* tmp = NULL;
	int i = 0;
	for(; i < 500; i++){
		np_new_obj(np_messagepart_t, tmp);
		np_free_obj(np_messagepart_t, tmp);
	}
    log_msg(LOG_DEBUG, "Initiated cache with %d free spaces",i);

}

void np_mem_newobj(np_obj_enum obj_type, np_obj_t** obj)
{
    log_msg(LOG_TRACE, "start: void np_mem_newobj(np_obj_enum obj_type, np_obj_t** obj){");
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
	log_msg(LOG_DEBUG, "Created new object on %p; t: %d", (*obj), (*obj)->type);
}

// printf("new  obj %p (type %d ptr %p ref_count %d):(next -> %p)n", np_obj->obj, np_obj->obj->type, np_obj->obj->ptr, np_obj->obj->ref_count, np_obj->obj->next );

void np_mem_freeobj(np_obj_enum obj_type, np_obj_t** obj)
{
    log_msg(LOG_TRACE, "start: void np_mem_freeobj(np_obj_enum obj_type, np_obj_t** obj){");

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
		_np_threads_mutex_destroy(&(*obj)->lock);
		__np_obj_pool_ptr->free_obj = (*obj);
		__np_obj_pool_ptr->available++;
		__np_obj_pool_ptr->current = NULL;
	}
}

// printf("free obj %p (type %d ptr %p ref_count %d):(next -> %p)n", obj, obj->type, obj->ptr, obj->ref_count, obj->next );

// increase ref count
void np_mem_refobj(np_obj_t* obj)
{
    log_msg(LOG_TRACE, "start: void np_mem_refobj(np_obj_t* obj){");
	obj->ref_count++;
	//log_msg(LOG_DEBUG,"Referencing object (%p; t: %d)", obj,obj->type);
}
// decrease ref count
void np_mem_unrefobj(np_obj_t* obj)
{
    log_msg(LOG_TRACE, "start: void np_mem_unrefobj(np_obj_t* obj){");
	obj->ref_count--;
	//log_msg(LOG_DEBUG,"Unreferencing object (%p; t: %d)", obj, obj->type);
	if(obj->ref_count < 0){
		log_msg(LOG_ERROR,"Unreferencing object (%p; t: %d) too often! (%d)", obj, obj->type, obj->ref_count);
	}
}

// print the complete object list and statistics
void np_mem_printpool()
{
    log_msg(LOG_TRACE, "start: void np_mem_printpool(){");

    _LOCK_MODULE(np_memory_t) {

		uint64_t summary[100] = {
				0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0,
				0,0,0,0,0,0,0,0,0,0
		};

		printf("\n--- used memory table---\n");
		for (np_obj_t* iter = __np_obj_pool_ptr->first; iter != NULL; iter = iter->next )
		{
			summary[iter->type]++;
			//printf("obj %p (type %d ptr %p ref_count %d):(next -> %p)\n", iter, iter->type, iter->ptr, iter->ref_count, iter->next );
		}
		printf("--- free memory table---\n");
		for (np_obj_t* iter = __np_obj_pool_ptr->free_obj; iter != NULL; iter = iter->next )
		{
			//printf("obj %p (type %d ptr %p ref_count %d):(next -> %p)\n", iter, iter->type, iter->ptr, iter->ref_count, iter->next );
		}
		printf("--- memory summary---\n");
		printf("first %p, free %p, current %p\n", __np_obj_pool_ptr->first, __np_obj_pool_ptr->free_obj, __np_obj_pool_ptr->current);
		printf("size %d            available %d\n", __np_obj_pool_ptr->size, __np_obj_pool_ptr->available);

		printf("np_none_t_e        count %d \n", 	summary[np_none_t_e]);
		printf("np_message_t_e     count %d \n", 	summary[np_message_t_e]);
		printf("np_messagepart_t_e count %d \n", 	summary[np_messagepart_t_e]);
		printf("np_node_t_e        count %d \n", 	summary[np_node_t_e]);
		printf("np_key_t_e         count %d \n", 	summary[np_key_t_e]);
		printf("np_aaatoken_t_e    count %d \n", 	summary[np_aaatoken_t_e]);
		printf("np_msgproperty_t_e count %d \n", 	summary[np_msgproperty_t_e]);
		printf("np_http_t_e        count %d \n", 	summary[np_http_t_e]);
		printf("np_network_t_e     count %d \n", 	summary[np_network_t_e]);
		printf("test_struct_t_e    count %d \n", 	summary[test_struct_t_e]);

		printf("--- memory end---\n");
    }
}
