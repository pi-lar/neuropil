/**
 *  copyright 2015 pi-lar GmbH
 *  header only implementation to manage heap objects
 *  taking the generating approach using the c preprocessor
 *  Stephan Schwichtenberg
 **/
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>

#include "np_memory.h"

#include "np_aaatoken.h"
#include "np_key.h"
#include "np_message.h"
#include "np_node.h"

np_obj_pool_t* np_obj_pool = NULL;

void np_mem_init()
{
	np_obj_pool = (np_obj_pool_t*) malloc(sizeof(np_obj_pool_t));
	np_obj_pool->current = NULL;
	np_obj_pool->first = NULL;
	np_obj_pool->free_obj = NULL;
	np_obj_pool->size = 0;
	np_obj_pool->available = 0;
	if (0 != pthread_mutex_init (&(np_obj_pool->lock), NULL))
	{
		exit(1);
	}
	// printf("np_obj_pool %p -> lock %p \n", np_obj_pool, &np_obj_pool->lock );
}

void np_mem_newobj(np_obj_enum obj_type, np_obj_t** obj)
{
    if (NULL != np_obj_pool->free_obj)
	{
    	np_obj_pool->current = np_obj_pool->free_obj;
    	np_obj_pool->free_obj = np_obj_pool->free_obj->next;
    	np_obj_pool->available--;
	}
	else
	{
    	np_obj_pool->current = (np_obj_t*) malloc (sizeof(np_obj_t) );
    	np_obj_pool->size++;
    }

    np_obj_pool->current->type = obj_type;
	np_obj_pool->current->ref_count = 0;
	np_obj_pool->current->next = NULL;
	if (NULL != np_obj_pool->first)
	{
		np_obj_pool->current->next = np_obj_pool->first;
	}
	np_obj_pool->first = np_obj_pool->current;
	(*obj) = np_obj_pool->current;
}

// printf("new  obj %p (type %d ptr %p ref_count %d):(next -> %p)n", np_obj->obj, np_obj->obj->type, np_obj->obj->ptr, np_obj->obj->ref_count, np_obj->obj->next );

void np_mem_freeobj(np_obj_enum obj_type, np_obj_t** obj)
{
	if (NULL != (*obj) &&
		NULL != (*obj)->ptr &&
		(*obj)->type == obj_type &&
		(*obj)->ref_count <= 0 )
	{
		np_obj_t* obj_tmp = NULL;
		np_obj_pool->current = np_obj_pool->first;
		while ((*obj) != np_obj_pool->current && NULL != np_obj_pool->current)
		{
			obj_tmp = np_obj_pool->current;
			np_obj_pool->current = np_obj_pool->current->next;
		}
		if (NULL != obj_tmp) obj_tmp->next = (*obj)->next;
		else np_obj_pool->first = np_obj_pool->first->next;
		(*obj)->type = np_none_t_e;
	    (*obj)->next = np_obj_pool->free_obj;
		np_obj_pool->free_obj = (*obj);
		np_obj_pool->available++;
		np_obj_pool->current = NULL;
	}
}

// printf("free obj %p (type %d ptr %p ref_count %d):(next -> %p)n", obj, obj->type, obj->ptr, obj->ref_count, obj->next );

// increase ref count
void np_mem_refobj(np_obj_enum obj_type, np_obj_t* obj)
{
    obj->ref_count++;
}
// decrease ref count
void np_mem_unrefobj(np_obj_enum obj_type, np_obj_t* obj)
{
	obj->ref_count--;
}

// print the complete object list and statistics
void np_mem_printpool()
{
	pthread_mutex_lock(&(np_obj_pool->lock));
	printf("\n--- used memory table---\n");
	for (np_obj_t* iter = np_obj_pool->first; iter != NULL; iter = iter->next )
	{
		printf("obj %p (type %d ptr %p ref_count %d):(next -> %p)\n", iter, iter->type, iter->ptr, iter->ref_count, iter->next );
	}
	printf("--- free memory table---\n");
	for (np_obj_t* iter = np_obj_pool->free_obj; iter != NULL; iter = iter->next )
	{
		printf("obj %p (type %d ptr %p ref_count %d):(next -> %p)\n", iter, iter->type, iter->ptr, iter->ref_count, iter->next );
	}
	printf("---memory summary---\n");
	printf("first %p, free %p,        current %p\n", np_obj_pool->first, np_obj_pool->free_obj, np_obj_pool->current);
	printf("size %d            available %d\n", np_obj_pool->size, np_obj_pool->available);
	printf("---memory end---\n");
	pthread_mutex_unlock(&(np_obj_pool->lock));
}
