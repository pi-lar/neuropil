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
#include <inttypes.h>

#include "np_memory.h"

#include "np_aaatoken.h"
#include "np_dhkey.h"
#include "np_key.h"
#include "np_message.h"
#include "np_messagepart.h"
#include "np_node.h"
#include "np_log.h"
#include "np_threads.h"
#include "np_util.h"



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
	/*
	np_messagepart_t* tmp = NULL;
	int i = 0;
	for(; i < 500; i++){
		np_new_obj(np_messagepart_t, tmp);
		np_free_obj(np_messagepart_t, tmp);
	}
	log_msg(LOG_DEBUG, "Initiated cache with %d free spaces",i);
	*/

}

void np_mem_newobj(np_obj_enum obj_type, np_obj_t** obj)
{
	log_msg(LOG_TRACE, "start: void np_mem_newobj(np_obj_enum obj_type, np_obj_t** obj){");
	if (NULL != __np_obj_pool_ptr->free_obj)
	{
		__np_obj_pool_ptr->current  = __np_obj_pool_ptr->free_obj;
		__np_obj_pool_ptr->free_obj = __np_obj_pool_ptr->free_obj->next;
		__np_obj_pool_ptr->available--;

#ifdef DEBUG
		free(__np_obj_pool_ptr->current->id);
		__np_obj_pool_ptr->current->id = np_uuid_create("MEMORY REF OBJ",0);
		sll_clear(char_ptr, __np_obj_pool_ptr->current->reasons);
#endif
	}
	else
	{
		__np_obj_pool_ptr->current = (np_obj_t*) malloc (sizeof(np_obj_t) );
		CHECK_MALLOC(__np_obj_pool_ptr->current);
		__np_obj_pool_ptr->current->id = np_uuid_create("MEMORY REF OBJ",0);
#ifdef DEBUG
		sll_init(char_ptr, (__np_obj_pool_ptr->current->reasons));
#endif
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
#ifdef DEBUG
		sll_clear(char_ptr, (*obj)->reasons);
#endif
		_np_threads_mutex_destroy(&(*obj)->lock);
		__np_obj_pool_ptr->free_obj = (*obj);
		__np_obj_pool_ptr->available++;
		__np_obj_pool_ptr->current = NULL;
	}
}

// printf("free obj %p (type %d ptr %p ref_count %d):(next -> %p)n", obj, obj->type, obj->ptr, obj->ref_count, obj->next );

// increase ref count
void np_mem_refobj(np_obj_t* obj,char* reason)
{
	log_msg(LOG_TRACE, "start: void np_mem_refobj(np_obj_t* obj){");
	obj->ref_count++;
	//log_msg(LOG_DEBUG,"Referencing object (%p; t: %d)", obj,obj->type);
#ifdef DEBUG
	sll_append(char_ptr, obj->reasons, reason);
#endif
	}
// decrease ref count
void np_mem_unrefobj(np_obj_t* obj, char* reason)
{
	log_msg(LOG_TRACE, "start: void np_mem_unrefobj(np_obj_t* obj){");
	obj->ref_count--;
	//log_msg(LOG_DEBUG,"Unreferencing object (%p; t: %d)", obj, obj->type);
	if(obj->ref_count < 0){
		log_msg(LOG_ERROR,"Unreferencing object (%p; t: %d) too often! (%d)", obj, obj->type, obj->ref_count);
	}
#ifdef DEBUG
	sll_iterator(char_ptr) iter_reasons = sll_first(obj->reasons);
	np_bool foundReason = FALSE;
	while (foundReason == FALSE && iter_reasons != NULL)
	{
		foundReason = 0 == strcmp(iter_reasons->val,reason);
		if (foundReason == TRUE) {
			sll_delete(char_ptr, obj->reasons, iter_reasons);
			break;
		}
		sll_next(iter_reasons);
	}
	if (FALSE == foundReason) {
		log_msg(LOG_ERROR, "reason \"%s\" for dereferencing obj %s (%d) was not found.",reason,obj->id,obj->type);
#ifdef STRICT
		exit(EXIT_FAILURE);
#endif
	}	
#endif

}

// print the complete object list and statistics
char* np_mem_printpool(np_bool asOneLine)
{
	log_msg(LOG_TRACE, "start: void np_mem_printpool(){");
	char* ret = NULL;
	char* new_line = "\n";
	if(asOneLine == TRUE){
		new_line = "    ";
	}
	char* subject_list = NULL;

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

	_LOCK_MODULE(np_memory_t) {
		//asprintf(ret, "--- used memory table---");
		for (np_obj_t* iter = __np_obj_pool_ptr->first; iter != NULL; iter = iter->next )
		{
			summary[iter->type]++;
			// printf("obj %p (type %d ptr %p ref_count %d):(next -> %p)\n", iter, iter->type, iter->ptr, iter->ref_count, iter->next );
			// if (iter->type == np_message_t_e) {
			// subject_list = _np_concatAndFree(subject_list, "%s%s", ((np_message_t*)iter->ptr)->uuid, new_line);
			// }
#ifdef DEBUG
			if (FALSE == asOneLine) 
			{
				ret = _np_concatAndFree(ret, "--- remaining reasons for %s (%d) start ---%s",iter->id, iter->type, new_line);

				sll_iterator(char_ptr) iter_reasons = sll_first(iter->reasons);
				while(iter_reasons != NULL)
				{
					ret = _np_concatAndFree(ret, "\"%s\"%s", iter_reasons->val, new_line);
					sll_next(iter_reasons);
				}
				ret = _np_concatAndFree(ret, "--- remaining reasons for %s (%d) end  ---%s", iter->id, iter->type, new_line);
			}
#endif

		}
		//asprintf(ret, "--- free memory table---\n");
		for (np_obj_t* iter = __np_obj_pool_ptr->free_obj; iter != NULL; iter = iter->next )
		{
			//printf("obj %p (type %d ptr %p ref_count %d):(next -> %p)\n", iter, iter->type, iter->ptr, iter->ref_count, iter->next );
		}
		ret = _np_concatAndFree(ret, "--- memory summary---%s", new_line);
		ret = _np_concatAndFree(ret, "first %12p, free %12p, current %12p%s", __np_obj_pool_ptr->first, __np_obj_pool_ptr->free_obj, __np_obj_pool_ptr->current,new_line);
		ret = _np_concatAndFree(ret, "size %4d, in use %4d,  available %4d%s", __np_obj_pool_ptr->size, __np_obj_pool_ptr->size - __np_obj_pool_ptr->available,__np_obj_pool_ptr->available,new_line);
		//0x7f8455c03e80
	}
	ret = _np_concatAndFree(ret, "np_none_t_e        count %4"PRIu64" %s", 	summary[np_none_t_e],		new_line);
	ret = _np_concatAndFree(ret, "np_message_t_e     count %4"PRIu64" %s", 	summary[np_message_t_e],	new_line);
	ret = _np_concatAndFree(ret, "np_messagepart_t_e count %4"PRIu64" %s", 	summary[np_messagepart_t_e],new_line);
	ret = _np_concatAndFree(ret, "np_node_t_e        count %4"PRIu64" %s", 	summary[np_node_t_e],		new_line);
	ret = _np_concatAndFree(ret, "np_key_t_e         count %4"PRIu64" %s", 	summary[np_key_t_e],		new_line);
	ret = _np_concatAndFree(ret, "np_aaatoken_t_e    count %4"PRIu64" %s", 	summary[np_aaatoken_t_e],	new_line);
	ret = _np_concatAndFree(ret, "np_msgproperty_t_e count %4"PRIu64" %s", 	summary[np_msgproperty_t_e],new_line);
	ret = _np_concatAndFree(ret, "np_http_t_e        count %4"PRIu64" %s", 	summary[np_http_t_e],		new_line);
	ret = _np_concatAndFree(ret, "np_network_t_e     count %4"PRIu64" %s", 	summary[np_network_t_e],	new_line);
	ret = _np_concatAndFree(ret, "test_struct_t_e    count %4"PRIu64" %s", 	summary[test_struct_t_e],	new_line);

	ret = _np_concatAndFree(ret, "--- memory end ---%s",new_line);

	// ret = _np_concatAndFree(ret, "--- subject list start ---%s",new_line);
	// ret = _np_concatAndFree(ret, "%s",subject_list);
	// ret = _np_concatAndFree(ret, "--- subject list end   ---%s",new_line);

	return (ret);
}
