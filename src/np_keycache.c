//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "sodium.h"
#include "tree/tree.h"

#include "np_keycache.h"

#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_log.h"
#include "np_dhkey.h"
#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_key.h"
#include "np_list.h"
#include "np_constants.h"
#include "np_util.h"

typedef struct st_keycache_s st_keycache_t;
SPLAY_GENERATE(st_keycache_s, np_key_s, link, _np_key_cmp);

np_module_struct(keycache) {
	np_state_t* context;	
	st_keycache_t* __key_cache;
};

bool _np_keycache_init(np_state_t* context)
{
	bool ret = false;
	if (!np_module_initiated(keycache)) {
		np_module_malloc(keycache);
		_module->__key_cache = (st_keycache_t*)malloc(sizeof(st_keycache_t));
		CHECK_MALLOC(_module->__key_cache);

		SPLAY_INIT(_module->__key_cache);
		ret = true;
	}
	return ret;
}

np_key_t* _np_keycache_find_or_create(np_state_t* context, np_dhkey_t search_dhkey)
{
	log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_find_or_create(np_dhkey_t search_dhkey){");
	np_key_t* key = NULL;
	np_key_t search_key = { .dhkey = search_dhkey };

	_LOCK_MODULE(np_keycache_t)
	{
		key = SPLAY_FIND(st_keycache_s, np_module(keycache)->__key_cache, &search_key);
		if (NULL == key)
		{
			key = _np_keycache_create(context, search_dhkey);
			ref_replace_reason(np_key_t, key, "_np_keycache_create", FUNC);
		}
		else {
			np_ref_obj(np_key_t, key);
		}

		key->last_update = np_time_now();
	}
	return (key);
}

np_key_t* _np_keycache_create(np_state_t* context, np_dhkey_t search_dhkey)
{
	log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_create(np_dhkey_t search_dhkey){");
	np_key_t* key = NULL;

	np_new_obj(np_key_t, key);
	key->dhkey = search_dhkey;
	key->last_update = np_time_now();

	ref_replace_reason(np_key_t, key, ref_obj_creation, FUNC);
	_np_keycache_add(key);
	
	return key;
}

np_key_t* _np_keycache_find(np_state_t* context, const np_dhkey_t search_dhkey)
{
	log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_find(const np_dhkey_t search_dhkey){");
	np_key_t* return_key = NULL;
	np_key_t search_key = { .dhkey = search_dhkey };

	_LOCK_MODULE(np_keycache_t)
	{
		return_key = SPLAY_FIND(st_keycache_s, np_module(keycache)->__key_cache, &search_key);
		if (NULL != return_key)
		{
			np_ref_obj(np_key_t, return_key);
			return_key->last_update = np_time_now();
		}
	}
	return return_key;
}

np_key_t* _np_keycache_find_by_details(
		np_state_t* context,
		char* details_container,
		bool search_myself,
		enum np_handshake_status search_handshake_status,
		bool require_handshake_status,
		bool require_dns,
		bool require_port,
		bool require_hash
	){
	log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_find_by_details(		char* details_container,		bool search_myself,		handshake_status_e is_handshake_send,		bool require_handshake_status,		bool require_dns,		bool require_port,		bool require_hash	){");
	np_key_t* ret = NULL;
	np_key_t *iter = NULL;

	np_waitref_obj(np_key_t, context->my_node_key, my_node_key, "np_waitref_key");
	np_waitref_obj(np_key_t, context->my_identity, my_identity, "np_waitref_identity");

	_LOCK_MODULE(np_keycache_t)
	{
		SPLAY_FOREACH(iter, st_keycache_s, np_module(keycache)->__key_cache)
		{
			TSP_GET(bool, iter->in_destroy, in_destroy);
			if(in_destroy == false){
				if(true == search_myself){
					if (
						true == _np_dhkey_equal(&iter->dhkey, &my_node_key->dhkey) ||
						true == _np_dhkey_equal(&iter->dhkey, &my_identity->dhkey) )
					{
						continue;
					}
				}

				if (
						(!require_handshake_status ||
								(NULL != iter->node &&
									iter->node->handshake_status == search_handshake_status									
								) 

						) &&
						(!require_hash ||
								(NULL != iter->dhkey_str &&
								strstr(details_container, iter->dhkey_str) != NULL
								)
						) &&
						(!require_dns ||
								(NULL != iter->node &&
								NULL != iter->node->dns_name &&
								strstr(details_container, iter->node->dns_name) != NULL
								)
						) &&
						(!require_port ||
								(NULL != iter->node &&
								NULL != iter->node->port &&
								strstr(details_container, iter->node->port) != NULL
								)
						)
				)
				{
					np_ref_obj(np_key_t, iter);
					ret = iter;
					ret->last_update = np_time_now();
					break;
				}
			}
		}
	}
	np_unref_obj(np_key_t, my_identity,"np_waitref_identity");
	np_unref_obj(np_key_t, my_node_key,"np_waitref_key");

	return (ret);
}

np_key_t* _np_keycache_find_deprecated(np_state_t* context)
{
	log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_find_deprecated(){");

	np_key_t* return_key = NULL;
	np_key_t *iter = NULL;
	_LOCK_MODULE(np_keycache_t)
	{
		SPLAY_FOREACH(iter, st_keycache_s, np_module(keycache)->__key_cache)
		{

			// our own key / identity never deprecates
			if (true == _np_dhkey_equal(&iter->dhkey, &context->my_node_key->dhkey) ||
				true == _np_dhkey_equal(&iter->dhkey, &context->my_identity->dhkey) )
			{
				continue;
			}

			double now = np_time_now();
			TSP_GET(bool, iter->in_destroy, in_destroy);

			if ((now - NP_KEYCACHE_DEPRECATION_INTERVAL) > iter->last_update && in_destroy == false)
			{
				np_ref_obj(np_key_t, iter);
				return_key = iter;
				break;
			}
		}
	}
	return (return_key);
}

sll_return(np_key_ptr) _np_keycache_find_aliase(np_key_t* forKey)
{
	np_ctx_memory(forKey);
	np_sll_t(np_key_ptr, ret) = sll_init(np_key_ptr, ret);
	np_key_t *iter = NULL;
	_LOCK_MODULE(np_keycache_t)
	{
		SPLAY_FOREACH(iter, st_keycache_s, np_module(keycache)->__key_cache)
		{
			TSP_GET(bool, iter->in_destroy, in_destroy);

			if (_np_key_cmp(iter->parent, forKey) == 0 && in_destroy == false)
			{
				np_ref_obj(np_key_t, iter);
				sll_append(np_key_ptr, ret, iter);
			}
		}
	}
	return (ret);
}

sll_return(np_key_ptr) _np_keycache_get_all(np_state_t* context)
{
	np_sll_t(np_key_ptr, ret) = sll_init(np_key_ptr, ret);
	np_key_t *iter = NULL;
	_LOCK_MODULE(np_keycache_t)
	{
		SPLAY_FOREACH(iter, st_keycache_s, np_module(keycache)->__key_cache)
		{
			np_ref_obj(np_key_t, iter);
			sll_append(np_key_ptr, ret, iter);
		}
	}
	return (ret);
}

np_key_t* _np_keycache_remove(np_state_t* context, np_dhkey_t search_dhkey)
{
	log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_remove(np_dhkey_t search_dhkey){");
	np_key_t* rem_key = NULL;
	np_key_t search_key = { .dhkey = search_dhkey };

	_LOCK_MODULE(np_keycache_t)
	{
		rem_key = SPLAY_FIND(st_keycache_s, np_module(keycache)->__key_cache, &search_key);
		if (NULL != rem_key) {
			SPLAY_REMOVE(st_keycache_s, np_module(keycache)->__key_cache, rem_key);
			np_unref_obj(np_key_t, rem_key, ref_keycache);
		}
	}
	return rem_key;
}

np_key_t* _np_keycache_add(np_key_t* subject_key)
{
	np_ctx_memory(subject_key);
	log_trace_msg(LOG_TRACE, "start: np_key_t* _np_keycache_add(np_key_t* key){");
	//TODO: ist das notwendig? warum einen leeren key hinzufügen?
	if (NULL == subject_key)
	{
		np_new_obj(np_key_t, subject_key);
	}
	np_ref_obj(np_key_t, subject_key,ref_keycache);

	_LOCK_MODULE(np_keycache_t)
	{
		SPLAY_INSERT(st_keycache_s, np_module(keycache)->__key_cache, subject_key);
		subject_key->last_update = np_time_now();
	}
	return subject_key;
}


/** _np_keycache_find_closest_key_to:
 ** finds the closest node in the array of #hosts# to #key# and put that in min_key.
 */
np_key_t* _np_keycache_find_closest_key_to (np_state_t* context,  np_sll_t(np_key_ptr, list_of_keys), const np_dhkey_t* const key)
{
	np_dhkey_t  dif, minDif = { 0 };
	np_key_t *min_key = NULL;

	sll_iterator(np_key_ptr) iter = sll_first(list_of_keys);
	bool first_run = true;
	while (NULL != iter)
	{
		TSP_GET(bool, iter->val->in_destroy, in_destroy);

		if(in_destroy == false){

			int cmp = _np_dhkey_cmp(key, &(iter->val->dhkey));
			// calculate distance to the left and right
			if(cmp > 0){
				_np_dhkey_distance (&dif, key, &(iter->val->dhkey));
			}
			else if(cmp < 0) {
				_np_dhkey_distance(&dif, &(iter->val->dhkey), key);
			}
			else {
				min_key = iter->val; // we have a perfect match
				break;
			}

			// Set reference point at first iteration, then compare current iterations distance with shortest known distance
			cmp = _np_dhkey_cmp(&dif, &minDif);
			if (true == first_run || cmp  < 0)
			{
				min_key = iter->val;
				_np_dhkey_assign (&minDif, &dif);
			}

			first_run = false;
		}
		sll_next(iter);		
	}

	if (sll_size(list_of_keys) == 0)
	{
		log_msg(LOG_KEY | LOG_WARN, "minimum size for closest key calculation not met !"); 
	}
	
	if(NULL != min_key){
		np_ref_obj(np_key_t, min_key);
	}
	return (min_key);
}

/** sort_hosts:
 ** Sorts #hosts# based on common prefix match and key distance from #np_key_t*
 */
void _np_keycache_sort_keys_cpm (np_sll_t(np_key_ptr, node_keys), const np_dhkey_t* key)
{
	np_dhkey_t dif1, dif2;

	uint16_t pmatch1 = 0;
	uint16_t pmatch2 = 0;

	if (sll_size(node_keys) < 2) return;

	np_key_t* tmp;
	sll_iterator(np_key_ptr) iter1 = sll_first(node_keys);
	sll_iterator(np_key_ptr) iter2;
	do
	{
		iter2 = sll_get_next(iter1);

		if (NULL == iter2) break;

		do
		{
			pmatch1 = _np_dhkey_index (key, &iter1->val->dhkey);
			pmatch2 = _np_dhkey_index (key, &iter2->val->dhkey);
			if (pmatch2 > pmatch1)
			{
				tmp = iter1->val;
				iter1->val = iter2->val;
				iter2->val = tmp;
			}
			else if (pmatch1 == pmatch2)
			{
				_np_dhkey_distance (&dif1, &iter1->val->dhkey, key);
				_np_dhkey_distance (&dif2, &iter2->val->dhkey, key);
				if (_np_dhkey_cmp (&dif2, &dif1) < 0)
				{
					tmp = iter1->val;
					iter1->val = iter2->val;
					iter2->val = tmp;
				}
			}
		} while (NULL != (sll_next(iter2)) );
	} while (NULL != (sll_next(iter1)) );
}

/** sort_hosts_key:
 ** Sorts #hosts# based on their key distance from #np_key_t*
 */
void _np_keycache_sort_keys_kd (np_sll_t(np_key_ptr, list_of_keys), const np_dhkey_t* key)
{
	np_dhkey_t dif1, dif2;

	// entry check for empty list
	if (sll_size(list_of_keys)<2) return;

	sll_iterator(np_key_ptr) curr = sll_first(list_of_keys);
	np_ctx_memory(curr->val);
	bool swap;
	do {
		curr = sll_first(list_of_keys);
		swap = false;
		
		while (NULL != curr) {
			// Maintain pointers.
			sll_iterator(np_key_ptr) next = sll_get_next(curr);

			// Cannot swap last element with its next.
			while (NULL != next)
			{
				// Swap if items in wrong order.
				_np_dhkey_distance(&dif1, &curr->val->dhkey, key);
				_np_dhkey_distance(&dif2, &next->val->dhkey, key);
				if (_np_dhkey_cmp(&dif2, &dif1) < 0)
				{
					swap = true;
					np_key_t* tmp = curr->val;
					curr->val = next->val;
					next->val = tmp;
					// Notify loop to do one more pass.
					break;
				}
				// continue with the loop
				sll_next(next);
			}
			sll_next(curr);

		}
	} while (swap);

#ifdef DEBUG
	char* str = NULL;
	char dhkey_str[65] = { 0 };
	np_id2str(key, dhkey_str);
	str = np_str_concatAndFree(str, "Base: %s %"PRIu32" ", dhkey_str, key->t[0]);
	str = np_str_concatAndFree(str, "DISTANCE SORTED KEYs (key/dist): ");

	curr = sll_first(list_of_keys);
	while (curr != NULL) {
		_np_dhkey_distance(&dif1, &curr->val->dhkey, key);
		np_id2str(&dif1, dhkey_str);
		str = np_str_concatAndFree(str, "%s / %s, ", _np_key_as_str(curr->val), dhkey_str);
		sll_next(curr);
	}
	log_debug_msg(LOG_DEBUG, "%s", str);
	free(str);
#endif
//    for (i = 0; i < size; i++)
//	{
//	    for (j = i + 1; j < size; j++)
//		{
//		    if (hosts[i] != NULL && hosts[j] != NULL)
//			{
//			    key_distance (&dif1, hosts[i], key);
//			    key_distance (&dif2, hosts[j], key);
//			    if (key_comp (&dif2, &dif1) < 0)
//				{
//				    tmp = hosts[i];
//				    hosts[i] = hosts[j];
//				    hosts[j] = tmp;
//				}
//			}
//		}
//	}
}



