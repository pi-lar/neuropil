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
#include <inttypes.h>

#include "np_legacy.h"

#include "event/ev.h"
#include "sodium.h"

#include "np_log.h"
#include "np_tree.h"
#include "np_types.h"
#include "np_treeval.h"
#include "np_threads.h"
#include "np_keycache.h"
#include "np_aaatoken.h"
#include "np_token_factory.h"
#include "np_network.h"
#include "np_node.h"
#include "np_msgproperty.h"
#include "np_key.h"
#include "np_route.h"
#include "np_jobqueue.h"
#include "np_constants.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_key_t);

NP_SLL_GENERATE_IMPLEMENTATION(np_key_ptr);
NP_PLL_GENERATE_IMPLEMENTATION(np_key_ptr);

int8_t _np_key_cmp(np_key_t* const k1, np_key_t* const k2)
{
	if (k1 == NULL) return -1;
	if (k2 == NULL) return  1;
 
	return _np_dhkey_cmp(&k1->dhkey,&k2->dhkey);
}

int8_t _np_key_cmp_inv(np_key_t* const k1, np_key_t* const k2)
{	
	return -1 * _np_key_cmp(k1, k2);
}

char* _np_key_as_str(np_key_t* key)
{
	assert(key != NULL);
	np_ctx_memory(key);

	if (NULL == key->dhkey_str){
		key->dhkey_str = (char*) malloc(65);
		CHECK_MALLOC(key->dhkey_str);
	}
	np_id2str(&key->dhkey, key->dhkey_str);
	log_debug_msg(LOG_KEY | LOG_DEBUG, "dhkey_str = %lu (%s)", strlen(key->dhkey_str), key->dhkey_str);

	return (key->dhkey_str);
}

void np_key_ref_list(np_sll_t(np_key_ptr, sll_list), const char* reason, const char* reason_desc)
{
	np_state_t* context = NULL; 
	sll_iterator(np_key_ptr) iter = sll_first(sll_list);	
	while (NULL !=
		iter)
	{
		if (context == NULL && iter->val != NULL) {
			context = np_ctx_by_memory(iter->val);
		}
		np_ref_obj(np_key_t, (iter->val), reason, reason_desc);
		sll_next(iter);
	}
}

void np_key_unref_list(np_sll_t(np_key_ptr, sll_list) , const char* reason)
{
	np_state_t* context = NULL;
	sll_iterator(np_key_ptr) iter = sll_first(sll_list);
	while (NULL != iter)
	{
		
		if (context == NULL && iter->val != NULL) {
			context = np_ctx_by_memory(iter->val);
		}
		np_unref_obj(np_key_t, (iter->val), reason);
		sll_next(iter);
	}
}

/**
 * Destroys a key with all resources
 */
void _np_key_destroy(np_key_t* to_destroy) {
	np_ctx_memory(to_destroy);

	TSP_SCOPE(to_destroy->in_destroy)
	{
		to_destroy->in_destroy = true;

		char* keyident = _np_key_as_str(to_destroy);
		log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key and associated data structures: %s", keyident);

		log_debug_msg(LOG_KEY | LOG_DEBUG, "refcount of key %s at destroy: %"PRIu32, keyident, np_memory_get_refcount(to_destroy));

		np_key_t* deleted;
		np_key_t* added;

		_np_route_leafset_update(to_destroy, false, &deleted, &added);
		_np_route_update(to_destroy, false, &deleted, &added);
		_np_network_disable(to_destroy->network);

		_np_keycache_remove(context, to_destroy->dhkey);

		// delete old receive tokens
		if (NULL != to_destroy->recv_tokens)
		{
			if (to_destroy->recv_property != NULL) {
				_LOCK_ACCESS(&to_destroy->recv_property->lock)
				{
					pll_iterator(np_aaatoken_ptr) iter = pll_first(to_destroy->recv_tokens);
					while (NULL != iter)
					{
						np_unref_obj(np_aaatoken_t, iter->val, "recv_tokens");
						pll_next(iter);
					}
					pll_free(np_aaatoken_ptr, to_destroy->recv_tokens);
					to_destroy->recv_tokens = NULL;
				}
			}
		}

		// delete send tokens
		if (NULL != to_destroy->send_tokens)
		{
			if (to_destroy->send_property != NULL) {
				_LOCK_ACCESS(&to_destroy->send_property->lock)
				{
					pll_iterator(np_aaatoken_ptr) iter = pll_first(to_destroy->send_tokens);
					while (NULL != iter)
					{
						np_unref_obj(np_aaatoken_t, iter->val, "send_tokens");
						pll_next(iter);
					}
					pll_free(np_aaatoken_ptr, to_destroy->send_tokens);
					to_destroy->send_tokens = NULL;
				}
			}
		}
	}

	np_sll_t(np_key_ptr, aliasse) = _np_keycache_find_aliase(to_destroy);
	sll_iterator(np_key_ptr) iter = sll_first(aliasse);

	while (iter != NULL) {
		_np_key_destroy(iter->val);
		np_unref_obj(np_key_t, iter->val, "_np_keycache_find_aliase");
		sll_next(iter);
	}
	sll_free(np_key_ptr, aliasse);

	if (to_destroy->parent != NULL) {
		np_unref_obj(np_key_t, to_destroy->parent, ref_key_parent);
		to_destroy->parent = NULL;
	}

	log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key and associated data structures done.");
}

void _np_key_t_new(np_state_t *context, uint8_t type, size_t size, void* key)
{
	log_trace_msg(LOG_TRACE | LOG_KEY, "start: void _np_key_t_new(void* key){");
	np_key_t* new_key = (np_key_t*) key;

	new_key->type = np_key_type_unknown;
	TSP_INITD(new_key->in_destroy, false);

	new_key->last_update = np_time_now();

	new_key->dhkey_str = NULL;
	new_key->node = NULL;		  // link to a neuropil node if this key represents a node
	new_key->network = NULL;      // link to a neuropil node if this key represents a node

	new_key->aaa_token = NULL;

	// used internally only
	new_key->recv_property = NULL;
	new_key->send_property = NULL;

	new_key->local_mx_tokens = NULL; // link to runtime interest data on which this node is interested in

	new_key->send_tokens = NULL; // link to runtime interest data on which this node is interested in
	new_key->recv_tokens = NULL; // link to runtime interest data on which this node is interested in

	new_key->parent = NULL;
	new_key->created_at = np_time_now();
	log_debug_msg(LOG_KEY | LOG_DEBUG, "Created new key");

}

void _np_key_t_del(np_state_t *context, uint8_t type, size_t size, void* key)
{
	log_trace_msg(LOG_TRACE | LOG_KEY, "start: void _np_key_t_del(void* key){");
	np_key_t* old_key = (np_key_t*) key;

	_np_key_destroy(old_key);

	// delete string presentation of key
	if (NULL != old_key->dhkey_str)
	{
		free (old_key->dhkey_str);
		old_key->dhkey_str = NULL;
	}

	// unref and delete of other object pointers has to be done outside of this function
	// otherwise double locking the memory pool will lead to a deadlock

	np_unref_obj(np_msgproperty_t, 	old_key->recv_property,ref_key_recv_property);
	np_unref_obj(np_msgproperty_t, 	old_key->send_property,ref_key_send_property);
	np_unref_obj(np_aaatoken_t,		old_key->aaa_token,ref_key_aaa_token);
	np_unref_obj(np_node_t,     	old_key->node,ref_key_node);
	np_unref_obj(np_network_t,  	old_key->network,ref_key_network);

	TSP_DESTROY(old_key->in_destroy);

}

/**
* Gets a np_key_t or a NULL pointer for the given hash value.
* Generates warnings and aborts the process if a misschief configuration is found.
* @param targetDhkey hash value of a node
* @return
*/
np_key_t* _np_key_get_by_key_hash(np_state_t* context, char* targetDhkey)
{
	log_trace_msg(LOG_TRACE, "start: np_key_t* _np_key_get_by_key_hash(char* targetDhkey){");
	np_key_t* target = NULL;

	if (NULL != targetDhkey) {

		target = _np_keycache_find_by_details(context, targetDhkey, false, np_handshake_status_Connected, true, false, false, true);

		if (NULL == target) {
			log_msg(LOG_WARN,
				"could not find the specific target %s for message. broadcasting msg", targetDhkey);
		}
		else {
			log_debug_msg(LOG_DEBUG, "could find the specific target %s for message.", targetDhkey);
		}

		if (NULL != target && strcmp(_np_key_as_str(target), targetDhkey) != 0) {
			log_msg(LOG_ERROR,
				"Found target key (%s) does not match requested target key (%s)! Aborting",
				_np_key_as_str(target), targetDhkey);
			exit(EXIT_FAILURE);
		}
	}
	return target;
}

void _np_key_set_recv_property(np_key_t* self, np_msgproperty_t* prop) {
	np_ctx_memory(self);
	np_ref_switch(np_msgproperty_t, self->recv_property, ref_key_recv_property, prop);
	prop->recv_key = self;

}

void _np_key_set_send_property(np_key_t* self, np_msgproperty_t* prop) {
	np_ctx_memory(self);
	np_ref_switch(np_msgproperty_t, self->send_property, ref_key_send_property, prop);
	prop->send_key = self;
}
