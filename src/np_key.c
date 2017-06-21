//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "neuropil.h"

#include "sodium.h"

#include "np_log.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "np_keycache.h"
#include "np_aaatoken.h"
#include "np_network.h"
#include "np_node.h"
#include "np_msgproperty.h"
#include "np_key.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_key_t);

NP_SLL_GENERATE_IMPLEMENTATION(np_key_t);
NP_PLL_GENERATE_IMPLEMENTATION(np_key_ptr);

int8_t _np_key_cmp(np_key_t* const k1, np_key_t* const k2)
{
	if (k1 == NULL) return -1;
	if (k2 == NULL) return  1;

	return _np_dhkey_comp(&k1->dhkey,&k2->dhkey);
}

int8_t _np_key_cmp_inv(np_key_t* const k1, np_key_t* const k2)
{
	return -1 * _np_key_cmp(k1, k2);
}

char* _np_key_as_str(np_key_t* key)
{
	if (NULL == key->dhkey_str)
	{
		key->dhkey_str = (char*) malloc(65);
		CHECK_MALLOC(key->dhkey_str);

		_np_dhkey_to_str(&key->dhkey, key->dhkey_str);
		log_debug_msg(LOG_KEY | LOG_DEBUG, "dhkey_str = %lu (%s)", strlen(key->dhkey_str), key->dhkey_str);
	}

	return key->dhkey_str;
}

/**
 * Destroys a key with all resources
 */
void _np_key_destroy(np_key_t* to_destroy) {

	if(NULL != to_destroy) {

		char* keyident = _np_key_as_str(to_destroy);
		log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key and associated data structures: %s", keyident);

		log_debug_msg( LOG_DEBUG, "refcount of key %s at destroy: %d", keyident, to_destroy->obj->ref_count);

		_np_keycache_remove(to_destroy->dhkey);

		_np_network_stop(to_destroy->network);

		// delete old receive tokens
		if (NULL != to_destroy->recv_tokens)
		{
			_LOCK_ACCESS(&to_destroy->recv_property->lock)
			{
				pll_iterator(np_aaatoken_ptr) iter = pll_first(to_destroy->recv_tokens);
				while (NULL != iter)
				{
					np_free_obj(np_aaatoken_t, iter->val);
					pll_next(iter);
				}
				pll_free(np_aaatoken_ptr, to_destroy->recv_tokens);
			}
		}

		// delete send tokens
		if (NULL != to_destroy->send_tokens)
		{
			_LOCK_ACCESS(&to_destroy->send_property->lock)
			{
				pll_iterator(np_aaatoken_ptr) iter = pll_first(to_destroy->send_tokens);
				while (NULL != iter)
				{
					np_free_obj(np_aaatoken_t, iter->val);
					pll_next(iter);
				}
				pll_free(np_aaatoken_ptr, to_destroy->send_tokens);
			}
		}

		np_sll_t(np_key_t, aliasse)  = _np_keycache_find_aliase(to_destroy);
		sll_iterator(np_key_t) iter = sll_first(aliasse);

		while(iter != NULL) {
			_np_key_destroy(iter->val);
			np_unref_obj(np_key_t, iter->val);
			sll_next(iter);
		}

		log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key and associated data structures done.");
	}else{
		log_debug_msg(LOG_KEY | LOG_DEBUG, "no key provided for cleanup");
	}
}


void _np_key_t_new(void* key)
{
	np_key_t* new_key = (np_key_t*) key;

	new_key->last_update = ev_time();

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
}

void _np_key_t_del(void* key)
{
	np_key_t* old_key = (np_key_t*) key;

    // log_msg(LOG_WARN, "destructor of key %p -> %s called ", old_key, _key_as_str(old_key));

	// delete string presentation of key
	if (NULL != old_key->dhkey_str)
	{
		free (old_key->dhkey_str);
		old_key->dhkey_str = NULL;
	}
	// unref and delete of other object pointers has to be done outside of this function
	// otherwise double locking the memory pool will lead to a deadlock

	// delete old network structure
	if (NULL != old_key->aaa_token) np_unref_obj(np_aaatoken_t, old_key->aaa_token);
	if (NULL != old_key->node)      np_unref_obj(np_node_t,     old_key->node);
	if (NULL != old_key->network)   np_unref_obj(np_network_t,  old_key->network);


}

