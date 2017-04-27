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

#include "sodium.h"

#include "np_keycache.h"

#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_log.h"
#include "np_key.h"
#include "np_network.h"
#include "np_node.h"

// TODO: make this a better constant value
static double __keycache_deprecation_interval = 31.415;

SPLAY_GENERATE(st_keycache_s, np_key_s, link, _np_key_cmp);
_NP_GENERATE_MEMORY_IMPLEMENTATION(np_key_t);

NP_SLL_GENERATE_IMPLEMENTATION(np_key_t);

static pthread_mutex_t __lock_mutex = PTHREAD_MUTEX_INITIALIZER;
_NP_MODULE_LOCK_IMPL(np_keycache_t);

typedef struct st_keycache_s st_keycache_t;
static st_keycache_t* __key_cache;

void _np_keycache_init()
{
	__key_cache = (st_keycache_t*) malloc(sizeof(st_keycache_t));
	CHECK_MALLOC(__key_cache);

	SPLAY_INIT(__key_cache);
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
}





np_key_t* _np_key_find_create(np_dhkey_t search_dhkey)
{
	np_key_t search_key = { .dhkey = search_dhkey };

	np_key_t* subject_key = SPLAY_FIND(st_keycache_s, __key_cache, &search_key);
	if (NULL == subject_key)
	{
		subject_key = _np_key_create(search_dhkey);
    }
	subject_key->last_update = ev_time();
	return subject_key;
}

np_key_t* _np_key_create(np_dhkey_t search_dhkey)
{

	np_key_t* subject_key ;
	np_new_obj(np_key_t, subject_key);
	subject_key->dhkey = search_dhkey;

	SPLAY_INSERT(st_keycache_s, __key_cache, subject_key);

	// np_ref_obj(np_key_t, subject_key);

	subject_key->last_update = ev_time();
	return subject_key;
}

np_key_t* _np_key_find(np_dhkey_t search_dhkey)
{
	np_key_t search_key = { .dhkey = search_dhkey };
	np_key_t* return_key = SPLAY_FIND(st_keycache_s, __key_cache, &search_key);

	if (NULL != return_key)
	{
		return_key->last_update = ev_time();
	}
	return return_key;
}



int8_t _np_key_cmp(np_key_t* const k1, np_key_t* const k2)
{
	if (k1 == NULL) return -1;
	if (k2 == NULL) return  1;

	return _dhkey_comp(&k1->dhkey,&k2->dhkey);
}

int8_t _np_key_cmp_inv(np_key_t* const k1, np_key_t* const k2)
{
	return -1 * _np_key_cmp(k1, k2);
}


np_key_t* _np_key_find_by_details(
		char* details_container,
		np_bool search_myself,
		handshake_status_e handshake_status,
		np_bool require_handshake_status,
		np_bool require_dns,
		np_bool require_port,
		np_bool require_hash
	){
	np_key_t* ret = NULL;
	np_key_t *iter = NULL;
	SPLAY_FOREACH(iter, st_keycache_s, __key_cache)
	{
		if(TRUE == search_myself){
			if (
				TRUE == _dhkey_equal(&iter->dhkey, &_np_state()->my_node_key->dhkey) ||
				TRUE == _dhkey_equal(&iter->dhkey, &_np_state()->my_identity->dhkey) )
			{
				continue;
			}
		}

		if (
				(!require_handshake_status || (NULL != iter->node && iter->node->handshake_status == handshake_status)) &&
				(!require_hash || (NULL != iter->dhkey_str && strstr(details_container, iter->dhkey_str) != NULL)) &&
				(!require_dns || (NULL != iter->node &&NULL != iter->node->dns_name && strstr(details_container, iter->node->dns_name) != NULL)) &&
				(!require_port || (NULL != iter->node && NULL != iter->node->port &&strstr(details_container, iter->node->port) != NULL))
		)
		{
			ret = iter;
			break;
		}
	}
	return (ret);
}

np_key_t* _np_key_find_by_dhkey(const np_dhkey_t dhkey){
	np_key_t* ret = NULL;
	np_key_t *iter = NULL;
	SPLAY_FOREACH(iter, st_keycache_s, __key_cache)
	{
		if (_dhkey_comp(&dhkey,&iter->dhkey) == 0)
		{
			ret = iter;
			break;
		}
	}
	return (ret);
}

np_key_t* _np_key_find_deprecated()
{
	np_key_t *iter = NULL;
	SPLAY_FOREACH(iter, st_keycache_s, __key_cache)
	{
		// our own key / identity never deprecates
		if (TRUE == _dhkey_equal(&iter->dhkey, &_np_state()->my_node_key->dhkey) ||
			TRUE == _dhkey_equal(&iter->dhkey, &_np_state()->my_identity->dhkey) )
		{
			continue;
		}

		double now = ev_time();
		if ((now - __keycache_deprecation_interval) > iter->last_update)
		{
			break;
		}
	}
	return (iter);
}

np_key_t* _np_key_remove(np_dhkey_t search_dhkey)
{
	np_key_t search_key = { .dhkey = search_dhkey };

	np_key_t* rem_key = SPLAY_FIND(st_keycache_s, __key_cache, &search_key);
	// np_key_t* rem_key = SPLAY_REMOVE(st_keycache_s, __key_cache, &search_key);
	SPLAY_REMOVE(st_keycache_s, __key_cache, rem_key);
	return rem_key;
}

np_key_t* _np_key_add(np_key_t* subject_key)
{
	np_new_obj(np_key_t, subject_key);

	SPLAY_INSERT(st_keycache_s, __key_cache, subject_key);

	// np_ref_obj(np_key_t, subject_key);

	subject_key->last_update = ev_time();
	return subject_key;
}

char* _key_as_str(np_key_t* key)
{
	if (NULL == key->dhkey_str)
	{
		key->dhkey_str = (char*) malloc(65);
		CHECK_MALLOC(key->dhkey_str);

		_dhkey_to_str(&key->dhkey, key->dhkey_str);
		log_msg (LOG_KEY | LOG_DEBUG, "dhkey_str = %lu (%s)", strlen(key->dhkey_str), key->dhkey_str);
	}

	return key->dhkey_str;
}


/** _np_find_closest_key:
 ** finds the closest node in the array of #hosts# to #key# and put that in min.
 */
np_key_t* _np_find_closest_key ( np_sll_t(np_key_t, list_of_keys), const np_dhkey_t* const key)
{
    np_dhkey_t  dif, minDif;
    np_key_t *min = NULL;

	sll_iterator(np_key_t) iter = sll_first(list_of_keys);
	np_bool first_run = TRUE;
	while (NULL != iter)
	{
		// clculate distance to the left and right
		_dhkey_distance (&dif, key, &iter->val->dhkey);

		// Set reference point at first iteration, then compare current iterations distance with shortest known distance
		if (TRUE == first_run || _dhkey_comp (&dif, &minDif) < 0)
		{
			min = iter->val;
			_dhkey_assign (&minDif, &dif);
		}

		sll_next(iter);
		first_run = FALSE;
	}

	if (sll_size(list_of_keys) == 0)
	{
		log_msg(LOG_KEY | LOG_ERROR, "minimum size for closest key calculation not met !");
	}

	return (min);
}

/** sort_hosts:
 ** Sorts #hosts# based on common prefix match and key distance from #np_key_t*
 */
void _np_sort_keys_cpm (np_sll_t(np_key_t, node_keys), const np_dhkey_t* key)
{
    np_dhkey_t dif1, dif2;

    uint16_t pmatch1 = 0;
    uint16_t pmatch2 = 0;

    if (sll_size(node_keys) < 2) return;

    np_key_t* tmp;
    sll_iterator(np_key_t) iter1 = sll_first(node_keys);

    do
    {
        sll_iterator(np_key_t) iter2 = sll_get_next(iter1);

        if (NULL == iter2) break;

        do
        {
        	pmatch1 = _dhkey_index (key, &iter1->val->dhkey);
			pmatch2 = _dhkey_index (key, &iter2->val->dhkey);
			if (pmatch2 > pmatch1)
			{
				tmp = iter1->val;
				iter1->val = iter2->val;
				iter2->val = tmp;
			}
			else if (pmatch1 == pmatch2)
			{
			    _dhkey_distance (&dif1, &iter1->val->dhkey, key);
			    _dhkey_distance (&dif2, &iter2->val->dhkey, key);
			    if (_dhkey_comp (&dif2, &dif1) < 0)
				{
					tmp = iter1->val;
					iter1->val = iter2->val;
					iter2->val = tmp;
				}
			}
		} while (NULL != (sll_next(iter2)) );
	} while (NULL != (sll_next(iter1)) );
}

void _np_ref_keys (np_sll_t(np_key_t, list_of_keys))
{
 	sll_iterator(np_key_t) iter = sll_first(list_of_keys);
	while (NULL != iter)
	{
		np_ref_obj(np_key_t,iter->val);
		sll_next(iter);
	}
}

void _np_unref_keys (np_sll_t(np_key_t, list_of_keys))
{
	sll_iterator(np_key_t) iter = sll_first(list_of_keys);
	while (NULL != iter)
	{
		np_unref_obj(np_key_t,iter->val);
		sll_next(iter);
	}
}


/** sort_hosts_key:
 ** Sorts #hosts# based on their key distance from #np_key_t*
 */
void _np_sort_keys_kd (np_sll_t(np_key_t, list_of_keys), const np_dhkey_t* key)
{
    np_dhkey_t dif1, dif2;

    // entry check for empty list
    if (NULL == sll_first(list_of_keys)) return;

    sll_iterator(np_key_t) curr = sll_first(list_of_keys);
    do {
        // Maintain pointers.
        sll_iterator(np_key_t) next = sll_get_next(curr);

        // Cannot swap last element with its next.
        while (NULL != next)
        {
        	// Swap if items in wrong order.
		    _dhkey_distance (&dif1, &curr->val->dhkey, key);
		    _dhkey_distance (&dif2, &next->val->dhkey, key);
		    if (_dhkey_comp (&dif2, &dif1) < 0)
			{
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

    } while (curr != sll_last(list_of_keys) && NULL != curr);

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



