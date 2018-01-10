//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "np_route.h"

#include "neuropil.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_list.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_types.h"
#include "np_util.h"
#include "np_event.h"
#include "np_settings.h"
#include "np_constants.h"


static const uint16_t __MAX_ROW   = 64; // length of key
static const uint16_t __MAX_COL   = 16; // 16 different characters
static const uint16_t __MAX_ENTRY =  3; // three alternatives for each key

// TODO: change size to match the possible log10(hash key max value)
// TODO: change the size according to the number of entries in the routing table (min: 2/ max: 8)
static const uint16_t __LEAFSET_SIZE = 8; /* (must be even) excluding node itself */

typedef struct np_routeglobal_s np_routeglobal_t;
struct np_routeglobal_s
{
	np_key_t* my_key;
	char* bootstrap_key;

	np_key_t* table[__MAX_ROW * __MAX_COL * __MAX_ENTRY];

	np_pll_t(np_key_ptr, left_leafset);
	np_pll_t(np_key_ptr, right_leafset);

	np_dhkey_t Rrange;
	np_dhkey_t Lrange;
};

static np_routeglobal_t* __routing_table;

void _np_route_append_leafset_to_sll(np_key_ptr_pll_t* left_leafset, np_sll_t(np_key_ptr, result));

/* route_init:
 * Initiates routing table and leafsets
 */
np_bool _np_route_init (np_key_t* me)
{
	__routing_table = (np_routeglobal_t *) calloc (1, sizeof (np_routeglobal_t));
	CHECK_MALLOC(__routing_table);

	__routing_table->bootstrap_key = NULL;
	_np_route_set_key(me);
	// np_ref_obj(np_key_t, __routing_table->my_key, ref_route_routingtable_mykey);

	pll_init(np_key_ptr,__routing_table->left_leafset);
	pll_init(np_key_ptr,__routing_table->right_leafset);

   // _np_route_clear();

	return (TRUE);
}

/**
 ** _np_route_leafset_update:
 ** this function is called whenever a _np_route_update is called the joined
 ** is 1 if the node has joined and 0 if a node is leaving.
 **/
void _np_route_leafset_update (np_key_t* node_key, np_bool joined, np_key_t** deleted, np_key_t** added)
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.leafset_update");

	if (node_key->in_destroy == TRUE)
		return;

	*added = NULL;
	*deleted = NULL;	
	_LOCK_MODULE(np_routeglobal_t)
	{
		if (_np_key_cmp(node_key, __routing_table->my_key) != 0)
		{
			np_key_ptr find_right = pll_find(np_key_ptr, __routing_table->right_leafset, node_key, _np_key_cmp_inv);
			np_key_ptr find_left = pll_find(np_key_ptr, __routing_table->left_leafset, node_key, _np_key_cmp);

			if (FALSE == joined) {

				if (NULL != find_right) {
					*deleted = (np_key_t*)node_key;
					pll_remove(np_key_ptr, __routing_table->right_leafset, node_key, _np_key_cmp_inv);

				}
				else if (NULL != find_left) {
					*deleted = (np_key_t*)node_key;
					pll_remove(np_key_ptr, __routing_table->left_leafset, node_key, _np_key_cmp);
				}
				else {
					log_debug_msg(LOG_ROUTING | LOG_DEBUG, "leafset did not change as key was not found");
				}

			}
			else {

				if (NULL != find_right || NULL != find_left) {
					log_debug_msg(LOG_ROUTING | LOG_DEBUG, "leafset did not change as key was already in leafset");

				}
				else {
					/**
					 * The key is not in our current leafset. So we need to check if we want to add it to our leafset
					 * Cases:
					 * 1. Leafset right or left is not fully filled
					 *    => Add to leafset
					 * 2. Leafsets are fully filled and our new key is between our outer bounds
					 *    => We need to insert the key at the appropiate point in the list (another key is removed from our leafset)
					 * 3. Leafsets are fully filled and our new key is further away then our outer bounds
					 *    => No action required
					 */

					pll_iterator(np_key_ptr) right_outer = pll_last(__routing_table->right_leafset);
					pll_iterator(np_key_ptr) left_outer = pll_last(__routing_table->left_leafset);
				
					np_dhkey_t my_inverse_dhkey = { 0 };
					np_dhkey_t dhkey_half_o = np_dhkey_half();
					_np_dhkey_add(&my_inverse_dhkey, &__routing_table->my_key->dhkey, &dhkey_half_o);

					if (_np_dhkey_between(&node_key->dhkey, &__routing_table->my_key->dhkey, &my_inverse_dhkey, TRUE))
					{
						if (
							pll_size(__routing_table->right_leafset) < __LEAFSET_SIZE ||
							_np_dhkey_between(
								&node_key->dhkey,
								&__routing_table->my_key->dhkey,
								&right_outer->val->dhkey,
								FALSE
							)
						)
						{
							if (pll_insert(np_key_ptr, __routing_table->right_leafset, node_key, FALSE, _np_key_cmp_inv)== TRUE) {
								*added = node_key;
							}
						}
						
						// Cleanup of leafset / resize leafsets to max size if necessary
						if (pll_size(__routing_table->right_leafset) > __LEAFSET_SIZE) {
							*deleted = pll_tail(np_key_ptr, __routing_table->right_leafset);
						}
					}
					else if (_np_dhkey_between(&node_key->dhkey, &my_inverse_dhkey, &__routing_table->my_key->dhkey, TRUE))
					{
						if (
							pll_size(__routing_table->left_leafset) < __LEAFSET_SIZE ||
							_np_dhkey_between(
								&node_key->dhkey,
								&left_outer->val->dhkey,
								&__routing_table->my_key->dhkey,
								FALSE
							)
						)
						{
							if(pll_insert(np_key_ptr, __routing_table->left_leafset, node_key, FALSE, _np_key_cmp) == TRUE){
								*added = node_key;
							}							
						}

						// Cleanup of leafset / resize leafsets to max size if necessary
						if (pll_size(__routing_table->left_leafset) > __LEAFSET_SIZE) {
							*deleted = pll_tail(np_key_ptr, __routing_table->left_leafset);
						}
					}
					else
					{	// Neither the lefsets are empty nor is the new key between our known outer bounds
						log_debug_msg(LOG_ROUTING | LOG_DEBUG, "not adding key to leafset ...");
					}

				}
			}
		}
	}

	// TODO: handle it via add a new async update job instead ?
	if (*deleted != NULL || *added != NULL)
	{
		_np_route_leafset_range_update();
	}

	np_key_t* tmp = *added ;
	if(tmp != NULL){
		np_ref_obj(np_key_t, tmp, ref_route_inleafset);
	}

	tmp = *deleted ;
	if(tmp != NULL){
		np_unref_obj(np_key_t, tmp, ref_route_inleafset);
		_np_route_check_for_joined_network();
	}
	
	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .leafset_update");
}

void _np_route_set_key (np_key_t* new_node_key)
{
	_LOCK_MODULE(np_routeglobal_t)
	{
		np_ref_switch(np_key_t, __routing_table->my_key, ref_route_routingtable_mykey, new_node_key);

		np_dhkey_t half = np_dhkey_half();
		_np_dhkey_add(&__routing_table->Rrange, &__routing_table->my_key->dhkey, &half);
		_np_dhkey_sub(&__routing_table->Lrange, &__routing_table->my_key->dhkey, &half);

		// TODO: re-order table entries and leafset table maybe ?
		// for now: hope that the routing table does it on its own as new keys arrive ...
	}
}

/** route_get_table:
 ** return the entire routing table
 */
sll_return(np_key_ptr) _np_route_get_table ()
{
	np_sll_t(np_key_ptr, sll_of_keys);
	sll_init(np_key_ptr, sll_of_keys);

	_LOCK_MODULE(np_routeglobal_t)
	{
		uint16_t i, j, k;
		for (i = 0; i < __MAX_ROW; i++)
		{
			for (j = 0; j < __MAX_COL; j++)
			{
				int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
				for (k = 0; k < __MAX_ENTRY; k++)
				{
					if (NULL != __routing_table->table[index + k])
					{
						sll_append(np_key_ptr, sll_of_keys, __routing_table->table[index + k]);
						log_debug_msg(LOG_ROUTING | LOG_DEBUG, "added to routes->table[%d]", index+k);
					}
				}
			}
		}

		np_ref_list(sll_of_keys, __func__,NULL);
	}
	return (sll_of_keys);
}

/** _np_route_row_lookup:key
 ** return the row in the routing table that matches the longest prefix with #key#
 **/
sll_return(np_key_ptr) _np_route_row_lookup (np_key_t* key)
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.route_row_lookup");

	np_sll_t(np_key_ptr, sll_of_keys);
	sll_init(np_key_ptr, sll_of_keys);

	_LOCK_MODULE(np_routeglobal_t)
	{
		uint16_t i, j, k;
		i = _np_dhkey_index (&__routing_table->my_key->dhkey, &key->dhkey);
		for (j = 0; j < __MAX_COL; j++)
		{
			int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
			for (k = 0; k < __MAX_ENTRY; k++)
			{
				if (__routing_table->table[index + k] != NULL &&
					!_np_dhkey_equal(&__routing_table->table[index + k]->dhkey, &key->dhkey) )
				{
					sll_append(np_key_ptr, sll_of_keys, __routing_table->table[index + k]);
				}
			}
		}

		sll_append(np_key_ptr, sll_of_keys, __routing_table->my_key);
		np_ref_list(sll_of_keys, __func__, NULL);
	}

	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_row_lookup");
	return (sll_of_keys);
}

void _np_route_append_leafset_to_sll(np_key_ptr_pll_t* leafset, np_sll_t(np_key_ptr, result))
{
	pll_iterator(np_key_ptr) iter = pll_first(leafset);

	while(iter != NULL) {
		if(iter->val != NULL) {
			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "Leafset: (%s)", _np_key_as_str (iter->val));
			sll_append(np_key_ptr, result, iter->val);
		}
		pll_next(iter);
	}
}
/** _np_route_lookup:
 ** returns an array of #count# keys that are acceptable next hops for a
 ** message being routed to #key#.
 */
sll_return(np_key_ptr) _np_route_lookup(np_dhkey_t key, uint8_t count)
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.route_lookup");
	uint32_t i, j, k, Lsize, Rsize;
	uint8_t match_col = 0;
	np_bool next_hop = FALSE;

	np_dhkey_t dif1, dif2;
	np_key_t *tmp_1 = NULL, *tmp_2 = NULL, *min = NULL;

	np_sll_t(np_key_ptr, return_list);
	sll_init(np_key_ptr, return_list);

	_LOCK_MODULE(np_routeglobal_t)
	{
		np_sll_t(np_key_ptr, key_list);
		sll_init(np_key_ptr, key_list);

		// log_debug_msg(
		// LOG_ROUTING | LOG_DEBUG, "%s is looking for key %s !",
		// _np_key_as_str(__routing_table->my_key), _np_key_as_str(key));

		/*calculate the leafset and table size */
		Lsize = pll_size(__routing_table->left_leafset);
		Rsize = pll_size(__routing_table->right_leafset);

		/* if the key is in the leafset range route through leafset */
		/* the additional 2 neuropil nodes pointed by the #hosts# are to consider the node itself and NULL at the end */
		if (count == 1 &&
			_np_dhkey_between (&key, &__routing_table->Lrange, &__routing_table->Rrange, TRUE))
		{
			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "routing through leafset");
			sll_append(np_key_ptr, key_list, __routing_table->my_key);

			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "ME: (%s)", _np_key_as_str (__routing_table->my_key));

			_np_route_append_leafset_to_sll(__routing_table->left_leafset, key_list);
			_np_route_append_leafset_to_sll(__routing_table->right_leafset, key_list);

			min = _np_keycache_find_closest_key_to (key_list, &key);
			if(NULL != min) {				
				ref_replace_reason(np_key_t, min, "_np_keycache_find_closest_key_to", __func__); 
				sll_append(np_key_ptr, return_list, min);				
 
				log_debug_msg(LOG_ROUTING | LOG_DEBUG, "++NEXT_HOP = %s", _np_key_as_str (min));
			}			

			sll_free (np_key_ptr, key_list);
			_np_threads_unlock_module(np_routeglobal_t_lock);
			log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_lookup");
			return (return_list);
		}

		/* check to see if there is a matching next hop (for fast routing) */
		i = _np_dhkey_index (&__routing_table->my_key->dhkey, &key);
		match_col = _np_dhkey_hexalpha_at (&key, i);

		int index = __MAX_ENTRY * (match_col + (__MAX_COL* (i)));
		for (k = 0; k < __MAX_ENTRY; k++)
		{
			if (__routing_table->table[index + k] != NULL)
			{
				tmp_1 = __routing_table->table[index + k];
				if (tmp_1->node->success_avg > BAD_LINK)
				{
					next_hop = TRUE;
					break;
				}
			}
		}

		if (TRUE == next_hop && 1 == count)
		{
			int index = __MAX_ENTRY * (match_col + (__MAX_COL* (i)));
			// int index = (i * __MAX_ROW + match_col) * __MAX_COL;
			for (k = 0; k < __MAX_ENTRY; k++)
			{
				if ( __routing_table->table[index + k] != NULL &&
					 !_np_dhkey_equal(&__routing_table->table[index + k]->dhkey, &tmp_1->dhkey) )
				{
					tmp_2 = __routing_table->table[index + k];
					// TODO: make it more algorithmic ...
					if ( tmp_2->node->success_avg >= tmp_1->node->success_avg &&
						 tmp_2->node->latency      < tmp_1->node->latency )
					{
						tmp_1 = __routing_table->table[index + k];
					}
				}
			}

			np_ref_obj(np_key_t, tmp_1 );
			sll_append(np_key_ptr, return_list, tmp_1);

			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "Routing through Table(%s), NEXT_HOP=%s",
				   _np_key_as_str (__routing_table->my_key),
				   _np_key_as_str (tmp_1) );

			sll_free (np_key_ptr, key_list);
			_np_threads_unlock_module(np_routeglobal_t_lock);
			log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_lookup");
			return (return_list);
		}

		/* if there is no matching next hop we have to find the best next hop */
		/* brute force method to solve count requirements */

		// log_msg (LOG_ROUTING, "Routing to next closest key I know of:");
		/* look left */

		_np_route_append_leafset_to_sll(__routing_table->left_leafset, key_list);
		_np_route_append_leafset_to_sll(__routing_table->right_leafset, key_list);

		if (count == 0) {
			// consider that this node could be the target as well
			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "+me: (%s)",
					/* leaf->dns_name, leaf->port,*/ _np_key_as_str (__routing_table->my_key) );
			sll_append(np_key_ptr, key_list, __routing_table->my_key);
		}

		/* find the longest prefix match */
		i = _np_dhkey_index (&__routing_table->my_key->dhkey, &key);
		for (j = 0; j < __MAX_COL; j++)
		{
			int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
			for (k = 0; k < __MAX_ENTRY; k++)
			{
				if (__routing_table->table[index + k] != NULL)
				{
					tmp_1 = __routing_table->table[index + k];
					if (NULL != tmp_1->node && tmp_1->node->success_avg > BAD_LINK)
					{
						sll_append(np_key_ptr, key_list, tmp_1);
						log_debug_msg(LOG_ROUTING | LOG_DEBUG, "+Table[%ul][%ul][%ul]: (%s)",
											  i, j, k, /* leaf->dns_name, leaf->port, */ _np_key_as_str (tmp_1));
					}
				}
			}
		}

		if (count == 1)
		{
			// printf ("route.c (%d): _np_route_lookup bounce count==1 ...\n", getpid());
			// printTable(state);
			min = _np_keycache_find_closest_key_to (key_list, &key);
			
			if (NULL != min) {
				ref_replace_reason(np_key_t, min, "_np_keycache_find_closest_key_to", __func__);
				sll_append(np_key_ptr, return_list, min);
			}
		}
		else
		{
			if (2 <= key_list->size)
			{
				_np_keycache_sort_keys_cpm (key_list, &key);
				/* find the best #count# entries that we looked at ... could be much better */
				
				/* removing duplicates from the list */				
				sll_iterator(np_key_ptr) iter1 = sll_first(key_list);
				sll_iterator(np_key_ptr) iter2 = NULL;
				np_bool iters_equal = FALSE;
				while (iter1 != NULL)
				{
					iters_equal = FALSE;
					iter2 = sll_first(return_list);
					while (iter2 != NULL)
					{
						if (_np_dhkey_equal(&iter2->val->dhkey, &iter1->val->dhkey)==TRUE) {
							iters_equal = TRUE;
							break;
						}
						sll_next(iter2);
					}
					if (iters_equal == FALSE) {
						np_ref_obj(np_key_t, iter1->val);
						sll_append(np_key_ptr, return_list, iter1->val);
					}
					sll_next(iter1);
				}
			}
		}
		

		/*  to prevent bouncing */
		if (count == 1 && sll_size(return_list) > 0)
		{
	//	    log_debug_msg(LOG_DEBUG, "_np_route_lookup bounce detection ...");
	//	    log_debug_msg(LOG_DEBUG, "search key: %s", _np_key_as_str(key) );
	//	    log_debug_msg(LOG_DEBUG, "my own key: %s", _np_key_as_str(routes->my_key) );
	//	    log_debug_msg(LOG_DEBUG, "lookup key: %s", _np_key_as_str(sll_first(return_list)->val) );

			_np_dhkey_distance (&dif1, &key, &sll_first(return_list)->val->dhkey);
			_np_dhkey_distance (&dif2, &key, &__routing_table->my_key->dhkey);

			// printTable(rg);

			// if (key_equal (dif1, dif2)) ret[0] = rg->me;
			// changed on 03.06.2014 STSW choose the closest neighbour
			if (_np_dhkey_comp(&dif1, &dif2) <= 0) {
				sll_iterator(np_key_ptr) first = sll_first(return_list);
				np_unref_obj(np_key_t, first->val, __func__);
				first->val = __routing_table->my_key;
				np_ref_obj(np_key_t, first->val);
			}

			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "route  key: %s", _np_key_as_str(sll_first(return_list)->val));

			// if (!key_comp(&dif1, &dif2) == 0) ret[0] = rg->me;
			// if (key_comp(&dif1, &dif2)  < 0) ret[0] = NULL;
			// if (key_comp(&dif1, &dif2)  > 0) ret[0] = rg->me;

		} else {
			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "route_lookup bounce detection not wanted ...");
		}
		
		sll_free(np_key_ptr, key_list);
	}	
	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_lookup");
	return (return_list);
}

/**
 ** _np_route_leafset_range_update:
 ** updates the leafset range whenever a node leaves or joins to the leafset
 **
 ** fills rrange and lrange with the outer bounds of our leafset
 */
void _np_route_leafset_range_update ()
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.leafset_range_update");
	pll_iterator(np_key_ptr) item = pll_last(__routing_table->right_leafset);

	if(item != NULL) {
		_np_dhkey_assign (&__routing_table->Rrange, &item->val->dhkey);
	} else {
		_np_dhkey_assign (&__routing_table->Rrange, &__routing_table->my_key->dhkey);
	}

	item = pll_last(__routing_table->left_leafset);
	if(item != NULL) {
		_np_dhkey_assign (&__routing_table->Lrange, &item->val->dhkey);
	} else {
		_np_dhkey_assign (&__routing_table->Lrange, &__routing_table->my_key->dhkey);
	}
	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .leafset_range_update");
}

/** _np_route_neighbors:
 ** returns an array of #count# neighbor nodes with priority to closer nodes
 **/
sll_return(np_key_ptr) _np_route_neighbors ()
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.route_neighbors");

	np_sll_t(np_key_ptr, node_keys);
	sll_init(np_key_ptr, node_keys);
	_LOCK_MODULE(np_routeglobal_t)
	{
		_np_route_append_leafset_to_sll(__routing_table->left_leafset, node_keys);
		_np_route_append_leafset_to_sll(__routing_table->right_leafset, node_keys);	

		np_ref_list(node_keys, __func__, NULL);
	}
	/* sort aux */
	_np_keycache_sort_keys_kd(node_keys, &__routing_table->my_key->dhkey);

	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_neighbors");
	return node_keys;
}

/** _np_route_clear
 ** wipe out all entries from the table and the leafset
 **/
void _np_route_clear ()
{
	np_key_t* deleted;
	np_key_t* added;

	_LOCK_MODULE(np_routeglobal_t)
	{
		/* initialize memory for routing table */
		uint16_t i, j, k;
		for (i = 0; i < __MAX_ROW; i++)
		{
			for (j = 0; j < __MAX_COL; j++)
			{
				int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
				for (k = 0; k < __MAX_ENTRY; k++)
				{
					np_key_t* item = __routing_table->table[index + k];
					if(item != NULL){
						_np_route_update(item, FALSE, &deleted, &added);
						__routing_table->table[index + k] = NULL;
					}
				}
			}
		}

		_np_route_leafset_clear();
	}
}
void _np_route_leafset_clear ()
{
	_LOCK_MODULE(np_routeglobal_t)
	{
		np_sll_t(np_key_ptr, neighbour_list) = _np_route_neighbors();
		sll_iterator(np_key_ptr) iter = sll_first(neighbour_list);
		np_key_t* deleted = NULL;
		np_key_t* added = NULL;

		while(iter != NULL) {
			_np_route_leafset_update(iter->val,FALSE,&deleted,&added);
			assert (deleted == iter->val);
			sll_next(iter);
		}
		np_unref_list(neighbour_list, "_np_route_neighbors");
		sll_free(np_key_ptr, neighbour_list);

		if(__routing_table->left_leafset->size != 0){
			log_msg(LOG_ERROR,"Could not clear left leafset!");
		}
		if(__routing_table->right_leafset->size != 0){
			log_msg(LOG_ERROR,"Could not clear right leafset!");
		}
	}
}

/** _np_route_update:
 ** updated the routing table in regard to #node#. If the host is joining
 ** the network (and #joined# == 1), then it is added to the routing table
 ** if it is appropriate. If it is leaving the network (and #joined# == 0),
 ** then it is removed from the routing tables
 **/
void _np_route_update (np_key_t* key, np_bool joined, np_key_t** deleted, np_key_t** added)
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.route_update");

	if (key->in_destroy == TRUE)
		return;

	_LOCK_MODULE(np_routeglobal_t)
	{

		log_msg(LOG_ROUTING | LOG_INFO, "update in routing: %u %s", joined, _np_key_as_str(key));

		if (_np_dhkey_equal (&__routing_table->my_key->dhkey, &key->dhkey))
		{
			log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_update");
			_np_threads_unlock_module(np_routeglobal_t_lock);
			return;
		}
		*added = NULL;
		*deleted = NULL;

		uint16_t i, j, k, found, pick;

		i = _np_dhkey_index (&__routing_table->my_key->dhkey, &key->dhkey);
		j = _np_dhkey_hexalpha_at (&key->dhkey, i);

		int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));

		/* a node joins the routing table */
		if (TRUE == joined)
		{
			found = 0;
			for (k = 0; k < __MAX_ENTRY; k++)
			{
				if (__routing_table->table[index + k] != NULL &&
					_np_dhkey_equal (&__routing_table->table[index + k]->dhkey, &key->dhkey))
				{
					found = 0;
					break;
				}

				if (__routing_table->table[index + k] == NULL)
				{
					__routing_table->table[index + k] = key;
					found = 0;
					*added   = key;
					log_debug_msg(LOG_ROUTING | LOG_DEBUG, "added to routes->table[%d]", index+k);
					break;
				}
				else if (__routing_table->table[index + k] != NULL &&
						 !_np_dhkey_equal (&__routing_table->table[index + k]->dhkey, &key->dhkey ))
				{
					found = 1;
				}
			}

			/* the entry array is full we have to get rid of one */
			/* replace the new node with the node with the highest latency in the entry array */
			if (found)
			{
				pick = 0;
				for (k = 1; k < __MAX_ENTRY; k++)
				{
					np_key_t *pick_node, *tmp_node;

					pick_node = __routing_table->table[index + pick];
					tmp_node  = __routing_table->table[index + k];

					log_debug_msg(LOG_ROUTING | LOG_DEBUG, "replace latencies at index %d: t..%f > p..%f ?",
							index, tmp_node->node->latency, pick_node->node->latency);

					if (tmp_node->node->latency > pick_node->node->latency  )
					{
						pick = k;
					}
				}
				np_key_t* check_to_del = __routing_table->table[index + pick];

				// only replace if the new latency is a better one
				if(check_to_del == NULL || check_to_del->node->latency > key->node->latency){
					*deleted = __routing_table->table[index + pick];
					log_debug_msg(LOG_ROUTING | LOG_DEBUG, "replaced to routes->table[%d]", index+pick);
					__routing_table->table[index + pick] = key;
					*added = __routing_table->table[index + pick];
				}
			}
		}
		else
		{
			/* delete a node from the routing table */
			for (k = 0; k < __MAX_ENTRY; k++)
			{
				if (__routing_table->table[index + k] != NULL &&
					_np_dhkey_equal (&__routing_table->table[index + k]->dhkey, &key->dhkey) )
				{
					*deleted = key;
					__routing_table->table[index + k] = NULL;

					log_debug_msg(LOG_ROUTING | LOG_DEBUG, "deleted to routes->table[%d]", index+k);
					break;
				}
			}
		}

		np_key_t* tmp = *added ;
		if(tmp != NULL){
			np_ref_obj(np_key_t, tmp, ref_route_inroute);
		}

		tmp = *deleted ;
		if(tmp != NULL){
			np_unref_obj(np_key_t, tmp, ref_route_inroute);

			_np_route_check_for_joined_network();
		}
	}
	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_update");
}

uint32_t __np_route_my_key_count_routes(np_bool break_on_first) {
	uint32_t ret = 0;

	_LOCK_MODULE(np_routeglobal_t)
	{
		if (__routing_table->my_key->node->joined_network == TRUE) {
			
			uint16_t i, j, k;
			for (i = 0; i < __MAX_ROW; i++)
			{
				for (j = 0; j < __MAX_COL; j++)
				{
					int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
					for (k = 0; k < __MAX_ENTRY; k++)
					{
						if (NULL != __routing_table->table[index + k])
						{
							ret += 1;
						}
						if (ret > 0 && break_on_first) {
							break;
						}
					}
					if (ret > 0 && break_on_first) {
						break;
					}
				}
				if (ret > 0 && break_on_first) {
					break;
				}
			}
		}
	}
	return ret;
}

np_bool _np_route_my_key_has_connection() {
	return (__np_route_my_key_count_routes(TRUE) + _np_route_my_key_count_neighbours()) > 0 ? TRUE: FALSE;
}

uint32_t _np_route_my_key_count_routes() {
	return __np_route_my_key_count_routes(FALSE);
}
uint32_t _np_route_my_key_count_neighbours() {
	return  pll_size(__routing_table->left_leafset) + pll_size(__routing_table->right_leafset);
}

void _np_route_check_for_joined_network()
{
	if( _np_route_my_key_has_connection() == FALSE)
	{
		__routing_table->my_key->node->joined_network = FALSE;
		//_np_route_rejoin_bootstrap(TRUE);
	}
}

char* np_route_get_bootstrap_connection_string() {
	log_msg(LOG_TRACE | LOG_ROUTING, "start: np_key_t* np_route_get_bootstrap_key() {");
	return __routing_table->bootstrap_key;
}

void np_route_set_bootstrap_key(np_key_t* bootstrap_key) {
	log_msg(LOG_TRACE | LOG_ROUTING, "void np_route_set_bootstrap_key(np_key_t* bootstrap_key) {");
		
	char* old = __routing_table->bootstrap_key;	
	__routing_table->bootstrap_key = np_get_connection_string_from(bootstrap_key,FALSE);
	free(old);
}

void _np_route_rejoin_bootstrap(np_bool force) {

	if (__routing_table->bootstrap_key != NULL) {

	np_bool rejoin = force
			|| _np_route_my_key_has_connection() == FALSE;
	
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "Check for rejoin result: %s%s necessary", (rejoin == TRUE ? "" : "not"), (force == TRUE ? "(f)" : ""));

		if(TRUE == rejoin
				// check for state availibility to prevent test issues. TODO: Make network objects mockable
				&& _np_state() != NULL) {
			char* bootstrap = np_route_get_bootstrap_connection_string();
			if(NULL != bootstrap)
			{
				if(force == FALSE)
				{
					log_msg(LOG_WARN, "lost all connections. try to reconnect to bootstrap host");
				}
				np_send_wildcard_join(bootstrap);
			}
		}
	}
}
