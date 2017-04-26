//
// neuropil is copyright 2016 by pi-lar GmbH
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

#include "np_list.h"
#include "np_log.h"
#include "np_keycache.h"
#include "np_list.h"
#include "np_memory.h"
#include "np_node.h"
#include "np_threads.h"

static const uint16_t __MAX_ROW   = 64; // length of key
static const uint16_t __MAX_COL   = 16; // 16 different characters
static const uint16_t __MAX_ENTRY =  3; // three alternatives for each key

// TODO: change size to match the possible log10(hash key max value)
static const uint16_t __LEAFSET_SIZE = 8; /* (must be even) excluding node itself */

static pthread_mutex_t __lock_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef np_key_t* np_key_ptr;
NP_PLL_GENERATE_PROTOTYPES(np_key_ptr);
NP_PLL_GENERATE_IMPLEMENTATION(np_key_ptr);

typedef struct np_routeglobal_s np_routeglobal_t;
struct np_routeglobal_s
{
	np_key_t* my_key;

	np_key_t* table[__MAX_ROW * __MAX_COL * __MAX_ENTRY];

    np_pll_t(np_key_ptr, left_leafset);
	np_pll_t(np_key_ptr, right_leafset);

    np_dhkey_t Rrange;
    np_dhkey_t Lrange;
};

static np_routeglobal_t* __routing_table;

_NP_MODULE_LOCK_IMPL(np_routeglobal_t);

void _np_append_leafset_to_sll(np_key_ptr_pll_t* left_leafset, np_sll_t(np_key_t, result));

void leafset_range_update (np_dhkey_t* rrange, np_dhkey_t* lrange);


/* route_init:
 * Ininitiates routing table and leafsets
 */
np_bool _np_route_init (np_key_t* me)
{
	__routing_table = (np_routeglobal_t *) malloc (sizeof (np_routeglobal_t));
    if (NULL == __routing_table) return FALSE;

    __routing_table->my_key = me;
    np_ref_obj(np_key_t, __routing_table->my_key);

    /* initialize memory for routing table */
    uint16_t i, j, k;
    for (i = 0; i < __MAX_ROW; i++)
	{
	    for (j = 0; j < __MAX_COL; j++)
		{
	    	int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
		    for (k = 0; k < __MAX_ENTRY; k++)
		    {
		    	// log_msg(LOG_ROUTING | LOG_DEBUG, "init routes->table[%d]", index + k);
		    	__routing_table->table[index + k] = NULL;
		    }
		}
	}

    // _dhkey_assign (&__routing_table->Rrange, &me->dhkey );
    // _dhkey_assign (&__routing_table->Lrange, &me->dhkey );
    np_dhkey_t half = dhkey_half();
    _dhkey_add(&__routing_table->Rrange, &me->dhkey, &half);
    _dhkey_sub(&__routing_table->Lrange, &me->dhkey, &half);

    pll_init(np_key_ptr,__routing_table->left_leafset);
    pll_init(np_key_ptr,__routing_table->right_leafset);

    return TRUE;
}

void _np_route_set_key (np_key_t* new_node_key)
{
	np_unref_obj(np_key_t, __routing_table->my_key);
    __routing_table->my_key = new_node_key;
    np_ref_obj(np_key_t, __routing_table->my_key);

    _dhkey_assign (&__routing_table->Rrange, &__routing_table->my_key->dhkey );
    _dhkey_assign (&__routing_table->Lrange, &__routing_table->my_key->dhkey );

    // TODO: re-order table entries and leafset table
    np_sll_t(np_key_t, tmp_key_list) = NULL;
	np_key_t *tmp_key = NULL;
	np_key_t *added = NULL, *deleted = NULL;

	// get list of keys
	tmp_key_list = _np_route_get_table();

	// wipe out old table
    for (int i = 0; i < __MAX_ROW; i++)
	{
	    for (int j = 0; j < __MAX_COL; j++)
		{
	    	int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
		    for (int k = 0; k < __MAX_ENTRY; k++)
		    {
		    	// log_msg(LOG_ROUTING | LOG_DEBUG, "init routes->table[%d]", index + k);
		    	__routing_table->table[index + k] = NULL;
		    }
		}
	}
    // re-add all entries, unref replaced or not added keys ?
    while (NULL != (tmp_key = sll_head(np_key_t, tmp_key_list)))
	{
		// route_update(tmp_key, TRUE, &added, &deleted);
		// if (added == NULL)
		// {
		np_unref_obj(np_key_t, tmp_key);
		// }
//		if (deleted != NULL)
//		{
//			np_unref_obj(np_key_t, deleted);
//			deleted = NULL;
//		}
	}
    sll_free(np_key_t, tmp_key_list);

    // get list of neighbours
	tmp_key_list = route_neighbors();

	// wipe out all entries
	pll_clear(np_key_ptr,__routing_table->left_leafset);
	pll_clear(np_key_ptr,__routing_table->right_leafset);

    // add all entries, unref replaced or not added keys
	deleted = NULL;
    while (NULL != (tmp_key = sll_head(np_key_t, tmp_key_list)))
	{
		leafset_update(tmp_key, TRUE, &added, &deleted);
		if (added == NULL)
		{
			np_unref_obj(np_key_t, tmp_key);
		}
		if (deleted != NULL)
		{
			np_unref_obj(np_key_t, deleted);
			deleted = NULL;
		}
	}
    sll_free(np_key_t, tmp_key_list);
}

/** route_get_table:
 ** return the entire routing table
 */
sll_return(np_key_t) _np_route_get_table ()
{
    uint16_t i, j, k;

	np_sll_t(np_key_t, sll_of_keys);
	sll_init(np_key_t, sll_of_keys);

    for (i = 0; i < __MAX_ROW; i++)
    {
    	for (j = 0; j < __MAX_COL; j++)
    	{
	    	int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
    		for (k = 0; k < __MAX_ENTRY; k++)
    		{
    			if (NULL != __routing_table->table[index + k])
    			{
    				sll_append(np_key_t, sll_of_keys, __routing_table->table[index + k]);
    		    	log_msg(LOG_ROUTING | LOG_DEBUG, "added to routes->table[%d]", index+k);
    			}
    		}
    	}
    }

    return sll_of_keys;
}

/** route_row_lookup:key
 ** return the row in the routing table that matches the longest prefix with #key#
 **/
sll_return(np_key_t) route_row_lookup (np_key_t* key)
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.route_row_lookup");
    uint16_t i, j, k;

	np_sll_t(np_key_t, sll_of_keys);
	sll_init(np_key_t, sll_of_keys);

    i = _dhkey_index (&__routing_table->my_key->dhkey, &key->dhkey);

	for (j = 0; j < __MAX_COL; j++)
	{
    	int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
		for (k = 0; k < __MAX_ENTRY; k++)
		{
			if (__routing_table->table[index + k] != NULL &&
				!_dhkey_equal(&__routing_table->table[index + k]->dhkey, &key->dhkey) )
			{
				sll_append(np_key_t, sll_of_keys, __routing_table->table[index + k]);
			}
		}
	}

	sll_append(np_key_t, sll_of_keys, __routing_table->my_key);

	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_row_lookup");
    return sll_of_keys;
}

void _np_append_leafset_to_sll(np_key_ptr_pll_t* leafset, np_sll_t(np_key_t, result)  ) {

    pll_iterator(np_key_ptr) iter = pll_first(leafset);

	while(iter != NULL) {
		if(iter->val != NULL) {
			log_msg (LOG_ROUTING | LOG_DEBUG, "Leafset: (%s)", _key_as_str (iter->val));
			sll_append(np_key_t, result, iter->val);
		}
		pll_next(iter);
	}
}
/** route_lookup:
 ** returns an array of #count# keys that are acceptable next hops for a
 ** message being routed to #key#.
 */
sll_return(np_key_t) route_lookup (np_key_t* key, uint8_t count)
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.route_lookup");
    uint32_t i, j, k, Lsize, Rsize;
    uint8_t match_col = 0;
    np_bool next_hop = FALSE;

    np_dhkey_t dif1, dif2;
    np_key_t *tmp_1 = NULL, *tmp_2 = NULL, *min = NULL;

    np_sll_t(np_key_t, return_list);
    sll_init(np_key_t, return_list);

    np_sll_t(np_key_t, key_list);
    sll_init(np_key_t, key_list);

	log_msg(
      LOG_ROUTING | LOG_DEBUG, "%s is looking for key %s !",
	  _key_as_str(__routing_table->my_key), _key_as_str(key));

    /*calculate the leafset and table size */

    Lsize = pll_size(__routing_table->left_leafset);
    Rsize = pll_size(__routing_table->right_leafset);

    /* if the key is in the leafset range route through leafset */
    /* the additional 2 neuropil nodes pointed by the #hosts# are to consider the node itself and NULL at the end */
    if (count == 1 &&
    	_dhkey_between (&key->dhkey, &__routing_table->Lrange, &__routing_table->Rrange))
	{
    	log_msg (LOG_ROUTING | LOG_DEBUG, "routing through leafset");
	    sll_append(np_key_t, key_list, __routing_table->my_key);

	    log_msg (LOG_ROUTING | LOG_DEBUG, "ME: (%s)", _key_as_str (__routing_table->my_key));

	    _np_append_leafset_to_sll(__routing_table->left_leafset, key_list);
	    _np_append_leafset_to_sll(__routing_table->right_leafset, key_list);

	    min = _np_find_closest_key (key_list, &key->dhkey);

	    sll_append(np_key_t, return_list, min);
	    sll_free (np_key_t, key_list);

	    log_msg (LOG_ROUTING | LOG_DEBUG, "++NEXT_HOP = %s", _key_as_str (min));

		log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_lookup");
	    return (return_list);
	}

    /* check to see if there is a matching next hop (for fast routing) */
    i = _dhkey_index (&__routing_table->my_key->dhkey, &key->dhkey);
    match_col = _dhkey_hexalpha_at (&key->dhkey, i);

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
		    	 !_dhkey_equal(&__routing_table->table[index + k]->dhkey, &tmp_1->dhkey) )
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

    	sll_append(np_key_t, return_list, tmp_1);

    	log_msg (LOG_ROUTING | LOG_DEBUG, "Routing through Table(%s), NEXT_HOP=%s",
			   _key_as_str (__routing_table->my_key),
			   _key_as_str (tmp_1) );

	    sll_free (np_key_t, key_list);
    	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_lookup");
	    return (return_list);
	}

    /* if there is no matching next hop we have to find the best next hop */
    /* brute force method to solve count requirements */

    // log_msg (LOG_ROUTING, "Routing to next closest key I know of:");
    /* look left */

    _np_append_leafset_to_sll(__routing_table->left_leafset, key_list);
    _np_append_leafset_to_sll(__routing_table->right_leafset, key_list);

    if (count == 0) {
    	// consider that this node could be the target as well
    	log_msg (LOG_ROUTING | LOG_DEBUG, "+me: (%s)",
    			/* leaf->dns_name, leaf->port,*/ _key_as_str (__routing_table->my_key) );
    	sll_append(np_key_t, key_list, __routing_table->my_key);
    }

    /* find the longest prefix match */
    i = _dhkey_index (&__routing_table->my_key->dhkey, &key->dhkey);
    for (j = 0; j < __MAX_COL; j++)
    {
    	int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
    	for (k = 0; k < __MAX_ENTRY; k++)
    	{
    		if (__routing_table->table[index + k] != NULL)
    		{
    			tmp_1 = __routing_table->table[index + k];
				if (tmp_1->node->success_avg > BAD_LINK)
				{
				    sll_append(np_key_t, key_list, tmp_1);
					log_msg (LOG_ROUTING | LOG_DEBUG, "+Table[%ul][%ul][%ul]: (%s)",
										  i, j, k, /* leaf->dns_name, leaf->port, */ _key_as_str (tmp_1));
				}
			}
    	}
    }

	if (count == 1)
	{
	    // printf ("route.c (%d): route_lookup bounce count==1 ...\n", getpid());
	    // printTable(state);
		min = _np_find_closest_key (key_list, &key->dhkey);
	    if (NULL != min) sll_append(np_key_t, return_list, min);
	}
	else
	{
		if (2 <= key_list->size)
		{
			_np_sort_keys_cpm (key_list, &key->dhkey);
			/* find the best #count# entries that we looked at ... could be much better */
			/* removing duplicates from the list */
			uint16_t i = j = 0;
			sll_iterator(np_key_t) iter1 = sll_first(key_list);
			sll_iterator(np_key_t) iter2 = sll_first(key_list);
			do {
				log_msg (LOG_ROUTING | LOG_DEBUG, "++Result[%hd]: (%s)", i, _key_as_str (iter1->val) );
				sll_append(np_key_t, return_list, iter1->val);

				while (NULL != iter2 && _dhkey_equal (&iter2->val->dhkey, &iter1->val->dhkey ))
				{
					sll_next(iter2);
					continue;
				}

				iter1 = iter2;
				i++;

			} while (i < count && NULL != iter1);
		}
	}

    /*  to prevent bouncing */
    if (count == 1 && sll_size(return_list) > 0)
	{
//	    log_msg(LOG_DEBUG, "route_lookup bounce detection ...");
//	    log_msg(LOG_DEBUG, "search key: %s", _key_as_str(key) );
//	    log_msg(LOG_DEBUG, "my own key: %s", _key_as_str(routes->my_key) );
//	    log_msg(LOG_DEBUG, "lookup key: %s", _key_as_str(sll_first(return_list)->val) );

	    _dhkey_distance (&dif1, &key->dhkey, &sll_first(return_list)->val->dhkey);
	    _dhkey_distance (&dif2, &key->dhkey, &__routing_table->my_key->dhkey);

	    // printTable(rg);

	    // if (key_equal (dif1, dif2)) ret[0] = rg->me;
	    // changed on 03.06.2014 STSW choose the closest neighbour
	    if (_dhkey_comp (&dif1, &dif2) <= 0) sll_first(return_list)->val = __routing_table->my_key;

	    log_msg(LOG_ROUTING | LOG_DEBUG, "route  key: %s", _key_as_str(sll_first(return_list)->val));

	    // if (!key_comp(&dif1, &dif2) == 0) ret[0] = rg->me;
	    // if (key_comp(&dif1, &dif2)  < 0) ret[0] = NULL;
	    // if (key_comp(&dif1, &dif2)  > 0) ret[0] = rg->me;

	} else {
	    log_msg (LOG_ROUTING | LOG_DEBUG, "route_lookup bounce detection not wanted ...");
	}

    sll_free (np_key_t, key_list);

    log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_lookup");
    return (return_list);
}


/**
 ** leafset_range_update:
 ** updates the leafset range whenever a node leaves or joins to the leafset
 **
 ** fills rrange and lrange with the outer bounds of our leafset
 */
void _np_leafset_range_update ()
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.leafset_range_update");

    pll_iterator(np_key_ptr) item = pll_last(__routing_table->right_leafset);

    if(item != NULL) {
    	_dhkey_assign (&__routing_table->Rrange, &item->val->dhkey);
    } else {
    	_dhkey_assign (&__routing_table->Rrange, &__routing_table->my_key->dhkey);
    }

    item = pll_last(__routing_table->left_leafset);
    if(item != NULL) {
    	_dhkey_assign (&__routing_table->Lrange, &item->val->dhkey);
    } else {
    	_dhkey_assign (&__routing_table->Lrange, &__routing_table->my_key->dhkey);
    }

	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .leafset_range_update");
}


/**
 ** leafset_update:
 ** this function is called whenever a route_update is called the joined
 ** is 1 if the node has joined and 0 if a node is leaving.
 **/
void leafset_update (np_key_t* node_key, np_bool joined, np_key_t** deleted, np_key_t** added)
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.leafset_update");

	np_key_ptr update_key =(np_key_ptr) node_key;
	*added = NULL;
	*deleted = NULL;

	np_key_ptr find_right = pll_find(np_key_ptr, __routing_table->right_leafset, node_key, _np_key_cmp);
	np_key_ptr find_left  = pll_find(np_key_ptr, __routing_table->left_leafset, update_key, _np_key_cmp_inv);

	if(FALSE == joined) {

		if(NULL != find_right ) {
			*deleted = (np_key_t*)update_key;
			pll_remove(np_key_ptr, __routing_table->right_leafset, update_key, _np_key_cmp);

		} else if (NULL != find_left ) {
			*deleted = (np_key_t*)update_key;
			pll_remove(np_key_ptr, __routing_table->left_leafset, update_key, _np_key_cmp_inv);
		} else {
			log_msg (LOG_ROUTING | LOG_DEBUG, "leafset did not change as key was not found");
		}

	}else{

		if(NULL != find_right || NULL != find_left ){
			log_msg (LOG_ROUTING | LOG_DEBUG, "leafset did not change as key was already in leafset");

		} else {
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

			// positive assumption that we will add this entry
			*added = update_key;

			np_dhkey_t my_inverse_dhkey;
			np_dhkey_t dhkey_half_o = dhkey_half();
			_dhkey_add(&my_inverse_dhkey,&__routing_table->my_key->dhkey,&dhkey_half_o);

			if(
				_dhkey_between (&node_key->dhkey, &__routing_table->my_key->dhkey, &my_inverse_dhkey) &&
				(
						__LEAFSET_SIZE > pll_size(__routing_table->right_leafset) ||
						 _dhkey_between (&node_key->dhkey, &__routing_table->my_key->dhkey, &right_outer->val->dhkey)
				)
			  ) {
					pll_insert(np_key_ptr, __routing_table->right_leafset, update_key, FALSE, _np_key_cmp);

			}
			else
			if(
					_dhkey_between (&node_key->dhkey, &my_inverse_dhkey, &__routing_table->my_key->dhkey) &&
					(
							__LEAFSET_SIZE > pll_size(__routing_table->left_leafset) ||
							 _dhkey_between (&node_key->dhkey, &left_outer->val->dhkey, &__routing_table->my_key->dhkey)
					)
			  ) {
				pll_insert(np_key_ptr, __routing_table->left_leafset, update_key, FALSE, _np_key_cmp_inv);
			}
			else
			{	// Neither the lefsets are empty nor is the new key between our known outer bounds
				*added = NULL; // assumption was faulty
				log_msg(LOG_ROUTING | LOG_DEBUG, "not adding key to leafset ...");
			}

			// Cleanup of leafset / resize leafsets to max size if necessary
			if(__LEAFSET_SIZE < pll_size(__routing_table->left_leafset)) {
				*deleted = pll_tail(np_key_ptr,__routing_table->left_leafset);
			}
			else if(__LEAFSET_SIZE < pll_size(__routing_table->right_leafset)) {
				*deleted = pll_tail(np_key_ptr,__routing_table->left_leafset);
			}
		}
	}

	// TODO: handle it via add a new async update job instead ?
	if (*deleted != NULL || *added != NULL)
	{
		_np_leafset_range_update();
	}

	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .leafset_update");
}

/** route_neighbors:
 ** returns an array of #count# neighbor nodes with priority to closer nodes
 **/
sll_return(np_key_t) route_neighbors ()
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.route_neighbors");

    np_sll_t(np_key_t, node_keys);
    sll_init(np_key_t, node_keys);

    _np_append_leafset_to_sll(__routing_table->left_leafset, node_keys);
    _np_append_leafset_to_sll(__routing_table->right_leafset, node_keys);

    /* sort aux */
    _np_sort_keys_kd(node_keys, &__routing_table->my_key->dhkey);

	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_neighbors");
    return node_keys;
}

/** route_update:
 ** updated the routing table in regard to #node#. If the host is joining
 ** the network (and #joined# == 1), then it is added to the routing table
 ** if it is appropriate. If it is leaving the network (and #joined# == 0),
 ** then it is removed from the routing tables
 **/
void route_update (np_key_t* key, np_bool joined, np_key_t** deleted, np_key_t** added)
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.route_update");
	log_msg(LOG_ROUTING | LOG_INFO, "update in routing: %u %s", joined, _key_as_str(key));

    uint16_t i, j, k, found, pick;

    if (_dhkey_equal (&__routing_table->my_key->dhkey, &key->dhkey))
	{
    	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_update");
	    return;
	}
    *added = NULL;
    *deleted = NULL;

    i = _dhkey_index (&__routing_table->my_key->dhkey, &key->dhkey);
    j = _dhkey_hexalpha_at (&key->dhkey, i);

	int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));

    /* a node joins the routing table */
    if (TRUE == joined)
	{
	    found = 0;
    	for (k = 0; k < __MAX_ENTRY; k++)
		{
	    	if (__routing_table->table[index + k] != NULL &&
	    		_dhkey_equal (&__routing_table->table[index + k]->dhkey, &key->dhkey))
	    	{
	    		found = 0;
	    		break;
	    	}

	    	if (__routing_table->table[index + k] == NULL)
			{
		    	__routing_table->table[index + k] = key;
			    found = 0;
			    *added   = key;
		    	log_msg(LOG_ROUTING | LOG_DEBUG, "added to routes->table[%d]", index+k);
			    break;
			}
		    else if (__routing_table->table[index + k] != NULL &&
 		    		 !_dhkey_equal (&__routing_table->table[index + k]->dhkey, &key->dhkey ))
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

		    	log_msg(LOG_ROUTING | LOG_DEBUG, "replace latencies at index %d: t..%f > p..%f ?",
		    			index, tmp_node->node->latency, pick_node->node->latency);

		    	if (tmp_node->node->latency > pick_node->node->latency  )
		    	{
		    		pick = k;
		    	}
		    }
		    *deleted = __routing_table->table[index + pick];
	    	log_msg(LOG_ROUTING | LOG_DEBUG, "replaced to routes->table[%d]", index+pick);
			__routing_table->table[index + pick] = key;
		    *added = __routing_table->table[index + pick];
		}
	}
    else
    {
		/* delete a node from the routing table */
	    for (k = 0; k < __MAX_ENTRY; k++)
	    {
	    	if (__routing_table->table[index + k] != NULL &&
	    		_dhkey_equal (&__routing_table->table[index + k]->dhkey, &key->dhkey) )
	    	{
	    		*deleted = key;
	    		__routing_table->table[index + k] = NULL;
		    	log_msg(LOG_ROUTING | LOG_DEBUG, "deleted to routes->table[%d]", index+k);
	    		break;
	    	}
	    }
	}
	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .route_update");
}
