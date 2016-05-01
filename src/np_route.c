/**
 *  neuropil - copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "np_route.h"

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

typedef struct np_routeglobal_s np_routeglobal_t;
struct np_routeglobal_s
{
	np_key_t* my_key;

    np_key_t* table[__MAX_ROW * __MAX_COL * __MAX_ENTRY];
    np_key_t* left_leafset[__LEAFSET_SIZE];
    np_key_t* right_leafset[__LEAFSET_SIZE];

    np_dhkey_t Rrange;
    np_dhkey_t Lrange;
};

static np_routeglobal_t* __routing_table;

_NP_MODULE_LOCK_IMPL(np_routeglobal_t);

uint16_t leafset_size (np_key_t* arr[__LEAFSET_SIZE]);

// void leafset_update (np_routeglobal_t* rg, np_node_t* host, np_bool joined, np_node_t* deleted, np_node_t** added);
void leafset_insert (np_key_t* host, uint8_t right_or_left, np_key_t** deleted, np_key_t** added);
void leafset_delete (np_key_t* host, uint8_t right_or_left, np_key_t** deleted);

void leafset_print ();
void leafset_range_update (np_dhkey_t* rrange, np_dhkey_t* lrange);

int8_t hexalpha_to_int (int8_t c);


/* route_init:
 * Ininitiates routing table and leafsets
 */
np_bool _np_route_init (np_key_t* me)
{
    __routing_table = (np_routeglobal_t *) malloc (sizeof (np_routeglobal_t));
    if (NULL == __routing_table) return FALSE;

    __routing_table->my_key = me;

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

    _dhkey_assign (&__routing_table->Rrange, &me->dhkey );
    _dhkey_assign (&__routing_table->Lrange, &me->dhkey );

    for (i = 0; i < (__LEAFSET_SIZE / 2) + 1; i++)
	{
    	__routing_table->left_leafset[i]  = NULL;
    	__routing_table->right_leafset[i] = NULL;
	}

    return TRUE;
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

/** route_lookup:
 ** returns an array of #count# keys that are acceptable next hops for a
 ** message being routed to #key#. #is_save# is ignored for now.
 */
sll_return(np_key_t) route_lookup (np_key_t* key, uint8_t count)
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.route_lookup");
    uint16_t i, j, k, Lsize, Rsize;
    uint8_t match_col = 0;
    np_bool next_hop = FALSE;

    np_dhkey_t dif1, dif2;
    np_key_t *leaf, *tmp_1 = NULL, *tmp_2 = NULL, *min = NULL;

    np_sll_t(np_key_t, return_list);
    sll_init(np_key_t, return_list);

    np_sll_t(np_key_t, key_list);
    sll_init(np_key_t, key_list);

	log_msg(
      LOG_ROUTING | LOG_DEBUG, "%s is looking for key %s !",
	  _key_as_str(__routing_table->my_key), _key_as_str(key));

    /*calculate the leafset and table size */
    Lsize = leafset_size (__routing_table->left_leafset);
    Rsize = leafset_size (__routing_table->right_leafset);

    /* if the key is in the leafset range route through leafset */
    /* the additional 2 neuropil nodes pointed by the #hosts# are to consider the node itself and NULL at the end */
    if (count == 1 &&
    	_dhkey_between (&key->dhkey, &__routing_table->Lrange, &__routing_table->Rrange))
	{
    	log_msg (LOG_ROUTING | LOG_DEBUG, "routing through leafset");
	    sll_append(np_key_t, key_list, __routing_table->my_key);

	    log_msg (LOG_ROUTING | LOG_DEBUG, "ME: (%s)", _key_as_str (__routing_table->my_key));

	    /* look left */
	    for (i = 0; i < Lsize; i++)
		{
		    leaf = __routing_table->left_leafset[i];
		    log_msg (LOG_ROUTING | LOG_DEBUG, "Left_leafset[%hd]: (%s)",
		    		i, _key_as_str (leaf));
		    sll_append(np_key_t, key_list, leaf);
		}
	    /* look right */
	    for (i = 0; i < Rsize; i++)
		{
		    leaf = __routing_table->right_leafset[i];
		    log_msg (LOG_ROUTING | LOG_DEBUG, "Right_leafset[%hd]: (%s)",
		    		 i, _key_as_str (leaf));
		    sll_append(np_key_t, key_list, leaf);
		}

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
    for (uint16_t l = 0; l < Lsize; l++)
	{
	    leaf = __routing_table->left_leafset[l];
	    log_msg (LOG_ROUTING | LOG_DEBUG, "+left_leafset[%hd]: (%s)",
	    		 l, /* leaf->dns_name, leaf->port,*/ _key_as_str (key));
	    sll_append(np_key_t, key_list, leaf);
	}
    /* look right */
    for (uint16_t r = 0; r < Rsize; r++)
	{
	    leaf = __routing_table->right_leafset[r];
	    log_msg (LOG_ROUTING | LOG_DEBUG, "+right_leafset[%hd]: (%s)",
	    		 r, /* leaf->dns_name, leaf->port,*/ _key_as_str (leaf));
	    sll_append(np_key_t, key_list, leaf);
	}

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
					log_msg (LOG_ROUTING | LOG_DEBUG, "+Table[%hd][%hd][%hd]: (%s)",
										  i, j, k, /* leaf->dns_name, leaf->port, */ _key_as_str (leaf));
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

uint16_t leafset_size (np_key_t* arr[__LEAFSET_SIZE])
{
    uint16_t i = 0;
    for (i = 0; arr[i] != NULL; i++);
    return i;
}

/**
 ** leafset_range_update:
 ** updates the leafset range whenever a node leaves or joins to the leafset
 **
 */
void leafset_range_update (np_dhkey_t* rrange, np_dhkey_t* lrange)
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.leafset_range_update");
    uint16_t i;

    /* right range */
    for (i = 0; __routing_table->right_leafset[i] != NULL; i++)
    	_dhkey_assign (rrange, &__routing_table->right_leafset[i]->dhkey);

    if (i == 0)
    	_dhkey_assign (rrange, &__routing_table->my_key->dhkey);

    /* left range */
    for (i = 0; __routing_table->left_leafset[i] != NULL; i++)
    	_dhkey_assign (lrange, &__routing_table->left_leafset[i]->dhkey);

    if (i == 0)
    	_dhkey_assign (lrange, &__routing_table->my_key->dhkey);

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
    uint16_t Lsize = 0;
    uint16_t Rsize = 0;
    np_dhkey_t midpoint;

    *added = NULL;
    *deleted = NULL;

    Lsize = leafset_size (__routing_table->left_leafset);
    Rsize = leafset_size (__routing_table->right_leafset);

    _dhkey_midpoint (&midpoint, &__routing_table->my_key->dhkey);

    if (TRUE == joined)
	{
		/* key falls in the right side of node */
		if (Rsize < __LEAFSET_SIZE / 2 ||
			_dhkey_between (
					&node_key->dhkey,
					&__routing_table->my_key->dhkey,
					&__routing_table->right_leafset[Rsize-1]->dhkey ))
		{	/* insert in Right leafset */
			leafset_insert (node_key, 1, deleted, added);
		}
		/* key falls in the left side of the node */
		if (Lsize < __LEAFSET_SIZE / 2 ||
			_dhkey_between (
					&node_key->dhkey,
					&__routing_table->left_leafset[Lsize-1]->dhkey,
					&__routing_table->my_key->dhkey))
		{	/* insert in Left leafset */
			leafset_insert (node_key, 0, deleted, added);
		}
	}
    else
	{
		/* key falls in the right side of node */
		if (Rsize < __LEAFSET_SIZE / 2 ||
			_dhkey_between (
					&node_key->dhkey,
					&__routing_table->my_key->dhkey,
					&__routing_table->right_leafset[Rsize-1]->dhkey ))
		{
			leafset_delete (node_key, 1, deleted);
		}
		if (Lsize < __LEAFSET_SIZE / 2 ||
			_dhkey_between (
					&node_key->dhkey,
					&__routing_table->left_leafset[Lsize-1]->dhkey,
					&__routing_table->my_key->dhkey) )
		{
			leafset_delete (node_key, 0, deleted);
		}
	}

    // TODO: handle it via add a new async update job instead ?
    if (*deleted != NULL)
	{
	    leafset_range_update (&(__routing_table->Rrange), &(__routing_table->Lrange));
	}
    if (*added != NULL)
	{
	    leafset_range_update (&(__routing_table->Rrange), &(__routing_table->Lrange));
	}
	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .leafset_update");
}

/** 
 ** leafset_delete:
 ** removes the #deleted# node from leafset
 **
 */
void leafset_delete (np_key_t* node_key, uint8_t right_or_left, np_key_t** deleted)
{
    uint16_t i = 0, size;
    uint16_t match = 0;
    // np_key_t* node_key;
    np_key_t** p;

    if (right_or_left == 1) /* insert in right leafset */
	{
	    size = leafset_size (__routing_table->right_leafset);
	    p = __routing_table->right_leafset;
	}
    else /*insert in left leafset */
	{
	    size = leafset_size (__routing_table->left_leafset);
	    p = __routing_table->left_leafset;
	}

    for (i = 0; i < size && !(_dhkey_equal (&p[i]->dhkey, &node_key->dhkey )); i++);

    if (i < size)
	{
	    *deleted = p[i];
	    match = 1;
	}

    /* shift leafset members to not have a hole in the leafset */
    if (match)
	{
	    do {
		    p[i] = p[i + 1];
		    i++;
		} while (i < size - 1);
	    p[i] = NULL;
	}
}

/**
 ** leafset_insert:
 ** inserts the added node to the leafset and removes the deleted from the leafset
 ** the deleted node is NULL if the new added node will not cause a node to leave the leafset.
 */
void leafset_insert (np_key_t* host_key, uint8_t right_or_left,
					 np_key_t** deleted, np_key_t** added)
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.leafset_insert");

    uint16_t i = 0, size;
    np_key_t **p;
    np_key_t *tmp1, *tmp2;
    np_key_t *input = host_key;

    if (right_or_left == 1) // insert in right leafset
	{
	    size = leafset_size (__routing_table->right_leafset);
	    p = __routing_table->right_leafset;
	}
    else // insert in left leafset
	{
	    size = leafset_size (__routing_table->left_leafset);
	    p = __routing_table->left_leafset;
	}

    if (size == 0)
	{
	    p[0] = input;
	    *added = input;
	}
    else
	{
    	uint16_t foundKeyPos = 0;
		// check other indexes
        while (i < size)
		{
        	// check current index
            if (_dhkey_equal (&p[i]->dhkey, &input->dhkey))
			{
			    return;
			}

            if (foundKeyPos) break;
            else i++;

            if (i < size)
			{
				if (right_or_left == 1)
				{
                    foundKeyPos = _dhkey_between(
                    		&input->dhkey,
                    		&__routing_table->my_key->dhkey,
                    		&p[i]->dhkey);
				}
				else
				{
                    foundKeyPos = _dhkey_between(
                    		&input->dhkey,
							&p[i]->dhkey,
							&__routing_table->my_key->dhkey);
				}
			}
		}

        tmp1 = input;
        *added = input;

        while (i < __LEAFSET_SIZE / 2)
        {
        	tmp2 = p[i];
        	p[i] = tmp1;
        	tmp1 = tmp2;
        	i++;
	    }
        /* there is a leftover */
        if (tmp2 != NULL && size == __LEAFSET_SIZE / 2) {
        	*deleted = tmp2;
	    }
	}
	log_msg(LOG_ROUTING | LOG_TRACE, ".end  .leafset_insert");
}

/** route_neighbors: 
 ** returns an array of #count# neighbor nodes with priority to closer nodes
 **/
sll_return(np_key_t) route_neighbors ()
{
	log_msg(LOG_ROUTING | LOG_TRACE, ".start.route_neighbors");

    uint8_t i = 0, Rsize = 0, Lsize = 0;

    np_sll_t(np_key_t, node_keys);
    sll_init(np_key_t, node_keys);

    Lsize = leafset_size (__routing_table->left_leafset);
    Rsize = leafset_size (__routing_table->right_leafset);

    /* create a jrb of leafset pointers sorted on distance */
    for (i = 0; i < Lsize; i++)
	{
    	sll_append(np_key_t, node_keys, __routing_table->left_leafset[i]);
	}

    for (i = 0; i < Rsize; i++)
	{
    	sll_append(np_key_t, node_keys, __routing_table->right_leafset[i]);
	}

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
	    		_dhkey_equal (&__routing_table->table[index + k]->dhkey, &key->dhkey)) {
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

		    	if (tmp_node->node->latency > pick_node->node->latency  ) {
		    		pick = k;
		    	}
		    }
		    *deleted = __routing_table->table[index + pick];
	    	log_msg(LOG_ROUTING | LOG_DEBUG, "replaced to routes->table[%d]", index+pick);
			__routing_table->table[index + pick] = key;
		    *added = __routing_table->table[index + pick];
		}

	} else {

		/* delete a node from the routing table */
	    for (k = 0; k < __MAX_ENTRY; k++) {

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

int8_t hexalpha_to_int (int8_t c)
{
    static char hexalpha[] = "0123456789abcdef";
    int8_t i;
    int8_t answer = 0;

    for (i = 0; answer == 0 && hexalpha[i] != '\0'; i++)
	{
	    if (hexalpha[i] == c)
		{
		    answer = i;
		}
	}
    return answer;
}

void leafset_print ()
{
	uint16_t i;
    uint16_t Lsize, Rsize;

    log_msg(LOG_ROUTING | LOG_DEBUG, "LEAFSET LEFT:");
    Lsize = leafset_size (__routing_table->left_leafset);
    for (i = 0; i < Lsize; i++)
    	log_msg(LOG_ROUTING | LOG_DEBUG, "%s", _key_as_str (__routing_table->left_leafset[i] ));

    log_msg(LOG_ROUTING | LOG_DEBUG, "LEAFSET RIGHT:");
    Rsize = leafset_size (__routing_table->right_leafset);
    for (i = 0; i < Rsize; i++)
    	log_msg(LOG_ROUTING | LOG_DEBUG, "%s", _key_as_str (__routing_table->right_leafset[i] ));
}

void printTable ()
{
    uint16_t i, j, k;

    /* print the table */
    log_msg (LOG_ROUTING | LOG_DEBUG, "------------------------------- TABLE-------------------------------");
    for (i = 0; i < __MAX_ROW; i++)
	{
	    for (j = 0; j < __MAX_COL; j++)
		{
	    	int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
		    for (k = 0; k < __MAX_ENTRY; k++)
		    {
				if (__routing_table->table[index + k] != NULL)
				{
		    		log_msg(LOG_ROUTING | LOG_DEBUG,
		    				"[%hd][%hd][%hd] %s",
							i, j, k, _key_as_str (__routing_table->table[index + k]));
				}
		    }
		}
	}
    log_msg (LOG_ROUTING | LOG_DEBUG, "----------------------------------------------------------------------");
}
