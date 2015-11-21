/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "np_route.h"

#include "jval.h"
#include "log.h"
#include "np_container.h"
#include "np_list.h"
#include "np_memory.h"
#include "np_threads.h"
#include "np_node.h"

uint16_t leafset_size (np_key_t** arr);

// void leafset_update (np_routeglobal_t* rg, np_node_t* host, np_bool joined, np_node_t* deleted, np_node_t** added);
void leafset_insert (np_state_t* state, np_key_t* host, uint8_t right_or_left, np_key_t** deleted, np_key_t** added);
void leafset_delete (np_routeglobal_t* rg, np_key_t* host, uint8_t right_or_left, np_key_t** deleted);

void leafset_print (const np_routeglobal_t* rg);
void leafset_range_update (np_state_t* state, np_key_t* rrange, np_key_t* lrange);

int8_t hexalpha_to_int (int8_t c);


/* route_init:
 * Ininitiates routing table and leafsets
 */
np_routeglobal_t* route_init (np_key_t* me)
{
    uint16_t i, j, k;
    np_routeglobal_t *rg = (np_routeglobal_t *) malloc (sizeof (struct np_routeglobal_t));

    /* allocate memory for routing table */
    rg->table = (np_key_t ****) malloc (sizeof (np_key_t ***) * MAX_ROW);
    for (i = 0; i < MAX_ROW; i++)
	{
	    rg->table[i] = (np_key_t ***) malloc (sizeof (np_key_t **) * MAX_COL);
	    for (j = 0; j < MAX_COL; j++)
		{
		    rg->table[i][j] = (np_key_t **) malloc (sizeof (np_key_t *) * MAX_ENTRY);
		    for (k = 0; k < MAX_ENTRY; k++)
		    	rg->table[i][j][k] = NULL;
		}
	}

    key_assign (&rg->Rrange, me );
    key_assign (&rg->Lrange, me );

    /* allocate memory for leafsets */
    rg->leftleafset  = (np_key_t **) malloc (sizeof (np_key_t *) * ((LEAFSET_SIZE / 2) + 1));
    rg->rightleafset = (np_key_t **) malloc (sizeof (np_key_t *) * ((LEAFSET_SIZE / 2) + 1));

    for (i = 0; i < (LEAFSET_SIZE / 2) + 1; i++)
	{
	    rg->leftleafset[i]  = NULL;
	    rg->rightleafset[i] = NULL;
	}

    pthread_mutex_init (&rg->lock, NULL);

    return rg;
}

/** route_get_table: 
 ** return the entire routing table
 */
sll_return(np_key_t) route_get_table (np_routeglobal_t* rg)
{
    uint16_t i, j, l;

	np_sll_t(np_key_t, sll_of_keys);
	sll_init(np_key_t, sll_of_keys);

	// pthread_mutex_lock (&rg->lock);
    for (i = 0; i < MAX_ROW; i++)
    	for (j = 0; j < MAX_COL; j++)
    		for (l = 0; l < MAX_ENTRY; l++)
    			if (rg->table[i][j][l] != NULL)
    			{
    				sll_append(np_key_t, sll_of_keys, rg->table[i][j][l]);
    				// np_node_lookup(rg->me->node_tree, np_node_get_key(rg->table[i][j][l]), 0);
    				// ret[k++] = np_node_get_by_hostname(rg->me->ng, rg->table[i][j][l]->dns_name, rg->table[i][j][l]->port);
    			}
    // pthread_mutex_unlock (&rg->lock);

    return sll_of_keys;
}

/** route_row_lookup:key 
 ** return the row in the routing table that matches the longest prefix with #key#
 **/
sll_return(np_key_t) route_row_lookup (np_state_t* state, np_key_t* key)
{
	log_msg(LOG_TRACE, ".start.route_row_lookup");
    uint16_t i, j, l;
	np_sll_t(np_key_t, sll_of_keys);
	sll_init(np_key_t, sll_of_keys);

    i = key_index (state->my_node_key, key);

    // pthread_mutex_lock (&state->routes->lock);

	for (j = 0; j < MAX_COL; j++)
	{
		for (l = 0; l < MAX_ENTRY; l++)
		{
			if (state->routes->table[i][j][l] != NULL &&
				!key_equal(state->routes->table[i][j][l], key) ) {
				sll_append(np_key_t, sll_of_keys, state->routes->table[i][j][l]);
			}
		}
	}
    // pthread_mutex_unlock (&state->routes->lock);
	sll_append(np_key_t, sll_of_keys, state->my_node_key);

	log_msg(LOG_TRACE, ".end  .route_row_lookup");
    return sll_of_keys;
}

/** route_lookup:
 ** returns an array of #count# keys that are acceptable next hops for a
 ** message being routed to #key#. #is_save# is ignored for now.
 */
sll_return(np_key_t) route_lookup (np_state_t* state, np_key_t* key, uint8_t count)
{
	log_msg(LOG_TRACE, ".start.route_lookup");
    uint16_t i, j, k, Lsize, Rsize;
    uint8_t match_col = 0;
    np_bool next_hop = FALSE;

    np_key_t dif1, dif2;
    np_key_t *leaf, *tmp_1 = NULL, *tmp_2 = NULL, *min = NULL;

    np_sll_t(np_key_t, return_list);
    sll_init(np_key_t, return_list);

    np_sll_t(np_key_t, key_list);
    sll_init(np_key_t, key_list);

	log_msg(
      LOG_ROUTING, "%s is looking for key %s !",
	  key_get_as_string(state->my_node_key), key_get_as_string(key));

	// pthread_mutex_lock (&state->routes->lock);

    /*calculate the leafset and table size */
    Lsize = leafset_size (state->routes->leftleafset);
    Rsize = leafset_size (state->routes->rightleafset);

    /* if the key is in the leafset range route through leafset */
    /* the additional 2 neuropil nodes pointed by the #hosts# are to consider the node itself and NULL at the end */
    if (count == 1 &&
    	key_between (key, &state->routes->Lrange, &state->routes->Rrange))
	{
    	log_msg (LOG_ROUTING, "routing through leafset");
	    sll_append(np_key_t, key_list, state->my_node_key);

	    log_msg (LOG_ROUTING, "ME: (%s)", key_get_as_string (state->my_node_key));

	    /* look left */
	    for (i = 0; i < Lsize; i++)
		{
		    leaf = state->routes->leftleafset[i];
		    log_msg (LOG_ROUTING, "Left_leafset[%hd]: (%s)",
		    		i, key_get_as_string (leaf));
		    sll_append(np_key_t, key_list, leaf);
		}
	    /* look right */
	    for (i = 0; i < Rsize; i++)
		{
		    leaf = state->routes->rightleafset[i];
		    log_msg (LOG_ROUTING, "Right_leafset[%hd]: (%s)",
		    		 i, key_get_as_string (leaf));
		    sll_append(np_key_t, key_list, leaf);
		}

	    min = find_closest_key (key_list, key);

	    sll_append(np_key_t, return_list, min);
	    sll_free (np_key_t, key_list);

	    log_msg (LOG_ROUTING, "++NEXT_HOP = %s", key_get_as_string (min));

		log_msg(LOG_TRACE, ".end  .route_lookup");
	    return (return_list);
	}

    /* check to see if there is a matching next hop (for fast routing) */
    i = key_index (state->my_node_key, key);
    match_col = hexalpha_to_int (key_get_as_string(key)[i]);

    for (k = 0; k < MAX_ENTRY; k++) {
    	if (state->routes->table[i][match_col][k] != NULL) {

    		tmp_1 = state->routes->table[i][match_col][k];
    		if (tmp_1->node->success_avg > BAD_LINK)
			{
				next_hop = TRUE;
				break;
			}
		}
    }

    if (TRUE == next_hop && 1 == count)
	{
    	for (k = 0; k < MAX_ENTRY; k++)
		{
		    if ( state->routes->table[i][match_col][k] != NULL &&
		    	 !key_equal(state->routes->table[i][match_col][k], tmp_1) )
		    {
		    	tmp_2 = state->routes->table[i][match_col][k];
		    	if ( (tmp_2->node->success_avg > tmp_1->node->success_avg  ||
		    		  tmp_2->node->success_avg == tmp_1->node->success_avg)
		    		&&
					  tmp_2->node->latency < tmp_1->node->latency )
		    	{
		    		tmp_1 = state->routes->table[i][match_col][k];
				}
		    }
		}

    	sll_append(np_key_t, return_list, tmp_1);

    	log_msg (LOG_ROUTING, "Routing through Table(%s), NEXT_HOP=%s",
			   key_get_as_string (state->my_node_key ),
			   key_get_as_string (tmp_1));

	    sll_free (np_key_t, key_list);
    	log_msg(LOG_TRACE, ".end  .route_lookup");
	    return (return_list);
	}

    /* if there is no matching next hop we have to find the best next hop */
    /* brute force method to solve count requirements */

    // log_msg (LOG_ROUTING, "Routing to next closest key I know of:");
    /* look left */
    for (uint16_t l = 0; l < Lsize; l++)
	{
	    leaf = state->routes->leftleafset[l];
	    log_msg (LOG_ROUTING, "+left_leafset[%hd]: (%s)",
	    		 l, /* leaf->dns_name, leaf->port,*/ key_get_as_string (key));
	    sll_append(np_key_t, key_list, leaf);
	}
    /* look right */
    for (uint16_t r = 0; r < Rsize; r++)
	{
	    leaf = state->routes->rightleafset[r];
	    log_msg (LOG_ROUTING, "+right_leafset[%hd]: (%s)",
	    		 r, /* leaf->dns_name, leaf->port,*/ key_get_as_string (leaf));
	    sll_append(np_key_t, key_list, leaf);
	}

    // leaf = state->my_node_key;
    log_msg (LOG_ROUTING, "+me: (%s)",
    		/* leaf->dns_name, leaf->port,*/ key_get_as_string (state->my_node_key) );
    sll_append(np_key_t, key_list, state->my_node_key);

    /* find the longest prefix match */
    i = key_index (state->my_node_key, key);

    for (j = 0; j < MAX_COL; j++) {
    	for (k = 0; k < MAX_ENTRY; k++) {
    		if (state->routes->table[i][j][k] != NULL) {

    			tmp_1 = state->routes->table[i][j][k];
				if (tmp_1->node->success_avg > BAD_LINK) {
				    sll_append(np_key_t, key_list, tmp_1);
					log_msg (LOG_ROUTING, "+Table[%hd][%hd][%hd]: (%s)",
										  i, j, k, /* leaf->dns_name, leaf->port, */ key_get_as_string (leaf));
				}
			}
    	}
    }

	if (count == 1)
	{
	    // printf ("route.c (%d): route_lookup bounce count==1 ...\n", getpid());
	    // printTable(state);
		min = find_closest_key (key_list, key);
	    sll_append(np_key_t, return_list, min);
	}
	else
	{
		sort_keys_cpm (key_list, key);

		/* find the best #count# entries that we looked at ... could be much better */
		/* removing duplicates from the list */
		uint16_t i = j = 0;
		sll_iterator(np_key_t) iter1 = sll_first(key_list);
		sll_iterator(np_key_t) iter2 = sll_first(key_list);
		do {
			log_msg (LOG_ROUTING, "++Result[%hd]: (%s)", i, key_get_as_string (iter1->val) );
			sll_append(np_key_t, return_list, iter1->val);

			while (NULL != iter2 && key_equal (iter2->val, iter1->val ))
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
//	    log_msg(LOG_DEBUG, "search key: %s", key_get_as_string(key) );
//	    log_msg(LOG_DEBUG, "my own key: %s", key_get_as_string(state->my_node_key) );
//	    log_msg(LOG_DEBUG, "lookup key: %s", key_get_as_string(sll_first(return_list)->val) );

	    key_distance (&dif1, key, sll_first(return_list)->val);
	    key_distance (&dif2, key, state->my_node_key);

	    // printTable(rg);

	    // if (key_equal (dif1, dif2)) ret[0] = rg->me;
	    // changed on 03.06.2014 STSW choose the closest neighbour
	    if (key_comp (&dif1, &dif2) <= 0) sll_first(return_list)->val = state->my_node_key;

	    log_msg(LOG_ROUTING, "route  key: %s", key_get_as_string(sll_first(return_list)->val));

	    // if (!key_comp(&dif1, &dif2) == 0) ret[0] = rg->me;
	    // if (key_comp(&dif1, &dif2)  < 0) ret[0] = NULL;
	    // if (key_comp(&dif1, &dif2)  > 0) ret[0] = rg->me;

	} else {
	    log_msg (LOG_ROUTING, "route_lookup bounce detection not wanted ...");
	}

    sll_free (np_key_t, key_list);
    // pthread_mutex_unlock (&state->routes->lock);

    log_msg(LOG_TRACE, ".end  .route_lookup");
    return (return_list);
}

uint16_t leafset_size (np_key_t** arr)
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
void leafset_range_update (np_state_t* state, np_key_t* rrange, np_key_t* lrange)
{
	log_msg(LOG_TRACE, ".start.leafset_range_update");
    uint16_t i;

    /* right range */
    for (i = 0; state->routes->rightleafset[i] != NULL; i++)
    	key_assign (rrange, state->routes->rightleafset[i]);

    if (i == 0)
    	key_assign (rrange, state->my_node_key);

    /* left range */
    for (i = 0; state->routes->leftleafset[i] != NULL; i++)
    	key_assign (lrange, state->routes->leftleafset[i]);

    if (i == 0)
    	key_assign (lrange, state->my_node_key);

	log_msg(LOG_TRACE, ".end  .leafset_range_update");
}


/**
 ** leafset_update:
 ** this function is called whenever a route_update is called the joined
 ** is 1 if the node has joined and 0 if a node is leaving. 
 **/
void leafset_update (np_state_t* state, np_key_t* node_key, np_bool joined, np_key_t** deleted, np_key_t** added)
{
	log_msg(LOG_TRACE, ".start.leafset_update");
    uint16_t Lsize = 0;
    uint16_t Rsize = 0;
    np_key_t midpoint;

    *added = NULL;
    *deleted = NULL;

    Lsize = leafset_size (state->routes->leftleafset);
    Rsize = leafset_size (state->routes->rightleafset);

    key_midpoint (&midpoint, state->my_node_key);

    if (TRUE == joined)
	{
		/* key falls in the right side of node */
		if (Rsize < LEAFSET_SIZE / 2 ||
			key_between (node_key, state->my_node_key, state->routes->rightleafset[Rsize-1] ))
		{	/* insert in Right leafset */
			leafset_insert (state, node_key, 1, deleted, added);
		}
		/* key falls in the left side of the node */
		if (Lsize < LEAFSET_SIZE / 2 ||
			key_between (node_key, state->routes->leftleafset[Lsize-1], state->my_node_key))
		{	/* insert in Left leafset */
			leafset_insert (state, node_key, 0, deleted, added);
		}
	}
    else
	{
		/* key falls in the right side of node */
		if (Rsize < LEAFSET_SIZE / 2 ||
			key_between (node_key, state->my_node_key, state->routes->rightleafset[Rsize-1] ))
		{
			leafset_delete (state->routes, node_key, 1, deleted);
		}
		if (Lsize < LEAFSET_SIZE / 2 ||
			key_between (node_key, state->routes->leftleafset[Lsize-1], state->my_node_key))
		{
			leafset_delete (state->routes, node_key, 0, deleted);
		}
	}

    // TODO: handle it via add a new async update job instead ?
    if (*deleted != NULL)
	{
	    leafset_range_update (state, &(state->routes->Rrange), &(state->routes->Lrange));
	}
    if (*added != NULL)
	{
	    leafset_range_update (state, &(state->routes->Rrange), &(state->routes->Lrange));
	}
	log_msg(LOG_TRACE, ".end  .leafset_update");
}

/** 
 ** leafset_delete:
 ** removes the #deleted# node from leafset
 **
 */
void leafset_delete (np_routeglobal_t* rg, np_key_t* node_key, uint8_t right_or_left, np_key_t** deleted)
{
    uint16_t i = 0, size;
    uint16_t match = 0;
    // np_key_t* node_key;
    np_key_t** p;

    if (right_or_left == 1) /* insert in right leafset */
	{
	    size = leafset_size (rg->rightleafset);
	    p = rg->rightleafset;
	}
    else /*insert in left leafset */
	{
	    size = leafset_size (rg->leftleafset);
	    p = rg->leftleafset;
	}

    for (i = 0; i < size && !(key_equal (p[i], node_key )); i++);

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
void leafset_insert (np_state_t* state, np_key_t* host_key,
					 uint8_t right_or_left, np_key_t** deleted,
					 np_key_t** added)
{
	log_msg(LOG_TRACE, ".start.leafset_insert");
    uint16_t i = 0, size;
    np_key_t **p;
    np_key_t *tmp1, *tmp2;
    np_key_t *input = host_key;
    np_routeglobal_t* rg = state->routes;

    if (right_or_left == 1) // insert in right leafset
	{
	    size = leafset_size (rg->rightleafset);
	    p = rg->rightleafset;
	}
    else // insert in left leafset
	{
	    size = leafset_size (rg->leftleafset);
	    p = rg->leftleafset;
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
            if (key_equal (p[i], input))
			{
			    return;
			}

            if (foundKeyPos) break;
            else i++;

            if (i < size)
			{
				if (right_or_left == 1)
				{
                    foundKeyPos = key_between(input, state->my_node_key, p[i]);
				}
				else
				{
                    foundKeyPos = key_between(input, p[i], state->my_node_key);
				}
			}
		}

        tmp1 = input;
        *added = input;

        while (i < LEAFSET_SIZE / 2)
        {
        	tmp2 = p[i];
        	p[i] = tmp1;
        	tmp1 = tmp2;
        	i++;
	    }
        /* there is a leftover */
        if (tmp2 != NULL && size == LEAFSET_SIZE / 2) {
        	*deleted = tmp2;
	    }
	}
	log_msg(LOG_TRACE, ".end  .leafset_insert");
}

/** route_neighbors: 
 ** returns an array of #count# neighbor nodes with priority to closer nodes
 **/
sll_return(np_key_t) route_neighbors (np_state_t* state, uint8_t count)
{
	log_msg(LOG_TRACE, ".start.route_neighbors");

	np_routeglobal_t* rg = state->routes;
    uint8_t i = 0, Rsize = 0, Lsize = 0;

    np_sll_t(np_key_t, node_keys);
    sll_init(np_key_t, node_keys);

    Lsize = leafset_size (rg->leftleafset);
    Rsize = leafset_size (rg->rightleafset);

    /* create a jrb of leafset pointers sorted on distance */
    for (i = 0; i < Lsize; i++)
	{
    	sll_append(np_key_t, node_keys, rg->leftleafset[i]);
	}

    for (i = 0; i < Rsize; i++)
	{
    	sll_append(np_key_t, node_keys, rg->rightleafset[i]);
	}

    /* sort aux */
    sort_keys_kd(node_keys, state->my_node_key);
    // sort_keys_cpm (node_keys, rg->me);

	log_msg(LOG_TRACE, ".end  .route_neighbors");
    return node_keys;
}

/** route_update:
 ** updated the routing table in regard to #node#. If the host is joining
 ** the network (and #joined# == 1), then it is added to the routing table
 ** if it is appropriate. If it is leaving the network (and #joined# == 0),
 ** then it is removed from the routing tables
 **/
void route_update (np_state_t* state, np_key_t* key, np_bool joined, np_key_t** deleted, np_key_t** added)
{
	log_msg(LOG_TRACE, ".start.route_update");
	log_msg(LOG_INFO, "update in routing: %hhd %s", joined, key_get_as_string(key));

    uint16_t i, j, k, found, pick;

    if (key_equal (state->my_node_key, key))
	{
    	log_msg(LOG_TRACE, ".end  .route_update");
	    return;
	}
    *added = NULL;
    *deleted = NULL;

    i = key_index (state->my_node_key, key);
    j = hexalpha_to_int (key_get_as_string(key)[i]);

    /* a node joins the routing table */
    if (TRUE == joined)
	{
        // pthread_mutex_lock (&state->routes->lock);
	    found = 0;

	    for (k = 0; k < MAX_ENTRY; k++)
		{
	    	if (state->routes->table[i][j][k] != NULL &&
	    		key_equal (state->routes->table[i][j][k], key)) {
	    		found = 0;
	    		break;
	    	}

	    	if (state->routes->table[i][j][k] == NULL)
			{
		    	state->routes->table[i][j][k] = key;
			    found = 0;
			    *added   = key;
			    break;

			}
		    else if (state->routes->table[i][j][k] != NULL &&
 		    		 !key_equal (state->routes->table[i][j][k], key ))
 			{
 		    	found = 1;
 			}
		}

	    /* the entry array is full we have to get rid of one */
	    /* replace the new node with the node with the highest latency in the entry array */
	    if (found)
		{
		    pick = 0;
		    for (k = 1; k < MAX_ENTRY; k++)
			{
		    	// if (state->routes->table[i][j][k] &&
		    	// 	!key_equal(state->routes->table[i][j][k], state->routes->table[i][j][pick])) {
		    		np_key_t *pick_node, *tmp_node;

		    		pick_node = state->routes->table[i][j][pick];
		    		tmp_node = state->routes->table[i][j][k];

		    		if (tmp_node->node->latency > pick_node->node->latency  ) {
		    			pick = k;
		    		}
		    	// }
		    }
		    *deleted = state->routes->table[i][j][pick];
			state->routes->table[i][j][pick] = key;
		    *added = state->routes->table[i][j][pick];
		}
        // pthread_mutex_unlock (&state->routes->lock);

	} else {

		// pthread_mutex_lock (&state->routes->lock);
		/* delete a node from the routing table */
	    for (k = 0; k < MAX_ENTRY; k++) {
	    	if (state->routes->table[i][j][k] != NULL &&
	    		key_equal (state->routes->table[i][j][k], key ))
	    	{
	    		*deleted = key;
	    		state->routes->table[i][j][k] = NULL;
	    		break;
	    	}
	    }
	    // pthread_mutex_unlock (&state->routes->lock);
	}
	log_msg(LOG_TRACE, ".end  .route_update");
}

int8_t hexalpha_to_int (int8_t c)
{
    char hexalpha[] = "0123456789abcdef";
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

void leafset_print (const np_routeglobal_t* rg)
{
	uint16_t i;
    uint16_t Lsize, Rsize;

    log_msg(LOG_ROUTING, "LEAFSET LEFT:");
    Lsize = leafset_size (rg->leftleafset);
    for (i = 0; i < Lsize; i++)
    	log_msg(LOG_ROUTING, "%s", key_get_as_string (rg->leftleafset[i] ));

    log_msg(LOG_ROUTING, "LEAFSET RIGHT:");
    Rsize = leafset_size (rg->rightleafset);
    for (i = 0; i < Rsize; i++)
    	log_msg(LOG_ROUTING, "%s", key_get_as_string (rg->rightleafset[i] ));
}

void printTable (np_routeglobal_t* rg)
{
    uint16_t i, j, k;
    // np_routeglobal_t* routeglob = (np_routeglobal_t* ) state->route;

    /* print the table */
    log_msg (LOG_ROUTING, "------------------------------- TABLE-------------------------------");
    for (i = 0; i < MAX_ROW; i++)
	{
	    for (j = 0; j < MAX_COL; j++)
		{
		    for (k = 0; k < MAX_ENTRY; k++)
		    	if (rg->table[i][j][k] != NULL)
		    		log_msg(LOG_ROUTING, "[%hd][%hd][%hd] %s",
		    						 	 i,j,k,
		    						 	 key_get_as_string (rg->table[i][j][k])
										 /* rg->table[i][j][k]->dns_name,
										 rg->table[i][j][k]->port*/ );
		    	// else
		    	//	fprintf (stderr, "00000000 00000000 00000000 00000000 00000000");
		}
	    // fprintf (stderr, "\n");
	}
    log_msg (LOG_ROUTING, "----------------------------------------------------------------------");
}
