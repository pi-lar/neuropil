#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "route.h"

#include "jrb.h"
#include "jval.h"
#include "log.h"
#include "np_container.h"
#include "np_memory.h"
#include "np_threads.h"
#include "node.h"

int leafset_size (np_key_t** arr);

// void leafset_update (np_routeglobal_t* rg, np_node_t* host, int joined, np_node_t* deleted, np_node_t** added);
void leafset_insert (np_routeglobal_t* rg, np_key_t* host, int right_or_left, np_key_t** deleted, np_key_t** added);
void leafset_delete (np_routeglobal_t* rg, np_key_t* host, int right_or_left, np_key_t** deleted);

void leafset_print (const np_routeglobal_t* rg);
void leafset_range_update (np_routeglobal_t*  rg, np_key_t* rrange, np_key_t* lrange);

int hexalpha_to_int (int c);

void route_update_me (np_routeglobal_t* rg, np_key_t* me)
{
    rg->me = me;
}

/* route_init:
 * Ininitiates routing table and leafsets
 */
np_routeglobal_t* route_init (np_key_t* me)
{
    int i, j, k;
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

    route_update_me(rg, me);

    key_assign (&(rg->Rrange), me );
    key_assign (&(rg->Lrange), me );

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
    int i, j, l;

	np_sll_t(np_key_t, sll_of_keys);
	sll_init(np_key_t, sll_of_keys);

	pthread_mutex_lock (&rg->lock);
    for (i = 0; i < MAX_ROW; i++)
    	for (j = 0; j < MAX_COL; j++)
    		for (l = 0; l < MAX_ENTRY; l++)
    			if (rg->table[i][j][l] != NULL)
    			{
    				sll_append(np_key_t, sll_of_keys, rg->table[i][j][l]);
    				// np_node_lookup(rg->me->node_tree, np_node_get_key(rg->table[i][j][l]), 0);
    				// ret[k++] = np_node_get_by_hostname(rg->me->ng, rg->table[i][j][l]->dns_name, rg->table[i][j][l]->port);
    			}
    pthread_mutex_unlock (&rg->lock);

    return sll_of_keys;
}

/** route_row_lookup:key 
 ** return the row in the routing table that matches the longest prefix with #key# 
 */
sll_return(np_key_t) route_row_lookup (np_state_t* state, np_key_t* key)
{
    int i, j, l;
	np_sll_t(np_key_t, sll_of_keys);
	sll_init(np_key_t, sll_of_keys);

    pthread_mutex_lock (&state->routes->lock);
    i = key_index (state->routes->me, key);

	for (j = 0; j < MAX_COL; j++)
		for (l = 0; l < MAX_ENTRY; l++)
			if (state->routes->table[i][j][l] != NULL &&
				!key_equal(state->routes->table[i][j][l], key) ) {
				sll_append(np_key_t, sll_of_keys, state->routes->table[i][j][l]);
			}
	// np_node_lookup(state->nodes, state->routes->table[i][j][l], 0); // np_node_lookup(rg->me->node_tree, np_node_get_key(rg->table[i][j][l]), 0);
	// ret[k++] = np_node_get_by_hostname (rg->me->ng, rg->table[i][j][l]->dns_name, rg->table[i][j][l]->port);
	// ret[k++] = np_node_get_by_hostname (rg->me->ng, rg->me->dns_name, rg->me->port);
	sll_append(np_key_t, sll_of_keys, state->neuropil->my_key);
	// np_node_lookup(state->nodes, state->neuropil->my_key, 0);
	// ret[k] = NULL;

    pthread_mutex_unlock (&state->routes->lock);

    return sll_of_keys;
}

/** route_lookup:
 ** returns an array of #count# keys that are acceptable next hops for a
 ** message being routed to #key#. #is_save# is ignored for now.
 */
np_key_t** route_lookup (np_state_t* state, np_key_t* key, int count, int is_safe)
{
    int i, j, k, Lsize, Rsize;
    int index = 0, match_col = 0, next_hop = 0;

    np_key_t dif1, dif2;

    np_key_t *leaf, *tmp, *min;
    np_key_t **ret;
    np_key_t **hosts;

	np_obj_t* o_node;
	np_node_t* node;

	log_msg(
      LOG_ROUTING, "%s is looking for key %s !",
	  key_get_as_string(state->routes->me), key_get_as_string(key));

	pthread_mutex_lock (&state->routes->lock);

    /*calculate the leafset and table size */
    Lsize = leafset_size (state->routes->leftleafset);
    Rsize = leafset_size (state->routes->rightleafset);

    /* if the key is in the leafset range route through leafset */
    /* the additional 2 neuropil nodes pointed by the #hosts# are to consider the node itself and NULL at the end */
    if (count == 1 &&
    	key_between (key, &state->routes->Lrange, &state->routes->Rrange))
	{
    	log_msg (LOG_ROUTING, "routing through leafset");

    	hosts = (np_key_t**) malloc (sizeof (np_key_t*) * (LEAFSET_SIZE + 2));
	    memset ((void *) hosts, 0, (sizeof (np_key_t*) * (LEAFSET_SIZE + 2)));

	    ret = (np_key_t**) malloc (sizeof (np_key_t*) * (count + 1));
	    memset ((void *) ret, 0, (sizeof (np_key_t*) * (count + 1)));

	    hosts[index++] = state->routes->me;

	    log_msg (LOG_ROUTING, "ME: (%s)",
	    		 // np_node_get_dns_name(rg->me),
				 // np_node_get_port(rg->me),
				 key_get_as_string (state->routes->me));

	    /* look left */
	    for (i = 0; i < Lsize; i++)
		{
		    leaf = state->routes->leftleafset[i];
		    log_msg (LOG_ROUTING, "Left_leafset[%d]: (%s)",
		    		i,
		    		// np_node_get_dns_name(leaf),
					// np_node_get_port(leaf),
					key_get_as_string (leaf));
		    hosts[index++] = leaf;
		}
	    /* look right */
	    for (i = 0; i < Rsize; i++)
		{
		    leaf = state->routes->rightleafset[i];
		    log_msg (LOG_ROUTING, "Right_leafset[%d]: (%s)",
		    		 i,
					 // np_node_get_dns_name(leaf),
					 // np_node_get_port(leaf),
					 key_get_as_string (leaf));
		    hosts[index++] = leaf;
		}
	    hosts[index] = NULL;

	    min = find_closest_key (hosts, key, index);

	    ret[0] = min;
	    ret[1] = NULL;
	    log_msg (LOG_ROUTING, "++NEXT_HOP = %s", key_get_as_string (ret[0]));

	    free (hosts);
	    pthread_mutex_unlock (&state->routes->lock);

	    return (ret);
	}

    /* check to see if there is a matching next hop (for fast routing) */
    i = key_index (state->routes->me, key);
    match_col = hexalpha_to_int (key_get_as_string(key)[i]);

    for (k = 0; k < MAX_ENTRY; k++) {
    	if (state->routes->table[i][match_col][k] != NULL) {

    		o_node = np_node_lookup(state->nodes, state->routes->table[i][match_col][k], 0);
    		np_bind(np_node_t, o_node, node);

    		if (node->success_avg > BAD_LINK)
			{
				next_hop = 1;
				tmp = state->routes->table[i][match_col][k];
				np_unbind(np_node_t, o_node, node);
				break;
			}
			np_unbind(np_node_t, o_node, node);
		}
    }

    if (next_hop == 1 && count == 1)
	{
    	np_obj_t* o_tmp_node;
    	np_node_t* tmp_node;

    	o_tmp_node = np_node_lookup(state->nodes, tmp, 0);
    	np_bind(np_node_t, o_tmp_node, tmp_node);

    	for (k = 0; k < MAX_ENTRY; k++)
		{
		    if ( state->routes->table[i][match_col][k] != NULL &&
		    	 !key_equal(state->routes->table[i][match_col][k], tmp_node->key) )
		    {
		    	o_node = np_node_lookup(state->nodes, state->routes->table[i][match_col][k], 0);
		    	np_bind(np_node_t, o_node, node);

		    	if ( (node->success_avg > tmp_node->success_avg  ||
		    		  node->success_avg == tmp_node->success_avg)
		    		&&
					  node->latency < tmp_node->latency )
		    	{
		    		np_unbind(np_node_t, o_tmp_node, tmp_node);
		    		tmp = state->routes->table[i][match_col][k];
		    		tmp_node = node;
		    		np_bind(np_node_t, o_tmp_node, tmp_node);
				} else {
		    		np_unbind(np_node_t, o_node, node);
		    	}
		    }
		}

    	ret = (np_key_t**) malloc (sizeof (np_key_t*) * (count + 1));
		ret[0] = tmp; // np_node_lookup(rg->me->node_tree, np_node_get_key(tmp), 0);
	    // ret[0] = np_node_get_by_hostname (rg->me->ng, tmp->dns_name, tmp->port);
	    ret[1] = NULL;

	    log_msg (LOG_ROUTING, "Routing through Table(%s), NEXT_HOP=%s",
			   key_get_as_string (state->routes->me ),
			   key_get_as_string (ret[0]));

	    np_unbind(np_node_t, o_tmp_node, tmp_node);
	    pthread_mutex_unlock (&state->routes->lock);
		return (ret);
	}

    /* if there is no matching next hop we have to find the best next hop */
    /* brute force method to solve count requirements */
    hosts = (np_key_t**) malloc (sizeof (np_key_t*) * (LEAFSET_SIZE + 1 + (MAX_COL * MAX_ENTRY)));
    memset  ((void *) hosts, 0,     (sizeof (np_key_t*) * (LEAFSET_SIZE + 1 + (MAX_COL * MAX_ENTRY))));

    // log_msg (LOG_ROUTING, "Routing to next closest key I know of:");
    leaf = state->routes->me;
    log_msg (LOG_ROUTING, "+me: (%s)",
    		 /* leaf->dns_name, leaf->port,*/ key_get_as_string (leaf) );
    hosts[index++] = state->routes->me;

    /* look left */
    for (int l = 0; l < Lsize; l++)
	{
	    leaf = state->routes->leftleafset[l];
	    log_msg (LOG_ROUTING, "+Left_leafset[%d]: (%s)",
	    		 l, /* leaf->dns_name, leaf->port,*/ key_get_as_string (key));
	    hosts[index++] = leaf;
	}
    /* look right */
    for (int r = 0; r < Rsize; r++)
	{
	    leaf = state->routes->rightleafset[r];
	    log_msg (LOG_ROUTING, "+Right_leafset[%d]: (%s)",
	    		 r, /* leaf->dns_name, leaf->port,*/ key_get_as_string (leaf));
	    hosts[index++] = leaf;
	}

    /* find the longest prefix match */
    i = key_index (state->routes->me, key);

    for (j = 0; j < MAX_COL; j++) {
    	for (k = 0; k < MAX_ENTRY; k++) {
    		if (state->routes->table[i][j][k] != NULL) {

    			o_node = np_node_lookup(state->nodes, state->routes->table[i][j][k], 0);
    			np_bind(np_node_t, o_node, node);

				if (node->success_avg > BAD_LINK) {
					leaf = state->routes->table[i][j][k];
					log_msg (LOG_ROUTING, "+Table[%d][%d][%d]: (%s)",
										  i, j, k, /* leaf->dns_name, leaf->port, */ key_get_as_string (leaf));
					hosts[index++] = leaf;
				}
				np_unbind(np_node_t, o_node, node);
			}
    	}
    }
    hosts[index] = NULL;

    ret = (np_key_t**) malloc (sizeof (np_key_t*) * (count + 1));

	if (count == 1)
	{
	    // printf ("route.c (%d): route_lookup bounce count==1 ...\n", getpid());
	    // printTable(state);
	    ret[0] = find_closest_key (hosts, key, index);
		ret[1] = NULL;
	}
	else
	{
		sort_keys_cpm (hosts, key, index);
		/* find the best #count# entries that we looked at ... could be much better */
		for (i = 0, j = 0; hosts[i] != NULL && (i - j) < count; i++)
		{
			tmp = hosts[i];

			if ((i - j) > 0 && key_equal (ret[(i - j) - 1], tmp ))
			{
				j++;
				continue;
			}
			log_msg (LOG_ROUTING, "++Result[%d]: (%s)", i,
					 // np_node_get_dns_name(tmp),
					 // np_node_get_port(tmp),
					 key_get_as_string (tmp) );

			ret[i - j] = tmp; // np_node_lookup(rg->me->node_tree, np_node_get_key(tmp), 0);
			// ret[i - j] = np_node_get_by_hostname (rg->me->ng, tmp->dns_name, tmp->port);
		}
		ret[i - j] = NULL;
	}

    /*  to prevent bouncing */
    if (count == 1)
	{
	    key_distance (&dif1, key, ret[0]);
	    key_distance (&dif2, key, state->routes->me);

	    // printTable(rg);
	    // log_msg(LOG_DEBUG, "route_lookup bounce detection ...");
	    // log_msg(LOG_DEBUG, "my own key: %s", key_get_as_string(np_node_get_key(rg->me) ));
	    // log_msg(LOG_DEBUG, "search key: %s", key_get_as_string(key));
	    // log_msg(LOG_DEBUG, "dif1   key: %s", key_get_as_string(&dif1));
	    // log_msg(LOG_DEBUG, "dif2   key: %s", key_get_as_string(&dif2));

	    // if (key_equal (dif1, dif2)) ret[0] = rg->me;
	    // changed on 03.06.2014 STSW choose the closest neighbour
	    if (key_comp (&dif1, &dif2) >= 0) ret[0] = state->routes->me;

	    log_msg(LOG_ROUTING, "route  key: %s", key_get_as_string(ret[0]));

	    // if (!key_comp(&dif1, &dif2) == 0) ret[0] = rg->me;
	    // if (key_comp(&dif1, &dif2)  < 0) ret[0] = NULL;
	    // if (key_comp(&dif1, &dif2)  > 0) ret[0] = rg->me;

	} else {
	    log_msg (LOG_ROUTING, "route_lookup bounce detection not wanted ...");
	}

    free (hosts);
    pthread_mutex_unlock (&state->routes->lock);

    return (ret);
}

int leafset_size (np_key_t** arr)
{
    int i = 0;
    for (i = 0; arr[i] != NULL; i++);
    return i;
}

/**
 ** leafset_range_update:
 ** updates the leafset range whenever a node leaves or joins to the leafset
 **
 */
void leafset_range_update (np_routeglobal_t* rg, np_key_t* rrange, np_key_t* lrange)
{
    int i;

    /* right range */
    for (i = 0; rg->rightleafset[i] != NULL; i++)
    	key_assign (rrange, rg->rightleafset[i]);
    if (i == 0)
    	key_assign (rrange, rg->me);

    /* left range */
    for (i = 0; rg->leftleafset[i] != NULL; i++)
    	key_assign (lrange, rg->leftleafset[i]);
    if (i == 0)
    	key_assign (lrange, rg->me);

    /* right range */
    /* for (i = 0; rg->rightleafset[i] != NULL; i++)
    	key_assign (rrange, rg->rightleafset[i]);
    if (i == 0)
    	key_assign (lrange, rg->me);
	*/
    /* left range */
    /* if (rg->leftleafset[0] != NULL)
    	key_assign (lrange, rg->leftleafset[0] );
    else
    	key_assign (lrange, rg->me);
	*/
}


/**
 ** leafset_update:
 ** this function is called whenever a route_update is called the joined
 ** is 1 if the node has joined and 0 if a node is leaving. 
 ** 
 */
void leafset_update (np_state_t* state, np_key_t* node_key, int joined, np_key_t** deleted, np_key_t** added)
{
    int Lsize = 0;
    int Rsize = 0;
    np_key_t midpoint;

    *added = NULL;
    *deleted = NULL;

    Lsize = leafset_size (state->routes->leftleafset);
    Rsize = leafset_size (state->routes->rightleafset);

    key_midpoint (&midpoint, state->routes->me);

    if (joined)
	{
		/* key falls in the right side of node */
		if (Rsize < LEAFSET_SIZE / 2 ||
			key_between (node_key, state->routes->me, state->routes->rightleafset[Rsize-1] ))
		{	/* insert in Right leafset */
			leafset_insert (state->routes, node_key, 1, deleted, added);
			return;
		}
		/* key falls in the left side of the node */
		if (Lsize < LEAFSET_SIZE / 2 ||
			key_between (node_key, state->routes->leftleafset[Lsize-1], state->routes->me))
		{	/* insert in Left leafset */
			leafset_insert (state->routes, node_key, 0, deleted, added);
			return;
		}
	}
    else
	{
		/* key falls in the right side of node */
		if (Rsize < LEAFSET_SIZE / 2 ||
			key_between (node_key, state->routes->me, state->routes->rightleafset[Rsize-1] ))
		{
			leafset_delete (state->routes, node_key, 1, deleted);
			return;
		}
		if (Lsize < LEAFSET_SIZE / 2 ||
			key_between (node_key, state->routes->leftleafset[Lsize-1], state->routes->me))
		{
			leafset_delete (state->routes, node_key, 0, deleted);
			return;
		}
	}

    // TODO: handle it via add a new async update job instead ?
    if (*deleted != NULL)
	{
	    leafset_range_update (state->routes, &(state->routes->Rrange), &(state->routes->Lrange));
	}
    if (*added != NULL)
	{
	    leafset_range_update (state->routes, &(state->routes->Rrange), &(state->routes->Lrange));
	}
}

/** 
 ** leafset_delete:
 ** removes the #deleted# node from leafset
 **
 */
void leafset_delete (np_routeglobal_t* rg, np_key_t* node_key, int right_or_left, np_key_t** deleted)
{
    int i = 0, size;
    int match = 0;
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
void leafset_insert (np_routeglobal_t* rg, np_key_t* host_key,
					 int right_or_left, np_key_t** deleted,
					 np_key_t** added)
{
    int i = 0, size;
    np_key_t **p;
    np_key_t *tmp1, *tmp2;
    np_key_t *input = host_key;

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
		int foundKeyPos = 0;
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
                    foundKeyPos = key_between(input, rg->me, p[i]);
				}
				else
				{
                    foundKeyPos = key_between(input, p[i], rg->me);
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
}

/** route_neighbors: 
 ** returns an array of #count# neighbor nodes with priority to closer nodes
 **/
sll_return(np_key_t) route_neighbors (np_routeglobal_t* rg, int count)
{
    int i = 0, Rsize = 0, Lsize = 0, index = 0;
    // int ret_size;

    np_sll_t(np_key_t, node_keys);
    sll_init(np_key_t, node_keys);

    pthread_mutex_lock (&rg->lock);

    Lsize = leafset_size (rg->leftleafset);
    Rsize = leafset_size (rg->rightleafset);

    // if (count > Rsize + Lsize) ret_size = Rsize + Lsize;
	// else ret_size = count;

    /* create a jrb of leafset pointers sorted on distance */
    for (i = 0; i < Lsize; i++)
	{
    	sll_append(np_key_t, node_keys, rg->leftleafset[i]);
	}

    for (i = 0; i < Rsize; i++)
	{
    	sll_append(np_key_t, node_keys, rg->rightleafset[i]);
	}

    // node_keys[index] = NULL;
    /* sort aux */
    sort_keys_kd(node_keys, rg->me, index);
    // sort_keys_cpm (node_keys, rg->me, index);

    pthread_mutex_unlock (&rg->lock);

    return node_keys;
}

/** route_update:
 ** updated the routing table in regard to #node#. If the host is joining
 ** the network (and #joined# == 1), then it is added to the routing table
 ** if it is appropriate. If it is leaving the network (and #joined# == 0),
 ** then it is removed from the routing tables
 **/
void route_update (np_state_t* state, np_key_t* key, int joined, np_key_t** deleted, np_key_t** added)
{
	log_msg(LOG_INFO, "update in routing: %d %s", joined, key_get_as_string(key));

    int i, j, k, found, pick;

    if (key_equal (state->routes->me, key))
	{
	    return;
	}
    *added = NULL;
    *deleted = NULL;

    i = key_index (state->routes->me, key);
    j = hexalpha_to_int (key_get_as_string(key)[i]);

    /* a node joins the routing table */
    if (joined)
	{
        pthread_mutex_lock (&state->routes->lock);
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

		    		np_obj_t *o_pick_node, *o_tmp_node;
		    		np_node_t *pick_node, *tmp_node;

		    		o_pick_node = np_node_lookup(state->nodes, state->routes->table[i][j][pick], 0);
		    		o_tmp_node = np_node_lookup(state->nodes, state->routes->table[i][j][k], 0);
		    		np_bind(np_node_t, o_pick_node, pick_node);
		    		np_bind(np_node_t, o_tmp_node, tmp_node);

		    		if (tmp_node->latency > pick_node->latency  ) {
		    			pick = k;
		    		}

		    		np_unbind(np_node_t, o_pick_node, pick_node);
		    		np_unbind(np_node_t, o_tmp_node, tmp_node);
		    	// }
		    }
		    *deleted = state->routes->table[i][j][pick];
			state->routes->table[i][j][pick] = key;
		    *added = state->routes->table[i][j][pick];
		}
        pthread_mutex_unlock (&state->routes->lock);

	} else {

		pthread_mutex_lock (&state->routes->lock);
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
	    pthread_mutex_unlock (&state->routes->lock);
	}
}

int hexalpha_to_int (int c)
{
    char hexalpha[] = "0123456789abcdef";
    int i;
    int answer = 0;

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
    int i;
    int Lsize, Rsize;

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
    int i, j, k;
    // np_routeglobal_t* routeglob = (np_routeglobal_t* ) state->route;

    /* print the table */
    log_msg (LOG_ROUTING, "------------------------------- TABLE-------------------------------");
    for (i = 0; i < MAX_ROW; i++)
	{
	    for (j = 0; j < MAX_COL; j++)
		{
		    for (k = 0; k < MAX_ENTRY; k++)
		    	if (rg->table[i][j][k] != NULL)
		    		log_msg(LOG_ROUTING, "[%d][%d][%d] %s",
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
