#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>

#include "route.h"

#include "jrb.h"
#include "jval.h"
#include "log.h"

#include "node.h"

// void leafset_update (np_routeglobal_t* rg, np_node_t* host, int joined, np_node_t* deleted, np_node_t** added);
void leafset_insert (np_routeglobal_t* rg, np_node_t* host, int right_or_left, np_node_t** deleted, np_node_t** added);
void leafset_delete (np_routeglobal_t* rg, np_node_t* host, int right_or_left, np_node_t** deleted);

int leafset_size (np_node_t** arr);

void leafset_print (const np_routeglobal_t* rg);
void leafset_range_update (np_routeglobal_t*  rg, Key * rrange, Key * lrange);

np_node_t* find_closest_key (np_node_t** hosts, Key* key, int size);
void sort_hosts (np_node_t** hosts, Key* key, int size);
void sort_hosts_key (np_node_t** hosts, Key* key, int size);

int hexalpha_to_int (int c);

// void route_keyupdate (np_routeglobal_t* routeglob, np_node_t* me)
void route_update_me (np_routeglobal_t* rg, np_node_t* me)
{
    // np_routeglobal_t* rg = (np_routeglobal_t* ) routeglob;
    rg->me = me;
    // sprintf (rg->keystr, "%s", key_get_as_string (np_node_get_key(rg->me) ));
}

/* route_init:
 * Ininitiates routing table and leafsets
 */
np_routeglobal_t* route_init (np_node_t* me)
{
    int i, j, k;
    np_routeglobal_t *rg = (np_routeglobal_t *) malloc (sizeof (np_routeglobal_t));

    /* allocate memory for routing table */
    rg->table = (np_node_t ****) malloc (sizeof (struct np_node_t ***) * MAX_ROW);
    for (i = 0; i < MAX_ROW; i++)
	{
	    rg->table[i] = (np_node_t ***) malloc (sizeof (np_node_t **) * MAX_COL);
	    for (j = 0; j < MAX_COL; j++)
		{
		    rg->table[i][j] = (np_node_t **) malloc (sizeof (np_node_t *) * MAX_ENTRY);
		    for (k = 0; k < MAX_ENTRY; k++)
		    	rg->table[i][j][k] = NULL;
		}
	}

    rg->keystr = (char *) malloc (sizeof (char) * (MAX_ROW + 1));
    route_update_me(rg, me);

    key_assign (&(rg->Rrange), np_node_get_key(me) );
    key_assign (&(rg->Lrange), np_node_get_key(me) );

    /* allocate memory for leafsets */
    rg->leftleafset  = (np_node_t **) malloc (sizeof (np_node_t *) * ((LEAFSET_SIZE / 2) + 1));
    rg->rightleafset = (np_node_t **) malloc (sizeof (np_node_t *) * ((LEAFSET_SIZE / 2) + 1));

    for (i = 0; i < (LEAFSET_SIZE / 2) + 1; i++)
	{
	    rg->leftleafset[i]  = NULL;
	    rg->rightleafset[i] = NULL;
	}

    pthread_mutex_init (&rg->lock, NULL);

    /* initiate a separate thread that constantly checks to see if the leafset members */
/*    if (pthread_attr_init (&rg->attr) != 0)
    {
        log_msg(LOG_ERROR, "(CHIMERA)pthread_attr_init: %s", strerror (errno));
        return (0);
    }
    if (pthread_attr_setscope (&rg->attr, PTHREAD_SCOPE_SYSTEM) != 0)
    {
        log_msg(LOG_ERROR, "(CHIMERA)pthread_attr_setscope: %s", strerror (errno));
        goto out;
    }
    if (pthread_attr_setdetachstate (&rg->attr, PTHREAD_CREATE_DETACHED) != 0)
    {
        log_msg(LOG_ERROR, "(CHIMERA)pthread_attr_setdetachstate: %s", strerror (errno));
        goto out;
    }
*/
    // TODO: has to be done somehwere else
//    if (pthread_create (&rg->tid, &rg->attr, chimera_check_leafset, (void*) np_state) != 0)
//    {
//        log_msg(LOG_ERROR, "(CHIMERA)pthread_create: %s", strerror (errno));
//        goto out;
//    }

    return rg;

    // out:
    //     pthread_attr_destroy (&rg->attr);
    // return (0);
}

/** route_get_table: 
 ** return the entire routing table
 */
np_node_t** route_get_table (np_routeglobal_t* rg)
{
	np_node_t **ret;
    int i, j, l, k, count;
    // np_routeglobal_t* routeglob = (np_routeglobal_t* ) state->route;

    pthread_mutex_lock (&rg->lock);

    count = 0;

    for (i = 0; i < MAX_ROW; i++)
    	for (j = 0; j < MAX_COL; j++)
    		for (l = 0; l < MAX_ENTRY; l++)
    			if (rg->table[i][j][l] != NULL)
    				count++;

    ret = (np_node_t**) malloc (sizeof (np_node_t*) * (count + 1));

    k = 0;
    for (i = 0; i < MAX_ROW; i++)
    	for (j = 0; j < MAX_COL; j++)
    		for (l = 0; l < MAX_ENTRY; l++)
    			if (rg->table[i][j][l] != NULL)
    			{
    				ret[k++] = rg->table[i][j][l];
    				// np_node_lookup(rg->me->node_tree, np_node_get_key(rg->table[i][j][l]), 0);
    				// ret[k++] = np_node_get_by_hostname(rg->me->ng, rg->table[i][j][l]->dns_name, rg->table[i][j][l]->port);
    			}
    ret[k] = NULL;
    pthread_mutex_unlock (&rg->lock);
    return ret;
}

/** route_row_lookup:key 
 ** return the row in the routing table that matches the longest prefix with #key# 
 */
np_node_t** route_row_lookup (np_routeglobal_t* rg, Key* key)
{
    // printf ("route.c (%d): route_row_lookup\n", getpid());
    np_node_t**ret;
    int i, j, k, l, count;

    pthread_mutex_lock (&rg->lock);

    i = key_index (np_node_get_key(rg->me), key);

    /* find out the number of hosts exists in the matching row */
    count = 0;
    for (j = 0; j < MAX_COL; j++)
    	for (l = 0; l < MAX_ENTRY; l++)
    		if (rg->table[i][j][l] != NULL)
    			count++;

    ret = (np_node_t**) malloc (sizeof (np_node_t*) * (count + 2));
    k = 0;
    for (j = 0; j < MAX_COL; j++)
    	for (l = 0; l < MAX_ENTRY; l++)
    		if (rg->table[i][j][l] != NULL)
				ret[k++] = np_node_lookup(rg->me->node_tree, np_node_get_key(rg->table[i][j][l]), 0);
    			// ret[k++] = np_node_get_by_hostname (rg->me->ng, rg->table[i][j][l]->dns_name, rg->table[i][j][l]->port);

    // ret[k++] = np_node_get_by_hostname (rg->me->ng, rg->me->dns_name, rg->me->port);
	ret[k++] = np_node_lookup(rg->me->node_tree, np_node_get_key(rg->me), 0);
    ret[k] = NULL;

    pthread_mutex_unlock (&rg->lock);

    return ret;
}

/** route_lookup:
 ** returns an array of #count# nodes that are acceptable next hops for a
 ** message being routed to #key#. #is_save# is ignored for now.
 */
np_node_t** route_lookup (np_routeglobal_t* rg, Key* key, int count, int is_safe)
{
    int i, j, k, Lsize, Rsize;
    int index = 0, match_col = 0, next_hop = 0, size = 0;
    np_node_t *leaf, *tmp, *min;
    Key dif1, dif2;
    np_node_t **ret;
    np_node_t **hosts;
    // np_routeglobal_t* routeglob = (np_routeglobal_t* ) state->route;

    pthread_mutex_lock (&rg->lock);

    log_msg(
      LOG_ROUTING, "%s is looking for key %s !",
      key_get_as_string (rg->me->key), key_get_as_string(key));

    /*calculate the leafset and table size */
    Lsize = leafset_size (rg->leftleafset);
    Rsize = leafset_size (rg->rightleafset);

    /* if the key is in the leafset range route through leafset */
    /* the additional 2 neuropil nodes pointed by the #hosts# are to consider the node itself and NULL at the end */
    if (count == 1 &&
    	key_between (key, &rg->Lrange, &rg->Rrange))
	{
    	log_msg (LOG_ROUTING, "routing through leafset");

    	hosts = (np_node_t**) malloc (sizeof (np_node_t*) * (LEAFSET_SIZE + 2));
	    memset ((void *) hosts, 0, (sizeof (np_node_t*) * (LEAFSET_SIZE + 2)));

	    ret = (np_node_t**) malloc (sizeof (np_node_t*) * (count + 1));
	    memset ((void *) ret, 0, (sizeof (np_node_t*) * (count + 1)));

	    hosts[index++] = rg->me;

	    log_msg (LOG_ROUTING, "ME: (%s, %d, %s)",
	    		 np_node_get_dns_name(rg->me),
				 np_node_get_port(rg->me),
				 key_get_as_string (rg->me->key));

	    /* look left */
	    for (i = 0; i < Lsize; i++)
		{
		    leaf = rg->leftleafset[i];
		    log_msg (LOG_ROUTING, "Left_leafset[%d]: (%s, %d, %s)", i,
		    		np_node_get_dns_name(leaf),
					np_node_get_port(leaf),
					key_get_as_string (leaf->key));

		    hosts[index++] = leaf;
		}
	    /* look right */
	    for (i = 0; i < Rsize; i++)
		{
		    leaf = rg->rightleafset[i];
		    log_msg (LOG_ROUTING, "Right_leafset[%d]: (%s, %d, %s)",
		    		 i,
					 np_node_get_dns_name(leaf),
					 np_node_get_port(leaf),
					 key_get_as_string (np_node_get_key(leaf)));

		    hosts[index++] = leaf;
		}
	    hosts[index] = NULL;

	    min = find_closest_key (hosts, key, index);

	    ret[0] = min;
	    ret[1] = NULL;
	    log_msg (LOG_ROUTING, "++NEXT_HOP = %s", key_get_as_string (ret[0]->key ));

	    free (hosts);
	    pthread_mutex_unlock (&rg->lock);

	    return (ret);
	}

    /* check to see if there is a matching next hop (for fast routing) */
    i = key_index (np_node_get_key(rg->me), key);
    match_col = hexalpha_to_int (key_get_as_string(key)[i]);

    for (k = 0; k < MAX_ENTRY; k++)
		if (rg->table[i][match_col][k] != NULL &&
				rg->table[i][match_col][k]->success_avg > BAD_LINK)
	    {
			next_hop = 1;
			tmp = rg->table[i][match_col][k];
			break;
	    }

    if (next_hop == 1 && count == 1)
	{
	    for (k = 0; k < MAX_ENTRY; k++)
		{
		    if ( rg->table[i][match_col][k] != NULL ) {
		    	if ( (rg->table[i][match_col][k]->success_avg > tmp->success_avg  ||
					  rg->table[i][match_col][k]->success_avg == tmp->success_avg)
		    		&&
		    		  rg->table[i][match_col][k]->latency < tmp->latency )
		    	{
		    		tmp = rg->table[i][match_col][k];
		    	}
		    }
		}
	    ret = (np_node_t**) malloc (sizeof (np_node_t*) * (count + 1));
		ret[0] = np_node_lookup(rg->me->node_tree, np_node_get_key(tmp), 0);
	    // ret[0] = np_node_get_by_hostname (rg->me->ng, tmp->dns_name, tmp->port);
	    ret[1] = NULL;
	    log_msg (LOG_ROUTING, "Routing through Table(%s), NEXT_HOP=%s",
			   key_get_as_string (np_node_get_key(rg->me) ),
			   key_get_as_string (np_node_get_key(ret[0]) ));
	    pthread_mutex_unlock (&rg->lock);
	    return (ret);
	}

    /* if there is no matching next hop we have to find the best next hop */
    /* brute force method to solve count requirements */

    hosts = (np_node_t**) malloc (sizeof (np_node_t*) * (LEAFSET_SIZE + 1 + (MAX_COL * MAX_ENTRY)));
    memset  ((void *) hosts, 0,     (sizeof (np_node_t*) * (LEAFSET_SIZE + 1 + (MAX_COL * MAX_ENTRY))));

    // log_msg (LOG_ROUTING, "Routing to next closest key I know of:");
    leaf = rg->me;
    log_msg (LOG_ROUTING, "+me: (%s, %d, %s)",
    		 leaf->dns_name, leaf->port, key_get_as_string (leaf->key) );
    hosts[index++] = rg->me;

    /* look left */
    for (i = 0; i < Lsize; i++)
	{
	    leaf = rg->leftleafset[i];
	    log_msg (LOG_ROUTING, "+Left_leafset[%d]: (%s, %d, %s)",
	    		 i, leaf->dns_name, leaf->port, key_get_as_string (leaf->key));
	    hosts[index++] = leaf;
	}
    /* look right */
    for (i = 0; i < Rsize; i++)
	{
	    leaf = rg->rightleafset[i];
	    log_msg (LOG_ROUTING, "+Right_leafset[%d]: (%s, %d, %s)",
	    		 i, leaf->dns_name, leaf->port, key_get_as_string (leaf->key ));
	    hosts[index++] = leaf;
	}

    /* find the longest prefix match */
    i = key_index (np_node_get_key(rg->me), key);

    for (j = 0; j < MAX_COL; j++)
    	for (k = 0; k < MAX_ENTRY; k++)
    		if (rg->table[i][j][k] != NULL &&
    			rg->table[i][j][k]->success_avg > BAD_LINK)
    		{
    			leaf = rg->table[i][j][k];
    			log_msg (LOG_ROUTING, "+Table[%d][%d][%d]: (%s, %d, %s)",
    					 i, j, k, leaf->dns_name, leaf->port, key_get_as_string (leaf->key));
    			hosts[index++] = leaf;
    		}

    hosts[index] = NULL;

    ret = (np_node_t**) malloc (sizeof (np_node_t*) * (count + 1));

	if (count == 1)
	{
	    // printf ("route.c (%d): route_lookup bounce count==1 ...\n", getpid());
	    // printTable(state);
	    ret[0] = find_closest_key (hosts, key, index);
		ret[1] = NULL;
	}
	else
	{
		sort_hosts (hosts, key, index);
		/* find the best #count# entries that we looked at... could be much better */
		for (i = 0, j = 0; hosts[i] != NULL && (i - j) < count; i++)
		{
			tmp = hosts[i];

			if ((i - j) > 0 && key_equal (np_node_get_key(ret[(i - j) - 1]), np_node_get_key(tmp) ))
			{
				j++;
				continue;
			}
			log_msg (LOG_ROUTING, "++Result[%d]: (%s, %d, %s)", i,
					 np_node_get_dns_name(tmp),
					 np_node_get_port(tmp),
					 key_get_as_string (np_node_get_key(tmp) ));

			ret[i - j] = np_node_lookup(rg->me->node_tree, np_node_get_key(tmp), 0);
			// ret[i - j] = np_node_get_by_hostname (rg->me->ng, tmp->dns_name, tmp->port);
		}
		ret[i - j] = NULL;
	}

    /*  to prevent bouncing */
    if (count == 1)
	{
	    key_distance (&dif1, key, np_node_get_key(ret[0]));
	    key_distance (&dif2, key, np_node_get_key(rg->me));

	    // printTable(rg);

	    // log_msg(LOG_DEBUG, "route_lookup bounce detection ...");
	    // log_msg(LOG_DEBUG, "my own key: %s", key_get_as_string(np_node_get_key(rg->me) ));
	    // log_msg(LOG_DEBUG, "search key: %s", key_get_as_string(key));
	    // log_msg(LOG_DEBUG, "dif1   key: %s", key_get_as_string(&dif1));
	    // log_msg(LOG_DEBUG, "dif2   key: %s", key_get_as_string(&dif2));

	    // if (key_equal (dif1, dif2)) ret[0] = rg->me;
	    // changed on 03.06.2014 STSW choose the closest neighbour
	    if (key_comp (&dif1, &dif2) >= 0) ret[0] = rg->me;

	    log_msg(LOG_DEBUG, "route  key: %s", key_get_as_string(np_node_get_key(ret[0]) ));

	    // if (!key_comp(&dif1, &dif2) == 0) ret[0] = rg->me;
	    // if (key_comp(&dif1, &dif2)  < 0) ret[0] = NULL;
	    // if (key_comp(&dif1, &dif2)  > 0) ret[0] = rg->me;

	} else {
	    log_msg (LOG_WARN, "route_lookup bounce detection not wanted ...");
	}

    free (hosts);
    pthread_mutex_unlock (&rg->lock);

    return (ret);
}

/** sort_hosts_key:
 ** Sorts #hosts# based on their key distance from #Key#, closest node first
 */
void sort_hosts_key (np_node_t** hosts, Key* key, int size)
{
    int i, j;
    np_node_t*tmp;
    Key dif1;
    Key dif2;

    for (i = 0; i < size; i++)
	{
	    for (j = i + 1; j < size; j++)
		{
		    if (hosts[i] != NULL && hosts[j] != NULL)
			{
			    key_distance (&dif1, np_node_get_key(hosts[i]), key);
			    key_distance (&dif2, np_node_get_key(hosts[j]), key);
			    if (key_comp (&dif2, &dif1) < 0)
				{
				    tmp = hosts[i];
				    hosts[i] = hosts[j];
				    hosts[j] = tmp;
				}
			}
		}
	}
}

/** find_closest_key:
 ** finds the closest node in the array of #hosts# to #key# and put that in min.
 */
np_node_t* find_closest_key (np_node_t** hosts, Key* key, int size)
{
    int i, j;
    Key dif;
    Key mindif;
    np_node_t *min, *tmp;

    if (size == 0)
	{
	    min = NULL;
	    // return;
	    // modified StSw 18.05.2014
	    log_msg(LOG_ERROR, "minimum size for closest key calculation not met !");
	    // return min;
	}
    else
	{
	    min = hosts[0];
	    key_distance (&mindif, np_node_get_key(hosts[0]), key);
	}

    for (i = 0; i < size; i++)
	{
	    if (hosts[i] != NULL)
		{
		    key_distance (&dif, np_node_get_key(hosts[i]), key);

		    if (key_comp (&dif, &mindif) < 0)
			{
			    min = hosts[i];
			    key_assign (&mindif, &dif);
			}
		}
	}
    // tmp = host_get (state, min->name, min->port);
    return (min);
}

/** sort_hosts:
 ** Sorts #hosts# based on common prefix match and key distance from #Key#
 */
void sort_hosts (np_node_t** hosts, Key* key, int size)
{
    int i, j;
    np_node_t* tmp;
    Key dif1;
    Key dif2;
    int pmatch1 = 0;
    int pmatch2 = 0;

    for (i = 0; i < size; i++)
	{
	    for (j = i + 1; j < size; j++)
		{
		    if (hosts[i] != NULL && hosts[j] != NULL)
			{
			    pmatch1 = key_index (key, np_node_get_key(hosts[i]));
			    pmatch2 = key_index (key, np_node_get_key(hosts[j]));
			    if (pmatch2 > pmatch1)
				{
				    tmp = hosts[i];
				    hosts[i] = hosts[j];
				    hosts[j] = tmp;
				}
			    else if (pmatch1 == pmatch2)
				{
				    key_distance (&dif1, np_node_get_key(hosts[i]), key);
				    key_distance (&dif2, np_node_get_key(hosts[j]), key);
				    if (key_comp (&dif2, &dif1) < 0)
					{
					    tmp = hosts[i];
					    hosts[i] = hosts[j];
					    hosts[j] = tmp;
					}
				}
			}

		}
	}
}

int leafset_size (np_node_t** arr)
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
void leafset_range_update (np_routeglobal_t* rg, Key* rrange, Key* lrange)
{
    int i, j;

    /* right range */
    for (i = 0; rg->rightleafset[i] != NULL; i++)
	key_assign (rrange, np_node_get_key(rg->rightleafset[i]) );
    if (i == 0)
	key_assign (lrange, np_node_get_key(rg->me));

    /* left range */
    if (rg->leftleafset[0] != NULL)
    	key_assign (lrange, np_node_get_key(rg->leftleafset[0]) );
    else
    	key_assign (lrange, np_node_get_key(rg->me));
}


/**
 ** leafset_update:
 ** this function is called whenever a route_update is called the joined
 ** is 1 if the node has joined and 0 if a node is leaving. 
 ** 
 */
void leafset_update (np_routeglobal_t* rg, np_node_t* node, int joined, np_node_t** deleted, np_node_t** added)
{
    int Lsize = 0;
    int Rsize = 0;
    Key midpoint;
    // np_routeglobal_t* routeglob = (np_routeglobal_t* ) state->route;

    Lsize = leafset_size (rg->leftleafset);
    Rsize = leafset_size (rg->rightleafset);

    key_midpoint (&midpoint, np_node_get_key(rg->me));

    if (joined)
	{
		/* key falls in the right side of node */
		if (Rsize < LEAFSET_SIZE / 2 ||
			key_between (node->key, rg->me->key, rg->rightleafset[Rsize-1]->key ))
		{	/* insert in Right leafset */
			leafset_insert (rg, node, 1, deleted, added);
			// reference counter handling
			if (*added   != NULL) np_node_lookup(rg->me->node_tree, (*added)->key, 1);
			if (*deleted != NULL) np_node_release(rg->me->node_tree, (*deleted)->key);
			return;
		}
		/* key falls in the left side of the node */
		if (Lsize < LEAFSET_SIZE / 2 ||
			key_between (node->key, rg->leftleafset[Lsize-1]->key, rg->me->key))
		{	/* insert in Left leafset */
			leafset_insert (rg, node, 0, deleted, added);
			// reference counter handling
			if (*added   != NULL) np_node_lookup(rg->me->node_tree, (*added)->key, 1);
			if (*deleted != NULL) np_node_release(rg->me->node_tree, (*deleted)->key);
			return;
		}

	}
    else
	{
		/* key falls in the right side of node */
		if (Rsize < LEAFSET_SIZE / 2 ||
			key_between (node->key, rg->me->key, rg->rightleafset[Rsize-1]->key ))
		{
			leafset_delete (rg, node, 1, deleted);
			// reference counter handling
			if (*deleted != NULL) np_node_release(rg->me->node_tree, (*deleted)->key);
			return;
		}
		if (Lsize < LEAFSET_SIZE / 2 ||
			key_between (node->key, rg->leftleafset[Lsize-1]->key, rg->me->key))
		{
			leafset_delete (rg, node, 0, deleted);
			// reference counter handling
			if (*deleted != NULL) np_node_release(rg->me->node_tree, (*deleted)->key);
			return;
		}
	}
}

/** 
 ** leafset_delete:
 ** removes the #deleted# node from leafset
 **
 */
void leafset_delete (np_routeglobal_t* rg, np_node_t* node, int right_or_left, np_node_t** deleted)
{
    int i = 0, size;
    int match = 0;
    np_node_t**p;
    // np_routeglobal_t* routeglob = (np_routeglobal_t* ) state->route;

    if (right_or_left == 1) /*insert in right leafset */
	{
	    size = leafset_size (rg->rightleafset);
	    p = rg->rightleafset;
	}
    else /*insert in left leafset */
	{
	    size = leafset_size (rg->leftleafset);
	    p = rg->leftleafset;
	}

    for (i = 0; i < size && !(key_equal (p[i]->key, node->key )); i++);

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
void leafset_insert (np_routeglobal_t* rg, np_node_t* host,
					 int right_or_left, np_node_t** deleted,
					 np_node_t** added)
{
    int i = 0, size;
    np_node_t **p;
    np_node_t *tmp1, *tmp2;
    np_node_t *input = host;
    Key dif1, dif2;
    // np_routeglobal_t* routeglob = (np_routeglobal_t* ) state->route;

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

    if (size == 0)
	{
	    p[0] = input;
	    *added = input;
	}
    else
	{
		// to avoid duplicate entries in the same leafset
    	// check index 0
		if (key_equal (p[i]->key, input->key ))
		{
			return;
		}
		int foundKeyPos = 0;
		if (right_or_left == 1)
		{
			foundKeyPos = key_between(np_node_get_key(host), rg->me->key, p[i]->key);
		}
		else
		{
			foundKeyPos = key_between(np_node_get_key(host), p[i]->key, rg->me->key);
		}
		// check other indexes
		while ((i < size) && !foundKeyPos)
		{
		    if (key_equal (p[i]->key, input->key ))
			{
			    return;
			}
		    i++;
		    if (i < size)
			{
				if (right_or_left == 1)
				{
					foundKeyPos = key_between(np_node_get_key(host), np_node_get_key(rg->me), np_node_get_key(p[i]));
				}
				else
				{
					foundKeyPos = key_between(np_node_get_key(host), np_node_get_key(p[i]), np_node_get_key(rg->me));
				}
			}
		}

	    tmp1 = input;
	    *added = input;

	    while (i < LEAFSET_SIZE / 2)
		{
		    tmp2 = p[i];
		    p[i++] = tmp1;
		    tmp1 = tmp2;
		}

	    /* there is a leftover */
	    if (tmp2 != NULL && size == LEAFSET_SIZE / 2) {
	    	*deleted = tmp2;
	    }
	}
}

/** route_neighbors: 
** returns an array of #count# neighbor nodes with priority to closer nodes 
*/
np_node_t** route_neighbors (np_routeglobal_t* rg, int count)
{
    int i = 0, j = 0, Rsize = 0, Lsize = 0, index = 0;
    int ret_size;

    np_node_t*  tmp;
    np_node_t** hosts = (np_node_t**) malloc (sizeof (np_node_t*) * (LEAFSET_SIZE + 1));
    np_node_t** ret   = (np_node_t**) malloc (sizeof (np_node_t*) * (count + 1));

    pthread_mutex_lock (&rg->lock);

    Lsize = leafset_size (rg->leftleafset);
    Rsize = leafset_size (rg->rightleafset);

    if (count > Rsize + Lsize) ret_size = Rsize + Lsize;
	else ret_size = count;

    /* creat a jrb of leafset pointers sorted on distance */
    for (i = 0; i < Lsize; i++)
	{
	    tmp = rg->leftleafset[i];
	    hosts[index++] = tmp;
	}

    for (i = 0; i < Rsize; i++)
	{
	    tmp = rg->rightleafset[i];
	    hosts[index++] = tmp;
	}

    hosts[index] = NULL;
    /* sort aux */
    sort_hosts (hosts, rg->me->key, index);

    for (i = 0; i < ret_size; i++)
	{
	    tmp = hosts[i];
	    ret[i] = tmp; // np_node_lookup(rg->me->node_tree, tmp->key, 0);
	    // ret[i] = np_node_get_by_hostname (rg->me->ng, tmp->dns_name, tmp->port);
	}

    ret[i] = NULL;

    free (hosts);
    pthread_mutex_unlock (&rg->lock);

    return ret;
}


/** route_update:
** updated the routing table in regard to #node#. If the host is joining
** the network (and #joined# == 1), then it is added to the routing table
** if it is appropriate. If it is leaving the network (and #joined# == 0),
** then it is removed from the routing tables 
*/
void route_update (np_routeglobal_t* rg, np_node_t* node, int joined)
{
	log_msg(LOG_INFO, "update in routing: %d %s", joined, key_get_as_string(node->key));

	// printf ("route.c (%d): route_update\n", getpid());
    int i, j, k, found, pick;
    np_node_t* tmp;
    np_node_t* deleted = NULL;
    np_node_t* added = NULL;

    pthread_mutex_lock (&rg->lock);
    if (key_equal (rg->me->key, node->key))
	{
        // printf ("route.c (%d): route_update same key ???\n", getpid());
	    pthread_mutex_unlock (&rg->lock);
	    return;
	}

    i = key_index (rg->me->key, node->key);
    j = hexalpha_to_int (key_get_as_string (node->key)[i]);

    /* a node joins the routing table */
    if (joined)
	{
	    found = 0;
	    for (k = 0; k < MAX_ENTRY; k++)
		{
		    if (rg->table[i][j][k] == NULL)
			{
			    rg->table[i][j][k] = np_node_lookup (rg->me->node_tree, node->key, 1);
			    // rg->table[i][j][k] = np_node_get_by_hostname (rg->me->ng, node->dns_name, node->port);
			    leafset_update (rg, node, joined, &deleted, &added);
			    // printf ("route.c (%d): route_update found index to insert leaf\n", getpid());

			    found = 1;
			    break;
			}
// 		    else if (rg->table[i][j][k] != NULL &&
// 		    		 key_equal (np_node_get_key(rg->table[i][j][k]), node->key ))
// 			{
		        // printf ("route.c (%d): route_update found already existing\n", getpid());
			    // pthread_mutex_unlock (&rg->lock);
			    // return;
// 			}
		}
	    /* the entry array is full we have to get rid of one */
	    /* replace the new node with the node with the highest latency in the entry array */
	    if (!found)
		{
		    pick = 0;
		    for (k = 1; k < MAX_ENTRY; k++)
			{
			    if (rg->table[i][j][pick]->success_avg > rg->table[i][j][k]->success_avg  )
			    	pick = k;
			}
		    np_node_release (rg->me->node_tree, rg->table[i][j][pick]->key);
		    rg->table[i][j][pick] = np_node_lookup (rg->me->node_tree, node->key, 1);
		    leafset_update (rg, node, joined, &deleted, &added);
		}

	} else {
		/* delete a node from the routing table */
	    for (k = 0; k < MAX_ENTRY; k++) {
	    	if (rg->table[i][j][k] != NULL && key_equal (rg->table[i][j][k]->key, node->key ))
	    	{
	    		np_node_release(rg->me->node_tree, rg->table[i][j][k]->key);
	    		rg->table[i][j][k] = NULL;
	    		break;
	    	}
	    }
	    leafset_update (rg, node, joined, &deleted, &added);
	}

    if (deleted != NULL)
	{
	    leafset_range_update (rg, &(rg->Rrange), &(rg->Lrange));
	    // TODO: add a new update job instead
	    // chimera_update_upcall (state, &(deleted->key), deleted, 0);
	}
    if (added != NULL)
	{
	    leafset_range_update (rg, &(rg->Rrange), &(rg->Lrange));
	    // TODO: add a new update job instead
	    // chimera_update_upcall (state, &(added->key), added, 1);
	}
    pthread_mutex_unlock (&rg->lock);
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
    	log_msg(LOG_ROUTING, "%s", key_get_as_string (rg->leftleafset[i]->key ));

    log_msg(LOG_ROUTING, "LEAFSET RIGHT:");
    Rsize = leafset_size (rg->rightleafset);
    for (i = 0; i < Rsize; i++)
    	log_msg(LOG_ROUTING, "%s", key_get_as_string (rg->rightleafset[i]->key ));
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
		    		log_msg(LOG_ROUTING, "[%d][%d][%d] %s - %s:%d",
		    						 	 i,j,k,
		    						 	 key_get_as_string (rg->table[i][j][k]->key),
										 rg->table[i][j][k]->dns_name,
										 rg->table[i][j][k]->port);
		    	// else
		    	//	fprintf (stderr, "00000000 00000000 00000000 00000000 00000000");
		}
	    // fprintf (stderr, "\n");
	}
    log_msg (LOG_ROUTING, "----------------------------------------------------------------------");
}
