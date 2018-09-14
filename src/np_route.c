//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "np_route.h"

#include "np_legacy.h"
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

np_module_struct(route)
{
    np_state_t* context;
    np_key_t* my_key;
    
    np_key_t* table[NP_ROUTES_TABLE_SIZE];
    TSP(uint32_t,route_count);

    np_sll_t(np_key_ptr, left_leafset);
    np_sll_t(np_key_ptr, right_leafset);

    np_dhkey_t Rrange;
    np_dhkey_t Lrange;

    TSP(uint32_t, leafset_left_count);
    TSP(uint32_t, leafset_right_count);

};

void _np_route_append_leafset_to_sll(np_key_ptr_sll_t* left_leafset, np_sll_t(np_key_ptr, result));

/* route_init:
 * Initiates routing table and leafsets
 */
bool _np_route_init (np_state_t* context, np_key_t* me)
{
    if (!np_module_initiated(route)) {
        np_module_malloc(route);
        
        for (int i = 0; i < NP_ROUTES_TABLE_SIZE; i++) {
            _module->table[i] = NULL;
        }
        _module->my_key = NULL;
        TSP_INITD(_module->route_count, 0);
        TSP_INITD(_module->leafset_left_count, 0);
        TSP_INITD(_module->leafset_right_count, 0);
        _np_route_set_key(me);

        sll_init(np_key_ptr, _module->left_leafset);
        sll_init(np_key_ptr, _module->right_leafset);

        // _np_route_clear();
    }

    return (true);
}

/**
 ** _np_route_leafset_update:
 ** this function is called whenever a _np_route_update is called the joined
 ** is 1 if the node has joined and 0 if a node is leaving.
 **/
void _np_route_leafset_update (np_key_t* node_key, bool joined, np_key_t** deleted, np_key_t** added)
{
    log_trace_msg(LOG_TRACE | LOG_ROUTING , ".start.leafset_update");
    np_ctx_memory(node_key);

    TSP_GET(bool, node_key->in_destroy, in_destroy);
    if (!np_module_initiated(route) || np_module(route)->my_key == NULL || (in_destroy == true && joined))
        return;

    if(added != NULL) *added = NULL;
    if (deleted != NULL) *deleted = NULL;
    np_key_t* add_to = NULL;
    np_key_t* deleted_from = NULL;
    bool handeling_left_leafset = true;

    _LOCK_MODULE(np_routeglobal_t)
    {
        if (_np_key_cmp(node_key, np_module(route)->my_key) != 0)
        {
            np_key_ptr find_right = sll_find(np_key_ptr, np_module(route)->right_leafset, node_key, _np_key_cmp_inv, NULL);
            np_key_ptr find_left = sll_find(np_key_ptr, np_module(route)->left_leafset, node_key, _np_key_cmp, NULL);

            if (false == joined) {
                if (NULL != find_right) {
                    handeling_left_leafset = false;
                    deleted_from = (np_key_t*)node_key;
                    sll_remove(np_key_ptr, np_module(route)->right_leafset, node_key, _np_key_cmp_inv);

                }
                else if (NULL != find_left) {
                    deleted_from = (np_key_t*)node_key;
                    sll_remove(np_key_ptr, np_module(route)->left_leafset, node_key, _np_key_cmp);
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

                    sll_iterator(np_key_ptr) right_outer = sll_last(np_module(route)->right_leafset);
                    sll_iterator(np_key_ptr) left_outer = sll_last(np_module(route)->left_leafset);

                    np_dhkey_t my_inverse_dhkey = { 0 };
                    np_dhkey_t dhkey_half_o = np_dhkey_half(context);
                    _np_dhkey_add(&my_inverse_dhkey, &np_module(route)->my_key->dhkey, &dhkey_half_o);

                    if (_np_dhkey_between(&node_key->dhkey, &np_module(route)->my_key->dhkey, &my_inverse_dhkey, true))
                    {
                        handeling_left_leafset = false;
                        if (
                            sll_size(np_module(route)->right_leafset) < NP_ROUTE_LEAFSET_SIZE ||
                            _np_dhkey_between(
                                &node_key->dhkey,
                                &np_module(route)->my_key->dhkey,
                                &right_outer->val->dhkey,
                                false
                            )
                            )
                        {
                            add_to = node_key;
                            sll_append(np_key_ptr, np_module(route)->right_leafset, node_key);
                            _np_keycache_sort_keys_kd(np_module(route)->right_leafset, &np_module(route)->my_key->dhkey);
                        }

                        // Cleanup of leafset / resize leafsets to max size if necessary
                        if (sll_size(np_module(route)->right_leafset) > NP_ROUTE_LEAFSET_SIZE) {
                            deleted_from = sll_tail(np_key_ptr, np_module(route)->right_leafset);
                        }
                    }
                    else //if (_np_dhkey_between(&node_key->dhkey, &my_inverse_dhkey, &np_module(route)->my_key->dhkey, true))
                    {
                        if (
                            sll_size(np_module(route)->left_leafset) < NP_ROUTE_LEAFSET_SIZE ||
                            _np_dhkey_between(
                                &node_key->dhkey,
                                &left_outer->val->dhkey,
                                &np_module(route)->my_key->dhkey,
                                false
                            )
                            )
                        {
                            add_to = node_key;
                            sll_append(np_key_ptr, np_module(route)->left_leafset, node_key);
                            _np_keycache_sort_keys_kd(np_module(route)->left_leafset, &np_module(route)->my_key->dhkey);
                        }

                        // Cleanup of leafset / resize leafsets to max size if necessary
                        if (sll_size(np_module(route)->left_leafset) > NP_ROUTE_LEAFSET_SIZE) {
                            deleted_from = sll_tail(np_key_ptr, np_module(route)->left_leafset);
                        }
                    }

                    if (deleted_from != NULL && _np_key_cmp(deleted_from, add_to) == 0) {
                        // we added and deleted in one. so nothing changed
                        deleted_from = NULL;
                        add_to = NULL;
                    }
                }
            }
        }


        if (deleted_from != NULL || add_to != NULL)
        {
            _np_route_leafset_range_update(context);
        }

        if (add_to != NULL) {
            if (added != NULL) *added = add_to;
            np_ref_obj(np_key_t, add_to, ref_route_inleafset);
            log_msg(LOG_ROUTING | LOG_INFO, "added   %s to   leafset table.", _np_key_as_str(add_to));
            if (handeling_left_leafset) {
                TSP_SCOPE(np_module(route)->leafset_left_count) {
                    np_module(route)->leafset_left_count += 1;
                }
            }
            else {
                TSP_SCOPE(np_module(route)->leafset_right_count) {
                    np_module(route)->leafset_right_count += 1;
                }
            }
        }

        if (deleted_from != NULL) {
            if (deleted != NULL) *deleted = deleted_from;
            np_unref_obj(np_key_t, deleted_from, ref_route_inleafset);
            log_msg(LOG_ROUTING | LOG_INFO, "removed %s from leafset table.", _np_key_as_str(deleted_from));
            if (handeling_left_leafset) {
                TSP_SCOPE(np_module(route)->leafset_left_count) {
                    np_module(route)->leafset_left_count -= 1;
                }
            }
            else {
                TSP_SCOPE(np_module(route)->leafset_right_count) {
                    np_module(route)->leafset_right_count -= 1;
                }
            }
        }
    }
    log_trace_msg(LOG_TRACE | LOG_ROUTING , ".end  .leafset_update");
}

np_key_t* _np_route_get_key(np_state_t* context) {
    np_key_t* ret = NULL;
    _LOCK_MODULE(np_routeglobal_t)
    {
        if (np_module_initiated(route)) {
            ret = np_module(route)->my_key;
            np_ref_obj(np_key_t, ret, FUNC);
        }			
    }
    
    return ret;
}

void _np_route_set_key (np_key_t* new_node_key)
{
    np_ctx_memory(new_node_key);
    _LOCK_MODULE(np_routeglobal_t)
    {
        if(np_module_initiated(route)){
            np_ref_switch(np_key_t, np_module(route)->my_key, ref_route_routingtable_mykey, new_node_key);

            np_dhkey_t half = np_dhkey_half(context);
            _np_dhkey_add(&np_module(route)->Rrange, &np_module(route)->my_key->dhkey, &half);
            _np_dhkey_sub(&np_module(route)->Lrange, &np_module(route)->my_key->dhkey, &half);

            // TODO: re-order table entries and leafset table maybe ?
            // for now: hope that the routing table does it on its own as new keys arrive ...
        }
    }
}

/** route_get_table:
 ** return the entire routing table
 */
sll_return(np_key_ptr) _np_route_get_table (np_state_t* context)
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
                    if (NULL != np_module(route)->table[index + k])
                    {
                        sll_append(np_key_ptr, sll_of_keys, np_module(route)->table[index + k]);
                    }
                }
            }
        }

        np_key_ref_list(sll_of_keys, FUNC,NULL);
    }
    return (sll_of_keys);
}

/** _np_route_row_lookup:key
 ** return the row in the routing table that matches the longest prefix with #key#
 **/
sll_return(np_key_ptr) _np_route_row_lookup (np_key_t* key)
{
    np_ctx_memory(key);

    np_sll_t(np_key_ptr, sll_of_keys);
    sll_init(np_key_ptr, sll_of_keys);

    _LOCK_MODULE(np_routeglobal_t)
    {
        uint16_t i, j, k;
        i = _np_dhkey_index (&np_module(route)->my_key->dhkey, &key->dhkey);
        for (j = 0; j < __MAX_COL; j++)
        {
            int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
            for (k = 0; k < __MAX_ENTRY; k++)
            {
                if (np_module(route)->table[index + k] != NULL &&
                    !_np_dhkey_equal(&np_module(route)->table[index + k]->dhkey, &key->dhkey) )
                {
                    sll_append(np_key_ptr, sll_of_keys, np_module(route)->table[index + k]);
                }
            }
        }

        sll_append(np_key_ptr, sll_of_keys, np_module(route)->my_key);
        np_key_ref_list(sll_of_keys, FUNC, NULL);
    }

    log_trace_msg(LOG_TRACE | LOG_ROUTING , ".end  .route_row_lookup");
    return (sll_of_keys);
}

void _np_route_append_leafset_to_sll(np_key_ptr_sll_t* leafset, np_sll_t(np_key_ptr, result))
{
    sll_iterator(np_key_ptr) iter = sll_first(leafset);

    while(iter != NULL) {
        if(iter->val != NULL) {
            //log_debug_msg(LOG_ROUTING | LOG_DEBUG, "Leafset: (%s)", _np_key_as_str (iter->val));
            sll_append(np_key_ptr, result, iter->val);
        }
        sll_next(iter);
    }
}
/** _np_route_lookup:
 ** returns an array of #count# keys that are acceptable next hops for a
 ** message being routed to #key#.
 */
sll_return(np_key_ptr) _np_route_lookup(np_state_t* context, np_dhkey_t key, uint8_t count)
{
    log_trace_msg(LOG_TRACE | LOG_ROUTING , ".start.route_lookup");
    uint32_t i, j, k, Lsize, Rsize;
    uint8_t match_col = 0;
    bool next_hop = false;

    np_dhkey_t dif1, dif2;
    np_key_t *tmp_1 = NULL, *tmp_2 = NULL, *min = NULL;

    np_sll_t(np_key_ptr, return_list);
    sll_init(np_key_ptr, return_list);

    _LOCK_MODULE(np_routeglobal_t)
    {
        np_sll_t(np_key_ptr, key_list);
        sll_init(np_key_ptr, key_list);

        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "ME:    (%s)", _np_key_as_str(np_module(route)->my_key));

#ifdef DEBUG
        char key_as_str[65] = { 0 };
        np_id2str((np_id*) &key, key_as_str);
        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "TARGET: %s", key_as_str);
#endif
        /*calculate the leafset and table size */
        Lsize = sll_size(np_module(route)->left_leafset);
        Rsize = sll_size(np_module(route)->right_leafset);

        /* if the key is in the leafset range route through leafset */
        /* the additional 2 neuropil nodes pointed by the #hosts# are to consider the node itself and NULL at the end */
        if (count == 1 &&
            _np_dhkey_between (&key, &np_module(route)->Lrange, &np_module(route)->Rrange, true))
        {
            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "routing through leafset");
            sll_append(np_key_ptr, key_list, np_module(route)->my_key);

            _np_route_append_leafset_to_sll(np_module(route)->left_leafset, key_list);
            _np_route_append_leafset_to_sll(np_module(route)->right_leafset, key_list);

            min = _np_keycache_find_closest_key_to (context, key_list, &key);
            if(NULL != min) {				
                ref_replace_reason(np_key_t, min, "_np_keycache_find_closest_key_to", FUNC); 
                sll_append(np_key_ptr, return_list, min);				
 
                log_debug_msg(LOG_ROUTING | LOG_DEBUG, "++NEXT_HOP = %s", _np_key_as_str (min));
            }			

            sll_free (np_key_ptr, key_list);
            _np_threads_unlock_module(context, np_routeglobal_t_lock);
            log_trace_msg(LOG_TRACE | LOG_ROUTING , ".end  .route_lookup");
            return (return_list);
        }

        /* check to see if there is a matching next hop (for fast routing) */
        i = _np_dhkey_index (&np_module(route)->my_key->dhkey, &key);
        match_col = _np_dhkey_hexalpha_at (context, &key, i);

        int index = __MAX_ENTRY * (match_col + (__MAX_COL* (i)));
        for (k = 0; k < __MAX_ENTRY; k++)
        {
            if (np_module(route)->table[index + k] != NULL)
            {
                tmp_1 = np_module(route)->table[index + k];
                if (tmp_1->node->success_avg > BAD_LINK)
                {
                    next_hop = true;
                    break;
                }
            }
        }

        if (true == next_hop && 1 == count)
        {
            int index = __MAX_ENTRY * (match_col + (__MAX_COL* (i)));
            // int index = (i * __MAX_ROW + match_col) * __MAX_COL;
            for (k = 0; k < __MAX_ENTRY; k++)
            {
                if ( np_module(route)->table[index + k] != NULL &&
                     !_np_dhkey_equal(&np_module(route)->table[index + k]->dhkey, &tmp_1->dhkey) )
                {
                    tmp_2 = np_module(route)->table[index + k];
                    // TODO: make it more algorithmic ...
                    if ( tmp_2->node->success_avg >= tmp_1->node->success_avg &&
                         tmp_2->node->latency      < tmp_1->node->latency )
                    {
                        tmp_1 = np_module(route)->table[index + k];
                    }
                }
            }

            np_ref_obj(np_key_t, tmp_1 );
            sll_append(np_key_ptr, return_list, tmp_1);

            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "Routing through Table(%s), NEXT_HOP=%s",
                   _np_key_as_str (np_module(route)->my_key),
                   _np_key_as_str (tmp_1) );

            sll_free (np_key_ptr, key_list);
            _np_threads_unlock_module(context, np_routeglobal_t_lock);
            log_trace_msg(LOG_TRACE | LOG_ROUTING , ".end  .route_lookup");
            return (return_list);
        }

        /* if there is no matching next hop we have to find the best next hop */
        /* brute force method to solve count requirements */

        // log_msg (LOG_ROUTING, "Routing to next closest key I know of:");
        /* look left */

        _np_route_append_leafset_to_sll(np_module(route)->left_leafset, key_list);
        _np_route_append_leafset_to_sll(np_module(route)->right_leafset, key_list);

        if (count == 0) {
            // consider that this node could be the target as well
            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "+me: (%s)",
                    /* leaf->dns_name, leaf->port,*/ _np_key_as_str (np_module(route)->my_key) );
            sll_append(np_key_ptr, key_list, np_module(route)->my_key);
        }

        /* find the longest prefix match */
        i = _np_dhkey_index (&np_module(route)->my_key->dhkey, &key);
        for (j = 0; j < __MAX_COL; j++)
        {
            int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));
            for (k = 0; k < __MAX_ENTRY; k++)
            {
                if (np_module(route)->table[index + k] != NULL)
                {
                    tmp_1 = np_module(route)->table[index + k];
                    if (NULL != tmp_1->node && tmp_1->node->success_avg > BAD_LINK)
                    {
                        sll_append(np_key_ptr, key_list, tmp_1);
                        
                        //log_debug_msg(
                        //	LOG_ROUTING | LOG_DEBUG, "+Table[%ul][%ul][%ul]: (%s)", 
                        //	i, j, k, /* leaf->dns_name, leaf->port, */ _np_key_as_str (tmp_1)
                        //);
                        
                    }
                }
            }
        }

        if (count == 1)
        {
            // printf ("route.c (%d): _np_route_lookup bounce count==1 ...\n", getpid());
            // printTable(state);
            min = _np_keycache_find_closest_key_to (context, key_list, &key);
            
            if (NULL != min) {
                ref_replace_reason(np_key_t, min, "_np_keycache_find_closest_key_to", FUNC);
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
                bool iters_equal = false;
                while (iter1 != NULL)
                {
                    iters_equal = false;
                    iter2 = sll_first(return_list);
                    while (iter2 != NULL)
                    {
                        if (_np_dhkey_equal(&iter2->val->dhkey, &iter1->val->dhkey)==true) {
                            iters_equal = true;
                            break;
                        }
                        sll_next(iter2);
                    }
                    if (iters_equal == false) {
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
            _np_dhkey_distance (&dif2, &key, &np_module(route)->my_key->dhkey);

            // printTable(rg);

            // if (key_equal (dif1, dif2)) ret[0] = rg->me;
            // changed on 03.06.2014 STSW choose the closest neighbour
            if (_np_dhkey_cmp(&dif1, &dif2) <= 0) {
                sll_iterator(np_key_ptr) first = sll_first(return_list);
                np_unref_obj(np_key_t, first->val, FUNC);
                first->val = np_module(route)->my_key;
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
    log_trace_msg(LOG_TRACE | LOG_ROUTING , ".end  .route_lookup");
    return (return_list);
}

/**
 ** _np_route_leafset_range_update:
 ** updates the leafset range whenever a node leaves or joins to the leafset
 **
 ** fills rrange and lrange with the outer bounds of our leafset
 */
void _np_route_leafset_range_update (np_state_t* context)
{
    log_trace_msg(LOG_TRACE | LOG_ROUTING , ".start.leafset_range_update");
    sll_iterator(np_key_ptr) item = sll_last(np_module(route)->right_leafset);

    if(item != NULL) {
        _np_dhkey_assign (&np_module(route)->Rrange, &item->val->dhkey);
    } else {
        _np_dhkey_assign (&np_module(route)->Rrange, &np_module(route)->my_key->dhkey);
    }

    item = sll_last(np_module(route)->left_leafset);
    if(item != NULL) {
        _np_dhkey_assign (&np_module(route)->Lrange, &item->val->dhkey);
    } else {
        _np_dhkey_assign (&np_module(route)->Lrange, &np_module(route)->my_key->dhkey);
    }
    log_trace_msg(LOG_TRACE | LOG_ROUTING , ".end  .leafset_range_update");
}

/** _np_route_neighbors:
 ** returns an array of #count# neighbor nodes with priority to closer nodes
 **/
sll_return(np_key_ptr) _np_route_neighbors (np_state_t* context)
{
    log_trace_msg(LOG_TRACE | LOG_ROUTING , ".start.route_neighbors");

    np_sll_t(np_key_ptr, node_keys);
    sll_init(np_key_ptr, node_keys);
    _LOCK_MODULE(np_routeglobal_t)
    {
        _np_route_append_leafset_to_sll(np_module(route)->left_leafset, node_keys);
        _np_route_append_leafset_to_sll(np_module(route)->right_leafset, node_keys);	

        np_key_ref_list(node_keys, FUNC, NULL);
    }
    /* sort aux */
    _np_keycache_sort_keys_kd(node_keys, &np_module(route)->my_key->dhkey);

    log_trace_msg(LOG_TRACE | LOG_ROUTING , ".end  .route_neighbors");
    return node_keys;
}

/** _np_route_clear
 ** wipe out all entries from the table and the leafset
 **/
void _np_route_clear (np_state_t* context)
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
                    np_key_t* item = np_module(route)->table[index + k];
                    if(item != NULL){
                        _np_route_update(item, false, &deleted, &added);
                        np_module(route)->table[index + k] = NULL;
                    }
                }
            }
        }

        _np_route_leafset_clear(context);
    }
}
void _np_route_leafset_clear (np_state_t* context)
{
    _LOCK_MODULE(np_routeglobal_t)
    {
        np_sll_t(np_key_ptr, neighbour_list) = _np_route_neighbors(context);
        sll_iterator(np_key_ptr) iter = sll_first(neighbour_list);
        np_key_t* deleted = NULL;
        np_key_t* added = NULL;

        while(iter != NULL) {
            _np_route_leafset_update(iter->val,false,&deleted,&added);
            assert (deleted == iter->val);
            sll_next(iter);
        }
        np_key_unref_list(neighbour_list, "_np_route_neighbors");
        sll_free(np_key_ptr, neighbour_list);

        if(np_module(route)->left_leafset->size != 0){
            log_msg(LOG_ERROR,"Could not clear left leafset!");
        }
        if(np_module(route)->right_leafset->size != 0){
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
void _np_route_update (np_key_t* key, bool joined, np_key_t** deleted, np_key_t** added)
{
    np_ctx_memory(key);

    TSP_GET(bool, key->in_destroy, in_destroy);

    if (!np_module_initiated(route) || np_module(route)->my_key == NULL || (in_destroy == true && joined))
        return;

    _LOCK_MODULE(np_routeglobal_t)
    {
        log_debug_msg(LOG_ROUTING | LOG_INFO, "update in routing: %u %s", joined, _np_key_as_str(key));

        if (_np_dhkey_equal (&np_module(route)->my_key->dhkey, &key->dhkey))
        {
            log_trace_msg(LOG_TRACE | LOG_ROUTING , ".end  .route_update");
            _np_threads_unlock_module(context, np_routeglobal_t_lock);
            return;
        }
        if (added != NULL) *added = NULL;
        if (deleted != NULL) *deleted = NULL;
        np_key_t* add_to = NULL;
        np_key_t* deleted_from = NULL;


        uint16_t i, j, k, found, pick;

        i = _np_dhkey_index (&np_module(route)->my_key->dhkey, &key->dhkey);
        j = _np_dhkey_hexalpha_at (context, &key->dhkey, i);

        int index = __MAX_ENTRY * (j + (__MAX_COL* (i)));

        /* a node joins the routing table */
        if (true == joined)
        {
            found = 0;
            for (k = 0; k < __MAX_ENTRY; k++)
            {
                if (np_module(route)->table[index + k] != NULL &&
                    _np_dhkey_equal (&np_module(route)->table[index + k]->dhkey, &key->dhkey))
                {
                    found = 0;
                    break;
                }

                if (np_module(route)->table[index + k] == NULL)
                {
                    np_module(route)->table[index + k] = key;
                    found = 0;
                    add_to = key;
                    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "%s added to routes->table[%d]",_np_key_as_str(key), index+k);
                    break;
                }
                else if (np_module(route)->table[index + k] != NULL &&
                         !_np_dhkey_equal (&np_module(route)->table[index + k]->dhkey, &key->dhkey ))
                {
                    found = 1;
                }
            }

            /* the entry array is full we have to get rid of one */
            /* replace the new node with the node with the highest latency in the entry array */
            if (found)
            {
                pick = 0;
                np_key_t *k_node;
                np_key_t *pick_node;
                for (k = 1; k < __MAX_ENTRY; k++)
                {					
                    pick_node = np_module(route)->table[index + pick];
                    if (pick_node == NULL || pick_node->node == NULL)
                        break;
                    k_node  = np_module(route)->table[index + k];

                    if (k_node == NULL || k_node->node == NULL) {
                        pick = k;
                        pick_node = np_module(route)->table[index + pick];
                        break;
                    }
                    else {
                        log_debug_msg(LOG_ROUTING | LOG_DEBUG, "replace latencies at index %d: t..%f > p..%f ?",
                            index, k_node->node->latency, pick_node->node->latency);

                        if (k_node->node->latency > pick_node->node->latency)
                        {							
                            pick = k;
                        }
                    }
                }
                
                if(pick_node == NULL) {
                    deleted_from = pick_node;
                    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "replaced to routes->table[%"PRId32"]", index + pick);
                    np_module(route)->table[index + pick] = key;
                    add_to = key;
                }
            }
        }
        else
        {
            /* delete a node from the routing table */
            for (k = 0; k < __MAX_ENTRY; k++)
            {
                if (np_module(route)->table[index + k] != NULL &&
                    _np_dhkey_equal (&np_module(route)->table[index + k]->dhkey, &key->dhkey) )
                {
                    deleted_from = key;
                    np_module(route)->table[index + k] = NULL;

                    log_debug_msg(LOG_ROUTING | LOG_DEBUG, "deleted to routes->table[%d]", index+k);
                    break;
                }
            }
        }

        if(add_to != NULL) {
            log_msg(LOG_ROUTING | LOG_INFO, "added   %s to   routing table.", _np_key_as_str(add_to));
            np_ref_obj(np_key_t, add_to, ref_route_inroute);
            if (added != NULL) *added = add_to;
            TSP_SCOPE(np_module(route)->route_count) {
                np_module(route)->route_count += 1;
            }
        }
        
        if(deleted_from != NULL) {
            log_msg(LOG_ROUTING | LOG_INFO, "removed %s from routing table.", _np_key_as_str(deleted_from));
            np_unref_obj(np_key_t, deleted_from, ref_route_inroute);
            if (deleted != NULL) *deleted = deleted_from;
            TSP_SCOPE(np_module(route)->route_count) {
                np_module(route)->route_count -= 1;
            }		
        }

#ifdef DEBUG
        if (add_to != NULL && deleted_from != NULL) {
            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "%s is already in routing table.", _np_key_as_str(key));
        }
#endif
    }
}

uint32_t __np_route_my_key_count_routes(np_state_t* context, bool break_on_first) {    
    TSP_GET(uint32_t, np_module(route)->route_count, ret);

    return ret;
}

bool _np_route_my_key_has_connection(np_state_t* context) {
    return (__np_route_my_key_count_routes(context, true) + _np_route_my_key_count_neighbours(context, NULL, NULL)) > 0 ? true: false;
}

uint32_t _np_route_my_key_count_routes(np_state_t* context) {
    return __np_route_my_key_count_routes(context, false);
}
uint32_t _np_route_my_key_count_neighbours(np_state_t* context, uint32_t* left, uint32_t* right) {
    TSP_GET(uint32_t, np_module(route)->leafset_left_count, l);
    TSP_GET(uint32_t, np_module(route)->leafset_right_count, r);

    if (left != NULL)*left = l;
    if (right != NULL)*right = r;

    return l+r;
}

