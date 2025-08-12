//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project

#include "np_route.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "neuropil_log.h"

#include "core/np_comp_node.h"
#include "util/np_event.h"
#include "util/np_list.h"

#include "np_constants.h"
#include "np_evloop.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_node.h"
#include "np_settings.h"
#include "np_threads.h"
#include "np_types.h"
#include "np_util.h"

np_module_struct(route) {
  np_state_t *context;
  np_key_t   *my_key;

  np_key_t *table[NP_ROUTES_TABLE_SIZE];
  TSP(uint16_t, route_count);

  np_sll_t(np_key_ptr, left_leafset);
  np_sll_t(np_key_ptr, right_leafset);

  uint16_t leafset_size;

  np_dhkey_t Rrange;
  np_dhkey_t Lrange;

  TSP(uint16_t, leafset_left_count);
  TSP(uint16_t, leafset_right_count);
};

void _np_route_append_leafset_to_sll(np_key_ptr_sll_t *left_leafset,
                                     np_sll_t(np_key_ptr, result));

bool __np_route_periodic_log(np_state_t               *context,
                             NP_UNUSED np_util_event_t event) {
  if (np_module_initiated(route)) {

    TSP_GET(uint16_t, np_module(route)->route_count, route_count);
    TSP_GET(uint16_t, np_module(route)->leafset_left_count, leafset_left_count);
    TSP_GET(uint16_t,
            np_module(route)->leafset_right_count,
            leafset_right_count);

    log_info(LOG_ROUTING,
             NULL,
             "[routing capacity] route total:%" PRIu16 "/%" PRIu16
             "=%f%% leafset:%" PRIu16 "+%" PRIu16 "=%" PRIu16 "/%" PRIu16 "=%f",
             route_count,
             NP_ROUTES_TABLE_SIZE,
             route_count / (NP_ROUTES_TABLE_SIZE + 0.0),
             leafset_left_count,
             leafset_right_count,
             leafset_left_count + leafset_right_count,
             np_module(route)->leafset_size * 2,
             (leafset_left_count + leafset_right_count) /
                 (0.0 + np_module(route)->leafset_size * 2));
  }
  return true;
}
/* route_init:
 * Initiates routing table and leafsets
 */
bool _np_route_init(np_state_t *context, np_key_t *me) {
  if (!np_module_initiated(route)) {
    np_module_malloc(route);
    assert(me != NULL);

    for (int i = 0; i < NP_ROUTES_TABLE_SIZE; i++) {
      _module->table[i] = NULL;
    }
    _module->my_key = me;
    np_ref_obj(np_key_t, me, ref_route_routingtable_mykey);
    TSP_INITD(_module->route_count, 0);
    TSP_INITD(_module->leafset_left_count, 0);
    TSP_INITD(_module->leafset_right_count, 0);

    _module->leafset_size = context->settings->leafset_size;

    sll_init(np_key_ptr, _module->left_leafset);
    sll_init(np_key_ptr, _module->right_leafset);

    _np_dhkey_assign(&np_module(route)->Rrange,
                     &np_module(route)->my_key->dhkey);
    _np_dhkey_assign(&np_module(route)->Lrange,
                     &np_module(route)->my_key->dhkey);
    // np_dhkey_t half = np_dhkey_half(context);
    // _np_dhkey_add(&np_module(route)->Rrange,
    // &np_module(route)->my_key->dhkey, &quart);
    // _np_dhkey_sub(&np_module(route)->Lrange,
    // &np_module(route)->my_key->dhkey, &half);

    // _np_route_clear();
  }

  return (true);
}

void _np_route_destroy(np_state_t *context) {
  if (np_module_initiated(route)) {
    np_module_var(route);

    np_unref_obj(np_key_t, _module->my_key, ref_route_routingtable_mykey);

    for (int i = 0; i < NP_ROUTES_TABLE_SIZE; i++) {
      if (_module->table[i] != NULL) {
        //_np_route_update (_module->table[i], false, NULL, NULL);
        np_unref_obj(np_key_t, _module->table[i], ref_route_inroute);
      }
    }

    TSP_DESTROY(_module->route_count);
    TSP_DESTROY(_module->leafset_left_count);
    TSP_DESTROY(_module->leafset_right_count);

    sll_iterator(np_key_ptr) iter_leaf;

    log_debug(LOG_ROUTING,
              NULL,
              "unreffing left leafset %d",
              sll_size(_module->left_leafset));
    iter_leaf = sll_first(_module->left_leafset);
    int i     = 0;
    while (iter_leaf != NULL) {
      if (iter_leaf->val != NULL) {
        char tmp[255] = {0};
        _np_dhkey_str(&iter_leaf->val->dhkey, tmp);
        log_debug(LOG_ROUTING, NULL, "unreffing idx: %d %s", i++, tmp);
        //_np_route_leafset_update (iter_leaf->val, false, NULL, NULL);
        np_unref_obj(np_key_t, iter_leaf->val, ref_route_inleafset);
      }
      sll_next(iter_leaf);
    }
    log_debug(LOG_ROUTING,
              NULL,
              "unreffing right leafset %d",
              sll_size(_module->right_leafset));
    iter_leaf = sll_first(_module->right_leafset);
    i         = 0;
    while (iter_leaf != NULL) {
      if (iter_leaf->val != NULL) {
        char tmp[255] = {0};
        _np_dhkey_str(&iter_leaf->val->dhkey, tmp);
        log_debug(LOG_ROUTING, NULL, "unreffing idx: %d %s", i++, tmp);
        //_np_route_leafset_update (iter_leaf->val, false, NULL, NULL);
        np_unref_obj(np_key_t, iter_leaf->val, ref_route_inleafset);
      }
      sll_next(iter_leaf);
    }
    sll_free(np_key_ptr, _module->left_leafset);
    sll_free(np_key_ptr, _module->right_leafset);

    np_module_free(route);
  }
}

/**
 ** _np_route_leafset_update:
 ** this function is called whenever a _np_route_update is called the joined
 ** is 1 if the node has joined and 0 if a node is leaving.
 **/
void _np_route_leafset_update(np_key_t  *node_key,
                              bool       joined,
                              np_key_t **deleted,
                              np_key_t **added) {
  np_ctx_memory(node_key);

  if (!np_module_initiated(route) || np_module(route)->my_key == NULL) return;

  if (_np_key_cmp(node_key, np_module(route)->my_key) == 0) return;

  if (added != NULL) *added = NULL;
  if (deleted != NULL) *deleted = NULL;
  np_key_t *add_to       = NULL;
  np_key_t *deleted_from = NULL;

  _LOCK_MODULE(np_routeglobal_t) {
    np_key_ptr find_right = sll_find(np_key_ptr,
                                     np_module(route)->right_leafset,
                                     node_key,
                                     _np_key_cmp,
                                     NULL);
    np_key_ptr find_left  = sll_find(np_key_ptr,
                                    np_module(route)->left_leafset,
                                    node_key,
                                    _np_key_cmp,
                                    NULL);

    if (false == joined) {
      if (NULL != find_right) {
        deleted_from = (np_key_t *)node_key;
        sll_remove(np_key_ptr,
                   np_module(route)->right_leafset,
                   node_key,
                   _np_key_cmp_inv);
      } else if (NULL != find_left) {
        deleted_from = (np_key_t *)node_key;
        sll_remove(np_key_ptr,
                   np_module(route)->left_leafset,
                   node_key,
                   _np_key_cmp);
      } else {
        log_debug(LOG_ROUTING,
                  NULL,
                  "leafset did not change as key was not found");
      }
    } else {
      if (NULL != find_right || NULL != find_left) {
        log_debug(LOG_ROUTING | LOG_DEBUG,
                  NULL,
                  "leafset did not change as key was already in leafset");
      } else { /**
                * The key is not in our current leafset. So we need to check if
                * we want to add it to our leafset Cases:
                * 1. Leafset right or left is not fully filled
                *    => Add to leafset
                * 2. Leafsets are fully filled and our new key is between our
                * outer bounds
                *    => We need to insert the key at the appropiate point in the
                * list (another key is removed from our leafset)
                * 3. Leafsets are fully filled and our new key is further away
                * then our outer bounds
                *    => No action required
                */
        np_dhkey_t my_inverse_dhkey = {0};
        np_dhkey_t dhkey_half_o     = np_dhkey_half(context);
        _np_dhkey_add(&my_inverse_dhkey,
                      &np_module(route)->my_key->dhkey,
                      &dhkey_half_o);

        if (_np_dhkey_between(&node_key->dhkey,
                              &np_module(route)->my_key->dhkey,
                              &my_inverse_dhkey,
                              true)) {
          if (sll_size(np_module(route)->right_leafset) <
                  np_module(route)->leafset_size ||
              _np_dhkey_between(&node_key->dhkey,
                                &np_module(route)->my_key->dhkey,
                                &np_module(route)->Rrange,
                                false)) {
            add_to = node_key;
            sll_prepend(np_key_ptr, np_module(route)->right_leafset, node_key);
            _np_keycache_sort_keys_kd(np_module(route)->right_leafset,
                                      &np_module(route)->my_key->dhkey);
          }

          // Cleanup of leafset / resize leafsets to max size if necessary
          if (sll_size(np_module(route)->right_leafset) >
              np_module(route)->leafset_size) {
            deleted_from =
                sll_tail(np_key_ptr, np_module(route)->right_leafset);
          }
        } else // if (_np_dhkey_between(&node_key->dhkey, &my_inverse_dhkey,
               // &np_module(route)->my_key->dhkey, true))
        {
          if (sll_size(np_module(route)->left_leafset) <
                  np_module(route)->leafset_size ||
              _np_dhkey_between(&node_key->dhkey,
                                &np_module(route)->Lrange,
                                &np_module(route)->my_key->dhkey,
                                false)) {
            add_to = node_key;
            sll_prepend(np_key_ptr, np_module(route)->left_leafset, node_key);
            _np_keycache_sort_keys_kd(np_module(route)->left_leafset,
                                      &np_module(route)->my_key->dhkey);
          }
          // Cleanup of leafset / resize leafsets to max size if necessary
          if (sll_size(np_module(route)->left_leafset) >
              np_module(route)->leafset_size) {
            deleted_from = sll_tail(np_key_ptr, np_module(route)->left_leafset);
          }
        }

        if (deleted_from != NULL && _np_key_cmp(deleted_from, add_to) == 0) {
          // we added and deleted in one. so nothing changed
          deleted_from = NULL;
          add_to       = NULL;
        }
      }
    }

    if (deleted_from != NULL || add_to != NULL) {
      _np_route_leafset_range_update(context);
    }

    if (add_to != NULL) {
      if (added != NULL) *added = add_to;
      np_ref_obj(np_key_t, add_to, ref_route_inleafset);
      log_info(LOG_ROUTING,
               NULL,
               "added   %s to   leafset table.",
               _np_key_as_str(add_to));
    }

    if (deleted_from != NULL) {
      if (deleted != NULL) *deleted = deleted_from;
      np_unref_obj(np_key_t, deleted_from, ref_route_inleafset);
      log_info(LOG_ROUTING,
               NULL,
               "removed %s from leafset table.",
               _np_key_as_str(deleted_from));
    }

    TSP_SET(np_module(route)->leafset_left_count,
            sll_size(np_module(route)->left_leafset));
    TSP_SET(np_module(route)->leafset_right_count,
            sll_size(np_module(route)->right_leafset));
  }
}

np_key_t *_np_route_get_key(np_state_t *context) {
  np_key_t *ret = NULL;
  _LOCK_MODULE(np_routeglobal_t) {
    if (np_module_initiated(route)) {
      ret = np_module(route)->my_key;
      np_ref_obj(np_key_t, ret, FUNC);
    }
  }

  return ret;
}

/** route_get_table:
 ** return the entire routing table
 */
sll_return(np_key_ptr) _np_route_get_table(np_state_t *context) {
  np_sll_t(np_key_ptr, sll_of_keys);
  sll_init(np_key_ptr, sll_of_keys);

  _LOCK_MODULE(np_routeglobal_t) {
    uint16_t i, j, k;
    for (i = 0; i < __MAX_ROW; i++) {
      for (j = 0; j < __MAX_COL; j++) {
        int index = __MAX_ENTRY * (j + (__MAX_COL * (i)));
        for (k = 0; k < __MAX_ENTRY; k++) {
          if (NULL != np_module(route)->table[index + k]) {
            sll_append(np_key_ptr,
                       sll_of_keys,
                       np_module(route)->table[index + k]);
          }
        }
      }
    }

    np_key_ref_list(sll_of_keys, FUNC, NULL);
  }
  return (sll_of_keys);
}

/** _np_route_row_lookup:key
 ** return the row in the routing table that matches the longest prefix with
 *#key#
 **/
sll_return(np_key_ptr)
    _np_route_row_lookup(np_state_t *context, np_dhkey_t dhkey) {
  np_sll_t(np_key_ptr, sll_of_keys);
  sll_init(np_key_ptr, sll_of_keys);

  _LOCK_MODULE(np_routeglobal_t) {
    uint16_t i, j, k;
    i = _np_dhkey_index(&np_module(route)->my_key->dhkey, &dhkey);
    ASSERT(i < __MAX_ROW, "index out of routing table bounds.");
    for (j = 0; j < __MAX_COL; j++) {
      uint16_t index = __MAX_ENTRY * (j + (__MAX_COL * (i)));
      // for (k = 0; k < __MAX_ENTRY; k++) {
      //   np_key_t *_key = np_module(route)->table[index + k];
      // only forward the fastest entry
      np_key_t *_key = np_module(route)->table[index];
      if (_key != NULL && !_np_dhkey_equal(&_key->dhkey, &dhkey)) {
        sll_append(np_key_ptr, sll_of_keys, _key);
      }
      // }
    }

    // sll_append(np_key_ptr, sll_of_keys, np_module(route)->my_key);
    np_key_ref_list(sll_of_keys, FUNC, NULL);
  }

  return (sll_of_keys);
}

sll_return(np_key_ptr)
    _np_route_neighbour_lookup(np_state_t *context, np_dhkey_t dhkey) {
  np_sll_t(np_key_ptr, sll_of_keys);
  sll_init(np_key_ptr, sll_of_keys);

  _LOCK_MODULE(np_routeglobal_t) {
    uint16_t col_index, row_index, entry_index;
    col_index = _np_dhkey_index(&np_module(route)->my_key->dhkey, &dhkey);
    ASSERT(col_index < __MAX_ROW, "index out of routing table bounds.");
    row_index          = _np_dhkey_hexalpha_at(context, &dhkey, col_index);
    uint8_t  max_count = NP_LEAFSET_MAX_ENTRIES;
    uint32_t dhkey_start_index = col_index * row_index;

    bool     left_end = false, right_end = false;
    uint32_t current_table_iterator = 0, current_table_index;
    bool     look_left              = false;

    while (sll_size(sll_of_keys) < max_count && !left_end && !right_end) {
      look_left = !look_left;

      if ((look_left && !left_end) || (!look_left && !right_end)) {
        for (entry_index = 0; entry_index < __MAX_ENTRY; entry_index++) {
          current_table_index =
              dhkey_start_index +
              ((look_left ? -1 : 1) * current_table_iterator) + entry_index;

          np_key_t *_key = np_module(route)->table[current_table_index];
          if (_key != NULL && !_np_dhkey_equal(&_key->dhkey, &dhkey)) {
            sll_append(np_key_ptr, sll_of_keys, _key);
          }

          if (current_table_index == NP_ROUTES_TABLE_SIZE) right_end = true;
          else if (current_table_index == 0) left_end = true;
        }
      }
      if (look_left) current_table_iterator++;
    }
    // sll_append(np_key_ptr, sll_of_keys, np_module(route)->my_key);
    np_key_ref_list(sll_of_keys, FUNC, NULL);
  }

  return (sll_of_keys);
}

void _np_route_append_leafset_to_sll(np_key_ptr_sll_t *leafset,
                                     np_sll_t(np_key_ptr, result)) {
  sll_iterator(np_key_ptr) iter = sll_first(leafset);

  while (iter != NULL) {
    if (iter->val != NULL) {
      // log_debug(LOG_ROUTING | LOG_DEBUG, NULL, "Leafset: (%s)",
      // _np_key_as_str (iter->val));
      sll_append(np_key_ptr, result, iter->val);
    }
    sll_next(iter);
  }
}

/** _np_route_lookup:
 ** returns an array of #count# keys that are acceptable next hops for a
 ** message being routed to #key#.
 */
sll_return(np_key_ptr)
    _np_route_lookup(np_state_t *context, np_dhkey_t key, uint8_t count) {
  uint32_t i, j, k;
  uint8_t  match_col = 0;
  bool     next_hop  = false;

  np_dhkey_t dif1, dif2;
  np_key_t  *tmp_1 = NULL, *tmp_2 = NULL, *min = NULL;

  np_sll_t(np_key_ptr, return_list);
  sll_init(np_key_ptr, return_list);

  _LOCK_MODULE(np_routeglobal_t) {
    np_sll_t(np_key_ptr, key_list);
    sll_init(np_key_ptr, key_list);

    log_debug(LOG_ROUTING | LOG_DEBUG,
              NULL,
              "ME:    (%s)",
              _np_key_as_str(np_module(route)->my_key));

#ifdef DEBUG
    char key_as_str[65] = {0};
    _np_dhkey_str(&key, key_as_str);
    log_debug(LOG_ROUTING | LOG_DEBUG, NULL, "TARGET: %s", key_as_str);
#endif
    /*calculate the leafset and table size */
    // Lsize = sll_size(np_module(route)->left_leafset);
    // Rsize = sll_size(np_module(route)->right_leafset);

    /* if the key is in the leafset range route through leafset */
    /* the additional 2 neuropil nodes pointed by the #hosts# are to consider
     * the node itself and NULL at the end */
    if (count == 1 && _np_dhkey_between(&key,
                                        &np_module(route)->Lrange,
                                        &np_module(route)->Rrange,
                                        true)) {
      log_debug(LOG_ROUTING | LOG_DEBUG, NULL, "routing through leafset");

      _np_route_append_leafset_to_sll(np_module(route)->right_leafset,
                                      key_list);
      _np_route_append_leafset_to_sll(np_module(route)->left_leafset, key_list);

      min = _np_keycache_find_closest_key_to(context, key_list, &key);
      if (NULL != min) {
        np_ref_obj(np_key_t, min);
        sll_append(np_key_ptr, return_list, min);
        log_debug(LOG_ROUTING | LOG_DEBUG,
                  NULL,
                  "++NEXT_HOP = %s",
                  _np_key_as_str(min));
      }
      sll_free(np_key_ptr, key_list);
      _np_threads_unlock_module(context, np_routeglobal_t_lock);
      return (return_list);
    }

    /* check to see if there is a matching next hop (for fast routing) */
    i = _np_dhkey_index(&np_module(route)->my_key->dhkey, &key);
    ASSERT(i < __MAX_ROW, "index out of routing table bounds.");

    match_col = _np_dhkey_hexalpha_at(context, &key, i);

    int index = __MAX_ENTRY * (match_col + (__MAX_COL * (i)));
    for (k = 0; k < __MAX_ENTRY; k++) {
      if (np_module(route)->table[index + k] != NULL) {
        tmp_1 = np_module(route)->table[index + k];
        if (_np_key_get_node(tmp_1)->success_avg > BAD_LINK) {
          next_hop = true;
          break;
        }
      }
    }

    if (true == next_hop && 1 <= count) {
      int index = __MAX_ENTRY * (match_col + (__MAX_COL * (i)));
      // int index = (i * __MAX_ROW + match_col) * __MAX_COL;
      for (k = 0; k < __MAX_ENTRY; k++) {
        if (np_module(route)->table[index + k] != NULL &&
            !_np_dhkey_equal(&np_module(route)->table[index + k]->dhkey,
                             &tmp_1->dhkey)) {
          tmp_2                 = np_module(route)->table[index + k];
          np_node_t *tmp_2_node = _np_key_get_node(tmp_2);
          np_node_t *tmp_1_node = _np_key_get_node(tmp_1);
          // normalize values
          double metric_1 = 1.0 - tmp_1_node->success_avg + tmp_1_node->latency;
          double metric_2 = 1.0 - tmp_2_node->success_avg + tmp_2_node->latency;
          if (metric_1 > metric_2) {
            // node 2 more stable and/or faster than node 1
            tmp_1 = np_module(route)->table[index + k];
          }
        }
      }

      np_ref_obj(np_key_t, tmp_1);
      sll_append(np_key_ptr, return_list, tmp_1);

      log_debug(LOG_ROUTING | LOG_DEBUG,
                NULL,
                "routing through table(%s), NEXT_HOP=%s",
                _np_key_as_str(np_module(route)->my_key),
                _np_key_as_str(tmp_1));

      sll_free(np_key_ptr, key_list);
      _np_threads_unlock_module(context, np_routeglobal_t_lock);
      return (return_list);
    }

    /* if there is no matching next hop we have to find the best next hop */
    /* brute force method to solve count requirements */
    // _np_route_append_leafset_to_sll(np_module(route)->right_leafset,
    // key_list);
    // _np_route_append_leafset_to_sll(np_module(route)->left_leafset,
    // key_list);

    if (count == 0) {
      // consider that this node could be the target as well
      log_debug(LOG_ROUTING | LOG_DEBUG,
                NULL,
                "+me: (%s)",
                /* leaf->ip_string, leaf->port,*/
                _np_key_as_str(np_module(route)->my_key));
      sll_append(np_key_ptr, key_list, np_module(route)->my_key);
    }

    /* find the longest prefix match */
    i = _np_dhkey_index(&np_module(route)->my_key->dhkey, &key);
    ASSERT(i < __MAX_ROW, "index out of routing table bounds.");

    while (sll_size(key_list) == 0 && i >= 0 && i < __MAX_ROW) {
      // search the prefix tree upwards until we have an entry in our list

      for (j = 0; j < __MAX_COL; j++) {
        int index = __MAX_ENTRY * (j + (__MAX_COL * (i)));
        for (k = 0; k < __MAX_ENTRY; k++) {
          if (np_module(route)->table[index + k] != NULL) {
            tmp_1 = np_module(route)->table[index + k];
            if (_np_key_get_node(tmp_1)->success_avg > BAD_LINK) {
              sll_append(np_key_ptr, key_list, tmp_1);
              // log_msg(LOG_ROUTING | LOG_INFO,NULL,
              //         "+Table[%ul][%ul][%ul]: (%s)",
              //         i,
              //         j,
              //         k,
              //         /* leaf->dns_name, leaf->port, */
              //         _np_key_as_str(tmp_1));
            }
          }
        }
      }
      if (i == 0) break;
      else i--;
    }

    if (count == 1) {
      // printf ("route.c (%d): _np_route_lookup bounce count==1 ...\n",
      // getpid());
      min = _np_keycache_find_closest_key_to(context, key_list, &key);

      if (NULL != min) {
        np_ref_obj(np_key_t, min);
        sll_append(np_key_ptr, return_list, min);
      }
      sll_free(np_key_ptr, key_list);
      _np_threads_unlock_module(context, np_routeglobal_t_lock);
      return return_list;
    }

    if (2 <= sll_size(key_list)) {

      /* find the best #count# entries that we looked at ... could be much
       * better */
      _np_keycache_sort_keys_cpm(key_list, &key);

      /* removing potential duplicates from the list */
      // _np_sll_remove_doublettes(key_list);

      sll_append(np_key_ptr, return_list, sll_first(key_list)->val);
      np_ref_obj(np_key_t, sll_first(key_list)->val);
    } else if (0 < sll_size(key_list)) {
      sll_append(np_key_ptr, return_list, sll_first(key_list)->val);
      np_ref_obj(np_key_t, sll_first(return_list)->val);
    }

    /* prevent bouncing -
       not needed anymore, routing table is not our priumary table to look up
       routes, because we use pheromones now */

    sll_free(np_key_ptr, key_list);
  }

  return (return_list);
}

/**
 ** _np_route_leafset_range_update:
 ** updates the leafset range whenever a node leaves or joins to the leafset
 **
 ** fills rrange and lrange with the outer bounds of our leafset
 */
void _np_route_leafset_range_update(np_state_t *context) {

  sll_iterator(np_key_ptr) item = sll_last(np_module(route)->right_leafset);
  if (item != NULL) {
    _np_dhkey_assign(&np_module(route)->Rrange, &item->val->dhkey);
  } else {
    _np_dhkey_assign(&np_module(route)->Rrange,
                     &np_module(route)->my_key->dhkey);
  }

  item = sll_last(np_module(route)->left_leafset);
  if (item != NULL) {
    _np_dhkey_assign(&np_module(route)->Lrange, &item->val->dhkey);
  } else {
    _np_dhkey_assign(&np_module(route)->Lrange,
                     &np_module(route)->my_key->dhkey);
  }
}

/** _np_route_neighbors:
 ** returns an array of #count# neighbor nodes with priority to closer nodes
 **/
sll_return(np_key_ptr) _np_route_neighbors(np_state_t *context) {

  np_sll_t(np_key_ptr, node_keys);
  sll_init(np_key_ptr, node_keys);
  _LOCK_MODULE(np_routeglobal_t) {
    _np_route_append_leafset_to_sll(np_module(route)->left_leafset, node_keys);
    _np_route_append_leafset_to_sll(np_module(route)->right_leafset, node_keys);

    np_key_ref_list(node_keys, FUNC, NULL);
  }
  /* sort aux */
  _np_keycache_sort_keys_kd(node_keys, &np_module(route)->my_key->dhkey);

  return node_keys;
}

/** _np_route_clear
 ** wipe out all entries from the table and the leafset
 **/
void _np_route_clear(np_state_t *context) {
  np_key_t *deleted;
  np_key_t *added;

  _LOCK_MODULE(np_routeglobal_t) {
    /* initialize memory for routing table */
    uint16_t i, j, k;
    for (i = 0; i < __MAX_ROW; i++) {
      for (j = 0; j < __MAX_COL; j++) {
        int index = __MAX_ENTRY * (j + (__MAX_COL * (i)));
        for (k = 0; k < __MAX_ENTRY; k++) {
          np_key_t *item = np_module(route)->table[index + k];
          if (item != NULL) {
            _np_route_update(item, false, &deleted, &added);
            np_module(route)->table[index + k] = NULL;
          }
        }
      }
    }

    _np_route_leafset_clear(context);
  }
}

void _np_route_leafset_clear(np_state_t *context) {
  _LOCK_MODULE(np_routeglobal_t) {
    np_sll_t(np_key_ptr, neighbour_list) = _np_route_neighbors(context);
    sll_iterator(np_key_ptr) iter        = sll_first(neighbour_list);
    np_key_t *deleted                    = NULL;
    np_key_t *added                      = NULL;

    while (iter != NULL) {
      _np_route_leafset_update(iter->val, false, &deleted, &added);
      assert(deleted == iter->val);
      sll_next(iter);
    }
    np_key_unref_list(neighbour_list, "_np_route_neighbors");
    sll_free(np_key_ptr, neighbour_list);

    if (np_module(route)->left_leafset->size != 0) {
      log_msg(LOG_ERROR, NULL, "Could not clear left leafset!");
    }
    if (np_module(route)->right_leafset->size != 0) {
      log_msg(LOG_ERROR, NULL, "Could not clear right leafset!");
    }
  }
}

/** _np_route_update:
 ** updated the routing table in regard to #node#. If the host is joining
 ** the network (and #joined# == 1), then it is added to the routing table
 ** if it is appropriate. If it is leaving the network (and #joined# == 0),
 ** then it is removed from the routing tables
 **/
void _np_route_update(np_key_t  *key,
                      bool       joined,
                      np_key_t **deleted,
                      np_key_t **added) {
  np_ctx_memory(key);

  if (!np_module_initiated(route) || np_module(route)->my_key == NULL) return;

  _LOCK_MODULE(np_routeglobal_t) {
    log_debug(LOG_ROUTING | LOG_INFO,
              NULL,
              "update in routing: %u %s",
              joined,
              _np_key_as_str(key));

    if (_np_dhkey_equal(&np_module(route)->my_key->dhkey, &key->dhkey)) {
      _np_threads_unlock_module(context, np_routeglobal_t_lock);
      return;
    }
    if (added != NULL) *added = NULL;
    if (deleted != NULL) *deleted = NULL;
    np_key_t *add_to       = NULL;
    np_key_t *deleted_from = NULL;

    uint16_t i, j, k, pick;

    i = _np_dhkey_index(&np_module(route)->my_key->dhkey, &key->dhkey);
    ASSERT(i < __MAX_ROW, "index out of routing table bounds.");

    j = _np_dhkey_hexalpha_at(context, &key->dhkey, i);

    int index = __MAX_ENTRY * (j + (__MAX_COL * (i)));

    bool found_empty_routing_table_entry = false;
    bool key_already_in_routing_table    = false;

    /* a node joins the routing table */
    if (true == joined) {
      np_key_t *slowest_node = NULL;
      np_key_t *k_node;
      for (k = 0; k < __MAX_ENTRY; k++) {
        if (np_module(route)->table[index + k] == NULL) {
          np_module(route)->table[index + k] = key;
          found_empty_routing_table_entry    = true;
          add_to                             = key;
          log_debug(LOG_ROUTING,
                    NULL,
                    "%s added to routes->table[%d]",
                    _np_key_as_str(key),
                    index + k);
          break;
        } else {
          if (_np_dhkey_equal(&np_module(route)->table[index + k]->dhkey,
                              &key->dhkey)) {
            key_already_in_routing_table = true;
            break;
          }

          k_node = np_module(route)->table[index + k];
          if (slowest_node == NULL) {
            pick         = k;
            slowest_node = np_module(route)->table[index + k];
          } else {
            // select slower node as pick_node
            if (_np_key_get_node(k_node)->latency >
                _np_key_get_node(slowest_node)->latency) {
              log_debug(LOG_ROUTING | LOG_DEBUG,
                        NULL,
                        "replace latencies at index %d.%d: k.%f < p.%f",
                        index,
                        pick,
                        _np_key_get_node(k_node)->latency,
                        _np_key_get_node(slowest_node)->latency);
              pick         = k;
              slowest_node = k_node;
            }
          }
        }
      }

      /* the entry array is full we have to get rid of one */
      /* replace the new node with the node with the highest latency in the
       * entry array */
      if (!key_already_in_routing_table && !found_empty_routing_table_entry) {
        double latency_diff = _np_key_get_node(slowest_node)->latency -
                              _np_key_get_node(key)->latency;
        if (latency_diff > NP_PI / 1000) // the new node has a reasonably
                                         // lower latency than slowest node
        {
          deleted_from                          = slowest_node;
          np_module(route)->table[index + pick] = key;
          add_to                                = key;
          log_debug(LOG_ROUTING,
                    NULL,
                    "replaced to routes->table[%" PRId32 "] ",
                    index + pick);
        }
      }
    } else {
      /* delete a node from the routing table */
      for (k = 0; k < __MAX_ENTRY; k++) {
        if (np_module(route)->table[index + k] != NULL &&
            _np_dhkey_equal(&np_module(route)->table[index + k]->dhkey,
                            &key->dhkey)) {
          deleted_from                       = key;
          np_module(route)->table[index + k] = NULL;

          log_debug(LOG_ROUTING,
                    NULL,
                    "deleted to routes->table[%" PRId32 "]",
                    index + k);
          break;
        }
      }
    }

    if (add_to != NULL) {
      log_info(LOG_ROUTING | LOG_EXPERIMENT,
               NULL,
               "[routing disturbance] added to routing table: %s",
               _np_key_as_str(add_to));
      np_ref_obj(np_key_t, add_to, ref_route_inroute);
      if (added != NULL) *added = add_to;
      TSP_SET(np_module(route)->route_count, np_module(route)->route_count + 1);
    }

    if (deleted_from != NULL) {
      log_info(LOG_ROUTING | LOG_EXPERIMENT,
               NULL,
               "[routing disturbance] deleted %s from routing table.",
               _np_key_as_str(deleted_from));
      np_unref_obj(np_key_t, deleted_from, ref_route_inroute);
      if (deleted != NULL) *deleted = deleted_from;
      TSP_SET(np_module(route)->route_count, np_module(route)->route_count - 1);
    }

#ifdef DEBUG
    if (add_to != NULL && deleted_from != NULL) {
      log_debug(LOG_ROUTING | LOG_DEBUG,
                NULL,
                "%s is already in routing table.",
                _np_key_as_str(key));
    }
#endif
  }
}

uint16_t _np_get_route_count(np_state_t *context) {
  TSP_GET(uint16_t, np_module(route)->route_count, ret);
  return ret;
}

bool _np_route_has_connection(np_state_t *context) {
  return (_np_get_route_count(context) +
          _np_route_count_neighbors(context, NULL, NULL)) > 0
             ? true
             : false;
}

uint16_t _np_route_count_neighbors(np_state_t *context,
                                   uint16_t   *left,
                                   uint16_t   *right) {
  TSP_GET(uint16_t, np_module(route)->leafset_left_count, l);
  TSP_GET(uint16_t, np_module(route)->leafset_right_count, r);

  if (left != NULL) *left = l;
  if (right != NULL) *right = r;

  return l + r;
}
