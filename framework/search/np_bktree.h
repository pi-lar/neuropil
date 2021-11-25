//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// neuropil is copyright 2016-2018 by pi-lar GmbH

#ifndef NP_FWK_SEARCH_BKTREE_H_
#define NP_FWK_SEARCH_BKTREE_H_

#include "np_dhkey.h"

#include "search/np_index.h"

#include "util/np_mapreduce.h"
#include "util/np_skiplist.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef bool (*compare_bktree_value)(const void* left, const void* right);

struct np_bktree_node_s
{
    uint8_t _max_distance;

    np_dhkey_t     _key;
    np_skiplist_t* _values;

    struct np_bktree_node_s** _child_nodes;
};
typedef struct np_bktree_node_s np_bktree_node_t;

struct np_bktree_s
{
    uint8_t _max_distance;

    np_bktree_node_t _root;

    compare_bktree_value map_func;
};
typedef struct np_bktree_s np_bktree_t;


void np_bktree_init(np_bktree_t* tree, np_dhkey_t key, uint8_t _distance);
void np_bktree_destroy(np_bktree_t* tree);

bool np_bktree_insert(np_bktree_t* tree, np_dhkey_t key, void* value);

void np_bktree_query(np_bktree_t* tree, np_dhkey_t key, void* value, np_map_reduce_t* mr_struct);

void np_bktree_remove(np_bktree_t* tree, np_dhkey_t key, void* value);

#ifdef __cplusplus
}
#endif

#endif // NP_FWK_SEARCH_BKTREE_H
