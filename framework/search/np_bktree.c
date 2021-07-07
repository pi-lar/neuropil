//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "search/np_bktree.h"

#include "search/np_search.h"

// 256 / 32 = 8
#define BKTREE_SPREAD 8
#define BKTREE_BUCKETSIZE 32

int8_t _compare_npindex_entry_add(const void* old, const void* new) 
{
    np_searchentry_t* _1 = (np_searchentry_t*) old;
    np_searchentry_t* _2 = (np_searchentry_t*) new;

    np_dhkey_t _common = {0}, _diff = {0}, _zero = {0};

    _np_dhkey_and(&_common, &_1->search_index.lower_dhkey, &_2->search_index.lower_dhkey);
    _np_dhkey_xor(&_diff  , &_1->search_index.lower_dhkey, &_2->search_index.lower_dhkey);

    uint8_t _dist_common = 0, _dist_diff = 0;
    _np_dhkey_hamming_distance(&_dist_common, &_zero, &_common);
    _np_dhkey_hamming_distance(&_dist_diff, &_zero, &_diff);

    // fprintf(stdout, "comm: %u diff: %u  --> %d\n", _dist_common, _dist_diff, _dist_common - _dist_diff); 
    if      (_dist_diff > _dist_common) return -1;
    else if (_dist_diff == 0)           return  0;
    else                                return  1;

    // return _dist_common - _dist_diff;
}

// typedef int8_t (*np_cmp_func   )(struct np_map_reduce_s* mr_struct, const void* element);
int8_t _compare_npindex_entry_query(struct np_map_reduce_s* mr_struct, const void* element) 
{
    // fprintf(stdout, "%p -> %p :::: ", element, mr_struct->map_args.io);
    // fflush(stdout);
    return _compare_npindex_entry_add(element, mr_struct->map_args.io);
}

void np_bktree_init(np_bktree_t* tree, np_dhkey_t key, uint8_t distance)
{
    memset(&tree->_root, 0, sizeof(np_bktree_node_t));
    tree->_root._values = NULL;
    tree->_root._child_nodes = NULL;

    _np_dhkey_assign(&tree->_root._key, &key);
}

void __np_bktree_destroy(np_bktree_node_t* tree_node) 
{
    for (uint8_t i = 0; i < BKTREE_BUCKETSIZE; i++)
    {
        if (NULL != tree_node->_child_nodes && NULL != tree_node->_child_nodes[i]) {
            __np_bktree_destroy(tree_node->_child_nodes[i]);
            free(tree_node->_child_nodes[i]);
        }
    }

    if (NULL != tree_node->_child_nodes)
        free(tree_node->_child_nodes);
    
    if (NULL != tree_node->_values)
    {
        np_skiplist_destroy(tree_node->_values);
    }
}

void np_bktree_destroy(np_bktree_t* tree)
{
    __np_bktree_destroy(&tree->_root);
}

bool __np_bktree_insert(np_bktree_node_t* tree_node, np_dhkey_t key, void* value)
{
    if (tree_node == NULL) return false;

    bool ret = false;

    // uint8_t diff = 0;
    // _np_dhkey_hamming_distance(&diff, &key, &tree_node->_key);

    // np_dhkey_t diff = { 0 };
    // uint32_t min_index = UINT32_MAX;
    // uint32_t min_diff  = UINT32_MAX;
    // _np_dhkey_hamming_distance_each(&diff, &key, &tree_node->_key);
    // for (uint16_t i = 0; i < 8; i++) 
    // {
    //     if (diff.t[i] < min_index)
    //     {
    //         min_diff = diff.t[i];
    //         min_index = i;
    //     }
    // }

    np_dhkey_t _common = {0}, _diff = {0}, _zero = {0};

    _np_dhkey_and(&_common, &key, &tree_node->_key);
    _np_dhkey_or(&_diff  , &key, &tree_node->_key);

    uint8_t _dist_common = 0, _dist_diff = 0;
    _np_dhkey_hamming_distance(&_dist_common, &_zero, &_common); // sum of 1 in both np_index
    _np_dhkey_hamming_distance(&_dist_diff, &_zero, &_diff); // sum of 1 in either np_index

    float _jc = (float) _dist_common / _dist_diff; // jaccard index

/*  _np_dhkey_and(&_containment, &tree_node->_key, &key);
    // _np_dhkey_hamming_distance_each(&_hd_zero, &_containment, &_null);
    for (uint8_t i = 0; i < 8; i++) 
    { 
        if (_containment.t[i] > 0) 
        { 
            _do_insert = true;
        }
    }
*/
    // fprintf(stdout, "--- %p:%p ( %f ) ---\n", tree_node, tree_node->_values, _jc);

    if (tree_node->_values != NULL && _jc > 0.9)
    // if (tree_node->values != NULL && _np_dhkey_equal(&tree_node->_key, &key)) 
    {
        // int8_t res = _compare_lph_entry(tree_node->_values->root.item, value); 
        // if (-1 <= res && res <= 1)
        // fprintf(stdout, ":%1.1f:%p !! ", _jc, tree_node->_values);
        np_skiplist_add(tree_node->_values, value);
        ret = true;
    }

    if (ret) return ret;

    // np_dhkey_t diff = {0};
    // uint16_t diff = 0; // _np_dhkey_cmp(&tree_node->_key, &key);
    // _np_dhkey_hamming_distance(&diff, &tree_node->_key, &key);
    // _np_neuropil_bloom_containment(it_2->bloom, it_1->bloom, &_similarity);
    uint8_t bin_index = round(_dist_common / BKTREE_SPREAD);
    // for (uint16_t i = 0; i < BKTREE_SPREAD; i++)
    // {
        // fprintf(stdout, "ibi: %u\n", bin_index);
        // if (_containment.t[i] == 0) continue;

        // int8_t _distance = diff.t[i]; // distance should be zero!
        // uint8_t _index = round(diff/BKTREE_BUCKETSIZE); // distance should be zero!
        // child_nodes_count == _distance+1 except for 0!
        // if (tree_node->_max_child_index < _distance)
        if (NULL == tree_node->_child_nodes)
        {
            // size_t pbkn = sizeof(np_bktree_node_t*);
            // size_t new_size     = 2 * pbkn;
            tree_node->_child_nodes = calloc(BKTREE_BUCKETSIZE, sizeof(np_bktree_node_t*));
            // tree_node->_child_nodes = realloc(tree_node->_child_nodes, new_size);

            // fprintf(stdout, "%u --> req: %d is: %d to zero: %u\n", i, _distance, tree_node->_child_nodes_count, _distance-tree_node->_child_nodes_count);
            // for (uint16_t k = tree_node->_max_child_index+1; k <= _distance; k++) 
            // {
            //     tree_node->_child_nodes[k] = NULL;
            //     // fprintf(stdout, "%u %u %u\n", k, tree_node->_child_nodes_count, _distance+1);
            // }
        }

        // fflush(stdout);
        if (tree_node->_child_nodes != NULL && tree_node->_child_nodes[bin_index] != NULL) 
        {
            // fprintf(stdout, "%1.1f:%u :: ", _jc, bin_index);
            ret = __np_bktree_insert(tree_node->_child_nodes[bin_index], key, value);
        }
        else if (tree_node->_child_nodes != NULL && tree_node->_child_nodes[bin_index] == NULL)
        {
            tree_node->_child_nodes[bin_index] = calloc(1, sizeof(np_bktree_node_t));
            _np_dhkey_assign(&tree_node->_child_nodes[bin_index]->_key, &key);
            tree_node->_child_nodes[bin_index]->_values = malloc(sizeof(np_skiplist_t));
            np_skiplist_init(tree_node->_child_nodes[bin_index]->_values, _compare_npindex_entry_add);
            np_skiplist_add(tree_node->_child_nodes[bin_index]->_values, value);
            // fprintf(stdout, "%1.1f:%u:%p !! ", 1.0, bin_index, tree_node->_child_nodes[bin_index]->_values);
            // fprintf(stdout, "inserted into table\n");
            ret = true;
        } 
        else
        {
            // fprintf(stdout, "häh!\n");
        }
    // }
    return ret;
}

bool np_bktree_insert(np_bktree_t* tree, np_dhkey_t key, void* value)
{
    // fprintf(stdout, "insert: ");
    bool ret = __np_bktree_insert(&tree->_root, key, value);
    // fprintf(stdout, "\n");
    // if (ret) fprintf(stdout, "inserted into table\n");
    return ret;
}

void __np_bktree_query(np_bktree_node_t* tree_node, np_dhkey_t key, void* value, np_map_reduce_t* mr_struct)
{
    // bool _do_map = false;
    // np_lph_t * v = (np_lph_t*) value;

    // np_dhkey_t _containment = { 0 };
    // np_dhkey_t _null = { 0 };
    // np_dhkey_t _hd_zero = {0};

    // uint8_t diff = { 0 };
    // _np_dhkey_hamming_distance(&diff, &key, &tree_node->_key);

    // np_dhkey_t diff = { 0 };
    // uint32_t min_index = UINT32_MAX;
    // uint32_t min_diff  = UINT32_MAX;

    // _np_dhkey_hamming_distance_each(&diff, &key, &tree_node->_key);
    // for (uint16_t i = 0; i < 8; i++) 
    // {
    //     if (diff.t[i] < min_index)
    //     {
    //         min_diff = diff.t[i];
    //         min_index = i;
    //     }
    // }

    np_dhkey_t _common = {0}, _diff = {0}, _zero = {0};

    _np_dhkey_and(&_common, &key, &tree_node->_key);
    _np_dhkey_or(&_diff  , &key, &tree_node->_key);

    uint8_t _dist_common = 0, _dist_diff = 0;
    _np_dhkey_hamming_distance(&_dist_common, &_zero, &_common); // sum of 1 in both np_index
    _np_dhkey_hamming_distance(&_dist_diff, &_zero, &_diff); // sum of 1 in either np_index

    float _jc = (float) _dist_common / _dist_diff; // jaccard index

    // _np_dhkey_and(&_containment, &tree_node->_key, &key);
    // _np_dhkey_hamming_distance_each(&_hd_zero, &_containment, &_null);
    // for (uint8_t i = 0; i < 8; i++) { 
    //     if (_containment.t[i] > 0) 
    //     { 
    //         _do_map = true;
    //         // fprintf(stdout, "!%u(%u) ", _containment.t[i],  _hd_zero.t[i]);
    //     }
    // } 
    // fprintf(stdout, "\n");

    // fprintf(stdout, "--- %p:%p ( %f ) ---\n", tree_node, tree_node->_values, _jc);

    if (tree_node->_values != NULL /*&& _jc > 0.5*/ )
    // if (_do_map && tree_node->_values != NULL) 
    {
        // int8_t res = _compare_lph_entry(tree_node->_values->root.item, value); 
        // if (-1 <= res && res <= 1)
        // fprintf(stdout, ":%:%p !! ", _jc, tree_node->_values);
        // fprintf(stdout, ":%1.1f:%p !! ", _jc, tree_node->_values);
        np_skiplist_map(tree_node->_values, mr_struct);
    }

    // np_dhkey_t diff = {0};
    // uint16_t diff = 0; //  = _np_dhkey_cmp(&tree_node->_key, &key);
    // _np_dhkey_hamming_distance(&diff, &tree_node->_key, &key);

    // uint8_t _index = round(diff/BKTREE_BUCKETSIZE);    
    // if (tree_node->_value != NULL) 
    // {   // not the root node
    //     // for (uint8_t i = 0; i < 8; i++)
    //     // {
    //     // if (diff.t[i] > tree_node->_max_distance) continue;
    //     // if (diff == 0 ) 
    //     {
    //         // fprintf(stdout, "%u:%d! \n", diff, _index);
    //         // fprintf(stdout, "%u:%d! ", diff, _index);
    //         // maybe add the item to result list
    //         // np_lph_t* tmp = (np_lph_t*) tree_node->_value;
    //         fprintf(stdout, "%u:%d !! ", diff, _index);
    //         mr_struct->map(mr_struct, tree_node->_value);
    //     }
    //     // }
    // }

    uint8_t bin_index = round(_dist_common / BKTREE_SPREAD);
    // fprintf(stdout, "qbi: %u ", bin_index);

    // fprintf(stdout, "%u:%u :: ", min_diff, bin_index);

    // if (tree_node->_max_child_index > -1)
    // {
        uint8_t min_idx = (bin_index == 0) ? 0 : bin_index - 1; 
        uint8_t max_idx = (bin_index == BKTREE_BUCKETSIZE) ? BKTREE_BUCKETSIZE : bin_index + 1; 
        // uint8_t j = _index;
        for (uint8_t i = min_idx; i <= max_idx; i++)
        {
        // fprintf(stdout, "%u", i);
        // if (_containment.t[i] == 0) continue;
        // for (int8_t j = 0; j <= _index; j++)
        // {
            if (tree_node->_child_nodes != NULL && tree_node->_child_nodes[i] != NULL)
            {
                // int8_t diff = 0; // _np_dhkey_cmp(&tree_node->_key, &key);
                // _np_dhkey_hamming_distance(&diff, &tree_node->_child_nodes[j]->_key, &key);
                // for (uint8_t i = 0; i < 8; i++)
                // {
                    // if (diff.t[i] > tree_node->_max_distance) continue;
                    // if (diff )
                    // fprintf(stdout, "%u %p --> step --> ", i, tree_node->_child_nodes[i]->_values);
                    __np_bktree_query(tree_node->_child_nodes[i], key, value, mr_struct);
                // }
            }
        }
    // }
    // fprintf(stdout, "<-- step\n");
}

void np_bktree_query(np_bktree_t* tree, np_dhkey_t key, void* value, np_map_reduce_t* mr_struct)
{
    // inspect virtual root node here
    // np_dhkey_t diff = {0};
    // _np_dhkey_hamming_distance_each(&diff, &key, &tree->_root._key);
    // fprintf(stdout, "search: ");
    mr_struct->cmp = _compare_npindex_entry_query;

    __np_bktree_query(&tree->_root, key, value, mr_struct);
    // fprintf(stdout, "\n");

    sll_iterator(void_ptr) iterator = sll_first(mr_struct->map_result);
    while (iterator != NULL) 
    {
        mr_struct->reduce(mr_struct, iterator->val);
        sll_next(iterator);
    }

/*    for (uint8_t i = 0; i < 8; i++)
    {
        int _distance = diff.t[i]; 
        // and step down to real search nodes
        if (_distance <= 24 &&  tree->_root._child_nodes != NULL && tree->_root._child_nodes[_distance] != NULL) 
        {
            // fprintf(stdout, " %d:%d / %p", i, _distance, tree->_root._child_nodes[_distance]);
            __np_bktree_query(tree->_root._child_nodes[_distance], key, value, result_list);
        }
    }
*/
    // fprintf(stdout, "\n");
}
