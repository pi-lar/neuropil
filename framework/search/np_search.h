//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// neuropil is copyright 2016-2021 by pi-lar GmbH
//
#ifndef NP_FWK_SEARCH_H_
#define NP_FWK_SEARCH_H_

#include "neuropil.h"
#include "neuropil_data.h"
#include "neuropil_attributes.h"

#include "util/np_mapreduce.h"
#include "np_index.h"
#include "np_bktree.h"

#ifdef __cplusplus
extern "C" {
#endif

// a single searchentry containing the np_index to insert the entry into a database.
// the intent token contains the information with regard to issuer, url and additional
// attributes. Attributes can be used in the reduce phase to filter according to the user.
// The searchentry structure is also used when querying for entries. In case of a query the 
// intent token contains the additional attributes of the searcher as well as the reply
// the mao reduce structure can be used to pass filter functions when creating the searchentry 
// i.e. t-idf or other filters
struct np_searchentry_s 
{
    // what is shared
    struct np_index search_index;

    // what will be there locally
    struct np_token intent;
    np_map_reduce_t map;
};
typedef struct np_searchentry_s np_searchentry_t;

#define BKTREE_ARRAY_SIZE 256

// a searchnode is capable to hold several (well, ehm, thousends ...) search entries.
// the node_id is the main virtual rendezvous point for other peers to route search entries.
// the tree will hold the different entries based on their hamming distance to the search_index.
// we use eight search trees to accomodate for the internal structure of the 256 bit search index.
// in our first implementation we use a bktree because the algorithm is very simplistic, but could be 
// replaced with a structure having better hamming dtstance metrics (vantage tree?).
// in peers we collect other search nodes that have announced their own id to the other search participants
struct np_searchnode_s 
{    
    np_id node_id;

    uint16_t local_peers;
    np_bktree_t* tree[BKTREE_ARRAY_SIZE];

    np_id peers[64][16][4];

    np_tree_t* results[UINT8_MAX];

    uint8_t min_distance;
};
typedef struct np_searchnode_s np_searchnode_t;


// a searchquery contains an result index (the reply subject) and a searchentry.
// The searchindex is populated with the np_index data from the query, the intent token contains
// the identity of the query sender and his mandatory search attributes, optional search attributes
// can be used as a second reduce stage to filter results.
struct np_searchquery_s {
    uint8_t query_id;
    np_id result_idx; // same as np_searchentry_s::search_index

    np_searchentry_t query_entry;
};
typedef struct np_searchquery_s np_searchquery_t;


// the searchresult structure is used to store result entries for a user.
// it can be used as a cache to search locally first before hitting the network
struct np_searchresult_s {
    uint8_t hit_counter;
    char* label;
    float level;

    struct np_token* intent;
};
typedef struct np_searchresult_s np_searchresult_t;


// initialize the np_searchnode structure and associated message exchanges
void np_searchnode_init(np_context* ac);
void np_searchnode_destroy(np_context* ac);

// read a file and create the searchentry using the attributes
bool np_create_searchentry(np_context* ac, np_searchentry_t* entry, const char* text, np_attributes_t* attributes);
// read a query text and create the searchentry using the attributes
bool np_create_searchquery(np_context* ac, np_searchquery_t* query, const char* query_text, np_attributes_t* attributes);

// ads the created searchentry to the global search index
void np_search_add_entry(np_context* ac, np_searchentry_t* entry);
// send the query and search for entries
void np_search_query(np_context* context, np_searchquery_t* query);

np_tree_t* np_search_get_resultset(np_context* context, np_searchquery_t* query);

// messages and callbacks required for nodes to interact
void _np_searchnode_anounce(np_context* ac, np_searchnode_t* node);
bool _np_searchnode_acounce_cb(np_context* ac, struct np_message* token_msg);
void _np_searchnode_withdraw(np_context* ac, np_searchnode_t* node);
bool _np_searchnode_withdraw_cb(np_context* ac, struct np_message* token_msg);

void _np_searchentry_anounce(np_context* ac, np_searchentry_t* entry);
bool _np_searchentry_anounce_cb(np_context* ac, struct np_message* token_msg);
// void _np_searchentry_withdraw(np_context* ac, struct np_searchentry_s* entry);
// bool _np_searchentry_withdraw_cb(np_context* ac, struct np_message* token);

void _np_searchentry_send_query(np_context* ac, np_searchquery_t* query);
void _np_searchentry_query_cb(np_context* ac, struct np_message* query_msg);

void _np_searchentry_send_result(np_context* ac, np_searchentry_t* result);
void _np_searchentry_result_cb(np_context* ac, struct np_message* result);

void _np_search_shutdown_hook(np_context* ac);

#ifdef __cplusplus
}
#endif

#endif // NP_FWK_SEARCH_H_
