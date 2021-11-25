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

#include "np_bktree.h"
#include "np_dhkey.h"
#include "np_index.h"

#include "util/np_mapreduce.h"
#include "np_message.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BKTREE_ARRAY_SIZE 256

typedef struct np_searchquery_s np_searchquery_t;

// a searchnode is capable to hold several (well, ehm, thousends ...) search entries.
// the node_id is the main virtual rendezvous point for other peers to route search entries.
// the tree will hold the different entries based on their hamming distance to the search_index.
// we use eight search trees to accommodate for the internal structure of the 256 bit search index.
// in our first implementation we use a bktree because the algorithm is very simplistic, but could be 
// replaced with a structure having better hamming distance metrics (vantage tree?).
// in peers we collect other search nodes that have announced their own id to the other search participants
struct np_searchnode_s 
{    
    np_dhkey_t node_id;

    uint16_t local_table_count;
    np_bktree_t* tree[BKTREE_ARRAY_SIZE];

    uint16_t remote_peer_count;
    np_dhkey_t peers[8][32]; // could be extended with additional third [128] in the future
    uint8_t min_distance; // derived internally from the distance calculation of the peer table

    np_tree_t* results[UINT8_MAX];
    np_searchquery_t* queries[UINT8_MAX];

    np_tree_t* local_search_content;
};
typedef struct np_searchnode_s np_searchnode_t;

// a set of settings that affect how your local node is build up and how it interacts with the
// other peers in the system
struct np_search_settings_s {

    // seed to set up an search space
    np_subject search_space;
    
    // settings how to interact with remote peers
    bool enable_remote_peers;
    char bootstrap_node[255]; // join the following network
    
    // settings that affect your local machine
    uint8_t local_peer_count;
    uint16_t local_table_count; // set BKTREE_ARRAY_SIZE
};
typedef struct np_search_settings_s np_search_settings_t;


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


// a searchquery contains an result index (the reply subject) and a searchentry.
// The searchindex is populated with the np_index data from the query, the intent token contains
// the identity of the query sender and his mandatory search attributes, optional search attributes
// can be used as a second reduce stage to filter results.
struct np_searchquery_s {
    uint8_t query_id;
    char result_uuid[NP_UUID_BYTES];

    np_searchentry_t query_entry;
};


// the searchresult structure is used to store result entries for a user.
// it can be used as a cache to search locally first before hitting the network
struct np_searchresult_s {

    uint8_t query_id;
    char result_uuid[NP_UUID_BYTES]; // same as np_searchquery_s::node_id

    uint8_t hit_counter;
    char* label;
    float level;

    np_searchentry_t* result_entry;
};
typedef struct np_searchresult_s np_searchresult_t;


// initialize the np_searchnode structure and associated message exchanges
np_search_settings_t* np_default_searchsettings();
void np_searchnode_init(np_context* ac, np_search_settings_t* settings);
void np_searchclient_init(np_context* ac);
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
void _np_searchnode_withdraw(np_context* ac, np_searchnode_t* node);
bool _np_searchnode_withdraw_cb(np_context* ac, struct np_message* token_msg);

void _np_searchresult_send(np_context* context, np_subject search_subject, np_searchresult_t* result);

bool _np_new_searchentry_cb(np_context* ac, const np_message_t* const msg, np_tree_t* body, void* localdata);
bool _np_new_searchquery_cb(np_context* ac, const np_message_t* const msg, np_tree_t* body, void* localdata);
bool _np_searchresult_receive_cb(np_context* ac, const np_message_t* const msg, np_tree_t* body, void* localdata);

void _np_search_shutdown_hook(np_context* ac);

#ifdef __cplusplus
}
#endif

#endif // NP_FWK_SEARCH_H_
