//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef NP_FWK_SEARCH_H_
#define NP_FWK_SEARCH_H_

#include "neuropil.h"
#include "neuropil_attributes.h"
#include "neuropil_data.h"
#include "search/neuropil_search.h"

#include "search/np_index.h"
#include "util/np_mapreduce.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BKTREE_ARRAY_SIZE 32

typedef struct np_searchquery_s np_searchquery_t;

// searchnode definition has been moved to the np_search.c file

// search setting are now defined in neuropil_search.h
typedef struct np_search_settings np_search_settings_t;

// a single searchentry containing the np_index_s to insert the entry into a
// database. the intent token contains the information with regard to issuer,
// url and additional attributes. Attributes can be used in the reduce phase to
// filter according to the user. The searchentry structure is also used when
// querying for entries. In case of a query the intent token contains the
// additional attributes of the searcher as well as the reply the mao reduce
// structure can be used to pass filter functions when creating the searchentry
// i.e. t-idf or other filters
struct np_searchentry_s {
  // what is shared
  struct np_index_s search_index;

  // what will be there locally
  struct np_token intent;
  np_map_reduce_t map;
};
typedef struct np_searchentry_s np_searchentry_t;

// a searchquery contains an result index (the reply subject) and a searchentry.
// The searchindex is populated with the np_index_s data from the query, the
// intent token contains the identity of the query sender and his mandatory
// search attributes, optional search attributes can be used as a second reduce
// stage to filter results.
struct np_searchquery_s {
  uint8_t query_id;
  char    result_uuid[NP_UUID_BYTES];
  float   target_similarity;

  np_searchentry_t query_entry;
};

// the searchresult structure is used to store result entries for a user.
// it can be used as a cache to search locally first before hitting the network
struct np_searchresult_s {

  uint8_t query_id;
  char    result_uuid[NP_UUID_BYTES]; // same as np_searchquery_s::node_id

  uint8_t hit_counter;
  char   *label;
  float   level;

  np_searchentry_t *result_entry;
};
typedef struct np_searchresult_s np_searchresult_t;

// initialize the np_searchnode structure and associated message exchanges
np_search_settings_t *np_default_searchsettings();
void np_searchnode_init(np_context *ac, np_search_settings_t *settings);
void np_searchclient_init(np_context *ac);
void np_searchnode_destroy(np_context *ac);

// read a file and create the searchentry using the attributes
bool np_create_searchentry(np_context       *ac,
                           np_searchentry_t *entry,
                           const char       *text,
                           np_attributes_t  *attributes);
// read a query text and create the searchentry using the attributes
bool np_create_searchquery(np_context       *ac,
                           np_searchquery_t *query,
                           const char       *query_text,
                           np_attributes_t  *attributes);

// ads the created searchentry to the global search index
void np_search_add_entry(np_context *ac, np_searchentry_t *entry);
// send the query and search for entries
void np_search_query(np_context *context, np_searchquery_t *query);
// retriev the result for a query
bool    np_search_get_resultset(np_context       *ac,
                                np_searchquery_t *query,
                                np_tree_t        *result_tree);
uint8_t np_search_get_resultset_size(np_searchquery_t *query);

// messages and callbacks required for nodes to interact
// void _np_searchnode_withdraw(np_context* ac, np_searchnode_t* node);
// bool _np_searchnode_withdraw_cb(np_context* ac, struct np_message*
// token_msg);

void _np_searchresult_send(np_context        *context,
                           np_subject         search_subject,
                           np_searchresult_t *result);

void _np_search_shutdown_hook(np_context *ac);

#ifdef __cplusplus
}
#endif

#endif // NP_FWK_SEARCH_H_
