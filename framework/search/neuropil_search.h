//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#ifndef NEUROPIL_FWK_SEARCH_H_
#define NEUROPIL_FWK_SEARCH_H_

#include "neuropil.h"
#include "neuropil_data.h"

#ifdef __cplusplus
extern "C" {
#endif

// enums defining the text analysis / processing to be performed on the input
// text
enum np_search_analytic_mode { SEARCH_ANALYTICS_OFF = 0, SEARCH_ANALYTICS_ON };
enum np_search_minhash_mode {
  SEARCH_MH_FIX256,
  SEARCH_MH_FIX512,
  SEARCH_MH_DD256
};
enum np_search_shingle_mode {
  SEARCH_1_SHINGLE = 1,
  SEARCH_1_IN_2_SHINGLE,
  SEARCH_3_SHINGLE,
  SEARCH_4_KMER
};
enum np_search_node_type { SEARCH_NODE_SERVER = 1, SEARCH_NODE_CLIENT };

// a set of settings that affect how your local node is build up and how it
// interacts with the other peers in the system
struct np_search_settings {

  // seed to set up an search space
  np_subject search_space;

  // settings how to interact with remote peers
  bool enable_remote_peers;
  char bootstrap_node[255]; // join the following network

  // settings that affect your local machine
  enum np_search_node_type node_type;
  uint8_t                  local_peer_count;
  uint16_t                 local_table_count; // set BKTREE_ARRAY_SIZE

  // settings that affect how text is pre-processed
  enum np_search_analytic_mode analytic_mode;
  enum np_search_minhash_mode  minhash_mode;
  enum np_search_shingle_mode  shingle_mode;

  // settings that affect how queries are matched to entries
  float target_similarity;

} NP_PACKED(1);

typedef np_id np_index;

// a single searchentry containing the np_index to insert the entry into a
// database. the intent token contains the information with regard to issuer,
// url and additional attributes. Attributes can be used in the reduce phase to
// filter according to the user. The searchentry structure is also used when
// querying for entries. In case of a query the intent token contains the
// additional attributes of the searcher as well as the reply the mao reduce
// structure can be used to pass filter functions when creating the searchentry
// i.e. t-idf or other filters
struct np_searchentry {
  // what is shared
  np_index search_index;

  // search entry owner with attributes of the search entry, will be there
  // locally
  struct np_token intent;
} NP_PACKED(1);

// a searchquery contains an result index (the reply subject) and a searchentry.
// The searchindex is populated with the np_index data from the query, the
// intent token contains the identity of the query sender and his mandatory
// search attributes, optional search attributes can be used as a second reduce
// stage to filter results.
struct np_searchquery {
  uint8_t query_id;
  char    result_uuid[NP_UUID_BYTES];
  float   similarity;

  // search query user with attributes of the search query, will be matched with
  // searchentry could be an anonymous user
  struct np_searchentry query_entry;
} NP_PACKED(1);

// the searchresult structure is used to store result entries for a user.
// it can be used as a cache to search locally first before hitting the network
struct np_searchresult {

  uint8_t hit_counter;
  char    label[256];
  float   level;

  struct np_searchentry result_entry;
} NP_PACKED(1);

// mapping code from possible python to internal c structures
struct np_search_settings *np_default_searchsettings();
void np_searchnode_init(np_context *ac, struct np_search_settings *settings);
void np_searchnode_destroy(np_context *ac);

// read a file and create the searchentry using the attributes
// bool py_create_searchentry(np_context* ac, struct np_searchentry* entry,
// const char* text, struct np_searchattributes attributes);
bool pysearch_entry(np_context            *ac,
                    struct np_searchentry *entry,
                    const char            *text,
                    np_attributes_t        attributes);
// read a query text and create the searchentry using the attributes
bool pysearch_query(np_context            *ac,
                    float                  search_probability,
                    struct np_searchquery *query,
                    const char            *query_text,
                    np_attributes_t        attributes);
// pull a searchresult from the query
bool     pysearch_pullresult(np_context            *context,
                             struct np_searchquery *query,
                             struct np_searchresult py_result[],
                             size_t                 elements_to_fetch);
uint32_t pysearch_pullresult_size(np_context            *context,
                                  struct np_searchquery *query);

#ifdef __cplusplus
}
#endif

#endif /* NEUROPIL_FWK_SEARCH_H_ */