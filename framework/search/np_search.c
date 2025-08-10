//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "search/np_search.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http/urldecode.h"
#include "parson/parson.h"

#include "neuropil_data.h"

#include "core/np_comp_msgproperty.h"
#include "http/np_http.h"
#include "search/np_index.h"
#include "util/np_bloom.h"
#include "util/np_cupidtrie.h"
#include "util/np_list.h"
#include "util/np_mapreduce.h"
#include "util/np_minhash.h"
#include "util/np_serialization.h"

#include "np_aaatoken.h"
#include "np_attributes.h"
#include "np_constants.h"
#include "np_data.h"
#include "np_dhkey.h"
#include "np_key.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_message.h"
#include "np_search_mxproperties.c"
#include "np_threads.h"
#include "np_token_factory.h"

// a searchnode is capable to hold several (well, ehm, thousends ...) search
// entries. the node_id is the main virtual rendezvous point for other peers to
// route search entries. the tree will hold the different entries based on their
// hamming distance to the search_index. we use eight search trees to
// accommodate for the internal structure of the 256 bit search index. in our
// first implementation we use a bktree because the algorithm is very
// simplistic, but could be replaced with a structure having better hamming
// distance metrics (vantage tree?). in peers we collect other search nodes that
// have announced their own id to the other search participants
struct np_searchnode_s {
  np_dhkey_t node_id;

  uint8_t             prime_shift;
  uint16_t            local_table_count;
  struct np_cupidtrie tree[BKTREE_ARRAY_SIZE];

  uint16_t   remote_peer_count;
  np_dhkey_t peers[8][32]; // could be extended with additional third [128] in
                           // the future
  uint8_t min_distance; // derived internally from the distance calculation of
                        // the peer table

  np_tree_t        *results[UINT8_MAX];
  np_searchquery_t *queries[UINT8_MAX];
};
typedef struct np_searchnode_s np_searchnode_t;

np_module_struct(search) {
  np_state_t          *context;    // the context
  np_search_settings_t searchcfg;  // store settings for later use
  np_searchnode_t      searchnode; // the searchnode structure
  uint8_t    query_id;    // a global counter of search queries of this nodes
  np_bloom_t peer_filter; // a counting bloom filter to check whether a peer has
                          // already been added
  np_tree_t
      pipeline_results; // pipelines in the meaning of callbacks, used to store
                        // intermediate results for queries / entries / ...

  bool on_shutdown_route;

  np_spinlock_t results_lock[UINT8_MAX];
  np_spinlock_t table_lock[BKTREE_ARRAY_SIZE];
  np_spinlock_t peer_lock[8 + 1];
  np_spinlock_t pipeline_lock;
};

bool _np_new_searchentry_cb(np_context                          *ac,
                            const struct np_e2e_message_s *const msg,
                            np_tree_t                           *body,
                            void                                *localdata);

bool _np_new_searchquery_cb(np_context                          *ac,
                            const struct np_e2e_message_s *const msg,
                            np_tree_t                           *body,
                            void                                *localdata);

bool _np_searchresult_receive_cb(np_context                          *ac,
                                 const struct np_e2e_message_s *const msg,
                                 np_tree_t                           *body,
                                 void *localdata);

struct search_pipeline_result {

  double start_time;
  double stop_time;

  uint8_t remote_distribution_count;

  np_dhkey_t search_subject;
  np_dhkey_t search_index;
  np_dhkey_t sending_peer_dhkey;

  union {
    np_searchquery_t *query;
    np_searchentry_t *entry;
  } obj;
};

static char       *__text_delimiter       = " ,!'.\"-_[]{}/";
static const char *SEARCH_PEERID          = "np:search:peerid";
static const char *SEARCH_PEERTYPE        = "np:search:type";
static const char *SEARCH_RESULTID        = "np:search:resultidx";
static const char *SEARCH_PEERTYPE_HYBRID = "np:search:type:hybrid";
static const char *SEARCH_PEERTYPE_SERVER = "np:search:type:server";
static const char *SEARCH_PEERTYPE_CLIENT = "np:search:type:client";

static const uint16_t NP_SEARCH_CLEANUP_INTERVAL = NP_SEARCH_RESULT_REFRESH_TTL;

bool __np_search_cleanup_pipeline(np_state_t               *context,
                                  NP_UNUSED np_util_event_t args) {

  if (np_module(search)->on_shutdown_route == true) return true;

  np_tree_t      *pipeline_results = &np_module(search)->pipeline_results;
  np_tree_elem_t *tmp              = NULL;

  np_spinlock_lock(&np_module(search)->pipeline_lock);
  RB_FOREACH (tmp, np_tree_s, pipeline_results) {
    struct search_pipeline_result *pipeline = tmp->val.value.v;
    if ((pipeline->stop_time + NP_SEARCH_CLEANUP_INTERVAL) < np_time_now()) {
      np_tree_del_uuid(pipeline_results, tmp->key.value.uuid);
      free(pipeline);
      break;
    }
  }
  np_spinlock_unlock(&np_module(search)->pipeline_lock);

  return true;
}

// map reduce algorithms or parts of those
bool _deprecate_map_func(np_map_reduce_t *mr_struct, const void *element) {
  np_searchentry_t *it_1              = (np_searchentry_t *)element;
  np_dhkey_t       *_deprecate_target = (np_dhkey_t *)mr_struct->map_args.io;
  if (it_1 == NULL) return false;

  // needed ?
  np_dhkey_t _common = {0}, _diff = {0};
  _np_dhkey_and(&_common, _deprecate_target, &it_1->search_index.lower_dhkey);
  _np_dhkey_or(&_diff, _deprecate_target, &it_1->search_index.lower_dhkey);

  uint8_t _dist_common = 0, _dist_diff = 0;
  _np_dhkey_hamming_distance(&_dist_common,
                             &dhkey_zero,
                             &_common); // sum of 1 in both np_index
  _np_dhkey_hamming_distance(&_dist_diff,
                             &dhkey_zero,
                             &_diff); // sum of 1 in either np_index

  float _jc = (float)_dist_common / _dist_diff; // jaccard index
  if (_jc > 0.9) {
    // log_msg(LOG_DEBUG, NULL, "deprecating entry %p (%f)\n", it_1, _jc);
    _np_neuropil_bloom_age_decrement(it_1->search_index._clk_hash);
    float _age = _np_neuropil_bloom_intersect_age(it_1->search_index._clk_hash,
                                                  it_1->search_index._clk_hash);
    if (_age == 0.0) {
      // log_msg(LOG_DEBUG, NULL, "identified entry for deletion %p \n", it_1);
      // log_msg(LOG_DEBUG, NULL,  "R COLLISION: %f <-> %p (%s)", _similarity,
      // it_2->search_index._clk_hash, it_2->intent.subject);
      sll_append(void_ptr, mr_struct->map_result, it_1);
    }
  } else {
    // log_msg(LOG_DEBUG, NULL, "similarity not close enough (%f), deprecation
    // of entry skipped \n", _jc);
  }
  return true;
}

bool _deprecate_reduce_func(np_map_reduce_t *mr_struct, const void *element) {
  if (element == NULL) return false;

  // log_msg(LOG_DEBUG, "deleting entry (%p) \n", element);
  np_searchentry_t    *search_elem = (np_searchentry_t *)element;
  struct np_cupidtrie *trie = (struct np_cupidtrie *)mr_struct->reduce_args.io;

  np_cupidtrie_delete(trie,
                      &search_elem->search_index.lower_dhkey,
                      &search_elem);

  np_tree_insert_str(mr_struct->reduce_result,
                     search_elem->intent.uuid,
                     np_treeval_new_v(search_elem));

  return true;
}

// select all search entries in trie
int8_t _cmp_all_searchentries(np_map_reduce_t *mr_struct, const void *element) {

  np_searchentry_t *_1 = (np_searchentry_t *)mr_struct->map_args.io;
  np_searchentry_t *_2 = (np_searchentry_t *)element;

  np_dhkey_t _common = {0}, _diff = {0};

  _np_dhkey_and(&_common,
                &_1->search_index.lower_dhkey,
                &_2->search_index.lower_dhkey);
  _np_dhkey_xor(&_diff,
                &_1->search_index.lower_dhkey,
                &_2->search_index.lower_dhkey);

  uint8_t _dist_common = 0, _dist_diff = 0;
  _np_dhkey_hamming_distance(&_dist_common, &dhkey_zero, &_common);
  _np_dhkey_hamming_distance(&_dist_diff, &dhkey_zero, &_diff);

  // fprintf(stdout,
  //         "    comm: %u diff: %u  --> %d\n",
  //         _dist_common,
  //         _dist_diff,
  //         _dist_common / _dist_diff);

  float _jc = (float)_dist_common / _dist_diff; // jaccard index
  if (_jc > 0.80) return 0;

  // if (_dist_diff == 0) {
  //   return 0;
  // } else if (_dist_diff > _dist_common) return -1;
  else return 1;

  return 0;
}

bool __np_search_deprecate_entries(np_state_t               *context,
                                   NP_UNUSED np_util_event_t args) {
  struct np_cupidtrie_s *search_tree = NULL;

  if (np_module(search)->on_shutdown_route == true) return true;

  np_dhkey_t _random_dhkey = {0};
  randombytes_buf(&_random_dhkey, NP_FINGERPRINT_BYTES);

  np_map_reduce_t mr = {0};
  mr.cmp             = _cmp_all_searchentries;
  mr.map             = _deprecate_map_func;
  mr.map_args.io     = &_random_dhkey;
  sll_init(void_ptr, mr.map_result);
  mr.reduce         = _deprecate_reduce_func;
  mr.reduce_args.io = NULL;
  mr.reduce_result  = np_tree_create();

  for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count;
       i++) {
    np_spinlock_lock(&np_module(search)->table_lock[i]);
    np_cupidtrie_map_reduce(&np_module(search)->searchnode.tree[i], &mr);
    np_spinlock_unlock(&np_module(search)->table_lock[i]);

    sll_iterator(void_ptr) iterator = sll_first(mr.map_result);
    while (iterator != NULL) {
      np_spinlock_lock(&np_module(search)->table_lock[i]);
      mr.reduce_args.io = &np_module(search)->searchnode.tree[i];
      mr.reduce(&mr, iterator->val);
      np_spinlock_unlock(&np_module(search)->table_lock[i]);

      sll_next(iterator);
    }
    sll_clear(void_ptr, mr.map_result);
  }

  np_tree_elem_t *tmp = NULL;
  RB_FOREACH (tmp, np_tree_s, mr.reduce_result) {
    np_searchentry_t *elem = (np_searchentry_t *)tmp->val.value.v;

    np_index_destroy(&elem->search_index);
    free(elem);
  }
  np_tree_free(mr.reduce_result);

  // static uint16_t i = 0;
  // log_msg(LOG_DEBUG, NULL, "__np_search_deprecate_entries \n");
  fflush(stdout);

  return true;
}

struct __search_table_bucket {
  uint16_t hamming_distance;
  uint16_t index;
};

static int __search_table_bucket_cmp(const void *a, const void *b) {
  const struct __search_table_bucket *da = a, *db = b;

  return da->hamming_distance < db->hamming_distance
             ? -1
             : da->hamming_distance > db->hamming_distance;
}

static JSON_Value *__np_generate_error_json(const char *error,
                                            const char *details) {
  JSON_Value *ret = json_value_init_object();

  json_object_set_string(json_object(ret), "error", error);
  json_object_set_string(json_object(ret), "details", details);

  return ret;
}

void __lower_case(char *str, uint8_t strlen) {
  for (int i = 0; i < strlen; i++) {
    str[i] = tolower(str[i]);
  }
}

void __map_peer_to_subject_mask(
    const char                       *new_peer_type,
    enum np_required_search_subjects *peer_subject_mask) {
  if (0 == strncmp(new_peer_type, SEARCH_PEERTYPE_HYBRID, 22))
    *peer_subject_mask = HYBRID_NODE_PROSUMER;
  if (0 == strncmp(new_peer_type, SEARCH_PEERTYPE_SERVER, 22))
    *peer_subject_mask = SERVER_NODE_PROVIDER;
  if (0 == strncmp(new_peer_type, SEARCH_PEERTYPE_CLIENT, 22))
    *peer_subject_mask = CLIENT_NODE_PROVIDER;
}

void __map_self_to_subject_mask(
    const char                       *new_peer_type,
    enum np_required_search_subjects *peer_subject_mask) {
  if (0 == strncmp(new_peer_type, SEARCH_PEERTYPE_HYBRID, 22))
    *peer_subject_mask = HYBRID_NODE_PROSUMER;
  if (0 == strncmp(new_peer_type, SEARCH_PEERTYPE_SERVER, 22))
    *peer_subject_mask = SERVER_NODE_CONSUMER;
  if (0 == strncmp(new_peer_type, SEARCH_PEERTYPE_CLIENT, 22))
    *peer_subject_mask = CLIENT_NODE_CONSUMER;
}

// map reduce algorithms or parts of those
bool _map_np_searchentry(np_map_reduce_t *mr_struct, const void *element) {
  np_searchentry_t *it_1 = (np_searchentry_t *)mr_struct->map_args.io;
  np_searchentry_t *it_2 = (np_searchentry_t *)element;

  if (it_1 == it_2) return true;
  if (it_1 == NULL || it_2 == NULL) return false;

  // if (it_2->search_index._clk_hash == NULL) return false;

  float _target_similarity =
      np_tree_find_int(mr_struct->map_args.kv_pairs, 1)->val.value.f;

  float _similarity = 0.0;
  // log_msg(LOG_DEBUG, NULL,  "P COLLISION: %p <-> %p ", it_1->intent,
  // it_2->intent);
  _np_neuropil_bloom_similarity(it_2->search_index._clk_hash,
                                it_1->search_index._clk_hash,
                                &_similarity);

  struct np_data_conf conf      = {0};
  np_data_value       val_title = {0};
  if (np_data_ok != np_get_data((np_datablock_t *)it_2->intent.attributes,
                                "title",
                                &conf,
                                &val_title)) {
    val_title.str = "";
  }
  fprintf(stdout,
          "COLLISION: %f <-> %p (%s / %s)\n",
          _similarity,
          it_2->search_index._clk_hash,
          val_title.str,
          it_2->intent.subject);

  if (_similarity > _target_similarity) {
    // log_msg(LOG_DEBUG, NULL, "R COLLISION: %f <-> %p (%s)", _similarity,
    // it_2->search_index._clk_hash, it_2->intent.subject);
    sll_append(void_ptr, mr_struct->map_result, it_2);
  }

  int8_t _continue_mapping = mr_struct->cmp(mr_struct, it_2);

  if (0 >= _continue_mapping) return true;
  else return false;
}

bool _reduce_np_searchentry(np_map_reduce_t *mr_struct, const void *element) {
  if (element == NULL) return false;

  np_searchentry_t *it_1 = (np_searchentry_t *)mr_struct->map_args.io;
  np_searchentry_t *it_2 = (np_searchentry_t *)element;

  np_tree_elem_t *result_elem = NULL;
  if (NULL != (result_elem = np_tree_find_str(mr_struct->reduce_result,
                                              it_2->intent.subject))) {
    np_searchresult_t *result = (np_searchresult_t *)result_elem->val.value.v;
    result->hit_counter++;

    float similarity = 0.0;
    _np_neuropil_bloom_similarity(it_1->search_index._clk_hash,
                                  it_2->search_index._clk_hash,
                                  &similarity);
    if (result->level < similarity) result->level = similarity;
  } else {
    np_searchresult_t *new_result =
        (np_searchresult_t *)malloc(sizeof(np_searchresult_t));
    new_result->hit_counter  = 1;
    new_result->label        = strndup(it_2->intent.subject, 255);
    new_result->result_entry = it_2;
    _np_neuropil_bloom_similarity(it_1->search_index._clk_hash,
                                  it_2->search_index._clk_hash,
                                  &new_result->level);

    np_tree_insert_str(mr_struct->reduce_result,
                       it_2->intent.subject,
                       np_treeval_new_v(new_result));
  }
  return true;
}

int __compare_uint16_t(const void *first, const void *second) {
  if (*(uint16_t *)first > *(uint16_t *)second) return 1;
  if (*(uint16_t *)first < *(uint16_t *)second) return -1;
  return 0;
}

// authz callbacks
bool __np_search_authorize_result_cb(np_context      *ac,
                                     struct np_token *intent_token) {
  np_ctx_cast(ac);

  // TODO: insert currently used result_idx into a tree. stop listening on reply
  // subject once a timeout has been exceeded

  // for now:
  return true;
}

bool __np_search_authorize_entries_cb(np_context      *ac,
                                      struct np_token *intent_token) {
  np_ctx_cast(ac);

  bool                ret  = false;
  struct np_data_conf conf = {0};
  // struct np_data_conf *conf_ptr = &conf;

  np_dhkey_t new_peer_dhkey = {0};
  np_id     *peer_id        = NULL;
  np_id      new_peer_id    = {0};

  // if (np_data_ok != np_get_token_attr_bin(intent_token, "np:key", &conf_ptr,
  // &new_peer_id_ptr) )
  // {
  //     return false;
  // }
  // if (_np_dhkey_equal(&new_peer_id, &np_module(search)->searchnode->node_id))
  // {
  //     return false;
  // }

  // log_msg(LOG_DEBUG, NULL, "authz request %s from %02X%02X%02X%02X%02X%02X :
  // %02X%02X%02X%02X%02X%02X ...",
  //                 intent_token->subject,
  //                 intent_token->issuer[0],     intent_token->issuer[1],
  //                 intent_token->issuer[2],     intent_token->issuer[3],
  //                 intent_token->issuer[4],     intent_token->issuer[5],
  //                 intent_token->public_key[0], intent_token->public_key[1],
  //                 intent_token->public_key[2], intent_token->public_key[3],
  //                 intent_token->public_key[4], intent_token->public_key[5]);

  log_msg(LOG_INFO,
          NULL,
          "search authz grant %s for %02x%02x%02x%02x%02x%02x : "
          "%02x%02x%02x%02x%02x%02x ...",
          intent_token->subject,
          intent_token->issuer[0],
          intent_token->issuer[1],
          intent_token->issuer[2],
          intent_token->issuer[3],
          intent_token->issuer[4],
          intent_token->issuer[5],
          intent_token->public_key[0],
          intent_token->public_key[1],
          intent_token->public_key[2],
          intent_token->public_key[3],
          intent_token->public_key[4],
          intent_token->public_key[5]);

  /*
  Right now it is only possible to return true, we have no added knowledge to
  verify whether a peer is allowed to send entries or queries. As we are using
  private data channels for entries and queries, we have to trust that the nodes
  have passed the node authz callback (otherwise they would not know our peerid)
  possible solutions:
      - use a bloom filter to check whether a node has send it peer information
  before
      - use a set of known identities (needs-preseeding)
      - use a governance node and forward the authorization requests to this
  node
      - ...

  np_dhkey_t dh_diff_index = {0};
  _np_dhkey_hamming_distance_each(&dh_diff_index, &new_peer_id,
  &np_module(search)->searchnode->node_id);

  for (uint8_t j = 0; j < 8; j++)
  {
      uint8_t index = dh_diff_index.t[j];
      if (!ret &&
  _np_dhkey_equal(&np_module(search)->searchnode->peers[j][index], &new_peer_id)
  )
      {
          log_msg(LOG_DEBUG,NULL,  "authz granted %s for
  %02X%02X%02X%02X%02X%02X : %02X%02X%02X%02X%02X%02X ...",
  intent_token->subject, intent_token->issuer[0], intent_token->issuer[1],
  intent_token->issuer[2], intent_token->issuer[3], intent_token->issuer[4],
  intent_token->issuer[5], intent_token->public_key[0],
  intent_token->public_key[1], intent_token->public_key[2],
  intent_token->public_key[3], intent_token->public_key[4],
  intent_token->public_key[5]); ret = true;
      }
  }

  return ret;
  */
  return true;
}

bool __np_search_authorize_node_cb(np_context      *ac,
                                   struct np_token *intent_token) {
  np_ctx_cast(ac);
  np_searchnode_t *searchnode = &np_module(search)->searchnode;

  if (np_module(search)->peer_filter._bitset == NULL) {
    struct np_bloom_optable_s counting_op = {
        .add_cb   = _np_counting_bloom_add,
        .check_cb = _np_counting_bloom_check,
        .clear_cb = _np_counting_bloom_clear,
    };
    np_bloom_t *_filter = _np_counting_bloom_create(4096, 8, 1);
    _filter->op         = counting_op;
    memcpy(&np_module(search)->peer_filter, _filter, sizeof(np_bloom_t));
  }

  bool ret = false;

  np_dhkey_t _zero = {0};

  struct np_data_conf  conf     = {0};
  struct np_data_conf *conf_ptr = &conf;

  enum np_required_search_subjects peer_subject_mask;

  np_dhkey_t     new_peer_dhkey    = {0};
  char           new_peer_type[22] = {0};
  unsigned char *bin_data          = NULL;
  // np_id new_peer_id = NULL;
  // log_msg(LOG_DEBUG, NULL, "authz request %s from %02X%02X%02X%02X%02X%02X :
  // %02X%02X%02X%02X%02X%02X ...",
  //                 intent_token->subject,
  //                 intent_token->issuer[0],     intent_token->issuer[1],
  //                 intent_token->issuer[2],     intent_token->issuer[3],
  //                 intent_token->issuer[4],     intent_token->issuer[5],
  //                 intent_token->public_key[0], intent_token->public_key[1],
  //                 intent_token->public_key[2], intent_token->public_key[3],
  //                 intent_token->public_key[4], intent_token->public_key[5]);

  if (np_data_ok != np_get_token_attr_bin(intent_token,
                                          SEARCH_PEERID,
                                          &conf_ptr,
                                          &bin_data)) {
    return false;
  }
  memcpy(&new_peer_dhkey, bin_data, NP_FINGERPRINT_BYTES);

  if (_np_dhkey_equal(&new_peer_dhkey, &searchnode->node_id) ||
      _np_dhkey_equal(&new_peer_dhkey, &_zero)) {
    return false;
  }

  if (np_data_ok != np_get_token_attr_bin(intent_token,
                                          SEARCH_PEERTYPE,
                                          &conf_ptr,
                                          &bin_data)) {
    return false;
  }
  memcpy(new_peer_type, bin_data, conf_ptr->data_size);
  new_peer_type[conf_ptr->data_size] = '\0';
  __map_peer_to_subject_mask(new_peer_type, &peer_subject_mask);
  // if (!FLAG_CMP(peer_subject_mask, SEARCH_SUBJECT_ENTRY) ||
  //     !FLAG_CMP(peer_subject_mask, SEARCH_SUBJECT_QUERY) ||
  //     !FLAG_CMP(peer_subject_mask, SEARCH_SUBJECT_RESULT))
  // {
  //   return false;
  // }

  np_spinlock_lock(&np_module(search)->peer_lock[8]);
  if (np_module(search)->peer_filter.op.check_cb(
          &np_module(search)->peer_filter,
          new_peer_dhkey)) {
    log_msg(LOG_DEBUG,
            NULL,
            "re-evaluation of  node as search peer %08" PRIx32 ":%08" PRIx32
            " skipped ...",
            new_peer_dhkey.t[0],
            new_peer_dhkey.t[1]);
    np_spinlock_unlock(&np_module(search)->peer_lock[8]);
    return true;
  }
  np_spinlock_unlock(&np_module(search)->peer_lock[8]);

  log_msg(LOG_DEBUG,
          NULL,
          "found node as search peer, peer id is %08" PRIx32 ":%08" PRIx32 "",
          new_peer_dhkey.t[0],
          new_peer_dhkey.t[1]);

  // if (strncmp(intent_token->subject, SEARCH_NODE_SUBJECT, 21))
  // {
  np_dhkey_t dh_diff_index = {0};
  np_dhkey_t to_delete     = {0};

  // log_msg(LOG_DEBUG, NULL, "checking search node as peer:
  // %02X%02X%02X%02X%02X%02X",
  //                 intent_token->issuer[0],     intent_token->issuer[1],
  //                 intent_token->issuer[2],     intent_token->issuer[3],
  //                 intent_token->issuer[4],     intent_token->issuer[5]);

  // check for chunked hamming distance to catch the index
  _np_dhkey_hamming_distance_each(&dh_diff_index,
                                  &new_peer_dhkey,
                                  &searchnode->node_id);

  // setup competitor entry
  uint8_t dh_diff_new = UINT8_MAX;
  // within the index choose the entry with the lowest overall hamming distance
  _np_dhkey_hamming_distance(&dh_diff_new,
                             &new_peer_dhkey,
                             &searchnode->node_id);

  bool not_subscribed = true;

  for (uint8_t j = 0; j < 8; j++) {
    np_spinlock_lock(&np_module(search)->peer_lock[j]);
    bool    is_zero     = false;
    uint8_t index       = dh_diff_index.t[j];
    uint8_t dh_diff_old = UINT8_MAX;

    // compare hamming distance between old and new data channel
    _np_dhkey_hamming_distance(&dh_diff_old,
                               &searchnode->peers[j][index],
                               &searchnode->node_id);
    is_zero = _np_dhkey_equal(&_zero, &searchnode->peers[j][index]);

    // check whether the node subscription channels has been already added
    if (not_subscribed)
      not_subscribed =
          !_np_dhkey_equal(&searchnode->peers[j][index], &new_peer_dhkey);

    // log_msg(LOG_DEBUG, NULL, "compare node as search peer [%u][%u], distance
    // is %u
    // (%u) (%u:%u)",
    //                 j, index, dh_diff_new.t[j], dh_diff_index.t[j], is_zero,
    //                 exists);

    if ((dh_diff_old > dh_diff_new) || is_zero) {
      _np_dhkey_assign(&to_delete, &searchnode->peers[j][index]);
      _np_dhkey_assign(&searchnode->peers[j][index], &new_peer_dhkey);
      log_msg(LOG_INFO,
              NULL,
              "adding node as search peer [%u][%u], distance is %u",
              j,
              index,
              dh_diff_new);
      np_spinlock_lock(&np_module(search)->peer_lock[8]);
      np_module(search)->peer_filter.op.add_cb(&np_module(search)->peer_filter,
                                               new_peer_dhkey);
      np_spinlock_unlock(&np_module(search)->peer_lock[8]);
    }

    np_spinlock_unlock(&np_module(search)->peer_lock[j]);

    if (not_subscribed && ((dh_diff_old > dh_diff_new) || is_zero)) {
      // search internal message types
      np_sll_t(np_msgproperty_conf_ptr, msgproperties);
      msgproperties = search_peer_msgproperties(context, peer_subject_mask);
      sll_iterator(np_msgproperty_conf_ptr) __np_search_messages =
          sll_first(msgproperties);
      while (__np_search_messages != NULL) {
        np_msgproperty_conf_t *property = __np_search_messages->val;
        property->is_internal           = false;

        char *tmp = property->msg_subject;

        np_generate_subject(&property->subject_dhkey,
                            property->msg_subject,
                            strnlen(property->msg_subject, 256));
        np_generate_subject(&property->subject_dhkey,
                            &new_peer_dhkey,
                            NP_FINGERPRINT_BYTES);

        property->msg_subject = calloc(65, sizeof(char));
        np_id_str(property->msg_subject, &property->subject_dhkey);

        np_msgproperty_register(property);
        np_set_mx_authorize_cb(context,
                               &property->subject_dhkey,
                               __np_search_authorize_entries_cb);

        char _tmp[65] = {0};
        np_id_str(_tmp, &new_peer_dhkey);
        log_msg(LOG_INFO,
                NULL,
                "subscribed to peer search subject %s, peer id is %s / %s",
                property->msg_subject,
                _tmp,
                tmp);
        sll_next(__np_search_messages);
      }
      sll_free(np_msgproperty_conf_ptr, msgproperties);

      ret = true;
      searchnode->remote_peer_count++;
      not_subscribed = false;
    }
    // else
    // {
    // log_msg(LOG_DEBUG, NULL, "checked search node as peer:
    // %02X%02X%02X%02X%02X%02X",
    //                 intent_token->issuer[0],     intent_token->issuer[1],
    //                 intent_token->issuer[2],     intent_token->issuer[3],
    //                 intent_token->issuer[4],     intent_token->issuer[5]);
    // log_msg(LOG_DEBUG, NULL, "checked node as search peer [%u][%u], distance
    // was %u",
    //                 j, index, dh_diff_new);
    // }

    is_zero = _np_dhkey_equal(&_zero, &to_delete);
    if (!is_zero) {
      np_spinlock_lock(&np_module(search)->peer_lock[8]);
      _np_counting_bloom_remove(&np_module(search)->peer_filter, to_delete);
      np_spinlock_unlock(&np_module(search)->peer_lock[8]);
    }
  }
  // }

  return ret;
}

// http handler
int __np_search_handle_http_get(ht_request_t  *ht_request,
                                ht_response_t *ht_response,
                                void          *user_arg) {
  np_context *ac = user_arg;
  np_ctx_cast(ac);

  // log_msg(LOG_DEBUG, NULL, "searching for ...");

  uint16_t    length;
  int         http_status = HTTP_CODE_INTERNAL_SERVER_ERROR; // HTTP_CODE_OK
  JSON_Value *json_obj    = NULL;

  if (NULL != ht_request->ht_path && NULL != ht_request->ht_query_args) {
    char *file_start = ht_request->ht_path + 1; // without leading '/'

    np_tree_elem_t *query_elem =
        np_tree_find_str(ht_request->ht_query_args, "query_text");
    if (NULL == query_elem) {
      log_msg(LOG_DEBUG, NULL, "no query found ...");
      json_obj =
          __np_generate_error_json("request invalid",
                                   "looks like you are using a wrong url ...");
      http_status = HTTP_CODE_BAD_REQUEST;
      goto __json_return__;
    }

    char *search_string = urlDecode(query_elem->val.value.s);
    log_msg(LOG_DEBUG, NULL, "searching for: ## %s ##\n", search_string);

    clock_t start_time;
    clock_t query_stop_time;
    clock_t popro_stop_time;

    start_time            = clock();
    np_searchquery_t sq   = {0};
    np_attributes_t  attr = {0};
    if (np_create_searchquery(context, &sq, search_string, &attr)) {
      sq.target_similarity = 0.75; // TODO: replace with query argument
      np_search_query(context, &sq);

      query_stop_time = clock();
      // wait for external replies
      np_time_sleep(0.500);
      struct search_pipeline_result *pipeline = NULL;
      np_spinlock_lock(&np_module(search)->pipeline_lock);
      {
        pipeline = np_tree_find_uuid(&np_module(search)->pipeline_results,
                                     sq.result_uuid)
                       ->val.value.v;
        if (pipeline) pipeline->stop_time = np_time_now();
      }
      np_spinlock_unlock(&np_module(search)->pipeline_lock);

      if (np_module(search)->searchnode.results[sq.query_id] &&
          np_module(search)->searchnode.results[sq.query_id]->size == 0) {
        np_index_destroy(&sq.query_entry.search_index);
        free(search_string);

        json_obj    = __np_generate_error_json("search invalid",
                                            "no search results found ...");
        http_status = HTTP_CODE_NO_CONTENT;
        goto __json_return__;
      }
      np_tree_insert_str(ht_response->ht_header,
                         "Content-Type",
                         np_treeval_new_s("application/json"));

      np_tree_t *srs_tree = np_tree_create();

      np_data_value search_val_title = {0};
      search_val_title.str           = "";

      uint32_t byte_count = 0;

      np_tree_elem_t *tmp = NULL;
      uint16_t        i   = 0;
      np_spinlock_lock(&np_module(search)->results_lock[sq.query_id]);
      RB_FOREACH (tmp,
                  np_tree_s,
                  np_module(search)->searchnode.results[sq.query_id]) {
        np_searchresult_t *result = tmp->val.value.v;

        np_tree_t          *r_tree    = np_tree_create();
        struct np_data_conf conf      = {0};
        np_data_value       val_title = {0};
        if (np_data_ok !=
            np_get_data(
                (np_datablock_t *)result->result_entry->intent.attributes,
                "title",
                &conf,
                &val_title)) {
          val_title.str = "";
        }
        np_tree_insert_str(r_tree,
                           "hit_counter",
                           np_treeval_new_i(result->hit_counter));
        np_tree_insert_str(r_tree,
                           "similarity",
                           np_treeval_new_f(result->level));
        np_tree_insert_str(r_tree, "label", np_treeval_new_s(result->label));
        np_tree_insert_str(r_tree, "title", np_treeval_new_s(val_title.str));

        // TODO:
        // __encode_intent(r_tree, result->intent);

        byte_count += r_tree->byte_size;
        if (byte_count < UINT16_MAX) {
          np_tree_insert_int(srs_tree, i, np_treeval_new_tree(r_tree));
          log_msg(LOG_DEBUG,
                  NULL,
                  "%5s :: %s :: %3u / %2.2f / %5s",
                  search_val_title.str,
                  tmp->key.value.s,
                  result->hit_counter,
                  result->level,
                  val_title.str);
        } else {
          log_msg(LOG_DEBUG,
                  NULL,
                  "please implement pagination of search results");
        }
        i++;
        np_tree_free(r_tree);
      }
      np_spinlock_unlock(&np_module(search)->results_lock[sq.query_id]);

      popro_stop_time = clock();

      log_msg(LOG_DEBUG,
              NULL,
              "search query took %3.6f seconds",
              (double)(query_stop_time - start_time) / CLOCKS_PER_SEC);
      log_msg(LOG_DEBUG,
              NULL,
              "search popro took %3.6f seconds",
              (double)(popro_stop_time - start_time) / CLOCKS_PER_SEC);

      JSON_Value *search_result_in_json = np_tree2json(context, srs_tree);
      ht_response->ht_body   = np_json2char(search_result_in_json, true);
      ht_response->ht_length = strnlen(ht_response->ht_body, UINT16_MAX + 4096);
      http_status            = HTTP_CODE_OK;

      np_tree_free(srs_tree);
      json_value_free(search_result_in_json);
      np_index_destroy(&sq.query_entry.search_index);

      ht_response->cleanup_body = true;
    } else {
      free(search_string);
      log_msg(LOG_DEBUG, NULL, "no search result");
      json_obj = __np_generate_error_json(
          "request invalid",
          "unable to to create query from arguments ...");
      http_status = HTTP_CODE_BAD_REQUEST;
      goto __json_return__;
    }

    free(search_string);
  } else {
    json_obj = __np_generate_error_json(
        "nothing to do",
        "unable to to create query from arguments ...");
    http_status = HTTP_CODE_NO_CONTENT;
    goto __json_return__;
  }

__json_return__:

  if (json_obj != NULL) {
    log_debug(LOG_DEBUG, NULL, "serialise json response");

    np_tree_insert_str(ht_response->ht_header,
                       "Content-Type",
                       np_treeval_new_s("application/json"));

    ht_response->ht_body   = np_json2char(json_obj, false);
    ht_response->ht_length = strnlen(ht_response->ht_body, UINT16_MAX);

    json_value_free(json_obj);
  }
  ht_response->ht_status = http_status;

  // by now there should be a response
  if (http_status == HTTP_CODE_INTERNAL_SERVER_ERROR) {
    log_msg(LOG_ERROR, NULL, "HTTP return is not defined for this code path");
  }

  return http_status;
}

// pipeline callbacks
bool __np_search_query(np_context                          *ac,
                       const struct np_e2e_message_s *const msg,
                       NP_UNUSED np_tree_t                 *body,
                       void                                *localdata) {
  np_ctx_cast(ac);

  np_tree_t                     *pipeline_results = (np_tree_t *)localdata;
  struct search_pipeline_result *pipeline         = NULL;

  np_spinlock_lock(&np_module(search)->pipeline_lock);
  if (NULL == np_tree_find_uuid(pipeline_results, msg->uuid)) abort();
  else pipeline = np_tree_find_uuid(pipeline_results, msg->uuid)->val.value.v;
  np_spinlock_unlock(&np_module(search)->pipeline_lock);

  np_searchquery_t *query = pipeline->obj.query;

  np_map_reduce_t mr = {.cmp    = _cmp_all_searchentries,
                        .map    = _map_np_searchentry,
                        .reduce = _reduce_np_searchentry};

  mr.map_args.io       = &query->query_entry;
  mr.map_args.kv_pairs = np_tree_create();
  np_tree_insert_int(mr.map_args.kv_pairs,
                     1,
                     np_treeval_new_f(query->target_similarity));
  sll_init(void_ptr, mr.map_result);

  np_subject result_subject = {0};

  if (_np_dhkey_equal(&pipeline->sending_peer_dhkey,
                      &dhkey_zero)) // remote query
  {
    np_spinlock_lock(&np_module(search)->results_lock[query->query_id]);
    mr.reduce_result = np_module(search)->searchnode.results[query->query_id];
    np_spinlock_unlock(&np_module(search)->results_lock[query->query_id]);
  } else { // prepare reply sending by creating the private reply subject
    np_generate_subject(&result_subject,
                        SEARCH_RESULT_SUBJECT,
                        strnlen(SEARCH_RESULT_SUBJECT, 256));
    np_generate_subject(&result_subject,
                        &pipeline->sending_peer_dhkey,
                        NP_FINGERPRINT_BYTES);
  }

  if (mr.reduce_result == NULL) {
    // local query or empty remote query entry
    mr.reduce_result = np_tree_create();
  }

  if (pipeline->remote_distribution_count <= 6) {
    /*    uint16_t min_index[8];
        uint16_t snd_index[8];
        np_dhkey_t min_diff = { .t[0] = UINT32_MAX, .t[1] = UINT32_MAX, .t[2] =
       UINT32_MAX, .t[3] = UINT32_MAX, .t[4] = UINT32_MAX, .t[5] = UINT32_MAX,
       .t[6] = UINT32_MAX, .t[7] = UINT32_MAX, }; for (uint16_t i = 0; i <
       np_module(search)->searchnode.local_table_count; i++)
        {
            // TODO: distance could be the same for two different tables. Right
       now the first table wins. Is there a better solution? np_dhkey_t diff = {
       0 }; _np_dhkey_hamming_distance_each(&diff,
       &query->query_entry.search_index.lower_dhkey,
       &np_module(search)->searchnode.tree[i]->_root._key); for (uint8_t j = 0;
       j < 8; j++)
            {
                if (diff.t[j] < min_diff.t[j])
                {
                    log_msg(LOG_DEBUG, NULL, "         into table %u (distance
       %u [at %u] : old %u)", i , diff.t[j], j, snd_index[j]); snd_index[j] =
       min_index[j]; min_index[j] = i; min_diff.t[j] = diff.t[j];
                }
            }
        }
        */
    uint8_t dh_diff = {0};
    struct __search_table_bucket
        buckets[np_module(search)->searchnode.local_table_count];
    memset(&buckets,
           0,
           np_module(search)->searchnode.local_table_count *
               sizeof(struct __search_table_bucket));

    uint8_t max_query_count =
        (np_module(search)->searchnode.local_table_count < 16)
            ? np_module(search)->searchnode.local_table_count
            : 8;
    for (uint8_t j = 0; j < max_query_count; j++) {

      np_dhkey_t rotated = {0};
      _np_dhkey_assign(&rotated, &np_module(search)->searchnode.node_id);
      // #pragma omp parallel for shared(query)
      for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count;
           i++) {
        _np_dhkey_rotate_left(&rotated,
                              (np_module(search)->searchnode.prime_shift));
        _np_dhkey_hamming_distance(&dh_diff,
                                   &query->query_entry.search_index.lower_dhkey,
                                   &rotated);
        buckets[i].hamming_distance = dh_diff;
        buckets[i].index            = i;
      }
    }
    qsort(buckets,
          np_module(search)->searchnode.local_table_count,
          sizeof(struct __search_table_bucket),
          __search_table_bucket_cmp);
    // log_msg(LOG_DEBUG, NULL,  "         into table: ");
    // for (uint16_t i = 0; i < 16; i++)
    // {
    //             log_msg(LOG_DEBUG,  "%u (%u) : ", buckets[i].index ,
    //             buckets[i].hamming_distance);
    // }
    // log_msg(LOG_DEBUG, NULL,  "");
    // log_msg(LOG_DEBUG, NULL,  "searching in   table: ");
    // #pragma omp parallel for shared(query)

    uint16_t j          = 0;
    uint16_t initial_hd = buckets[0].hamming_distance;
    while (buckets[j].hamming_distance <= (initial_hd + 1)) {

      // for (uint16_t j = 0;
      //      (j < max_query_count) && (mr.reduce_result->size == 0);
      //      j++) {
      log_msg(LOG_INFO,
              msg->uuid,
              "distribution factor was %2d, querying locally in %3d | "
              "distance %3d",
              pipeline->remote_distribution_count,
              buckets[j].index,
              buckets[j].hamming_distance);
      // log_msg(LOG_DEBUG, NULL,  " %2u (distance %3u [at %2u] )",
      // buckets[j].index , buckets[j].hamming_distance, j);
      // np_skipbi_query(&lsh->_skipbi[j], &mr);

      np_spinlock_lock(&np_module(search)->table_lock[j]);
      np_cupidtrie_map_reduce(
          &np_module(search)->searchnode.tree[buckets[j].index],
          &mr);
      np_spinlock_unlock(&np_module(search)->table_lock[j]);

      np_spinlock_lock(&np_module(search)->results_lock[query->query_id]);
      sll_iterator(void_ptr) iterator = sll_first(mr.map_result);
      while (iterator != NULL) {
        mr.reduce(&mr, iterator->val);
        sll_next(iterator);
      }
      np_spinlock_unlock(&np_module(search)->results_lock[query->query_id]);

      // np_bktree_query(np_module(search)->searchnode.tree[ min_index[j] ],
      // entry->query_entry.search_index.upper_dhkey, &entry->query_entry,
      // &mr);
      sll_clear(void_ptr, mr.map_result);
      j++;
    }
  } else {
    log_msg(LOG_DEBUG,
            msg->uuid,
            "distribution factor was %2d, not querying locally",

            pipeline->remote_distribution_count);
  }
  // log_msg(LOG_DEBUG, NULL,  "");

  // if (mr.map_result->size == 0)
  // {
  //     // log_msg(LOG_DEBUG, NULL,  "searching in   table: ");
  //     for (uint16_t j = 0; j < 8; j++)
  //     {
  //         // log_msg(LOG_DEBUG, NULL,  " %2u (distance %3u [at %2u] )",
  //         min_index[j] , min_diff.t[j], j);
  //         // np_skipbi_query(&lsh->_skipbi[j], &mr);
  //         np_bktree_query(np_module(search)->searchnode.tree[ snd_index[j] ],
  //         query->query_entry.search_index.lower_dhkey, &query->query_entry,
  //         &mr);
  //         // np_bktree_query(np_module(search)->searchnode.tree[ min_index[j]
  //         ], entry->query_entry.search_index.upper_dhkey,
  //         &entry->query_entry, &mr);
  //         // sll_clear(void_ptr, mr.map_result);
  //     }
  // }
  // sll_iterator(void_ptr) iterator = sll_first(mr.map_result);
  // while (iterator != NULL)
  // {
  //     mr.reduce(&mr, iterator->val);
  //     sll_next(iterator);
  // }

  if (!_np_dhkey_equal(&pipeline->sending_peer_dhkey, &dhkey_zero)) {
    np_tree_elem_t *tmp = NULL;
    RB_FOREACH (tmp, np_tree_s, mr.reduce_result) {
      np_searchresult_t *result = tmp->val.value.v;
      result->query_id          = query->query_id;
      memcpy(result->result_uuid, query->result_uuid, NP_UUID_BYTES);
      _np_searchresult_send(context, result_subject, result);
    }
    sll_clear(void_ptr, mr.map_result);
    np_tree_free(mr.reduce_result);

    pipeline->stop_time = np_time_now();

    // clean up query
    // np_searchquery_t* query = pipeline->obj.query;
    // np_index_destroy(&query->query_entry.search_index);
    // free(&query->query_entry);
    // free(query);
  }

  np_tree_free(mr.map_args.kv_pairs);
  sll_free(void_ptr, mr.map_result);

  // optional - print result to to log file
  // else
  // {
  //     struct np_data_conf search_conf = { 0 };
  //     np_data_value search_val_title  = { 0 };
  //     if (np_data_ok != np_get_data((np_datablock_t*)
  //     query->query_entry.intent.attributes, "title", &search_conf,
  //     &search_val_title ) )
  //     {
  //         search_val_title.str = "";
  //     }
  //     np_tree_elem_t* tmp = NULL;

  //     np_spinlock_lock(&np_module(search)->results_lock[query->query_id]);
  //     RB_FOREACH(tmp, np_tree_s,
  //     np_module(search)->searchnode.results[query->query_id])
  //     {
  //         np_searchresult_t* result = tmp->val.value.v;

  //         struct np_data_conf conf = { 0 };
  //         np_data_value val_title  = { 0 };
  //         if (np_data_ok != np_get_data((np_datablock_t*)
  //         result->result_entry->intent.attributes, "title", &conf, &val_title
  //         ) )
  //         {
  //             val_title.str = "";
  //         }
  //         log_msg(LOG_INFO, NULL,
  //                           "search result %-5s :: %s :: %3u / %2.2f / %5s",
  //                           search_val_title.str, tmp->key.value.s,
  //                           result->hit_counter, result->level,
  //                           val_title.str);
  //     }
  //     np_spinlock_unlock(&np_module(search)->results_lock[query->query_id]);
  // }

  // np_tree_del_str(pipeline_results, msg->uuid);
  // free(pipeline);

  return true;
}

bool __np_search_add_entry(np_context                          *ac,
                           const struct np_e2e_message_s *const msg,
                           np_tree_t                           *body,
                           void                                *localdata) {
  np_ctx_cast(ac);

  np_tree_t                     *pipeline_results = (np_tree_t *)localdata;
  struct search_pipeline_result *pipeline         = NULL;

  np_spinlock_lock(&np_module(search)->pipeline_lock);
  if (NULL == np_tree_find_uuid(pipeline_results, msg->uuid)) abort();
  else pipeline = np_tree_find_uuid(pipeline_results, msg->uuid)->val.value.v;
  np_spinlock_unlock(&np_module(search)->pipeline_lock);

  /*
     uint16_t min_index[8];
     np_dhkey_t min_diff = { .t[0] = UINT32_MAX, .t[1] = UINT32_MAX, .t[2] =
     UINT32_MAX, .t[3] = UINT32_MAX, .t[4] = UINT32_MAX, .t[5] = UINT32_MAX,
     .t[6] = UINT32_MAX, .t[7] = UINT32_MAX, }; for (uint16_t i = 0; i <
     np_module(search)->searchnode.local_table_count; i++)
      {
          // TODO: distance could be the same for two different tables. Right
     now the first table wins. Is there a better solution? np_dhkey_t diff = { 0
     }; _np_dhkey_hamming_distance_each(&diff, &entry->search_index.lower_dhkey,
     &np_module(search)->searchnode.tree[i]->_root._key); for (uint8_t j = 0; j
     < 8; j++)
          {
              if (diff.t[j] < min_diff.t[j])
              {
                  // log_msg(LOG_DEBUG,  NULL, "         into table %u (distance
     %u [at %u] )", i , diff.t[j], j); min_index[j] = i; min_diff.t[j] =
     diff.t[j];
              }
          }
      }
  */

  if (pipeline->remote_distribution_count <= 6) {
    uint8_t dh_diff = {0};
    struct __search_table_bucket
            buckets[np_module(search)->searchnode.local_table_count];
    uint8_t max_create_count =
        (np_module(search)->searchnode.local_table_count < 8)
            ? np_module(search)->searchnode.local_table_count
            : 8;
    for (uint8_t j = 0; j < max_create_count; j++) {
      // #pragma omp parallel for shared(entry)
      np_dhkey_t rotated = {0};
      _np_dhkey_assign(&rotated, &np_module(search)->searchnode.node_id);

      for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count;
           i++) {
        _np_dhkey_rotate_left(&rotated,
                              (np_module(search)->searchnode.prime_shift));
        _np_dhkey_hamming_distance(
            &dh_diff,
            &pipeline->obj.entry->search_index.lower_dhkey,
            &rotated);
        buckets[i].hamming_distance = dh_diff;
        buckets[i].index            = i;
      }
    }

    qsort(buckets,
          np_module(search)->searchnode.local_table_count,
          sizeof(struct __search_table_bucket),
          __search_table_bucket_cmp);

    // log_msg(LOG_DEBUG, "         into table: ");
    // for (uint16_t i = 0; i < 16; i++) {
    //   log_msg(LOG_DEBUG,
    //           "%u (%u) : ",
    //           buckets[i].index,
    //           buckets[i].hamming_distance);
    // }
    // log_msg(LOG_DEBUG, NULL,  "");

    // uint8_t i = 0;
    log_msg(LOG_INFO,
            NULL,
            "inserting into %" PRIu8 " tables : ",
            max_create_count);
    // #pragma omp parallel for shared(entry)
    uint16_t j          = 0;
    uint16_t initial_hd = buckets[0].hamming_distance;
    while (buckets[j].hamming_distance == initial_hd) {
      // for (uint16_t j = 0; j < max_create_count; j++) {
      log_msg(LOG_INFO,
              msg->uuid,
              "distribution factor was %2d, storing locally in %3d | "
              "distance %3d",
              pipeline->remote_distribution_count,
              buckets[j].index,
              buckets[j].hamming_distance);

      np_spinlock_lock(&np_module(search)->table_lock[j]);

      // log_msg(LOG_DEBUG,
      //         " %2u (distance %3u [at %2u] )",
      //         buckets[j].index,
      //         buckets[j].hamming_distance,
      //         j);
      // log_msg(LOG_DEBUG, "< NODE INDEX:>");
      // for (uint32_t k = 0; k < 8; k++) {
      //   log_msg(LOG_DEBUG, "%08x", lsh->_bktree[j]._root._key.t[k]);
      //   log_msg(LOG_DEBUG, ".");
      // }
      // log_msg(LOG_DEBUG, " </ NODE INDEX:>");

      uintptr_t *search_storage = NULL;
      np_cupidtrie_insert(&np_module(search)->searchnode.tree[buckets[j].index],
                          &pipeline->obj.entry->search_index.lower_dhkey,
                          &search_storage);
      if (search_storage == NULL) {
        log_msg(LOG_DEBUG,
                NULL,
                "could not insert data into search table at index %" PRIu16,
                buckets[j].index);
        np_spinlock_unlock(&np_module(search)->table_lock[j]);
        return (false);
      }
      *search_storage = (uintptr_t)pipeline->obj.entry;

      np_spinlock_unlock(&np_module(search)->table_lock[j]);
      j++;
    }
    // log_msg(LOG_DEBUG, NULL,  "");
  } else {
    log_msg(LOG_DEBUG,
            "distribution factor for %s was %2d, not adding locally",
            msg->uuid,
            "distribution factor was %2d, not querying locally",
            pipeline->remote_distribution_count);
    np_searchentry_t *entry = pipeline->obj.entry;
    np_index_destroy(&entry->search_index);
    free(entry);
  }

  pipeline->stop_time = np_time_now();

  return true;
}

bool __check_remote_peer_distribution(np_context                          *ac,
                                      const struct np_e2e_message_s *const msg,
                                      np_tree_t                           *body,
                                      void *localdata) {
  np_ctx_cast(ac);

  np_tree_t                     *pipeline_results = (np_tree_t *)localdata;
  struct search_pipeline_result *pipeline         = NULL;

  NP_CAST(msg, struct np_e2e_message_s, old_msg);

  np_spinlock_lock(&np_module(search)->pipeline_lock);
  // if (NULL == np_tree_find_str(pipeline_results, msg->uuid)) abort();
  pipeline = np_tree_find_uuid(pipeline_results, old_msg->uuid)->val.value.v;
  np_spinlock_unlock(&np_module(search)->pipeline_lock);

  pipeline->remote_distribution_count = 0;

  // check for chunked hamming distance to catch the index
  np_dhkey_t local_diff_index = {0};
  _np_dhkey_hamming_distance_each(&local_diff_index,
                                  &pipeline->search_index,
                                  &np_module(search)->searchnode.node_id);
  // within the index choose the entry with the lowest overall hamming distance
  // uint8_t dh_diff_target  = 0;
  // _np_dhkey_hamming_distance(&dh_diff_target, &search_index,
  // &np_module(search)->searchnode->node_id);

  bool is_zero = false;

  struct __search_table_bucket buckets[8][32];
  memset(&buckets,
         0,
         np_module(search)->searchnode.local_table_count *
             sizeof(struct __search_table_bucket));

  for (uint8_t j = 0; j < 8; j++) {
    np_spinlock_lock(&np_module(search)->peer_lock[j]);
    uint8_t best_index     = 32;
    int8_t  local_index    = local_diff_index.t[j];
    uint8_t dh_diff_target = local_diff_index.t[j];

    // search best competitor entry with an equal distance
    np_dhkey_t peer_diff_index = {0};
    _np_dhkey_hamming_distance_each(
        &peer_diff_index,
        &pipeline->search_index,
        &np_module(search)->searchnode.peers[j][local_index]);

    int32_t index = peer_diff_index.t[j];
    int32_t delta = local_diff_index.t[j] - peer_diff_index.t[j];

    log_msg(LOG_DEBUG,
            NULL,
            "%2d local distance %3d | peer distance %3d | %3d |",
            j,
            local_diff_index.t[j],
            peer_diff_index.t[j],
            delta);
    while (index != 0) {
      _np_dhkey_hamming_distance_each(
          &peer_diff_index,
          &pipeline->search_index,
          &np_module(search)->searchnode.peers[j][index]);
      // prevent follow up actions with empty cells
      is_zero = _np_dhkey_equal(&dhkey_zero,
                                &np_module(search)->searchnode.peers[j][index]);

      if (!is_zero && peer_diff_index.t[j] < dh_diff_target) {
        best_index     = index;
        dh_diff_target = peer_diff_index.t[j];
      }

      if (index == local_diff_index.t[j]) index = 0;
      else index = (delta > 0) ? index + 1 : index - 1;

      if (32 <= index) index = 0;
      log_msg(LOG_DEBUG,
              NULL,
              "[%p]                       | peer distance %3d | next index %3d "
              "| best index %3d ",
              ac,
              peer_diff_index.t[j],
              index,
              best_index);
    }

    if (best_index < 32) {
      np_dhkey_t localized_subject;
      _np_dhkey_assign(&localized_subject, &pipeline->search_subject);
      np_generate_subject(&localized_subject,
                          &np_module(search)->searchnode.peers[j][best_index],
                          NP_FINGERPRINT_BYTES);

      np_dhkey_t out_dhkey =
          _np_msgproperty_tweaked_dhkey(OUTBOUND, localized_subject);
      np_msgproperty_run_t *out_property =
          _np_msgproperty_run_get(context, OUTBOUND, localized_subject);

      if (out_property) {
        struct np_e2e_message_s *cloned_msg = NULL;
        np_new_obj(np_message_t, cloned_msg);

        _np_message_create(cloned_msg,
                           out_property->current_fp,
                           out_property->current_fp,
                           localized_subject,
                           body);
        memcpy(cloned_msg->uuid, old_msg->uuid, NP_UUID_BYTES);

        // np_message_clone(cloned_msg, old_msg);
        // _np_dhkey_assign(cloned_msg->subject, &localized_subject);
        // _np_dhkey_assign(cloned_msg->audience, &out_property->current_fp);

        // TODO: add to message attributes
        // np_tree_replace_str(
        //     cloned_msg->msg_attributes,
        //     _NP_MSG_HEADER_FROM,
        //     np_treeval_new_dhkey(np_module(search)->searchnode.node_id));

        np_util_event_t send_event = {.type      = (evt_internal | evt_message),
                                      .user_data = cloned_msg,
                                      .target_dhkey = out_property->current_fp};

        // _np_keycache_handle_event(context, subject_dhkey, send_event, false);
        if (!np_jobqueue_submit_event(
                context,
                0.0,
                out_dhkey,
                send_event,
                "event: userspace message delivery request")) {
          log_msg(
              LOG_DEBUG,
              NULL,
              "rejecting possible sending of message, please check jobqueue "
              "settings!");
        } else {
          char tmp[65];
          np_id_str(tmp, &localized_subject);
          log_msg(LOG_DEBUG,
                  msg->uuid,
                  "send new search object to peer: %" PRIx32 " via channel %s",
                  np_module(search)->searchnode.peers[j][best_index].t[0],
                  tmp);
        }
        np_unref_obj(np_message_t, cloned_msg, ref_obj_creation);
        pipeline->remote_distribution_count++;

      } else {
        char temp[65] = {0};
        log_warn(LOG_WARNING,
                 NULL,
                 "runtime property not found for index %" PRId16
                 " and subject %s",
                 best_index,
                 np_id_str(temp, &localized_subject));
      }
    }

    np_spinlock_unlock(&np_module(search)->peer_lock[j]);
  }
  return true;
}

// dummy callbacks
bool _np_searchnode_announce_cb(np_context        *context,
                                struct np_message *token_msg) {
  // just here for the completion of the api, will never be called
  return true;
}

bool __is_prime(uint8_t x) {
  uint8_t o = 4;
  for (uint8_t i = 5; true; i += o) {
    uint8_t q = x / i;
    if (q < i) return true;
    if (x == q * i) return false;
    o ^= 6;
  }
  return true;
}

uint8_t __get_next_prime(uint8_t number) {
  bool found_prime = false;
  if (number <= 2) return 2;
  if (number == 3) return 3;
  if (number <= 5) return 5;

  uint8_t k = number / 6;
  uint8_t i = number - 6 * k;
  uint8_t o = i < 2 ? 1 : 5;
  number    = 6 * k + o;
  for (i = (3 + o) / 2; !__is_prime(number); number += i)
    i ^= 6;
  return number;
}

np_search_settings_t *np_default_searchsettings() {
  np_search_settings_t *settings = calloc(1, sizeof(np_search_settings_t));
  settings->enable_remote_peers  = true;
  settings->local_table_count    = BKTREE_ARRAY_SIZE;

  settings->node_type = SEARCH_NODE_SERVER;

  memset(settings->search_space, 0, NP_FINGERPRINT_BYTES);

  settings->minhash_mode      = SEARCH_MH_FIX256;
  settings->analytic_mode     = SEARCH_ANALYTICS_OFF;
  settings->shingle_mode      = SEARCH_3_SHINGLE;
  settings->target_similarity = 0.75;
  // add more file specific settings

  return settings;
}

// initialize the np_searchnode structure and associated message exchanges
void np_searchnode_init(np_context *ac, np_search_settings_t *settings) {
  np_ctx_cast(ac);

  if (np_module_not_initiated(search)) {
    np_module_malloc(search);
    np_module(search)->query_id          = 0;
    np_module(search)->on_shutdown_route = false;
    // np_module(search)->pipeline_results = np_tree_create();
    // np_module(search)->pipeline_results = np_tree_create();

    if (settings) {
      np_module(search)->searchnode.local_table_count =
          settings->local_table_count;
      np_module(search)->searchnode.prime_shift =
          __get_next_prime(256 / settings->local_table_count);
      memcpy(&np_module(search)->searchcfg,
             settings,
             sizeof(np_search_settings_t));

    } else {
      settings = np_default_searchsettings();
      memcpy(&np_module(search)->searchcfg,
             settings,
             sizeof(np_search_settings_t));
      np_module(search)->searchnode.local_table_count =
          settings->local_table_count;
      np_module(search)->searchnode.prime_shift =
          __get_next_prime(256 / settings->local_table_count);
      free(settings);
    }
    randombytes_buf(&np_module(search)->searchnode.node_id,
                    NP_FINGERPRINT_BYTES);

    for (uint16_t i = 0; i < UINT8_MAX; i++)
      np_spinlock_init(&np_module(search)->results_lock[i],
                       PTHREAD_PROCESS_PRIVATE);

    for (uint16_t i = 0; i < np_module(search)->searchcfg.local_table_count;
         i++)
      np_spinlock_init(&np_module(search)->table_lock[i],
                       PTHREAD_PROCESS_PRIVATE);

    for (uint8_t i = 0; i <= 8; i++)
      np_spinlock_init(&np_module(search)->peer_lock[i],
                       PTHREAD_PROCESS_PRIVATE);

    np_spinlock_init(&np_module(search)->pipeline_lock,
                     PTHREAD_PROCESS_PRIVATE);

    char _tmp[65] = {0};
    np_id_str(_tmp, &np_module(search)->searchnode.node_id);
    log_msg(LOG_INFO, NULL, "starting up searchnode, peer id is: %s", _tmp);

    for (uint16_t i = 0; i < np_module(search)->searchcfg.local_table_count;
         i++) {
      np_module(search)->searchnode.tree[i].alloc_key_memory = false;
      np_module(search)->searchnode.tree[i].key_length = NP_FINGERPRINT_BYTES;
    }
    memset(np_module(search)->searchnode.results,
           0,
           UINT8_MAX * sizeof(np_tree_t *));
    memset(np_module(search)->searchnode.queries,
           0,
           UINT8_MAX * sizeof(np_searchquery_t *));

    if (np_module(search)->searchcfg.enable_remote_peers == true) {
      memset(np_module(search)->searchnode.peers,
             0,
             sizeof(np_module(search)->searchnode.peers));

      if (np_data_ok !=
          np_set_ident_attr_bin(ac,
                                NULL,
                                NP_ATTR_INTENT_AND_IDENTITY,
                                SEARCH_PEERID,
                                &np_module(search)->searchnode.node_id,
                                NP_FINGERPRINT_BYTES)) {
        log_msg(LOG_WARNING,
                NULL,
                "could not set search peer id to context / intent messages");
      }

      char *peer_type = NULL;
      if (FLAG_CMP(np_module(search)->searchcfg.node_type, SEARCH_NODE_SERVER))
        peer_type = SEARCH_PEERTYPE_SERVER;
      if (FLAG_CMP(np_module(search)->searchcfg.node_type, SEARCH_NODE_CLIENT))
        peer_type = SEARCH_PEERTYPE_CLIENT;

      if (np_data_ok !=
          np_set_ident_attr_bin(ac,
                                NULL,
                                NP_ATTR_INTENT_AND_IDENTITY,
                                SEARCH_PEERTYPE,
                                peer_type,
                                strnlen(SEARCH_PEERTYPE_HYBRID, 255))) {
        log_msg(LOG_WARNING,
                NULL,
                "could not set search peer id to context / intent messages");
      }

      // search internal message types
      np_sll_t(np_msgproperty_conf_ptr, msgproperties);

      enum np_required_search_subjects required_subjects =
          (SEARCH_NODE | SERVER_NODE_PROVIDER);
      if (FLAG_CMP(np_module(search)->searchcfg.node_type, SEARCH_NODE_CLIENT))
        required_subjects = (SEARCH_NODE | CLIENT_NODE_PROVIDER);

      msgproperties = search_msgproperties(context, required_subjects);
      sll_iterator(np_msgproperty_conf_ptr) __np_search_messages =
          sll_first(msgproperties);

      while (__np_search_messages != NULL) {
        np_msgproperty_conf_t *property = __np_search_messages->val;
        property->is_internal           = false;

        char *tmp = property->msg_subject;
        // np_generate_subject(&property->subject_dhkey, property->msg_subject,
        // strnlen(property->msg_subject, 256));

        if (property->audience_type == NP_MX_AUD_PRIVATE) {
          // seed the private subject with the peer id to
          // disguise/localize the interface
          np_generate_subject(&property->subject_dhkey,
                              property->msg_subject,
                              strnlen(property->msg_subject, 256));
          np_generate_subject(&property->subject_dhkey,
                              &np_module(search)->searchnode.node_id,
                              NP_FINGERPRINT_BYTES);
        } else { // use the default search space (whoever defined it), so
                 // everybody can discover and use our search peer
          memcpy(
              &property->subject_dhkey, // seed with search space
              np_module(search)
                  ->searchcfg
                  .search_space, // default search space is initialized with 0
              NP_FINGERPRINT_BYTES);
          np_generate_subject(&property->subject_dhkey,
                              property->msg_subject,
                              strnlen(property->msg_subject, 256));
        }

        property->msg_subject = calloc(65, sizeof(char));
        np_id_str(property->msg_subject, &property->subject_dhkey);
        np_id_str(_tmp, &np_module(search)->searchnode.node_id);
        log_msg(LOG_INFO,
                NULL,
                "adding peer search subject %s, peer id is %s / %s",
                property->msg_subject,
                _tmp,
                tmp);

        np_msgproperty_register(property);

        if (strncmp(tmp, SEARCH_ENTRY_SUBJECT, 256) == 0) {
          np_add_receive_listener(context,
                                  _np_new_searchentry_cb,
                                  &np_module(search)->pipeline_results,
                                  property->subject_dhkey);
          np_add_receive_listener(context,
                                  __check_remote_peer_distribution,
                                  &np_module(search)->pipeline_results,
                                  property->subject_dhkey);
          np_add_receive_listener(context,
                                  __np_search_add_entry,
                                  &np_module(search)->pipeline_results,
                                  property->subject_dhkey);
        } else if (strncmp(tmp, SEARCH_QUERY_SUBJECT, 256) == 0) {
          np_add_receive_listener(context,
                                  _np_new_searchquery_cb,
                                  &np_module(search)->pipeline_results,
                                  property->subject_dhkey);
          np_add_receive_listener(context,
                                  __check_remote_peer_distribution,
                                  &np_module(search)->pipeline_results,
                                  property->subject_dhkey);
          np_add_receive_listener(context,
                                  __np_search_query,
                                  &np_module(search)->pipeline_results,
                                  property->subject_dhkey);
        } else if (strncmp(tmp, SEARCH_RESULT_SUBJECT, 256) == 0) {
          np_add_receive_listener(context,
                                  _np_searchresult_receive_cb,
                                  &np_module(search)->pipeline_results,
                                  property->subject_dhkey);
        }

        np_set_mxp_attr_bin(context,
                            &property->subject_dhkey,
                            NP_ATTR_INTENT,
                            SEARCH_PEERID,
                            &np_module(search)->searchnode.node_id,
                            NP_FINGERPRINT_BYTES);

        if (property->audience_type == NP_MX_AUD_VIRTUAL)
          np_set_mx_authorize_cb(context,
                                 &property->subject_dhkey,
                                 __np_search_authorize_node_cb);
        if (property->audience_type == NP_MX_AUD_PRIVATE)
          np_set_mx_authorize_cb(context,
                                 &property->subject_dhkey,
                                 __np_search_authorize_entries_cb);

        sll_next(__np_search_messages);
      }
      sll_free(np_msgproperty_conf_ptr, msgproperties);

      log_msg(LOG_DEBUG,
              NULL,
              "added node as search peer, peer id is %08" PRIx32 ":%08" PRIx32
              "",
              np_module(search)->searchnode.node_id.t[0],
              np_module(search)->searchnode.node_id.t[1]);

      // np_jobqueue_submit_event_periodic(context, PRIORITY_MOD_USER_DEFAULT,
      //                             np_global_rng_bounded(
      //                             SYSINFO_PROACTIVE_SEND_IN_SEC) / 1.),
      //                             //sysinfo_response_props->msg_ttl /
      //                             sysinfo_response_props->max_threshold,
      //                             SYSINFO_PROACTIVE_SEND_IN_SEC+.0,
      //                             _np_search_cleanup,
      //                             "_np_search_cleanup");
    }

    np_jobqueue_submit_event_periodic(context,
                                      PRIORITY_MOD_USER_DEFAULT,
                                      NP_SEARCH_CLEANUP_INTERVAL,
                                      NP_SEARCH_CLEANUP_INTERVAL,
                                      __np_search_cleanup_pipeline,
                                      "__np_search_cleanup_pipeline");

    if (FLAG_CMP(np_module(search)->searchcfg.node_type, SEARCH_NODE_SERVER)) {
      np_jobqueue_submit_event_periodic(context,
                                        PRIORITY_MOD_USER_DEFAULT,
                                        NP_SEARCH_CLEANUP_INTERVAL,
                                        NP_SEARCH_CLEANUP_INTERVAL,
                                        __np_search_deprecate_entries,
                                        "__np_search_deprecate_entries");
    }
  }

  // log_msg(LOG_DEBUG, NULL,  "pipeline_results %p->%p", context,
  // &np_module(search)->pipeline_results);

  if (np_module_initiated(http)) {
    _np_add_http_callback(ac,
                          "search",
                          htp_method_GET,
                          context,
                          __np_search_handle_http_get);
  }

  np_add_shutdown_cb(ac, _np_search_shutdown_hook);
  // log_msg(LOG_DEBUG, NULL,  "pipeline_results %p->%p", context,
  // &np_module(search)->pipeline_results);
}

void np_searchnode_destroy(np_context *ac) {
  np_ctx_cast(ac);

  if (np_module_not_initiated(search)) {
    return;
  } else {
    np_module(search)->on_shutdown_route = true;
  }

  for (uint16_t i = 0; i < UINT8_MAX; i++) {
    if (np_module(search)->searchnode.results[i] != NULL) {
      np_tree_elem_t *tmp = NULL;
      RB_FOREACH (tmp, np_tree_s, np_module(search)->searchnode.results[i]) {
        np_searchresult_t *x = (np_searchresult_t *)tmp->val.value.v;
        np_index_destroy(&x->result_entry->search_index);
        free(x->result_entry);
      }
    }
    np_tree_free(np_module(search)->searchnode.results[i]);
    np_spinlock_destroy(&np_module(search)->results_lock[i]);
  }

  for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count;
       i++) {
    np_cupidtrie_free(&np_module(search)->searchnode.tree[i]);
    np_spinlock_destroy(&np_module(search)->table_lock[i]);
  }

  for (uint8_t i = 0; i <= 8; i++) // 8+1
    np_spinlock_destroy(&np_module(search)->peer_lock[i]);

  np_module_var(search);
  np_module_free(search);
}

void _np_search_shutdown_hook(np_context *ac) {
  // TODO: tell the other nodes that this node will be down

  // cleanup the search module
  np_searchnode_destroy(ac);
}

// (de-) serialization of search objects
np_tree_t *__encode_search_intent(struct np_token *data) {
  np_tree_t *intent_as_tree = np_tree_create();

  np_tree_insert_str(intent_as_tree,
                     "uuid",
                     np_treeval_new_bin(data->uuid, NP_UUID_BYTES));
  np_tree_insert_str(intent_as_tree,
                     "subject",
                     np_treeval_new_s(data->subject));
  np_tree_insert_str(intent_as_tree,
                     "issuer",
                     np_treeval_new_bin(data->issuer, NP_FINGERPRINT_BYTES));
  np_tree_insert_str(intent_as_tree,
                     "realm",
                     np_treeval_new_bin(data->realm, NP_FINGERPRINT_BYTES));
  np_tree_insert_str(intent_as_tree,
                     "audience",
                     np_treeval_new_bin(data->audience, NP_FINGERPRINT_BYTES));
  np_tree_insert_str(intent_as_tree,
                     "not_before",
                     np_treeval_new_d(data->not_before));
  np_tree_insert_str(intent_as_tree,
                     "expires_at",
                     np_treeval_new_d(data->expires_at));
  np_tree_insert_str(intent_as_tree,
                     "issued_at",
                     np_treeval_new_d(data->issued_at));
  np_tree_insert_str(intent_as_tree,
                     "public_key",
                     np_treeval_new_bin(data->public_key, NP_PUBLIC_KEY_BYTES));
  np_tree_insert_str(intent_as_tree,
                     "signature",
                     np_treeval_new_bin(data->signature, NP_SIGNATURE_BYTES));

  size_t attr_size = 0;
  np_get_data_size((np_datablock_t *)data->attributes, &attr_size);
  np_tree_insert_str(intent_as_tree,
                     "attributes",
                     np_treeval_new_bin(data->attributes, attr_size));
  np_tree_insert_str(
      intent_as_tree,
      "attributes_signature",
      np_treeval_new_bin(data->attributes_signature, NP_SIGNATURE_BYTES));

  return intent_as_tree;
}

bool __decode_search_intent(np_tree_t *tree, struct np_token *data) {
  CHECK_STR_FIELD(tree, "uuid", uuid);
  CHECK_STR_FIELD(tree, "subject", subject);
  CHECK_STR_FIELD(tree, "issuer", issuer);
  CHECK_STR_FIELD(tree, "realm", realm);
  CHECK_STR_FIELD(tree, "audience", audience);
  CHECK_STR_FIELD(tree, "not_before", not_before);
  CHECK_STR_FIELD(tree, "expires_at", expires_at);
  CHECK_STR_FIELD(tree, "issued_at", issued_at);
  CHECK_STR_FIELD(tree, "public_key", public_key);
  CHECK_STR_FIELD(tree, "signature", signature);

  CHECK_STR_FIELD(tree, "attributes", attributes);
  CHECK_STR_FIELD(tree, "attributes_signature", attributes_signature);

  memcpy(data->uuid, uuid.value.bin, NP_UUID_BYTES);
  strncpy(data->subject, subject.value.s, subject.size);
  memcpy(&data->realm, realm.value.bin, NP_FINGERPRINT_BYTES);
  memcpy(&data->issuer, issuer.value.bin, NP_FINGERPRINT_BYTES);
  memcpy(&data->audience, audience.value.bin, NP_FINGERPRINT_BYTES);
  data->expires_at = expires_at.value.d;
  data->issued_at  = issued_at.value.d;
  data->not_before = not_before.value.d;
  memcpy(data->public_key, public_key.value.bin, NP_PUBLIC_KEY_BYTES);
  memcpy(data->signature, signature.value.bin, NP_SIGNATURE_BYTES);

  memcpy(data->attributes, attributes.value.bin, attributes.size);
  memcpy(data->attributes_signature,
         attributes_signature.value.bin,
         NP_SIGNATURE_BYTES);

__np_cleanup__:

  return true;
}

np_tree_t *__encode_search_index(struct np_index_s *index) {
  np_tree_t *index_as_tree = np_tree_create();

  unsigned char *clk_data = NULL;
  size_t         clk_size = 0;
  _np_neuropil_bloom_serialize(index->_clk_hash, &clk_data, &clk_size);

  np_tree_insert_str(index_as_tree,
                     "idx",
                     np_treeval_new_dhkey(index->lower_dhkey));
  np_tree_insert_str(index_as_tree,
                     "clk",
                     np_treeval_new_bin(clk_data, clk_size));

  return index_as_tree;
}

bool __decode_search_index(np_tree_t *tree, struct np_index_s *index) {
  CHECK_STR_FIELD(tree, "idx", idx);
  CHECK_STR_FIELD(tree, "clk", clk);

  index->_clk_hash = _np_neuropil_bloom_create();
  _np_neuropil_bloom_deserialize(index->_clk_hash, clk.value.bin, clk.size);
  memcpy(&index->lower_dhkey, &idx.value.dhkey, NP_FINGERPRINT_BYTES);

  index->_cbl_index         = NULL;
  index->_cbl_index_counter = NULL;

__np_cleanup__:

  return true;
}

//
// serialization of search entries
//
np_tree_t *__encode_search_entry(np_searchentry_t *data) {
  np_tree_t *entry_as_tree = np_tree_create();

  np_tree_t *index_as_tree = __encode_search_index(&data->search_index);
  // log_msg(LOG_DEBUG, NULL,  "searchentry index as tree %p (%u / %u)",
  // index_as_tree, index_as_tree->byte_size, index_as_tree->size);
  np_tree_insert_str(entry_as_tree,
                     "entry.index",
                     np_treeval_new_tree(index_as_tree));

  np_tree_t *intent_as_tree = __encode_search_intent(&data->intent);
  // log_msg(LOG_DEBUG, NULL,  "searchentry intent as tree %p (%u / %u)",
  // intent_as_tree, intent_as_tree->byte_size, intent_as_tree->size);
  np_tree_insert_str(entry_as_tree,
                     "entry.intent",
                     np_treeval_new_tree(intent_as_tree));

  return entry_as_tree;
}

np_searchentry_t *__decode_search_entry(np_tree_t *data) {
  np_searchentry_t *new_entry = NULL;

  CHECK_STR_FIELD(data, "entry.index", search_index);
  CHECK_STR_FIELD(data, "entry.intent", search_intent);

  new_entry = calloc(1, sizeof(np_searchentry_t));

  // log_msg(LOG_DEBUG, NULL,  "searchentry index as tree %p (%u / %u)",
  // search_index.value.tree, search_index.value.tree->byte_size,
  // search_index.value.tree->size);
  if (!__decode_search_index(search_index.value.tree,
                             &new_entry->search_index)) {
    // log_msg(LOG_DEBUG, NULL,  "could not decode searchentry index");
    free(new_entry);
    return NULL;
  }

  // log_msg(LOG_DEBUG, NULL,  "searchentry intent as tree %p (%u / %u)",
  // search_intent.value.tree, search_intent.value.tree->byte_size,
  // search_intent.value.tree->size);
  if (!__decode_search_intent(search_intent.value.tree, &new_entry->intent)) {
    // log_msg(LOG_DEBUG, NULL,  "could not decode searchentry intent");
    np_index_destroy(&new_entry->search_index);
    free(new_entry);
    return NULL;
  }

__np_cleanup__:

  return new_entry;
}

//
// serialization of search queries
//
np_tree_t *__encode_search_query(np_searchquery_t *data) {
  np_tree_t *query_as_tree = np_tree_create();

  np_tree_insert_str(query_as_tree,
                     "query.query_id",
                     np_treeval_new_ush(data->query_id));
  np_tree_insert_str(query_as_tree,
                     "query.uuid",
                     np_treeval_new_s(data->result_uuid));
  np_tree_insert_str(query_as_tree,
                     "query.similarity",
                     np_treeval_new_f(data->target_similarity));
  np_tree_insert_str(query_as_tree,
                     "query.index",
                     np_treeval_new_tree(__encode_search_index(
                         &data->query_entry.search_index)));
  np_tree_insert_str(
      query_as_tree,
      "query.intent",
      np_treeval_new_tree(__encode_search_intent(&data->query_entry.intent)));

  return query_as_tree;
}

np_searchquery_t *__decode_search_query(np_tree_t *data) {
  np_searchquery_t *new_query = NULL;

  CHECK_STR_FIELD(data, "query.query_id", search_query_id);
  CHECK_STR_FIELD(data, "query.uuid", search_uuid);
  CHECK_STR_FIELD(data, "query.similarity", search_similarity);
  CHECK_STR_FIELD(data, "query.index", search_index);
  CHECK_STR_FIELD(data, "query.intent", search_intent);

  new_query = calloc(1, sizeof(np_searchquery_t));

  new_query->query_id          = search_query_id.value.ush;
  new_query->target_similarity = search_similarity.value.f;
  memcpy(new_query->result_uuid, search_uuid.value.bin, NP_UUID_BYTES);

  if (!__decode_search_index(search_index.value.tree,
                             &new_query->query_entry.search_index)) {
    free(new_query);
    return NULL;
  }
  if (!__decode_search_intent(search_intent.value.tree,
                              &new_query->query_entry.intent)) {
    _np_bloom_free(new_query->query_entry.search_index._clk_hash);
    free(new_query);
    return NULL;
  }

__np_cleanup__:

  return new_query;
}

//
// serialization of search queries
//
np_tree_t *__encode_search_result(np_searchresult_t *data) {
  np_tree_t *result_as_tree = np_tree_create();

  np_tree_insert_str(result_as_tree,
                     "result.query_id",
                     np_treeval_new_ush(data->query_id));
  np_tree_insert_str(result_as_tree,
                     "result.uuid",
                     np_treeval_new_s(data->result_uuid));
  np_tree_insert_str(result_as_tree,
                     "result.label",
                     np_treeval_new_s(data->label));
  np_tree_insert_str(result_as_tree,
                     "result.level",
                     np_treeval_new_f(data->level));
  np_tree_insert_str(result_as_tree,
                     "result.hit_count",
                     np_treeval_new_ush(data->hit_counter));
  np_tree_insert_str(
      result_as_tree,
      "result.entry",
      np_treeval_new_tree(__encode_search_entry(data->result_entry)));

  return result_as_tree;
}

np_searchresult_t *__decode_search_result(np_tree_t *result_tree) {
  np_searchresult_t *new_result = NULL;

  CHECK_STR_FIELD(result_tree, "result.query_id", result_query_id);
  CHECK_STR_FIELD(result_tree, "result.uuid", result_uuid);
  CHECK_STR_FIELD(result_tree, "result.label", result_label);
  CHECK_STR_FIELD(result_tree, "result.level", result_level);
  CHECK_STR_FIELD(result_tree, "result.hit_count", result_hit_count);
  CHECK_STR_FIELD(result_tree, "result.entry", result_entry);

  new_result = calloc(1, sizeof(np_searchresult_t));

  new_result->query_id = result_query_id.value.ush;
  strncpy(new_result->result_uuid, result_uuid.value.bin, NP_UUID_BYTES);
  new_result->label       = strndup(result_label.value.s, 256);
  new_result->level       = result_level.value.f;
  new_result->hit_counter = result_hit_count.value.ush;

  new_result->result_entry = __decode_search_entry(result_entry.value.tree);
  if (NULL == new_result->result_entry) {
    free(new_result);
    return NULL;
  }

__np_cleanup__:

  return new_result;
}

// read a file and create the searchentry using the attributes
bool np_create_searchentry(np_context       *ac,
                           np_searchentry_t *entry,
                           const char       *text,
                           np_attributes_t  *attributes) {
  bool ret = false;

  np_ctx_cast(ac);

  struct np_data_conf conf    = {0};
  np_data_value       val_urn = {0};
  if (np_data_ok ==
      np_get_data((np_datablock_t *)attributes, "urn", &conf, &val_urn)) {
    // TODO: base minhash_seed on actual content type
    // (html/pdf/txt/sourcecode/newsfeed/...)
    np_dhkey_t   minhash_seed = np_dhkey_create_from_hostport("", "");
    np_minhash_t minhash      = {0};

    np_index_init(&entry->search_index);

    // TODO: extract keyword using tf-idf (c99 / libbow) and add them to the
    // attributes
    // TODO: explore BM25 scoring for attributes and text analysis
    // TODO: only for pure text files right now, add different content types
    char *copied_text = strndup(text, strlen(text));

    uint16_t   count          = 0;
    np_tree_t *text_as_array  = np_tree_create();
    np_tree_t *text_occurance = np_tree_create();

    char *part = strtok(copied_text, __text_delimiter);
    while (part != NULL) {
      if (strnlen(part, 255) > 3) {
        __lower_case(part, strnlen(part, 255));
        np_tree_insert_int(text_as_array, count, np_treeval_new_s(part));

        if (np_tree_find_str(text_occurance, part) != NULL)
          np_tree_find_str(text_occurance, part)->val.value.a2_ui[1]++;
        else
          np_tree_insert_str(text_occurance,
                             part,
                             np_treeval_new_iarray(count, 1));

        count++;
      }
      part = strtok(NULL, __text_delimiter);
    }

    if (np_module(search)->searchcfg.analytic_mode == SEARCH_ANALYTICS_ON) {
      np_data_value val_title = {0};
      if (np_data_ok == np_get_data((np_datablock_t *)attributes,
                                    "title",
                                    &conf,
                                    &val_title)) {
        log_msg(LOG_INFO, NULL, "SEARCH_ANALYTICS START");
        log_msg(LOG_INFO,
                NULL,
                "analyzing %s (%" PRIsizet " unique words / %" PRIsizet
                " words):",
                val_title.str,
                text_occurance->size,
                text_as_array->size);
        uint16_t        i = 0;
        uint16_t        occurences[text_occurance->size];
        np_tree_elem_t *tmp = NULL;

        RB_FOREACH (tmp, np_tree_s, text_occurance) {
          uint16_t word_count = tmp->val.value.a2_ui[1];
          if (word_count > 3 && word_count < 13)
            log_msg(LOG_INFO,
                    NULL,
                    "word: %s (pos: %u) appeared %u times",
                    tmp->key.value.s,
                    tmp->val.value.a2_ui[0],
                    tmp->val.value.a2_ui[1]);
          occurences[i++] = word_count;
        }
        qsort(occurences,
              text_occurance->size,
              sizeof(uint16_t),
              __compare_uint16_t);

        log_msg(LOG_INFO,
                NULL,
                "analysis word count distribution: %u / %u / %u / %u / %u",
                occurences[text_occurance->size * 2 / 64],
                occurences[text_occurance->size * 11 / 64],
                occurences[text_occurance->size * 32 / 64],
                occurences[text_occurance->size * 53 / 64],
                occurences[text_occurance->size * 62 / 64]);

        np_minhash_t dd_minhash = {0};
        np_minhash_init(&dd_minhash,
                        256,
                        MIXHASH_DATADEPENDANT_FIX,
                        minhash_seed);
        np_minhash_push_tree(&dd_minhash, text_as_array, 1, false);

        uint32_t dd_signature[256] = {0};
        np_minhash_signature(&dd_minhash, &dd_signature);
        char _number_string[256];
        memset(_number_string, 256, '0');
        _number_string[0] = '\0';

        for (uint32_t i = 0; i < 256; i++) {
          if (i > 0 && (i % 16 == 0)) {
            log_msg(LOG_INFO, NULL, "%s", _number_string);
            memset(_number_string, 256, '0');
          }
          snprintf(_number_string,
                   256,
                   "%s%10u ",
                   _number_string,
                   dd_signature[i]);
        }
        log_msg(LOG_INFO, NULL, "SEARCH_ANALYTICS END");
      }
    }

    // TODO: get a copy of intent token for H("filename") and extend it with
    // attributes

    if (FLAG_CMP(np_module(search)->searchcfg.minhash_mode, SEARCH_MH_FIX256)) {
      np_minhash_init(&minhash, 256, MIXHASH_MULTI, minhash_seed);
    } else if (FLAG_CMP(np_module(search)->searchcfg.minhash_mode,
                        SEARCH_MH_FIX512)) {
      np_minhash_init(&minhash, 512, MIXHASH_MULTI, minhash_seed);
    } else {
      log_error(
          NULL,
          "%s",
          "only fixed minhash sizes available, data dependant not implemented");
      free(copied_text);

      return false;
    }

    if (FLAG_CMP(np_module(search)->searchcfg.shingle_mode, SEARCH_1_SHINGLE)) {
      np_minhash_push_tree(&minhash, text_as_array, 1, false);
    } else if (FLAG_CMP(np_module(search)->searchcfg.shingle_mode,
                        SEARCH_3_SHINGLE)) {
      np_minhash_push_tree(&minhash, text_as_array, 3, false);
    } else {
      log_error(NULL,
                "%s",
                "additional shingle modes currently not implemented");
      free(copied_text);
      return false;
    }

    np_index_update_with_minhash(&entry->search_index, &minhash);

    np_dhkey_t urn_dhkey = {0};
    np_generate_subject(&urn_dhkey, val_urn.str, conf.data_size);
    np_msgproperty_conf_t *prop =
        _np_msgproperty_get_or_create(np_module(search)->context,
                                      OUTBOUND,
                                      urn_dhkey);
    // np_merge_data(&prop->attributes, (np_datablock_t*) attributes);

    // TODO: fetch the already existing mx token for this subject
    np_message_intent_public_token_t *token =
        _np_token_factory_new_message_intent_token(prop);
    np_aaatoken4user(&entry->intent, token, false);
    np_merge_data((np_datablock_t *)entry->intent.attributes,
                  (np_datablock_t *)attributes);

    // not now, but one possible solution
    // users could subscribe to each "search subject" to retrieve more
    // information but this also leads to a massive impact for the pheromone
    // system, it has to be designed a bit more elegantly
    // np_msgproperty_register(prop);

    // TODO: push all attributes as dhkey's into the index
    // np_index_update_with_dhkey(&entry, ...);
    // np_index_update_with_dhkey(&entry->search_index, );
    np_index_hash(&entry->search_index);

    np_minhash_destroy(&minhash);
    np_tree_free(text_as_array);
    np_tree_free(text_occurance);
    free(copied_text);

    ret = true;
  } else {
    log_msg(LOG_DEBUG, NULL, "data element not found !!!");
  }
  return ret;
}

// read a query text and create the searchentry using the attributes
bool np_create_searchquery(np_context       *ac,
                           np_searchquery_t *query,
                           const char       *query_text,
                           np_attributes_t  *attributes) {
  np_ctx_cast(ac);

  if (np_module_not_initiated(search)) {
    np_searchnode_init(context, NULL);
  }

  // TODO: base minhash_seed on actual content type (html/pdf/txt/sourcecode)
  np_dhkey_t   minhash_seed = np_dhkey_create_from_hostport("", "");
  np_minhash_t minhash      = {0};

  query->target_similarity = np_module(search)->searchcfg.target_similarity;
  np_index_init(&query->query_entry.search_index);

  // TODO: extract keyword using tf-idf (libbow) and add them to the attributes
  // TODO: only for pure text files right now, could also be defined for json
  // (see also examples/neuropil_search_node_2.c )
  char *copied_text = strndup(query_text, strlen(query_text));

  uint16_t   count          = 0;
  np_tree_t *text_as_array  = np_tree_create();
  np_tree_t *text_occurance = np_tree_create();

  char *part = strtok(copied_text, __text_delimiter);
  while (part != NULL) {
    if (strnlen(part, 255) > 3) {
      __lower_case(part, strnlen(part, 255));
      np_tree_insert_int(text_as_array, count, np_treeval_new_s(part));

      if (np_tree_find_str(text_occurance, part) != NULL)
        np_tree_find_str(text_occurance, part)->val.value.a2_ui[1]++;
      else
        np_tree_insert_str(text_occurance,
                           part,
                           np_treeval_new_iarray(count, 1));

      count++;
    }
    part = strtok(NULL, __text_delimiter);
  }

  if (FLAG_CMP(np_module(search)->searchcfg.minhash_mode, SEARCH_MH_FIX256)) {
    np_minhash_init(&minhash, 256, MIXHASH_MULTI, minhash_seed);
  } else if (FLAG_CMP(np_module(search)->searchcfg.minhash_mode,
                      SEARCH_MH_FIX512)) {
    np_minhash_init(&minhash, 512, MIXHASH_MULTI, minhash_seed);
  } else {
    log_error(
        NULL,
        "%s",
        "only fixed minhash sized available, data dependant not implemented");
    free(copied_text);
    return false;
  }

  if (FLAG_CMP(np_module(search)->searchcfg.shingle_mode, SEARCH_1_SHINGLE)) {
    np_minhash_push_tree(&minhash, text_as_array, 1, false);
  } else if (FLAG_CMP(np_module(search)->searchcfg.shingle_mode,
                      SEARCH_3_SHINGLE)) {
    np_minhash_push_tree(&minhash, text_as_array, 3, false);
  } else {
    log_error(NULL, "%s", "additional shingle modes currently not implemented");
    free(copied_text);
    return false;
  }

  np_index_update_with_minhash(&query->query_entry.search_index, &minhash);

  // set reply target
  // _np_dhkey_assign(&query->result_idx,
  // &np_module(search)->searchnode.node_id);
  char *tmp = query->result_uuid;
  np_uuid_create(SEARCH_QUERY_SUBJECT, 0, &tmp);

  np_subject search_result_subject = {0};
  np_generate_subject(&search_result_subject,
                      SEARCH_RESULT_SUBJECT,
                      strnlen(SEARCH_RESULT_SUBJECT, 256));
  np_generate_subject(&search_result_subject,
                      &np_module(search)->searchnode.node_id,
                      NP_FINGERPRINT_BYTES);

  np_dhkey_t search_result_dhkey = {0};
  memcpy(&search_result_dhkey, search_result_subject, NP_FINGERPRINT_BYTES);
  // create our own interest to retrieve search results and attributes
  np_msgproperty_conf_t *prop =
      _np_msgproperty_get_or_create(np_module(search)->context,
                                    INBOUND,
                                    search_result_dhkey);

  // TODO: fetch the already existing mx token for this subject
  np_message_intent_public_token_t *token =
      _np_token_factory_new_message_intent_token(prop);
  np_aaatoken4user(&query->query_entry.intent, token, false);
  // TODO: push all attributes as dhkey's into the index
  // np_index_update_with_dhkey(&entry, ...);
  // for now: only merge to apply later "reduce" functionality
  np_merge_data((np_datablock_t *)query->query_entry.intent.attributes,
                (np_datablock_t *)attributes);

  // np_msgproperty_register(prop);

  // np_index_update_with_dhkey(&entry->search_index, );
  np_index_hash(&query->query_entry.search_index);

  // TODO: use the identity token to show our interest
  query->query_id = np_module(search)->query_id++;

  np_minhash_destroy(&minhash);
  np_tree_free(text_as_array);
  np_tree_free(text_occurance);
  free(copied_text);

  return true;
}

// ads the created searchentry to the global search index
void np_search_add_entry(np_context *ac, np_searchentry_t *entry) {
  np_ctx_cast(ac);

  np_tree_t *pipeline_results = &np_module(search)->pipeline_results;

  struct search_pipeline_result *pipeline =
      calloc(1, sizeof(struct search_pipeline_result));
  pipeline->stop_time = pipeline->start_time = np_time_now();

  np_generate_subject(&pipeline->search_subject,
                      SEARCH_ENTRY_SUBJECT,
                      strnlen(SEARCH_ENTRY_SUBJECT, 256));
  pipeline->obj.entry = entry;

  np_tree_t *search_entry = __encode_search_entry(entry);
  // size_t data_length = search_entry->byte_size;
  // unsigned char data[data_length];
  // np_tree2buffer(context, search_entry, data);
  log_msg(LOG_INFO,
          NULL,
          "using searchentry (%s) as tree %p (%" PRIsizet " / %" PRIsizet ")",
          entry->intent.subject,
          search_entry,
          search_entry->byte_size,
          search_entry->size);

  struct np_e2e_message_s *new_entry_msg = NULL;
  np_new_obj(np_message_t, new_entry_msg);

  _np_message_create(new_entry_msg,
                     pipeline->search_subject,
                     np_module(search)->searchnode.node_id,
                     pipeline->search_subject,
                     search_entry);

  np_spinlock_lock(&np_module(search)->pipeline_lock);
  np_tree_insert_uuid(pipeline_results,
                      new_entry_msg->uuid,
                      np_treeval_new_v(pipeline));
  np_spinlock_unlock(&np_module(search)->pipeline_lock);

  // manual execution of pipeline for now
  __check_remote_peer_distribution(ac,
                                   new_entry_msg,
                                   search_entry,
                                   &np_module(search)->pipeline_results);

  if (FLAG_CMP(np_module(search)->searchcfg.node_type, SEARCH_NODE_SERVER))
    __np_search_add_entry(ac,
                          new_entry_msg,
                          search_entry,
                          &np_module(search)->pipeline_results);

  np_tree_free(search_entry);
  np_unref_obj(np_message_t, new_entry_msg, ref_obj_creation);
}

// send the query and search for entries
void np_search_query(np_context *ac, np_searchquery_t *query) {
  np_ctx_cast(ac);

  np_tree_t *pipeline_results = &np_module(search)->pipeline_results;

  np_spinlock_lock(&np_module(search)->results_lock[query->query_id]);

  if (np_module(search)->searchnode.queries[query->query_id] != NULL) {
    np_searchquery_t *old_query =
        np_module(search)->searchnode.queries[query->query_id];
    np_index_destroy(&old_query->query_entry.search_index);
    free(old_query);
  }
  np_module(search)->searchnode.queries[query->query_id] = query;

  if (np_module(search)->searchnode.results[query->query_id] != NULL) {
    np_tree_elem_t *tmp = NULL;
    RB_FOREACH (tmp,
                np_tree_s,
                np_module(search)->searchnode.results[query->query_id]) {
      np_searchresult_t *result = tmp->val.value.v;
      free(result->label);
      free(result);
    }
    np_tree_free(np_module(search)->searchnode.results[query->query_id]);
  }
  np_module(search)->searchnode.results[query->query_id] = np_tree_create();

  np_spinlock_unlock(&np_module(search)->results_lock[query->query_id]);

  struct search_pipeline_result *pipeline =
      calloc(1, sizeof(struct search_pipeline_result));
  pipeline->stop_time = pipeline->start_time = np_time_now();

  np_generate_subject(&pipeline->search_subject,
                      SEARCH_QUERY_SUBJECT,
                      strnlen(SEARCH_QUERY_SUBJECT, 256));

  pipeline->obj.query = query;

  np_spinlock_lock(&np_module(search)->pipeline_lock);
  np_tree_insert_uuid(pipeline_results,
                      query->result_uuid,
                      np_treeval_new_v(pipeline));
  np_spinlock_unlock(&np_module(search)->pipeline_lock);

  np_tree_t *search_query = __encode_search_query(query);

  // size_t data_length = search_query->byte_size;
  // unsigned char data[data_length];
  // np_tree2buffer(context, search_query, data);
  log_msg(LOG_INFO,
          query->result_uuid,
          "using searchquery (%s) as tree %p (%" PRIsizet " / %" PRIsizet ")",
          query->query_entry.intent.subject,
          search_query,
          search_query->byte_size,
          search_query->size);

  struct np_e2e_message_s *new_query_msg = NULL;
  np_new_obj(np_message_t, new_query_msg);

  _np_message_create(new_query_msg,
                     pipeline->search_subject,
                     np_module(search)->searchnode.node_id,
                     pipeline->search_subject,
                     search_query);

  memcpy(new_query_msg->uuid, query->result_uuid, NP_UUID_BYTES);

  // manual execution of pipeline for now
  __check_remote_peer_distribution(ac,
                                   new_query_msg,
                                   search_query,
                                   &np_module(search)->pipeline_results);

  if (FLAG_CMP(np_module(search)->searchcfg.node_type, SEARCH_NODE_SERVER))
    __np_search_query(ac,
                      new_query_msg,
                      search_query,
                      &np_module(search)->pipeline_results);

  np_tree_free(search_query);
  np_unref_obj(np_message_t, new_query_msg, ref_obj_creation);
}

bool np_search_get_resultset(np_context       *ac,
                             np_searchquery_t *query,
                             np_tree_t        *result_tree) {
  np_ctx_cast(ac);

  if (np_module_not_initiated(search)) {
    np_searchnode_init(context, NULL);
    return false;
  }

  // stop waiting for results, prevents concurrent acces to result list
  struct search_pipeline_result *pipeline = NULL;
  np_spinlock_lock(&np_module(search)->pipeline_lock);
  {
    pipeline = np_tree_find_uuid(&np_module(search)->pipeline_results,
                                 query->result_uuid)
                   ->val.value.v;
    if (pipeline) pipeline->stop_time = np_time_now();
  }
  np_spinlock_unlock(&np_module(search)->pipeline_lock);

  if (np_module(search)->searchnode.results[query->query_id] &&
      np_module(search)->searchnode.results[query->query_id]->size == 0) {
    return false;
  }

  np_tree_elem_t *tmp = NULL;

  np_spinlock_lock(&np_module(search)->results_lock[query->query_id]);
  RB_FOREACH (tmp,
              np_tree_s,
              np_module(search)->searchnode.results[query->query_id]) {
    np_searchresult_t *result = (np_searchresult_t *)tmp->val.value.v;

    struct np_data_conf conf      = {0};
    np_data_value       val_title = {0};

    if (np_data_ok !=
        np_get_data((np_datablock_t *)result->result_entry->intent.attributes,
                    "title",
                    &conf,
                    &val_title)) {
      val_title.str = "";
    }

    np_tree_insert_int(result_tree,
                       result->hit_counter,
                       np_treeval_new_v(result));
    log_msg(LOG_DEBUG,
            NULL,
            ":: %s :: %3u / %2.2f / %25s",
            tmp->key.value.s,
            result->hit_counter,
            result->level,
            val_title.str);
  }
  np_spinlock_unlock(&np_module(search)->results_lock[query->query_id]);

  return true;
}

void _np_searchnode_withdraw(np_context *ac, struct np_searchnode_s *node) {}

bool _np_searchnode_withdraw_cb(np_context *ac, struct np_message *token_msg) {
  return true;
}

bool _np_new_searchentry_cb(np_context                          *ac,
                            const struct np_e2e_message_s *const entry_msg,
                            np_tree_t                           *body,
                            void                                *localdata) {
  np_ctx_cast(ac);

  log_msg(LOG_INFO, entry_msg->uuid, "received new searchentry from peer");
  np_tree_t *pipeline_results = (np_tree_t *)localdata;

  struct search_pipeline_result *pipeline =
      calloc(1, sizeof(struct search_pipeline_result));
  pipeline->stop_time = pipeline->start_time = np_time_now();

  np_generate_subject(&pipeline->search_subject,
                      SEARCH_ENTRY_SUBJECT,
                      strnlen(SEARCH_ENTRY_SUBJECT, 256));

  log_msg(LOG_DEBUG,
          NULL,
          "searchentry as tree %p (%" PRIsizet " / %" PRIsizet ")",
          body,
          body->byte_size,
          body->size);

  pipeline->obj.entry = __decode_search_entry(body);
  _np_dhkey_assign(&pipeline->search_index,
                   &pipeline->obj.entry->search_index.lower_dhkey);

  if (pipeline->obj.entry == NULL) {
    log_msg(LOG_DEBUG, NULL, "could not decode searchentry");
    return false;
  } else {
    np_spinlock_lock(&np_module(search)->pipeline_lock);
    np_tree_insert_uuid(pipeline_results,
                        entry_msg->uuid,
                        np_treeval_new_v(pipeline));
    np_spinlock_unlock(&np_module(search)->pipeline_lock);
  }
  return true;
}

bool _np_new_searchquery_cb(np_context                          *ac,
                            const struct np_e2e_message_s *const query_msg,
                            np_tree_t                           *body,
                            void                                *localdata) {
  np_ctx_cast(ac);

  log_msg(LOG_INFO, query_msg->uuid, "received new searchquery from peer");

  np_tree_t *pipeline_results = (np_tree_t *)localdata;

  struct search_pipeline_result *pipeline =
      calloc(1, sizeof(struct search_pipeline_result));
  pipeline->stop_time = pipeline->start_time = np_time_now();
  np_generate_subject(&pipeline->search_subject,
                      SEARCH_QUERY_SUBJECT,
                      strnlen(SEARCH_QUERY_SUBJECT, 256));

  // TODO: get from message attributes
  np_dhkey_t search_peer_dhkey = {0}; // _np_message_get_sender(query_msg);
  _np_dhkey_assign(&pipeline->sending_peer_dhkey, &search_peer_dhkey);

  log_msg(LOG_DEBUG,
          query_msg->uuid,
          "searchquery as tree %p (%" PRIsizet " / %" PRIsizet ")",
          body,
          body->byte_size,
          body->size);

  pipeline->obj.query = __decode_search_query(body);
  _np_dhkey_assign(&pipeline->search_index,
                   &pipeline->obj.query->query_entry.search_index.lower_dhkey);

  if (pipeline->obj.query == NULL) {
    log_msg(LOG_DEBUG, query_msg->uuid, "could not decode searchquery");
    return false;
  } else {
    np_spinlock_lock(&np_module(search)->pipeline_lock);
    np_tree_insert_uuid(pipeline_results,
                        query_msg->uuid,
                        np_treeval_new_v(pipeline));
    np_spinlock_unlock(&np_module(search)->pipeline_lock);
  }

  return true;
}

void _np_searchresult_send(np_context        *ac,
                           np_subject         result_subject,
                           np_searchresult_t *result) {
  np_ctx_cast(ac);

  np_tree_t *search_result = __encode_search_result(result);
  log_msg(LOG_INFO,
          result->result_uuid,
          "sending searchresult (%s) as tree %p (%" PRIsizet
          " bytes / %" PRIsizet ")",
          result->result_entry->intent.subject,
          result,
          search_result->byte_size,
          search_result->size);

  size_t data_length = np_tree_get_byte_size(search_result);
  // np_serializer_add_map_bytesize(search_result, &data_length);
  unsigned char data[data_length];
  np_tree2buffer(context, search_result, data);

  np_send(context, result_subject, data, data_length);
}

bool _np_searchresult_receive_cb(np_context                    *ac,
                                 const struct np_e2e_message_s *result_msg,
                                 np_tree_t                     *body,
                                 void                          *localdata) {
  np_ctx_cast(ac);

  np_tree_elem_t *userdata = np_tree_find_str(body, NP_SERIALISATION_USERDATA);
  if (userdata == NULL) {
    log_msg(LOG_DEBUG, result_msg->uuid, "could not find userdate element");
    return false;
  }

  np_tree_t *search_result = np_tree_create();
  np_buffer2tree(context,
                 userdata->val.value.bin,
                 userdata->val.size,
                 search_result);

  log_msg(LOG_DEBUG,
          result_msg->uuid,
          "received searchresult as tree %p (%" PRIsizet " bytes / %" PRIsizet
          ")",
          search_result,
          search_result->byte_size,
          search_result->size);

  np_searchresult_t *new_result = __decode_search_result(search_result);

  if (new_result == NULL) {
    log_msg(LOG_DEBUG, result_msg->uuid, "could not decode searchresult");
    np_tree_free(search_result);
    return false;
  }

  log_msg(LOG_INFO,
          result_msg->uuid,
          "received new searchresult from peer for query with uuid: %s",
          new_result->result_uuid);

  np_tree_t                     *pipeline_results = (np_tree_t *)localdata;
  struct search_pipeline_result *pipeline         = NULL;

  np_spinlock_lock(&np_module(search)->pipeline_lock);
  if (NULL == np_tree_find_uuid(pipeline_results, new_result->result_uuid)) {
    log_msg(LOG_DEBUG,
            result_msg->uuid,
            "could not find pipeline definition for %s",
            new_result->result_uuid);
    np_spinlock_unlock(&np_module(search)->pipeline_lock);
    return false;
  } else {
    pipeline = np_tree_find_uuid(pipeline_results, new_result->result_uuid)
                   ->val.value.v;
  }

  np_spinlock_unlock(&np_module(search)->pipeline_lock);
  if (_np_dhkey_equal(&pipeline->sending_peer_dhkey, &dhkey_zero)) {
    np_spinlock_lock(&np_module(search)->pipeline_lock);
    if (pipeline->stop_time > pipeline->start_time) {
      log_msg(LOG_INFO,
              result_msg->uuid,
              "pipeline %s already stopped by user",
              new_result->result_uuid);
      np_spinlock_unlock(&np_module(search)->pipeline_lock);
      return false;
    }
    np_spinlock_unlock(&np_module(search)->pipeline_lock);

    assert(np_module(search)->on_shutdown_route == false);

    np_spinlock_lock(&np_module(search)->results_lock[new_result->query_id]);

    if (&np_module(search)->searchnode.queries[new_result->query_id] == NULL) {
      np_spinlock_unlock(
          &np_module(search)->results_lock[new_result->query_id]);
      return false;
    };

    np_map_reduce_t mr = {.cmp    = _cmp_all_searchentries,
                          .map    = _map_np_searchentry,
                          .reduce = _reduce_np_searchentry};

    mr.reduce_result =
        np_module(search)->searchnode.results[new_result->query_id];
    mr.map_args.io = &np_module(search)
                          ->searchnode.queries[new_result->query_id]
                          ->query_entry;

    //        np_searchquery_t* query =
    //        np_module(search)->searchnode.queries[new_result->query_id];
    mr.reduce(&mr, new_result->result_entry);
    np_spinlock_unlock(&np_module(search)->results_lock[new_result->query_id]);

  } else {
    log_msg(LOG_DEBUG,
            result_msg->uuid,
            "re-sending searchresult as tree %p (%" PRIsizet
            " bytes / %" PRIsizet ")",
            search_result,
            search_result->byte_size,
            search_result->size);
    np_subject result_subject = {0};
    // TODO: implement possible intermediate reduce step
    np_generate_subject(&result_subject,
                        SEARCH_RESULT_SUBJECT,
                        strnlen(SEARCH_RESULT_SUBJECT, 256));
    np_generate_subject(&result_subject,
                        &pipeline->sending_peer_dhkey,
                        NP_FINGERPRINT_BYTES);

    _np_searchresult_send(context, result_subject, new_result);
    // pipeline->stop_time = np_time_now();
  }

  return true;
}

//
// python wrapper functions
// the followig function are used by the python binding to execute a search on a
// given neuropil node set
//
// create and add a new searchentry. expects "urn" and "title" to be present as
// attributes
bool pysearch_entry(np_context            *context,
                    struct np_searchentry *entry,
                    const char            *text,
                    np_attributes_t        attributes) {
  bool ret = false;
  // log_msg(LOG_DEBUG, NULL,  "%p : %s", &attributes, attributes);
  // np_iterate_data(attributes, __print_attributes, "-- external --");

  np_subject          urn_subject = {0};
  struct np_data_conf conf        = {0};
  np_data_value       val_urn     = {0};
  if (np_data_ok ==
      np_get_data((np_datablock_t *)attributes, "urn", &conf, &val_urn))
    np_generate_subject(&urn_subject, val_urn.str, strnlen(val_urn.str, 256));

  // np_searchentry_t searchentry = {};
  np_searchentry_t *searchentry = calloc(1, sizeof(np_searchentry_t));
  if (np_create_searchentry(context, searchentry, text, attributes)) {
    np_search_add_entry(context, searchentry);
    np_mx_properties_disable(context, urn_subject);

    memcpy(&entry->search_index,
           &searchentry->search_index,
           NP_FINGERPRINT_BYTES);
    memcpy(&entry->intent, &searchentry->intent, sizeof(struct np_token));
    ret = true;
  }
  return ret;
}

// read a query text and create the searchentry using the attributes
bool pysearch_query(np_context            *context,
                    float                  search_probability,
                    struct np_searchquery *query,
                    const char            *query_text,
                    np_attributes_t        attributes) {
  bool              ret         = false;
  np_searchquery_t *searchquery = calloc(1, sizeof(np_searchquery_t));

  if (np_create_searchquery(context, searchquery, query_text, attributes)) {
    searchquery->target_similarity = search_probability;

    query->query_id   = searchquery->query_id;
    query->similarity = searchquery->target_similarity;
    memcpy(&query->result_uuid, &searchquery->result_uuid, NP_UUID_BYTES);
    memcpy(&query->query_entry.search_index,
           &searchquery->query_entry.search_index,
           NP_FINGERPRINT_BYTES);
    memcpy(&query->query_entry.intent,
           &searchquery->query_entry.intent,
           sizeof(struct np_token));

    np_search_query(context, searchquery);

    ret = true;
  }
  return ret;
}

// return the amount of searchresults
uint32_t pysearch_pullresult_size(np_context            *ac,
                                  struct np_searchquery *query) {
  np_ctx_cast(ac);

  uint32_t resultset_size = 0;
  np_spinlock_lock(&np_module(search)->results_lock[query->query_id]);
  resultset_size = np_module(search)->searchnode.results[query->query_id]->size;
  np_spinlock_unlock(&np_module(search)->results_lock[query->query_id]);
  return resultset_size;
}

// pull a searchresult from the query
bool pysearch_pullresult(np_context            *context,
                         struct np_searchquery *query,
                         struct np_searchresult py_result[],
                         size_t                 elements_to_fetch) {

  np_tree_t       *result_tree  = np_tree_create();
  np_searchquery_t searchquery  = {0};
  searchquery.query_id          = query->query_id;
  searchquery.target_similarity = query->similarity;
  memcpy(&searchquery.result_uuid, &query->result_uuid, NP_UUID_BYTES);

  if (np_search_get_resultset(context, &searchquery, result_tree)) {
    uint16_t        counter = 0;
    np_tree_elem_t *tmp     = NULL;
    // fprintf(stdout,  "mapping result %zu\n", elements_to_fetch);
    // get the top x search results
    RB_FOREACH (tmp, np_tree_s, result_tree) {
      if (counter >= elements_to_fetch) break;

      np_searchresult_t *result = (np_searchresult_t *)tmp->val.value.v;
      // fprintf(stdout,  "mapping result %s : %d : %f\n", result->label,
      // result->hit_counter, result->level);
      log_msg(LOG_DEBUG,
              NULL,
              "mapping result %s : %d : %f",
              result->label,
              result->hit_counter,
              result->level);

      py_result[counter].hit_counter = result->hit_counter;
      py_result[counter].level       = result->level;
      strncpy(py_result[counter].label,
              result->label,
              strnlen(result->label, 255));
      // py_result[counter].result_entry = calloc(1, sizeof(struct
      // np_searchentry));
      memcpy(&py_result[counter].result_entry.intent,
             &result->result_entry->intent,
             sizeof(struct np_token));
      memcpy(&py_result[counter].result_entry.search_index,
             &result->result_entry->search_index.lower_dhkey,
             NP_FINGERPRINT_BYTES);

      counter++;
    }
  } else {
    return false;
  }
  np_tree_free(result_tree);
  return true;
}
