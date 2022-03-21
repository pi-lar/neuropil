//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// neuropil is copyright 2016-2022 by pi-lar GmbH
//
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "search/np_search.h"
#include "search/np_bktree.h"
#include "search/np_index.h"

#include "neuropil_data.h"

#include "np_aaatoken.h"
#include "np_attributes.h" 
#include "np_constants.h"
#include "np_data.h"
#include "np_dhkey.h"
#include "np_key.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_threads.h"
#include "np_token_factory.h"

#include "core/np_comp_msgproperty.h"

#include "util/np_list.h"
#include "util/np_mapreduce.h"
#include "util/np_minhash.h"
#include "util/np_bloom.h"

#include "http/np_http.h"
#include "http/urldecode.h"

#include "parson/parson.h"

#include "np_search_mxproperties.c"

np_module_struct(search) {
    np_state_t* context;         // the context
    np_searchnode_t searchnode;  // the searchnode structure
    uint8_t query_id;            // a global counter of search queries of this nodes
    np_bloom_t peer_filter;     // a counting bloom filter to check whether a peer has already been added
    np_tree_t pipeline_results;  // pipelines in the meaning of callbacks, used to store intermediate results for queries / entries / ...
    np_spinlock_t results_lock[UINT8_MAX];
    np_spinlock_t table_lock[BKTREE_ARRAY_SIZE];
    np_spinlock_t peer_lock[8+1];
    np_spinlock_t pipeline_lock;
};

struct search_pipeline_result {
    
    double start_time;    
    double stop_time;

    uint8_t remote_distribution_count;

    np_dhkey_t search_subject;
    np_dhkey_t search_index;
    np_dhkey_t sending_peer_dhkey;

    union {
        np_searchquery_t* query;
        np_searchentry_t* entry;
    } obj;

};

static char* __text_delimiter = " ,!'.\"-_[]{}/";
static const char* SEARCH_PEERID = "np:search:peerid";
static const char* SEARCH_RESULTID = "np:search:resultidx";

static const uint16_t NP_SEARCH_CLEANUP_INTERVAL = NP_SEARCH_RESULT_REFRESH_TTL;


bool __np_search_cleanup_pipeline(np_state_t* context, NP_UNUSED np_util_event_t args)
{
    np_tree_t* pipeline_results = &np_module(search)->pipeline_results;
    np_tree_elem_t* tmp = NULL;

    np_spinlock_lock(&np_module(search)->pipeline_lock);
    RB_FOREACH (tmp, np_tree_s, pipeline_results)
    {
        struct search_pipeline_result *pipeline = tmp->val.value.v;
        if ((pipeline->stop_time + NP_SEARCH_CLEANUP_INTERVAL) < np_time_now()) 
        {
            np_tree_del_str(pipeline_results, tmp->key.value.s);
            free(pipeline);
            break;
        }
    }   
    np_spinlock_unlock(&np_module(search)->pipeline_lock);
}


// map reduce algorithms or parts of those
bool _deprecate_map_func(np_map_reduce_t* mr_struct, const void* element)
{
    np_searchentry_t* it_1 = (np_searchentry_t*) element;
    np_dhkey_t* _deprecate_target = (np_dhkey_t*) mr_struct->map_args.io;
    if (it_1 == NULL) return false;

    // needed ?
    np_dhkey_t _common = {0}, _diff = {0};
    _np_dhkey_and (&_common, _deprecate_target, &it_1->search_index.lower_dhkey);
    _np_dhkey_or  (&_diff   , _deprecate_target, &it_1->search_index.lower_dhkey);

    uint8_t _dist_common = 0, _dist_diff = 0;
    _np_dhkey_hamming_distance(&_dist_common, &dhkey_zero, &_common); // sum of 1 in both np_index
    _np_dhkey_hamming_distance(&_dist_diff  , &dhkey_zero, &_diff  ); // sum of 1 in either np_index

    float _jc = (float) _dist_common / _dist_diff; // jaccard index
    if (_jc > 0.9)
    {
        // log_msg(LOG_DEBUG, "deprecating entry %p (%f)\n", it_1, _jc);
        _np_neuropil_bloom_age_decrement(it_1->search_index._clk_hash);
        float _age = _np_neuropil_bloom_intersect_age(it_1->search_index._clk_hash, it_1->search_index._clk_hash);
        if (_age == 0.0)
        {
            // log_msg(LOG_DEBUG, "identified entry for deletion %p \n", it_1);
            // log_msg(LOG_DEBUG,  "R COLLISION: %f <-> %p (%s)", _similarity, it_2->search_index._clk_hash, it_2->intent.subject);
            sll_append(void_ptr, mr_struct->map_result, it_1);
        }
    }
    else
    {
        // log_msg(LOG_DEBUG, "similarity not close enough (%f), deprecation of entry skipped \n", _jc);
    }
    return true;
}

bool _deprecate_reduce_func(np_map_reduce_t* mr_struct, const void* element)
{   
    if (element == NULL) return false;

    // log_msg(LOG_DEBUG, "deleting entry (%p) \n", element);
    np_searchentry_t* search_elem = (np_searchentry_t*) element;
    np_bktree_t* tree = (np_bktree_t*) mr_struct->reduce_args.io;

    np_bktree_remove(tree, search_elem->search_index.lower_dhkey, search_elem);

    np_tree_insert_str(mr_struct->reduce_result, search_elem->intent.uuid, np_treeval_new_v(search_elem));

    return true;
}

bool __np_search_deprecate_entries(np_state_t* context, NP_UNUSED np_util_event_t args)
{
    np_bktree_t* search_tree = NULL;

    np_dhkey_t _random_dhkey = {0};
    randombytes_buf(&_random_dhkey, NP_FINGERPRINT_BYTES);

    np_map_reduce_t mr = {0};
    mr.map    = _deprecate_map_func;
    mr.map_args.io = &_random_dhkey;
    sll_init(void_ptr, mr.map_result);
    mr.reduce = _deprecate_reduce_func;
    mr.reduce_args.io = NULL;
    mr.reduce_result = np_tree_create();

    for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count; i++)
    {
        np_spinlock_lock(&np_module(search)->table_lock[i]);
        np_bktree_query(np_module(search)->searchnode.tree[i], _random_dhkey, NULL, &mr);
        np_spinlock_unlock(&np_module(search)->table_lock[i]);

        sll_iterator(void_ptr) iterator = sll_first(mr.map_result);
        while (iterator != NULL) 
        {
            np_spinlock_lock(&np_module(search)->table_lock[i]);
            mr.reduce_args.io = np_module(search)->searchnode.tree[i];
            mr.reduce(&mr, iterator->val);
            np_spinlock_unlock(&np_module(search)->table_lock[i]);

            sll_next(iterator);
        }
        sll_clear(void_ptr, mr.map_result);
    }

    np_tree_elem_t* tmp = NULL;
    RB_FOREACH(tmp, np_tree_s, mr.reduce_result) 
    {
        np_searchentry_t* elem = (np_searchentry_t*) tmp->val.value.v;        

        np_index_destroy(&elem->search_index);
        free(elem);
    }
    np_tree_free(mr.reduce_result);

    // static uint16_t i = 0;
    // log_msg(LOG_DEBUG, "__np_search_deprecate_entries \n");
    fflush(stdout);

    return true;
}

struct __search_table_bucket {
  uint16_t hamming_distance;
  uint16_t index;
};

static
int __search_table_bucket_cmp(const void *a, const void *b)
{
  const struct __search_table_bucket *da = a, *db = b;

  return da->hamming_distance < db->hamming_distance ? -1 : da->hamming_distance > db->hamming_distance;
}

static
JSON_Value* __np_generate_error_json(const char* error,const char* details)
{
    log_trace_msg(LOG_TRACE | LOG_HTTP, "start: JSON_Value* _np_generate_error_json(const char* error,const char* details) {");
    JSON_Value* ret = json_value_init_object();

    json_object_set_string(json_object(ret), "error", error);
    json_object_set_string(json_object(ret), "details", details);

    return ret;
}

void __lower_case(char* str, uint8_t strlen) 
{
    for(int i = 0; i < strlen; i++){
        str[i] = tolower(str[i]);
    }
}

// map reduce algorithms or parts of those
bool _map_np_searchentry(np_map_reduce_t* mr_struct, const void* element)
{
    np_searchentry_t* it_1 = (np_searchentry_t*)mr_struct->map_args.io;
    np_searchentry_t* it_2 = (np_searchentry_t*)element;

    if (it_1 == it_2)                 return true;
    if (it_1 == NULL || it_2 == NULL) return false;

    // if (it_2->search_index._clk_hash == NULL) return false;

    float _target_similarity = np_tree_find_int(mr_struct->map_args.kv_pairs, 1)->val.value.f;

    float _similarity = 0.0;
    // log_msg(LOG_DEBUG,  "P COLLISION: %p <-> %p ", it_1->intent, it_2->intent);
    _np_neuropil_bloom_similarity(it_2->search_index._clk_hash, it_1->search_index._clk_hash, &_similarity);

    struct np_data_conf conf = { 0 };
    np_data_value val_title  = { 0 };
    if (np_data_ok != np_get_data((np_datablock_t*) it_2->intent.attributes, "title", &conf, &val_title ) )
    {
        val_title.str = "";
    }
    fprintf(stdout,  "COLLISION: %f <-> %p (%s / %s)\n", _similarity, it_2->search_index._clk_hash, val_title.str, it_2->intent.subject);

    if (_similarity > _target_similarity)
    {
        // log_msg(LOG_DEBUG,  "R COLLISION: %f <-> %p (%s)", _similarity, it_2->search_index._clk_hash, it_2->intent.subject);
        sll_append(void_ptr, mr_struct->map_result, it_2);
    }

    int8_t _continue_mapping = mr_struct->cmp(mr_struct, it_2);

    if (0 >= _continue_mapping) return true;
    else                        return false;
}

bool _reduce_np_searchentry(np_map_reduce_t* mr_struct, const void* element)
{   
    if (element == NULL) return false;

    np_searchentry_t* it_1 = (np_searchentry_t*) mr_struct->map_args.io;
    np_searchentry_t* it_2 = (np_searchentry_t*) element;

    np_tree_elem_t* result_elem = NULL;
    if (NULL != (result_elem = np_tree_find_str(mr_struct->reduce_result, it_2->intent.subject)) ) 
    {
        np_searchresult_t* result = (np_searchresult_t*) result_elem->val.value.v;
        result->hit_counter++;

        float similarity = 0.0;
        _np_neuropil_bloom_similarity(it_1->search_index._clk_hash, it_2->search_index._clk_hash, &similarity);
        if (result->level < similarity) result->level = similarity;
    }
    else
    {
        np_searchresult_t* new_result = (np_searchresult_t*) malloc(sizeof(np_searchresult_t));
        new_result->hit_counter = 1;
        new_result->label = strndup(it_2->intent.subject, 255);
        new_result->result_entry = it_2;
        _np_neuropil_bloom_similarity(it_1->search_index._clk_hash, it_2->search_index._clk_hash, &new_result->level);

        np_tree_insert_str(mr_struct->reduce_result, it_2->intent.subject, np_treeval_new_v(new_result) );
    }
    return true;
}

int __compare_uint16_t(uint16_t* first, uint16_t* second)
{ 
    if (*first>*second) return  1;
    if (*first<*second) return -1;
    return 0;
}

// authz callbacks
bool __np_search_authorize_result_cb(np_context* ac, struct np_token* intent_token) 
{
	np_ctx_cast(ac);

    // TODO: insert currently used result_idx into a tree. stop listening on reply subject once a timeout has been exceeded 

    // for now:
    return true;
}

bool __np_search_authorize_entries_cb(np_context* ac, struct np_token* intent_token) 
{
	np_ctx_cast(ac);

    bool ret = false;
    struct np_data_conf conf = {0};
    struct np_data_conf* conf_ptr = &conf;

    np_dhkey_t new_peer_dhkey = {0};
    np_id* peer_id = NULL;
    np_id new_peer_id = {0};

    // if (np_data_ok != np_get_token_attr_bin(intent_token, "np:key", &conf_ptr, &new_peer_id_ptr) )
    // {
    //     return false;
    // }    
    // if (_np_dhkey_equal(&new_peer_id, &np_module(search)->searchnode->node_id))
    // {
    //     return false;
    // }
	
    // log_msg(LOG_DEBUG,  "authz request %s from %02X%02X%02X%02X%02X%02X : %02X%02X%02X%02X%02X%02X ...",
    //                 intent_token->subject,
    //                 intent_token->issuer[0],     intent_token->issuer[1],     intent_token->issuer[2],     intent_token->issuer[3],     intent_token->issuer[4],     intent_token->issuer[5],
    //                 intent_token->public_key[0], intent_token->public_key[1], intent_token->public_key[2], intent_token->public_key[3], intent_token->public_key[4], intent_token->public_key[5]);

    log_msg(LOG_INFO,  "authz grant %s for %02x%02x%02x%02x%02x%02x : %02x%02x%02x%02x%02x%02x ...",
                    intent_token->subject,
                    intent_token->issuer[0],     intent_token->issuer[1],     intent_token->issuer[2],     intent_token->issuer[3],     intent_token->issuer[4],     intent_token->issuer[5],
                    intent_token->public_key[0], intent_token->public_key[1], intent_token->public_key[2], intent_token->public_key[3], intent_token->public_key[4], intent_token->public_key[5]);

    /*
    Right now it is only possible to return true, we have no added knowledge to verify whether a peer is allowed to send entries or queries.
    As we are using private data channels for entries and queries, we have to trust that the nodes have passed the node authz callback (otherwise they would not know our peerid)
    possible solutions: 
        - use a bloom filter to check whether a node has send it peer information before
        - use a set of known identities (needs-preseeding)
        - use a governance node and forward the authorization requests to this node
        - ...

    np_dhkey_t dh_diff_index = {0};
    _np_dhkey_hamming_distance_each(&dh_diff_index, &new_peer_id, &np_module(search)->searchnode->node_id);

    for (uint8_t j = 0; j < 8; j++) 
    {
        uint8_t index = dh_diff_index.t[j];
        if (!ret && _np_dhkey_equal(&np_module(search)->searchnode->peers[j][index], &new_peer_id) )
        {
            log_msg(LOG_DEBUG,  "authz granted %s for %02X%02X%02X%02X%02X%02X : %02X%02X%02X%02X%02X%02X ...",
                            intent_token->subject,
                            intent_token->issuer[0],     intent_token->issuer[1],     intent_token->issuer[2],     intent_token->issuer[3],     intent_token->issuer[4],     intent_token->issuer[5],
                            intent_token->public_key[0], intent_token->public_key[1], intent_token->public_key[2], intent_token->public_key[3], intent_token->public_key[4], intent_token->public_key[5]);
            ret = true;
        }
    }
    
    return ret;
    */
    return true;
}

bool __np_search_authorize_node_cb(np_context* ac, struct np_token* intent_token) 
{
	np_ctx_cast(ac);
    np_searchnode_t* searchnode = &np_module(search)->searchnode;

    if (np_module(search)->peer_filter._bitset == NULL) 
    {
        struct np_bloom_optable_s counting_op = {
            .add_cb = _np_counting_bloom_add,
            .check_cb = _np_counting_bloom_check,
            .clear_cb = _np_counting_bloom_clear,
        };
        np_bloom_t* _filter = _np_counting_bloom_create(4096, 8, 1);
        _filter->op = counting_op;
        memcpy(&np_module(search)->peer_filter, _filter, sizeof(np_bloom_t)); 
    }

    bool ret = false;

    np_dhkey_t _zero          = {0};

    struct np_data_conf conf = {0};
    struct np_data_conf* conf_ptr = &conf;

    np_dhkey_t   new_peer_dhkey = {0};
    unsigned char* bin_data = NULL;
    // np_id new_peer_id = NULL;
	// log_msg(LOG_DEBUG,  "authz request %s from %02X%02X%02X%02X%02X%02X : %02X%02X%02X%02X%02X%02X ...",
    //                 intent_token->subject,
    //                 intent_token->issuer[0],     intent_token->issuer[1],     intent_token->issuer[2],     intent_token->issuer[3],     intent_token->issuer[4],     intent_token->issuer[5],
    //                 intent_token->public_key[0], intent_token->public_key[1], intent_token->public_key[2], intent_token->public_key[3], intent_token->public_key[4], intent_token->public_key[5]);

    if (np_data_ok != np_get_token_attr_bin(intent_token, SEARCH_PEERID, &conf_ptr, &bin_data) )
    {
        return false;
    }

    memcpy(&new_peer_dhkey, bin_data, NP_FINGERPRINT_BYTES);

    if (_np_dhkey_equal(&new_peer_dhkey, &searchnode->node_id) || _np_dhkey_equal(&new_peer_dhkey, &_zero) )
    {
        return false;
    }

    np_spinlock_lock(&np_module(search)->peer_lock[8]);
    if (np_module(search)->peer_filter.op.check_cb(&np_module(search)->peer_filter, new_peer_dhkey)) 
    {
        log_msg(LOG_DEBUG,  "re-evaluation of  node as search peer %08"PRIx32":%08"PRIx32" skipped ...", new_peer_dhkey.t[0], new_peer_dhkey.t[1]);
        np_spinlock_unlock(&np_module(search)->peer_lock[8]);
        return true;
    }
    np_spinlock_unlock(&np_module(search)->peer_lock[8]);

    log_msg(LOG_DEBUG,  "found node as search peer, peer id is %08"PRIx32":%08"PRIx32"", new_peer_dhkey.t[0], new_peer_dhkey.t[1]);

    // if (strncmp(intent_token->subject, SEARCH_NODE_SUBJECT, 21)) 
    // {
        np_dhkey_t dh_diff_index  = {0};
        np_dhkey_t to_delete      = {0};

        // log_msg(LOG_DEBUG,  "checking search node as peer: %02X%02X%02X%02X%02X%02X", 
        //                 intent_token->issuer[0],     intent_token->issuer[1],     intent_token->issuer[2],     intent_token->issuer[3],     intent_token->issuer[4],     intent_token->issuer[5]);

        // check for chunked hamming distance to catch the index        
        _np_dhkey_hamming_distance_each(&dh_diff_index, &new_peer_dhkey, &searchnode->node_id);

        // setup competitor entry
        uint8_t   dh_diff_new  = UINT8_MAX;
        // within the index choose the entry with the lowest overall hamming distance
        _np_dhkey_hamming_distance(&dh_diff_new, &new_peer_dhkey, &searchnode->node_id);

        bool not_subscribed = true;            

        for (uint8_t j = 0; j < 8; j++) 
        {
            np_spinlock_lock(&np_module(search)->peer_lock[j]);
            bool    is_zero = false;
            uint8_t index = dh_diff_index.t[j];
            uint8_t dh_diff_old  = UINT8_MAX;

            // compare hamming distance between old and new data channel
            _np_dhkey_hamming_distance(&dh_diff_old, &searchnode->peers[j][index], &searchnode->node_id);
            is_zero = _np_dhkey_equal(&_zero, &searchnode->peers[j][index]);

            // check whether the node subscription channels has been already added            
            if (not_subscribed) not_subscribed = !_np_dhkey_equal(&searchnode->peers[j][index], &new_peer_dhkey);

            // log_msg(LOG_DEBUG,  "compare node as search peer [%u][%u], distance is %u (%u) (%u:%u)", 
            //                 j, index, dh_diff_new.t[j], dh_diff_index.t[j], is_zero, exists);

            if ( (dh_diff_old > dh_diff_new) || is_zero) 
            {
                _np_dhkey_assign(&to_delete, &searchnode->peers[j][index]);
                _np_dhkey_assign(&searchnode->peers[j][index], &new_peer_dhkey);
                log_msg(LOG_INFO,  "adding node as search peer [%u][%u], distance is %u", 
                                j, index, dh_diff_new);
                np_spinlock_lock(&np_module(search)->peer_lock[8]);
                np_module(search)->peer_filter.op.add_cb(&np_module(search)->peer_filter, new_peer_dhkey);
                np_spinlock_unlock(&np_module(search)->peer_lock[8]);
            }

            np_spinlock_unlock(&np_module(search)->peer_lock[j]);

            if ( not_subscribed && ((dh_diff_old > dh_diff_new) || is_zero))
            {
                // search internal message types
                np_sll_t(np_msgproperty_conf_ptr, msgproperties);
                msgproperties = search_peer_msgproperties(context);
                sll_iterator(np_msgproperty_conf_ptr) __np_search_messages = sll_first(msgproperties);
                while (__np_search_messages != NULL)
                {
                    np_msgproperty_conf_t* property = __np_search_messages->val;
                    property->is_internal = false;

                    char* tmp = property->msg_subject;

                    np_generate_subject(&property->subject_dhkey, property->msg_subject, strnlen(property->msg_subject, 256));
                    np_generate_subject(&property->subject_dhkey, &new_peer_dhkey, NP_FINGERPRINT_BYTES);

                    property->msg_subject = calloc(65, sizeof(char));
                    np_id_str(property->msg_subject, &property->subject_dhkey);

                    np_msgproperty_register(property);

                    np_set_mx_authorize_cb(context, &property->subject_dhkey, __np_search_authorize_entries_cb);

                    char _tmp[65] = {0};
                    np_id_str(_tmp, &new_peer_dhkey);
                    log_msg(LOG_INFO,  "subscribed to peer search subject %s, peer id is %s / %s", property->msg_subject, _tmp, tmp);
                    sll_next(__np_search_messages);
                }
                sll_free(np_msgproperty_conf_ptr, msgproperties);

                ret = true;
                searchnode->remote_peer_count++;
                not_subscribed = false;
            }
            // else 
            // {
                // log_msg(LOG_DEBUG,  "checked search node as peer: %02X%02X%02X%02X%02X%02X", 
                //                 intent_token->issuer[0],     intent_token->issuer[1],     intent_token->issuer[2],     intent_token->issuer[3],     intent_token->issuer[4],     intent_token->issuer[5]);
                // log_msg(LOG_DEBUG,  "checked node as search peer [%u][%u], distance was %u", 
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
int __np_search_handle_http_get(ht_request_t* ht_request, ht_response_t* ht_response, void* user_arg) 
{
    np_context* ac = user_arg;
    np_ctx_cast(ac);

    // log_msg(LOG_DEBUG,  "searching for ...");

    uint16_t length;
    int http_status = HTTP_CODE_INTERNAL_SERVER_ERROR; // HTTP_CODE_OK
    JSON_Value* json_obj = NULL;
    
    if (NULL != ht_request->ht_path && NULL != ht_request->ht_query_args)
    {
        char* file_start = ht_request->ht_path+1; // without leading '/'

        np_tree_elem_t* query_elem = np_tree_find_str(ht_request->ht_query_args, "query_text");
        if (NULL == query_elem) 
        {
            log_msg(LOG_DEBUG,  "no query found ...");
            json_obj = __np_generate_error_json("request invalid", "looks like you are using a wrong url ...");
            http_status = HTTP_CODE_BAD_REQUEST;
            goto __json_return__; 
        }

        char* search_string = urlDecode(query_elem->val.value.s);
        log_msg(LOG_DEBUG,  "searching for: %s", search_string);

        clock_t start_time;
        clock_t query_stop_time;
        clock_t popro_stop_time;

        start_time = clock();
        np_searchquery_t sq = {0};
        np_attributes_t attr = {0};
        if (np_create_searchquery(context, &sq, search_string, &attr))
        {
            np_search_query(context, &sq);
            query_stop_time = clock();
            // wait for external replies
            np_time_sleep(0.250);
            struct search_pipeline_result* pipeline = NULL;
            np_spinlock_lock(&np_module(search)->pipeline_lock);
            {
                pipeline = np_tree_find_str(&np_module(search)->pipeline_results, sq.result_uuid)->val.value.v;
                if (pipeline) pipeline->stop_time = np_time_now();
            }
            np_spinlock_unlock(&np_module(search)->pipeline_lock);

            if (np_module(search)->searchnode.results[sq.query_id] && 
                np_module(search)->searchnode.results[sq.query_id]->size == 0)
            {
                np_index_destroy(&sq.query_entry.search_index);            
                free(search_string);

                json_obj = __np_generate_error_json(
                    "search invalid", "no search results found ...");
                http_status = HTTP_CODE_NO_CONTENT;
                goto __json_return__;
            }

            np_tree_insert_str(ht_response->ht_header, "Content-Type", np_treeval_new_s("application/json") );

            np_tree_t* srs_tree = np_tree_create();

            np_data_value search_val_title  = { 0 };
            search_val_title.str = "";

            uint32_t byte_count = 0;

            np_tree_elem_t* tmp = NULL;
            uint16_t i = 0;
            np_spinlock_lock(&np_module(search)->results_lock[sq.query_id]);
            RB_FOREACH(tmp, np_tree_s, np_module(search)->searchnode.results[sq.query_id]) 
            {
                np_searchresult_t* result = tmp->val.value.v;

                np_tree_t* r_tree = np_tree_create();
                struct np_data_conf conf = { 0 };
                np_data_value val_title  = { 0 };
                if (np_data_ok != np_get_data((np_datablock_t*) result->result_entry->intent.attributes, "title", &conf, &val_title ) )
                {
                    val_title.str = "";
                }
                np_tree_insert_str(r_tree, "hit_counter", np_treeval_new_i(result->hit_counter));
                np_tree_insert_str(r_tree, "similarity", np_treeval_new_f(result->level));
                np_tree_insert_str(r_tree, "label", np_treeval_new_s(result->label));
                np_tree_insert_str(r_tree, "title", np_treeval_new_s(val_title.str));

                // TODO:
                // __encode_intent(r_tree, result->intent);

                byte_count += r_tree->byte_size;
                if (byte_count < UINT16_MAX)
                {
                    np_tree_insert_int(srs_tree, i, np_treeval_new_tree(r_tree));
                    log_msg(LOG_DEBUG,  "%5s :: %s :: %3u / %2.2f / %5s", 
                                    search_val_title.str, tmp->key.value.s, result->hit_counter, result->level, val_title.str);
                }
                else
                {
                    log_msg(LOG_DEBUG,  "please implement pagination of search results");                    
                }
                i++;
                np_tree_free(r_tree);
            }    
            np_spinlock_unlock(&np_module(search)->results_lock[sq.query_id]);
   
            popro_stop_time = clock();

            log_msg(LOG_DEBUG,  "search query took %3.6f seconds", (double) (query_stop_time-start_time) / CLOCKS_PER_SEC);
            log_msg(LOG_DEBUG,  "search popro took %3.6f seconds", (double) (popro_stop_time-start_time) / CLOCKS_PER_SEC);

            JSON_Value* search_result_in_json = np_tree2json(context, srs_tree);
            ht_response->ht_body = np_json2char(search_result_in_json, true);
            ht_response->ht_length = strnlen(ht_response->ht_body, UINT16_MAX + 4096);
            http_status = HTTP_CODE_OK;

            np_tree_free(srs_tree);
            json_value_free(search_result_in_json);
            np_index_destroy(&sq.query_entry.search_index);            

            ht_response->cleanup_body = true;
        }
        else
        {
            free(search_string);
            log_msg(LOG_DEBUG,  "no search result");
            json_obj = __np_generate_error_json(
                "request invalid", "unable to to create query from arguments ...");
            http_status = HTTP_CODE_BAD_REQUEST;
            goto __json_return__; 
        }

        free(search_string);
    }
    else 
    {
        json_obj = __np_generate_error_json(
            "nothing to do", "unable to to create query from arguments ...");
        http_status = HTTP_CODE_NO_CONTENT;
        goto __json_return__; 
    }

__json_return__:

    if (json_obj != NULL) 
    {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "serialise json response");

        np_tree_insert_str( ht_response->ht_header, "Content-Type", np_treeval_new_s("application/json") );

        ht_response->ht_body = np_json2char(json_obj, false);
        ht_response->ht_length = strnlen(ht_response->ht_body, UINT16_MAX);

        json_value_free(json_obj);
    }
    ht_response->ht_status = http_status;

    // by now there should be a response
    if (http_status == HTTP_CODE_INTERNAL_SERVER_ERROR) 
    {
        log_msg(LOG_ERROR, "HTTP return is not defined for this code path");
    } 

    return http_status;
}

// pipeline callbacks
bool __np_search_query(np_context* ac, const np_message_t* const msg, np_tree_t* body, void* localdata) 
{
    np_ctx_cast(ac);

    np_tree_t* pipeline_results = (np_tree_t*) localdata;
    struct search_pipeline_result * pipeline = NULL;
    
    np_spinlock_lock(&np_module(search)->pipeline_lock);
    if (NULL == np_tree_find_str(pipeline_results, msg->uuid)) abort();
    else pipeline = np_tree_find_str(pipeline_results, msg->uuid)->val.value.v;
    np_spinlock_unlock(&np_module(search)->pipeline_lock);

    np_searchquery_t* query = pipeline->obj.query;

    np_map_reduce_t mr = { .map=_map_np_searchentry, .reduce=_reduce_np_searchentry };

    mr.map_args.io = &query->query_entry;
    mr.map_args.kv_pairs = np_tree_create();
    np_tree_insert_int(mr.map_args.kv_pairs, 1, np_treeval_new_f(0.5));
    sll_init(void_ptr, mr.map_result);

    if (!_np_dhkey_equal(&pipeline->sending_peer_dhkey, &dhkey_zero)) // remote query
        mr.reduce_result = np_tree_create();
    else                                                              // local query
        mr.reduce_result = np_module(search)->searchnode.results[query->query_id];
    
        
    // prepare reply sending by creating the private reply subject
    np_subject result_subject = {0};
    if (!_np_dhkey_equal(&pipeline->sending_peer_dhkey, &dhkey_zero) )
    {
        np_generate_subject(&result_subject, SEARCH_RESULT_SUBJECT, strnlen(SEARCH_RESULT_SUBJECT, 256));
        np_generate_subject(&result_subject, &pipeline->sending_peer_dhkey, NP_FINGERPRINT_BYTES);
    }

    // not all parts of the index matched, we have to handle the query locally as well
    if (pipeline->remote_distribution_count <= 6)
    {
/*    uint16_t min_index[8];
    uint16_t snd_index[8];
    np_dhkey_t min_diff = { .t[0] = UINT32_MAX, .t[1] = UINT32_MAX, .t[2] = UINT32_MAX, .t[3] = UINT32_MAX, .t[4] = UINT32_MAX, .t[5] = UINT32_MAX, .t[6] = UINT32_MAX, .t[7] = UINT32_MAX, };
    for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count; i++) 
    {
        // TODO: distance could be the same for two different tables. Right now the first table wins. Is there a better solution?
        np_dhkey_t diff = { 0 };
        _np_dhkey_hamming_distance_each(&diff, &query->query_entry.search_index.lower_dhkey, &np_module(search)->searchnode.tree[i]->_root._key);
        for (uint8_t j = 0; j < 8; j++) 
        {
            if (diff.t[j] < min_diff.t[j]) 
            {
                log_msg(LOG_DEBUG,  "         into table %u (distance %u [at %u] : old %u)", i , diff.t[j], j, snd_index[j]);
                snd_index[j] = min_index[j];
                min_index[j] = i;
                min_diff.t[j] = diff.t[j];
            }
        }
    }
    */
        uint8_t dh_diff = {0};
        struct __search_table_bucket buckets[np_module(search)->searchnode.local_table_count];
        memset(&buckets, 0, np_module(search)->searchnode.local_table_count*sizeof(struct __search_table_bucket));

        uint8_t max_query_count = (np_module(search)->searchnode.local_table_count < 16) ? np_module(search)->searchnode.local_table_count : 16;
        for (uint8_t j = 0; j < max_query_count; j++) 
        {
            // #pragma omp parallel for shared(query)
            for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count; i++) 
            {
                _np_dhkey_hamming_distance(&dh_diff, &query->query_entry.search_index.lower_dhkey, &np_module(search)->searchnode.tree[i]->_root._key);
                buckets[i].hamming_distance = dh_diff;
                buckets[i].index = i;
            }
        }
        qsort(buckets, np_module(search)->searchnode.local_table_count, sizeof(struct __search_table_bucket), __search_table_bucket_cmp);
        // log_msg(LOG_DEBUG,  "         into table: ");
        // for (uint16_t i = 0; i < 16; i++) 
        // {
        //             log_msg(LOG_DEBUG,  "%u (%u) : ", buckets[i].index , buckets[i].hamming_distance);
        // }
        // log_msg(LOG_DEBUG,  "");
        // log_msg(LOG_DEBUG,  "searching in   table: ");
        // #pragma omp parallel for shared(query)
        for (uint16_t j = 0; (j < max_query_count) && (mr.reduce_result->size == 0); j++)
        {
            log_msg(LOG_DEBUG,  "distribution factor for %s was %2d, querying locally in %3d | distance %3d", msg->uuid, pipeline->remote_distribution_count, buckets[j].index, buckets[j].hamming_distance);
            // log_msg(LOG_DEBUG,  " %2u (distance %3u [at %2u] )", buckets[j].index , buckets[j].hamming_distance, j);
            // np_skipbi_query(&lsh->_skipbi[j], &mr);

            np_spinlock_lock(&np_module(search)->table_lock[j]);
            np_bktree_query(np_module(search)->searchnode.tree[ buckets[j].index ], query->query_entry.search_index.lower_dhkey, &query->query_entry, &mr);
            np_spinlock_unlock(&np_module(search)->table_lock[j]);


            np_spinlock_lock(&np_module(search)->results_lock[query->query_id]);
            sll_iterator(void_ptr) iterator = sll_first(mr.map_result);
            while (iterator != NULL) 
            {
                mr.reduce(&mr, iterator->val);
                sll_next(iterator);
            }
            np_spinlock_unlock(&np_module(search)->results_lock[query->query_id]);

            // np_bktree_query(np_module(search)->searchnode.tree[ min_index[j] ], entry->query_entry.search_index.upper_dhkey, &entry->query_entry, &mr);
            sll_clear(void_ptr, mr.map_result);
        }
    }
    else
    {
        log_msg(LOG_DEBUG,  "distribution factor for %s was %2d, not querying locally", msg->uuid, pipeline->remote_distribution_count);
    }
    // log_msg(LOG_DEBUG,  "");

    // if (mr.map_result->size == 0) 
    // {
    //     // log_msg(LOG_DEBUG,  "searching in   table: ");
    //     for (uint16_t j = 0; j < 8; j++) 
    //     {
    //         // log_msg(LOG_DEBUG,  " %2u (distance %3u [at %2u] )", min_index[j] , min_diff.t[j], j);
    //         // np_skipbi_query(&lsh->_skipbi[j], &mr);
    //         np_bktree_query(np_module(search)->searchnode.tree[ snd_index[j] ], query->query_entry.search_index.lower_dhkey, &query->query_entry, &mr);
    //         // np_bktree_query(np_module(search)->searchnode.tree[ min_index[j] ], entry->query_entry.search_index.upper_dhkey, &entry->query_entry, &mr);
    //         // sll_clear(void_ptr, mr.map_result);
    //     }
    // }
    // sll_iterator(void_ptr) iterator = sll_first(mr.map_result);
    // while (iterator != NULL) 
    // {
    //     mr.reduce(&mr, iterator->val);
    //     sll_next(iterator);
    // }

    if (!_np_dhkey_equal(&pipeline->sending_peer_dhkey, &dhkey_zero) )
    {
        np_tree_elem_t* tmp = NULL;
        RB_FOREACH (tmp, np_tree_s, mr.reduce_result)
        {
            np_searchresult_t* result = tmp->val.value.v;
            result->query_id = query->query_id;
            strncpy(result->result_uuid, query->result_uuid, NP_UUID_BYTES);
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
    //     if (np_data_ok != np_get_data((np_datablock_t*) query->query_entry.intent.attributes, "title", &search_conf, &search_val_title ) )
    //     {
    //         search_val_title.str = "";
    //     }
    //     np_tree_elem_t* tmp = NULL;

    //     np_spinlock_lock(&np_module(search)->results_lock[query->query_id]);
    //     RB_FOREACH(tmp, np_tree_s, np_module(search)->searchnode.results[query->query_id]) 
    //     {
    //         np_searchresult_t* result = tmp->val.value.v;

    //         struct np_data_conf conf = { 0 };
    //         np_data_value val_title  = { 0 };
    //         if (np_data_ok != np_get_data((np_datablock_t*) result->result_entry->intent.attributes, "title", &conf, &val_title ) )
    //         {
    //             val_title.str = "";
    //         }
    //         log_msg(LOG_INFO, "search result %-5s :: %s :: %3u / %2.2f / %5s", 
    //                           search_val_title.str, tmp->key.value.s, result->hit_counter, result->level, val_title.str);
    //     }
    //     np_spinlock_unlock(&np_module(search)->results_lock[query->query_id]);
    // }

    // np_tree_del_str(pipeline_results, msg->uuid);
    // free(pipeline);

    return true;
}

bool __np_search_add_entry(np_context* ac, const np_message_t* const msg, np_tree_t* body, void* localdata) 
{
    np_ctx_cast(ac);

    np_tree_t* pipeline_results = (np_tree_t*) localdata;
    struct search_pipeline_result * pipeline = NULL;
    
    np_spinlock_lock(&np_module(search)->pipeline_lock);
    if (NULL == np_tree_find_str(pipeline_results, msg->uuid)) abort();
    else pipeline = np_tree_find_str(pipeline_results, msg->uuid)->val.value.v;
    np_spinlock_unlock(&np_module(search)->pipeline_lock);

/*
    uint16_t min_index[8];
    np_dhkey_t min_diff = { .t[0] = UINT32_MAX, .t[1] = UINT32_MAX, .t[2] = UINT32_MAX, .t[3] = UINT32_MAX, .t[4] = UINT32_MAX, .t[5] = UINT32_MAX, .t[6] = UINT32_MAX, .t[7] = UINT32_MAX, };
    for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count; i++) 
    {
        // TODO: distance could be the same for two different tables. Right now the first table wins. Is there a better solution?
        np_dhkey_t diff = { 0 };
        _np_dhkey_hamming_distance_each(&diff, &entry->search_index.lower_dhkey, &np_module(search)->searchnode.tree[i]->_root._key);
        for (uint8_t j = 0; j < 8; j++) 
        {
            if (diff.t[j] < min_diff.t[j]) 
            {
                // log_msg(LOG_DEBUG,  "         into table %u (distance %u [at %u] )", i , diff.t[j], j);
                min_index[j] = i;
                min_diff.t[j] = diff.t[j];
            }
        }
    }
*/

    if (pipeline->remote_distribution_count <= 6)
    {
        uint8_t dh_diff = {0};
        struct __search_table_bucket buckets[np_module(search)->searchnode.local_table_count];
        uint8_t max_create_count = (np_module(search)->searchnode.local_table_count < 8) ? np_module(search)->searchnode.local_table_count : 8;
        for (uint8_t j = 0; j < max_create_count; j++) 
        {
            // #pragma omp parallel for shared(entry)
            for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count; i++) 
            {
                _np_dhkey_hamming_distance(&dh_diff, &pipeline->obj.entry->search_index.lower_dhkey, &np_module(search)->searchnode.tree[i]->_root._key);
                buckets[i].hamming_distance = dh_diff;
                buckets[i].index = i;
            }
        }

        qsort(buckets, np_module(search)->searchnode.local_table_count, sizeof(struct __search_table_bucket), __search_table_bucket_cmp);

        // log_msg(LOG_DEBUG,  "         into table: ");
        // for (uint16_t i = 0; i < 16; i++) 
        // {
        //             log_msg(LOG_DEBUG,  "%u (%u) : ", buckets[i].index , buckets[i].hamming_distance);
        // }
        // log_msg(LOG_DEBUG,  "");

        // uint8_t i = 0;
        // log_msg(LOG_DEBUG,  "inserting into table: ");
        // #pragma omp parallel for shared(entry)
        for (uint16_t j = 0; j < max_create_count; j++) 
        {
            log_msg(LOG_DEBUG,  "distribution factor for %s was %2d, storing locally in %3d | distance %3d", msg->uuid, pipeline->remote_distribution_count, buckets[j].index, buckets[j].hamming_distance);
            
            np_spinlock_lock(&np_module(search)->table_lock[j]);

            // log_msg(LOG_DEBUG,  " %2u (distance %3u [at %2u] )", buckets[j].index , buckets[j].hamming_distance, j);
            // log_msg(LOG_DEBUG,  "< NODE INDEX:> ");
            // for (uint32_t k = 0; k < 8; k++) 
            // {
            //     log_msg(LOG_DEBUG,  "%08x", lsh->_bktree[j]._root._key.t[k]);
            //     log_msg(LOG_DEBUG,  ".");
            // }
            // log_msg(LOG_DEBUG,  " </ NODE INDEX:>");
            np_bktree_insert(np_module(search)->searchnode.tree[ buckets[j].index ], pipeline->obj.entry->search_index.lower_dhkey, pipeline->obj.entry);

            np_spinlock_unlock(&np_module(search)->table_lock[j]);

            // np_bktree_insert(np_module(search)->searchnode.tree[ min_index[j] ], entry->search_index.upper_dhkey, entry);
            // np_skipbi_add(&lsh->_skipbi[j], _lp);
        }
        // log_msg(LOG_DEBUG,  "");
    }
    else 
    {
        log_msg(LOG_DEBUG,  "distribution factor for %s was %2d, not querying locally", msg->uuid, pipeline->remote_distribution_count);
        np_searchentry_t* entry = pipeline->obj.entry;
        np_index_destroy(&entry->search_index);
        free(entry);
    }

    pipeline->stop_time = np_time_now();
    
    return true; 
}

bool __check_remote_peer_distribution(np_context* ac, const np_message_t* const msg, np_tree_t* body, void* localdata) 
{
	np_ctx_cast(ac);

    np_tree_t* pipeline_results = (np_tree_t*) localdata;
    struct search_pipeline_result * pipeline = NULL;
    
    np_spinlock_lock(&np_module(search)->pipeline_lock);
    if (NULL == np_tree_find_str(pipeline_results, msg->uuid)) abort();
    else pipeline = np_tree_find_str(pipeline_results, msg->uuid)->val.value.v;
    np_spinlock_unlock(&np_module(search)->pipeline_lock);

    pipeline->remote_distribution_count = 0;            

    // check for chunked hamming distance to catch the index      
    np_dhkey_t local_diff_index  = {0};
    _np_dhkey_hamming_distance_each(&local_diff_index, &pipeline->search_index, &np_module(search)->searchnode.node_id);
    // within the index choose the entry with the lowest overall hamming distance
    // uint8_t dh_diff_target  = 0;
    // _np_dhkey_hamming_distance(&dh_diff_target, &search_index, &np_module(search)->searchnode->node_id);

    bool is_zero = false;

    struct __search_table_bucket buckets[8][32];
    memset(&buckets, 0, np_module(search)->searchnode.local_table_count*sizeof(struct __search_table_bucket));

    for (uint8_t j = 0; j < 8; j++)
    {
        np_spinlock_lock(&np_module(search)->peer_lock[j]);
        uint8_t best_index     = 32;
        int8_t  local_index    = local_diff_index.t[j];        
        uint8_t dh_diff_target = local_diff_index.t[j];

        // search best competitor entry with an equal distance
        np_dhkey_t peer_diff_index = {0};
        _np_dhkey_hamming_distance_each(&peer_diff_index, &pipeline->search_index, &np_module(search)->searchnode.peers[j][local_index]);

        int8_t index = peer_diff_index.t[j];                
        int8_t delta = local_diff_index.t[j] - peer_diff_index.t[j];

        log_msg(LOG_DEBUG,  "%2d local distance %3d | peer distance %3d | %3d |", j, local_diff_index.t[j], peer_diff_index.t[j], delta);
        while(index != 0) 
        {   
            _np_dhkey_hamming_distance_each(&peer_diff_index, &pipeline->search_index, &np_module(search)->searchnode.peers[j][index]);
            // prevent follow up actions with empty cells
            is_zero = _np_dhkey_equal(&dhkey_zero, &np_module(search)->searchnode.peers[j][index]);

            if (!is_zero && peer_diff_index.t[j] < dh_diff_target) 
            {
                best_index = index;
                dh_diff_target = peer_diff_index.t[j];
            } 

            if (index == local_diff_index.t[j]) index = 0;
            else                                index = (delta > 0) ? index+1 : index-1;

            if (32 <= index) index = 0;
            log_msg(LOG_DEBUG,  "[%p]                       | peer distance %3d | next index %3d | best index %3d ", ac, peer_diff_index.t[j], index, best_index);
        }
 
        if (best_index < 32) 
        {
            np_dhkey_t localized_subject;
            _np_dhkey_assign(&localized_subject, &pipeline->search_subject);
            np_generate_subject(&localized_subject, &np_module(search)->searchnode.peers[j][best_index], NP_FINGERPRINT_BYTES);
            
            np_dhkey_t target_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, localized_subject);

            np_message_t* cloned_msg = NULL;
            np_new_obj(np_message_t, cloned_msg, FUNC);
            np_message_clone(cloned_msg, msg);

            np_tree_replace_str(cloned_msg->header, _NP_MSG_HEADER_SUBJECT, np_treeval_new_dhkey(localized_subject));
            np_tree_replace_str(cloned_msg->header, _NP_MSG_HEADER_FROM, np_treeval_new_dhkey(context->my_node_key->dhkey));

            np_util_event_t send_event = { .type=(evt_internal | evt_message), .user_data=cloned_msg, .target_dhkey=dhkey_zero };
            // _np_keycache_handle_event(context, subject_dhkey, send_event, false);
            if(!np_jobqueue_submit_event(context, 0.0, target_dhkey, send_event, "event: userspace message delivery request"))
            {
                log_msg(LOG_DEBUG,  "rejecting possible sending of message, please check jobqueue settings!");
            }
            else 
            {
                char tmp[65];
                np_id_str(tmp, &localized_subject);
                log_msg(LOG_DEBUG,  "send new search object to peer: %"PRIx32" via channel %s (%s)",
                                   np_module(search)->searchnode.peers[j][best_index].t[0], tmp, msg->uuid);
            }
            np_unref_obj(np_message_t, cloned_msg, FUNC);
            pipeline->remote_distribution_count++;
        } 
        
        np_spinlock_unlock(&np_module(search)->peer_lock[j]);
    }
    return true;
}

// dummy callbacks
bool _np_searchnode_announce_cb(np_context* context, struct np_message* token_msg) 
{ 
    // just here for the completion of the api, will never be called
    return true;
}

np_search_settings_t* np_default_searchsettings() 
{
    np_search_settings_t* settings = calloc(1, sizeof(np_search_settings_t));
    settings->enable_remote_peers = true;
    settings->local_table_count = 16;
    settings->local_table_count = BKTREE_ARRAY_SIZE;

    memset(settings->search_space, 0, NP_FINGERPRINT_BYTES);

    // add more file specific settings
    
    return settings;
}

// initialize the np_searchnode structure and associated message exchanges
void np_searchnode_init(np_context* ac, np_search_settings_t* settings)
{
	np_ctx_cast(ac);

    if (np_module_not_initiated(search))
    {
        np_module_malloc(search);
        np_module(search)->query_id = 0;

        // np_module(search)->pipeline_results = np_tree_create();
        // np_module(search)->pipeline_results = np_tree_create();

        if (settings)
            np_module(search)->searchnode.local_table_count = settings->local_table_count;
        else
            np_module(search)->searchnode.local_table_count = BKTREE_ARRAY_SIZE;

        randombytes_buf(&np_module(search)->searchnode.node_id, NP_FINGERPRINT_BYTES);
        
        for (uint8_t i = 0; i < UINT8_MAX; i++)
            np_spinlock_init(&np_module(search)->results_lock[i], PTHREAD_PROCESS_PRIVATE);

        for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count; i++)
            np_spinlock_init(&np_module(search)->table_lock[i], PTHREAD_PROCESS_PRIVATE);

        for (uint8_t i = 0; i <= 8; i++)
            np_spinlock_init(&np_module(search)->peer_lock[i], PTHREAD_PROCESS_PRIVATE);

        np_spinlock_init(&np_module(search)->pipeline_lock, PTHREAD_PROCESS_PRIVATE);

        char _tmp[65] = {0};
        np_id_str(_tmp, &np_module(search)->searchnode.node_id);
        log_msg(LOG_INFO, "starting up searchnode, peer id is: %s", _tmp);

        for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count; i++)
        {
            np_dhkey_t seed = {0};
            randombytes_buf(&seed, sizeof (np_dhkey_t) );
            np_module(search)->searchnode.tree[i] = malloc(sizeof(np_bktree_t));
            np_bktree_init(np_module(search)->searchnode.tree[i], seed, 10);
            // np_bktree_init(__my_searchresults.entries[i], seed, 10);
        }
        memset(np_module(search)->searchnode.results, 0, UINT8_MAX*sizeof(np_tree_t*));
        memset(np_module(search)->searchnode.queries, 0, UINT8_MAX*sizeof(np_searchquery_t*));
        
        if (settings == NULL || settings->enable_remote_peers == true)
        {
            memset(np_module(search)->searchnode.peers, 0, sizeof(np_module(search)->searchnode.peers));

            if (np_data_ok != np_set_ident_attr_bin(ac, NULL, NP_ATTR_INTENT_AND_IDENTITY, SEARCH_PEERID, &np_module(search)->searchnode.node_id, NP_FINGERPRINT_BYTES) )
            {
                log_msg(LOG_DEBUG,  "could not set search peer id to context / intent messages");
            }

            // search internal message types
            np_sll_t(np_msgproperty_conf_ptr, msgproperties);
            msgproperties = default_search_msgproperties(context);
            sll_iterator(np_msgproperty_conf_ptr) __np_search_messages = sll_first(msgproperties);

            while (__np_search_messages != NULL)
            {
                np_msgproperty_conf_t* property = __np_search_messages->val;
                property->is_internal = false;

                char* tmp = property->msg_subject;
                // np_generate_subject(&property->subject_dhkey, property->msg_subject, strnlen(property->msg_subject, 256));

                if (property->audience_type == NP_MX_AUD_PRIVATE) 
                {   // seed the private subject with the peer id to disguise/localize the interface
                    np_generate_subject(&property->subject_dhkey, property->msg_subject, strnlen(property->msg_subject, 256));
                    np_generate_subject(&property->subject_dhkey, &np_module(search)->searchnode.node_id, NP_FINGERPRINT_BYTES);
                }
                else if (settings) 
                {   // seed the initial discovery subject with the search space from the settings (create a private sub-space for searching)
                    memcpy(&property->subject_dhkey, settings->search_space, NP_FINGERPRINT_BYTES);
                    np_generate_subject(&property->subject_dhkey, property->msg_subject, strnlen(property->msg_subject, 256));
                }
                else
                {   // use the default search space (whoever defined it), so everybody can discover and use our search peer
                    np_generate_subject(&property->subject_dhkey, property->msg_subject, strnlen(property->msg_subject, 256));
                }                

                property->msg_subject = calloc(65, sizeof(char));
                np_id_str(property->msg_subject, &property->subject_dhkey);

                np_id_str(_tmp, &np_module(search)->searchnode.node_id);
                log_msg(LOG_INFO,  "adding peer search subject %s, peer id is %s / %s", property->msg_subject, _tmp, tmp);

                np_msgproperty_register(property);

                if      (strncmp(tmp, SEARCH_ENTRY_SUBJECT, 256) == 0) 
                {
                    np_add_receive_listener(context, _np_new_searchentry_cb,           &np_module(search)->pipeline_results, property->subject_dhkey);
                    np_add_receive_listener(context, __check_remote_peer_distribution, &np_module(search)->pipeline_results, property->subject_dhkey);
                    np_add_receive_listener(context, __np_search_add_entry,            &np_module(search)->pipeline_results, property->subject_dhkey);
                }
                else if (strncmp(tmp, SEARCH_QUERY_SUBJECT, 256) == 0) 
                {
                    np_add_receive_listener(context, _np_new_searchquery_cb,           &np_module(search)->pipeline_results, property->subject_dhkey);
                    np_add_receive_listener(context, __check_remote_peer_distribution, &np_module(search)->pipeline_results, property->subject_dhkey);
                    np_add_receive_listener(context, __np_search_query,                &np_module(search)->pipeline_results, property->subject_dhkey);
                }
                else if (strncmp(tmp, SEARCH_RESULT_SUBJECT, 256) == 0) 
                {
                    np_add_receive_listener(context, _np_searchresult_receive_cb,      &np_module(search)->pipeline_results, property->subject_dhkey);
                }

                np_set_mxp_attr_bin(context, &property->subject_dhkey, NP_ATTR_INTENT, SEARCH_PEERID, &np_module(search)->searchnode.node_id, NP_FINGERPRINT_BYTES);

                if (property->audience_type == NP_MX_AUD_VIRTUAL)
                    np_set_mx_authorize_cb(context, &property->subject_dhkey, __np_search_authorize_node_cb);
                if (property->audience_type == NP_MX_AUD_PRIVATE)
                    np_set_mx_authorize_cb(context, &property->subject_dhkey, __np_search_authorize_entries_cb);

                sll_next(__np_search_messages);
            }
            sll_free(np_msgproperty_conf_ptr, msgproperties);

            log_msg(LOG_DEBUG,  "added node as search peer, peer id is %08"PRIx32":%08"PRIx32"", np_module(search)->searchnode.node_id.t[0], np_module(search)->searchnode.node_id.t[1]);

            // np_jobqueue_submit_event_periodic(context, PRIORITY_MOD_USER_DEFAULT,
            //                             np_crypt_rand_mm(0, SYSINFO_PROACTIVE_SEND_IN_SEC*1000) / 1000.,
            //                             //sysinfo_response_props->msg_ttl / sysinfo_response_props->max_threshold,
            //                             SYSINFO_PROACTIVE_SEND_IN_SEC+.0,
            //                             _np_search_cleanup,
            //                             "_np_search_cleanup");
        }

        np_jobqueue_submit_event_periodic(
                                        context, 
                                        PRIORITY_MOD_USER_DEFAULT, NP_SEARCH_CLEANUP_INTERVAL, NP_SEARCH_CLEANUP_INTERVAL,
                                        __np_search_cleanup_pipeline, "__np_search_cleanup_pipeline");

        np_jobqueue_submit_event_periodic(
                                        context, 
                                        PRIORITY_MOD_USER_DEFAULT, NP_SEARCH_CLEANUP_INTERVAL, NP_SEARCH_CLEANUP_INTERVAL,
                                        __np_search_deprecate_entries, "__np_search_deprecate_entries");

    }
   
    // log_msg(LOG_DEBUG,  "pipeline_results %p->%p", context, &np_module(search)->pipeline_results);

    if (np_module_initiated(http)) 
    {
        _np_add_http_callback(ac, "search", htp_method_GET, context, __np_search_handle_http_get);
    }

    np_add_shutdown_cb(ac, _np_search_shutdown_hook);
    // log_msg(LOG_DEBUG,  "pipeline_results %p->%p", context, &np_module(search)->pipeline_results);
}

void np_searchclient_init(np_context* ac)
{
	np_ctx_cast(ac);

    if (np_module_not_initiated(search))
    {
        np_module_malloc(search);
        np_module(search)->query_id = 0;
        // np_module(search)->pipeline_results = np_tree_create();
    
        np_module(search)->searchnode.local_table_count = BKTREE_ARRAY_SIZE;
        randombytes_buf(&np_module(search)->searchnode.node_id, NP_FINGERPRINT_BYTES);

        for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count; i++)
        {
            np_dhkey_t seed = {0};
            randombytes_buf(&seed, sizeof (np_dhkey_t) );
            np_module(search)->searchnode.tree[i] = malloc(sizeof(np_bktree_t));
            np_bktree_init(np_module(search)->searchnode.tree[i], seed, 10);

            memset(np_module(search)->searchnode.results, 0, UINT8_MAX*sizeof(np_searchresult_t));
            memset(np_module(search)->searchnode.queries, 0, UINT8_MAX*sizeof(np_searchquery_t));
            // np_bktree_init(__my_searchresults.entries[i], seed, 10);
        }        

        memset(np_module(search)->searchnode.peers, 0, 8*32*NP_FINGERPRINT_BYTES);

        np_set_authorize_cb(context, __np_search_authorize_node_cb);

        np_subject search_node_subject = {0};
        np_generate_subject(&search_node_subject, SEARCH_NODE_SUBJECT, strnlen(SEARCH_NODE_SUBJECT, 256));

        struct np_mx_properties search_property = np_get_mx_properties(context, search_node_subject);

        search_property.role = NP_MX_PROSUMER;
        search_property.audience_type = NP_MX_AUD_VIRTUAL;
        search_property.intent_ttl = NP_SEARCH_NODE_TTL;
        search_property.intent_update_after = NP_SEARCH_INTENT_REFRESH_TTL;
        np_set_mx_properties(context, search_node_subject, search_property);
        np_set_mxp_attr_bin(context, search_node_subject, NP_ATTR_INTENT, SEARCH_PEERID, &np_module(search)->searchnode.node_id, NP_FINGERPRINT_BYTES);
        np_set_mx_authorize_cb(context, search_node_subject, __np_search_authorize_node_cb);

        log_msg(LOG_DEBUG,  "adding node as search client, peer id is %08"PRIx32":%08"PRIx32"", np_module(search)->searchnode.node_id.t[0], np_module(search)->searchnode.node_id.t[1]);

        np_subject search_result_subject = {0};
        np_generate_subject(&search_result_subject, SEARCH_RESULT_SUBJECT, strnlen(SEARCH_RESULT_SUBJECT, 256));
        np_generate_subject(&search_result_subject, &np_module(search)->searchnode.node_id, NP_FINGERPRINT_BYTES);
        search_property.role = NP_MX_CONSUMER;
        search_property.audience_type = NP_MX_AUD_PRIVATE;
        search_property.intent_ttl = NP_SEARCH_RESULT_TTL;
        search_property.intent_update_after = NP_SEARCH_INTENT_REFRESH_TTL;
        np_set_mx_properties(context, search_result_subject, search_property);
        np_set_mxp_attr_bin(context, search_result_subject, NP_ATTR_INTENT, SEARCH_PEERID, &np_module(search)->searchnode.node_id, NP_FINGERPRINT_BYTES);
        // TODO: set explicit callback for search entries. the same authz as for node, but without registration
        np_set_mx_authorize_cb(context, search_result_subject, __np_search_authorize_entries_cb);
        
        np_mx_properties_disable(context, search_result_subject);

        // setup how entries can be queried / receiver channels
        np_subject search_query_subject = {0};
        np_generate_subject(&search_query_subject, SEARCH_QUERY_SUBJECT, strnlen(SEARCH_QUERY_SUBJECT, 256));
        np_generate_subject(&search_query_subject, &np_module(search)->searchnode.node_id, NP_FINGERPRINT_BYTES);
        randombytes_buf(search_property.reply_id, NP_FINGERPRINT_BYTES);
        search_property.role = NP_MX_PROVIDER;
        search_property.audience_type = NP_MX_AUD_PRIVATE;
        search_property.intent_ttl = NP_SEARCH_INTENT_TTL;
        search_property.intent_update_after = NP_SEARCH_INTENT_REFRESH_TTL;
        memcpy(search_property.reply_id, search_result_subject, NP_FINGERPRINT_BYTES);
        np_set_mx_properties(context, search_query_subject, search_property);
        np_set_mxp_attr_bin(context, search_query_subject, NP_ATTR_INTENT, SEARCH_PEERID, &np_module(search)->searchnode.node_id, NP_FINGERPRINT_BYTES);
        // np_add_receive_cb(context, search_query_subject, _np_new_searchquery_cb);
        np_set_mx_authorize_cb(context, search_query_subject, __np_search_authorize_entries_cb);
        log_msg(LOG_DEBUG,  "listening on search query subject, id is %02X%02X%02X%02X%02X%02X", search_query_subject[0], search_query_subject[1], search_query_subject[2], search_query_subject[3], search_query_subject[4], search_query_subject[5]);

        // np_jobqueue_submit_event_periodic(context, PRIORITY_MOD_USER_DEFAULT,
        //                             np_crypt_rand_mm(0, SYSINFO_PROACTIVE_SEND_IN_SEC*1000) / 1000.,
        //                             //sysinfo_response_props->msg_ttl / sysinfo_response_props->max_threshold,
        //                             SYSINFO_PROACTIVE_SEND_IN_SEC+.0,
        //                             _np_search_cleanup,
        //                             "_np_search_cleanup");
    }

    if (np_module_initiated(http)) 
    {
        _np_add_http_callback(ac, "search", htp_method_GET, context, __np_search_handle_http_get);
    }

    np_add_shutdown_cb(ac, _np_search_shutdown_hook);
}

void np_searchnode_destroy(np_context* ac) 
{
	np_ctx_cast(ac);

    if (np_module_not_initiated(search))
    {
        return;
    }
    np_module_var(search);

    for (uint16_t i = 0; i < np_module(search)->searchnode.local_table_count; i++)
    {
        np_bktree_destroy(np_module(search)->searchnode.tree[i]);
    }

    for (uint16_t i = 0; i < UINT8_MAX; i++)
    {
        np_tree_free(np_module(search)->searchnode.results[i]);
        np_spinlock_destroy(&np_module(search)->results_lock[i]);
    }

    for (uint8_t i = 0; i < np_module(search)->searchnode.local_table_count; i++)
        np_spinlock_destroy(&np_module(search)->table_lock[i]);
    for (uint8_t i = 0; i <= 8; i++)
        np_spinlock_destroy(&np_module(search)->peer_lock[i]);

    np_module_free(search);
}

void _np_search_shutdown_hook(np_context* ac)
{
    // TODO: tell the other nodes that this node will be down 


    // cleanup the search module
    np_searchnode_destroy(ac);
}

// (de-) serialization of search objects
np_tree_t* __encode_search_intent(struct np_token* data) 
{
    np_tree_t* intent_as_tree = np_tree_create();

    np_tree_insert_str(intent_as_tree, "uuid", np_treeval_new_s(data->uuid));
    np_tree_insert_str(intent_as_tree, "subject", np_treeval_new_s(data->subject));
    np_tree_insert_str(intent_as_tree, "issuer", np_treeval_new_bin(data->issuer, NP_FINGERPRINT_BYTES));
    np_tree_insert_str(intent_as_tree, "realm", np_treeval_new_bin(data->realm, NP_FINGERPRINT_BYTES));
    np_tree_insert_str(intent_as_tree, "audience", np_treeval_new_bin(data->audience, NP_FINGERPRINT_BYTES));
    np_tree_insert_str(intent_as_tree, "not_before", np_treeval_new_d(data->not_before));
    np_tree_insert_str(intent_as_tree, "expires_at", np_treeval_new_d(data->expires_at));
    np_tree_insert_str(intent_as_tree, "issued_at", np_treeval_new_d(data->issued_at));
    np_tree_insert_str(intent_as_tree, "public_key", np_treeval_new_bin(data->public_key, NP_PUBLIC_KEY_BYTES));
    np_tree_insert_str(intent_as_tree, "signature", np_treeval_new_bin(data->signature, NP_SIGNATURE_BYTES));

    size_t attr_size = 0;
    np_get_data_size((np_datablock_t*) data->attributes, &attr_size);
    np_tree_insert_str(intent_as_tree, "attributes", np_treeval_new_bin(data->attributes, attr_size));
    np_tree_insert_str(intent_as_tree, "attributes_signature", np_treeval_new_bin(data->attributes_signature, NP_SIGNATURE_BYTES));

    return intent_as_tree;
}

bool __decode_search_intent(np_tree_t* tree, struct np_token* data) 
{
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

    strncpy(data->uuid, uuid.value.s, NP_UUID_BYTES);
    strncpy(data->subject, subject.value.s, subject.size);
    memcpy(&data->realm, realm.value.bin, NP_FINGERPRINT_BYTES);    
    memcpy(&data->issuer, issuer.value.bin, NP_FINGERPRINT_BYTES);    
    memcpy(&data->audience, audience.value.bin, NP_FINGERPRINT_BYTES);  
    data->expires_at = expires_at.value.d;  
    data->issued_at = issued_at.value.d;  
    data->not_before = not_before.value.d;  
    memcpy(data->public_key, public_key.value.bin, NP_PUBLIC_KEY_BYTES);
    memcpy(data->signature, signature.value.bin, NP_SIGNATURE_BYTES);

    memcpy(data->attributes, attributes.value.bin, attributes.size);
    memcpy(data->attributes_signature, attributes_signature.value.bin, NP_SIGNATURE_BYTES);

    __np_cleanup__: { /* return false; */ }

    return true;
}

np_tree_t* __encode_search_index(struct np_index* index) 
{
    np_tree_t* index_as_tree = np_tree_create();
    
    char* clk_data = NULL;
    size_t clk_size = 0;
    _np_neuropil_bloom_serialize(index->_clk_hash, &clk_data, &clk_size);
    
    np_tree_insert_str(index_as_tree, "idx", np_treeval_new_dhkey(index->lower_dhkey));
    np_tree_insert_str(index_as_tree, "clk", np_treeval_new_bin(clk_data, clk_size));

    return index_as_tree;
}

bool __decode_search_index(np_tree_t* tree, struct np_index* index) 
{
    CHECK_STR_FIELD(tree, "idx", idx);
    CHECK_STR_FIELD(tree, "clk", clk);

    index->_clk_hash = _np_neuropil_bloom_create();
    _np_neuropil_bloom_deserialize(index->_clk_hash, clk.value.bin, &clk.size);
    memcpy(&index->lower_dhkey, &idx.value.dhkey, NP_FINGERPRINT_BYTES);

    index->_cbl_index = NULL;
    index->_cbl_index_counter = NULL;

    __np_cleanup__: 
        // return false;
    
    return true;
}

//
// serialization of search entries
// 
np_tree_t* __encode_search_entry(np_searchentry_t* data) 
{
    np_tree_t* entry_as_tree = np_tree_create();

    np_tree_t* index_as_tree = __encode_search_index(&data->search_index);
    // log_msg(LOG_DEBUG,  "searchentry index as tree %p (%u / %u)", index_as_tree, index_as_tree->byte_size, index_as_tree->size);
    np_tree_insert_str(entry_as_tree, "entry.index", np_treeval_new_tree(index_as_tree));

    np_tree_t* intent_as_tree = __encode_search_intent(&data->intent);
    // log_msg(LOG_DEBUG,  "searchentry intent as tree %p (%u / %u)", intent_as_tree, intent_as_tree->byte_size, intent_as_tree->size);
    np_tree_insert_str(entry_as_tree, "entry.intent", np_treeval_new_tree(intent_as_tree));

    return entry_as_tree;
}

np_searchentry_t* __decode_search_entry(np_tree_t* data) 
{
    np_searchentry_t* new_entry = NULL;
    
    CHECK_STR_FIELD(data, "entry.index", search_index);
    CHECK_STR_FIELD(data, "entry.intent", search_intent);

    new_entry = calloc(1, sizeof(np_searchentry_t));

    // log_msg(LOG_DEBUG,  "searchentry index as tree %p (%u / %u)", search_index.value.tree, search_index.value.tree->byte_size, search_index.value.tree->size);
    if (!__decode_search_index(search_index.value.tree, &new_entry->search_index))
    {
        // log_msg(LOG_DEBUG,  "could not decode searchentry index");        
        free(new_entry);
        return NULL; 
    }

    // log_msg(LOG_DEBUG,  "searchentry intent as tree %p (%u / %u)", search_intent.value.tree, search_intent.value.tree->byte_size, search_intent.value.tree->size);
    if (!__decode_search_intent(search_intent.value.tree, &new_entry->intent))
    {
        // log_msg(LOG_DEBUG,  "could not decode searchentry intent");
        np_index_destroy(&new_entry->search_index);
        free(new_entry);
        return NULL;
    }

    __np_cleanup__: {}

    return new_entry;
}

//
// serialization of search queries
// 
np_tree_t* __encode_search_query(np_searchquery_t* data) 
{
    np_tree_t* query_as_tree = np_tree_create();

    np_tree_insert_str(query_as_tree, "query.query_id", np_treeval_new_ush(data->query_id));
    np_tree_insert_str(query_as_tree, "query.uuid", np_treeval_new_s(data->result_uuid));
    np_tree_insert_str(query_as_tree, "query.index", np_treeval_new_tree(__encode_search_index(&data->query_entry.search_index)));
    np_tree_insert_str(query_as_tree, "query.intent", np_treeval_new_tree(__encode_search_intent(&data->query_entry.intent)));
    
    return query_as_tree;
}

np_searchquery_t* __decode_search_query(np_tree_t* data) 
{
    np_searchquery_t* new_query = NULL;
    
    CHECK_STR_FIELD(data, "query.query_id", search_query_id);
    CHECK_STR_FIELD(data, "query.uuid", search_uuid);
    CHECK_STR_FIELD(data, "query.index", search_index);
    CHECK_STR_FIELD(data, "query.intent", search_intent);

    new_query = calloc(1, sizeof(np_searchquery_t));

    new_query->query_id = search_query_id.value.ush;
    strncpy(new_query->result_uuid, search_uuid.value.s, NP_UUID_BYTES);

    if (!__decode_search_index(search_index.value.tree, &new_query->query_entry.search_index))
    {
        free(new_query);
        return NULL; 
    }
    if (!__decode_search_intent(search_intent.value.tree, &new_query->query_entry.intent))
    {
        _np_bloom_free(new_query->query_entry.search_index._clk_hash);
        free(new_query);
        return NULL;
    }

    __np_cleanup__: {}

    return new_query;
}

//
// serialization of search queries
// 
np_tree_t* __encode_search_result(np_searchresult_t* data) 
{
    np_tree_t* result_as_tree = np_tree_create();

    np_tree_insert_str(result_as_tree, "result.query_id", np_treeval_new_ush(data->query_id));
    np_tree_insert_str(result_as_tree, "result.uuid", np_treeval_new_s(data->result_uuid));
    np_tree_insert_str(result_as_tree, "result.label", np_treeval_new_s(data->label));
    np_tree_insert_str(result_as_tree, "result.level", np_treeval_new_f(data->level));
    np_tree_insert_str(result_as_tree, "result.hit_count", np_treeval_new_ush(data->hit_counter));
    np_tree_insert_str(result_as_tree, "result.entry", np_treeval_new_tree(__encode_search_entry(data->result_entry)));

    return result_as_tree;
}

np_searchresult_t* __decode_search_result(np_tree_t* result_tree) 
{
    np_searchresult_t* new_result = NULL;

    CHECK_STR_FIELD(result_tree, "result.query_id", result_query_id);
    CHECK_STR_FIELD(result_tree, "result.uuid", result_uuid);
    CHECK_STR_FIELD(result_tree, "result.label", result_label);
    CHECK_STR_FIELD(result_tree, "result.level", result_level);
    CHECK_STR_FIELD(result_tree, "result.hit_count", result_hit_count);
    CHECK_STR_FIELD(result_tree, "result.entry", result_entry);

    new_result = calloc(1, sizeof(np_searchresult_t));

    new_result->query_id    = result_query_id.value.ush;
    strncpy(new_result->result_uuid, result_uuid.value.s, NP_UUID_BYTES);
    new_result->label       = strndup(result_label.value.s, 256);
    new_result->level       = result_level.value.f;
    new_result->hit_counter = result_hit_count.value.ush;

    new_result->result_entry = __decode_search_entry(result_entry.value.tree);
    if (NULL == new_result->result_entry)    
    {
        free(new_result);
        return NULL;
    }

    __np_cleanup__: {}

    return new_result;
}

// read a file and create the searchentry using the attributes
bool np_create_searchentry(np_context* ac, np_searchentry_t* entry, const char* text, np_attributes_t* attributes) 
{   
    bool ret = false;

	np_ctx_cast(ac);

    struct np_data_conf conf = { 0 };
    np_data_value val_urn  = { 0 };
    if (np_data_ok == np_get_data((np_datablock_t*) attributes, "urn", &conf, &val_urn ) )
    {
        np_index_init(&entry->search_index); 

        // TODO: base minhash_seed on actual content type (html/pdf/txt/sourcecode/newsfeed/...)
        np_dhkey_t minhash_seed = np_dhkey_create_from_hostport("", "");
        np_minhash_t minhash = {0};

        // TODO: extract keyword using tf-idf (c99 / libbow) and add them to the attributes
        // TODO: explore BM25 scoring for attributes and text analysis
        // TODO: only for pure text files right now, add different content types
        char* copied_text = strndup(text, strlen(text));

        uint16_t    count = 0;
        np_tree_t* text_as_array = np_tree_create();
        np_tree_t* text_occurance = np_tree_create();
        
        char* part = strtok (copied_text, __text_delimiter);
        while (part != NULL)
        {
            if (strnlen(part, 255) > 3) 
            {
                __lower_case(part, strnlen(part, 255));
                np_tree_insert_int(text_as_array, count, np_treeval_new_s(part) );

                if (np_tree_find_str(text_occurance, part) != NULL) 
                    np_tree_find_str(text_occurance, part)->val.value.a2_ui[1]++;
                else
                    np_tree_insert_str(text_occurance, part, np_treeval_new_iarray(count, 1) );

                count++;
            }
            part = strtok(NULL, __text_delimiter);
        }

        // np_data_value val_title  = { 0 };
        // if (np_data_ok == np_get_data((np_datablock_t*) attributes, "title", &conf, &val_title ) )
        // {
        //     log_msg(LOG_DEBUG,  "analyzing %s (%u unique words / %u words):", val_title, text_occurance->size, text_as_array->size);
        //     uint16_t i = 0;
        //     uint16_t occurences[text_occurance->size];
        //     np_tree_elem_t* tmp = NULL;
        //     RB_FOREACH(tmp, np_tree_s, text_occurance)
        //     {
        //         uint16_t word_count = tmp->val.value.a2_ui[1];
        //         if (word_count > 3 && word_count < 13)
        //             log_msg(LOG_DEBUG,  "word: %s (pos: %u) appeared %u times", tmp->key.value.s, tmp->val.value.a2_ui[0], tmp->val.value.a2_ui[1]);
        //         occurences[i++] = word_count;
        //     }
        //     qsort(occurences, text_occurance->size, sizeof(uint16_t), __compare_uint16_t);

        //     log_msg(LOG_DEBUG,  "analyzing %u / %u / %u / %u / %u:", 
        //             occurences[text_occurance->size*1/32], occurences[text_occurance->size*2/8], occurences[text_occurance->size*4/8],
        //             occurences[text_occurance->size*60/64], occurences[text_occurance->size*63/64]);
        //     np_minhash_t dd_minhash = {0};

        //     np_minhash_init(&dd_minhash, 512, true, minhash_seed);
        //     np_minhash_push_tree(&dd_minhash, text_as_array, 1, false);

        //     uint32_t dd_signature[512] = {0};
        //     np_minhash_signature(&dd_minhash, &dd_signature);
        //     for (uint32_t i = 0; i < 512; i++) 
        //     {
        //         if (i > 0 && (i%16 == 0))
        //             log_msg(LOG_DEBUG,  "");
        //         log_msg(LOG_DEBUG,  "%10u ", dd_signature[i]);
        //     }
        //     log_msg(LOG_DEBUG,  "");
        // }

        // abort();

        // TODO: get a copy of intent token for H("filename") and extend it with attributes
        np_minhash_init(&minhash, 256, false, minhash_seed);
        np_minhash_push_tree(&minhash, text_as_array, 1, false);

        np_index_update_with_minhash(&entry->search_index, &minhash);
    
        np_dhkey_t urn_dhkey = {0};
        np_generate_subject(&urn_dhkey, val_urn.str, strnlen(val_urn.str, 256));
        np_msgproperty_conf_t* prop = _np_msgproperty_get_or_create(np_module(search)->context, OUTBOUND, urn_dhkey);
        // np_merge_data(&prop->attributes, (np_datablock_t*) attributes);

        // TODO: fetch the already existing mx token for this subject
        np_message_intent_public_token_t* token = _np_token_factory_new_message_intent_token(prop);
        np_aaatoken4user(&entry->intent, token);
        np_merge_data((np_datablock_t*) entry->intent.attributes, (np_datablock_t*) attributes);

        // not now, but one possible solution
        // users could subscribe to each "search subject" to retrieve more information
        // but this also leads to a massive impact for the pheromone system, it has to be designed a bit more elegantly
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
    }
    else
    {
        log_msg(LOG_DEBUG,  "data element not found !!!");
    }
    return ret;
}

// read a query text and create the searchentry using the attributes
bool np_create_searchquery(np_context* ac, np_searchquery_t* query, const char* query_text, np_attributes_t* attributes) 
{ 
	np_ctx_cast(ac);

    if (np_module_not_initiated(search)) {
        np_searchnode_init(context, NULL);
    }

    // TODO: base minhash_seed on actual content type (html/pdf/txt/sourcecode)
    np_dhkey_t minhash_seed = np_dhkey_create_from_hostport("", "");
    np_minhash_t minhash = {0};

    np_index_init(&query->query_entry.search_index);

    // TODO: extract keyword using tf-idf (libbow) and add them to the attributes
    // TODO: only for pure text files right now, could also be defined for json (see also examples/neuropil_search_node_2.c )
    char* copied_text = strndup(query_text, strlen(query_text));

    uint16_t    count = 0;
    np_tree_t* text_as_array = np_tree_create();
    np_tree_t* text_occurance = np_tree_create();
    
    char* part = strtok (copied_text, __text_delimiter);
    while (part != NULL)
    {
        if (strnlen(part, 255) > 3) 
        {
            __lower_case(part, strnlen(part, 255));
            np_tree_insert_int(text_as_array, count, np_treeval_new_s(part) );

            if (np_tree_find_str(text_occurance, part) != NULL) 
                np_tree_find_str(text_occurance, part)->val.value.a2_ui[1]++;
            else
                np_tree_insert_str(text_occurance, part, np_treeval_new_iarray(count, 1) );

            count++;
        }
        part = strtok(NULL, __text_delimiter);
    }

    // TODO: get a copy of intent token for H("filename") and extend it with attributes
    np_minhash_init(&minhash, 256, false, minhash_seed);
    np_minhash_push_tree(&minhash, text_as_array, 1, false); // 3 for shingles, has to be adopted for each kind of search

    np_index_update_with_minhash(&query->query_entry.search_index, &minhash);

    // set reply target
    // _np_dhkey_assign(&query->result_idx, &np_module(search)->searchnode.node_id);
    char* tmp = query->result_uuid;
    np_uuid_create(SEARCH_QUERY_SUBJECT, 0, &tmp);

    np_subject search_query_subject = {0};
    np_generate_subject(&search_query_subject, SEARCH_RESULT_SUBJECT, strnlen(SEARCH_RESULT_SUBJECT, 256));
    np_generate_subject(&search_query_subject, &np_module(search)->searchnode.node_id, NP_FINGERPRINT_BYTES);

    np_dhkey_t search_query_dhkey = {0};
    memcpy(&search_query_dhkey, search_query_subject, NP_FINGERPRINT_BYTES);
    // create our own interest to share search attributes
    np_msgproperty_conf_t* prop = _np_msgproperty_get_or_create(np_module(search)->context, INBOUND, search_query_dhkey);

    // TODO: fetch the already existing mx token for this subject
    np_message_intent_public_token_t* token = _np_token_factory_new_message_intent_token(prop);
    np_aaatoken4user(&query->query_entry.intent, token);
    // TODO: push all attributes as dhkey's into the index
    // np_index_update_with_dhkey(&entry, ...);
    // for now: only merge to apply later "reduce" functionality
    np_merge_data((np_datablock_t*) query->query_entry.intent.attributes, (np_datablock_t*) attributes);

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
void np_search_add_entry(np_context* ac, np_searchentry_t* entry) 
{ 
    np_ctx_cast(ac);

    np_tree_t* pipeline_results = &np_module(search)->pipeline_results;

    struct search_pipeline_result* pipeline = calloc(1, sizeof(struct search_pipeline_result));
    pipeline->stop_time = pipeline->start_time = np_time_now();

    np_generate_subject(&pipeline->search_subject, SEARCH_ENTRY_SUBJECT, strnlen(SEARCH_ENTRY_SUBJECT, 256));
    pipeline->obj.entry = entry;

    np_tree_t* search_entry = __encode_search_entry(entry);
    // size_t data_length = search_entry->byte_size;
    // unsigned char data[data_length];
    // np_tree2buffer(context, search_entry, data);
    log_msg(LOG_DEBUG,  "searchentry (%s) as tree %p (%u / %u)", entry->intent.subject, search_entry, search_entry->byte_size, search_entry->size);

    np_message_t* new_entry_msg = NULL;
    np_new_obj(np_message_t, new_entry_msg, ref_obj_creation);
    _np_message_create(new_entry_msg, pipeline->search_subject, np_module(search)->searchnode.node_id, pipeline->search_subject, search_entry);

    np_spinlock_lock(&np_module(search)->pipeline_lock);
    np_tree_insert_str(pipeline_results, new_entry_msg->uuid, np_treeval_new_v(pipeline));    
    np_spinlock_unlock(&np_module(search)->pipeline_lock);

    // manual execution of pipeline for now
    __check_remote_peer_distribution(ac, new_entry_msg, new_entry_msg->body, &np_module(search)->pipeline_results);
    __np_search_add_entry           (ac, new_entry_msg, new_entry_msg->body, &np_module(search)->pipeline_results);

    // np_tree_free(search_entry); // deleted by message
    np_unref_obj(np_message_t, new_entry_msg, ref_obj_creation);
}

// send the query and search for entries
void np_search_query(np_context* ac, np_searchquery_t* query) 
{ 
    np_ctx_cast(ac);

    np_tree_t* pipeline_results = &np_module(search)->pipeline_results;

    if (np_module(search)->searchnode.queries[query->query_id] != NULL) 
    {
        np_searchquery_t* old_query = np_module(search)->searchnode.queries[query->query_id];        
        np_index_destroy(&old_query->query_entry.search_index);            
        free(old_query);
    }
    np_module(search)->searchnode.queries[query->query_id] = query;        

    np_spinlock_lock(&np_module(search)->results_lock[query->query_id]);
    if (np_module(search)->searchnode.results[query->query_id] != NULL) 
    {
        np_tree_elem_t* tmp = NULL;
        RB_FOREACH(tmp, np_tree_s, np_module(search)->searchnode.results[query->query_id]) 
        {
            np_searchresult_t* result = tmp->val.value.v;
            free(result->label);
            free(result);
        }
        np_tree_free(np_module(search)->searchnode.results[query->query_id]);
    }
    np_module(search)->searchnode.results[query->query_id] = np_tree_create();        
    np_spinlock_unlock(&np_module(search)->results_lock[query->query_id]);


    struct search_pipeline_result * pipeline = calloc(1, sizeof(struct search_pipeline_result));
    pipeline->stop_time = pipeline->start_time = np_time_now();

    np_generate_subject(&pipeline->search_subject, SEARCH_QUERY_SUBJECT, strnlen(SEARCH_QUERY_SUBJECT, 256));

    pipeline->obj.query = query;

    np_spinlock_lock(&np_module(search)->pipeline_lock);
    np_tree_insert_str(pipeline_results, query->result_uuid, np_treeval_new_v(pipeline));    
    np_spinlock_unlock(&np_module(search)->pipeline_lock);

    np_tree_t* search_query = __encode_search_query(query);

    // size_t data_length = search_query->byte_size;
    // unsigned char data[data_length];
    // np_tree2buffer(context, search_query, data);
    log_msg(LOG_DEBUG,  "using searchquery (%s / %s) as tree %p (%u / %u)", query->query_entry.intent.subject, query->result_uuid, search_query, search_query->byte_size, search_query->size);

    np_message_t* new_query_msg = NULL;
    np_new_obj(np_message_t, new_query_msg, ref_obj_creation);
    strncpy(new_query_msg->uuid, query->result_uuid, NP_UUID_BYTES);

    _np_message_create(new_query_msg, pipeline->search_subject, context->my_node_key->dhkey, pipeline->search_subject, search_query);

    // manual execution of pipeline for now
    __check_remote_peer_distribution(ac, new_query_msg, new_query_msg->body, &np_module(search)->pipeline_results);
    __np_search_query               (ac, new_query_msg, new_query_msg->body, &np_module(search)->pipeline_results);

    np_unref_obj(np_message_t, new_query_msg, ref_obj_creation);
}

np_tree_t* np_search_get_resultset(np_context* ac, np_searchquery_t* query)
{
    np_ctx_cast(ac);

    if (np_module_not_initiated(search)) {
        np_searchnode_init(context, NULL);
    }

    return np_module(search)->searchnode.results[query->query_id];
}

void _np_searchnode_withdraw(np_context* ac, struct np_searchnode_s* node) 
{ 

}

bool _np_searchnode_withdraw_cb(np_context* ac, struct np_message* token_msg) 
{ 
    return true;
}

// bool (*np_usercallbackfunction_t) (np_context* ac, const np_message_t* const msg, np_tree_t* body, void* localdata);

bool _np_new_searchentry_cb(np_context* ac, const np_message_t* const entry_msg, np_tree_t* body, void* localdata) 
{ 
	np_ctx_cast(ac);

    log_msg(LOG_INFO,  "received new searchentry from peer with uuid: %s", entry_msg->uuid);
    np_tree_t* pipeline_results = (np_tree_t*) localdata;

    struct search_pipeline_result * pipeline = calloc(1, sizeof(struct search_pipeline_result));
    pipeline->stop_time = pipeline->start_time = np_time_now();

    np_generate_subject(&pipeline->search_subject, SEARCH_ENTRY_SUBJECT, strnlen(SEARCH_ENTRY_SUBJECT, 256));

    log_msg(LOG_DEBUG,  "searchentry as tree %p (%u / %u)", body, body->byte_size, body->size);

    pipeline->obj.entry = __decode_search_entry(body);
    _np_dhkey_assign(&pipeline->search_index, &pipeline->obj.entry->search_index.lower_dhkey);

    if (pipeline->obj.entry == NULL) { 
        log_msg(LOG_DEBUG,  "could not decode searchentry"); 
        return false; }
    else {
        np_spinlock_lock(&np_module(search)->pipeline_lock);
        np_tree_insert_str(pipeline_results, entry_msg->uuid, np_treeval_new_v(pipeline));
        np_spinlock_unlock(&np_module(search)->pipeline_lock);
    }
    return true;
}

bool _np_new_searchquery_cb(np_context* ac, const np_message_t* const query_msg, np_tree_t* body, void* localdata) 
{ 
	np_ctx_cast(ac);

    log_msg(LOG_DEBUG,  "received new searchquery from peer with uuid: %s", query_msg->uuid);
        
    np_tree_t* pipeline_results = (np_tree_t*) localdata;

    struct search_pipeline_result * pipeline = calloc(1, sizeof(struct search_pipeline_result));
    pipeline->stop_time = pipeline->start_time = np_time_now();
    np_generate_subject(&pipeline->search_subject, SEARCH_QUERY_SUBJECT, strnlen(SEARCH_QUERY_SUBJECT, 256) );

    struct np_data_conf* conf = NULL;
    np_data_value val;
    // TODO: check whether pipeline // query already exists (node is the originator of the query)
    if (np_data_ok == np_get_data(query_msg->decryption_token->attributes, SEARCH_PEERID, conf, &val) )
    {
        memcpy(&pipeline->sending_peer_dhkey, val.bin, NP_FINGERPRINT_BYTES);
    }
    else
    {   // no reply path available? stop the query!
        log_msg(LOG_INFO,  "no peer-id in sender token, rejecting searchquery from peer with uuid: %s", query_msg->uuid);
        free(pipeline);
        return false;
    }

    log_msg(LOG_DEBUG,  "searchquery as tree %p (%u / %u)", body, body->byte_size, body->size);

    pipeline->obj.query = __decode_search_query(body);
    _np_dhkey_assign(&pipeline->search_index, &pipeline->obj.query->query_entry.search_index.lower_dhkey);

    if (pipeline->obj.query == NULL) 
    { 
        log_msg(LOG_DEBUG,  "could not decode searchquery"); 
        return false; 
    }
    else 
    {
        np_spinlock_lock(&np_module(search)->pipeline_lock);
        np_tree_insert_str(pipeline_results, query_msg->uuid, np_treeval_new_v(pipeline));
        np_spinlock_unlock(&np_module(search)->pipeline_lock);
    }

    return true;
}

void _np_searchresult_send(np_context* ac, np_subject result_subject, np_searchresult_t* result) 
{ 
	np_ctx_cast(ac);

    np_tree_t* search_result = __encode_search_result(result);
    log_msg(LOG_DEBUG,  "sending searchresult (%s / %s) as tree %p (%u bytes / %u)", result->result_entry->intent.subject, result->result_uuid, result, search_result->byte_size, search_result->size);

    size_t data_length = search_result->byte_size;
    unsigned char data[data_length];
    np_tree2buffer(context, search_result, data);

    np_send(context, result_subject, data, data_length);
}

bool _np_searchresult_receive_cb(np_context* ac, const np_message_t* result_msg, np_tree_t* body, void* localdata) 
{ 
	np_ctx_cast(ac);

    np_tree_elem_t* userdata = np_tree_find_str(body, NP_SERIALISATION_USERDATA);    
    if (userdata == NULL) { log_msg(LOG_DEBUG,  "could not find userdate element"); return false; }

    np_tree_t* search_result = np_tree_create();
    np_buffer2tree(context, userdata->val.value.bin, search_result);

    log_msg(LOG_DEBUG,  "received searchresult as tree %p (%u bytes / %u)", search_result, search_result->byte_size, search_result->size);

    np_searchresult_t* new_result = __decode_search_result(search_result);

    if (new_result == NULL) { log_msg(LOG_DEBUG,  "could not decode searchresult"); np_tree_free(search_result); return false; }

    log_msg(LOG_INFO,  "received new searchresult from peer with uuid %s for query with uuid: %s", result_msg->uuid, new_result->result_uuid);

    np_tree_t* pipeline_results = (np_tree_t*) localdata;
    struct search_pipeline_result* pipeline = NULL;


    np_spinlock_lock(&np_module(search)->pipeline_lock);
    if (NULL == np_tree_find_str(pipeline_results, new_result->result_uuid)) 
    { 
        log_msg(LOG_DEBUG,  "could not find pipeline definition for %s", new_result->result_uuid); 
        np_spinlock_unlock(&np_module(search)->pipeline_lock);
        return false; 
    }
    else 
    {
        pipeline = np_tree_find_str(pipeline_results, new_result->result_uuid)->val.value.v;
    }    
    np_spinlock_unlock(&np_module(search)->pipeline_lock);

    if (_np_dhkey_equal(&pipeline->sending_peer_dhkey, &dhkey_zero) )
    {
        np_spinlock_lock(&np_module(search)->pipeline_lock);
        if (pipeline->stop_time > pipeline->start_time)
        {
            log_msg(LOG_INFO,  "pipeline %s already stopped by user", new_result->result_uuid);
            np_spinlock_unlock(&np_module(search)->pipeline_lock);
            return false;
        }
        np_spinlock_unlock(&np_module(search)->pipeline_lock);

        np_map_reduce_t mr = { .map=_map_np_searchentry, .reduce=_reduce_np_searchentry };
        mr.reduce_result = np_module(search)->searchnode.results[new_result->query_id];
        mr.map_args.io = &np_module(search)->searchnode.queries[new_result->query_id]->query_entry;

//        np_searchquery_t* query = np_module(search)->searchnode.queries[new_result->query_id];
        np_spinlock_lock(&np_module(search)->results_lock[new_result->query_id]);
        mr.reduce(&mr, new_result->result_entry);
        np_spinlock_unlock(&np_module(search)->results_lock[new_result->query_id]);
    }
    else
    {
        log_msg(LOG_DEBUG,  "re-sending searchresult as tree %p (%u bytes / %u)", search_result, search_result->byte_size, search_result->size);
        np_subject result_subject = {0};
        // TODO: implement possible intermediate reduce step
        np_generate_subject(&result_subject, SEARCH_RESULT_SUBJECT, strnlen(SEARCH_RESULT_SUBJECT, 256));
        np_generate_subject(&result_subject, &pipeline->sending_peer_dhkey, NP_FINGERPRINT_BYTES);

        _np_searchresult_send(context, result_subject, new_result);
    }

    return true;
}
