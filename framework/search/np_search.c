//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// neuropil is copyright 2016-2021 by pi-lar GmbH
//
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "search/np_search.h"
#include "search/np_bktree.h"
#include "search/np_index.h"

#include "np_legacy.h"
#include "np_aaatoken.h"
#include "np_attributes.h" 
#include "np_token_factory.h"
#include "neuropil_data.h"

#include "core/np_comp_msgproperty.h"

#include "util/np_list.h"
#include "util/np_mapreduce.h"
#include "util/np_minhash.h"
#include "util/np_bloom.h"

#include "http/np_http.h"
#include "http/urldecode.h"
#include "parson/parson.h"

np_module_struct(search) {
    np_state_t* context;
    np_searchnode_t* searchnode;
};

static np_searchnode_t __my_searchnode = {0};
static uint8_t __query_id = 0;
static np_searchresult_t __my_searchresults[UINT8_MAX];

static char* __text_delimiter = " ,!'.\"-_[]{}";

struct __search_table_bucket {
  uint16_t hamming_distance;
  uint16_t index;
};

static int __search_table_bucket_cmp(const void *a, const void *b)
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

void __encode_intent(np_tree_t* target, struct np_token* intent_token) {}

int __np_search_handle_http_get(ht_request_t* ht_request, ht_response_t* ht_response, void* user_arg) 
{
    np_context* context = user_arg;

    // fprintf(stdout, "searching for ...");

    uint16_t length;
    int http_status = HTTP_CODE_INTERNAL_SERVER_ERROR; // HTTP_CODE_OK
    JSON_Value* json_obj = NULL;
    
    if (NULL != ht_request->ht_path)
    {
        char* file_start = ht_request->ht_path+1; // without leading '/'

        np_tree_elem_t* query_elem = np_tree_find_str(ht_request->ht_query_args, "query_text");
        if (NULL == query_elem) 
        {
            fprintf(stdout, "no query found ...");
            json_obj = __np_generate_error_json("request invalid", "looks like you are using a wrong url ...");
            http_status = HTTP_CODE_BAD_REQUEST;
            goto __json_return__; 
        }

        char* search_string = urlDecode(query_elem->val.value.s);
        fprintf(stdout, "searching for: %s\n", search_string);

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

            if (__my_searchnode.results[sq.query_id]->size == 0)
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

            struct np_data_conf search_conf = { 0 };
            np_data_value search_val_title  = { 0 };
            search_val_title.str = "";

            uint32_t byte_count = 0;

            np_tree_elem_t* tmp = NULL;
            RB_FOREACH(tmp, np_tree_s, __my_searchnode.results[sq.query_id]) 
            {
                np_searchresult_t* result = tmp->val.value.v;

                np_tree_t* r_tree = np_tree_create();
                struct np_data_conf conf = { 0 };
                np_data_value val_title  = { 0 };
                if (np_data_ok != np_get_data((np_datablock_t*) result->intent->attributes, "title", &conf, &val_title ) )
                {
                    val_title.str = "";
                }
                np_tree_insert_str(r_tree, "hit_counter", np_treeval_new_i(result->hit_counter));
                np_tree_insert_str(r_tree, "similarity", np_treeval_new_f(result->level));
                np_tree_insert_str(r_tree, "label", np_treeval_new_s(result->label));
                np_tree_insert_str(r_tree, "title", np_treeval_new_s(val_title.str));

                __encode_intent(r_tree, result->intent);

                byte_count = r_tree->byte_size;
                if (byte_count < UINT16_MAX)
                {
                    np_tree_insert_int(srs_tree, result->hit_counter, np_treeval_new_tree(r_tree));
                    fprintf(stdout, "%5s :: %s :: %3u / %2.2f / %5s\n", 
                                    search_val_title.str, tmp->key.value.s, result->hit_counter, result->level, val_title.str);
                }
                else
                {
                    fprintf(stdout, "please implement pagination of search results");                    
                }
                np_tree_free(r_tree);
            }    
            popro_stop_time = clock();

            fprintf(stdout, "search query took %3.6f seconds\n", (double) (query_stop_time-start_time) / CLOCKS_PER_SEC);
            fprintf(stdout, "search popro took %3.6f seconds\n", (double) (popro_stop_time-start_time) / CLOCKS_PER_SEC);

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
            fprintf(stdout, "no search result");
            json_obj = __np_generate_error_json(
                "request invalid", "unable to to create query from arguments ...");
            http_status = HTTP_CODE_BAD_REQUEST;
            goto __json_return__; 
        }

        free(search_string);
    }

__json_return__:

    if (json_obj != NULL) 
    {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "serialise json response");

        np_tree_insert_str( ht_response->ht_header, "Content-Type", np_treeval_new_s("application/json") );

        ht_response->ht_body = np_json2char(json_obj, false);
        ht_response->ht_length = strnlen(ht_response->ht_body, 1024);

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

static const char* SEARCH_NODE_SUBJECT = "urn:np:search:node:v1";
static const char* SEARCH_ENTRY_SUBJECT = "urn:np:search:entry:v1";
static const char* SEARCH_QUERY_SUBJECT = "urn:np:search:query:v1";

bool _np_search_authorize_entries_cb(np_context* ac, struct np_token* intent_token) 
{
	np_ctx_cast(ac);

    bool ret = false;
    struct np_data_conf conf = {0};
    struct np_data_conf* conf_ptr = &conf;
    np_dhkey_t  intent_token_new_id = {0};
    np_dhkey_t* intent_token_new_id_ptr = &intent_token_new_id;

	// fprintf(stdout, "authz request %s from %02X%02X%02X%02X%02X%02X : %02X%02X%02X%02X%02X%02X ...\n",
    //                 intent_token->subject,
    //                 intent_token->issuer[0],     intent_token->issuer[1],     intent_token->issuer[2],     intent_token->issuer[3],     intent_token->issuer[4],     intent_token->issuer[5],
    //                 intent_token->public_key[0], intent_token->public_key[1], intent_token->public_key[2], intent_token->public_key[3], intent_token->public_key[4], intent_token->public_key[5]);

    if (np_data_ok != np_get_token_attr_bin(intent_token, "np:key", &conf_ptr, &intent_token_new_id_ptr) )
    {
        return false;
    }

    if (_np_dhkey_equal(&intent_token_new_id, &np_module(search)->searchnode->node_id))
    {
        return false;
    }

    if (0 == strncmp(intent_token->subject, SEARCH_ENTRY_SUBJECT, 22) || 
        0 == strncmp(intent_token->subject, SEARCH_QUERY_SUBJECT, 22) )
    {
        fprintf(stdout, "authz request %s from %02X%02X%02X%02X%02X%02X : %02X%02X%02X%02X%02X%02X ...\n",
                        intent_token->subject,
                        intent_token->issuer[0],     intent_token->issuer[1],     intent_token->issuer[2],     intent_token->issuer[3],     intent_token->issuer[4],     intent_token->issuer[5],
                        intent_token->public_key[0], intent_token->public_key[1], intent_token->public_key[2], intent_token->public_key[3], intent_token->public_key[4], intent_token->public_key[5]);

        np_dhkey_t dh_diff_index = {0};
        _np_dhkey_hamming_distance_each(&dh_diff_index, &intent_token_new_id, &np_module(search)->searchnode->node_id);

        for (uint8_t j = 0; j < 8; j++) 
        {
            uint8_t index = dh_diff_index.t[j];
            if (_np_dhkey_equal(&np_module(search)->searchnode->peers[j][index], &intent_token_new_id) )
            {
                fprintf(stdout, "authz granted %s for %02X%02X%02X%02X%02X%02X : %02X%02X%02X%02X%02X%02X ...\n",
                                intent_token->subject,
                                intent_token->issuer[0],     intent_token->issuer[1],     intent_token->issuer[2],     intent_token->issuer[3],     intent_token->issuer[4],     intent_token->issuer[5],
                                intent_token->public_key[0], intent_token->public_key[1], intent_token->public_key[2], intent_token->public_key[3], intent_token->public_key[4], intent_token->public_key[5]);
                ret = true;
            }
        }
    }    
    
    return ret;
}


bool _np_search_authorize_node_cb(np_context* ac, struct np_token* intent_token) 
{
	np_ctx_cast(ac);

    bool ret = false;

    struct np_data_conf conf = {0};
    struct np_data_conf* conf_ptr = &conf;
    np_dhkey_t  intent_token_new_id = {0};
    np_dhkey_t* intent_token_new_id_ptr = &intent_token_new_id;
	// fprintf(stdout, "authz request %s from %02X%02X%02X%02X%02X%02X : %02X%02X%02X%02X%02X%02X ...\n",
    //                 intent_token->subject,
    //                 intent_token->issuer[0],     intent_token->issuer[1],     intent_token->issuer[2],     intent_token->issuer[3],     intent_token->issuer[4],     intent_token->issuer[5],
    //                 intent_token->public_key[0], intent_token->public_key[1], intent_token->public_key[2], intent_token->public_key[3], intent_token->public_key[4], intent_token->public_key[5]);

    if (np_data_ok != np_get_token_attr_bin(intent_token, "np:key", &conf_ptr, &intent_token_new_id_ptr) )
    {
        return false;
    }

    if (_np_dhkey_equal(&intent_token_new_id, &np_module(search)->searchnode->node_id))
    {
        return false;
    }

    if (strncmp(intent_token->subject, SEARCH_NODE_SUBJECT, 21)) 
    {
        np_dhkey_t dh_diff_index  = {0};
        np_dhkey_t      to_delete = {0};

        // fprintf(stdout, "checking search node as peer: %02X%02X%02X%02X%02X%02X\n", 
        //                 intent_token->issuer[0],     intent_token->issuer[1],     intent_token->issuer[2],     intent_token->issuer[3],     intent_token->issuer[4],     intent_token->issuer[5]);
        
        _np_dhkey_hamming_distance_each(&dh_diff_index, &intent_token_new_id, &np_module(search)->searchnode->node_id);

        // setup competitor entry
        uint8_t   dh_diff_new  = UINT8_MAX;
        _np_dhkey_hamming_distance(&dh_diff_new, &intent_token_new_id, &np_module(search)->searchnode->node_id);

        for (uint8_t j = 0; j < 8; j++) 
        {
            bool is_zero = false;
            uint8_t index = dh_diff_index.t[j];
            uint8_t   dh_diff_old  = UINT8_MAX;
            
            // compare hamming distance between old and new data channel
            _np_dhkey_hamming_distance(&dh_diff_old, &np_module(search)->searchnode->peers[j][index], &np_module(search)->searchnode->node_id);
            is_zero = _np_dhkey_equal(&dhkey_zero, &np_module(search)->searchnode->peers[j][index]);

            // fprintf(stdout, "compare node as search peer [%u][%u], distance is %u (%u) (%u:%u)\n", 
            //                 j, index, dh_diff_new.t[j], dh_diff_index.t[j], is_zero, exists);

            if ( (dh_diff_old > dh_diff_new) || is_zero)
            {
                memcpy(&to_delete, &np_module(search)->searchnode->peers[j][index], NP_FINGERPRINT_BYTES);
                memcpy(&np_module(search)->searchnode->peers[j][index], &intent_token_new_id, NP_FINGERPRINT_BYTES);

                // subscribe to data channels provided by peer
                // setup how entries can be added
                struct np_mx_properties search_property = np_get_mx_properties(context, SEARCH_ENTRY_SUBJECT);

                search_property.audience_type = NP_MX_AUD_PROTECTED;
                search_property.intent_ttl = 3600;
                search_property.intent_update_after = 120;
                memcpy(&search_property.audience_id, &intent_token_new_id, NP_FINGERPRINT_BYTES);
                np_set_mx_properties(context, SEARCH_ENTRY_SUBJECT, search_property);
                np_set_mxp_attr_bin(context, SEARCH_ENTRY_SUBJECT, NP_ATTR_INTENT, "np:key", &__my_searchnode.node_id, NP_FINGERPRINT_BYTES);
                
                // setup how entries can be queried
                np_set_mx_properties(context, SEARCH_QUERY_SUBJECT, search_property);
                np_set_mxp_attr_bin(context, SEARCH_ENTRY_SUBJECT, NP_ATTR_INTENT, "np:key", &__my_searchnode.node_id, NP_FINGERPRINT_BYTES);

                ret = true;
                fprintf(stdout, "adding node as search peer [%u][%u], distance is %u\n", 
                                j, index, dh_diff_new);
            }
            // else 
            // {
                // fprintf(stdout, "checked search node as peer: %02X%02X%02X%02X%02X%02X\n", 
                //                 intent_token->issuer[0],     intent_token->issuer[1],     intent_token->issuer[2],     intent_token->issuer[3],     intent_token->issuer[4],     intent_token->issuer[5]);
                // fprintf(stdout, "checked node as search peer [%u][%u], distance was %u\n", 
                //                 j, index, dh_diff_new);
            // }

            is_zero = _np_dhkey_equal(&dhkey_zero, &to_delete);
            if (!is_zero) {
                // todo:
            }
            // if (push_back) {
            // unsubscribe from old data channel (now in variable tmp)
            // TODO: this doesn't work yet for private channels, we have to integrate the interface id first
            // np_mx_properties_disable(context, SEARCH_ENTRY_SUBJECT);
            // np_mx_properties_disable(context, SEARCH_QUERY_SUBJECT);
            // }
        }
    }

    // np_set_mx_properties(context, SEARCH_NODE_SUBJECT, search_property);
    // np_set_mx_properties(context, SEARCH_ENTRY_SUBJECT, search_property);
    // np_set_mx_properties(context, SEARCH_QUERY_SUBJECT, search_property);

    return ret;
}

bool _np_searchnode_announce_cb(np_context* context, struct np_message* token_msg) 
{ 
    // just here for the completion of the api, will never be called
    return true;
}

// initialize the np_searchnode structure and associated message exchanges
void np_searchnode_init(np_context* ac)
{
	np_ctx_cast(ac);

    if (np_module_not_initiated(search))
    {
        np_module_malloc(search);
        np_module(search)->searchnode = &__my_searchnode;

        __my_searchnode.local_peers = BKTREE_ARRAY_SIZE;

        randombytes_buf(__my_searchnode.node_id, NP_FINGERPRINT_BYTES);
        
        for (uint16_t i = 0; i < __my_searchnode.local_peers; i++)
        {
            np_dhkey_t seed = {0};
            randombytes_buf(&seed, sizeof (np_dhkey_t) );
            __my_searchnode.tree[i] = malloc(sizeof(np_bktree_t));
            np_bktree_init(__my_searchnode.tree[i], seed, 10);

            memset(__my_searchresults, 0, UINT8_MAX*sizeof(np_searchresult_t));
            // np_bktree_init(__my_searchresults.entries[i], seed, 10);
        }
        
        memset(__my_searchnode.peers, 0, 8*32*NP_FINGERPRINT_BYTES);

        np_set_authorize_cb(context, _np_search_authorize_node_cb);
        np_set_mx_authorize_cb(context, SEARCH_NODE_SUBJECT, _np_search_authorize_node_cb);

        struct np_mx_properties search_property = np_get_mx_properties(context, SEARCH_NODE_SUBJECT);

        search_property.intent_ttl = 86400;
        search_property.intent_update_after = 120;
        search_property.audience_type = NP_MX_AUD_VIRTUAL;
        np_set_mx_properties(context, SEARCH_NODE_SUBJECT, search_property);

        np_set_mxp_attr_bin(context, SEARCH_NODE_SUBJECT, NP_ATTR_INTENT, "np:key", &__my_searchnode.node_id, NP_FINGERPRINT_BYTES);
        np_add_receive_cb(context, SEARCH_NODE_SUBJECT, _np_searchnode_announce_cb);
        // np_set_mxp_attr_bin(context, SEARCH_NODE_SUBJECT, NP_ATTR_INTENT, "np:search:peers", __my_searchnode.remote_peer_count, sizeof(uint16_t));

        np_set_mx_authorize_cb(context, SEARCH_ENTRY_SUBJECT, _np_search_authorize_entries_cb);

        // setup how entries can be added / receiver channels
        search_property.intent_ttl = 3600;
        search_property.intent_update_after = 120;
        search_property.audience_type = NP_MX_AUD_PROTECTED;
        memcpy(&search_property.audience_id, &__my_searchnode.node_id, NP_FINGERPRINT_BYTES);
        np_set_mxp_attr_bin(context, SEARCH_ENTRY_SUBJECT, NP_ATTR_INTENT, "np:key", &__my_searchnode.node_id, NP_FINGERPRINT_BYTES);
        np_set_mx_properties(context, SEARCH_ENTRY_SUBJECT, search_property);
        np_add_receive_cb(context, SEARCH_ENTRY_SUBJECT, _np_searchentry_announce_cb);

        // setup how queries can be added
        // search_property.reply_subject = {0}; // add random garbage value for reply_subject
        np_set_mx_authorize_cb(context, SEARCH_QUERY_SUBJECT, _np_search_authorize_entries_cb);

        np_set_mx_properties(context, SEARCH_QUERY_SUBJECT, search_property);
        np_set_mxp_attr_bin(context, SEARCH_QUERY_SUBJECT, NP_ATTR_INTENT, "np:key", &__my_searchnode.node_id, NP_FINGERPRINT_BYTES);
        np_add_receive_cb(context, SEARCH_QUERY_SUBJECT, _np_searchentry_query_cb);

        // np_add_receive_cb(context, SEARCH_QUERY_SUBJECT, _np_searchentry_result_cb);

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

    np_module(search)->searchnode = &__my_searchnode;
    __my_searchnode.local_peers = BKTREE_ARRAY_SIZE;
    
    for (uint16_t i = 0; i < __my_searchnode.local_peers; i++)
    {
        np_bktree_destroy(__my_searchnode.tree[i]);
    }

    for (uint16_t i = 0; i < UINT8_MAX; i++)
    {
        np_tree_free(__my_searchnode.results[i]);
    }
    np_module_free(search);
}

void _np_search_shutdown_hook(np_context* ac)
{
    // TODO: tell the other nodes that this node will be down 


    // cleanup the search module
    np_searchnode_destroy(ac);
}

void __lower_case(char* str, uint8_t strlen) 
{
    for(int i = 0; i < strlen; i++){
        str[i] = tolower(str[i]);
    }
}

bool _map_np_searchentry(np_map_reduce_t* mr_struct, const void* element)
{
    np_searchentry_t* it_1 = (np_searchentry_t*)mr_struct->map_args.io;
    np_searchentry_t* it_2 = (np_searchentry_t*)element;

    if (it_1 == it_2)                 return true;
    if (it_1 == NULL || it_2 == NULL) return false;

    // if (it_2->search_index._clk_hash == NULL) return false;

    float _target_similarity = np_tree_find_int(mr_struct->map_args.kv_pairs, 1)->val.value.f;

    float _similarity = 0.0;
    // fprintf(stdout, "P COLLISION: %p <-> %p \n", it_1->intent, it_2->intent);
    _np_neuropil_bloom_similarity(it_2->search_index._clk_hash, it_1->search_index._clk_hash, &_similarity);
    // fprintf(stdout, "P COLLISION: %f <-> %p (%s)\n", _similarity, it_2->search_index._clk_hash, it_2->intent.subject);
    if (_similarity > _target_similarity)
    {
        // fprintf(stdout, "R COLLISION: %f <-> %p (%s)\n", _similarity, it_2->search_index._clk_hash, it_2->intent.subject);
        sll_append(void_ptr, mr_struct->map_result, it_2);
    }

    int8_t _continue_mapping = mr_struct->cmp(mr_struct, it_2);

    if (0 >= _continue_mapping) return true;
    else                       return false;
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
    }
    else
    {
        np_searchresult_t* new_result = (np_searchresult_t*) malloc(sizeof(np_searchresult_t));
        new_result->hit_counter = 1;
        new_result->label = strndup(it_2->intent.subject, 255);
        new_result->intent = &it_2->intent;
        _np_neuropil_bloom_similarity(it_1->search_index._clk_hash, it_2->search_index._clk_hash, &new_result->level);

        np_tree_insert_str(mr_struct->reduce_result, it_2->intent.subject, np_treeval_new_v(new_result) );
    }
    return true;
}

// read a file and create the searchentry using the attributes
bool np_create_searchentry(np_context* ac, np_searchentry_t* entry, const char* text, np_attributes_t* attributes) 
{   
    bool ret = false;

	np_ctx_cast(ac);
    if (np_module_not_initiated(search)) {
        np_searchnode_init(context);
    }

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
        char* part = strtok (copied_text, __text_delimiter);
        while (part != NULL)
        {
            if (strnlen(part, 255) > 3) 
            {
                __lower_case(part, strnlen(part, 255));
                np_tree_insert_int(text_as_array, count, np_treeval_new_s(part) );
                count++;
            }
            part = strtok(NULL, __text_delimiter);
        }
        // TODO: get a copy of intent token for H("filename") and extend it with attributes
        np_minhash_init(&minhash, 256, minhash_seed);
        np_minhash_push_tree(&minhash, text_as_array, 3, false);

        np_index_update_with_minhash(&entry->search_index, &minhash);
    
        np_dhkey_t urn_dhkey = {0};
        np_generate_subject(&urn_dhkey, val_urn.str, strnlen(val_urn.str, 256));
        np_msgproperty_conf_t* prop = _np_msgproperty_get_or_create(np_module(search)->context, OUTBOUND, urn_dhkey);
        // np_merge_data(&prop->attributes, (np_datablock_t*) attributes);

        // TODO: fetch the already existing mx token for this subject
        np_message_intent_public_token_t* token = _np_token_factory_new_message_intent_token(prop);
        np_aaatoken4user(&entry->intent, token);
        np_merge_data((np_datablock_t*) entry->intent.attributes, (np_datablock_t*) attributes);

        np_msgproperty_register(prop);
        
        // TODO: push all attributes as dhkey's into the index
        // np_index_update_with_dhkey(&entry, ...);
        // np_index_update_with_dhkey(&entry->search_index, );
        np_index_hash(&entry->search_index);

        np_minhash_destroy(&minhash);
        np_tree_free(text_as_array);
        free(copied_text);

        ret = true;
    }
    else
    {
        fprintf(stdout, "data element not found !!!\n");
    }
    return ret;
}

// read a query text and create the searchentry using the attributes
bool np_create_searchquery(np_context* ac, np_searchquery_t* query, const char* query_text, np_attributes_t* attributes) 
{ 
    bool ret = false;
	np_ctx_cast(ac);
    if (np_module_not_initiated(search)) {
        np_searchnode_init(context);
    }

    // TODO: base minhash_seed on actual content type (html/pdf/txt/sourcecode)
    np_dhkey_t minhash_seed = np_dhkey_create_from_hostport("", "");
    np_minhash_t minhash = {0};

    np_index_init(&query->query_entry.search_index);

    // TODO: extract keyword using tf-idf (libbow) and add them to the attributes
    // TODO: only for pure text files right now
    char* copied_text = strndup(query_text, strlen(query_text));

    uint16_t    count = 0;
    np_tree_t* text_as_array = np_tree_create();
    char* part = strtok (copied_text, __text_delimiter);
    while (part != NULL)
    {
        if (strnlen(part, 255) > 3) 
        {
            __lower_case(part, strnlen(part, 255));
            np_tree_insert_int(text_as_array, count, np_treeval_new_s(part) );
            count++;
        }
        part = strtok(NULL, __text_delimiter);
    }

    // TODO: get a copy of intent token for H("filename") and extend it with attributes
    np_minhash_init(&minhash, 256, minhash_seed);
    np_minhash_push_tree(&minhash, text_as_array, 3, false); // 3 for shingles, has to be adopted for each kind of search

    np_index_update_with_minhash(&query->query_entry.search_index, &minhash);

    // create random reply target
    randombytes_buf(&query->result_idx, NP_FINGERPRINT_BYTES);

    // create our own interest to share search attributes
    np_msgproperty_conf_t* prop = _np_msgproperty_get_or_create(np_module(search)->context, INBOUND, query->result_idx);
    prop->reply_dhkey = query->result_idx;

    // TODO: fetch the already existing mx token for this subject
    np_message_intent_public_token_t* token = _np_token_factory_new_message_intent_token(prop);
    np_aaatoken4user(&query->query_entry.intent, token);
    // TODO: push all attributes as dhkey's into the index
    // np_index_update_with_dhkey(&entry, ...);
    // for now: only merge to apply later "reduce" functionality
    np_merge_data((np_datablock_t*) query->query_entry.intent.attributes, (np_datablock_t*) attributes);

    np_msgproperty_register(prop);

    // np_index_update_with_dhkey(&entry->search_index, );
    np_index_hash(&query->query_entry.search_index);

    // TODO: use the identity token to show our interest
    query->query_id = __query_id++;
    
    np_minhash_destroy(&minhash);
    np_tree_free(text_as_array);
    free(copied_text);

    return true;
}

// ads the created searchentry to the global search index
void np_search_add_entry(np_context* context, np_searchentry_t* entry) 
{ 
/*
    uint16_t min_index[8];
    np_dhkey_t min_diff = { .t[0] = UINT32_MAX, .t[1] = UINT32_MAX, .t[2] = UINT32_MAX, .t[3] = UINT32_MAX, .t[4] = UINT32_MAX, .t[5] = UINT32_MAX, .t[6] = UINT32_MAX, .t[7] = UINT32_MAX, };
    for (uint16_t i = 0; i < __my_searchnode.local_peers; i++) 
    {
        // TODO: distance could be the same for two different tables. Right now the first table wins. Is there a better solution?
        np_dhkey_t diff = { 0 };
        _np_dhkey_hamming_distance_each(&diff, &entry->search_index.lower_dhkey, &__my_searchnode.tree[i]->_root._key);
        for (uint8_t j = 0; j < 8; j++) 
        {
            if (diff.t[j] < min_diff.t[j]) 
            {
                // fprintf(stdout, "         into table %u (distance %u [at %u] )\n", i , diff.t[j], j);
                min_index[j] = i;
                min_diff.t[j] = diff.t[j];
            }
        }
    }
*/

    uint16_t dh_diff = {0};
    struct __search_table_bucket buckets[__my_searchnode.local_peers];
    uint8_t max_create_count = (__my_searchnode.local_peers < 8) ? __my_searchnode.local_peers : 8;
    for (uint8_t j = 0; j < max_create_count; j++) 
    {
        // #pragma omp parallel for shared(entry)
        for (uint16_t i = 0; i < __my_searchnode.local_peers; i++) 
        {
            _np_dhkey_hamming_distance(&dh_diff, &entry->search_index.lower_dhkey, &__my_searchnode.tree[i]->_root._key);
            buckets[i].hamming_distance = dh_diff;
            buckets[i].index = i;
        }
    }
    qsort(buckets, __my_searchnode.local_peers, sizeof(struct __search_table_bucket), __search_table_bucket_cmp);
    // fprintf(stdout, "         into table: ");
    // for (uint16_t i = 0; i < 16; i++) 
    // {
    //             fprintf(stdout, "%u (%u) : ", buckets[i].index , buckets[i].hamming_distance);
    // }
    // fprintf(stdout, "\n");

    // uint8_t i = 0;
    // fprintf(stdout, "inserting into table: \n");
    // #pragma omp parallel for shared(entry)
    for (uint16_t j = 0; j < max_create_count; j++) 
    {
        // fprintf(stdout, " %2u (distance %3u [at %2u] )\n", buckets[j].index , buckets[j].hamming_distance, j);
        // fprintf(stdout, "\n< NODE INDEX:> ");
        // for (uint32_t k = 0; k < 8; k++) 
        // {
        //     fprintf(stdout, "%08x", lsh->_bktree[j]._root._key.t[k]);
        //     fprintf(stdout, ".");
        // }
        // fprintf(stdout, " </ NODE INDEX:>\n");
        np_bktree_insert(__my_searchnode.tree[ buckets[j].index ], entry->search_index.lower_dhkey, entry);
        // np_bktree_insert(__my_searchnode.tree[ min_index[j] ], entry->search_index.upper_dhkey, entry);
        // np_skipbi_add(&lsh->_skipbi[j], _lp);
    }
    // fprintf(stdout, "\n");
}

// send the query and search for entries
void np_search_query(np_context* context, np_searchquery_t* query) 
{ 
    np_map_reduce_t mr = { 0 };

    mr.map = _map_np_searchentry;
    mr.map_args.io = &query->query_entry;
    mr.map_args.kv_pairs = np_tree_create();
    np_tree_insert_int(mr.map_args.kv_pairs, 1, np_treeval_new_f(0.5));
    // np_tree_insert_int(mr.map_args.kv_pairs, 1, np_treeval_new_f(*probability));

    mr.reduce = _reduce_np_searchentry;
    mr.reduce_result = np_tree_create();
    sll_init(void_ptr, mr.map_result);

/*    uint16_t min_index[8];
    uint16_t snd_index[8];
    np_dhkey_t min_diff = { .t[0] = UINT32_MAX, .t[1] = UINT32_MAX, .t[2] = UINT32_MAX, .t[3] = UINT32_MAX, .t[4] = UINT32_MAX, .t[5] = UINT32_MAX, .t[6] = UINT32_MAX, .t[7] = UINT32_MAX, };
    for (uint16_t i = 0; i < __my_searchnode.local_peers; i++) 
    {
        // TODO: distance could be the same for two different tables. Right now the first table wins. Is there a better solution?
        np_dhkey_t diff = { 0 };
        _np_dhkey_hamming_distance_each(&diff, &query->query_entry.search_index.lower_dhkey, &__my_searchnode.tree[i]->_root._key);
        for (uint8_t j = 0; j < 8; j++) 
        {
            if (diff.t[j] < min_diff.t[j]) 
            {
                fprintf(stdout, "         into table %u (distance %u [at %u] : old %u)\n", i , diff.t[j], j, snd_index[j]);
                snd_index[j] = min_index[j];
                min_index[j] = i;
                min_diff.t[j] = diff.t[j];
            }
        }
    }
    */

    uint16_t dh_diff = {0};
    struct __search_table_bucket buckets[__my_searchnode.local_peers];
    memset(&buckets, 0, __my_searchnode.local_peers*sizeof(struct __search_table_bucket));

    uint8_t max_query_count = (__my_searchnode.local_peers < 16) ? __my_searchnode.local_peers : 16;
    for (uint8_t j = 0; j < max_query_count; j++) 
    {
        // #pragma omp parallel for shared(query)
        for (uint16_t i = 0; i < __my_searchnode.local_peers; i++) 
        {
            _np_dhkey_hamming_distance(&dh_diff, &query->query_entry.search_index.lower_dhkey, &__my_searchnode.tree[i]->_root._key);
            buckets[i].hamming_distance = dh_diff;
            buckets[i].index = i;
        }
    }
    qsort(buckets, __my_searchnode.local_peers, sizeof(struct __search_table_bucket), __search_table_bucket_cmp);
    // fprintf(stdout, "         into table: ");
    // for (uint16_t i = 0; i < 16; i++) 
    // {
    //             fprintf(stdout, "%u (%u) : ", buckets[i].index , buckets[i].hamming_distance);
    // }
    // fprintf(stdout, "\n");
    // fprintf(stdout, "searching in   table: ");
    // #pragma omp parallel for shared(query)
    for (uint16_t j = 0; (j < max_query_count) && (mr.reduce_result->size == 0); j++)
    {
        // fprintf(stdout, " %2u (distance %3u [at %2u] )", buckets[j].index , buckets[j].hamming_distance, j);
        // np_skipbi_query(&lsh->_skipbi[j], &mr);
        np_bktree_query(__my_searchnode.tree[ buckets[j].index ], query->query_entry.search_index.lower_dhkey, &query->query_entry, &mr);
        // np_bktree_query(__my_searchnode.tree[ min_index[j] ], entry->query_entry.search_index.upper_dhkey, &entry->query_entry, &mr);
        sll_clear(void_ptr, mr.map_result);
    }
    np_tree_free(mr.map_args.kv_pairs);
    sll_free(void_ptr, mr.map_result);

    // fprintf(stdout, "\n");

    // if (mr.map_result->size == 0) 
    // {
    //     // fprintf(stdout, "searching in   table: \n");
    //     for (uint16_t j = 0; j < 8; j++) 
    //     {
    //         // fprintf(stdout, " %2u (distance %3u [at %2u] )\n", min_index[j] , min_diff.t[j], j);
    //         // np_skipbi_query(&lsh->_skipbi[j], &mr);
    //         np_bktree_query(__my_searchnode.tree[ snd_index[j] ], query->query_entry.search_index.lower_dhkey, &query->query_entry, &mr);
    //         // np_bktree_query(__my_searchnode.tree[ min_index[j] ], entry->query_entry.search_index.upper_dhkey, &entry->query_entry, &mr);
    //         // sll_clear(void_ptr, mr.map_result);
    //     }
    // }
    // sll_iterator(void_ptr) iterator = sll_first(mr.map_result);
    // while (iterator != NULL) 
    // {
    //     mr.reduce(&mr, iterator->val);
    //     sll_next(iterator);
    // }

    if (__my_searchnode.results[query->query_id] != NULL)
    {
        np_tree_elem_t* tmp = NULL;
        RB_FOREACH(tmp, np_tree_s, __my_searchnode.results[query->query_id]) 
        {
            np_searchresult_t* result = tmp->val.value.v;
            free(result->label);
            free(result);
        }
        np_tree_free(__my_searchnode.results[query->query_id]);
    }
    __my_searchnode.results[query->query_id] = mr.reduce_result;

    struct np_data_conf search_conf = { 0 };
    np_data_value search_val_title  = { 0 };
    if (np_data_ok != np_get_data((np_datablock_t*) query->query_entry.intent.attributes, "title", &search_conf, &search_val_title ) )
    {
        search_val_title.str = "";
    }

    np_tree_elem_t* tmp = NULL;
    RB_FOREACH(tmp, np_tree_s, __my_searchnode.results[query->query_id]) 
    {
        np_searchresult_t* result = tmp->val.value.v;

        struct np_data_conf conf = { 0 };
        np_data_value val_title  = { 0 };
        if (np_data_ok != np_get_data((np_datablock_t*) result->intent->attributes, "title", &conf, &val_title ) )
        {
            val_title.str = "";
        }
        fprintf(stdout, "search result %-5s :: %s :: %3u / %2.2f / %5s\n", 
                        search_val_title.str, tmp->key.value.s, result->hit_counter, result->level, val_title.str);
    }    
}

np_tree_t* np_search_get_resultset(np_context* ac, np_searchquery_t* query)
{
    np_ctx_cast(ac);

    if (np_module_not_initiated(search)) {
        np_searchnode_init(context);
    }

    return __my_searchnode.results[query->query_id];
}

void _np_searchnode_withdraw(np_context* context, struct np_searchnode_s* node) 
{ 

}

bool _np_searchnode_withdraw_cb(np_context* context, struct np_message* token_msg) 
{ 
    return true;
}

void _np_searchentry_announce(np_context* context, struct np_searchentry_s* entry) 
{ 
}

bool _np_searchentry_announce_cb(np_context* context, struct np_message* token_msg) 
{ 
    return true;
}

// void _np_searchentry_withdraw(np_context* ac, struct np_searchentry_s* entry) { }
// bool _np_searchentry_withdraw_cb(np_context* ac, struct np_message* token) { }

void _np_searchentry_send_query(np_context* context, struct np_searchquery_s* query) 
{ 

}

bool _np_searchentry_query_cb(np_context* context, struct np_message* query_msg) 
{ 
    return true;
}

void _np_searchentry_send_result(np_context* context, struct np_searchentry_s* result) 
{ 

}

bool _np_searchentry_result_cb(np_context* context, struct np_message* result) 
{ 
    return true;
}
