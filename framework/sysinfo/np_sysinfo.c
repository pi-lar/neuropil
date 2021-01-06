//
// neuropil is copyright 2016-2021 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include <stdlib.h>
#include "inttypes.h"

#include "../framework/sysinfo/np_sysinfo.h"
#include "../framework/http/np_http.h"

#include "neuropil.h"

#include "np_constants.h"
#include "np_log.h"
#include "np_key.h"
#include "np_node.h"
#include "np_memory.h"
#include "np_route.h"
#include "np_settings.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"
#include "np_types.h"

#include "util/np_event.h"

#include "json/parson.h"

#define  _NP_SYSINFO_MY_NODE "node"
#define  _NP_SYSINFO_MY_NODE_TIMESTAMP "timestamp"
#define  _NP_SYSINFO_MY_NODE_STARTUP_AT "startup_at"

#define  _NP_SYSINFO_MY_NEIGHBOURS "neighbour_nodes"
#define  _NP_SYSINFO_MY_ROUTES "routing_nodes"

#define  _NP_SYSINFO_SOURCE  "source_hash"
#define  _NP_SYSINFO_TARGET  "target_hash"

#ifdef np_context
typedef np_context np_state_t*
#endif

np_module_struct(sysinfo) {
    np_state_t* context;
    np_tree_t* _cache;
    double startup_at;
};

void _np_sysinfo_init_cache(np_state_t* context)
{
    _LOCK_MODULE(np_sysinfo_t)
    {
        if (!np_module_initiated(sysinfo))
        {
            np_module_malloc(sysinfo);
            _module->_cache = np_tree_create();
            _module->startup_at = np_time_now();
        }
    }
}

void _np_sysinfo_destroy_cache(np_state_t* context)
{
    _LOCK_MODULE(np_sysinfo_t)
    {
        if (np_module_initiated(sysinfo))
        {
            np_module_var(sysinfo);
            np_tree_free(_module->_cache);
            np_module_free(sysinfo);
        }
    }
}

bool _np_sysinfo_client_send_cb(np_state_t* context, NP_UNUSED np_util_event_t args)
{
    _np_sysinfo_init_cache(context);

    if(np_has_receiver_for(context, _NP_SYSINFO_DATA))
    {
        np_tree_t* payload = np_sysinfo_get_my_info(context);

        // build properties
        np_tree_insert_str(payload, _NP_SYSINFO_SOURCE, np_treeval_new_s(_np_key_as_str(context->my_node_key)) );
        // send msg
        log_msg(LOG_INFO, "sending sysinfo proactive (size: %"PRIu16")", payload->size);

        unsigned char buffer[payload->byte_size];
        np_tree2buffer(context, payload, buffer);

        np_send(context, _NP_SYSINFO_DATA, buffer, payload->byte_size);

        np_tree_free(payload);
    }
    else
    {
        log_debug_msg(LOG_DEBUG| LOG_SYSINFO, "no receiver token for %s", _NP_SYSINFO_DATA);
    }
    return true;
}

void np_sysinfo_enable_client(np_state_t* context)
{
    log_trace_msg(LOG_TRACE, "start: void np_sysinfo_enable_client() {");

    struct np_mx_properties sysinfo_properties = {
        .reply_subject = {0},
        .ackmode = NP_MX_ACK_DESTINATION,
        .message_ttl = 20.0,
        .max_retry = 2,
        .max_parallel = 1,
        .cache_policy = NP_MX_FIFO_PURGE,
        .cache_size = 1,
        .intent_ttl = SYSINFO_MAX_TTL,
        .intent_update_after = SYSINFO_MIN_TTL,
    };

    np_set_mx_properties(context, _NP_SYSINFO_DATA, sysinfo_properties);

    np_jobqueue_submit_event_periodic(context, PRIORITY_MOD_USER_DEFAULT,
                                 np_crypt_rand_mm(0, SYSINFO_PROACTIVE_SEND_IN_SEC*1000) / 1000.,
                                 //sysinfo_response_props->msg_ttl / sysinfo_response_props->max_threshold,
                                 SYSINFO_PROACTIVE_SEND_IN_SEC+.0,
                                 _np_sysinfo_client_send_cb,
                                 "sysinfo_client_send_cb");
}

int _np_http_handle_sysinfo_hash(ht_request_t* request, ht_response_t* ret, void* context);
int _np_http_handle_sysinfo_all(ht_request_t* request, ht_response_t* ret, void* context);

void np_sysinfo_enable_server(np_state_t* context)
{
    _np_sysinfo_init_cache(context);

    struct np_mx_properties sysinfo_properties = {
        .reply_subject = {0},
        .ackmode = NP_MX_ACK_NONE,
        .message_ttl = 20.0,
        .max_retry = 2,
        .max_parallel = 8,
        .cache_policy = NP_MX_FIFO_PURGE,
        .cache_size = 32 * (SYSINFO_MAX_TTL / SYSINFO_PROACTIVE_SEND_IN_SEC),
        .intent_ttl = SYSINFO_MAX_TTL,
        .intent_update_after = SYSINFO_MIN_TTL,
    };

    np_set_mx_properties(context, _NP_SYSINFO_DATA, sysinfo_properties);
    np_add_receive_cb(context, _NP_SYSINFO_DATA, _np_in_sysinfo);

    if(np_module_initiated(http))
    {
        _np_add_http_callback(context, "/sysinfo", htp_method_GET, context, _np_http_handle_sysinfo_all);

        char my_sysinfo[9+64+1];
        snprintf(my_sysinfo, 9+64+1, "/sysinfo/%s", _np_key_as_str(context->my_node_key));
        _np_add_http_callback(context, my_sysinfo, htp_method_GET, context, _np_http_handle_sysinfo_hash);
    }
}

bool _np_in_sysinfo(np_state_t* context, struct np_message* msg)
{
    log_msg(LOG_INFO | LOG_SYSINFO, "received sysinfo (uuid: %s )", msg->uuid);

    np_tree_t payload = {0}; // np_tree_create();
    np_buffer2tree(context, msg->data, &payload);

    np_tree_elem_t* source = np_tree_find_str(&payload, _NP_SYSINFO_SOURCE);
    if (NULL == source)
    {
        log_msg(LOG_WARN | LOG_SYSINFO,
                "received sysinfo request w/o source key information.");
        return false;
    }
    bool source_str_free = false;
    char* source_val = np_treeval_to_str(source->val, &source_str_free);

    log_debug_msg(LOG_DEBUG | LOG_SYSINFO,"caching content for key %s (size: %"PRIu16", byte_size: %"PRIu32")",
        source_val, payload.size, payload.byte_size);

    // insert / replace cache item
    _LOCK_MODULE(np_sysinfo_t)
    {
        np_tree_elem_t* item = np_tree_find_str(np_module(sysinfo)->_cache, source_val);
        // only insert if the data is newer
        if(NULL != item && item->val.value.tree != NULL)
        {
            np_tree_elem_t* new_check = np_tree_find_str(&payload, _NP_SYSINFO_MY_NODE_TIMESTAMP);
            np_tree_elem_t* old_check = np_tree_find_str(item->val.value.tree, _NP_SYSINFO_MY_NODE_TIMESTAMP);

            if( NULL != new_check &&
                NULL != old_check &&
               new_check->val.value.d > old_check->val.value.d)
            {
                log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "removing old sysinfo for newer data (uuid:%s)", msg->uuid);
                np_tree_replace_str(np_module(sysinfo)->_cache, source_val, np_treeval_new_tree(&payload));
            }
            else
            {
                log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "ignoring sysinfo (uuid: %s ) due to newer data in cache", msg->uuid);
            }
        }
        else
        {
            log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "got sysinfo (uuid: %s) for a new node", msg->uuid);
            np_tree_replace_str(np_module(sysinfo)->_cache, source_val, np_treeval_new_tree(&payload));

            char new_sysinfo[9+64+1];
            snprintf(new_sysinfo, 9+64+1, "/sysinfo/%s", source_val);
            _np_add_http_callback(context, new_sysinfo, htp_method_GET, context, _np_http_handle_sysinfo_hash);
        }
    }
    if (source_str_free == true) {
        free(source_val);
    }
    np_tree_clear(&payload);
    return true;
}

// HTTP callback functions
np_tree_t* np_sysinfo_get_info(np_state_t* context, const char* const hash_of_target)
{
    log_trace_msg(LOG_TRACE, "start: np_tree_t* np_sysinfo_get_info(const char* const hash_of_target) {");

    char* my_key = _np_key_as_str(context->my_node_key);

    np_tree_t* ret = NULL;
    if (strncmp(hash_of_target, my_key, 64) == 0) {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Requesting sysinfo for myself");
        // If i request myself i can answer instantly
        ret = np_sysinfo_get_my_info(context);

        // I may anticipate the one requesting my information wants to request others as well
    } else {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Requesting sysinfo for node %s", hash_of_target);
        ret = _np_sysinfo_get_from_cache(context, hash_of_target, -1);
    }
    return ret;
}

np_tree_t* np_sysinfo_get_my_info(np_state_t* context)
{
    log_trace_msg(LOG_TRACE, "start: np_tree_t* np_sysinfo_get_my_info() {");
    np_tree_t* ret = np_tree_create();

    np_tree_insert_str(ret, _NP_SYSINFO_MY_NODE_TIMESTAMP, np_treeval_new_d(np_time_now()));
    np_tree_insert_str(ret, _NP_SYSINFO_MY_NODE_STARTUP_AT, np_treeval_new_d(np_module(sysinfo)->startup_at));

    // build local node
    np_tree_t* local_node = np_tree_create();
    _np_node_encode_to_jrb(local_node, context->my_node_key, true);

    np_tree_insert_str( ret, _NP_SYSINFO_MY_NODE, np_treeval_new_tree(local_node));
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "my sysinfo object has a node");
    np_tree_free( local_node);

    // build neighbours list
    np_tree_t* neighbours = np_tree_create();
    np_sll_t(np_key_ptr, neighbour_table) = _np_route_neighbors(context);
    if (NULL != neighbour_table && 0 < sll_size(neighbour_table) )
    {
        _np_node_encode_multiple_to_jrb(neighbours, neighbour_table, true);
    }
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "my sysinfo object has %"PRIu32" neighbours", sll_size(neighbour_table) );

    np_tree_insert_str( ret, _NP_SYSINFO_MY_NEIGHBOURS"_count", np_treeval_new_ul(sll_size(neighbour_table)));
    np_tree_insert_str( ret, _NP_SYSINFO_MY_NEIGHBOURS, np_treeval_new_tree(neighbours));

    np_key_unref_list(neighbour_table, "_np_route_neighbors");
    sll_free(np_key_ptr, neighbour_table);
    np_tree_free(neighbours);

    // build routing list
    np_tree_t* routes = np_tree_create();
    np_sll_t(np_key_ptr, routing_table) = _np_route_get_table(context);

    uint32_t routes_counter = 0;
    if (NULL != routing_table && 0 < sll_size(routing_table) )
    {
        _np_node_encode_multiple_to_jrb(routes, routing_table, true);
    }
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "my sysinfo object has %"PRIu32" routing table entries", sll_size(routing_table));

    np_tree_insert_str( ret, _NP_SYSINFO_MY_ROUTES"_count", np_treeval_new_ul(sll_size(routing_table) ) );
    np_tree_insert_str( ret, _NP_SYSINFO_MY_ROUTES, np_treeval_new_tree(routes));

    np_key_unref_list(routing_table, "_np_route_get_table");
    sll_free(np_key_ptr, routing_table);
    np_tree_free(routes);

    return ret;
}

np_tree_t* _np_sysinfo_get_from_cache(np_state_t* context, const char* const hash_of_target, uint16_t max_cache_ttl)
{
    log_trace_msg(LOG_TRACE, "start: np_tree_t* _np_sysinfo_get_from_cache(const char* const hash_of_target, uint16_t max_cache_ttl) {");
    _np_sysinfo_init_cache(context);

    np_tree_t* ret = NULL;
    _LOCK_MODULE(np_sysinfo_t)
    {
        np_tree_elem_t* item = np_tree_find_str(np_module(sysinfo)->_cache, hash_of_target);
        if (NULL != item && item->val.value.tree != NULL) {
            np_tree_t* tmp = item->val.value.tree;
            ret = np_tree_clone(tmp);
        }
    }
    // we may need to reset the found item to prevent the output of a dummy
    if(NULL != ret && max_cache_ttl != ((uint16_t)-1)){
        if( NULL == np_tree_find_str(ret, _NP_SYSINFO_MY_NODE)){
            np_tree_free( ret);
            ret = NULL;
        }
    }

    if (NULL == ret) {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo reply data received: no");
    } else {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO,
                "sysinfo reply data received: yes (size: %"PRIu16", byte_size: %"PRIu32")",
                ret->size, ret->byte_size);
    }

    return ret;
}

np_tree_t* np_sysinfo_get_all(np_state_t* context)
{
    log_trace_msg(LOG_TRACE, "start: void _np_sysinfo_request_others() {");

    np_tree_t* ret = np_tree_create();
    int16_t count = 0;

    np_tree_t * tmp = np_sysinfo_get_my_info(context);

    np_tree_insert_int( ret, count++, np_treeval_new_tree(tmp));
    np_tree_free( tmp);

    _LOCK_MODULE(np_sysinfo_t)
    {
        np_tree_elem_t* iter = RB_MIN(np_tree_s, np_module(sysinfo)->_cache);
        while (iter != NULL) {
            if (iter->val.value.tree != NULL) {
                np_tree_insert_int(ret, count++, np_treeval_new_tree(iter->val.value.tree));
            }
            iter = RB_NEXT(np_tree_s, np_module(sysinfo)->_cache, iter);
        }
    }

    return ret;
}

JSON_Value* _np_generate_error_json(const char* error,const char* details)
{
    log_trace_msg(LOG_TRACE | LOG_HTTP, "start: JSON_Value* _np_generate_error_json(const char* error,const char* details) {");
    JSON_Value* ret = json_value_init_object();

    json_object_set_string(json_object(ret), "error", error);
    json_object_set_string(json_object(ret), "details", details);

    return ret;
}

int _np_http_handle_sysinfo_hash(ht_request_t* request, ht_response_t* ret, void* context)
{
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Requesting sysinfo");

    char target_hash[65];
    int http_status = HTTP_CODE_BAD_REQUEST; // HTTP_CODE_OK
    char* response;
    JSON_Value* json_obj;
    np_key_t*  key = NULL;

    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "parse arguments of %s", request->ht_path);

    if (NULL != request->ht_path)
    {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "request has arguments");

        char *to_parse = NULL, *ht_path_dup = NULL;
        ht_path_dup = to_parse = strndup(request->ht_path, 9+64+1);
        char *path            = strsep(&to_parse, "/"); // strip leading "/""
              path            = strsep(&to_parse, "/"); // sysinfo
        char *tmp_target_hash = strsep(&to_parse, "/"); // target_hash

        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "parse path arguments of %s / %s", path, tmp_target_hash);

        if (NULL != tmp_target_hash) {
            if (strlen(tmp_target_hash) == 64) {
                snprintf(target_hash, 65, "%s", tmp_target_hash);
            }
            else
            {
                json_obj = _np_generate_error_json(
                    "provided key invalid.",
                    "length is not 64 characters");
                free(ht_path_dup);
                goto __json_return__;
            }
        }
        free(ht_path_dup);
    }
    else
    {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "no arguments provided");
        json_obj = _np_generate_error_json("no path arguments found", "expected length is 64 characters");
        goto __json_return__;
    }

    char* my_key = _np_key_as_str( ((np_state_t*)context)->my_node_key);

    np_tree_t* sysinfo = np_sysinfo_get_info(context, target_hash);
    if (NULL == sysinfo)
    {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Could not find system informations");
        http_status = HTTP_CODE_ACCEPTED;
        json_obj = _np_generate_error_json("key not found.", "update request is send. please wait.");
    }
    else
    {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo response tree (byte_size: %"PRIu32, sysinfo->byte_size);
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo response tree (size: %"PRIu16, sysinfo->size);
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Convert sysinfo to json");
        http_status = HTTP_CODE_OK;
        json_obj = np_tree2json(context, sysinfo);
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "cleanup");
    }
    np_tree_free(sysinfo);

__json_return__:

    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "serialise json response");

    if (NULL == json_obj) {
        log_msg(LOG_ERROR, "HTTP return is not defined for this code path");
        http_status = HTTP_CODE_INTERNAL_SERVER_ERROR;
        json_obj = _np_generate_error_json("Unknown Error", "no response defined");
    }
    response = np_json2char(json_obj, false);
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo response should be (strlen: %lu):", strlen(response));
    json_value_free(json_obj);

    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "write to body");

    ret->ht_status = http_status;
    ret->ht_body = response;

    return http_status;
}

int _np_http_handle_sysinfo_all(ht_request_t* request, ht_response_t* ret, void* context)
{
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Requesting sysinfo");

    char target_hash[65];

    bool usedefault = true;
    int http_status = HTTP_CODE_BAD_REQUEST;
    char* response;
    JSON_Value* json_obj;

    /**
     * Default behavior if no argument is given: display own node informations
     */
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "parse path arguments of %s", request->ht_path);

    np_tree_t* sysinfo = NULL;

    if (NULL != request->ht_path)
    {
        if (0 == strncmp(request->ht_path, "/sysinfo", 9))
        {
            sysinfo = np_sysinfo_get_all(context);
        }
        else
        {
            json_obj = _np_generate_error_json(
                "provided key invalid.",
                "length is not 64 characters");
            goto __json_return__;
        }
    }

    if (NULL == sysinfo)
    {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Could not find system informations");
        http_status = HTTP_CODE_ACCEPTED;
        json_obj = _np_generate_error_json("path not found", "only \"/sysinfo\" accepted at this point");
    }
    else
    {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo response tree (byte_size: %"PRIu32, sysinfo->byte_size);
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo response tree (size: %"PRIu16, sysinfo->size);

        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Convert sysinfo to json");
        json_obj = np_tree2json(context, sysinfo);
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "cleanup");

        http_status = HTTP_CODE_OK;
    }
    np_tree_free(sysinfo);


__json_return__:

    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "serialise json response");
    if (NULL == json_obj) {
        log_msg(LOG_ERROR,
            "HTTP return is not defined for this code path");
        http_status = HTTP_CODE_INTERNAL_SERVER_ERROR;
        json_obj = _np_generate_error_json("Unknown Error",
            "no response defined");
    }

    response = np_json2char(json_obj, false);
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo response should be (strlen: %lu):", strlen(response));
    json_value_free(json_obj);

    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "write to body");
    ret->ht_status = http_status;
    ret->ht_body = response;

    return http_status;
}
