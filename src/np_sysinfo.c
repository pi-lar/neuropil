//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include <stdlib.h>
#include "inttypes.h"

#include "np_sysinfo.h"
 
#include "np_legacy.h"
#include "np_types.h"
#include "np_log.h"
#include "np_msgproperty.h"
#include "np_message.h"
#include "np_memory.h"

#include "np_node.h"
#include "np_route.h"
#include "np_dhkey.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_treeval.h"
#include "np_tree.h"
#include "np_threads.h"
#include "np_jobqueue.h"
#include "np_axon.h"
#include "np_settings.h"
#include "np_constants.h"
#include "np_network.h"

#include "np_scache.h"

#define  _NP_SYSINFO_MY_NODE "node"
#define  _NP_SYSINFO_MY_NODE_TIMESTAMP "timestamp"
#define  _NP_SYSINFO_MY_NODE_STARTUP_AT "startup_at"

#define  _NP_SYSINFO_MY_NEIGHBOURS "neighbour_nodes"
#define  _NP_SYSINFO_MY_ROUTES "routing_nodes"

#define  _NP_SYSINFO_SOURCE  "source_hash"
#define  _NP_SYSINFO_TARGET  "target_hash"


np_module_struct(sysinfo) {
    np_state_t* context;
    np_tree_t* _cache;

    double startup_at;
};
void _np_sysinfo_client_send_cb(np_state_t* context, np_jobargs_t args);

void _np_sysinfo_init_cache(np_state_t* context)
{
    _LOCK_MODULE(np_sysinfo_t)
    {
        if (!np_module_initiated(sysinfo)) {
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
        if (np_module_initiated(sysinfo)) {
            np_module_var(sysinfo);
            np_tree_free(_module->_cache);            
            np_module_free(sysinfo);
        }
    }
}

void _np_sysinfo_client_send_cb(np_state_t* context, NP_UNUSED np_jobargs_t args) {
    
    _np_sysinfo_init_cache(context);

    if(np_has_receiver_for(context, _NP_SYSINFO_REPLY)) {
        np_waitref_obj(np_key_t, context->my_node_key, my_node_key, "usage");
        np_tree_t* reply_body = np_sysinfo_get_my_info(context);

        // build properties
        np_tree_insert_str(reply_body, _NP_SYSINFO_SOURCE,
                np_treeval_new_s(_np_key_as_str(my_node_key)));

        // send msg
        log_msg(LOG_INFO | LOG_SYSINFO, "sending sysinfo proactive (size: %"PRIu16")",
                reply_body->size);
        
        np_send_msg(context, _NP_SYSINFO_REPLY, reply_body, NULL);

        np_unref_obj(np_key_t, my_node_key, "usage");
    }
    else {
        log_debug_msg(LOG_DEBUG| LOG_SYSINFO, "no receiver token for \""_NP_SYSINFO_REPLY"\"");
    }
}

void np_sysinfo_enable_client(np_state_t* context) {
    log_trace_msg(LOG_TRACE, "start: void np_sysinfo_enable_client() {");
    // the client does not need the cache
    //_np_sysinfo_init_cache();
    
   bool created = false;
    np_msgproperty_t* sysinfo_response_props = np_msgproperty_get(context, OUTBOUND, _NP_SYSINFO_REPLY);
    if(sysinfo_response_props == NULL){
        np_new_obj(np_msgproperty_t, sysinfo_response_props);
        created = true;
    }
    
    sysinfo_response_props->msg_subject = strndup(_NP_SYSINFO_REPLY, 255);
    sysinfo_response_props->mep_type = ONE_WAY;
    sysinfo_response_props->ack_mode = ACK_NONE;
    sysinfo_response_props->retry    = 0;
    sysinfo_response_props->priority += 1;
    sysinfo_response_props->msg_ttl  = 20.0;
    sysinfo_response_props->mode_type = OUTBOUND | ROUTE;
    sysinfo_response_props->max_threshold = 2;

    sysinfo_response_props->token_max_ttl = SYSINFO_MAX_TTL;
    sysinfo_response_props->token_min_ttl = SYSINFO_MIN_TTL;

    np_msgproperty_register(sysinfo_response_props);
    if(created) {
        np_unref_obj(np_msgproperty_t, sysinfo_response_props, ref_obj_creation);        
    }    

    np_job_submit_event_periodic(context, PRIORITY_MOD_USER_DEFAULT,
                                 np_crypt_rand_mm(0, SYSINFO_PROACTIVE_SEND_IN_SEC*1000) / 1000.,
                                 //sysinfo_response_props->msg_ttl / sysinfo_response_props->max_threshold,
                                 SYSINFO_PROACTIVE_SEND_IN_SEC+.0,
                                 _np_sysinfo_client_send_cb,
                                 "sysinfo_client_send_cb");
}

void np_sysinfo_enable_server(np_state_t* context) {
    
    _np_sysinfo_init_cache(context);
    bool created = false;

    np_msgproperty_t* sysinfo_response_props = np_msgproperty_get(context, INBOUND, _NP_SYSINFO_REPLY);
    if(sysinfo_response_props == NULL){
        np_new_obj(np_msgproperty_t, sysinfo_response_props);
        created = true;
    }
    
    sysinfo_response_props->msg_subject = strndup(_NP_SYSINFO_REPLY, 255);
    sysinfo_response_props->mep_type = ONE_WAY;
    sysinfo_response_props->ack_mode = ACK_NONE;
    sysinfo_response_props->retry    = 0;
    sysinfo_response_props->msg_ttl  = 20.0;
    sysinfo_response_props->priority += 1;
    
    sysinfo_response_props->token_max_ttl = SYSINFO_MAX_TTL;
    sysinfo_response_props->token_min_ttl = SYSINFO_MIN_TTL;
    sysinfo_response_props->mode_type = INBOUND | ROUTE;
    sysinfo_response_props->max_threshold =  32/*expected count of nodes */ * (SYSINFO_MAX_TTL / SYSINFO_PROACTIVE_SEND_IN_SEC);
    
    np_msgproperty_register(sysinfo_response_props);
    
    if(created) {
        np_unref_obj(np_msgproperty_t, sysinfo_response_props, ref_obj_creation);        
    }
    np_add_receive_listener(context, _np_in_sysinforeply, NULL, _NP_SYSINFO_REPLY);
}

bool _np_in_sysinfo(np_context* ac, NP_UNUSED const np_message_t* const msg, np_tree_t* body, NP_UNUSED void* localdata) {
    np_ctx_cast(ac);
    log_trace_msg(LOG_TRACE, "start: bool _np_in_sysinfo(NP_UNUSED const np_message_t* const msg, np_tree_t* properties, NP_UNUSED np_tree_t* body) {");
    log_msg(LOG_INFO | LOG_SYSINFO, "received sysinfo request");

    np_tree_elem_t* source = np_tree_find_str(body, _NP_SYSINFO_SOURCE);

    if (NULL == source) {
        log_msg(LOG_WARN | LOG_SYSINFO,
                "received sysinfo request w/o source key information.");
        return false;
    }

    np_tree_elem_t* target = np_tree_find_str(body, _NP_SYSINFO_TARGET);

    char* mynode_hash = _np_key_as_str(context->my_node_key);

    bool source_str_free = false;
    char* source_val = np_treeval_to_str(source->val, &source_str_free);

    if (NULL != target) {

        bool target_str_free = false;
        char* target_val = np_treeval_to_str(target->val, &target_str_free);
    
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo request message is from %s for %s !",
            source_val,  target_val);

        if(strcmp(mynode_hash, target_val) != 0) {
            // should not happen as it does mean a wrong routing
            log_msg(LOG_WARN | LOG_SYSINFO,
                    "i am %s not %s . I cannot handle this sysinfo request",
                    mynode_hash,  target_val);

            if (target_str_free == true) {
                free(target_val);
            }
            return false;
        }
    } else {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo request message is from %s for anyone!",
            source_val);
    }

    if (source_str_free == true) {
        free(source_val);
    }


    // checks completed. continue with reply building

    // build body
    np_tree_t* reply_body = np_sysinfo_get_my_info(context);

    // build properties

    np_tree_insert_str(reply_body, _NP_SYSINFO_SOURCE,
            np_treeval_new_s(mynode_hash));

// TODO: Reenable target after functional audience selection for messages is implemented
//	np_tree_insert_str( reply_properties, _NP_SYSINFO_TARGET,
//			np_treeval_new_s( np_treeval_to_str(source->val)));
//	np_dhkey_t target_dhkey;
//	_np_str_dhkey(  np_treeval_to_str(source->val), &target_dhkey);

    // send msg
    log_msg(LOG_INFO | LOG_SYSINFO, "sending sysinfo reply (size: %"PRIu16")",
            reply_body->size);

    np_send_msg(context, _NP_SYSINFO_REPLY, reply_body, NULL /* &target_dhkey */);

    return true;
}

bool _np_in_sysinforeply(np_context* ac, const np_message_t* const msg, np_tree_t* body, NP_UNUSED void* localdata) {
    np_ctx_cast(ac);

    log_trace_msg(LOG_TRACE, "start: bool _np_in_sysinforeply(NP_UNUSED const np_message_t* const msg, np_tree_t* properties, np_tree_t* body) {");
    _np_sysinfo_init_cache(context);

    np_tree_elem_t* source = np_tree_find_str(body, _NP_SYSINFO_SOURCE);

    if (NULL == source) {
        log_msg(LOG_WARN | LOG_SYSINFO,
                "received sysinfo request w/o source key information.");
        return false;
    }
    log_msg(LOG_INFO | LOG_SYSINFO, "received sysinfo reply (uuid: %s )",msg->uuid);

    bool source_str_free = false;
    char* source_val = np_treeval_to_str(source->val, &source_str_free);

    log_debug_msg(LOG_DEBUG | LOG_SYSINFO,"caching content for key %s (size: %"PRIu16", byte_size: %"PRIu32")",
        source_val, body->size, body->byte_size);

    // insert / replace cache item
    _LOCK_MODULE(np_sysinfo_t)
    {
        np_tree_elem_t* item = np_tree_find_str(np_module(sysinfo)->_cache, source_val);		
        // only insert if the data is newer
        if(NULL != item && item->val.value.tree != NULL) {
            np_tree_elem_t* new_check = np_tree_find_str(body, _NP_SYSINFO_MY_NODE_TIMESTAMP);
            np_tree_elem_t* old_check = np_tree_find_str(item->val.value.tree, _NP_SYSINFO_MY_NODE_TIMESTAMP);

            if(NULL != new_check && NULL != old_check
            && new_check->val.value.d > old_check->val.value.d) {
                log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Removing old SysInfo reply for newer data (uuid:%s)", msg->uuid);
                np_tree_replace_str(np_module(sysinfo)->_cache, source_val, np_treeval_new_tree(body));				
            }else{
                log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Ignoring SysInfo reply (uuid: %s ) due to newer data in cache", msg->uuid);
            }

        } else {
            log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Got SysInfo reply (uuid: %s) for a new node", msg->uuid);
            np_tree_replace_str(np_module(sysinfo)->_cache, source_val, np_treeval_new_tree(body));
        }
    }
    if (source_str_free == true) {
        free(source_val);
    }

    return true;
}

np_tree_t* np_sysinfo_get_my_info(np_state_t* context) {
    log_trace_msg(LOG_TRACE, "start: np_tree_t* np_sysinfo_get_my_info() {");
    np_tree_t* ret = np_tree_create();	
    ret->attr.disable_special_str = true;

    np_tree_insert_str(ret, _NP_SYSINFO_MY_NODE_TIMESTAMP, np_treeval_new_d(np_time_now()));
    np_tree_insert_str(ret, _NP_SYSINFO_MY_NODE_STARTUP_AT, np_treeval_new_d(np_module(sysinfo)->startup_at));

    // build local node
    np_tree_t* local_node = np_tree_create();
    np_waitref_obj(np_key_t, context->my_node_key, my_node_key, "usage");
    _np_node_encode_to_jrb(local_node, my_node_key, true);
    np_tree_replace_str( local_node, NP_SERIALISATION_NODE_PROTOCOL, np_treeval_new_s(_np_network_get_protocol_string(context, my_node_key->node->protocol)));

    np_unref_obj(np_key_t, my_node_key, "usage");

    np_tree_insert_str( ret, _NP_SYSINFO_MY_NODE, np_treeval_new_tree(local_node));
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "my sysinfo object has a node");
    np_tree_free( local_node);

    // build neighbours list
    np_sll_t(np_key_ptr, neighbours_table) = _np_route_neighbors(context);

    np_tree_t* neighbours = np_tree_create();
    uint32_t neighbour_counter = 0;
    if (NULL != neighbours_table && 0 < neighbours_table->size) {
        np_key_t* current;
        while (NULL != sll_first(neighbours_table)) {
            current = sll_head(np_key_ptr, neighbours_table);
            if (current->node) {
                np_tree_t* neighbour = np_tree_create();
                _np_node_encode_to_jrb(neighbour, current, true);
                np_tree_replace_str( neighbour, NP_SERIALISATION_NODE_PROTOCOL, np_treeval_new_s(_np_network_get_protocol_string(context, current->node->protocol)));
                np_tree_insert_int( neighbours, neighbour_counter++,
                        np_treeval_new_tree(neighbour));
                np_tree_free( neighbour);
                np_unref_obj(np_key_t, current,"_np_route_neighbors");
            }
        }
    }
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "my sysinfo object has %"PRIu32" neighbours",
            neighbour_counter);

    np_tree_insert_str( ret, _NP_SYSINFO_MY_NEIGHBOURS"_count", np_treeval_new_ul(neighbour_counter));
    np_tree_insert_str( ret, _NP_SYSINFO_MY_NEIGHBOURS, np_treeval_new_tree(neighbours));
    sll_free(np_key_ptr, neighbours_table);
    np_tree_free( neighbours);

    // build routing list
    np_sll_t(np_key_ptr, routing_table) = _np_route_get_table(context);
    
    np_tree_t* routes = np_tree_create();
    uint32_t routes_counter = 0;
    if (NULL != routing_table && 0 < routing_table->size) {
        np_key_t* current;
        while (NULL != sll_first(routing_table)) {
            current = sll_head(np_key_ptr, routing_table);
            if (current->node) {
                np_tree_t* route = np_tree_create();
                _np_node_encode_to_jrb(route, current, true);
                np_tree_replace_str(
                    route,
                    NP_SERIALISATION_NODE_PROTOCOL,
                    np_treeval_new_s(_np_network_get_protocol_string(context, current->node->protocol))
                );
                np_tree_replace_str(
                    route,
                    "np.node.route.idx",
                    np_treeval_new_ul(routes_counter)
                );
                np_tree_insert_int( routes, routes_counter++,
                    np_treeval_new_tree(route)
                );
                np_tree_free( route);
                np_unref_obj(np_key_t, current,"_np_route_get_table");
            }
        }
    }
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "my sysinfo object has %"PRIu32" routing table entries",
            routes_counter);

    np_tree_insert_str( ret, _NP_SYSINFO_MY_ROUTES"_count", np_treeval_new_ul(routes_counter));
    np_tree_insert_str( ret, _NP_SYSINFO_MY_ROUTES, np_treeval_new_tree(routes));	
    sll_free(np_key_ptr, routing_table);
    np_tree_free( routes);

    return ret;
}

void _np_sysinfo_request(np_state_t* context, const char* const hash_of_target) {
    log_trace_msg(LOG_TRACE, "start: void _np_sysinfo_request(const char* const hash_of_target) {");

    _np_sysinfo_init_cache(context);

    if (NULL != hash_of_target && hash_of_target[0] != '\0')
    {
        // Add dummy to prevent request spam
        _LOCK_MODULE(np_sysinfo_t)
        {
            if(NULL ==  _np_sysinfo_get_from_cache(context, hash_of_target,-1)) {
                np_tree_t* dummy = np_tree_create();
                np_tree_insert_str(dummy, _NP_SYSINFO_MY_NODE_TIMESTAMP, np_treeval_new_d(np_time_now()));
                np_tree_insert_str(dummy, _NP_SYSINFO_MY_NODE_TIMESTAMP, np_treeval_new_d(np_module(sysinfo)->startup_at));				

                np_tree_replace_str(np_module(sysinfo)->_cache, hash_of_target, np_treeval_new_tree(dummy));
            }
        }
        log_msg(LOG_INFO | LOG_SYSINFO, "sending sysinfo request to %s", hash_of_target);
        np_tree_t* body = np_tree_create();

        np_tree_insert_str(body, _NP_SYSINFO_SOURCE,
                np_treeval_new_s(_np_key_as_str(context->my_node_key)));

// TODO: Reenable target after functional audience selection for messages is implemented
//		np_tree_insert_str( properties, _NP_SYSINFO_TARGET,
//				np_treeval_new_s(hash_of_target));

        // np_dhkey_t target_dhkey = np_dhkey_create_from_hash(hash_of_target);
        // np_send_msg(_NP_SYSINFO_REQUEST, properties, body, &target_dhkey);

    } else {
        log_msg(LOG_WARN | LOG_SYSINFO,
                "could not sending sysinfo request. (unknown target)");
    }

}

np_tree_t* np_sysinfo_get_info(np_state_t* context, const char* const hash_of_target) {
    log_trace_msg(LOG_TRACE, "start: np_tree_t* np_sysinfo_get_info(const char* const hash_of_target) {");

    char* my_key = _np_key_as_str(context->my_node_key);

    np_tree_t* ret = NULL;
    if (strncmp(hash_of_target, my_key, 64) == 0) {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Requesting sysinfo for myself");
        // If i request myself i can answer instantly
        ret = np_sysinfo_get_my_info(context);

        // I may anticipate the one requesting my information wants to request others as well
        //_np_sysinfo_request_others();
    } else {
        log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Requesting sysinfo for node %s", hash_of_target);
        ret = _np_sysinfo_get_from_cache(context, hash_of_target, -1);
    }
    return ret;
}

np_tree_t* _np_sysinfo_get_from_cache(np_state_t* context, const char* const hash_of_target, uint16_t max_cache_ttl) {
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

void _np_sysinfo_request_others(np_state_t* context) {
    log_trace_msg(LOG_TRACE, "start: void _np_sysinfo_request_others() {");

    np_sll_t(np_key_ptr, routing_table) = NULL;
    np_sll_t(np_key_ptr, neighbours_table) = NULL;
    np_tree_t * tmp = NULL;

    np_waitref_obj(np_key_t, context->my_node_key, my_node_key, "usage");

    routing_table = _np_route_get_table(context);
    if (NULL != routing_table && 0 < routing_table->size) {
        np_key_t* current;
        while (NULL != sll_first(routing_table)) {
            current = sll_head(np_key_ptr, routing_table);
            if (NULL != current &&
                strcmp(_np_key_as_str(current), _np_key_as_str(my_node_key)) != 0 &&
                NULL == (tmp = _np_sysinfo_get_from_cache(context, _np_key_as_str(current), -2)))
            {
                _np_sysinfo_request(context, _np_key_as_str(current));
            }
            np_unref_obj(np_key_t, current, "_np_route_get_table");
        }
    }

    neighbours_table = _np_route_neighbors(context);
    if (NULL != neighbours_table && 0 < neighbours_table->size) {
        np_key_t* current;
        while (NULL != sll_first(neighbours_table)) {
            current = sll_head(np_key_ptr, neighbours_table);
            if (NULL != current &&
                strcmp(_np_key_as_str(current), _np_key_as_str(my_node_key)) != 0 &&
                NULL == (tmp = _np_sysinfo_get_from_cache(context, _np_key_as_str(current), -2)))
            {
                _np_sysinfo_request(context, _np_key_as_str(current));
            }
            np_unref_obj(np_key_t, current, "_np_route_neighbors");
        }
    }

    sll_free(np_key_ptr, routing_table);
    sll_free(np_key_ptr, neighbours_table);
    np_unref_obj(np_key_t, my_node_key, "usage");
}

np_tree_t* np_sysinfo_get_all(np_state_t* context) {
    log_trace_msg(LOG_TRACE, "start: void _np_sysinfo_request_others() {");

    np_tree_t* ret = np_tree_create();
    int16_t count = 0;

    np_tree_t * tmp = np_sysinfo_get_my_info(context);
    
    np_tree_insert_int( ret, count++, np_treeval_new_tree(tmp));
    np_tree_free( tmp);

    // np_sll_t(np_key_ptr, routing_table) = NULL;
    // np_sll_t(np_key_ptr, neighbours_table) = NULL;

    np_waitref_obj(np_key_t, context->my_node_key, my_node_key, "usage");	

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
    /*
    routing_table = _np_route_get_table(context);
    neighbours_table = _np_route_neighbors(context);
    np_sll_t(np_key_ptr, merge_table) = sll_merge(np_key_ptr, routing_table, neighbours_table, _np_key_cmp);

    // now serialize both tables into np_tree
    if (NULL != merge_table && 0 < merge_table->size) {
        np_key_t* current;
        while (NULL != sll_first(merge_table)) {
            current = sll_head(np_key_ptr, merge_table);
            if (
                strcmp(_np_key_as_str(current), _np_key_as_str(my_node_key)) != 0 &&
                NULL != (tmp = _np_sysinfo_get_from_cache(context, _np_key_as_str(current), -2)))
            {
                
                np_tree_insert_int( ret, count++,np_treeval_new_tree(tmp));
                np_tree_free( tmp);
            }
        }
    }
    
    sll_free(np_key_ptr, merge_table);
    np_key_unref_list(routing_table,"_np_route_get_table");
    sll_free(np_key_ptr, routing_table);
    np_key_unref_list(neighbours_table, "_np_route_neighbors");
    sll_free(np_key_ptr, neighbours_table);
    */
    np_unref_obj(np_key_t, my_node_key, "usage");

    return ret;
}
