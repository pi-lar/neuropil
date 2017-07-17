/*
 * np_sysinfo.c
 *
 *  Created on: 11.04.2017
 *      Author: sklampt
 */

#include <stdlib.h>
#include "inttypes.h"

#include "np_sysinfo.h"
#include "event/ev.h"

#include "neuropil.h"
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
#include "np_axon.h"
#include "np_settings.h"

#include "np_scache.h"


static char _NP_SYSINFO_REQUEST[] = "_NP.SYSINFO.REQUEST";
static char _NP_SYSINFO_REPLY[] = "_NP.SYSINFO.REPLY";

static const char* _NP_SYSINFO_MY_NODE = "node";
static const char* _NP_SYSINFO_MY_NODE_TIMESTAMP = "timestamp";
static const char* _NP_SYSINFO_MY_NEIGHBOURS = "neighbour_nodes";
static const char* _NP_SYSINFO_MY_ROUTES = "routing_nodes";

static const char* _NP_SYSINFO_SOURCE = "source_hash";
static const char* _NP_SYSINFO_TARGET = "target_hash";


static np_simple_cache_table_t* _cache = NULL;
static ev_timer* slave_send;

void slave_send_cb(NP_UNUSED EV_P_ ev_timer *w, NP_UNUSED int re);

void _np_sysinfo_init_cache()
{
    log_msg(LOG_TRACE, "start: void _np_sysinfo_init_cache(){");

    _LOCK_MODULE(np_sysinfo_t)
	{
    	if(NULL == _cache) {

			_cache = (np_simple_cache_table_t*) malloc(
					sizeof(np_simple_cache_table_t));
			CHECK_MALLOC(_cache);
			_np_threads_mutex_init(&_cache->lock);

			for (int i = 0; i < SIMPLE_CACHE_NR_BUCKETS; i++) {
				sll_init(np_cache_item_t, _cache->buckets[i]);
			}
		}
	}
}

void slave_send_cb(NP_UNUSED EV_P_ ev_timer *w, NP_UNUSED int re) {

  	np_waitref_obj(np_key_t, _np_state()->my_node_key, my_node_key);
  	if(my_node_key->node->joined_network == TRUE) {
		np_tree_t* reply_body = np_get_my_sysinfo();

		// build properties
		np_tree_t* reply_properties = np_tree_create();
		np_tree_insert_str(reply_properties, _NP_SYSINFO_SOURCE,
				np_treeval_new_s(_np_key_as_str(my_node_key)));

		// send msg
		log_msg(LOG_INFO, "sending sysinfo proactive (size: %"PRIu16")",
				reply_body->size);

		// TODO: set to broadcast (or better every master) if available
		np_send_msg(_NP_SYSINFO_REPLY, reply_properties, reply_body, NULL);
  	}
	np_unref_obj(np_key_t, my_node_key);

}

void np_sysinfo_enable_slave() {
    log_msg(LOG_TRACE, "start: void np_sysinfo_enable_slave() {");
    // the slave does not need the cache
	//_np_sysinfo_init_cache();
	np_msgproperty_t* sysinfo_request_props = NULL;
	np_new_obj(np_msgproperty_t, sysinfo_request_props);
	sysinfo_request_props->msg_subject = strndup(_NP_SYSINFO_REQUEST, 255);
	sysinfo_request_props->rep_subject = strndup(_NP_SYSINFO_REPLY, 255);
	sysinfo_request_props->mep_type =  REQ_REP;
	sysinfo_request_props->ack_mode = ACK_DESTINATION;
	sysinfo_request_props->retry    = 1;
	sysinfo_request_props->msg_ttl  = 20.0;

	np_msgproperty_t* sysinfo_response_props = NULL;
	np_new_obj(np_msgproperty_t, sysinfo_response_props);
	sysinfo_response_props->msg_subject = strndup(_NP_SYSINFO_REPLY, 255);
	sysinfo_response_props->mep_type = ONE_WAY;
	sysinfo_response_props->ack_mode = ACK_NONE;
	sysinfo_response_props->retry    = 1;
	sysinfo_response_props->msg_ttl  = 20.0;

	sysinfo_request_props->token_max_ttl = sysinfo_response_props->token_max_ttl = SYSINFO_MAX_TTL;
	sysinfo_request_props->token_min_ttl = sysinfo_response_props->token_min_ttl = SYSINFO_MIN_TTL;

	sysinfo_request_props->mode_type = INBOUND | ROUTE;
	sysinfo_request_props->max_threshold = 10;
	sysinfo_response_props->mode_type = OUTBOUND | ROUTE;
	sysinfo_response_props->max_threshold = 10;

	np_msgproperty_register(sysinfo_response_props);
	np_msgproperty_register(sysinfo_request_props);

	np_set_listener(_np_in_sysinfo, _NP_SYSINFO_REQUEST);

	if(slave_send  == NULL){
		slave_send = (ev_timer*) malloc(sizeof(struct ev_timer));
		CHECK_MALLOC(slave_send);
		ev_timer_init(slave_send, slave_send_cb, 0., SYSINFO_PROACTIVE_SEND_IN_SEC);
		EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
		ev_timer_start(EV_A_ slave_send);
 	}
}

void np_sysinfo_enable_master(){
    log_msg(LOG_TRACE, "start: void np_sysinfo_enable_master(){");
	_np_sysinfo_init_cache();
	np_msgproperty_t* sysinfo_request_props = NULL;
	np_new_obj(np_msgproperty_t, sysinfo_request_props);
	sysinfo_request_props->msg_subject = strndup(_NP_SYSINFO_REQUEST, 255);
	sysinfo_request_props->rep_subject = strndup(_NP_SYSINFO_REPLY, 255);
	sysinfo_request_props->mep_type =  REQ_REP;
	sysinfo_request_props->ack_mode = ACK_DESTINATION;
	sysinfo_request_props->retry    = 1;
	sysinfo_request_props->msg_ttl  = 20.0;

	np_msgproperty_t* sysinfo_response_props = NULL;
	np_new_obj(np_msgproperty_t, sysinfo_response_props);
	sysinfo_response_props->msg_subject = strndup(_NP_SYSINFO_REPLY, 255);
	sysinfo_response_props->mep_type = ONE_WAY;
	sysinfo_response_props->ack_mode = ACK_NONE;
	sysinfo_response_props->retry    = 1;
	sysinfo_response_props->msg_ttl  = 20.0;

	sysinfo_request_props->token_max_ttl = sysinfo_response_props->token_max_ttl = SYSINFO_MAX_TTL;
	sysinfo_request_props->token_min_ttl = sysinfo_response_props->token_min_ttl = SYSINFO_MIN_TTL;

	sysinfo_request_props->mode_type = OUTBOUND | ROUTE;
	sysinfo_request_props->max_threshold = 10;
	sysinfo_response_props->mode_type = INBOUND | ROUTE;
	sysinfo_response_props->max_threshold = 65534;

	np_msgproperty_register(sysinfo_response_props);
	np_msgproperty_register(sysinfo_request_props);

	np_set_listener(_np_in_sysinforeply, _NP_SYSINFO_REPLY);
}

np_bool _np_in_sysinfo(NP_UNUSED const np_message_t* const msg, np_tree_t* properties, NP_UNUSED np_tree_t* body) {
    log_msg(LOG_TRACE, "start: np_bool _np_in_sysinfo(NP_UNUSED const np_message_t* const msg, np_tree_t* properties, NP_UNUSED np_tree_t* body) {");
	log_msg(LOG_INFO, "received sysinfo request");

	np_tree_elem_t* source = np_tree_find_str(properties, _NP_SYSINFO_SOURCE);

	if (NULL == source) {
		log_msg(LOG_WARN,
				"received sysinfo request w/o source key information.");
		return FALSE;
	}

	np_tree_elem_t* target = np_tree_find_str(properties, _NP_SYSINFO_TARGET);

	char* mynode_hash = _np_key_as_str(_np_state()->my_node_key);

	if (NULL != target) {
		log_debug_msg(LOG_DEBUG, "sysinfo request message is from %s for %s !",
				source->val.value.s, target->val.value.s);

		if(strcmp(mynode_hash, target->val.value.s) != 0) {
			// should not happen as it does mean a wrong routing
			log_msg(LOG_WARN,
					"i am %s not %s . I cannot handle this sysinfo request",
					mynode_hash, target->val.value.s);
			return FALSE;
		}
	} else {
		log_debug_msg(LOG_DEBUG, "sysinfo request message is from %s for anyone!",
						source->val.value.s);
	}
	// checks completed. continue with reply building

	// build body
	np_tree_t* reply_body = np_get_my_sysinfo();

	// build properties
	np_tree_t* reply_properties = np_tree_create();
	np_tree_insert_str(reply_properties, _NP_SYSINFO_SOURCE,
			np_treeval_new_s(mynode_hash));

// TODO: Reenable target after functional audience selection for messages is implemented
//	np_tree_insert_str(reply_properties, _NP_SYSINFO_TARGET,
//			np_treeval_new_s(source->val.value.s));
//	np_dhkey_t target_dhkey;
//	_np_dhkey_from_str(source->val.value.s, &target_dhkey);

	// send msg
	log_msg(LOG_INFO, "sending sysinfo reply (size: %"PRIu16")",
			reply_body->size);

	np_send_msg(_NP_SYSINFO_REPLY, reply_properties, reply_body, NULL /* &target_dhkey */);


	return TRUE;
}

np_bool _np_in_sysinforeply(NP_UNUSED const np_message_t* const msg, np_tree_t* properties, np_tree_t* body) {
    log_msg(LOG_TRACE, "start: np_bool _np_in_sysinforeply(NP_UNUSED const np_message_t* const msg, np_tree_t* properties, np_tree_t* body) {");
	_np_sysinfo_init_cache();

	np_tree_elem_t* source = np_tree_find_str(properties, _NP_SYSINFO_SOURCE);

	if (NULL == source) {
		log_msg(LOG_WARN,
				"received sysinfo request w/o source key information.");
		return FALSE;
	}
	log_msg(LOG_INFO, "received sysinfo reply (uuid: %s )",msg->uuid);

	log_debug_msg(LOG_DEBUG,"caching content for key %s (size: %"PRIu16", byte_size: %"PRIu64")",
			source->val.value.s, body->size, body->byte_size);

	// insert / replace cache item
	_LOCK_MODULE(np_sysinfo_t)
	{
		np_cache_item_t* item = np_simple_cache_get(_cache,source->val.value.s);
		// only insert if the data is newer
		if(NULL != item) {
			np_tree_elem_t* new_check = np_tree_find_str(body, _NP_SYSINFO_MY_NODE_TIMESTAMP);
			np_tree_elem_t* old_check = np_tree_find_str(item->value, _NP_SYSINFO_MY_NODE_TIMESTAMP);

			if(NULL != new_check && NULL != old_check
			&& new_check->val.value.d > old_check->val.value.d) {
			    log_debug_msg(LOG_DEBUG, "Removing old SysInfo reply for newer data");
				np_tree_free(item->value);
				np_simple_cache_insert(_cache, source->val.value.s, np_tree_copy(body));
			}else{
			    log_debug_msg(LOG_DEBUG, "Ignoring SysInfo reply due to newer data in cache");
			}

		} else {
		    log_debug_msg(LOG_DEBUG, "Got SysInfo reply for a new node");
		    np_simple_cache_insert(_cache, source->val.value.s, np_tree_copy(body));
		}
	}

	return TRUE;
}

np_tree_t* np_get_my_sysinfo() {
    log_msg(LOG_TRACE, "start: np_tree_t* np_get_my_sysinfo() {");
	np_tree_t* ret = np_tree_create();

	np_tree_insert_str(ret, _NP_SYSINFO_MY_NODE_TIMESTAMP, np_treeval_new_d(ev_time()));

	// build local node
	np_tree_t* local_node = np_tree_create();
  	np_waitref_obj(np_key_t, _np_state()->my_node_key, my_node_key);
	_np_node_encode_to_jrb(local_node, my_node_key, FALSE);
	np_unref_obj(np_key_t, my_node_key);

	np_tree_insert_str(ret, _NP_SYSINFO_MY_NODE, np_treeval_new_tree(local_node));
	log_debug_msg(LOG_DEBUG, "my sysinfo object has a node");
	np_tree_free(local_node);

	// build neighbours list
	np_sll_t(np_key_t, neighbours_table) = _np_route_neighbors();

	np_tree_t* neighbours = np_tree_create();
	int neighbour_counter = 0;
	if (NULL != neighbours_table && 0 < neighbours_table->size) {
		np_key_t* current;
		while (NULL != sll_first(neighbours_table)) {
			current = sll_head(np_key_t, neighbours_table);
			if (current->node) {
				np_tree_t* neighbour = np_tree_create();
				_np_node_encode_to_jrb(neighbour, current, TRUE);
				np_tree_insert_int(neighbours, neighbour_counter++,
						np_treeval_new_tree(neighbour));
				np_tree_free(neighbour);
			}
		}
	}
	log_debug_msg(LOG_DEBUG, "my sysinfo object has %d neighbours",
			neighbour_counter);

	np_tree_insert_str(ret, _NP_SYSINFO_MY_NEIGHBOURS, np_treeval_new_tree(neighbours));
	np_unref_list(np_key_t, neighbours_table);
	sll_free(np_key_t, neighbours_table);
	np_tree_free(neighbours);

	// build routing list
	np_sll_t(np_key_t, routing_table) = _np_route_get_table();

	np_tree_t* routes = np_tree_create();
	int routes_counter = 0;
	if (NULL != routing_table && 0 < routing_table->size) {
		np_key_t* current;
		while (NULL != sll_first(routing_table)) {
			current = sll_head(np_key_t, routing_table);
			if (current->node) {
				np_tree_t* route = np_tree_create();
				_np_node_encode_to_jrb(route, current, TRUE);
				np_tree_insert_int(routes, routes_counter++, np_treeval_new_tree(route));
				np_tree_free(route);
			}
		}
	}
	log_debug_msg(LOG_DEBUG, "my sysinfo object has %d routing table entries",
			routes_counter);

	np_tree_insert_str(ret, _NP_SYSINFO_MY_ROUTES, np_treeval_new_tree(routes));
	np_unref_list(np_key_t, routing_table);
	sll_free(np_key_t, routing_table);
	np_tree_free(routes);

	return ret;
}

void _np_request_sysinfo(const char* const hash_of_target) {
    log_msg(LOG_TRACE, "start: void _np_request_sysinfo(const char* const hash_of_target) {");

	_np_sysinfo_init_cache();

	if (NULL != hash_of_target && hash_of_target[0] != '\0')
	{
		// Add dummy to prevent request spam
		_LOCK_MODULE(np_sysinfo_t)
		{
			if(NULL ==  _np_get_sysinfo_from_cache(hash_of_target,-1)) {
				np_tree_t* dummy = np_tree_create();
				np_tree_insert_str(dummy, _NP_SYSINFO_MY_NODE_TIMESTAMP, np_treeval_new_f(ev_time()));
				np_simple_cache_insert(_cache, hash_of_target, np_tree_copy(dummy));
			}
		}
		log_msg(LOG_INFO, "sending sysinfo request to %s", hash_of_target);
		np_tree_t* properties = np_tree_create();
		np_tree_t* body = np_tree_create();

		np_tree_insert_str(properties, _NP_SYSINFO_SOURCE,
				np_treeval_new_s(_np_key_as_str(_np_state()->my_node_key)));

// TODO: Reenable target after functional audience selection for messages is implemented
//		np_tree_insert_str(properties, _NP_SYSINFO_TARGET,
//				np_treeval_new_s(hash_of_target));

		np_dhkey_t target_dhkey = np_dhkey_create_from_hash(hash_of_target);

		np_send_msg(_NP_SYSINFO_REQUEST, properties, body, &target_dhkey);

	} else {
		log_msg(LOG_WARN,
				"could not sending sysinfo request. (unknown target)");
	}

}

np_tree_t* np_get_sysinfo(const char* const hash_of_target) {
    log_msg(LOG_TRACE, "start: np_tree_t* np_get_sysinfo(const char* const hash_of_target) {");

	char* my_key = _np_key_as_str(_np_state()->my_node_key);

	np_tree_t* ret = NULL;
	if (strncmp(hash_of_target, my_key, 64) == 0) {
		log_debug_msg(LOG_DEBUG, "Requesting sysinfo for myself");
		// If i request myself i can answer instantly
		ret = np_get_my_sysinfo();

		// I may anticipate the one requesting my information wants to request others as well
		//_np_request_others();
	} else {
		log_debug_msg(LOG_DEBUG, "Requesting sysinfo for node %s", hash_of_target);
		ret = _np_get_sysinfo_from_cache(hash_of_target, -1);
	}
	return ret;
}

np_tree_t* _np_get_sysinfo_from_cache(const char* const hash_of_target, uint16_t max_cache_ttl) {
    log_msg(LOG_TRACE, "start: np_tree_t* _np_get_sysinfo_from_cache(const char* const hash_of_target, uint16_t max_cache_ttl) {");
	_np_sysinfo_init_cache();
	np_tree_t* ret = NULL;
	_LOCK_MODULE(np_sysinfo_t)
	{
		np_cache_item_t* item = np_simple_cache_get(_cache, hash_of_target);
		if (NULL != item && item->value != NULL) {
			if ((ev_time() - item->insert_time) <= max_cache_ttl) {
				np_tree_t* tmp = item->value;
				ret = np_tree_copy(tmp);
			}
		}
	}
	// we may need to reset the found item to prevent the output of a dummy
	if(NULL != ret && max_cache_ttl != ((uint16_t)-1)){
		if( NULL == np_tree_find_str(ret, _NP_SYSINFO_MY_NODE)){
			np_tree_free(ret);
			ret = NULL;
		}
	}

	if (NULL == ret) {
		log_debug_msg(LOG_DEBUG, "sysinfo reply data received: no");
	} else {
		log_debug_msg(LOG_DEBUG,
				"sysinfo reply data received: yes (size: %"PRIu16", byte_size: %"PRIu64")",
				ret->size, ret->byte_size);
	}

	return ret;
}

void _np_request_others() {
    log_msg(LOG_TRACE, "start: void _np_request_others() {");

	np_sll_t(np_key_t, routing_table) = NULL;
	np_sll_t(np_key_t, neighbours_table) = NULL;
	np_tree_t * tmp = NULL;

	np_waitref_obj(np_key_t, _np_state()->my_node_key, my_node_key);

	routing_table = _np_route_get_table();
	if (NULL != routing_table && 0 < routing_table->size) {
		np_key_t* current;
		while (NULL != sll_first(routing_table)) {
			current = sll_head(np_key_t, routing_table);
			if (	NULL != current &&
					strcmp(_np_key_as_str(current),_np_key_as_str(my_node_key) ) != 0 &&
					NULL == (tmp = _np_get_sysinfo_from_cache(_np_key_as_str(current),-2)))
			{
				_np_request_sysinfo(_np_key_as_str(current));
			}
			np_tree_free(tmp);
		}
	}

	neighbours_table = _np_route_neighbors();
	if (NULL != neighbours_table && 0 < neighbours_table->size) {
		np_key_t* current;
		while (NULL != sll_first(neighbours_table)) {
			current = sll_head(np_key_t, neighbours_table);
			if (	NULL != current &&
					strcmp(_np_key_as_str(current),_np_key_as_str(my_node_key) ) != 0 &&
					NULL == (tmp = _np_get_sysinfo_from_cache(_np_key_as_str(current),-2)))
			{
						_np_request_sysinfo(_np_key_as_str(current));
			}
			np_tree_free(tmp);
		}
	}

	np_unref_list(np_key_t, routing_table);
	sll_free(np_key_t, routing_table);
	np_unref_list(np_key_t, neighbours_table);
	sll_free(np_key_t, neighbours_table);
	np_unref_obj(np_key_t, my_node_key);
}
