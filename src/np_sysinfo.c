/*
 * np_sysinfo.c
 *
 *  Created on: 11.04.2017
 *      Author: sklampt
 */

#include <stdlib.h>
#include "inttypes.h"

#include "np_sysinfo.h"

#include "neuropil.h"
#include "np_types.h"
#include "np_log.h"
#include "np_msgproperty.h"
#include "np_message.h"
#include "np_node.h"
#include "np_route.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_val.h"
#include "np_tree.h"

#include "np_scache.h"


static char _NP_SYSINFO_REQUEST[] = "_NP.SYSINFO.REQUEST";
static char _NP_SYSINFO_REPLY[] = "_NP.SYSINFO.REPLY";

static const char* _NP_SYSINFO_MY_NODE = "node";
static const char* _NP_SYSINFO_MY_NEIGHBOURS = "neighbour_nodes";
static const char* _NP_SYSINFO_MY_ROUTES = "routing_nodes";

static const char* _NP_SYSINFO_SOURCE = "source_hash";
static const char* _NP_SYSINFO_TARGET = "target_hash";

static pthread_mutex_t __lock_mutex = PTHREAD_MUTEX_INITIALIZER;
_NP_MODULE_LOCK_IMPL(np_sysinfo);

static struct np_simple_cache_table_t* _cache;

void _np_sysinfo_init(np_bool isRequestor) {

	//TODO: currently the system cannot handle in/out of the same node A->A as is decryptes wrong
	np_msgproperty_t* sysinfo_request_props = NULL;
	np_new_obj(np_msgproperty_t, sysinfo_request_props);
	sysinfo_request_props->mep_type = ONE_WAY_WITH_REPLY;
	sysinfo_request_props->msg_subject = _NP_SYSINFO_REQUEST;
	sysinfo_request_props->ack_mode = ACK_DESTINATION;
	sysinfo_request_props->ttl = 20.0;
	sysinfo_request_props->max_threshold = 4;

	np_msgproperty_t* sysinfo_response_props = NULL;
	np_new_obj(np_msgproperty_t, sysinfo_response_props);
	sysinfo_response_props->mep_type = ONE_WAY;
	sysinfo_response_props->msg_subject = _NP_SYSINFO_REPLY;
	sysinfo_response_props->ack_mode = ACK_DESTINATION;
	sysinfo_response_props->ttl = 20.0;
	sysinfo_response_props->max_threshold = 8;

	if (isRequestor) {
		_cache = (np_simple_cache_table_t*) malloc(
				sizeof(np_simple_cache_table_t));

		for (int i = 0; i < SIMPLE_CACHE_NR_BUCKETS; i++) {
			sll_init(np_cache_item_t, _cache->buckets[i]);
		}

		sysinfo_response_props->mode_type = INBOUND | ROUTE;
		sysinfo_request_props->mode_type = OUTBOUND | ROUTE;

		np_msgproperty_register(sysinfo_response_props);
		np_msgproperty_register(sysinfo_request_props);

		np_set_listener(_np_in_sysinforeply, _NP_SYSINFO_REPLY);

	} else {
		sysinfo_response_props->mode_type = OUTBOUND | ROUTE;
		sysinfo_request_props->mode_type = INBOUND | ROUTE;

		np_msgproperty_register(sysinfo_response_props);
		np_msgproperty_register(sysinfo_request_props);

		np_set_listener(_np_in_sysinfo, _NP_SYSINFO_REQUEST);
	}

}

np_bool _np_in_sysinfo(np_tree_t* properties, NP_UNUSED np_tree_t* body) {
	log_msg(LOG_TRACE, ".start._in_sysinfo");

	np_tree_elem_t* source = tree_find_str(properties, _NP_SYSINFO_SOURCE);

	if (NULL == source) {
		log_msg(LOG_WARN,
				"received sysinfo request w/o source key information.");
		return FALSE;
	}

	np_tree_elem_t* target = tree_find_str(properties, _NP_SYSINFO_TARGET);

	if (NULL == target) {
		log_msg(LOG_WARN,
				"received sysinfo request w/o target key information.");
		return FALSE;
	}
	log_msg(LOG_INFO, "received sysinfo request");

	log_msg(LOG_DEBUG, "sysinfo request message is from %s for %s !",
			source->val.value.s, target->val.value.s);

	char* mynode_hash = _key_as_str(_np_state()->my_node_key);

	if (strcmp(mynode_hash, target->val.value.s) != 0) {
		// should not happen as it does mean a wrong routing
		log_msg(LOG_WARN,
				"i am %s not %s . I cannot handle this sysinfo request",
				mynode_hash, target->val.value.s);
		return FALSE;
	}
	// checks completed. continue with reply building

	// build body
	np_tree_t* reply_body = np_get_my_sysinfo();

	// build properties
	np_tree_t* reply_properties = make_nptree();
	tree_insert_str(reply_properties, _NP_SYSINFO_SOURCE,
			new_val_s(mynode_hash));
	tree_insert_str(reply_properties, _NP_SYSINFO_TARGET,
			new_val_s(source->val.value.s));

	// send msg
	log_msg(LOG_INFO, "sending sysinfo reply (size: %"PRIu16")",
			reply_body->size);

	np_dhkey_t* target_dhkey = malloc(sizeof(np_dhkey_t));
	if(NULL == target_dhkey) {
		log_msg(LOG_ERROR, "Could not allocate memory");
	}

	_str_to_dhkey(source->val.value.s, target_dhkey);
	np_send_msg(_NP_SYSINFO_REPLY, reply_properties, reply_body, target_dhkey);

	log_msg(LOG_TRACE, ".end  ._in_sysinfo");
	return TRUE;
}

np_bool _np_in_sysinforeply(np_tree_t* properties, np_tree_t* body) {
	log_msg(LOG_TRACE, ".start._in_sysinforeply");

	np_tree_elem_t* source = tree_find_str(properties, _NP_SYSINFO_SOURCE);

	if (NULL == source) {
		log_msg(LOG_WARN,
				"received sysinfo request w/o source key information.");
		return FALSE;
	}
	log_msg(LOG_DEBUG,
			"received sysinfo reply. caching content for key %s (size: %"PRIu16", byte_size: %"PRIu64")",
			source->val.value.s, body->size, body->byte_size);
	//log_msg(LOG_DEBUG, "%s", np_json_to_char(np_tree_to_json(body), TRUE));

	_LOCK_MODULE(np_sysinfo)
	{
		np_simple_cache_insert(_cache, strdup(source->val.value.s),
				np_tree_copy(body));
	}
	log_msg(LOG_TRACE, ".end  ._in_sysinforeply");

	return TRUE;
}

np_tree_t* np_get_my_sysinfo() {
	np_tree_t* ret = make_nptree();

	// build local node
	np_tree_t* local_node = make_nptree();
	_np_node_encode_to_jrb(local_node, _np_state()->my_node_key, FALSE);
	tree_insert_str(ret, _NP_SYSINFO_MY_NODE, new_val_tree(local_node));
	log_msg(LOG_DEBUG, "my sysinfo object has a node");

	// build neighbours list
	np_sll_t(np_key_t, neighbours_table) = NULL;
	_LOCK_MODULE(np_routeglobal_t)
	{
		neighbours_table = route_neighbors();
	}
	np_tree_t* neighbours = make_nptree();
	int neighbour_counter = 0;
	if (NULL != neighbours_table && 0 < neighbours_table->size) {
		np_key_t* current;
		while (NULL != sll_first(neighbours_table)) {
			current = sll_head(np_key_t, neighbours_table);
			if (current->node) {
				np_tree_t* neighbour = make_nptree();
				_np_node_encode_to_jrb(neighbour, current, TRUE);
				tree_insert_int(neighbours, neighbour_counter++,
						new_val_tree(neighbour));
			}
		}
	}
	log_msg(LOG_DEBUG, "my sysinfo object has %d neighbours",
			neighbour_counter);

	tree_insert_str(ret, _NP_SYSINFO_MY_NEIGHBOURS, new_val_tree(neighbours));
	sll_free(np_key_t, neighbours_table);
	np_free_tree(neighbours);

	// build routing list
	np_sll_t(np_key_t, routing_table) = NULL;
	_LOCK_MODULE(np_routeglobal_t)
	{
		routing_table = _np_route_get_table();
	}
	np_tree_t* routes = make_nptree();
	int routes_counter = 0;
	if (NULL != routing_table && 0 < routing_table->size) {
		np_key_t* current;
		while (NULL != sll_first(routing_table)) {
			current = sll_head(np_key_t, routing_table);
			if (current->node) {
				np_tree_t* route = make_nptree();
				_np_node_encode_to_jrb(route, current, TRUE);
				tree_insert_int(routes, routes_counter++, new_val_tree(route));
			}
		}
	}
	log_msg(LOG_DEBUG, "my sysinfo object has %d routing table entries",
			routes_counter);

	tree_insert_str(ret, _NP_SYSINFO_MY_ROUTES, new_val_tree(routes));
	sll_free(np_key_t, routing_table);
	np_free_tree(routes);

	return ret;
}

void _np_request_sysinfo(const char* hash_of_target) {
	if (NULL != hash_of_target) {
		log_msg(LOG_INFO, "sending sysinfo request to %s", hash_of_target);
		np_tree_t* properties = make_nptree();
		np_tree_t* body = make_nptree();

		tree_insert_str(properties, _NP_SYSINFO_SOURCE,
				new_val_s(_key_as_str(_np_state()->my_node_key)));

		tree_insert_str(properties, _NP_SYSINFO_TARGET,
				new_val_s((char*) hash_of_target));

		log_msg(LOG_DEBUG, "Converting %s to dhkey", hash_of_target);
		np_dhkey_t* target_dhkey = malloc(sizeof(np_dhkey_t));

		if(NULL == target_dhkey) {
			log_msg(LOG_ERROR, "Could not allocate memory");
		}

		_str_to_dhkey(hash_of_target, target_dhkey);
		np_send_msg(_NP_SYSINFO_REQUEST, properties, body, target_dhkey);
	} else {
		log_msg(LOG_WARN,
				"could not sending sysinfo request. (unknown target)");
	}
}

np_tree_t* np_get_sysinfo(const char* hash_of_target) {

	char* my_key = _key_as_str(_np_state()->my_node_key);

	np_tree_t* ret = NULL;
	if (strcmp(hash_of_target, my_key) == 0) {
		log_msg(LOG_DEBUG, "Requesting sysinfo for myself");
		// If i request myself i can answer instantly
		ret = np_get_my_sysinfo();
		// I may anticipate the one requesting my information wants to request others as well
		_np_request_others();
	} else {
		log_msg(LOG_DEBUG, "Requesting sysinfo for node %s", hash_of_target);
		_np_request_sysinfo(hash_of_target);
		ret = _np_get_sysinfo_from_cache(hash_of_target);
		//TODO: maybe drop informations if they are too old
	}

	return ret;
}

np_tree_t* _np_get_sysinfo_from_cache(const char* hash_of_target) {
	np_tree_t* ret = NULL;
	_LOCK_MODULE(np_sysinfo)
	{
		np_cache_item_t* item = np_simple_cache_get(_cache, hash_of_target);
		if (NULL != item && item->value != NULL) {
			if ((ev_time() - item->insert_time) < 30.0) {
				np_tree_t* tmp = item->value;
				ret = np_tree_copy(tmp);
			}

		}
	}

	if (NULL == ret) {
		log_msg(LOG_DEBUG, "sysinfo reply data received: no");
	} else {
		log_msg(LOG_DEBUG,
				"sysinfo reply data received: yes (size: %"PRIu16", byte_size: %"PRIu64")",
				ret->size, ret->byte_size);
	}

	return ret;
}

void _np_request_others() {

	np_sll_t(np_key_t, routing_table) = NULL;
	np_sll_t(np_key_t, neighbours_table) = NULL;
	_LOCK_MODULE(np_routeglobal_t)
	{
		routing_table = _np_route_get_table();
		if (NULL != routing_table && 0 < routing_table->size) {
			np_key_t* current;
			while (NULL != sll_first(routing_table)) {
				current = sll_head(np_key_t, routing_table);
				if (	NULL != current &&
						strcmp(_key_as_str(current),_key_as_str(_np_state()->my_node_key) ) != 0 &&
						NULL == _np_get_sysinfo_from_cache(_key_as_str(current)))
				{
					_np_request_sysinfo(_key_as_str(current));
				}
			}
		}

		neighbours_table = route_neighbors();
		if (NULL != neighbours_table && 0 < neighbours_table->size) {
			np_key_t* current;
			while (NULL != sll_first(neighbours_table)) {
				current = sll_head(np_key_t, neighbours_table);
				if (	NULL != current &&
						strcmp(_key_as_str(current),_key_as_str(_np_state()->my_node_key) ) != 0 &&
						NULL == _np_get_sysinfo_from_cache(_key_as_str(current)))
				{
							_np_request_sysinfo(_key_as_str(current));
				}
			}
		}
	}
	sll_free(np_key_t, routing_table);
	sll_free(np_key_t, neighbours_table);
}
