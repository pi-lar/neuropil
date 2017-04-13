/*
 * np_sysinfo.c
 *
 *  Created on: 11.04.2017
 *      Author: sklampt
 */

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
#include "inttypes.h"

#include "np_sysinfo.h"

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

void _np_sysinfo_init() {

	_cache = (np_simple_cache_table_t*) malloc(sizeof(np_simple_cache_table_t));

	struct np_simple_cache_table_t cache = { { 0 }, NULL, NULL };
	_cache = &cache;

	np_msgproperty_t* sysinfo_request_props = NULL;
	np_new_obj(np_msgproperty_t, sysinfo_request_props);
	//.mode_type = INBOUND | OUTBOUND | ROUTE, // do we need this?
	//sysinfo_request_props->mep_type = ONE_WAY_WITH_REPLY
	sysinfo_request_props->msg_subject = _NP_SYSINFO_REQUEST;
	sysinfo_request_props->ack_mode = ACK_DESTINATION;
	sysinfo_request_props->ttl = 20.0;
	np_msgproperty_register(sysinfo_request_props);
	np_set_listener(_np_in_sysinfo, _NP_SYSINFO_REQUEST);

	np_msgproperty_t* sysinfo_response_props = NULL;
	np_new_obj(np_msgproperty_t, sysinfo_response_props);
	//.mode_type = INBOUND | OUTBOUND | ROUTE, // do we need this?
	sysinfo_response_props->msg_subject = _NP_SYSINFO_REPLY;
	sysinfo_response_props->ack_mode = ACK_DESTINATION;
	sysinfo_response_props->ttl = 20.0;
	np_msgproperty_register(sysinfo_response_props);
	np_set_listener(_np_in_sysinforeply, _NP_SYSINFO_REPLY);
}

np_bool _np_in_sysinfo(np_tree_t* properties, np_tree_t* body) {
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
	np_send_msg(_NP_SYSINFO_REPLY, reply_properties, reply_body);

	log_msg(LOG_TRACE, ".end  ._in_sysinfo");
	return TRUE;
}

np_bool _np_in_sysinforeply(np_tree_t* properties, np_tree_t* body) {
	log_msg(LOG_TRACE, ".start._in_sysinforeply");

	np_key_t* sysinfo_key = NULL;

	np_tree_elem_t* source = tree_find_str(properties, _NP_SYSINFO_SOURCE);

	if (NULL == source) {
		log_msg(LOG_WARN,
				"received sysinfo request w/o source key information.");
		return FALSE;
	}
	log_msg(LOG_DEBUG,
			"received sysinfo reply. caching content for key %s (size: %"PRIu16", byte_size: %"PRIu64")",
			source->val.value.s, body->size, body->byte_size);
	log_msg(LOG_DEBUG, "%s", np_json_to_char(np_tree_to_json(body),TRUE));

	_LOCK_MODULE(np_sysinfo) {
		np_simple_cache_insert(&_cache, strdup(source->val.value.s), np_tree_copy(body));
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
	sll_free(np_key_t, neighbours_table);
	tree_insert_str(ret, _NP_SYSINFO_MY_NEIGHBOURS, new_val_tree(neighbours));

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
	sll_free(np_key_t, routing_table);
	tree_insert_str(ret, _NP_SYSINFO_MY_ROUTES, new_val_tree(routes));

	log_msg(LOG_DEBUG, "my sysinfo object at build:");
	log_msg(LOG_DEBUG, "%s", np_json_to_char(np_tree_to_json(ret), TRUE));
	return ret;
}

np_tree_t* np_get_sysinfo(const char* dhkey_of_target, int timeout) {
	np_tree_t* ret = NULL;
	np_tree_t* properties = make_nptree();
	np_tree_t* body = make_nptree();
	tree_insert_str(properties, _NP_SYSINFO_SOURCE,
			new_val_s(_key_as_str(_np_state()->my_node_key)));

	tree_insert_str(properties, _NP_SYSINFO_TARGET, new_val_s(dhkey_of_target));

	log_msg(LOG_DEBUG, "sending sysinfo request to %s", dhkey_of_target);
	np_send_msg(_NP_SYSINFO_REQUEST, properties, body);

	while (timeout > 0 && NULL == ret) {
		ev_sleep(0.1);
		_LOCK_MODULE(np_sysinfo) {
			ret = np_simple_cache_get(&_cache, dhkey_of_target);
		}
		timeout--;
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
