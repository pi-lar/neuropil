/*
 * np_sysinfo.c
 *
 *  Created on: 11.04.2017
 *      Author: sklampt
 */
#include "neuropil.h"
#include "np_log.h"
#include "np_types.h"
#include "np_msgproperty.h"
#include "np_message.h"
#include "np_keycache.h"
#include "np_sysinfo.h"

static char _NP_SYSINFO_REQUEST[] = "_NP.SYSINFO.REQUEST";
static char _NP_SYSINFO_REPLY[] = "_NP.SYSINFO.REPLY";

static const char* _NP_SYSINFO_MY_NODE = "node";
static const char* _NP_SYSINFO_MY_NEIGHBOURS = "neighbour_nodes";
static const char* _NP_SYSINFO_MY_ROUTES = "routing_nodes";

static const char* _NP_SYSINFO_SOURCE = "source_hash";
static const char* _NP_SYSINFO_TARGET = "target_hash";

np_bool _in_sysinfo(np_tree_t* properties, np_tree_t* body) {
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
		log_msg(LOG_WARN, "i am %s not %s . I cannot handle this request",
				mynode_hash, target->val.value.s);
		return FALSE;
	}

	// send a reply

	// build body
	np_tree_t* reply_body = make_nptree();
	np_tree_t* tmp_tree = make_nptree();
	// local node json reply
	_np_node_encode_to_jrb(tmp_tree, _np_state()->my_node_key, FALSE);
	tree_insert_str(reply_body, _NP_SYSINFO_MY_NODE, new_val_tree(tmp_tree));
	np_clear_tree(tmp_tree);

	// build properties
	np_tree_t* reply_properties = make_nptree();
	tree_insert_str(reply_properties, _NP_SYSINFO_SOURCE,
			new_val_s(mynode_hash));
	tree_insert_str(reply_properties, _NP_SYSINFO_TARGET,
			new_val_s(source->val.value.s));

	// send msg
	log_msg(LOG_INFO, "sending sysinfo reply");
	np_send_msg(_NP_SYSINFO_REPLY, reply_properties, reply_body);

	log_msg(LOG_TRACE, ".end  ._in_sysinfo");
	return TRUE;
}

np_bool _in_sysinforeply(np_tree_t* properties, np_tree_t* body) {
	log_msg(LOG_TRACE, ".start._in_sysinforeply");

	np_key_t* sysinfo_key = NULL;

	np_tree_elem_t* source = tree_find_str(properties, _NP_SYSINFO_SOURCE);

	if (NULL == source) {
		log_msg(LOG_WARN,
				"received sysinfo request w/o source key information.");
		return FALSE;
	}

	log_msg(LOG_DEBUG, "received sysinfo reply");

	// for debugging
	JSON_Value* json_obj = json_value_init_object();
	serialize_jrb_to_json(body, json_object(json_obj));

	size_t json_size = json_serialization_size_pretty(json_obj);
	// write to http request body
	char* tmp = (char*) malloc(json_size * sizeof(char));
	json_serialize_to_buffer_pretty(json_obj, tmp, json_size);

	json_value_free(json_obj);

	log_msg(LOG_DEBUG, "SYSINFO:");
	log_msg(LOG_DEBUG, "%s", tmp);

	//TODO: write into a cache

	log_msg(LOG_TRACE, ".end  ._in_sysinforeply");

	return TRUE;
}

void _np_sysinfo_init() {
	np_msgproperty_t* sysinfo_request_props = NULL;
	np_new_obj(np_msgproperty_t, sysinfo_request_props);
	//.mode_type = INBOUND | OUTBOUND | ROUTE, // do we need this?

	//sysinfo_request_props->mep_type = ONE_WAY_WITH_REPLY
	sysinfo_request_props->msg_subject = _NP_SYSINFO_REQUEST;
	sysinfo_request_props->ack_mode = ACK_DESTINATION;
	sysinfo_request_props->ttl = 20.0;
	np_msgproperty_register(sysinfo_request_props);
	np_set_listener(_in_sysinfo, _NP_SYSINFO_REQUEST);

	np_msgproperty_t* sysinfo_response_props = NULL;
	np_new_obj(np_msgproperty_t, sysinfo_response_props);
	//.mode_type = INBOUND | OUTBOUND | ROUTE, // do we need this?
	sysinfo_response_props->msg_subject = _NP_SYSINFO_REPLY;
	sysinfo_response_props->ack_mode = ACK_DESTINATION;
	sysinfo_response_props->ttl = 20.0;
	np_msgproperty_register(sysinfo_response_props);
	np_set_listener(_in_sysinforeply, _NP_SYSINFO_REPLY);
}

np_tree_t* np_get_sysinfo(const char* hash_of_target, int timeout_ms) {
	np_tree_t* ret = NULL;
	np_tree_t* properties = make_nptree();
	np_tree_t* body = make_nptree();
	tree_insert_str(properties, _NP_SYSINFO_SOURCE,
			new_val_s(_key_as_str(_np_state()->my_node_key)));

	tree_insert_str(properties, _NP_SYSINFO_TARGET, new_val_s(hash_of_target));

	log_msg(LOG_INFO, "sending sysinfo request");
	np_send_msg(_NP_SYSINFO_REQUEST, properties, body);
	//TODO: wait for answer and return answer

	return ret;
}
