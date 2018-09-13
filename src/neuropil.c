//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <inttypes.h>

#include <sodium.h>
#include <unistd.h>

#include "neuropil.h"
#include "np_legacy.h"

#include "np_util.h"
#include "np_key.h"
#include "np_network.h"
#include "np_route.h"
#include "np_event.h"
#include "np_statistics.h"
#include "np_jobqueue.h"
#include "np_threads.h"
#include "np_msgproperty.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "np_shutdown.h"
#include "np_aaatoken.h"
#include "np_message.h"
#include "np_bootstrap.h"
#include "np_keycache.h"
#include "np_types.h"
#include "np_memory.h"
#include "np_log.h"
#include "np_serialization.h"
#include "np_token_factory.h"

// split into hash 
void np_get_id(np_context * ac, np_id* id, char* string, size_t length) {
	np_ctx_cast(ac);
	 
	np_dhkey_t  dhkey = np_dhkey_create_from_hostport(string, "0");
	memcpy(id, &dhkey, NP_FINGERPRINT_BYTES);
}

struct np_settings * np_default_settings(struct np_settings * settings) {
	struct np_settings * ret;
	if (settings == NULL) {
		ret = malloc(sizeof(struct np_settings));
	}
	else {
		ret = settings;
	}	
	ret->n_threads = 3;
	snprintf(ret->log_file, 256, "%.0f_neuropil.log",np_time_now()*100);
	ret->log_level = LOG_ERROR;
	ret->log_level |= LOG_WARN;
#ifdef DEBUG
	ret->log_level |= LOG_INFO;
	ret->log_level |= LOG_DEBUG;
	ret->log_level |= LOG_TRACE;
#endif

	return ret;
}

np_context* np_new_context(struct np_settings * settings_in) {
	enum np_error status = np_ok;
	np_state_t* context= NULL;

	struct np_settings * settings = settings_in;

	if (settings_in == NULL) {
		settings = np_default_settings(NULL);
	}

	//TODO: check settings for bad configuration

	context= (np_state_t *)calloc(1, sizeof(np_state_t));
	CHECK_MALLOC(context);
	if (context == NULL)
	{
		debugf("neuropil_init: state module not created: %s", strerror(errno));
	}
	else {	

		context->settings = settings;

		_np_log_init(context, settings->log_file, settings->log_level);

		if (sodium_init() == -1) {
			log_msg(LOG_ERROR, "neuropil_init: could not init crypto library");
			status = np_startup;
		}else if (_np_threads_init(context) == false) {
			log_msg(LOG_ERROR, "neuropil_init: could not init threding mutexes");
			status = np_startup;
		}
		else  if (_np_statistics_init(context) == false) {
			log_msg(LOG_ERROR, "neuropil_init: could not init statistics");
			status = np_startup;
		}
		else if (_np_memory_init(context) == false) {
			log_msg(LOG_ERROR, "neuropil_init: could not init memory");
			status = np_startup;
		}
		else if (_np_msgproperty_init(context) == false)
		{
			log_msg(LOG_ERROR, "neuropil_init: _np_msgproperty_init failed");
			status = np_startup;
		}
		else if (_np_event_init(context) == false)
		{
			log_msg(LOG_ERROR, "neuropil_init: could not init event system");
			status = np_startup;
		}
		else if (_np_dhkey_init(context) == false)
		{
			log_msg(LOG_ERROR, "neuropil_init: could not init distributed hash table");
			status = np_startup;
		}
		else if (_np_keycache_init(context) == false)
		{
			log_msg(LOG_ERROR, "neuropil_init: could not init keycache");
			status = np_startup;
		}
		else {

			np_thread_t * new_thread =
				__np_createThread(context, 0, NULL, false, np_thread_type_main);
			new_thread->id = (unsigned long) getpid();

			// set default aaa functions
			np_set_authorize_cb(context, _np_default_authorizefunc);
			np_set_authenticate_cb(context, _np_default_authenticatefunc);
			np_set_accounting_cb(context, _np_default_accountingfunc);

			context->enable_realm_client = false;
			context->enable_realm_server = false;
		}
	}
	TSP_INITD(context->status, np_uninitialized);
	if(status == np_ok){
		TSP_SET(context->status, np_stopped);
	}
	else  if (context->status != np_error) {
		TSP_SET(context->status, np_error);
	}
	return ((np_context*)context);
}

enum np_error np_listen(np_context* ac, char* protocol, char* host, uint16_t port) {
	enum np_error ret = np_ok;
	np_ctx_cast(ac);

	if (context->my_node_key != NULL && context->my_node_key->network != NULL) {
		log_msg(LOG_ERROR, "node listens already and cannot get a second listener");
		ret = np_invalid_operation;
	}
	else {
		char* np_service;
		enum socket_type np_proto = UDP | IPv6;

		asprintf(&np_service, "%"PRIu16, port);

		if (NULL != protocol)
		{
			np_proto = _np_network_parse_protocol_string(protocol);
			if (np_proto == UNKNOWN_PROTO) {
				ret = np_invalid_argument;
			}
			else {
				log_debug_msg(LOG_DEBUG, "now initializing networking for %s:%s", protocol, np_service);
			}
		}
		else
		{
			log_debug_msg(LOG_DEBUG, "now initializing networking for udp6://%s", np_service);
		}

		if (ret == np_ok) {
			log_debug_msg(LOG_DEBUG, "building network base structure");
			np_network_t* my_network = NULL;
			np_new_obj(np_network_t, my_network);
			// get public / local network interface id
			char ng_host[255];
			if (NULL == host) {		
				log_msg(LOG_INFO, "neuropil_init: resolve hostname");
				if (np_get_local_ip(context, ng_host, 255) == false) {
					if (0 != gethostname(ng_host, 255)) {
						strncpy(ng_host,"localhost",255);
					}
				}
			}
			else {
				strncpy(ng_host, host, 255);
			}
			log_debug_msg(LOG_DEBUG, "initialise network (type:%d/%s/%s)", np_proto, _np_network_get_protocol_string(context, np_proto), protocol);
			_LOCK_MODULE(np_network_t)
			{
				_np_network_init(my_network, true, np_proto, ng_host, np_service, -1, UNKNOWN_PROTO);
			}
		
			log_debug_msg(LOG_DEBUG, "check for initialised network");
			if (false == my_network->initialized)
			{
				log_msg(LOG_ERROR, "neuropil_init: network_init failed, see log for details");
				ret = np_network_error;
			}
			else {

				log_debug_msg(LOG_DEBUG, "building node base structure");
				np_node_t* my_node = NULL;
				np_new_obj(np_node_t, my_node, ref_key_node);
				_np_node_update(my_node, np_proto, ng_host, np_service);
				_np_context_create_new_nodekey(context, my_node);
				if (context->my_identity == NULL)
					_np_set_identity(context, context->my_node_key->aaa_token);

				np_ref_obj(np_network_t, my_network, ref_key_network);
				context->my_node_key->network = my_network;
				
				_np_network_set_key(my_network, context->my_node_key);

				// initialize routing table
				if (false == _np_route_init(context, context->my_node_key))
				{
					log_msg(LOG_ERROR, "neuropil_init: route_init failed: %s", strerror(errno));
					ret = np_startup;
				}
				else {
					// initialize job queue
					if (false == _np_jobqueue_create(context))
					{
						log_msg(LOG_ERROR, "neuropil_init: _np_jobqueue_create failed: %s", strerror(errno));
						ret = np_startup;
					}
					else if (false == _np_bootstrap_init(context))
					{
						log_msg(LOG_ERROR, "neuropil_init: _np_bootstrap_init failed: %s", strerror(errno));
						ret = np_startup;
					}					
					// initialize message handling system
					else {

						context->msg_tokens = np_tree_create();

						context->msg_part_cache = np_tree_create();

						_np_shutdown_init_auto_notify_others(context);

						log_debug_msg(LOG_DEBUG | LOG_NETWORK, "Network %s is the main receiving network", np_memory_get_id(my_network));
						_np_network_enable(my_network);

						np_threads_start_workers(context, context->settings->n_threads);

						log_msg(LOG_INFO, "neuropil successfully initialized: id:   %s", _np_key_as_str(context->my_identity));
						log_msg(LOG_INFO, "neuropil successfully initialized: node: %s", _np_key_as_str(context->my_node_key));
						_np_log_fflush(context, true);
					}

				}
			}
			np_unref_obj(np_network_t, my_network, ref_obj_creation);
		}

		if (ret == np_ok) {
			TSP_SET(context->status, np_running);
		}
		else {
			TSP_SET(context->status, np_error);
		}
	}

	return ret;
}

// secret_key is nullable
struct np_token np_new_identity(np_context* ac, double expires_at, uint8_t* (secret_key[NP_SECRET_KEY_BYTES])) {
	np_ctx_cast(ac); 
	
	struct np_token ret = {0};	
	np_ident_private_token_t* new_token =  np_token_factory_new_identity_token(context, expires_at, secret_key);
	np_aaatoken4user(&ret, new_token);
	np_unref_obj(np_aaatoken_t, new_token, "np_token_factory_new_identity_token");

	return ret;
}

enum np_error np_use_identity(np_context* ac, struct np_token identity) {
	np_ctx_cast(ac); 
	
	enum np_error ret = np_ok;	
	np_ident_private_token_t* imported_token=NULL;
	np_new_obj(np_aaatoken_t, imported_token);
	np_user4aaatoken(imported_token, &identity);
	_np_aaatoken_update_type_and_scope(imported_token);	
	_np_set_identity(ac, imported_token);
	np_unref_obj(np_aaatoken_t, imported_token, ref_obj_creation);

	return ret;
}

enum np_error np_get_address(np_context* ac, char* address, uint32_t max) {
	enum np_error ret = np_ok;
	np_ctx_cast(ac);

	char* str = np_get_connection_string_from(context->my_node_key, true);
	if (strlen(str) > max) {
		ret = np_invalid_argument;
	}
	else {
		strncpy(address, str, max);
	}
	free(str);

	return ret;
}

bool np_has_joined(np_context* ac) {
	assert(ac != NULL);
	bool ret = false;
	np_ctx_cast(ac);

	if (_np_route_my_key_has_connection(context) && context->my_node_key != NULL && context->my_node_key->node != NULL) {
		ret = context->my_node_key->node->joined_network;
	}

	return ret;
}

bool np_has_receiver_for(np_context*ac, char * subject) {
	assert(ac != NULL);
	assert(subject != NULL);
	np_ctx_cast(ac);
	bool ret = false;
	if (_np_route_my_key_has_connection(context)) {
		np_aaatoken_t * token = _np_aaatoken_get_receiver(context, subject, NULL);

		if (token != NULL) {
			ret = true;
		}
		np_unref_obj(np_aaatoken_t, token, "_np_aaatoken_get_receiver");
	}
	return ret;
}

enum np_error np_join(np_context* ac, char* address) {
	enum np_error ret = np_ok;
	np_ctx_cast(ac);

	np_send_join(context, address);
	return ret;
}

enum np_error np_send(np_context* ac, char* subject, uint8_t* message, size_t length) {
	return np_send_to(ac, subject, message, length, NULL);
}

enum np_error np_send_to(np_context* ac, char* subject, uint8_t* message, size_t  length, np_id * target) {
	enum np_error ret = np_ok;
	np_ctx_cast(ac);

	np_tree_t* body = np_tree_create();
	np_tree_insert_str(body, NP_SERIALISATION_USERDATA, np_treeval_new_bin(message, length));
	np_send_msg(context, subject, body, (np_dhkey_t*)target);
	return ret;
}

bool __np_receive_callback_converter(np_context* ac, const np_message_t* const msg, np_tree_t* body, void* localdata) {
	np_ctx_cast(ac);
	bool ret = true;
	np_receive_callback callback = localdata;
	np_tree_elem_t*  userdata = np_tree_find_str(body, NP_SERIALISATION_USERDATA);

	if (userdata != NULL) {
		struct np_message message = { 0 };
		strncpy(message.uuid, msg->uuid, NP_UUID_BYTES-1);
		np_get_id(context, &message.subject, msg->msg_property->msg_subject, strlen(msg->msg_property->msg_subject));
		
		memcpy(&message.from, _np_message_get_sender(msg), NP_FINGERPRINT_BYTES);

		message.received_at = np_time_now(); // todo get from network
		//message.send_at = msg.             // todo get from msg
		message.data = userdata->val.value.bin;
		message.data_length = userdata->val.size;

		callback(context, &message);
	}
	return ret;
}

enum np_error np_add_receive_cb(np_context* ac, char* subject, np_receive_callback callback) {
	enum np_error ret = np_ok;

	np_add_receive_listener(ac, __np_receive_callback_converter, callback, subject);
	return ret;
}

enum np_error np_set_authenticate_cb(np_context* ac, np_aaa_callback callback) {
	enum np_error ret = np_ok;
	np_ctx_cast(ac);

	context->authenticate_func = callback;

	return ret;
}
enum np_error np_set_authorize_cb(np_context* ac, np_aaa_callback callback) {
	enum np_error ret = np_ok;
	np_ctx_cast(ac);

	context->authorize_func = callback;

	return ret;
}
enum np_error np_set_accounting_cb(np_context* ac, np_aaa_callback callback) {
	enum np_error ret = np_ok;
	np_ctx_cast(ac);

	context->accounting_func = callback;

	return ret;
}

struct np_mx_properties np_get_mx_properties(np_context* ac, char* subject) {
	np_ctx_cast(ac);
	struct np_mx_properties ret = { 0 };
	bool exisits = false;
	np_msgproperty_t* property = np_msgproperty_get(context, DEFAULT_MODE, subject);
	if (property == NULL)
	{
		np_new_obj(np_msgproperty_t, property, FUNC);
		property->msg_subject = strndup(subject, 255);
		exisits = false;
	}
	else {
		exisits = true;
	}

	np_msgproperty4user(&ret, property);

	if (exisits == false) {
		np_unref_obj(np_msgproperty_t, property, FUNC);             																									\
	}
	
	return ret;
}
enum np_error np_set_mx_properties(np_context* ac, char* subject, struct np_mx_properties user_property) {
	np_ctx_cast(ac);
	enum np_error ret = np_ok;

	// todo: validate user_property
	np_msgproperty_t* property = np_msgproperty_get(context, DEFAULT_MODE, subject);
	if (property == NULL)
	{
		np_new_obj(np_msgproperty_t, property);
		property->msg_subject = strndup(subject, 255);
		np_msgproperty_register(property);
	}
	np_msgproperty_from_user(property, &user_property);

	return ret;
}

enum np_error np_run(np_context* ac, double duration) {
	np_ctx_cast(ac);
	enum np_error ret = np_ok;

	if (duration <= 0) {
		__np_jobqueue_run_jobs_once(context);
	}
	else {
		np_jobqueue_run_jobs_for(context, duration);
	}

	return ret;
}

void np_set_userdata(np_context *ac, void* userdata) {
	np_ctx_cast(ac);
	context->userdata = userdata;
}

void* np_get_userdata(np_context *ac) {
	np_ctx_cast(ac);
	return context->userdata;
}

enum np_status np_get_status(np_context* ac) {
	np_ctx_cast(ac);
	TSP_GET(enum np_status, context->status, ret);
	return ret;
}


void np_id2str(const np_id* id, char* key_string)
{
	np_dhkey_t* k = (np_dhkey_t*)id;
	// TODO: use sodium bin2hex function
	snprintf(key_string, 65,
		"%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32,
		k->t[0], k->t[1], k->t[2], k->t[3], k->t[4], k->t[5], k->t[6], k->t[7]
	);
	key_string[64] = '\0';
}

void np_str2id(const char* key_string, np_id* id)
{
	np_dhkey_t* k = (np_dhkey_t*)id;
	// TODO: this is dangerous, encoding could be different between systems,
	// encoding has to be send over the wire to be sure ...
	// for now: all tests on the same system
	// assert (64 == strlen((char*) key_string));

	char substring[9];
	substring[8] = '\0';
	for (uint8_t i = 0; i < 8; i++)
	{
		memcpy(substring, key_string + i * 8, 8);
		k->t[i] = strtoul((const char*)substring, NULL, 16);
	}
	/*
	log_debug_msg(LOG_KEY | LOG_DEBUG,
	"key %08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32,
	k->t[0], k->t[1], k->t[2], k->t[3], k->t[4], k->t[5], k->t[6], k->t[7]
	);
	*/
}
