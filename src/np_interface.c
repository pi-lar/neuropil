//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>

#include <unistd.h>


#include "np_interface.h"

#include "neuropil.h"

#include "np_util.h"

void np_get_id(np_id* id, char* string, size_t length) {
	assert(length >= 64);
	_np_dhkey_from_str(string, (np_dhkey_t*) id);
}

struct np_settings * np_default_settings(struct np_settings ** settings) {
	struct np_settings * ret;
	if (settings == NULL) {
		ret = malloc(sizeof(struct np_settings));
	}
	else {
		ret = *settings;
	}

	ret->n_threads = 9;
	//TODO: init other settings

	return ret;
}

np_context* np_new_context(struct np_settings *settings) {
	enum np_error status = np_ok;
	np_state_t* context= NULL;

	if (settings == NULL) {
		np_default_settings(&settings);
	}
	

	//TODO: check settings for bad configuration

	context= (np_state_t *)calloc(1, sizeof(np_state_t));	
	if (context== NULL)
	{
		debugf("neuropil_init: state module not created: %s", strerror(errno));
		status = np_insufficient_memory;
	}
	else {
		TSP_INITD(context->__is_in_shutdown, FALSE);

		context->settings = settings;
		np_log_init(context, settings->log_file, settings->log_level);

		log_trace_msg(LOG_TRACE, "start: np_state_t* np_init(char* proto, char* port, np_bool start_http, char* hostname){");
		log_debug_msg(LOG_DEBUG, "neuropil_init");

		if (_np_threads_init(context) == FALSE) {
			log_msg(LOG_ERROR, "neuropil_init: could not init threding mutexes");
			status = np_startup;
		}
		else {
			// encryption and memory protection
			if (sodium_init() == -1) {
				log_msg(LOG_ERROR, "neuropil_init: could not init crypto library");
				status = np_startup;
			}
			else {
				// memory pool
				np_mem_init(context);
				//v2
				np_memory_init(context);
				
				np_event_init(context);

				// initialize key min max ranges
				_np_dhkey_init(context);

				context->threads_lock = malloc(sizeof(np_mutex_t));
				_np_threads_mutex_init(context, context->threads_lock, "context->threads_lock ");
				sll_init(np_thread_ptr, context->threads);

				np_thread_t * new_main_thread;
				np_new_obj(np_thread_t, new_main_thread);
				new_main_thread->id = (unsigned long)getpid();
				new_main_thread->thread_type = np_thread_type_main;
				sll_append(np_thread_ptr, context->threads, new_main_thread);
				context->thread_count = 1;

				// splay tree initializing
				_np_keycache_init(context);

				//
				// TODO: read my own identity from file, if a e.g. a password is given
				//
				// set default aaa functions
				context->authorize_func = _np_default_authorizefunc;
				context->authenticate_func = _np_default_authenticatefunc;
				context->accounting_func = _np_default_accountingfunc;

				context->enable_realm_slave = FALSE;
				context->enable_realm_master = FALSE;

				log_debug_msg(LOG_DEBUG, "building node base structure");
				np_node_t* my_node = NULL;
				np_new_obj(np_node_t, my_node);

				np_ref_obj(np_node_t, my_node, ref_key_node);
				np_context_create_new_nodekey(context, my_node);

				np_set_identity_v1(context, context->my_node_key->aaa_token);

				// initialize routing table
				if (FALSE == _np_route_init(context, context->my_node_key))
				{
					log_msg(LOG_ERROR, "neuropil_init: route_init failed: %s", strerror(errno));
					status = np_startup;
				}
				else {
					// initialize job queue
					if (FALSE == _np_job_queue_create(context))
					{
						log_msg(LOG_ERROR, "neuropil_init: _np_job_queue_create failed: %s", strerror(errno));
						status = np_startup;
					}
					else {
						// initialize message handling system
						if (FALSE == _np_msgproperty_init(context))
						{
							log_msg(LOG_ERROR, "neuropil_init: _np_msgproperty_init failed: %s", strerror(errno));
							status = np_startup;
						}
						else {

							context->msg_tokens = np_tree_create();

							context->msg_part_cache = np_tree_create();

							np_unref_obj(np_node_t, my_node, ref_obj_creation);

							_np_shutdown_init_auto_notify_others(context);

							log_msg(LOG_INFO, "neuropil successfully initialized: id:   %s", _np_key_as_str(context->my_identity));
							log_msg(LOG_INFO, "neuropil successfully initialized: node: %s", _np_key_as_str(context->my_node_key));
							_np_log_fflush(context, TRUE);
						}
					}
				}
			}
		}
	}

	return ((np_context*)context);
}

enum np_error np_listen(np_context* ac, char* protocol, char* host, uint16_t port) {
	enum np_error ret = np_ok;
	np_ctx_cast(ac);

	if (context->my_node_key->network != NULL) {
		log_msg(LOG_ERROR, "node listens already on %s", _np_network_as_string(context->my_node_key->network));
		ret = np_invalid_operation;
	}
	else {
		char* np_service;
		uint8_t np_proto = UDP | IPv6;

		asprintf(&np_service, "%"PRIu16, port);

		if (NULL != protocol)
		{
			np_proto = _np_network_parse_protocol_string(protocol);
			log_debug_msg(LOG_DEBUG, "now initializing networking for %s:%s", protocol, np_service);
		}
		else
		{
			log_debug_msg(LOG_DEBUG, "now initializing networking for udp6://%s", np_service);
		}

		log_debug_msg(LOG_DEBUG, "building network base structure");
		np_network_t* my_network = NULL;
		np_new_obj(np_network_t, my_network);

		// get public / local network interface id
		if (NULL == host) {
			host = calloc(1, sizeof(char) * 255);
			CHECK_MALLOC(host);
			log_msg(LOG_INFO, "neuropil_init: resolve hostname");

			if (np_get_local_ip(context, host, 255) == FALSE) {
				if (0 != gethostname(host, 255)) {
					free(host);
					host = strdup("localhost");
				}
			}
		}

		log_debug_msg(LOG_DEBUG, "initialise network");
		_LOCK_MODULE(np_network_t)
		{
			_np_network_init(my_network, TRUE, np_proto, host, np_service);
		}
		log_debug_msg(LOG_DEBUG, "check for initialised network");
		if (FALSE == my_network->initialized)
		{
			log_msg(LOG_ERROR, "neuropil_init: network_init failed, see log for details");
			ret = np_network_error;
		}
		else {
			log_debug_msg(LOG_DEBUG, "update my node data");
			_np_node_update(context->my_node_key->node, np_proto, host, np_service);

			np_ref_obj(np_network_t, my_network, ref_key_network);
			context->my_node_key->network = my_network;
			my_network->watcher.data = context->my_node_key;
			np_ref_obj(np_key_t, context->my_node_key, ref_network_watcher);
		}
		np_unref_obj(np_network_t, my_network, ref_obj_creation);
	}
	return ret;
}

struct np_token *np_new_identity(np_context* ac, double expires_at, uint8_t* (secret_key[NP_SECRET_KEY_BYTES])) {
	np_ctx_cast(ac);	
}

enum np_error np_set_identity(np_context* ac, struct np_token identity) {
	enum np_error ret = np_ok;
	np_ctx_cast(ac);

	return ret;
}

enum np_error np_get_address(np_context* ac, char* address, uint32_t max) {
	enum np_error ret = np_ok;
	np_ctx_cast(ac);

	char* str = np_get_connection_string_from(context->my_node_key, TRUE);
	if (strlen(str) > max) {
		ret = np_invalid_argument;
	}
	else {
		strncpy(address, str, max);
	}
	free(str);

	return ret;
}

enum np_error np_join(np_context* ac, char* address) {
	enum np_error ret = np_not_implemented;
	np_ctx_cast(ac);
	
//	np_send_join(context, address);

	return ret;
}

enum np_error np_send(np_context* ac, np_id* subject, uint8_t* message, size_t length) {
	enum np_error ret = np_ok;
	
	return ret;
}

enum np_error np_add_receive_cb(np_context* ac, np_id* subject, np_receive_callback callback) {
	return np_not_implemented;
}

enum np_error np_set_authenticate_cb(np_context* ac, np_aaa_callback callback) {
	return np_not_implemented;
}

enum np_error np_set_authorize_cb(np_context* ac, np_aaa_callback callback) {
	return np_not_implemented;
}

enum np_error np_run(np_context* ac, double duration) {
	np_ctx_cast(ac);

	_np_start_job_queue(context, context->settings->n_threads);

}

enum np_error np_set_mx_properties(np_context* ac, np_id* subject, struct np_mx_properties properties) {
	return np_not_implemented;
}