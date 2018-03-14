//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "inttypes.h"

#include "sys/socket.h"
#include "np_http.h"

#include "json/parson.h"
#include "http/htparse.h"
#include "http/htparse.c"

#include "np_log.h"
#include "np_memory.h"
#include "np_memory_v2.h"
#include "neuropil.h"
#include "np_glia.h"
#include "np_tree.h"
#include "np_jobqueue.h"
#include "np_network.h"
#include "np_node.h"
#include "np_route.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_dhkey.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_treeval.h"
#include "np_sysinfo.h"
#include "np_event.h"
#include "np_list.h"



JSON_Value* _np_generate_error_json(const char* error,const char* details);
JSON_Value* _np_generate_error_json(const char* error,const char* details) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: JSON_Value* _np_generate_error_json(const char* error,const char* details) {");
	JSON_Value* ret = json_value_init_object();

	json_object_set_string(json_object(ret), "error", error);
	json_object_set_string(json_object(ret), "details", details);

	return ret;
}

// static pthread_mutex_t __http_mutex = PTHREAD_MUTEX_INITIALIZER;

// static char* HTML_DEFAULT_PAGE    = "<html><head><title>neuropil</title></head><body></body></html>";
static char* HTML_NOT_IMPLEMENTED =
		"<html><head><title>neuropil</title></head><body>not implemented</body></html>";

#define HTTP_CRLF "\r\n"

typedef enum np_http_status_e {
	UNUSED = 0, ACCEPTED, CONNECTED, REQUEST, PROCESSING, RESPONSE, SHUTDOWN
} np_http_status_e;


struct np_http_client_s {
	int client_fd;
	struct ev_io client_watcher_in;
	struct ev_io client_watcher_out;

	// http parser and callbacks
	htparser* parser;
	// http request structure
	ht_request_t ht_request;
	// http response structure
	ht_response_t ht_response;
	// global status and last update time
	np_http_status_e status;
};
typedef struct np_http_client_s np_http_client_t;
typedef np_http_client_t* np_http_client_ptr;

NP_SLL_GENERATE_PROTOTYPES(np_http_client_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_http_client_ptr);

typedef struct np_http_s np_http_t;
struct np_http_s {
	// memory management
	np_obj_t* obj;

	// network io handling
	np_network_t* network;

	np_sll_t(np_http_client_ptr, clients);

	htparse_hooks* hooks;
	np_tree_t* user_hooks;

};

static np_http_t* __local_http;

typedef struct http_return_t {
	const char* text;
	int http_code;
} http_return_t;
http_return_t http_return_codes[] = {
		{ "HTTP_NO_RESPONSE", 					  0 },
		{ "HTTP_CODE_CONTINUE", 				100 },
		{ "HTTP_CODE_OK", 						200 },
		{ "HTTP_CODE_CREATED", 					201 },
		{ "HTTP_CODE_NO_Accepted", 				202 },
		{ "HTTP_CODE_NO_CONTENT", 				204 },
		{ "HTTP_CODE_PARTIAL_CONTENT", 			206 },
		{ "HTTP_CODE_MULTI_STATUS", 			207 },
		{ "HTTP_CODE_MOVED_TEMPORARILY", 		302 },
		{ "HTTP_CODE_NOT_MODIFIED", 			304 },
		{ "HTTP_CODE_BAD_REQUEST", 				400 },
		{ "HTTP_CODE_UNAUTHORIZED", 			401 },
		{ "HTTP_CODE_FORBIDDEN", 				403 },
		{ "HTTP_CODE_NOT_FOUND", 				404 },
		{ "HTTP_CODE_METHOD_NOT_ALLOWED", 		405 },
		{ "HTTP_CODE_REQUEST_TIME_OUT", 		408 },
		{ "HTTP_CODE_GONE", 					410 },
		{ "HTTP_CODE_REQUEST_URI_TOO_LONG", 	414 },
		{ "HTTP_CODE_LOCKED", 					423 },
		{ "HTTP_CODE_INTERNAL_SERVER_ERROR", 	500 },
		{ "HTTP_CODE_NOT_IMPLEMENTED", 			501 },
		{ "HTTP_CODE_SERVICE_UNAVAILABLE", 		503 }
};

typedef struct _np_http_callback_s {
	_np_http_callback_func_t callback;
	void* user_arg;
} _np_http_callback_t;


void _np_http_handle_sysinfo(np_http_client_t* client);


void _np_add_http_callback(const char* path, htp_method method, void* user_args,
		_np_http_callback_func_t func) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: void _np_add_http_callback(const char* path, htp_method method, void* user_args,		_np_http_callback_func_t func) {");
	if (NULL == __local_http->user_hooks)
		__local_http->user_hooks = np_tree_create();

	char key[32];
	snprintf(key, 31, "%d:%s", method, path);

	_np_http_callback_t* callback_data = malloc(sizeof(_np_http_callback_t));
	CHECK_MALLOC(callback_data);

	callback_data->user_arg = user_args;
	callback_data->callback = func;
	np_tree_insert_str(__local_http->user_hooks, key, np_treeval_new_v(callback_data));
}

void _np_rem_http_callback(const char* path, htp_method method) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: void _np_rem_http_callback(const char* path, htp_method method) {");
	if (NULL == __local_http->user_hooks)
		__local_http->user_hooks = np_tree_create();

	char key[32];
	snprintf(key, 31, "%d:%s", method, path);
	np_tree_elem_t* callback_val = np_tree_find_str(__local_http->user_hooks, key);
	if (NULL != callback_val) {
		_np_http_callback_t* callback_data =
				(_np_http_callback_t*) callback_val->val.value.v;
		np_tree_del_str(__local_http->user_hooks, key);
		free(callback_data);
	}
}

int _np_http_on_msg_begin(htparser* parser) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: int _np_http_on_msg_begin(NP_UNUSED htparser* parser) {");
	// pthread_mutex_lock(__http_mutex);
	np_http_client_t* client = (np_http_client_t*) parser->userdata;
	client->status = REQUEST;

	return 0;
}

int _np_http_query_args(htparser * parser, const char * data,
		size_t in_len) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: int _np_http_query_args(NP_UNUSED htparser * parser, const char * data,		size_t in_len) {");
	char* key = NULL;
	char* val = NULL;

	np_http_client_t* client = (np_http_client_t*) parser->userdata;

	if (NULL != client->ht_request.ht_query_args)
		np_tree_clear(client->ht_request.ht_query_args);
	if (NULL == client->ht_request.ht_query_args)
		client->ht_request.ht_query_args = np_tree_create();

	char* query_string = strndup(data, in_len);
	char* kv_pair = strtok(query_string, "&=");

	while (NULL != kv_pair) {
		if (NULL == key) {
			key = strndup(kv_pair, strlen(kv_pair));
		} else {
			val = strndup(kv_pair, strlen(kv_pair));
			np_tree_insert_str(client->ht_request.ht_query_args, key,
					np_treeval_new_s(val));
			free(key);
			free(val);
			key = NULL;
			val = NULL;
		}
		kv_pair = strtok(NULL, "&=");
	}
	free(query_string);
	return 0;
}

int _np_http_on_hdrs_begin(htparser* parser) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: int _np_http_on_hdrs_begin(NP_UNUSED htparser* parser) {");
	np_http_client_t* client = (np_http_client_t*) parser->userdata;

	if (NULL != client->ht_request.ht_header)
		np_tree_clear(client->ht_request.ht_header);
	if (NULL == client->ht_request.ht_header)
		client->ht_request.ht_header = np_tree_create();
	return 0;
}

int _np_http_hdr_key(htparser * parser, const char * data,
		size_t in_len) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: int _np_http_hdr_key(NP_UNUSED htparser * parser, const char * data,		size_t in_len) {");
	np_http_client_t* client = (np_http_client_t*) parser->userdata;

	if (NULL != client->ht_request.current_key)
		free(client->ht_request.current_key);
	client->ht_request.current_key = strndup(data, in_len);
	return 0;
}

int _np_http_hdr_value(htparser * parser, const char * data,
NP_UNUSED size_t in_len) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: int _np_http_hdr_value(NP_UNUSED htparser * parser, const char * data,NP_UNUSED size_t in_len) {");
	np_http_client_t* client = (np_http_client_t*) parser->userdata;

	np_tree_insert_str(client->ht_request.ht_header,
			client->ht_request.current_key, np_treeval_new_s((char*) data));

	free(client->ht_request.current_key);
	client->ht_request.current_key = NULL;

	return 0;
}

int _np_http_path( htparser * parser, const char * data, size_t in_len) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: int _np_http_path(NP_UNUSED htparser * parser, const char * data, size_t in_len) {");
	np_http_client_t* client = (np_http_client_t*) parser->userdata;
	if (NULL != client->ht_request.ht_path)
		free(client->ht_request.ht_path);

	client->ht_request.ht_path = strndup(data, in_len);

	return 0;
}

int _np_http_body(htparser * parser, const char * data, size_t in_len) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: int _np_http_body(NP_UNUSED htparser * parser, const char * data, size_t in_len) {");
	np_http_client_t* client = (np_http_client_t*) parser->userdata;

	if (NULL != client->ht_request.ht_body)
		free(client->ht_request.ht_body);
	client->ht_request.ht_body = strndup(data, in_len);

	return 0;
}

int _np_http_on_msg_complete(htparser* parser) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: int _np_http_on_msg_complete(NP_UNUSED htparser* parser) {");
	np_http_client_t* client = (np_http_client_t*) parser->userdata;
	client->ht_request.ht_method = htparser_get_method(parser);
	client->ht_request.ht_length = htparser_get_content_length(parser);

	client->status = PROCESSING;

	return 0;
}

void _np_http_dispatch( np_http_client_t* client) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: void _np_http_dispatch(NP_UNUSED np_jobargs_t* args) {");

	assert(PROCESSING == client->status);

	if (NULL == __local_http->user_hooks)
		__local_http->user_hooks = np_tree_create();

	char key[32];
	snprintf(key, 31, "%d:%s", client->ht_request.ht_method,
			client->ht_request.ht_path);

	np_tree_elem_t* user_callback = np_tree_find_str(__local_http->user_hooks,
			key);

	if (NULL != user_callback) {
		_np_http_callback_t* callback_data =
				(_np_http_callback_t*) user_callback->val.value.v;
		client->ht_response.ht_status = callback_data->callback(
				&client->ht_request, &client->ht_response,
				callback_data->user_arg);
		client->ht_response.cleanup_body = TRUE;
		client->status = RESPONSE;
	} else {
		switch (client->ht_request.ht_method) {
		case (htp_method_GET): {

			_np_http_handle_sysinfo(client);
			break;
		}

		default:
			client->ht_response.ht_body = HTML_NOT_IMPLEMENTED;
			client->ht_response.ht_header = np_tree_create();
			client->ht_response.ht_status = HTTP_CODE_NOT_IMPLEMENTED;
			client->ht_response.cleanup_body = FALSE;
			client->status = RESPONSE;
		}
	}
}

void _np_http_handle_sysinfo(np_http_client_t* client)
{
	log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Requesting sysinfo");

	char target_hash[65];

	np_bool usedefault = TRUE;
	int http_status = HTTP_CODE_OK;
	char* response;
	JSON_Value* json_obj;
	np_key_t*  key = NULL;

	/**
	* Default behavior if no argument is given: display own node informations
	*/
	log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "parse arguments of %s",
		client->ht_request.ht_path);


	if (NULL != client->ht_request.ht_path) {
		log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "request has arguments");

		char* path = strdup(client->ht_request.ht_path);
		char* tmp_target_hash = strtok(path, "/");

		if (NULL != tmp_target_hash) {
			if (strlen(tmp_target_hash) == 64) {
				snprintf(target_hash, 65, "%s", tmp_target_hash);
				usedefault = FALSE;
			}
			else {
				http_status = HTTP_CODE_BAD_REQUEST;
				json_obj = _np_generate_error_json(
					"provided key invalid.",
					"length is not 64 characters");
				free(path);
				goto __json_return__;
			}
		}
		free(path);

	}
	else {
		log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "no arguments provided");
	}

	key = np_state()->my_node_key;
	np_tryref_obj(np_key_t, key, keyExists);
	if (keyExists) {
		char* my_key = _np_key_as_str(key);
		np_tree_t* sysinfo = NULL;
		if (usedefault) {
			log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "using own node as info system");
			sprintf(target_hash, "%s", my_key);

			sysinfo = np_sysinfo_get_all();
		}
		else {

			sysinfo = np_sysinfo_get_info(target_hash);
		}
		if (NULL == sysinfo) {
			log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Could not find system informations");
			http_status = HTTP_CODE_ACCEPTED;
			json_obj = _np_generate_error_json("key not found.",
				"update request is send. please wait.");
		}
		else {
			log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo response tree (byte_size: %"PRIu32,
				sysinfo->byte_size);
			log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo response tree (size: %"PRIu16,
				sysinfo->size);

			log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Convert sysinfo to json");
			json_obj = np_tree2json(sysinfo);
			log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "cleanup");
		}
		np_tree_free(sysinfo);

		np_unref_obj(np_key_t, key, __func__);
	}
	else {
		http_status = HTTP_CODE_SERVICE_UNAVAILABLE;
		json_obj = _np_generate_error_json("refreshing own key",
			"Refreshing own key. please wait.");
	}
__json_return__:

	log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "serialise json response");
	if (NULL == json_obj) {
		log_msg(LOG_ERROR,
			"HTTP return is not defined for this code path");
		http_status = HTTP_CODE_INTERNAL_SERVER_ERROR;
		json_obj = _np_generate_error_json("Unknown Error",
			"no response defined");
	}
	response = np_json2char(json_obj, TRUE);
	log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo response should be (strlen: %lu):",
		strlen(response));
	json_value_free(json_obj);

	log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "write to body");
	client->ht_response.ht_status = http_status;
	client->ht_response.ht_body = response; //strdup(response);;

	client->ht_response.ht_header = np_tree_create();
	np_tree_insert_str(client->ht_response.ht_header, "Content-Type",
		np_treeval_new_s("application/json"));
	np_tree_insert_str(client->ht_response.ht_header,
		"Access-Control-Allow-Origin", np_treeval_new_s("*"));
	np_tree_insert_str(client->ht_response.ht_header,
		"Access-Control-Allow-Methods", np_treeval_new_s("GET"));
	client->ht_response.cleanup_body = TRUE;
	client->status = RESPONSE;

}

void _np_http_write_callback(NP_UNUSED struct ev_loop* loop,
NP_UNUSED ev_io* ev, int event_type) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: void _np_http_write_callback(NP_UNUSED struct ev_loop* loop,NP_UNUSED ev_io* ev, int event_type) {");

	np_http_client_t* client = (np_http_client_t*) ev->data;

	if (((event_type & EV_WRITE) == EV_WRITE && (event_type &  EV_ERROR) != EV_ERROR) && RESPONSE == client->status) {
		log_debug_msg(LOG_HTTP | LOG_DEBUG, "start writing response");
		// create http reply
		char data[2048];

		char * ht_body = client->ht_response.ht_body;
		// HTTP start
		int pos =
				sprintf(data, "%s %d %s" HTTP_CRLF, "HTTP/1.1",
						http_return_codes[client->ht_response.ht_status].http_code,
						http_return_codes[client->ht_response.ht_status].text);

		// add content length header
		uint32_t s_contentlength = strlen(ht_body);
		char body_length[255];
		snprintf(body_length, 254, "%"PRIu32, s_contentlength);
		np_tree_insert_str(client->ht_response.ht_header, "Content-Length",
				np_treeval_new_s(body_length));
		np_tree_insert_str(client->ht_response.ht_header, "Content-Type",
				np_treeval_new_s("application/json"));
		// add keep alive header
		np_tree_insert_str(client->ht_response.ht_header, "Connection",
				np_treeval_new_s(
						htparser_should_keep_alive(client->parser) ?
								"Keep-Alive" : "close"));

		// HTTP header
		np_tree_elem_t* iter = RB_MIN(np_tree_s,
				client->ht_response.ht_header);
		while (NULL != iter) {
			pos += snprintf(data + pos,
					snprintf(NULL, 0, "%s: %s" HTTP_CRLF,  np_treeval_to_str(iter->key, NULL),
							 np_treeval_to_str(iter->val, NULL)) + 1, "%s: %s" HTTP_CRLF,
					 np_treeval_to_str(iter->key, NULL),  np_treeval_to_str(iter->val, NULL));
			iter = RB_NEXT(np_tree_s, __local_http->ht_response.ht_header,
					iter);
		}
		pos += snprintf(data + pos, snprintf(NULL, 0, "" HTTP_CRLF) + 1,
				"" HTTP_CRLF);
		// send header
		send(client->client_fd, data, pos, 0);
		np_tree_free(client->ht_response.ht_header);

		log_debug_msg(LOG_HTTP | LOG_DEBUG, "send http header success");

		// HTTP body
		//memset(data, 0, 2048);

		uint32_t bytes_send = 0;
		double t1 = np_time_now();
		int retry = 0;
		while (bytes_send < s_contentlength)
		{
			if ((np_time_now() - t1) >= 30) {
				log_debug_msg(LOG_HTTP | LOG_DEBUG, "http timeout");
				break;
			}
			else if (retry > 3) {
				log_debug_msg(LOG_HTTP | LOG_DEBUG, "http too many errors");
				break;
			}

			int send_return = send(client->client_fd,
				ht_body + bytes_send,
				min(2048, s_contentlength - bytes_send),
				0
			);
			if (send_return >= 0) {
				bytes_send += send_return;
				log_debug_msg(LOG_HTTP | LOG_DEBUG, "send http body part success");
			}
			else {
				// we may need to wait for the output buffer to be free
				if(EAGAIN != errno){
					log_msg(LOG_HTTP | LOG_WARN, "Sending http data error. %s", strerror(errno));
					retry++;				
				}
			}
		}

		if(bytes_send == s_contentlength){
			log_debug_msg(LOG_HTTP | LOG_DEBUG, "send http body success");		
		}
		else {
			log_msg(LOG_HTTP | LOG_WARN, "send http body NO success (%"PRIu32"/%"PRIu32")", bytes_send, s_contentlength);
		}

		if (client->ht_response.cleanup_body) {
			free(ht_body);
		}
		client->status = CONNECTED;
	}
}

void _np_http_read_callback(NP_UNUSED struct ev_loop* loop, NP_UNUSED ev_io* ev,
		int event_type) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: void _np_http_read_callback(NP_UNUSED struct ev_loop* loop, NP_UNUSED ev_io* ev,		int event_type) {");

	np_http_client_t* client = (np_http_client_t*) ev->data;

	if ((event_type & EV_READ) == EV_READ && (event_type &  EV_ERROR) != EV_ERROR && CONNECTED <= client->status
			&& REQUEST >= client->status) {
		char data[2048];
		/* receive the new data */
		int16_t in_msg_len = recv(client->client_fd, data, 2048, 0);

		if (0 == in_msg_len) {			
			// tcp disconnect
			log_debug_msg(LOG_HTTP | LOG_DEBUG, "received disconnect");
			close(client->client_fd);
			ev_io_stop(EV_A_&client->client_watcher_in);
			ev_io_stop(EV_A_&client->client_watcher_out);
			client->status = UNUSED;
			
		}

		if (0 > in_msg_len) {
			log_msg(LOG_ERROR, "http receive failed: %s", strerror(errno));
			log_trace_msg(LOG_TRACE | LOG_HTTP, ".end  .np_network_read");
			return;
		}

		log_debug_msg(LOG_HTTP | LOG_DEBUG, "parsing http request");

		htparser_run(client->parser, __local_http->hooks, data,
				in_msg_len);
		if (htparser_get_error(client->parser) != htparse_error_none) {
			log_msg(LOG_ERROR, "error parsing http request");
			client->ht_response.ht_status = HTTP_CODE_BAD_REQUEST;
			client->status = RESPONSE;
		}

		if (PROCESSING == client->status) {
			_np_http_dispatch(client);
		}

	} else {
		// log_debug_msg(LOG_DEBUG, "local http status now %d, but should be %d or %d",
		// __local_http->status, CONNECTED, REQUEST);
	}
}

void _np_http_accept(NP_UNUSED struct ev_loop* loop, NP_UNUSED ev_io* ev,
NP_UNUSED int event_type) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: void _np_http_accept(NP_UNUSED struct ev_loop* loop, NP_UNUSED ev_io* ev,NP_UNUSED int event_type) {");

	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);

	np_http_client_t* new_client = malloc(sizeof(np_http_client_t));
	CHECK_MALLOC(new_client);

	new_client->parser = htparser_new();
	new_client->ht_request.ht_header = NULL;
	new_client->ht_request.ht_query_args = NULL;
	new_client->ht_request.ht_path = NULL;
	new_client->ht_request.current_key = NULL;
	new_client->status = UNUSED;



	/*
	if (UNUSED < __local_http->status) {	// check if connection expired
		if (new_client->last_update < (ev_time() - __np_http_timeout)) {
			close(new_client);
			// _np_suspend_event_loop();
			ev_io_stop(EV_A_&new_client->client_watcher_in);
			ev_io_stop(EV_A_&new_client->client_watcher_out);
			// _np_resume_event_loop();
			__local_http->status = UNUSED;
		}
	}
	 */

	if (UNUSED == new_client->status) {
		new_client->client_fd = accept(__local_http->network->socket,
				(struct sockaddr*) &from, &fromlen);

		if (new_client->client_fd < 0) {
			free(new_client);

			log_msg(LOG_HTTP | LOG_WARN, "Could not accept http connection. %s", strerror(errno));
		}
		else {
			sll_append(np_http_client_ptr, __local_http->clients, new_client);

			htparser_init(new_client->parser, htp_type_request);
			htparser_set_userdata(new_client->parser, new_client);

			// get calling address and port for logging
			char ipstr[255] = { 0 };
			char port[6] = { 0 };

			if (from.ss_family == AF_INET) {
				struct sockaddr_in *s = (struct sockaddr_in *) &from;
				getnameinfo((struct sockaddr*) s, sizeof s, ipstr, 255, port, 6, 0);
			}
			else {
				struct sockaddr_in6 *s = (struct sockaddr_in6 *) &from;
				getnameinfo((struct sockaddr*) s, sizeof s, ipstr, 255, port, 6, 0);
			}

			log_debug_msg(LOG_HTTP | LOG_DEBUG,
				"received http request from %s:%s (client fd: %"PRIi32")", ipstr, port,
				new_client->client_fd);

			new_client->status = CONNECTED;

			// set non blocking
			int current_flags = fcntl(new_client->client_fd, F_GETFL);
			current_flags |= O_NONBLOCK;
			fcntl(new_client->client_fd, F_SETFL, current_flags);

			// _np_suspend_event_loop();
			ev_io_init(&new_client->client_watcher_in, _np_http_read_callback,
				new_client->client_fd, EV_READ);
			ev_io_init(&new_client->client_watcher_out, _np_http_write_callback,
				new_client->client_fd, EV_WRITE);

			new_client->client_watcher_in.data = new_client;
			new_client->client_watcher_out.data = new_client;

			ev_io_start(EV_A_&new_client->client_watcher_in);
			ev_io_start(EV_A_&new_client->client_watcher_out);
			// _np_resume_event_loop();
		}

	} else {
		log_debug_msg(LOG_HTTP | LOG_DEBUG, "http connection attempt not accepted");
	}
}

np_bool np_http_init(char* domain) {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: np_bool np_http_init() {");

	if (domain == NULL) {
		domain = strdup("localhost");
	}
	
	char* port = "31415";
	
	__local_http = (np_http_t*) malloc(sizeof(np_http_t));
	CHECK_MALLOC(__local_http);

	sll_init(np_http_client_ptr, __local_http->clients);

	_LOCK_MODULE(np_network_t)
	{
		np_new_obj(np_network_t, __local_http->network);

		_np_network_init(__local_http->network, TRUE, TCP | IPv4, domain, port);
		_np_network_start(__local_http->network);
	}
	if (NULL == __local_http->network || FALSE == __local_http->network->initialized )
		return FALSE;

	__local_http->hooks = (htparse_hooks*) malloc(sizeof(htparse_hooks));
	CHECK_MALLOC(__local_http->hooks);

	if (NULL == __local_http->hooks)
		return FALSE;

	// define callbacks
	__local_http->hooks->on_msg_begin = _np_http_on_msg_begin;
	__local_http->hooks->method = NULL;
	__local_http->hooks->scheme = NULL; /* called if scheme is found */
	__local_http->hooks->hostname = NULL;
	__local_http->hooks->host = NULL; /* called if a host was in the request scheme */
	__local_http->hooks->port = NULL; /* called if a port was in the request scheme */
	__local_http->hooks->path = _np_http_path; /* only the path of the uri */
	__local_http->hooks->args = _np_http_query_args; /* only the arguments of the uri */
	__local_http->hooks->uri = NULL; /* the entire uri including path/args */
	__local_http->hooks->on_hdrs_begin = _np_http_on_hdrs_begin;
	__local_http->hooks->hdr_key = _np_http_hdr_key;
	__local_http->hooks->hdr_val = _np_http_hdr_value;
	__local_http->hooks->on_hdrs_complete = NULL;
	__local_http->hooks->on_new_chunk = NULL; /* called after parsed chunk octet */
	__local_http->hooks->on_chunk_complete = NULL; /* called after single parsed chunk */
	__local_http->hooks->on_chunks_complete = NULL; /* called after all parsed chunks processed */
	__local_http->hooks->body = _np_http_body;
	__local_http->hooks->on_msg_complete = _np_http_on_msg_complete;
	
	_np_suspend_event_loop_http();
	EV_P = _np_event_get_loop_http();
	ev_io_init(&__local_http->network->watcher, _np_http_accept,
			__local_http->network->socket, EV_READ);
	__local_http->network->watcher.data = __local_http;
	ev_io_start(EV_A_&__local_http->network->watcher);
	_np_resume_event_loop_http();
	__local_http->user_hooks = NULL;

	return TRUE;
}

void _np_http_destroy() {
	log_trace_msg(LOG_TRACE | LOG_HTTP, "start: void _np_http_destroy() {");


	EV_P = _np_event_get_loop_http();
	_np_suspend_event_loop_http();
	ev_io_stop(EV_A_&__local_http->network->watcher);
	_np_resume_event_loop_http();
	sll_iterator(np_http_client_ptr) iter = sll_first(__local_http->clients);
	while(iter != NULL){
		np_http_client_t* client = iter->val;
		client->status = SHUTDOWN;

		ev_io_stop(EV_A_&client->client_watcher_in);
		ev_io_stop(EV_A_&client->client_watcher_out);
		close(iter->val->client_fd);

		if (client->ht_request.ht_body)
			free(client->ht_request.ht_body);
		if (client->ht_request.ht_path)
			free(client->ht_request.ht_path);
		if (client->ht_request.current_key)
			free(client->ht_request.current_key);
		if (client->ht_request.ht_header)
			np_tree_free(client->ht_request.ht_header);
		if (client->ht_request.ht_query_args)
			np_tree_free(client->ht_request.ht_query_args);
		if (client->ht_response.ht_header)
			np_tree_free(client->ht_response.ht_header);
		if (client->ht_response.ht_body)
			free(client->ht_response.ht_body);

		free(client->parser);
		free(iter->val);
		sll_next(iter);
	}

	if (__local_http->user_hooks)
		np_tree_free(__local_http->user_hooks);

	free(__local_http->hooks);

	np_unref_obj(np_network_t, __local_http->network,"np_http_init");
}

