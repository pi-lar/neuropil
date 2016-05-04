/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "sys/socket.h"

#include "json/parson.h"

#include "np_log.h"
#include "neuropil.h"
#include "np_glia.h"
#include "np_http.h"
#include "np_tree.h"
#include "np_jobqueue.h"
#include "np_network.h"
#include "np_node.h"
#include "np_route.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_threads.h"

static double __np_http_timeout = 20.0f;
// static pthread_mutex_t __http_mutex = PTHREAD_MUTEX_INITIALIZER;

// static char* HTML_DEFAULT_PAGE    = "<html><head><title>neuropil</title></head><body></body></html>";
static char* HTML_NOT_IMPLEMENTED = "<html><head><title>neuropil</title></head><body>not implemented</body></html>";

#define HTTP_CRLF "\r\n"

typedef enum np_http_status_e {
	UNUSED = 0,
	ACCEPTED,
	CONNECTED,
	REQUEST,
	PROCESSING,
	RESPONSE,
	SHUTDOWN
} np_http_status_e;

typedef struct np_http_s np_http_t;
struct np_http_s
{
	// memory management
	np_obj_t* obj;

	// network io handling
	np_network_t* network;
	int client_fd;
	struct ev_io client_watcher_in;
	struct ev_io client_watcher_out;

	// global status and last update time
	np_http_status_e status;
	double last_update;

	// http parser and callbacks
	htparser* parser;
	htparse_hooks* hooks;

	np_tree_t* user_hooks;

	// http request structure
	ht_request_t ht_request;
	// http response structure
	ht_response_t ht_response;
};

static np_http_t* __local_http;

typedef struct http_return_t { const char* text; int http_code; } http_return_t;
http_return_t http_return_codes[] = {
	{ "HTTP_NO_RESPONSE"                ,   0},
	{ "HTTP_CODE_CONTINUE"              , 100},
	{ "HTTP_CODE_OK"                    , 200},
	{ "HTTP_CODE_CREATED"               , 201},
	{ "HTTP_CODE_NO_CONTENT"            , 204},
	{ "HTTP_CODE_PARTIAL_CONTENT"       , 206},
	{ "HTTP_CODE_MULTI_STATUS"          , 207},
	{ "HTTP_CODE_MOVED_TEMPORARILY"     , 302},
	{ "HTTP_CODE_NOT_MODIFIED"          , 304},
	{ "HTTP_CODE_BAD_REQUEST"           , 400},
	{ "HTTP_CODE_UNAUTHORIZED"          , 401},
	{ "HTTP_CODE_FORBIDDEN"             , 403},
	{ "HTTP_CODE_NOT_FOUND"             , 404},
	{ "HTTP_CODE_METHOD_NOT_ALLOWED"    , 405},
	{ "HTTP_CODE_REQUEST_TIME_OUT"      , 408},
	{ "HTTP_CODE_GONE"                  , 410},
	{ "HTTP_CODE_REQUEST_URI_TOO_LONG"  , 414},
	{ "HTTP_CODE_LOCKED"                , 423},
	{ "HTTP_CODE_INTERNAL_SERVER_ERROR" , 500},
	{ "HTTP_CODE_NOT_IMPLEMENTED"       , 501},
	{ "HTTP_CODE_SERVICE_UNAVAILABLE"   , 503}
};

typedef struct _np_http_callback_s {
	_np_http_callback_func_t callback;
	void* user_arg;
} _np_http_callback_t;

void _np_add_http_callback(const char* path, htp_method method, void* user_args, _np_http_callback_func_t func)
{
	if (NULL == __local_http->user_hooks) __local_http->user_hooks = make_jtree();

	char key[32];
	snprintf(key, 31, "%d:%s", method, path);

	_np_http_callback_t* callback_data = malloc(sizeof (_np_http_callback_t));
	callback_data->user_arg = user_args;
	callback_data->callback = func;
	tree_insert_str(__local_http->user_hooks, key, new_val_v(callback_data));
}


void _np_rem_http_callback(const char* path, htp_method method)
{
	if (NULL == __local_http->user_hooks) __local_http->user_hooks = make_jtree();

	char key[32];
	snprintf(key, 31, "%d:%s", method, path);
	np_tree_elem_t* callback_val = tree_find_str(__local_http->user_hooks, key);
	if (NULL != callback_val)
	{
		_np_http_callback_t* callback_data = (_np_http_callback_t*) callback_val->val.value.v;
		tree_del_str(__local_http->user_hooks, key);
		free(callback_data);
	}
}

int _np_http_on_msg_begin(htparser* parser)
{
	// pthread_mutex_lock(__http_mutex);
	__local_http->status = REQUEST;
	__local_http->last_update = ev_time();

	return 0;
}

int _np_http_query_args(htparser * parser, const char * data, size_t in_len)
{
	char* key = NULL;
	char* val = NULL;

	if (NULL != __local_http->ht_request.ht_query_args) np_clear_tree(__local_http->ht_request.ht_query_args);
	if (NULL == __local_http->ht_request.ht_query_args) __local_http->ht_request.ht_query_args = make_jtree();

	char* query_string = strndup(data, in_len);
	char* kv_pair = strtok(query_string, "&=");

	while (NULL != kv_pair)
	{
		if (NULL == key)
		{
			key = strndup(kv_pair, strlen(kv_pair));
		}
		else
		{
			val = strndup(kv_pair, strlen(kv_pair));
			tree_insert_str(__local_http->ht_request.ht_query_args, key, new_val_s(val) );
			free(key);
			free(val);
			key = NULL;
		}

		kv_pair = strtok(NULL, "&=");
	}
	free(query_string);
	return 0;
}

int _np_http_on_hdrs_begin(htparser* parser)
{
	if (NULL != __local_http->ht_request.ht_header) np_clear_tree(__local_http->ht_request.ht_header);
	if (NULL == __local_http->ht_request.ht_header) __local_http->ht_request.ht_header = make_jtree();
	return 0;
}

int _np_http_hdr_key(htparser * parser, const char * data, size_t in_len)
{
	if (NULL != __local_http->ht_request.current_key) free (__local_http->ht_request.current_key);
	__local_http->ht_request.current_key = strndup(data, in_len);
	return 0;
}

int _np_http_hdr_value(htparser * parser, const char * data, size_t in_len)
{
	tree_insert_str(
			__local_http->ht_request.ht_header,
			__local_http->ht_request.current_key,
			new_val_s( (char*) data ) );

	free(__local_http->ht_request.current_key);
	__local_http->ht_request.current_key = NULL;

	return 0;
}

int _np_http_path(htparser * parser, const char * data, size_t in_len)
{
	if(NULL != __local_http->ht_request.ht_path) free(__local_http->ht_request.ht_path);

	__local_http->ht_request.ht_path = strndup(data, in_len);

	return 0;
}

int _np_http_body(htparser * parser, const char * data, size_t in_len)
{
	if(NULL != __local_http->ht_request.ht_body) free(__local_http->ht_request.ht_body);
	__local_http->ht_request.ht_body = strndup(data, in_len);

	return 0;
}

int _np_http_on_msg_complete(htparser* parser)
{
	__local_http->ht_request.ht_method = htparser_get_method(parser);
	__local_http->ht_request.ht_length = htparser_get_content_length(parser);

	__local_http->status = PROCESSING;
	__local_http->last_update = ev_time();

	return 0;
}

void _np_http_dispatch(np_jobargs_t* args)
{
	assert(PROCESSING == __local_http->status);

	if (NULL == __local_http->user_hooks) __local_http->user_hooks = make_jtree();

	char key[32];
	snprintf(key, 31, "%d:%s", __local_http->ht_request.ht_method, __local_http->ht_request.ht_path);

	np_tree_elem_t* user_callback = tree_find_str(__local_http->user_hooks, key);

	if (NULL != user_callback)
	{
		_np_http_callback_t* callback_data = (_np_http_callback_t*) user_callback->val.value.v;
		__local_http->ht_response.ht_status =
				callback_data->callback(&__local_http->ht_request, &__local_http->ht_response, callback_data->user_arg);
		__local_http->ht_response.cleanup_body = TRUE;
		__local_http->status = RESPONSE;
	}
	else
	{
		switch(__local_http->ht_request.ht_method)
		{
			case(htp_method_GET):
				{
				np_tree_t* tree = make_jtree();

				JSON_Value* arr = json_value_init_array();

				// local node json reply
				JSON_Value* my_node_obj = json_value_init_object();
				JSON_Value* obj = json_value_init_object();
				np_node_encode_to_jrb(tree, _np_state()->my_node_key, FALSE);
				serialize_jrb_to_json(tree, json_object(obj));
				json_object_set_value(json_object(my_node_obj), "local_node", obj);
				json_array_append_value(json_array(arr), my_node_obj);

				np_clear_tree(tree);

				// leafset
				JSON_Value* neighbour_obj = json_value_init_object();
				JSON_Value* neighbour_arr = json_value_init_object();
				np_sll_t(np_key_t, neighbours) = NULL;
				_LOCK_MODULE(np_routeglobal_t)
				{
					neighbours = route_neighbors();
				}
				np_encode_nodes_to_jrb(tree, neighbours, TRUE);
				serialize_jrb_to_json(tree, json_object(neighbour_arr));

				json_object_set_value(json_object(neighbour_obj), "neighbour_nodes", neighbour_arr);
				json_array_append_value(json_array(arr), neighbour_obj);

				sll_free(np_key_t, neighbours);
				np_clear_tree(tree);

				// routing table
				JSON_Value* route_obj = json_value_init_object();
				JSON_Value* route_tbl = json_value_init_object();
				np_sll_t(np_key_t, table) = NULL;
				_LOCK_MODULE(np_routeglobal_t)
				{
					table = _np_route_get_table();
				}

				np_encode_nodes_to_jrb(tree, table, TRUE);
				serialize_jrb_to_json(tree, json_object(route_tbl));

				json_object_set_value(json_object(route_obj), "routing_table", route_tbl);
				json_array_append_value(json_array(arr), route_obj);

				sll_free(np_key_t, table);
				np_free_tree(tree);

				// serialize
				size_t json_size = json_serialization_size_pretty(arr);
				__local_http->ht_response.ht_body   = (char*) malloc(json_size * sizeof(char));
				json_serialize_to_buffer_pretty(arr, __local_http->ht_response.ht_body, json_size);

				__local_http->ht_response.ht_header = make_jtree();
				tree_insert_str(
						__local_http->ht_response.ht_header, "Content-Type", new_val_s("application/json"));
				__local_http->ht_response.ht_status = HTTP_CODE_OK;
				__local_http->ht_response.cleanup_body = TRUE;
				__local_http->status = RESPONSE;

				json_value_free(arr);
				// do some more disatching
				break;
			}

			default:
				__local_http->ht_response.ht_body      = HTML_NOT_IMPLEMENTED;
				__local_http->ht_response.ht_header    = make_jtree();
				__local_http->ht_response.ht_status    = HTTP_CODE_NOT_IMPLEMENTED;
				__local_http->ht_response.cleanup_body = FALSE;
				__local_http->status = RESPONSE;
		}
	}
}

void _np_http_write_callback(struct ev_loop* loop, ev_io* ev, int event_type)
{
	if ( (event_type & EV_WRITE) &&
		 RESPONSE == __local_http->status)
	{
		log_msg(LOG_HTTP | LOG_DEBUG, "start writing response");
		// create http reply
		char data[2048];

		// HTTP start
		int pos = sprintf(data,
						"%s %d %s" HTTP_CRLF,
						"HTTP/1.1",
						http_return_codes[__local_http->ht_response.ht_status].http_code,
						http_return_codes[__local_http->ht_response.ht_status].text);

		// add content length header
		size_t s_cl = strlen(__local_http->ht_response.ht_body);
		char body_length[snprintf(NULL, 0, "%lu", s_cl) + 1];
		snprintf(body_length, s_cl ,"%lu", s_cl);
		tree_insert_str(
				__local_http->ht_response.ht_header, "Content-Length", new_val_s(body_length));
		tree_insert_str(
				__local_http->ht_response.ht_header, "Content-Type", new_val_s("text/html"));
		// add keep alive header
		tree_insert_str(
				__local_http->ht_response.ht_header, "Connection",
				new_val_s(htparser_should_keep_alive(__local_http->parser) ? "Keep-Alive" : "close"));

		// HTTP header
		np_tree_elem_t* iter = RB_MIN(np_tree_s, __local_http->ht_response.ht_header);
		while (NULL != iter)
		{
			pos += snprintf(
					data+pos,
					snprintf(NULL, 0, "%s: %s" HTTP_CRLF, iter->key.value.s, iter->val.value.s) + 1,
					"%s: %s" HTTP_CRLF, iter->key.value.s, iter->val.value.s);
			iter = RB_NEXT(np_tree_s, __local_http->ht_response.ht_header, iter);
		}
		pos += snprintf(data+pos,
						snprintf(NULL, 0, "" HTTP_CRLF) + 1,
						"" HTTP_CRLF);
		// send header
		send(__local_http->client_fd, data, pos, 0);
		np_free_tree(__local_http->ht_response.ht_header);

		log_msg(LOG_HTTP | LOG_DEBUG, "send http header success");

		// HTTP body
		memset(data, 0, 2048);
		int parts = ((int) (strlen(__local_http->ht_response.ht_body) / 2048)) + 1;
		int last_part_size = (strlen(__local_http->ht_response.ht_body) % 2048);

		pos = 0;
		for (int i = 0; i < parts; i++)
		{
			log_msg(LOG_HTTP | LOG_DEBUG, "sending http body part (%d / %d)", i+1, parts);
			if (i+1 == parts)
			{
				send(__local_http->client_fd, __local_http->ht_response.ht_body + pos, last_part_size, 0);
				log_msg(LOG_HTTP | LOG_DEBUG, "send http body end (%lu) success", strlen(__local_http->ht_response.ht_body) - pos);
			}
			else
			{
				send(__local_http->client_fd, __local_http->ht_response.ht_body + pos, 2048, 0);
				pos += 2048;
				log_msg(LOG_HTTP | LOG_DEBUG, "send http body part success");
			}
		}

		if (__local_http->ht_response.cleanup_body)
		{
			free(__local_http->ht_response.ht_body);
		}
		__local_http->status = CONNECTED;
	}
}

void _np_http_read_callback(struct ev_loop* loop, ev_io* ev, int event_type)
{
	if ((event_type & EV_READ) &&
		CONNECTED <= __local_http->status &&
		REQUEST   >= __local_http->status)
	{
		char data[2048];
		/* receive the new data */
		int16_t in_msg_len = recv(__local_http->client_fd, data, 2048, 0);

		if (0 == in_msg_len)
		{
			// tcp disconnect
			log_msg(LOG_HTTP | LOG_DEBUG, "received disconnect");
			close(__local_http->client_fd);
			ev_io_stop(EV_A_ &__local_http->client_watcher_in);
			ev_io_stop(EV_A_ &__local_http->client_watcher_out);
			__local_http->status = UNUSED;
		}

		if (0 > in_msg_len)
		{
			log_msg(LOG_ERROR, "http receive failed: %s", strerror(errno));
			log_msg(LOG_HTTP | LOG_TRACE, ".end  .np_network_read");
			return;
		}

		log_msg(LOG_HTTP | LOG_DEBUG, "parsing http request");
		htparser_run(__local_http->parser, __local_http->hooks, data, in_msg_len);
		if (htparser_get_error(__local_http->parser) != htparse_error_none)
		{
			log_msg(LOG_ERROR, "error parsing http request");
			__local_http->ht_response.ht_status = HTTP_CODE_BAD_REQUEST;
			__local_http->status = RESPONSE;
		}

		if (PROCESSING == __local_http->status)
		{
			np_job_submit_event(0.0, _np_http_dispatch);
		}

	} else {
		// log_msg(LOG_DEBUG, "local http status now %d, but should be %d or %d",
		// __local_http->status, CONNECTED, REQUEST);
	}
}

void _np_http_accept(struct ev_loop* loop, ev_io* ev, int event_type)
{
	log_msg(LOG_HTTP | LOG_TRACE, ".start.np_network_accept");

	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);

	if (UNUSED < __local_http->status)
	{	// check if connection expired
		if (__local_http->last_update < (ev_time() - __np_http_timeout))
		{
			close(__local_http->client_fd);
			// _np_suspend_event_loop();
			ev_io_stop(EV_A_ &__local_http->client_watcher_in);
			ev_io_stop(EV_A_ &__local_http->client_watcher_out);
			// _np_resume_event_loop();
			__local_http->status = UNUSED;
		}
	}

	if (UNUSED == __local_http->status)
	{
		__local_http->client_fd = accept(__local_http->network->socket, (struct sockaddr*)&from, &fromlen);
		htparser_init(__local_http->parser, htp_type_request);
		htparser_set_userdata(__local_http->parser, __local_http);

		// get calling address and port for logging
		char ipstr[255];
		char port [6];

		if (from.ss_family == AF_INET)
		{
			struct sockaddr_in *s = (struct sockaddr_in *) &from;
			getnameinfo((struct sockaddr*)s, sizeof s, ipstr, 255, port, 6, 0);
		}
		else
		{
			struct sockaddr_in6 *s = (struct sockaddr_in6 *) &from;
			getnameinfo((struct sockaddr*) s, sizeof s, ipstr, 255, port, 6, 0);
		}

		log_msg(LOG_HTTP | LOG_DEBUG, "received http request from %s:%s (client fd: %d)", ipstr, port, __local_http->client_fd);

		__local_http->status = CONNECTED;

		// set non blocking
		int current_flags = fcntl(__local_http->client_fd, F_GETFL);
		current_flags |= O_NONBLOCK;
		fcntl(__local_http->client_fd, F_SETFL, current_flags);

		// _np_suspend_event_loop();
		ev_io_init(&__local_http->client_watcher_in,  _np_http_read_callback, __local_http->client_fd, EV_READ);
		ev_io_init(&__local_http->client_watcher_out, _np_http_write_callback, __local_http->client_fd, EV_WRITE);

		ev_io_start(EV_A_ &__local_http->client_watcher_in);
		ev_io_start(EV_A_ &__local_http->client_watcher_out);
		// _np_resume_event_loop();

	} else {
		log_msg(LOG_HTTP | LOG_DEBUG, "http connection attempt not accepted");
	}
}

np_bool _np_http_init()
{
	__local_http = (np_http_t*) malloc(sizeof(np_http_t));
	if (NULL == __local_http) return FALSE;

	__local_http->network = network_init(TRUE, TCP | IPv4, "localhost", "31415" );
	if (NULL == __local_http->network) return FALSE;

	__local_http->parser = htparser_new();
	if (NULL == __local_http->parser) return FALSE;

	__local_http->hooks = (htparse_hooks*) malloc(sizeof(htparse_hooks));
	if (NULL == __local_http->hooks) return FALSE;

	// define callbacks
	__local_http->hooks->on_msg_begin = _np_http_on_msg_begin;
	__local_http->hooks->method = NULL;
    __local_http->hooks->scheme = NULL;              /* called if scheme is found */
    __local_http->hooks->hostname = NULL;
    __local_http->hooks->host = NULL;                /* called if a host was in the request scheme */
    __local_http->hooks->port = NULL;                /* called if a port was in the request scheme */
    __local_http->hooks->path = _np_http_path;                /* only the path of the uri */
    __local_http->hooks->args = _np_http_query_args;                /* only the arguments of the uri */
    __local_http->hooks->uri = NULL;                 /* the entire uri including path/args */
    __local_http->hooks->on_hdrs_begin = _np_http_on_hdrs_begin;
    __local_http->hooks->hdr_key = _np_http_hdr_key;
    __local_http->hooks->hdr_val = _np_http_hdr_value;
    __local_http->hooks->on_hdrs_complete = NULL;
    __local_http->hooks->on_new_chunk = NULL;        /* called after parsed chunk octet */
    __local_http->hooks->on_chunk_complete = NULL;   /* called after single parsed chunk */
    __local_http->hooks->on_chunks_complete = NULL;  /* called after all parsed chunks processed */
    __local_http->hooks->body = _np_http_body;
    __local_http->hooks->on_msg_complete = _np_http_on_msg_complete;

	_np_suspend_event_loop();
	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_io_stop(EV_A_ &__local_http->network->watcher);
	ev_io_init(&__local_http->network->watcher, _np_http_accept, __local_http->network->socket, EV_READ);
	__local_http->network->watcher.data = __local_http;
	ev_io_start(EV_A_ &__local_http->network->watcher);
	_np_resume_event_loop();

	__local_http->ht_request.ht_header = NULL;
	__local_http->ht_request.ht_query_args = NULL;
	__local_http->ht_request.ht_path = NULL;
	__local_http->ht_request.current_key = NULL;

	__local_http->last_update = ev_time();
	__local_http->status = UNUSED;

	return TRUE;
}

void _np_http_destroy()
{
	close(__local_http->client_fd);

	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_io_stop(EV_A_ &__local_http->client_watcher_in);
	ev_io_stop(EV_A_ &__local_http->client_watcher_out);
	ev_io_stop(EV_A_ &__local_http->network->watcher);

	__local_http->status = SHUTDOWN;
	if (__local_http->ht_request.ht_body) free (__local_http->ht_request.ht_body);
	if (__local_http->ht_request.ht_path) free (__local_http->ht_request.ht_path);
	if (__local_http->ht_request.current_key) free (__local_http->ht_request.current_key);
	if (__local_http->user_hooks) np_free_tree(__local_http->user_hooks);
	if (__local_http->ht_request.ht_header) np_free_tree(__local_http->ht_request.ht_header);
	if (__local_http->ht_request.ht_query_args) np_free_tree(__local_http->ht_request.ht_query_args);

	if (__local_http->ht_response.ht_header) np_free_tree(__local_http->ht_response.ht_header);
	if (__local_http->ht_response.ht_body) free (__local_http->ht_response.ht_body);

	free(__local_http->parser);
	free(__local_http->hooks);
}

