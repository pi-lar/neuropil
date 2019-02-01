//
// neuropil is copyright 2016-2019 by pi-lar GmbH
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

#include "np_dhkey.h"
#include "np_event.h"
#include "np_glia.h"
#include "np_http.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_list.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_network.h"
#include "np_node.h"
#include "np_route.h"
#include "np_sysinfo.h"
#include "np_threads.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "np_util.h"

#include "json/parson.h"
#include "http/htparse.h"
#include "http/htparse.c"

#include "../examples/example_helper.h"

#define HTTP_PORT 31415

// generate new and del method for np_node_t
// _NP_GENERATE_MEMORY_PROTOTYPES(np_http_t);


enum http_return_e {
    HTTP_NO_RESPONSE = 0,
    HTTP_CODE_CONTINUE,
    HTTP_CODE_OK,
    HTTP_CODE_ACCEPTED,
    HTTP_CODE_CREATED,
    HTTP_CODE_NO_CONTENT,
    HTTP_CODE_PARTIAL_CONTENT,
    HTTP_CODE_MULTI_STATUS,
    HTTP_CODE_MOVED_TEMPORARILY,
    HTTP_CODE_NOT_MODIFIED,
    HTTP_CODE_BAD_REQUEST,
    HTTP_CODE_UNAUTHORIZED,
    HTTP_CODE_FORBIDDEN,
    HTTP_CODE_NOT_FOUND,
    HTTP_CODE_METHOD_NOT_ALLOWED,
    HTTP_CODE_REQUEST_TIME_OUT,
    HTTP_CODE_GONE,
    HTTP_CODE_REQUEST_URI_TOO_LONG,
    HTTP_CODE_LOCKED,
    HTTP_CODE_INTERNAL_SERVER_ERROR,
    HTTP_CODE_NOT_IMPLEMENTED,
    HTTP_CODE_SERVICE_UNAVAILABLE
};


// http request structure
struct ht_request_s {
    // char* ht_version;
    // char* ht_hostname;
    // char* ht_port;
    char* ht_path;
    char* current_key;
    htp_method ht_method;
    np_tree_t* ht_query_args;
    np_tree_t* ht_header;
    uint16_t ht_length;
    char* ht_body;
};

// http response structure
struct ht_response_s {
    int ht_status;
    char* ht_reason;
    np_tree_t* ht_header;
    uint16_t ht_length;
    char* ht_body;
    bool cleanup_body;
};

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
    np_state_t* context;
};
typedef struct np_http_client_s np_http_client_t;
typedef np_http_client_t* np_http_client_ptr;

NP_SLL_GENERATE_PROTOTYPES(np_http_client_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_http_client_ptr);

struct np_http_s {
    // memory management
    

    // network io handling
    np_network_t* network;

    np_sll_t(np_http_client_ptr, clients);

    htparse_hooks* hooks;
    np_tree_t* user_hooks;	
};


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


void _np_http_handle_sysinfo(np_state_t* context, np_http_client_t* client);

void _np_add_http_callback(np_state_t *context, const char* path, htp_method method, void* user_args,
        _np_http_callback_func_t func) {
    log_trace_msg(LOG_TRACE | LOG_HTTP, "start: void _np_add_http_callback(const char* path, htp_method method, void* user_args,		_np_http_callback_func_t func) {");

    np_http_t* __local_http = ((example_user_context*)np_get_userdata(context))->local_http;
    if (NULL == __local_http->user_hooks)
        __local_http->user_hooks = np_tree_create();

    char key[32];
    snprintf(key, 31, "%d:%s", method, path);

    _np_http_callback_t* callback_data = malloc(sizeof(_np_http_callback_t));
    CHECK_MALLOC(callback_data);

    callback_data->user_arg = user_args;
    callback_data->callback = func;
    np_tree_insert_str( __local_http->user_hooks, key, np_treeval_new_v(callback_data));
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
        np_tree_clear( client->ht_request.ht_query_args);
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
        np_tree_clear( client->ht_request.ht_header);
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

    np_http_client_t* client = (np_http_client_t*) parser->userdata;
    client->ht_request.ht_method = htparser_get_method(parser);
    client->ht_request.ht_length = htparser_get_content_length(parser);

    client->status = PROCESSING;

    return 0;
}

void _np_http_dispatch(np_state_t* context, np_http_client_t* client) {
    log_trace_msg(LOG_TRACE | LOG_HTTP, "start: void _np_http_dispatch(NP_UNUSED np_jobargs_t* args) {");

    assert(PROCESSING == client->status);
    np_http_t* __local_http = ((example_user_context*)np_get_userdata(context))->local_http;
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
        client->ht_response.cleanup_body = true;
        client->status = RESPONSE;
    } else {
        switch (client->ht_request.ht_method) {
        case (htp_method_GET): {            
            if (np_module_initiated(sysinfo)) {
                _np_http_handle_sysinfo(context, client);
                break;
            }            
        }

        default:
            client->ht_response.ht_body = HTML_NOT_IMPLEMENTED;
            client->ht_response.ht_header = np_tree_create();
            client->ht_response.ht_status = HTTP_CODE_NOT_IMPLEMENTED;
            client->ht_response.cleanup_body = false;
            client->status = RESPONSE;
        }
    }
}

void _np_http_handle_sysinfo(np_state_t* context , np_http_client_t* client)
{

    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "Requesting sysinfo");

    char target_hash[65];

    bool usedefault = true;
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
                usedefault = false;
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

    key = context->my_node_key;
    np_tryref_obj(np_key_t, key, keyExists);
    if (keyExists) {
        char* my_key = _np_key_as_str(key);
        np_tree_t* sysinfo = NULL;
        if (usedefault) {
            log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "using own node as info system");
            snprintf(target_hash, 64, "%s", my_key);

            sysinfo = np_sysinfo_get_all(context);
        }
        else {

            sysinfo = np_sysinfo_get_info(context, target_hash);
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
            json_obj = np_tree2json(context, sysinfo);
            log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "cleanup");
        }
        np_tree_free( sysinfo);

        np_unref_obj(np_key_t, key, FUNC);
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
    response = np_json2char(json_obj, false);
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "sysinfo response should be (strlen: %lu):",
        strlen(response));
    json_value_free(json_obj);

    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "write to body");
    client->ht_response.ht_status = http_status;
    client->ht_response.ht_body = response; //strdup(response);;

    client->ht_response.ht_header = np_tree_create();
    np_tree_insert_str( client->ht_response.ht_header, "Content-Type",
        np_treeval_new_s("application/json"));
    np_tree_insert_str( client->ht_response.ht_header,
        "Access-Control-Allow-Origin", np_treeval_new_s("*"));
    np_tree_insert_str( client->ht_response.ht_header,
        "Access-Control-Allow-Methods", np_treeval_new_s("GET"));
    client->ht_response.cleanup_body = true;
    client->status = RESPONSE;
}

void _np_http_write_callback(struct ev_loop* loop, NP_UNUSED ev_io* ev, int event_type) {
    np_state_t* context = ev_userdata(loop);
    np_http_client_t* client = (np_http_client_t*) ev->data;

    if (((event_type & EV_WRITE) == EV_WRITE && (event_type &  EV_ERROR) != EV_ERROR) && RESPONSE == client->status) {
        log_debug_msg(LOG_HTTP | LOG_DEBUG, "start writing response");
        // create http reply
        char data[2048];

        char * ht_body = client->ht_response.ht_body;
        // HTTP start
        int pos =
                snprintf(data, 2048, "%s %d %s" HTTP_CRLF, "HTTP/1.1",
                        http_return_codes[client->ht_response.ht_status].http_code,
                        http_return_codes[client->ht_response.ht_status].text);

        // add content length header
        uint32_t s_contentlength = strlen(ht_body);
        char body_length[255];
        snprintf(body_length, 254, "%"PRIu32, s_contentlength);
        np_tree_insert_str( client->ht_response.ht_header, "Content-Length",
                np_treeval_new_s(body_length));
        np_tree_insert_str( client->ht_response.ht_header, "Content-Type",
                np_treeval_new_s("application/json"));
        // add keep alive header
        np_tree_insert_str( client->ht_response.ht_header, "Connection",
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
#ifdef MSG_NOSIGNAL 
        send(client->client_fd, data, pos, MSG_NOSIGNAL);
#else
        send(client->client_fd, data, pos, 0);
#endif
        np_tree_free( client->ht_response.ht_header);

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

#ifdef MSG_NOSIGNAL 
            int send_return = send(client->client_fd,
                ht_body + bytes_send,
                fmin(2048, s_contentlength - bytes_send),
                MSG_NOSIGNAL
            );
#else
            int send_return = send(client->client_fd,
                ht_body + bytes_send,
                fmin(2048, s_contentlength - bytes_send),
                0
            );
#endif

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

void _np_http_read_callback(struct ev_loop* loop, NP_UNUSED ev_io* ev,
        int event_type) {
    np_state_t* context = ev_userdata(loop);
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
            ev_io_stop(EV_A_ &client->client_watcher_in);
            ev_io_stop(EV_A_ &client->client_watcher_out);
            client->status = UNUSED;
            
        }

        if (0 > in_msg_len) {
            log_msg(LOG_ERROR, "http receive failed: %s", strerror(errno));
            log_trace_msg(LOG_TRACE | LOG_HTTP, ".end  .np_network_read");
            return;
        }

        log_debug_msg(LOG_HTTP | LOG_DEBUG, "parsing http request");
        np_http_t* __local_http = ((example_user_context*)np_get_userdata(context))->local_http;
        htparser_run(client->parser, __local_http->hooks, data,
                in_msg_len);
        if (htparser_get_error(client->parser) != htparse_error_none) {
            log_msg(LOG_ERROR, "error parsing http request");
            client->ht_response.ht_status = HTTP_CODE_BAD_REQUEST;
            client->status = RESPONSE;
        }

        if (PROCESSING == client->status) {
            _np_http_dispatch(context, client);
        }

    } else {
        // log_debug_msg(LOG_DEBUG, "local http status now %d, but should be %d or %d",
        // __local_http->status, CONNECTED, REQUEST);
    }
}

void _np_http_accept(struct ev_loop* loop, NP_UNUSED ev_io* ev, NP_UNUSED int event_type) {
    np_state_t* context = ev_userdata(loop);
    np_http_t* __local_http = ((example_user_context*)np_get_userdata(context))->local_http;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);

    np_http_client_t* new_client = calloc(1, sizeof(np_http_client_t));
    CHECK_MALLOC(new_client);

    new_client->parser = htparser_new();
    new_client->ht_request.ht_body = NULL;
    new_client->ht_request.ht_header = NULL;
    new_client->ht_request.ht_query_args = NULL;
    new_client->ht_request.ht_path = NULL;
    new_client->ht_request.current_key = NULL;
    new_client->status = UNUSED;
    new_client->context = context;
    
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

            _np_event_suspend_loop_http(context);

            ev_io_init(&new_client->client_watcher_in, _np_http_read_callback,
                new_client->client_fd, EV_READ);
            ev_io_init(&new_client->client_watcher_out, _np_http_write_callback,
                new_client->client_fd, EV_WRITE);

            new_client->client_watcher_in.data = new_client;
            new_client->client_watcher_out.data = new_client;

            ev_io_start(EV_A_&new_client->client_watcher_in);
            ev_io_start(EV_A_&new_client->client_watcher_out);

            _np_event_resume_loop_http(context);
        }

    } else {
        log_debug_msg(LOG_HTTP | LOG_DEBUG, "http connection attempt not accepted");
    }
} 
bool np_http_init(np_state_t* context, char* domain) {
 
    if (domain == NULL) {
        domain = strdup("localhost");
    }
    
    char* port = TO_STRING(HTTP_PORT);
    np_http_t* __local_http = (np_http_t*) malloc(sizeof(np_http_t));
    CHECK_MALLOC(__local_http);
    
    sll_init(np_http_client_ptr, __local_http->clients);

    _LOCK_MODULE(np_network_t)
    {
        np_new_obj(np_network_t, __local_http->network);

        _np_network_init(__local_http->network, true, TCP | IPv4, domain, port,-1, UNKNOWN_PROTO);
        // _np_network_enable(__local_http->network);
    }
    if (NULL == __local_http->network || false == __local_http->network->initialized )
        return false;

    __local_http->hooks = (htparse_hooks*) malloc(sizeof(htparse_hooks));
    CHECK_MALLOC(__local_http->hooks);

    if (NULL == __local_http->hooks)
        return false;

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
    
    _np_event_suspend_loop_http(context);
    EV_P = _np_event_get_loop_http(context);
    ev_io_init(&__local_http->network->watcher, _np_http_accept,
            __local_http->network->socket, EV_READ);
    __local_http->network->watcher.data = __local_http;
    ev_io_start(EV_A_&__local_http->network->watcher);
    _np_event_resume_loop_http(context);
    __local_http->user_hooks = NULL;
    
    ((example_user_context*)np_get_userdata(context))->local_http = __local_http;
    return true;
}

void _np_http_destroy(np_state_t* context) {	
    example_user_context* ud = (example_user_context*)np_get_userdata(context);
    if(ud){
        np_http_t* __local_http = ud->local_http;

        if(__local_http != NULL) {
            ((example_user_context*) np_get_userdata(context))->local_http = NULL;

            EV_P = _np_event_get_loop_http(context);
            _np_event_suspend_loop_http(context);
            ev_io_stop(EV_A_&__local_http->network->watcher);

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
                    np_tree_free( client->ht_request.ht_header);
                if (client->ht_request.ht_query_args)
                    np_tree_free( client->ht_request.ht_query_args);

                free(client->parser);
                free(client);
                sll_next(iter);
            }
            sll_free(np_http_client_ptr, __local_http->clients);

            _np_event_resume_loop_http(context);

            if (__local_http->user_hooks)
                np_tree_free( __local_http->user_hooks);

            free(__local_http->hooks);

            __local_http->network->watcher.data = NULL;
            // _np_network_disable(__local_http->network);
            np_unref_obj(np_network_t, __local_http->network, ref_obj_creation);

            free(__local_http);
            __local_http = NULL;
        }
    }
}

void example_http_server_destroy(np_context* context) {
    _np_http_destroy(context);
}

bool example_http_server_init(np_context* context, char* http_domain, np_sysinfo_opt_e opt_sysinfo_mode) {
    bool ret = false;
    bool free_http_domain=false;
    if (http_domain == NULL || (strncmp("none", http_domain, 5) != 0 && strncmp("false", http_domain, 5) != 0 && strncmp("false", http_domain, 5) != 0 && strncmp("0", http_domain, 2) != 0)) {
        if (http_domain == NULL) {
            http_domain = calloc(1, sizeof(char) * 255);
            CHECK_MALLOC(http_domain);
            if (np_get_local_ip(context, http_domain, 255) == false) {
                free(http_domain);
                http_domain = NULL;
            } else {
                free_http_domain=true;
            }
        }
        ret = np_http_init(context, http_domain);
        if (ret == false) {
            log_msg(LOG_WARN, "Node could not start HTTP interface");
        }
    }
    if (opt_sysinfo_mode != np_sysinfo_opt_disable) {
        if ((ret && opt_sysinfo_mode == np_sysinfo_opt_auto) || opt_sysinfo_mode == np_sysinfo_opt_force_server)
        {
            np_example_print(context, stdout, "HTTP interface set to %s:%d\n", http_domain, HTTP_PORT);
            log_msg(LOG_INFO, "HTTP interface set to %s:%d", http_domain,HTTP_PORT);
            np_example_print(context, stdout, "Enable sysinfo server option\n");
            np_sysinfo_enable_server(context);
        }
        else {
            np_example_print(context, stdout, "Node could not start HTTP interface\n");
            np_example_print(context, stdout, "Enable sysinfo client option\n");
            np_sysinfo_enable_client(context);
        }
        
        np_example_print(context, stdout, "Watch sysinfo subjects \n");
        // If you want to you can enable the statistics modulte to view the nodes statistics
        np_statistics_add_watch(context, _NP_SYSINFO_REQUEST);
        np_statistics_add_watch(context, _NP_SYSINFO_REPLY);

    }
    if(free_http_domain) free(http_domain);

    return ret;
}
