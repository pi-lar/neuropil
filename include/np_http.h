//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_HTTP_H_
#define _NP_HTTP_H_

#include "http/htparse.h"

#include "np_memory.h"

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// generate new and del method for np_node_t
// _NP_GENERATE_MEMORY_PROTOTYPES(np_http_t);

enum http_return_e {
	HTTP_NO_RESPONSE = 0,
	HTTP_CODE_CONTINUE              ,
	HTTP_CODE_OK                    ,
	HTTP_CODE_ACCEPTED              ,
	HTTP_CODE_CREATED               ,
	HTTP_CODE_NO_CONTENT            ,
	HTTP_CODE_PARTIAL_CONTENT       ,
	HTTP_CODE_MULTI_STATUS          ,
	HTTP_CODE_MOVED_TEMPORARILY     ,
	HTTP_CODE_NOT_MODIFIED          ,
	HTTP_CODE_BAD_REQUEST           ,
	HTTP_CODE_UNAUTHORIZED          ,
	HTTP_CODE_FORBIDDEN             ,
	HTTP_CODE_NOT_FOUND             ,
	HTTP_CODE_METHOD_NOT_ALLOWED    ,
	HTTP_CODE_REQUEST_TIME_OUT      ,
	HTTP_CODE_GONE                  ,
	HTTP_CODE_REQUEST_URI_TOO_LONG  ,
	HTTP_CODE_LOCKED                ,
	HTTP_CODE_INTERNAL_SERVER_ERROR ,
	HTTP_CODE_NOT_IMPLEMENTED       ,
	HTTP_CODE_SERVICE_UNAVAILABLE
};

typedef struct ht_request_s ht_request_t;
typedef struct ht_response_s ht_response_t;

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
	np_bool cleanup_body;
};

typedef int (*_np_http_callback_func_t)(ht_request_t* request, ht_response_t* response, void* user_arg);

NP_API_EXPORT
np_bool np_http_init(np_state_t* context, char* domain);

NP_API_EXPORT
void _np_add_http_callback(np_state_t *context, const char* path, htp_method method, void* user_args, _np_http_callback_func_t func);

NP_API_EXPORT
void _np_rem_http_callback(const char* path, htp_method method);


#ifdef __cplusplus
}
#endif

#endif //  _NP_HTTP_H_

