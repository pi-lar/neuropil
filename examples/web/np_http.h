//
// neuropil is copyright 2016-2018 by pi-lar GmbH
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

enum np_sysinfo_opt_e {
	np_sysinfo_opt_disable = 0,
	np_sysinfo_opt_auto = 1,
	np_sysinfo_opt_force_server = 2,
	np_sysinfo_opt_force_client = 3
} typedef np_sysinfo_opt_e;

typedef struct ht_request_s ht_request_t;
typedef struct ht_response_s ht_response_t;

typedef int(*_np_http_callback_func_t)(ht_request_t* request, ht_response_t* response, void* user_arg);


np_bool np_http_init(np_state_t* context, char* domain);

void _np_add_http_callback(np_state_t *context, const char* path, htp_method method, void* user_args, _np_http_callback_func_t func);

void _np_rem_http_callback(const char* path, htp_method method);

void example_http_server_init(np_context* context, char* http_domain, np_sysinfo_opt_e opt_sysinfo_mode);

#ifdef __cplusplus
}
#endif

#endif //  _NP_HTTP_H_

