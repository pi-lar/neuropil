//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_GLIA_H_
#define _NP_GLIA_H_

#include "np_types.h"

#include "core/np_comp_msgproperty.h"

#ifdef __cplusplus
extern "C" {
#endif

void _np_glia_route_lookup (np_state_t* context, np_jobargs_t args);

// critical self invoking functions
void _np_retransmit_message_tokens_jobexec(np_state_t* context, np_jobargs_t args);
void _np_renew_node_token_jobexec(np_state_t* context, np_jobargs_t args);

void _np_cleanup_ack_jobexec(np_state_t* context, np_jobargs_t args);
void _np_cleanup_keycache_jobexec(np_state_t* context, np_jobargs_t args);


void _np_send_subject_discovery_messages(np_state_t* context, np_msg_mode_type mode_type, const char* subject);
void _np_send_msg_interest(const char* subject);
void _np_send_msg_availability(const char* subject);

bool _np_send_msg (char* subject, np_message_t* msg, np_msgproperty_t* msg_prop, np_dhkey_t* target);

void _np_glia_check_neighbours(np_state_t* context, np_jobargs_t args);
void _np_glia_check_routes(np_state_t* context, np_jobargs_t args);
void _np_glia_log_flush(np_state_t* context, np_jobargs_t args);

typedef void(*__np_glia_check_connections_handler)(np_key_t*, bool, np_key_t**, np_key_t**);
void __np_glia_check_connections(np_sll_t(np_key_ptr, connections), __np_glia_check_connections_handler fn);

#ifdef __cplusplus
}
#endif

#endif // _NP_GLIA_H_
