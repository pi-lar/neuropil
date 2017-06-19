//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_GLIA_H_
#define _NP_GLIA_H_

#include "np_types.h"

#include "np_msgproperty.h"

#ifdef __cplusplus
extern "C" {
#endif

void _np_route_lookup_jobexec (np_jobargs_t* args);

// critical self invoking functions
void _np_route_check_leafset_jobexec(np_jobargs_t* args);
void _np_retransmit_message_tokens_jobexec(np_jobargs_t* args);
void _np_renew_node_token_jobexec(np_jobargs_t* args);

void _np_cleanup_ack_jobexec(np_jobargs_t* args);
void _np_cleanup_keycache_jobexec(np_jobargs_t* args);

void _np_never_called_jobexec(np_jobargs_t* args);

// other helper functions
void _np_send_rowinfo_jobexec (np_jobargs_t* args);

np_aaatoken_t* _np_create_msg_token(np_msgproperty_t* msg_request);

void _np_send_subject_discovery_messages(np_msg_mode_type mode_type, const char* subject);
void _np_send_msg_interest(const char* subject);
void _np_send_msg_availability(const char* subject);

np_bool _np_send_msg (char* subject, np_message_t* msg, np_msgproperty_t* msg_prop, np_dhkey_t* target);

#ifdef __cplusplus
}
#endif

#endif // _NP_GLIA_H_
