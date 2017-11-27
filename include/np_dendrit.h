//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_DENDRIT_H_
#define _NP_DENDRIT_H_

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// input message handlers
NP_API_INTERN
void _np_in_handshake(np_jobargs_t* args);

NP_API_INTERN
void _np_in_received (np_jobargs_t* args);

NP_API_INTERN
void _np_in_piggy (np_jobargs_t* args);
NP_API_INTERN
void _np_in_update (np_jobargs_t* args);
NP_API_INTERN
void _np_in_ack(np_jobargs_t* args);
NP_API_INTERN
void __np_in_ack_handle(np_message_t * msg);

NP_API_INTERN
void _np_in_join_req(np_jobargs_t* args);
NP_API_INTERN
void _np_in_join_ack (np_jobargs_t* args);
NP_API_INTERN
void _np_in_join_nack (np_jobargs_t* args);

NP_API_INTERN
void _np_in_leave_req(np_jobargs_t* args);

NP_API_INTERN
void _np_in_discover_receiver(np_jobargs_t* args);
NP_API_INTERN
void _np_in_discover_sender(np_jobargs_t* args);
NP_API_INTERN
void _np_in_available_sender(np_jobargs_t* args);
NP_API_INTERN
void _np_in_available_receiver(np_jobargs_t* args);

NP_API_INTERN
void _np_in_authenticate(np_jobargs_t* args);
NP_API_INTERN
void _np_in_authenticate_reply(np_jobargs_t* args);

NP_API_INTERN
void _np_in_authorize(np_jobargs_t* args);
NP_API_INTERN
void _np_in_authorize_reply(np_jobargs_t* args);

NP_API_INTERN
void _np_in_account(np_jobargs_t* args);

NP_API_INTERN
void _np_in_signal_np_receive (np_jobargs_t* args);
NP_API_INTERN
void _np_in_callback_wrapper(np_jobargs_t* args);
#ifdef __cplusplus
}
#endif

#endif // _NP_HANDLER_H_
