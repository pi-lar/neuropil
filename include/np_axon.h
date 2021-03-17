//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_AXON_H_
#define _NP_AXON_H_

#include "np_types.h"

#include "np_dhkey.h"
#include "util/np_statemachine.h"
#include "util/np_event.h"

#ifdef __cplusplus
extern "C" {
#endif

NP_API_INTERN
bool _np_out_callback_wrapper(np_state_t* context, const np_util_event_t event);

// default sending of message, i.e. used to forward messages
NP_API_INTERN
bool _np_out_default(np_state_t* context, np_util_event_t event);

NP_API_INTERN
bool _np_out_forward(np_state_t* context, np_util_event_t event);

// sends a handshake message to the target node, assumes physical neighbourhood
NP_API_INTERN
bool _np_out_handshake(np_state_t* context, const np_util_event_t event);

NP_API_INTERN
bool _np_out_join(np_state_t* context, const np_util_event_t event);

NP_API_INTERN
bool _np_out_leave(np_state_t* context, const np_util_event_t event);

NP_API_INTERN
bool _np_out_piggy(np_state_t* context, const np_util_event_t event);

NP_API_INTERN
bool _np_out_ping(np_state_t* context, const np_util_event_t event);

NP_API_INTERN
bool _np_out_update(np_state_t* context, const np_util_event_t event);

NP_API_INTERN
bool _np_out_pheromone(np_state_t* context, np_util_event_t msg_event);

// send an acknowledgement to the target node
NP_API_INTERN
bool _np_out_ack (np_state_t* context, np_util_event_t msg_event);

NP_API_INTERN
bool _np_out_discovery_messages(np_state_t* context, np_util_event_t msg_event);
NP_API_INTERN
bool _np_out_available_messages(np_state_t* context, np_util_event_t msg_event);

// send an authentication request to the target
NP_API_INTERN
bool _np_out_authentication_request(np_state_t* context, np_util_event_t msg_event);
NP_API_INTERN
bool _np_out_authentication_reply(np_state_t* context, np_util_event_t msg_event);

// send an authorization request to the target
NP_API_INTERN
bool _np_out_authorization_request(np_state_t* context, np_util_event_t msg_event);
NP_API_INTERN
bool _np_out_authorization_reply(np_state_t* context, np_util_event_t msg_event);

// send an accounting request to the target
NP_API_INTERN
bool _np_out_accounting_request(np_state_t* context, np_util_event_t msg_event);

#ifdef __cplusplus
}
#endif

#endif // _NP_AXON_H_
