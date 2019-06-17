//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
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
// sends a handshake message to the target node, assumes physical neighbourhood
NP_API_INTERN
void _np_out_handshake(np_state_t* context, const np_util_event_t event);
// void _np_out_handshake(np_state_t* context, np_util_event_t msg_event); 

NP_API_INTERN
void _np_out_join_req(np_state_t* context, const np_util_event_t event);

// splits up message into parts and sends all parts to the next node
NP_API_INTERN
void _np_out (np_state_t* context, np_util_event_t msg_event);

// send an acknowledgement to the target node
NP_API_INTERN
void _np_out_ack (np_state_t* context, np_util_event_t msg_event);

// void _np_out_sender_discovery(np_msgproperty_t* msg_prop, np_key_t* target);
NP_API_INTERN
void _np_out_sender_discovery(np_state_t* context, np_util_event_t msg_event);
// void _np_out_receiver_discovery(np_msgproperty_t* msg_prop, np_key_t* target);

NP_API_INTERN
void _np_out_receiver_discovery(np_state_t* context, np_util_event_t msg_event);

NP_API_INTERN
void _np_out_discovery_messages(np_state_t* context, np_util_event_t msg_event);

// send an authentication request to the target
NP_API_INTERN
void _np_out_authentication_request(np_state_t* context, np_util_event_t msg_event);
NP_API_INTERN
void _np_out_authentication_reply(np_state_t* context, np_util_event_t msg_event);

// send an authorization request to the target
NP_API_INTERN
void _np_out_authorization_request(np_state_t* context, np_util_event_t msg_event);
NP_API_INTERN
void _np_out_authorization_reply(np_state_t* context, np_util_event_t msg_event);

// send an accounting request to the target
NP_API_INTERN
void _np_out_accounting_request(np_state_t* context, np_util_event_t msg_event);

#ifdef __cplusplus
}
#endif

#endif // _NP_AXON_H_
