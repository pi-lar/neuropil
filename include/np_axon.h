//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_AXON_H_
#define _NP_AXON_H_

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif
// sends a handshake message to the target node, assumes physical neighbourhood
NP_API_INTERN
void _np_out_handshake(np_jobargs_t* args); 
// splits up message into parts and sends all parts to the next node
NP_API_INTERN
void _np_out (np_jobargs_t* args);
// send an acknowledgement to the target node
NP_API_INTERN
void _np_out_ack (np_jobargs_t* args);

// void _np_out_sender_discovery(np_msgproperty_t* msg_prop, np_key_t* target);
NP_API_INTERN
void _np_out_sender_discovery(np_jobargs_t* args);
// void _np_out_receiver_discovery(np_msgproperty_t* msg_prop, np_key_t* target);
NP_API_INTERN
void _np_out_receiver_discovery(np_jobargs_t* args);

NP_API_INTERN
void _np_out_discovery_messages(np_jobargs_t* args);

// send an authentication request to the target
NP_API_INTERN
void _np_out_authentication_request(np_jobargs_t* args);
NP_API_INTERN
void _np_out_authentication_reply(np_jobargs_t* args);

// send an authorization request to the target
NP_API_INTERN
void _np_out_authorization_request(np_jobargs_t* args);
NP_API_INTERN
void _np_out_authorization_reply(np_jobargs_t* args);

// send an accounting request to the target
NP_API_INTERN
void _np_out_accounting_request(np_jobargs_t* args);

#ifdef __cplusplus
}
#endif

#endif // _NP_AXON_H_
