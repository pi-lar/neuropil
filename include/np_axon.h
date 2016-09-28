/**
 *  neuropil is copyright 2015 by pi-lar GmbH
 */
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
void _np_out_send (np_jobargs_t* args);
// send an acknowledgement to the target node
NP_API_INTERN
void _np_out_ack (np_jobargs_t* args);

// void _np_send_sender_discovery(np_msgproperty_t* msg_prop, np_key_t* target);
NP_API_INTERN
void _np_send_sender_discovery(np_jobargs_t* args);
// void _np_send_receiver_discovery(np_msgproperty_t* msg_prop, np_key_t* target);
NP_API_INTERN
void _np_send_receiver_discovery(np_jobargs_t* args);

// send an authentication request to the target
NP_API_INTERN
void np_send_authentication_request(np_jobargs_t* args);
NP_API_INTERN
void np_send_authentication_reply(np_jobargs_t* args);

// send an authorization request to the target
NP_API_INTERN
void np_send_authorization_request(np_jobargs_t* args);
NP_API_INTERN
void np_send_authorization_reply(np_jobargs_t* args);

// send an accounting request to the target
NP_API_INTERN
void np_send_accounting_request(np_jobargs_t* args);


#ifdef __cplusplus
}
#endif

#endif // _NP_AXON_H_
