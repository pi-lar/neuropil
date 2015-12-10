/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_DENDRIT_H_
#define _NP_DENDRIT_H_

#include "neuropil.h"
#include "np_jobqueue.h"

#ifdef __cplusplus
extern "C" {
#endif

// input message handlers
void hnd_msg_in_handshake(np_state_t* state, np_jobargs_t* args);

void hnd_msg_in_received (np_state_t* state, np_jobargs_t* args);

void hnd_msg_in_ping(np_state_t* state, np_jobargs_t* args);
void hnd_msg_in_pingreply(np_state_t* state, np_jobargs_t* args);

void hnd_msg_in_piggy (np_state_t* state, np_jobargs_t* args);
void hnd_msg_in_join_req(np_state_t*, np_jobargs_t* args);
void hnd_msg_in_join_ack (np_state_t* state, np_jobargs_t* args);
void hnd_msg_in_join_nack (np_state_t* state, np_jobargs_t* args);

void hnd_msg_in_update (np_state_t* state, np_jobargs_t* args);

void hnd_msg_in_interest(np_state_t* state, np_jobargs_t* args);
void hnd_msg_in_available(np_state_t* state, np_jobargs_t* args);

void hnd_msg_in_authenticate(np_state_t* state, np_jobargs_t* args);
void hnd_msg_in_authenticate_reply(np_state_t* state, np_jobargs_t* args);

void hnd_msg_in_authorize(np_state_t* state, np_jobargs_t* args);
void hnd_msg_in_authorize_reply(np_state_t* state, np_jobargs_t* args);

void hnd_msg_in_account(np_state_t* state, np_jobargs_t* args);
void hnd_msg_in_account_reply(np_state_t* state, np_jobargs_t* args);

void np_signal (np_state_t* state, np_jobargs_t* args);
void np_callback_wrapper(np_state_t* state, np_jobargs_t* args);


#ifdef __cplusplus
}
#endif

#endif // _NP_HANDLER_H_
