/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_AXON_H_
#define _NP_AXON_H_

#include "include.h"

// out message handlers
void hnd_msg_out_ack (np_state_t* state, np_jobargs_t* args);
void hnd_msg_out_send (np_state_t* state, np_jobargs_t* args);

void hnd_msg_out_handshake(np_state_t* state, np_jobargs_t* args);

// default message handlers
// NONE YET

#endif // _NP_AXON_H_
