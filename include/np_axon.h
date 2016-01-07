/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_AXON_H_
#define _NP_AXON_H_

#include "include.h"

#ifdef __cplusplus
extern "C" {
#endif

// send and acknowledgement to the target node
void hnd_msg_out_ack (np_state_t* state, np_jobargs_t* args);

// splits up message into parts and sends all parts to teh target node
void hnd_msg_out_send (np_state_t* state, np_jobargs_t* args);

// sends a handshake message to the target node, assumes physical neighbourhood
void hnd_msg_out_handshake(np_state_t* state, np_jobargs_t* args);

#ifdef __cplusplus
}
#endif

#endif // _NP_AXON_H_
