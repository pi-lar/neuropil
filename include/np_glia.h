/**
 *  copyright 2015 pi-lar GmbH
 *  original version was taken from chimera project (MIT licensed), but heavily modified
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_GLIA_H_
#define _NP_GLIA_H_

#include "include.h"

#ifdef __cplusplus
extern "C" {
#endif

void np_route_lookup (np_state_t* state, np_jobargs_t* args);

// critical self invoking functions
void _np_check_leafset(np_state_t* state, np_jobargs_t* args);
void _np_retransmit_tokens(np_state_t* state, np_jobargs_t* args);
void _np_cleanup(np_state_t* state, np_jobargs_t* args);
void _np_network_read(np_state_t* np_state, np_jobargs_t* args);
void _np_write_log(np_state_t* state, np_jobargs_t* args);

// other helper functions
void _np_send_rowinfo (np_state_t* state, np_jobargs_t* args);

void _np_send_msg_interest(np_state_t* state, const char* subject);
void _np_send_msg_availability(np_state_t* state, const char* subject);

np_bool _np_send_msg (np_state_t* state, char* subject, np_message_t* msg, np_msgproperty_t* msg_prop);

#ifdef __cplusplus
}
#endif

#endif // _NP_GLIA_H_
