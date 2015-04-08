#ifndef _NP_GLIA_H_
#define _NP_GLIA_H_

#include "include.h"

// critical self incarnation functions
void np_check_leafset(np_state_t* state, np_jobargs_t* args);
void np_retransmit_messages(np_state_t* state, np_jobargs_t* args);
void np_network_read(np_state_t* np_state, np_jobargs_t* args);

// other helper functions
void np_send_rowinfo (np_state_t* state, np_jobargs_t* args);
void np_route_lookup (np_state_t* state, np_jobargs_t* args);

void np_send_msg_interest(const np_state_t* state, np_msginterest_t* interest);
void np_send_msg_availability(const np_state_t* state, np_msginterest_t* available);

#endif // _NP_GLIA_H_
