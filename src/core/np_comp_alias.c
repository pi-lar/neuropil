//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that an identity can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include "core/np_comp_alias.h"

#include "neuropil.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"


bool __is_alias_handshake_token(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_alias_set(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // handle external received handsjake token

void __np_create_session(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // create node as well and "steal" network sructure
 
bool __is_msg_join_ack(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_node_transfer_session(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // join acknowledge

bool __is_msg_join_nack(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_node_handle_leave(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // join hasn't been acknowledged, drop everything

bool __is_crypted_message(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_alias_decrypt(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // decrypt transport encryption

bool __is_dht_message(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_handle_np_message(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // handle ght messages (ping, piggy, ...)

bool __is_usr_message(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_handle_usr_msg(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // pass on to the specific message intent

bool __is_leave_message(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_handle_leave_msg(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // node has left, invalidate node


