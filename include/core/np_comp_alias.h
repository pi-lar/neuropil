//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that an identity can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#ifndef _NP_COMP_ALIAS_H_
#define _NP_COMP_ALIAS_H_


#include "neuropil.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * a alias component is the representation of an external physical node running on a distant os.
 * it resides in memory at the dhkey composed by using the incoming IP/Port. usually it is used as
 * an inbound channel to receive and decrypt messages. it has a np_node_t and np_network_t
 * structure which can be shared with it outound counterpart, the node component.
 */

NP_API_INTERN
bool __is_alias_handshake_token(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_alias_set(np_util_statemachine_t* statemachine, const np_util_event_t event); // handle external received handsjake token

NP_API_INTERN
bool __is_alias_node_info(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_HIDDEN
void __np_alias_set_node(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_create_session(np_util_statemachine_t* statemachine, const np_util_event_t event); // create node as well and "steal" network sructure

NP_API_INTERN
bool __is_join_in_message(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
bool __is_crypted_message(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_alias_decrypt(np_util_statemachine_t* statemachine, const np_util_event_t event); // decrypt transport encryption

NP_API_INTERN
bool __is_discovery_message(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_dht_message(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_handle_np_message(np_util_statemachine_t* statemachine, const np_util_event_t event); // handle ght messages (ping, piggy, ...)
NP_API_INTERN
bool __is_pheromone_message(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_handle_pheromone(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_handle_np_discovery(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_handle_np_forward(np_util_statemachine_t* statemachine, const np_util_event_t event); // handle ght messages (dicovery, ...)
NP_API_INTERN
bool __is_forward_message(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
bool __is_usr_in_message(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
bool __is_usr_message(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_handle_usr_msg(np_util_statemachine_t* statemachine, const np_util_event_t event); // pass on to the specific message intent

NP_API_INTERN
bool __is_alias_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_alias_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event); // handle external received handsjake token

NP_API_INTERN
void __np_alias_shutdown(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_alias_update(np_util_statemachine_t* statemachine, const np_util_event_t event);


#ifdef __cplusplus
}
#endif

#endif /* _NP_COMP_ALIAS_H_ */

