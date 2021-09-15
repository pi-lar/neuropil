//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
///
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that an identity can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#ifndef _NP_COMP_NODE_H_
#define _NP_COMP_NODE_H_

#include "neuropil.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "np_network.h"
#include "np_node.h"
#include "np_aaatoken.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * a node component is the representation of an external physical node running on a distant os.
 * it resides in memory at the fingerprint dhkey of its token. usually it is used as an outbound
 * channel to send or forward messages. Is has a np_node_t and np_network_t structure attached,
 * which may be shared with its inbound counterpart, the alias component.
 */

// CHECKS
NP_API_INTERN
bool __is_node_authn(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_node_identity_authn(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_node_handshake_token(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_node_token(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_node_info(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
bool __is_node_join_nack(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_node_leave_message(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_node_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_wildcard_key(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_node_authn(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_set(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_set_node(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_wildcard_set(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_update(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_identity_upgrade(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_upgrade(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_update_token(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_handle_completion(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_node_add_to_leafset(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_remove_from_routing(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
bool __is_node_join(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_invalid_message(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_create_client_network (np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_wildcard_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_np_message(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_join_out_message(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
bool __is_handshake_message(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_send_direct(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_send_encrypted(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_discard_message(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_wildcard_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
bool __is_shutdown_event(np_util_statemachine_t* statemachine, const np_util_event_t event);
NP_API_INTERN
void __np_node_send_shutdown(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_node_handle_response(np_util_statemachine_t* statemachine, const np_util_event_t event);

#ifdef __cplusplus
}
#endif

#endif /* _NP_COMP_NODE_H_ */
