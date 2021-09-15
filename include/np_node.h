//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version was taken from chimera project, but modified
#ifndef _NP_NODE_H_
#define _NP_NODE_H_

#include <pthread.h>

#include "sodium.h"

#include "np_memory.h"

#include "np_types.h"
#include "np_network.h"
#include "np_threads.h"
#include "np_settings.h"
#include "np_constants.h"
#include "np_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

	enum np_node_status {
		np_status_Disconnected    = 0,
		np_status_SelfInitiated   = 1,
		np_status_RemoteInitiated = 1,
		np_status_Connected       = 2,
	};
	static const char* np_node_status_str[] = {
		"Disconnected",
		"SelfInitiated",
		"RemoteInitiated",
		"Connected",
	};


struct np_node_s
{
	char *host_key;
	enum socket_type protocol;
	char *dns_name;
	char* port;

	// state extension
	enum np_node_status _handshake_status;
	double handshake_send_at;
	uint32_t handshake_priority;

	enum np_node_status _joined_status;
	double join_send_at;
	bool joined_network;

	uint8_t connection_attempts;

	np_crypto_session_t session;
	bool session_key_is_set;

	double next_routing_table_update;
	bool is_in_routing_table;
	bool is_in_leafset;

	// statistics
	double last_success;

	double latency;
	double latency_win[NP_NODE_SUCCESS_WINDOW];
	uint8_t latency_win_index;

	uint8_t success_win[NP_NODE_SUCCESS_WINDOW];
	uint8_t success_win_index;
	float success_avg;

	// load average of the node
	float load;

} NP_API_INTERN;

// generate new and del method for np_node_t
_NP_GENERATE_MEMORY_PROTOTYPES(np_node_t);

/** _np_node_update
 ** updates node hostname and port for a given node, without changing the hash
 **
 **/
NP_API_INTERN
void _np_node_update (np_node_t* node, enum socket_type proto, char *hn, char* port);

/** _np_node_update_stat
 ** updates the success rate to the np_node based on the NP_NODE_SUCCESS_WINDOW average
 **
 **/
NP_API_INTERN
np_node_t* _np_node_from_token(np_handshake_token_t* token, np_aaatoken_type_e expected_type);
/** np_node_decode routines
 ** decodes a string into a neuropil np_node structure, including lookup to the global key tree
 **
 **/
NP_API_INTERN
np_node_t* _np_node_decode_from_str (np_state_t* context, const char *key);

NP_API_INTERN
sll_return(np_node_ptr) _np_node_decode_multiple_from_jrb (np_state_t* context, np_tree_t* data);

NP_API_INTERN
np_node_t*  _np_node_decode_from_jrb (np_state_t* context, np_tree_t* data);

/** np_node_encode routines
 **/
NP_API_INTERN
uint16_t _np_node_encode_multiple_to_jrb (np_tree_t* data, np_sll_t(np_key_ptr, node_keys), bool include_stats);

NP_API_INTERN
void _np_node_encode_to_jrb  (np_tree_t* data, np_key_t* node_key, bool include_stats);

/** various getter method, mostly unused **/
NP_API_INTERN
char* _np_node_get_dns_name (np_node_t* np_node);

NP_API_INTERN
char* _np_node_get_port (np_node_t* np_node);

NP_API_INTERN
uint8_t _np_node_check_address_validity (np_node_t* np_node);
NP_API_INTERN
int _np_node_cmp(np_node_t* a, np_node_t* b);

#ifdef __cplusplus
}
#endif

#endif /* _NP_NODE_H_ */
