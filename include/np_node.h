//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version was taken from chimera project, but modified
#ifndef _NP_NODE_H_
#define _NP_NODE_H_

#include <pthread.h>

#include "sodium.h"

#include "np_memory.h"
#include "np_types.h"
#include "np_threads.h"
#include "np_settings.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SUCCESS_WINDOW 20

struct np_node_s
{
	// link to memory management
	np_obj_t* obj;
	np_mutex_t lock;

	uint8_t protocol;
	char *dns_name;
	char* port;

	// state extension
	np_bool is_handshake_send;
	np_bool is_handshake_received;
	np_bool joined_network;   // TRUE / FALSE
	unsigned char session_key[crypto_scalarmult_SCALARBYTES];
	np_bool session_key_is_set;

	// statistics
	double failuretime;
	double last_success;
	double latency;
	double latency_win[SUCCESS_WINDOW];
	uint8_t latency_win_index;
	uint8_t success_win[SUCCESS_WINDOW];
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
void _np_node_update (np_node_t* node, uint8_t proto, char *hn, char* port);

/** _np_node_update_stat
 ** updates the success rate to the np_node based on the SUCCESS_WINDOW average
 **
 **/
NP_API_INTERN
void _np_node_update_stat (np_node_t* np_node, uint8_t success);
NP_API_INTERN
void _np_node_update_latency (np_node_t* node, double new_latency);

/** np_node_decode routines
 ** decodes a string into a neuropil np_node structure, including lookup to the global key tree
 **
 **/
NP_API_INTERN
np_key_t* _np_node_decode_from_str (const char *key);

NP_API_INTERN
sll_return(np_key_ptr) _np_node_decode_multiple_from_jrb (np_tree_t* data);

NP_API_INTERN
np_node_t*  _np_node_decode_from_jrb (np_tree_t* data);

/** np_node_encode routines
 **/
NP_API_INTERN
void _np_node_encode_to_str  (char *s, uint16_t len, np_key_t* key);

NP_API_INTERN
uint16_t _np_node_encode_multiple_to_jrb (np_tree_t* data, np_sll_t(np_key_ptr, node_keys), np_bool include_stats);

NP_API_INTERN
void _np_node_encode_to_jrb  (np_tree_t* data, np_key_t* node_key, np_bool include_stats);

/** np_node aaa_token routines
 **/
NP_API_INTERN
np_aaatoken_t* _np_node_create_token(np_node_t* node);

NP_API_INTERN
np_key_t* _np_key_create_from_token(np_aaatoken_t* token);

/** various getter method, mostly unused **/
NP_API_INTERN
char* _np_node_get_dns_name (np_node_t* np_node);

NP_API_INTERN
char* _np_node_get_port (np_node_t* np_node);

NP_API_INTERN
float _np_node_get_success_avg (np_node_t* np_node);

NP_API_INTERN
float _np_node_get_latency (np_node_t* np_node);

NP_API_INTERN
uint8_t _np_node_check_address_validity (np_node_t* np_node);

#ifdef __cplusplus
}
#endif

#endif /* _NP_NODE_H_ */
