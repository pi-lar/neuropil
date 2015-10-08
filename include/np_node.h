/**
 *  copyright 2015 pi-lar GmbH
 *  original version was taken from chimera project (MIT licensed), but heavily modified
 *  Stephan Schwichtenberg
 **/

#ifndef _NP_NODE_H_
#define _NP_NODE_H_

#include <pthread.h>

#include "include.h"
#include "np_container.h"
#include "np_key.h"
#include "np_memory.h"
#include "np_network.h"

#define SUCCESS_WINDOW 20
#define GOOD_LINK 0.7
#define BAD_LINK 0.3

enum handshake_status {
	HANDSHAKE_UNKNOWN = 0,
	HANDSHAKE_INITIALIZED,
	HANDSHAKE_COMPLETE
};

struct np_node_s
{
	// link to memory management
	np_obj_t* obj;

	np_network_t* network;

	uint8_t protocol;
	char *dns_name;
    char* port;
    // uint32_t address;

    // state extension
    uint8_t handshake_status; // enum
    np_bool joined_network;   // TRUE / FALSE

	// statistics
    // int failed;
    double failuretime;
    // double last_loss;
    double last_success;
    double latency;
    double latency_win[SUCCESS_WINDOW];
    uint8_t latency_win_index;
    uint8_t success_win[SUCCESS_WINDOW];
    uint8_t success_win_index;
    float success_avg;

    // load average of the node
    float load;
};

// generate new and del method for np_node_t
_NP_GENERATE_MEMORY_PROTOTYPES(np_node_t);

/** np_node_update
 ** updates node hostname and port for a given node, without changing the hash
 **/
void np_node_update (np_node_t* node, uint8_t proto, char *hn, char* port);

/** np_node_update_stat
 ** updates the success rate to the np_node based on the SUCCESS_WINDOW average
 **/
void np_node_update_stat (np_node_t* np_node, uint8_t success);
void np_node_update_latency (np_node_t* node, double new_latency);

/** np_node_decode routines
 ** decodes a string into a neuropil np_node structure, including lookup to the global key tree
 **/
sll_return(np_key_t) np_decode_nodes_from_jrb (np_state_t* state, np_jtree_t* data);
np_key_t* np_node_decode_from_str (np_state_t* state, const char *key);
np_key_t*  np_node_decode_from_jrb (np_state_t* state, np_jtree_t* data);

/** np_node_encode routines
 **/
void np_node_encode_to_str  (char *s, uint16_t len, np_key_t* key);
uint16_t np_encode_nodes_to_jrb (np_jtree_t* data, np_sll_t(np_key_t, node_keys));
void np_node_encode_to_jrb  (np_jtree_t* data, np_key_t* np_node);

/** various getter method, mostly unused **/
char* np_node_get_dns_name (np_node_t* np_node);
// uint32_t np_node_get_address (np_node_t* np_node);
char* np_node_get_port (np_node_t* np_node);
float np_node_get_success_avg (np_node_t* np_node);
float np_node_get_latency (np_node_t* np_node);
uint8_t np_node_check_address_validity (np_node_t* np_node);

#endif /* _NP_NODE_H_ */
