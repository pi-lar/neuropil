/*
 * ** $Id: np_node.h,v 1.15 2006/06/07 09:21:28 krishnap Exp $
 * **
 * ** Matthew Allen
 * ** description: 
 * */

#ifndef _NP_NODE_H_
#define _NP_NODE_H_

#include <pthread.h>

#include "include.h"

#include "np_memory.h"
#include "key.h"

#define SUCCESS_WINDOW 20
#define GOOD_LINK 0.8
#define BAD_LINK 0.3

enum handshake_status {
	HANDSHAKE_UNKNOWN = 0,
	HANDSHAKE_INITIALIZED,
	HANDSHAKE_COMPLETE
};

struct np_nodecache_s
{
    np_jrb_t* np_node_cache;
    int size;
    int max;

    pthread_mutex_t lock;
};

struct np_node_s
{
    np_key_t* key;

    char *dns_name;
    unsigned long address;
    int port;

    // crypto extension
    int handshake_status;

	// statistics
    int failed;
    double failuretime;
    double latency;
    double loss;
    double success;
    int success_win[SUCCESS_WINDOW];
    int success_win_index;
    float success_avg;
    // reference counter
    int ref_count;
    // load
    float load;

    // back pointer to global node cache structures
    np_nodecache_t* node_tree;
};

/** np_node_cache_create:
 ** initialize a np_node struct with a #size# element cache.
 **/
np_nodecache_t* np_node_cache_create (int size);


// generate new and del method for np_node_t
_NP_GENERATE_MEMORY_PROTOTYPES(np_node_t);

// PUBLIC //
/** np_node_release:
 ** releases a np_node from the cache, declaring that the memory could be
 ** freed any time.
 **/
void np_node_release (np_nodecache_t* ng, np_key_t* key);

/** np_node_lookup _
 ** find node structure for a given key
 **/
np_obj_t* np_node_lookup(np_nodecache_t* ng, np_key_t* key, int increase_ref_count);
int np_node_exists(np_nodecache_t* ng, np_key_t* key);


// PROTECTED // DO A NP_BIND BEFORE USING THEM

/** np_node_update:
 ** updates node hostname and port for a given node, without changing the hash
 **/
void np_node_update (np_node_t* node, char *hn, int port);
/** np_node_update_stat:
 ** updates the success rate to the np_node based on the SUCCESS_WINDOW average
 **/
void np_node_update_stat (np_node_t* np_node, int success);

/** np_node_decode:
 ** decodes a string into a chimera np_node structure. This acts as a
 ** np_node_get, and should be followed eventually by a np_node_release.
 **/
np_obj_t*  np_node_decode_from_str (np_nodecache_t* nc, const char *s);
np_obj_t*  np_node_decode_from_jrb (np_nodecache_t* nc, np_jrb_t* data);
np_obj_t** np_decode_nodes_from_jrb (np_nodecache_t* nc, np_jrb_t* data);

/** np_node_encode:
 ** encodes the #np_node# into a string, putting it in #s#, which has
 ** #len# bytes in it.
 **/
void np_node_encode_to_str  (char *s, int len, np_node_t* np_node);
void np_node_encode_to_jrb  (np_jrb_t* data, np_node_t* np_node);
int  np_encode_nodes_to_jrb (np_nodecache_t* nc, np_jrb_t* data, np_key_t** node_keys);

/** various getter method */
np_key_t* np_node_get_key(np_node_t* node);
char* np_node_get_dns_name (np_node_t* np_node);
unsigned long np_node_get_address (np_node_t* np_node);
int np_node_get_port (np_node_t* np_node);
float np_node_get_success_avg (np_node_t* np_node);
float np_node_get_latency (np_node_t* np_node);
int np_node_check_address_validity (np_node_t* np_node);


#endif /* _NP_NODE_H_ */
