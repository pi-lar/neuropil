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

#include "key.h"

#define SUCCESS_WINDOW 20
#define GOOD_LINK 0.8
#define BAD_LINK 0.3

struct np_nodecache_s
{
    np_jrb_t* np_node_cache;
    // dllist dll_free_nodes;
    int size;
    int max;
    pthread_mutex_t lock;
};

struct np_node_s
{
    // char *sha1_name;
    char *dns_name;
    unsigned long address;
    int port;
    np_key_t* key;

    // crypto extension
    int handshake_complete;

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

/** np_node_create:
 ** updates node hostname and port for a given node, without changing the hash
 **/
void np_node_update (np_node_t* node, char *hn, int port);

/** np_node_release:
 ** releases a np_node from the cache, declaring that the memory could be
 ** freed any time.
 **/
void np_node_release (np_nodecache_t* ng, np_key_t* key);

/** np_node_decode:
 ** decodes a string into a chimera np_node structure. This acts as a
 ** np_node_get, and should be followed eventually by a np_node_release.
 **/
np_node_t* np_node_decode_from_str (np_nodecache_t* ng, const char *s);
np_node_t* np_node_decode_from_amqp (np_nodecache_t* gn, np_jrb_t* data);
np_node_t** np_decode_nodes_from_amqp (np_nodecache_t* gn, np_jrb_t* data);

/** np_node_encode:
 ** encodes the #np_node# into a string, putting it in #s#, which has
 ** #len# bytes in it.
 **/
void np_node_encode_to_str (char *s, int len, np_node_t* np_node);
void np_node_encode_to_amqp (np_jrb_t* data, np_node_t* np_node);
int np_encode_nodes_to_amqp (np_jrb_t* data, np_node_t** host);

/** np_node_update_stat:
 ** updates the success rate to the np_node based on the SUCCESS_WINDOW average
 **/
void np_node_update_stat (np_node_t* np_node, int success);

/** various getter method */
np_key_t* np_node_get_key(np_node_t* node);
char* np_node_get_dns_name (np_node_t* np_node);
unsigned long np_node_get_address (np_node_t* np_node);
int np_node_get_port (np_node_t* np_node);
float np_node_get_success_avg (np_node_t* np_node);
float np_node_get_latency (np_node_t* np_node);
int np_node_check_address_validity (np_node_t* np_node);

/** np_node_lookup _
 ** find node structure for a given key
 **/
np_node_t* np_node_lookup(np_nodecache_t* ng, np_key_t* key, int inc_ref_count);
int np_node_exists(np_nodecache_t* ng, np_key_t* key);

#endif /* _NP_NODE_H_ */
