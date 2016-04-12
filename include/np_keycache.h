/**
 *  copyright 2015 pi-lar GmbH
 *  original version was taken from chimera project (MIT licensed), but heavily modified
 *  Stephan Schwichtenberg
 **/

#ifndef _NP_KEYCACHE_H_
#define _NP_KEYCACHE_H_

#include <limits.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "include.h"

#include "np_container.h"
#include "np_memory.h"
#include "np_jtree.h"
#include "np_key.h"

#ifdef __cplusplus
extern "C" {
#endif

struct np_key_s
{
    np_obj_t* obj;              // link to memory management and ref counter
    SPLAY_ENTRY(np_key_s) link; // link for cache management

    np_dhkey_t dhkey;
    char*      dhkey_str;

    np_node_t*    node;		    // link to a neuropil node if this key represents a node
    np_network_t* network;	    // link to a neuropil network if this key represents a node

    // required structure if this node becomes a mitm for message exchange
    np_msgproperty_t* recv_property;
    np_msgproperty_t* send_property;

    np_pll_t(np_aaatoken_ptr, recv_tokens); // link to runtime interest data on which this node is interested in
    np_pll_t(np_aaatoken_ptr, send_tokens); // link to runtime interest data on which this node is interested in

    np_aaatoken_t* aaa_token; // link to aaatoken for this key (if it exists)
};

// organize keys in a splay tree
int8_t __key_comp (const np_key_t* k1, const np_key_t* k2);

SPLAY_HEAD(st_keycache_s, np_key_s);
SPLAY_PROTOTYPE(st_keycache_s, np_key_s, link, __key_comp);

_NP_ENABLE_MODULE_LOCK(np_keycache_t);

_NP_GENERATE_MEMORY_PROTOTYPES(np_key_t);

void _np_keycache_init();

np_key_t* _np_key_find_create(np_dhkey_t key);
np_key_t* _np_key_find(np_dhkey_t key);
np_key_t* _np_key_remove(np_dhkey_t key);

char* _key_as_str(np_key_t * key);

// TODO: this needs to be refactored: closest distance clock- or counterclockwise ?
// will have an important effect on routing decisions
np_key_t* find_closest_key (np_sll_t(np_key_t, list_of_keys), const np_dhkey_t* key);
void sort_keys_cpm (np_sll_t(np_key_t, node_keys), const np_dhkey_t* key);
void sort_keys_kd (np_sll_t(np_key_t, list_of_keys), const np_dhkey_t* key);

#ifdef __cplusplus
}
#endif

#endif /* _NP_KEYCACHE_H_ */
