//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_KEYCACHE_H_
#define _NP_KEYCACHE_H_

#include <limits.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "tree/tree.h"

#include "np_key.h"
#include "np_memory.h"
#include "np_types.h"
#include "np_node.h"

#ifdef __cplusplus
extern "C" {
#endif

struct np_key_s
{
    np_obj_t* obj;              // link to memory management and ref counter
    SPLAY_ENTRY(np_key_s) link; // link for cache management

    np_dhkey_t dhkey;
    double last_update;
    char*      dhkey_str;

    np_node_t*    node;		    // link to a neuropil node if this key represents a node
    np_network_t* network;	    // link to a neuropil network if this key represents a node

    np_pll_t(np_aaatoken_ptr, local_mx_tokens); // link to runtime interest data on which this node is interested in

    // required structure if this node becomes a mitm for message exchange
    np_msgproperty_t* recv_property;
    np_msgproperty_t* send_property;

    np_pll_t(np_aaatoken_ptr, recv_tokens); // link to runtime interest data on which this node is interested in
    np_pll_t(np_aaatoken_ptr, send_tokens); // link to runtime interest data on which this node is interested in

    np_aaatoken_t* aaa_token; // link to aaatoken for this key (if it exists)
} NP_API_INTERN;

_NP_ENABLE_MODULE_LOCK(np_keycache_t);
_NP_GENERATE_MEMORY_PROTOTYPES(np_key_t);

// organize keys in a splay tree
NP_API_INTERN
int8_t __key_comp (const np_key_t* k1, const np_key_t* k2);

SPLAY_HEAD(st_keycache_s, np_key_s);
SPLAY_PROTOTYPE(st_keycache_s, np_key_s, link, __key_comp);

NP_API_INTERN
void _np_keycache_init();

NP_API_INTERN
np_key_t* _np_key_find_create(np_dhkey_t key);

NP_API_INTERN
np_key_t* _np_key_create(np_dhkey_t search_dhkey);

NP_API_INTERN
np_key_t* _np_key_add(np_key_t* subject_key);

NP_API_INTERN
np_key_t* _np_key_find(np_dhkey_t key);

NP_API_INTERN
np_key_t* _np_key_remove(np_dhkey_t key);

NP_API_INTERN
np_key_t* _np_key_find_deprecated();

NP_API_INTERN
char* _key_as_str(np_key_t * key);

// TODO: this needs to be refactored: closest distance clock- or counterclockwise ?
// will have an important effect on routing decisions
NP_API_INTERN
np_key_t* _np_find_closest_key (np_sll_t(np_key_t, list_of_keys), const np_dhkey_t* key);

NP_API_INTERN
void _np_sort_keys_cpm (np_sll_t(np_key_t, node_keys), const np_dhkey_t* key);

NP_API_INTERN
void _np_sort_keys_kd (np_sll_t(np_key_t, list_of_keys), const np_dhkey_t* key);

NP_API_INTERN
np_key_t* _np_key_find_by_details(char* details_container, np_bool search_myself, handshake_status_e handshake_status, np_bool require_handshake_status, np_bool require_dns,np_bool require_port,np_bool require_hash );

NP_API_INTERN
np_key_t* _np_key_find_by_dhkey(const np_dhkey_t dhkey);

NP_API_INTERN
void _np_ref_keys (np_sll_t(np_key_t, list_of_keys));
NP_API_INTERN
void _np_unref_keys (np_sll_t(np_key_t, list_of_keys));

NP_API_INTERN
int8_t _np_key_cmp(const np_key_t* const k1, const np_key_t* const k2);
NP_API_INTERN
int8_t _np_key_cmp_inv(const np_key_t* const k1, const np_key_t* const k2);


#ifdef __cplusplus
}
#endif

#endif /* _NP_KEYCACHE_H_ */
