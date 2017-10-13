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

#include "np_dhkey.h"
#include "np_memory.h"
#include "np_types.h"
#include "np_node.h"
#include "np_key.h"
#include "np_list.h"

#ifdef __cplusplus
extern "C" {
#endif


// organize keys in a splay tree
SPLAY_HEAD(st_keycache_s, np_key_s);
SPLAY_PROTOTYPE(st_keycache_s, np_key_s, link, _np_key_cmp);

NP_API_INTERN
void _np_keycache_init();

NP_API_INTERN
np_key_t* _np_keycache_find_or_create(np_dhkey_t key);

NP_API_INTERN
np_key_t* _np_keycache_create(np_dhkey_t search_dhkey);

NP_API_INTERN
np_key_t* _np_keycache_add(np_key_t* subject_key);

NP_API_INTERN
np_key_t* _np_keycache_find(np_dhkey_t key);

NP_API_INTERN
np_key_t* _np_keycache_remove(np_dhkey_t key);

NP_API_INTERN
np_key_t* _np_keycache_find_deprecated();

NP_API_INTERN
sll_return(np_key_ptr) _np_keycache_find_aliase(np_key_t* forKey);

// TODO: this needs to be refactored: closest distance clock- or counterclockwise ?
// will have an important effect on routing decisions
NP_API_INTERN
np_key_t* _np_keycache_find_closest_key_to (np_sll_t(np_key_ptr, list_of_keys), const np_dhkey_t* key);

NP_API_INTERN
void _np_keycache_sort_keys_cpm (np_sll_t(np_key_ptr, node_keys), const np_dhkey_t* key);

NP_API_INTERN
void _np_keycache_sort_keys_kd (np_sll_t(np_key_ptr, list_of_keys), const np_dhkey_t* key);

NP_API_INTERN
np_key_t* _np_keycache_find_by_details(
	char* details_container, np_bool search_myself, np_bool is_handshake_send, 
	np_bool is_handshake_received, np_bool require_handshake_status, 
	np_bool require_dns, np_bool require_port, np_bool require_hash );

NP_API_INTERN
sll_return(np_key_ptr) _np_keycache_get_all();


#ifdef __cplusplus
}
#endif

#endif /* _NP_KEYCACHE_H_ */
