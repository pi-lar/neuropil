//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project

#ifndef _NP_KEYCACHE_H_
#define _NP_KEYCACHE_H_

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "tree/tree.h"

#include "util/np_event.h"
#include "util/np_list.h"

#include "np_dhkey.h"
#include "np_key.h"
#include "np_memory.h"
#include "np_node.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// organize keys in a splay tree
// SPLAY_HEAD(st_keycache_s, np_key_s);
// SPLAY_PROTOTYPE(st_keycache_s, np_key_s, link, _np_key_cmp);
RB_HEAD(st_keycache_s, np_key_s);

RB_PROTOTYPE(st_keycache_s, np_key_s, link, _np_key_cmp)

NP_API_INTERN
bool _np_keycache_init(np_state_t *context);
NP_API_INTERN
void _np_keycache_destroy(np_state_t *context);

NP_API_INTERN
bool _np_keycache_exists_state(np_state_t               *context,
                               NP_UNUSED np_util_event_t args);

NP_API_INTERN
void _np_keycache_execute_event(np_state_t     *context,
                                np_dhkey_t      dhkey,
                                np_util_event_t event);

NP_API_INTERN
np_key_t *_np_keycache_find_or_create(np_state_t *context, np_dhkey_t key);

NP_API_INTERN
np_key_t *_np_keycache_create(np_state_t *context, np_dhkey_t search_dhkey);

NP_API_INTERN
np_key_t *_np_keycache_add(np_state_t *context, np_key_t *subject_key);

NP_API_INTERN
np_key_t *_np_keycache_find(np_state_t *context, np_dhkey_t key);

NP_API_INTERN
/**
 * @brief Checks if a given dhkey exists in the keycache and revives a read only
 * copy if possible.
 *
 * @param[in] context The application context.
 * @param[in] search_dhkey The dhkey to search for.
 * @param[out] readonly_buffer The buffer to save the read only data to. Set no
 * NULL if not needed.
 * @return True if the dhkey is available in the keycache. False if not.
 */
bool _np_keycache_exists(np_state_t  *context,
                         np_dhkey_t   search_dhkey,
                         np_key_ro_t *readonly_buffer);

NP_API_INTERN
np_key_t *_np_keycache_remove(np_state_t *context, np_dhkey_t key);

NP_API_INTERN
np_key_t *_np_keycache_find_deprecated(np_state_t *context);

// TODO: this needs to be refactored: closest distance clock- or
// counterclockwise ? will have an important effect on routing decisions
NP_API_INTERN
np_key_t *_np_keycache_find_closest_key_to(np_state_t *context,
                                           np_sll_t(np_key_ptr, list_of_keys),
                                           const np_dhkey_t *key);

NP_API_INTERN
void _np_keycache_sort_keys_cpm(np_sll_t(np_key_ptr, node_keys),
                                const np_dhkey_t *key);

NP_API_INTERN
void _np_keycache_sort_keys_kd(np_sll_t(np_key_ptr, list_of_keys),
                               const np_dhkey_t *key);

NP_API_INTERN
np_key_t *
_np_keycache_find_by_details(np_state_t         *context,
                             char               *details_container,
                             bool                search_myself,
                             enum np_node_status search_handshake_status,
                             bool                require_handshake_status,
                             bool                require_dns,
                             bool                require_port,
                             bool                require_hash);

NP_API_INTERN
sll_return(np_key_ptr) _np_keycache_get_all(np_state_t *context);

#ifdef __cplusplus
}
#endif

#endif /* _NP_KEYCACHE_H_ */
