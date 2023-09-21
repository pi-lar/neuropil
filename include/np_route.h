//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project
#ifndef _NP_ROUTE_H_
#define _NP_ROUTE_H_

#include "np_threads.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** route_init:
 ** Ininitiates routing table and leafsets.
 **
 **/
NP_API_INTERN
bool _np_route_init(np_state_t *context, np_key_t *me);
NP_API_INTERN
void _np_route_destroy(np_state_t *context);

/** _np_route_update:
 ** updates the routing table in regard to host. If the host is joining
 ** the network (and joined == 1), then it is added to the routing table
 ** if it is appropriate. If it is leaving the network (and joined == 0),
 ** then it is removed from the routing tables.
 **
 **/
NP_API_INTERN
void _np_route_leafset_update(np_key_t  *key,
                              bool       joined,
                              np_key_t **deleted,
                              np_key_t **added);

NP_API_INTERN
void _np_route_update(np_key_t  *key,
                      bool       joined,
                      np_key_t **deleted,
                      np_key_t **added);

NP_API_INTERN
void _np_route_clear(np_state_t *context);
NP_API_INTERN
void _np_route_leafset_clear(np_state_t *context);

/** _np_route_lookup:
 ** returns an list of 'count' nodes that are acceptable next hops for a message
 *being routed to key
 **
 **/
NP_API_INTERN
sll_return(np_key_ptr)
    _np_route_lookup(np_state_t *context, np_dhkey_t key, uint8_t count);

/** _np_route_neighbors:
 ** returns an list of neighbor nodes with priority to closer nodes.
 **
 **/
NP_API_INTERN
sll_return(np_key_ptr) _np_route_neighbors(np_state_t *context);

/** _np_route_row_lookup:
 ** return the row in the routing table that matches the longest prefix with
 *key.
 **
 **/
NP_API_INTERN
sll_return(np_key_ptr)
    _np_route_row_lookup(np_state_t *context, np_dhkey_t dhkey);
NP_API_INTERN
sll_return(np_key_ptr)
    _np_route_neighbour_lookup(np_state_t *context, np_dhkey_t dhkey);

/** route_get_table:
 ** returns all the entries in the routing table in an array of ChimeraHost.
 **
 **/
NP_API_INTERN
sll_return(np_key_ptr) _np_route_get_table(np_state_t *context);

NP_API_INTERN
void _np_route_leafset_insert(np_key_t  *host,
                              uint8_t    right_or_left,
                              np_key_t **deleted,
                              np_key_t **added);
NP_API_INTERN
void _np_route_leafset_delete(np_key_t  *host,
                              uint8_t    right_or_left,
                              np_key_t **deleted);
NP_API_INTERN
void _np_route_leafset_range_update(np_state_t *context);

NP_API_INTERN
bool _np_route_my_key_has_connection(np_state_t *context);
NP_API_INTERN
uint32_t _np_route_my_key_count_routes(np_state_t *context);
NP_API_INTERN
uint32_t _np_route_my_key_count_neighbors(np_state_t *context,
                                          uint32_t   *left,
                                          uint32_t   *right);
NP_API_INTERN
np_key_t *_np_route_get_key(np_state_t *context);
NP_API_INTERN
bool __np_route_periodic_log(np_state_t               *context,
                             NP_UNUSED np_util_event_t event);

#ifdef __cplusplus
}
#endif

#endif /* _NP_ROUTE_H_ */
