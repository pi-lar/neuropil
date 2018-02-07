//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
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
np_bool _np_route_init (np_key_t* me);

NP_API_INTERN
void _np_route_set_key (np_key_t* new_node_key);

/** _np_route_update:
 ** updates the routing table in regard to host. If the host is joining
 ** the network (and joined == 1), then it is added to the routing table
 ** if it is appropriate. If it is leaving the network (and joined == 0),
 ** then it is removed from the routing tables.
 **
 **/
NP_API_INTERN
void _np_route_leafset_update (np_key_t* key, np_bool joined, np_key_t** deleted, np_key_t** added);

NP_API_INTERN
void _np_route_update (np_key_t* key, np_bool joined, np_key_t** deleted, np_key_t** added);

NP_API_INTERN
void _np_route_clear ();
NP_API_INTERN
void _np_route_leafset_clear ();


/** _np_route_lookup:
 ** returns an list of 'count' nodes that are acceptable next hops for a message being routed to key
 **
 **/
NP_API_INTERN
sll_return(np_key_ptr) _np_route_lookup (np_dhkey_t key, uint8_t count);
// np_key_t** _np_route_lookup (np_state_t* state, np_key_t* key, int count, int is_safe);

/** _np_route_neighbors:
 ** returns an list of neighbor nodes with priority to closer nodes.
 **
 **/
NP_API_INTERN
sll_return(np_key_ptr) _np_route_neighbors ();

/** _np_route_row_lookup:
 ** return the row in the routing table that matches the longest prefix with key.
 **
 **/
NP_API_INTERN
sll_return(np_key_ptr) _np_route_row_lookup (np_key_t* key);

/** route_get_table:
 ** returns all the entries in the routing table in an array of ChimeraHost.
 **
 **/
NP_API_INTERN
sll_return(np_key_ptr) _np_route_get_table ();

NP_API_INTERN
void _np_route_leafset_insert (np_key_t* host, uint8_t right_or_left, np_key_t** deleted, np_key_t** added);
NP_API_INTERN
void _np_route_leafset_delete (np_key_t* host, uint8_t right_or_left, np_key_t** deleted);
NP_API_INTERN
void _np_route_leafset_range_update ();

NP_API_EXPORT
char* np_route_get_bootstrap_connection_string();
NP_API_EXPORT
void np_route_set_bootstrap_key(np_key_t* bootstrapKey);

NP_API_INTERN
void _np_route_rejoin_bootstrap(np_bool force);
NP_API_INTERN
void _np_route_check_for_joined_network();
NP_API_INTERN
np_bool _np_route_my_key_has_connection();
NP_API_INTERN
uint32_t _np_route_my_key_count_routes();
NP_API_INTERN
uint32_t _np_route_my_key_count_neighbours();
NP_API_INTERN
np_key_t* _np_route_get_key();
#ifdef __cplusplus
}
#endif


#endif /* _NP_ROUTE_H_ */
