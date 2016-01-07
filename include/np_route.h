/**
 *  copyright 2015 pi-lar GmbH
 *  original version was taken from chimera project (MIT licensed), but heavily modified
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_ROUTE_H_
#define _NP_ROUTE_H_

#include "include.h"

#include "neuropil.h"
#include "np_container.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ROW 64 // length of key
#define MAX_COL 16 // 16 different characters
#define MAX_ENTRY 3 // three alternatives for each key

#define LEAFSET_SIZE 8		/* (must be even) excluding node itself */

typedef struct np_routeglobal_t
{
    np_key_t**** table;
    np_key_t** leftleafset;
    np_key_t** rightleafset;

    np_key_t Rrange;
    np_key_t Lrange;

    pthread_mutex_t lock;
    pthread_attr_t attr;
    pthread_t tid;

} *np_routeglobal;


/** route_init:
 ** Ininitiates routing table and leafsets.
 **/
np_routeglobal_t* route_init (np_key_t* me);

/** route_update:
 ** updates the routing table in regard to host. If the host is joining
 ** the network (and joined == 1), then it is added to the routing table
 ** if it is appropriate. If it is leaving the network (and joined == 0),
 ** then it is removed from the routing tables.
 **/
void leafset_update (np_state_t* state, np_key_t* key, np_bool joined, np_key_t** deleted, np_key_t** added);
void route_update (np_state_t* state, np_key_t* key, np_bool joined, np_key_t** deleted, np_key_t** added);
// void route_update (np_state_t* state, np_key_t* key, int joined);

/** route_lookup:
 ** returns an array of count nodes that are acceptable next hops for a message being routed to key
 **/
sll_return(np_key_t) route_lookup (np_state_t* state, np_key_t* key, uint8_t count);
// np_key_t** route_lookup (np_state_t* state, np_key_t* key, int count, int is_safe);

/** route_neighbors: 
 ** returns an array of count neighbor nodes with priority to closer nodes.
 **/
sll_return(np_key_t) route_neighbors (np_state_t* state, uint8_t count);

/** route_row_lookup:
 ** return the row in the routing table that matches the longest prefix with key.
 **/
sll_return(np_key_t) route_row_lookup (np_state_t* state, np_key_t* key);

/** route_get_table:
 ** returns all the entries in the routing table in an array of ChimeraHost.
 **/
sll_return(np_key_t) route_get_table (np_routeglobal_t* rg);

/**
 ** prints routing table,
 **/
void printTable (np_routeglobal_t* rg);

#ifdef __cplusplus
}
#endif


#endif /* _NP_ROUTE_H_ */
