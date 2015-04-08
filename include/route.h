#ifndef _NP_ROUTE_H_
#define _NP_ROUTE_H_

#include "include.h"

#include "key.h"

#define MAX_ROW KEY_SIZE/BASE_B
#define MAX_COL power(2,BASE_B)
#define MAX_ENTRY 3
#define LEAFSET_SIZE 8		/* (must be even) excluding node itself */

typedef struct np_routeglobal_t
{
    np_node_t* me;
    char *keystr;

    np_node_t**** table;
    np_node_t** leftleafset;
    np_node_t** rightleafset;

    Key Rrange;
    Key Lrange;

    pthread_mutex_t lock;
    pthread_attr_t attr;
    pthread_t tid;

} *np_routeglobal;


/** route_init:
** Ininitiates routing table and leafsets. 
*/
np_routeglobal_t* route_init (np_node_t* me);

/** route_lookup:
 ** returns an array of count nodes that are acceptable next hops for a
 ** message being routed to key. is_save is ignored for now.
 */
np_node_t** route_lookup (np_routeglobal_t* rg, Key* key, int count, int is_safe);

/** route_neighbors: 
 ** returns an array of count neighbor nodes with priority to closer nodes.
 */
np_node_t** route_neighbors (np_routeglobal_t* rg, int count);


/** route_update:
 ** updates the routing table in regard to host. If the host is joining
 ** the network (and joined == 1), then it is added to the routing table
 ** if it is appropriate. If it is leaving the network (and joined == 0),
 ** then it is removed from the routing tables.
 */
void route_update (np_routeglobal_t* rg, np_node_t* node, int joined);

/** route_row_lookup:
 ** return the row in the routing table that matches the longest prefix with key.
 */
np_node_t** route_row_lookup (np_routeglobal_t* rg, Key* key);

/** route_get_table:
 ** returns all the entries in the routing table in an array of ChimeraHost.
 */
np_node_t** route_get_table (np_routeglobal_t* rg);

/** prints routing table, 
 */
void printTable (np_routeglobal_t* rg);


#endif /* _NP_ROUTE_H_ */
