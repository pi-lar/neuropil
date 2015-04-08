/*
** $Id: host.c,v 1.14 2006/06/16 07:55:37 ravenben Exp $
**
** Matthew Allen
** description: 
*/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include "node.h"

#include "network.h"
#include "message.h"
#include "log.h"
#include "dllist.h"
#include "jval.h"
#include "jrb.h"


const char* np_node_amqp_map_fmt = "[SSi]";

/** np_node_encode:
 ** encodes the #node# into a string, putting it in #s#, which has
 ** #len# bytes in it.
 **/
void np_node_encode_to_str (char *s, int len, np_node_t * node)
{
    snprintf (s, len, "%s:", key_get_as_string(node->key));
    snprintf (s + strlen (s), len - strlen (s), "%s:", node->dns_name);
    snprintf (s + strlen (s), len - strlen (s), "%d", node->port);
}

void np_node_encode_to_amqp (pn_data_t* amqp_data, np_node_t* node)
{
	char* keystring = (char*) key_get_as_string (node->key);

	pn_data_put_list(amqp_data);
	pn_data_enter(amqp_data);
	pn_data_put_string(amqp_data, pn_bytes(strlen(keystring), keystring));
	pn_data_put_string(amqp_data, pn_bytes(strlen(node->dns_name), node->dns_name));
	pn_data_put_int(amqp_data, node->port);
	pn_data_exit(amqp_data);

	// pn_data_fill(amqp_data, np_node_amqp_map_fmt,
	// 						key_get_as_string (node->key),
	// 						node->dns_name,
	// 						node->port);
	if (pn_data_errno(amqp_data) < 0) {
		log_msg(LOG_ERROR, "error encoding host as amqp data structure");
	}
	// pn_data_dump(amqp_data);
}

/** np_node_decode:
 ** decodes a string into a node structure. This acts as a
 ** np_node_get, and should be followed eventually by a np_node_release.
 **/
np_node_t* np_node_decode_from_str (np_nodecache_t* ng, const char *key)
{
	assert (key != 0);

	np_node_t *node = NULL;
	Key kHostkey;

	char *key_dup = strdup(key);
	assert (key_dup != NULL);
	int iLen = strlen(key);
	assert (iLen > 0);

	char *sHostkey = NULL; // (char*) malloc(255);
	char *sHostname = NULL; // (char*) malloc(255);
	int iHostport = 0;

	// log_msg(LOG_DEBUG, "now decoding: %s", key);
	// key is mandatory element in string
	sHostkey = strtok(key_dup, ":");
	// log_msg(LOG_DEBUG, "node decoded, extracted hostkey %s", sHostkey);

	if (iLen > strlen(sHostkey)) {
		sHostname = strtok(NULL, ":");
		// log_msg(LOG_DEBUG, "node decoded, extracted hostname %s", sHostname);
		iHostport = atoi(strtok(NULL, ":"));
		// log_msg(LOG_DEBUG, "node decoded, extracted hostport %d", iHostport);
	}

	// string encoded data contains key, eventually plus hostname and hostport
	// key string is mandatory !
	// Key *nodeKey = str_to_key(sHostkey);
	Key* nodeKey = (Key*) malloc(sizeof(Key));
	str_to_key(nodeKey, sHostkey);
	node = np_node_lookup(ng, nodeKey, 0);

	if (sHostname != NULL) {
		np_node_update( node, sHostname, iHostport);
	}

	free (key_dup);
	return node;
}


np_node_t* np_node_decode_from_amqp (np_nodecache_t* ng, pn_data_t* amqp_data) {

	char sNodetext[255];
	int size;

	char sHostkey[255];
	char sHostname[255];
	int iHostport;

	np_node_t *node;

	assert(pn_data_type(amqp_data) == PN_LIST);
	int count = pn_data_get_list(amqp_data);
	assert(count == 3);
	pn_data_enter(amqp_data);

	pn_data_next(amqp_data);
    assert(pn_data_type(amqp_data) == PN_STRING);
	pn_bytes_t bHostkey = pn_data_get_string(amqp_data);

	pn_data_next(amqp_data);
    assert(pn_data_type(amqp_data) == PN_STRING);
	pn_bytes_t bHostname = pn_data_get_string(amqp_data);

	pn_data_next(amqp_data);
    assert(pn_data_type(amqp_data) == PN_INT);
	iHostport = pn_data_get_int(amqp_data);

	pn_data_exit(amqp_data);

	// pn_data_dump(amqp_data);
	// np_nodeglobal_t *hg = (np_nodeglobal_t *) state->host;
	//	pn_data_scan(amqp_data, np_node_amqp_map_fmt,
	//							&sHostkey,
	//							&sHostname,
	//							&iHostport);
	if (pn_data_errno(amqp_data) < 0) {
		log_msg(LOG_ERROR, "error decoding host from amqp data structure");
		return NULL;
	}

	strncpy(sHostkey, bHostkey.start, 255);
	strncpy(sHostname, bHostname.start, 255);
	// log_msg(LOG_TRACE, "PARSED (%s:%s:%d)", sHostkey, sHostname, iHostport);

	Key *nodeKey = (Key*) malloc(sizeof(Key));
	str_to_key(nodeKey, sHostkey);
	node = np_node_lookup(ng, nodeKey, 0);

	if (sHostname != NULL) {
		np_node_update( node, sHostname, iHostport);
	}

    return (node);
}


int np_encode_nodes_to_amqp (pn_data_t* amqp_data, np_node_t** host)
{
    int i;
    pn_data_put_list(amqp_data);
    pn_data_enter(amqp_data);
    for (i = 0; host[i] != NULL; i++)
	{
    	// pn_data_next(amqp_data);
    	// pn_data_t* node = pn_data(4);
	    np_node_encode_to_amqp(amqp_data, host[i]);
	    // pn_data_append(amqp_data, node);
	    // log_msg (LOG_DEBUG, "ENCODED %d = %s\n", i, pn_data_encode(node));
	}
    pn_data_exit(amqp_data);
    return i;
}

np_node_t** np_decode_nodes_from_amqp (np_nodecache_t* ng, pn_data_t* amqp_data)
{
    np_node_t **node;
    int i, j, k;

	assert(pn_data_type(amqp_data) == PN_LIST);
    int nodenum = pn_data_get_list(amqp_data);

    node = (np_node_t **) malloc (sizeof (np_node_t *) * (nodenum + 1));
    memset(node, 0, (sizeof(np_node_t *) * (nodenum + 1)));

    pn_data_enter(amqp_data);
    /* gets the number of hosts in the lists and goes through them 1 by 1 */
    for (i = 0; i < nodenum; i++)
	{
    	pn_data_next(amqp_data);
	    /* once you've found the seperater, decode the host and send it an update */
	    node[i] = np_node_decode_from_amqp(ng, amqp_data);
	}
	pn_data_exit(amqp_data);

	node[i] = NULL;

    return (node);
}

/**
 ** np_node_get:
 ** gets a host entry for the given host, getting it from the cache if
 ** possible, or allocates memory for it
 **/
np_node_t* np_node_get_by_hostname (np_nodecache_t* ng, char *hostname, int port)
{
    np_jrb_t *jrb_node;
    Dllist dllnode;
    unsigned long address;
    np_node_t* entry;
    unsigned char *ip;
    char id[256];
    int i;

    /* create an id of the form ip:port */
    memset (id, 0, 256);
    address = get_network_address (hostname);
    ip = (unsigned char *) &address;
    for (i = 0; i < 4; i++)
    	sprintf (id + strlen (id), "%s%d", (i == 0) ? ("") : ("."), (int) ip[i]);
    sprintf (id + strlen (id), ":%d", port);

    pthread_mutex_lock (&ng->lock);

    jrb_node = jrb_find_str (ng->np_node_cache, id);
    /* if the node is not in the cache, create an entry and allocate a host */
    if (jrb_node == NULL)
	{
	    // entry = (CacheEntry *) malloc (sizeof (CacheEntry));
    	entry = (np_node_t *) malloc (sizeof (np_node_t));
    	entry->dns_name = strdup (hostname);
    	entry->port = port;
    	entry->address = address;
    	entry->failed = 0;
    	entry->failuretime = 0;
    	entry->success_win_index = 0;
    	entry->success_avg = 0.5;
    	entry->node_tree = ng;
    	entry->ref_count = 1;

    	key_assign_ui (entry->key, 0);

	    for (i = 0; i < SUCCESS_WINDOW / 2; i++)
	    	entry->success_win[i] = 0;
	    for (i = SUCCESS_WINDOW / 2; i < SUCCESS_WINDOW; i++)
	    	entry->success_win[i] = 1;

	    jrb_insert_str (ng->np_node_cache, strdup (id), new_jval_v (entry));
	    // jrb_insert_str (ng->np_key_node_cache, strdup (id), new_jval_v (entry));
	    // new_node->jrb_node = jrb_find_str (ng->jrb_nodes, id);
	    ng->size++;
	}
    /* otherwise, increase the reference count */
    else
	{
	    entry = (np_node_t *) jrb_node->val.v;
	    /* if it was in the free list, remove it from the free list */
	    // if (entry->reference_count == 0)
		// {
		//     dll_delete_node (entry->dll_free_nodes);
		// }
	    entry->ref_count++;
	}

    /* if the cache was overfull, empty it as much as possible */
// TODO: empty cache based on reference count if it is too full
//    while (ng->size > ng->max && !jrb_empty (ng->dll_free_nodes))
//	{
//	    dllnode = dll_first (ng->dll_free_nodes);
//	    tmp = (np_node_t *) dllnode->val.v;
//	    dll_delete_node (dllnode);
//	    jrb_delete_node (tmp->jrb_node);
//	    cacheentry_free (tmp);
//	    ng->size--;
//	}
    pthread_mutex_unlock (&ng->lock);

    return entry;
}

void np_node_update (np_node_t* node, char *hn, int port) {

	unsigned long address = get_network_address (hn);
	if (address == 0)
		log_msg(LOG_WARN, "couldn't resolve hostname to ip address: %s", hn);
    unsigned char* ip = (unsigned char *) &address;

    node->dns_name = strndup (hn, strlen(hn));
	node->port = port;
	node->address = address;
	// log_msg(LOG_DEBUG, "resolved hostname to ip address: %s -> %lu", hn, address);
	// log_msg(LOG_TRACE, "ENDED, %s, %u, %d", node->dns_name, node->address, node->port);
}


np_node_t* np_node_lookup(np_nodecache_t* ng, Key* key, int increase_ref_count) {

	assert (ng != NULL);

	int i = 0;
	np_node_t* entry;

	pthread_mutex_lock (&ng->lock);

    np_jrb_t *jrb_node = jrb_find_str (ng->np_node_cache, (char*) key_get_as_string(key));

    if (jrb_node == NULL) {
		entry = (np_node_t *) malloc (sizeof (np_node_t));
    	entry->dns_name = NULL;
    	entry->port = 0;
    	entry->address = 0;
    	entry->failed = 0;
    	entry->failuretime = 0;
    	entry->success_win_index = 0;
    	entry->success_avg = 0.5;
    	entry->node_tree = ng;
    	entry->ref_count = increase_ref_count;

    	entry->key = key;

    	for (i = 0; i < SUCCESS_WINDOW / 2; i++)
	    	entry->success_win[i] = 0;
	    for (i = SUCCESS_WINDOW / 2; i < SUCCESS_WINDOW; i++)
	    	entry->success_win[i] = 1;

    	jrb_insert_str (ng->np_node_cache, strdup ((char*) key_get_as_string(key)), new_jval_v (entry));
	    ng->size++;

	    // log_msg(LOG_TRACE, "NODE REF COUNT (%p) %d #%s#", entry, entry->ref_count, key_get_as_string(entry->key));

    } else {
		// just extract from cache
		entry = (np_node_t*) jrb_node->val.v;
    	entry->ref_count += increase_ref_count;
    	// log_msg(LOG_TRACE, "NODE REF COUNT (%p) %d #%s#", entry, entry->ref_count, key_get_as_string(entry->key));
	}
    pthread_mutex_unlock (&ng->lock);

    return entry;
}

/** np_node_release:
 ** releases a host from the cache, declaring that the memory could be
 ** freed any time. returns NULL if the entry is deleted, otherwise it
 ** returns #host#
 */
void np_node_release(np_nodecache_t* ng, Key* key)
{
    pthread_mutex_lock (&ng->lock);

    np_jrb_t* jrb_node = jrb_find_str (ng->np_node_cache, (char*) key_get_as_string(key));
    if (jrb_node == NULL)
	{
	    pthread_mutex_unlock (&ng->lock);
	    return;
	}

    np_node_t* entry = (np_node_t *) jrb_node->val.v;
    entry->ref_count--;

    // log_msg(LOG_TRACE, "NODE REF COUNT (%p) %d %s", entry, entry->ref_count, key_get_as_string(entry->key));

    /* if we reduce the node to 0 references, remove it from the cache */
    if (entry->ref_count <= 0)
	{
	    if (entry->dns_name) free (entry->dns_name);

	    free (entry->key);
	    free (entry);
	    ng->size--;

	    jrb_delete_node (jrb_node);
	}

    pthread_mutex_unlock (&ng->lock);
}

//void np_node_release (np_node_t* node)
//{
//    np_jrb_t *jrb_node;
//    np_node_t* entry;
//
//    pthread_mutex_lock (&node->node_tree->lock);
//
//    jrb_node = jrb_find_str (node->node_tree->np_node_cache, key_get_as_string(node->key));
//    if (jrb_node == NULL)
//	{
//	    pthread_mutex_unlock (&node->node_tree->lock);
//	    return;
//	}
//
//    entry = (np_node_t *) jrb_node->val.v;
//    entry->ref_count--;
//
//    /* if we reduce the node to 0 references, remove it from the cache */
//    if (entry->ref_count == 0)
//	{
//    	jrb_delete_node (jrb_node);
//	    if (entry->dns_name) free (entry->dns_name);
//	    free (entry->key);
//	    free (entry);
//	    // dll_append (host->ng->dll_free_nodes, new_jval_v (entry));
//	    // entry->dll_free_nodes = dll_last (host->ng->dll_free_nodes);
//	    ng->size--;
//	}
//
//    /* if the cache was overfull, empty it as much as possible */
////    while (host->ng->size > host->ng->max && !jrb_empty (host->ng->dll_free_nodes))
////	{
////	    dllnode = dll_first (host->ng->dll_free_nodes);
////	    tmp = (CacheEntry *) dllnode->val.v;
////	    dll_delete_node (dllnode);
////	    jrb_delete_node (tmp->jrb_node);
////	    cacheentry_free (tmp);
////	    host->ng->size--;
////	}
//    pthread_mutex_unlock (&node->node_tree->lock);
//}


/** np_node_update_stat:
 ** updates the success rate to the host based on the SUCCESS_WINDOW average
 **/
void np_node_update_stat (np_node_t* node, int success)
{
    int i;
    float total = 0;
    node->success_win[node->success_win_index++ % SUCCESS_WINDOW] = success;
    node->success_avg = 0.0;
    // printf("SUCCESS_WIN["); 
    for (i = 0; i < SUCCESS_WINDOW; i++)
	{
	    total += node->success_win[i];
	}
    node->success_avg = total / SUCCESS_WINDOW;
	log_msg(LOG_DEBUG, "success rate for node %s now: %1.1f", key_get_as_string(node->key), node->success_avg);
}

Key* np_node_get_key (np_node_t* np_node)
{
	assert(np_node != NULL);
	return np_node->key;
}

char* np_node_get_dns_name (np_node_t* np_node) {
	assert(np_node != NULL);
	return np_node->dns_name;
}

unsigned long np_node_get_address (np_node_t* np_node){
	assert(np_node != NULL);
	return np_node->address;
}

int np_node_get_port (np_node_t* np_node) {
	assert(np_node != NULL);
	return np_node->port;
}

float np_node_get_success_avg (np_node_t* np_node) {
	assert(np_node != NULL);
	return np_node->success_avg;
}
float np_node_get_latency (np_node_t* np_node) {
	assert(np_node != NULL);
	return np_node->latency;
}

/** np_node_init:
 ** initialize a host struct with a #size# element cache.
 **/
np_nodecache_t* np_node_cache_create (int size)
{
	np_nodecache_t* ng = (np_nodecache_t*) malloc (sizeof (np_nodecache_t));

	ng->np_node_cache = make_jrb ();
    // ng->dll_free_nodes = new_dllist ();
    ng->size = 0;
    ng->max = size;

    if (pthread_mutex_init (&ng->lock, NULL) != 0)
	{
    	log_msg(LOG_ERROR, "pthread_mutex_init: %s", strerror (errno));
	    return (NULL);
	}
    return ng;
}
