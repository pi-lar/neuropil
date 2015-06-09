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

#include "aaatoken.h"
#include "network.h"
#include "message.h"
#include "log.h"
#include "dllist.h"
#include "jval.h"
#include "jrb.h"
#include "np_threads.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_node_t);

void np_node_t_new(void* node) {

	np_node_t* entry = (np_node_t *) node;

	entry->dns_name = NULL;
	entry->port = 0;
	entry->address = 0;
	entry->failed = 0;
	entry->failuretime = 0;
	entry->success_win_index = 0;
	entry->success_avg = 0.5;
	// entry->node_tree = ng;
	// entry->ref_count = increase_ref_count;
	entry->handshake_status = HANDSHAKE_UNKNOWN;
	// entry->key = key;

	for (int i = 0; i < SUCCESS_WINDOW / 2; i++)
    	entry->success_win[i] = 0;
    for (int i = SUCCESS_WINDOW / 2; i < SUCCESS_WINDOW; i++)
    	entry->success_win[i] = 1;

	// jrb_insert_key (ng->np_node_cache, key, new_jval_v (entry));
    // ng->size++;
}

void np_node_t_del(void* node) {

	np_node_t* entry = (np_node_t *) node;

	if (entry->node_tree) {
		np_jrb_t* jrb_node = jrb_find_key (entry->node_tree->np_node_cache, entry->key);
		if (jrb_node) {
			jrb_delete_node (jrb_node);
			entry->node_tree->size--;
		}
	}

	if (entry->dns_name) free (entry->dns_name);
}

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

void np_node_encode_to_jrb (np_jrb_t* data, np_node_t* node)
{
	char* keystring = (char*) key_get_as_string (node->key);

	jrb_insert_str(data, "_np.node.key", new_jval_s(keystring));
	jrb_insert_str(data, "_np.node.dns_name", new_jval_s(node->dns_name));
	jrb_insert_str(data, "_np.node.port", new_jval_i(node->port));

	if (node->failuretime > 0.0)
		jrb_insert_str(data, "_np.node.failuretime", new_jval_d(node->failuretime));
}

/** np_node_decode:
 ** decodes a string into a node structure. This acts as a
 ** np_node_get, and should be followed eventually by a np_node_release.
 **/
np_obj_t* np_node_decode_from_str (np_nodecache_t* ng, const char *key)
{
	assert (key != 0);

	np_node_t *node = NULL;
	np_obj_t *o_node = NULL;

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
	np_key_t* nodeKey = (np_key_t*) malloc(sizeof(np_key_t));
	str_to_key(nodeKey, sHostkey);

	o_node = np_node_lookup(ng, nodeKey, 0);
	np_bind(np_node_t, o_node, node);
	if (sHostname != NULL) {
		np_node_update(node, sHostname, iHostport);
	}
	np_unbind(np_node_t, o_node, node);

	free (key_dup);
	return o_node;
}

np_obj_t* np_node_decode_from_jrb (np_nodecache_t* ng, np_jrb_t* data) {

	np_obj_t *o_node;
	np_node_t *node;

	// MANDATORY paramter
	char* sHostkey =  jrb_find_str(data, "_np.node.key")->val.value.s;
	char* sHostname = jrb_find_str(data, "_np.node.dns_name")->val.value.s;
	int iHostport =   jrb_find_str(data, "_np.node.port")->val.value.i;

	np_key_t* nodeKey = (np_key_t*) malloc(sizeof(np_key_t));
	str_to_key(nodeKey, sHostkey);

	o_node = np_node_lookup(ng, nodeKey, 0);
	np_bind(np_node_t, o_node, node);
	if (sHostname != NULL) {
		np_node_update( node, sHostname, iHostport);
	}
	// OPTIONAL parameter
	np_jrb_t* failure = jrb_find_str(data, "_np.node.failuretime");
	if (failure) node->failuretime = failure->val.value.d;
	// np_jrb_t* latency = jrb_find_str(data, "_np.node.latency");
	// if (latency) node->latency = latency->val.value.d;
	np_unbind(np_node_t, o_node, node);

    return (o_node);
}


int np_encode_nodes_to_jrb (np_nodecache_t* nc, np_jrb_t* data, np_key_t** node_keys)
{
    int i, j=0;
    np_node_t* tmp;
    for (i = 0; node_keys[i] != NULL; i++)
	{
    	if (np_node_exists(nc, node_keys[i])) {
    		np_jrb_t* node_jrb = make_jrb();
    		// log_msg(LOG_DEBUG, "c: %p -> adding np_node to jrb", node);
    		np_obj_t* node = np_node_lookup(nc, node_keys[i], 0);
    		np_bind(np_node_t, node, tmp);
    		np_node_encode_to_jrb(node_jrb, tmp);
    		jrb_insert_int(data, j, new_jval_tree(node_jrb));
    		np_unbind(np_node_t, node, tmp);
    		j++;
    	}
    }
    return j;
}

np_obj_t** np_decode_nodes_from_jrb (np_nodecache_t* nc, np_jrb_t* data)
{
    np_obj_t** node_list;
    int i;

    int nodenum = data->size;

    node_list = (np_obj_t **) malloc (sizeof (np_obj_t *) * (nodenum + 1));
    memset(node_list, 0, (sizeof(np_obj_t *) * (nodenum + 1)));

    /* gets the number of hosts in the lists and goes through them 1 by 1 */
    for (i = 0; i < nodenum; i++)
	{
    	np_jrb_t* node_data = jrb_find_int(data, i);
    	node_list[i] = np_node_decode_from_jrb(nc, node_data->val.value.tree);
	}

    node_list[i] = NULL;
    return (node_list);
}

/**
 ** np_node_get:
 ** gets a host entry for the given host, getting it from the cache if
 ** possible, or allocates memory for it
 **/
np_obj_t* np_node_get_by_hostname (np_nodecache_t* ng, char *hostname, int port)
{
    // np_jrb_t *jrb_node;
    unsigned long address;
    np_obj_t* o_entry;
    np_node_t* entry;
    // unsigned char *ip;
    // char id[256];
    // int i;

    /* create an id of the form ip:port */
    address = get_network_address (hostname);
    // memset (id, 0, 256);
    // ip = (unsigned char *) &address;
    // for (i = 0; i < 4; i++)
    // sprintf (id + strlen (id), "%s%d", (i == 0) ? ("") : ("."), (int) ip[i]);
    // sprintf (id + strlen (id), ":%d", port);
    np_key_t* nodeKey = key_create_from_hostport(hostname, port);

    // pthread_mutex_lock (&ng->lock);
    o_entry = np_node_lookup(ng, nodeKey, 0);
    np_bind(np_node_t, o_entry, entry);
    entry->dns_name = strdup (hostname);
	entry->port = port;
	entry->address = address;
    np_unbind(np_node_t, o_entry, entry);

    return o_entry;
}

void np_node_update (np_node_t* node, char *hn, int port) {

	unsigned long address = get_network_address (hn);
	if (address == 0)
		log_msg(LOG_WARN, "couldn't resolve hostname to ip address: %s", hn);

    node->dns_name = strndup (hn, strlen(hn));
	node->port = port;
	node->address = address;
	// log_msg(LOG_DEBUG, "resolved hostname to ip address: %s -> %lu", hn, address);
	// log_msg(LOG_TRACE, "ENDED, %s, %u, %d", node->dns_name, node->address, node->port);
}


np_obj_t* np_node_lookup(np_nodecache_t* ng, np_key_t* key, int increase_ref_count)
{
	assert (ng  != NULL);
	assert (key != NULL);

	np_obj_t* o_node;
	np_node_t* node;

    np_jrb_t *jrb_node = jrb_find_key (ng->np_node_cache, key);

    if (jrb_node == NULL) {

    	np_new(np_node_t, o_node);
    	np_bind(np_node_t, o_node, node);

    	// entry = (np_node_t *) malloc (sizeof (np_node_t));
    	// entry->dns_name = NULL;
    	// entry->port = 0;
    	// entry->address = 0;
    	// entry->failed = 0;
    	// entry->failuretime = 0;
    	// entry->success_win_index = 0;
    	// entry->success_avg = 0.5;
    	node->node_tree = ng;
    	node->node_tree->size++;
    	// entry->ref_count = increase_ref_count;
    	// entry->handshake_status = HANDSHAKE_UNKNOWN;

    	// TODO: np_ref(np_key_t, node->key);
    	node->key = key;

    	jrb_insert_key (ng->np_node_cache, key, new_jval_obj (o_node));

	    // log_msg(LOG_TRACE, "NODE REF COUNT (%p) %d #%s#", entry, entry->ref_count, key_get_as_string(entry->key));
    	np_unbind(np_node_t, o_node, node);

    } else {
		// just extract from cache
    	o_node = (np_obj_t*) jrb_node->val.value.obj;
    	// entry->ref_count += increase_ref_count;
    	// log_msg(LOG_TRACE, "NODE REF COUNT (%p) %d #%s#", entry, entry->ref_count, key_get_as_string(entry->key));
	}
    if (increase_ref_count) np_ref(np_node_t, o_node);

    return o_node;
}

/** np_node_release:
 ** releases a host from the cache, declaring that the memory could be
 ** freed any time. returns NULL if the entry is deleted, otherwise it
 ** returns #host#
 */
void np_node_release(np_nodecache_t* ng, np_key_t* key)
{
    np_jrb_t* jrb_node = jrb_find_key (ng->np_node_cache, key);
    if (jrb_node == NULL)
	{
	    return;
	}

    np_node_t* entry;
    np_obj_t* o_entry = (np_obj_t*) jrb_node->val.value.obj;
    np_unref(np_node_t, o_entry);

    /* if we reduce the node to 0 references, remove it from the cache */
    np_bind(np_node_t, o_entry, entry);
    if (o_entry->ref_count <= 0) {
    	jrb_delete_node (jrb_node);
    	ng->size--;
    }

    np_unbind(np_node_t, o_entry, entry);
    np_free(np_node_t, o_entry);
}

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

np_key_t* np_node_get_key(np_node_t* np_node)
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

int np_node_check_address_validity (np_node_t* np_node) {
	assert(np_node != NULL);
	return np_node->dns_name && np_node->address && np_node->port;
}

int np_node_exists(np_nodecache_t* ng, np_key_t* key)
{
	int i = 0;

	np_jrb_t* jrb_node = jrb_find_key (ng->np_node_cache, key);
	if (jrb_node != NULL)
	{
		i = 1;
	}
	return i;
}

/** np_node_init:
 ** initialize a host struct with a #size# element cache.
 **/
np_nodecache_t* np_node_cache_create (int size)
{
	np_nodecache_t* ng = (np_nodecache_t*) malloc (sizeof (np_nodecache_t));

	ng->np_node_cache = make_jrb ();
    ng->size = 0;
    // ng->max = size;

    if (pthread_mutex_init (&ng->lock, NULL) != 0)
	{
    	log_msg(LOG_ERROR, "pthread_mutex_init: %s", strerror (errno));
	    return (NULL);
	}
    return ng;
}
