/*
** $Id: host.c,v 1.14 2006/06/16 07:55:37 ravenben Exp $
**
** Matthew Allen
** description: 
*/

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "jval.h"
#include "log.h"
#include "dtime.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_container.h"
#include "np_jtree.h"
#include "np_message.h"
#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_node_t);

static const char* NP_NODE_KEY         = "_np.node.key";
static const char* NP_NODE_PROTOCOL    = "_np.node.protocol";
static const char* NP_NODE_DNS_NAME    = "_np.node.dns_name";
static const char* NP_NODE_PORT        = "_np.node.port";
static const char* NP_NODE_FAILURETIME = "_np.node.failuretime";

void np_node_t_new(void* node) {

	np_node_t* entry = (np_node_t *) node;

	entry->dns_name = NULL;
	entry->port = 0;
	entry->network = NULL;

	entry->failuretime = 0.0;
	entry->last_success = 0.0;
	entry->success_win_index = 0;
	entry->success_avg = 0.5;
	entry->handshake_status = HANDSHAKE_UNKNOWN;
	entry->joined_network = FALSE;

	for (uint8_t i = 0; i < SUCCESS_WINDOW / 2; i++)
    	entry->success_win[i] = 0;
    for (uint8_t i = SUCCESS_WINDOW / 2; i < SUCCESS_WINDOW; i++)
    	entry->success_win[i] = 1;
}

void np_node_t_del(void* node) {
	np_node_t* entry = (np_node_t *) node;
	if (entry->dns_name) free (entry->dns_name);
	if (entry->port) free (entry->port);
}

/** np_node_encode:
 ** encodes the #node# into a string, putting it in #s#, which has
 ** #len# bytes in it.
 **/
void np_node_encode_to_str (char *s, uint16_t len, np_key_t* key)
{
    snprintf (s, len, "%s:", key_get_as_string(key));

    if (NULL != key->node->dns_name) {
    	snprintf (s + strlen (s), len - strlen (s), "%s:", np_get_protocol_string(key->node->protocol));
    	snprintf (s + strlen (s), len - strlen (s), "%s:", key->node->dns_name);
    	snprintf (s + strlen (s), len - strlen (s), "%s",  key->node->port);
    }
}

void np_node_encode_to_jrb (np_jtree_t* data, np_key_t* key)
{
	char* keystring = (char*) key_get_as_string (key);

	jrb_insert_str(data, NP_NODE_KEY, new_jval_s(keystring));
	jrb_insert_str(data, NP_NODE_PROTOCOL, new_jval_s(np_get_protocol_string(key->node->protocol)));
	jrb_insert_str(data, NP_NODE_DNS_NAME, new_jval_s(key->node->dns_name));
	jrb_insert_str(data, NP_NODE_PORT, new_jval_s(key->node->port));

	if (key->node->failuretime > 0.0)
		jrb_insert_str(data, NP_NODE_FAILURETIME,
				new_jval_d(key->node->failuretime));
}

/** np_node_decode
 * decodes a string into a node structure. This acts as a
 * np_node_get, and should be followed eventually by a np_node_release.
 **/
np_key_t* np_node_decode_from_str (np_state_t* state, const char *key)
{
	assert (key != 0);

	char *key_dup = strndup(key, 255);
	assert (key_dup != NULL);
	uint16_t iLen = strlen(key);
	assert (iLen > 0);

	char     *s_hostkey = NULL;
	char     *s_hostproto = NULL;
	char     *s_hostname = NULL;
	char     *s_hostport = NULL;

	// key is mandatory element in string
	s_hostkey = strtok(key_dup, ":");
	// log_msg(LOG_DEBUG, "node decoded, extracted hostkey %s", sHostkey);

	if (iLen > strlen(s_hostkey)) {
		s_hostproto = strtok(NULL, ":");
		s_hostname = strtok(NULL, ":");
		s_hostport = strtok(NULL, ":");
	}

	// string encoded data contains key, eventually plus hostname and hostport
	// key string is mandatory !
	log_msg(LOG_WARN, "s_hostkey %s / %s : %s : %s", s_hostkey, s_hostproto, s_hostname, s_hostport);

	np_key_t* node_key = NULL;
	np_key_t* search_key = key_create_from_hash((unsigned char*) s_hostkey);

	if (NULL == (node_key = SPLAY_FIND(spt_key, &state->key_cache, search_key)) ) {
		SPLAY_INSERT(spt_key, &state->key_cache, search_key);
		node_key = search_key;
		np_ref_obj(np_key_t, node_key);
    } else {
    	np_free_obj(np_key_t, search_key);
    }

	if (NULL == node_key->node) {
		np_new_obj(np_node_t, node_key->node);
	}

	if (NULL != s_hostname &&
		NULL == node_key->node->dns_name) {
		// overwrite hostname only if it is not set yet
		uint8_t proto = np_parse_protocol_string(s_hostproto);
		np_node_update(node_key->node, proto, s_hostname, s_hostport);
	}

	if (s_hostkey) free (s_hostkey);
	// if (s_hostname) free (s_hostname);
	// if (s_hostport) free (s_hostport);

	return node_key;
}

np_key_t* np_node_decode_from_jrb (np_state_t* state, np_jtree_t* data) {

	// MANDATORY paramter
	unsigned char* s_host_key =
			(unsigned char*) jrb_find_str(data, NP_NODE_KEY)->val.value.s;
	char* s_host_proto = jrb_find_str(data, NP_NODE_PROTOCOL)->val.value.s;
	char* s_host_name = jrb_find_str(data, NP_NODE_DNS_NAME)->val.value.s;
	char* s_host_port = jrb_find_str(data, NP_NODE_PORT)->val.value.s;

	np_key_t* node_key;
	np_key_t* search_key = key_create_from_hash(s_host_key);

	if (NULL == (node_key = SPLAY_FIND(spt_key, &state->key_cache, search_key)) ) {
		SPLAY_INSERT(spt_key, &state->key_cache, search_key);
		node_key = search_key;
		np_ref_obj(np_key_t, node_key);
    } else {
    	np_free_obj(np_key_t, search_key);
    }

    if (NULL == node_key->node) {
		np_new_obj(np_node_t, node_key->node);
	}

	np_node_t* node = node_key->node;
	if (NULL != s_host_name &&
		NULL == node->dns_name)
	{
		uint8_t proto = np_parse_protocol_string(s_host_proto);
		np_node_update( node, proto, s_host_name, s_host_port);
	}

	// OPTIONAL parameter
	np_jtree_elem_t* failure = jrb_find_str(data, NP_NODE_FAILURETIME);
	if (failure) node->failuretime = failure->val.value.d;
	// np_jrb_t* latency = jrb_find_str(data, "_np.node.latency");
	// if (latency) node->latency = latency->val.value.d;

	return (node_key);
}


uint16_t np_encode_nodes_to_jrb (np_jtree_t* data, np_sll_t(np_key_t, node_keys))
{
	uint16_t j=0;
    np_key_t* current;
    while(sll_first(node_keys) != NULL)
	{
    	current = sll_head(np_key_t, node_keys);
    	if (current->node) {
    		np_jtree_t* node_jrb = make_jtree();
    		// log_msg(LOG_DEBUG, "c: %p -> adding np_node to jrb", node);
    		np_node_encode_to_jrb(node_jrb, current);
    		jrb_insert_int(data, j, new_jval_tree(node_jrb));
    		j++;
    	}
    }
    return j;
}

sll_return(np_key_t) np_decode_nodes_from_jrb (np_state_t* state, np_jtree_t* data)
{
    uint16_t nodenum = data->size;

    np_sll_t(np_key_t, node_list);
	sll_init(np_key_t, node_list);

    /* gets the number of hosts in the lists and goes through them 1 by 1 */
    for (uint16_t i = 0; i < nodenum; i++)
	{
    	np_jtree_elem_t* node_data = jrb_find_int(data, i);
    	sll_append(np_key_t, node_list, np_node_decode_from_jrb(state, node_data->val.value.tree));
	}

    return (node_list);
}

void np_node_update (np_node_t* node, uint8_t proto, char *hn, char* port) {

	if (NULL == node->network)
		node->network = network_init(FALSE, proto, hn, port);
	// log_msg(LOG_WARN, "couldn't resolve hostname to ip address: %s", hn);

	node->protocol = proto;
	node->dns_name = strndup (hn, strlen(hn));
	node->port = strndup(port, strlen(port));

	// log_msg(LOG_DEBUG, "resolved hostname to ip address: %s -> %u", hn, address);
	// log_msg(LOG_TRACE, "ENDED, %s, %u, %hd", node->dns_name, node->address, node->port);
}


/** np_node_update_stat:
 ** updates the success rate to the host based on the SUCCESS_WINDOW average
 **/
void np_node_update_stat (np_node_t* node, uint8_t success)
{
    float total = 0;
    node->success_win[node->success_win_index++ % SUCCESS_WINDOW] = success;
    node->success_avg = 0.0;
    // printf("SUCCESS_WIN["); 
    for (uint8_t i = 0; i < SUCCESS_WINDOW; i++)
	{
	    total += node->success_win[i];
	}
    node->success_avg = total / SUCCESS_WINDOW;

    if (success) node->last_success = dtime();

	// log_msg(LOG_DEBUG, "success rate for node now: %1.1f", node->success_avg);
}

void np_node_update_latency (np_node_t* node, double new_latency)
{
	if (new_latency > 0) {
		if (node->latency == 0.0) {
			node->latency = new_latency;
		} else {
			// TODO: this is wrong to calculate the moving average latency
			node->latency = (0.9 * node->latency) + (0.1 * new_latency);
		}
	}
}

char* np_node_get_dns_name (np_node_t* np_node) {
	assert(np_node != NULL);
	return np_node->dns_name;
}

//uint32_t np_node_get_address (np_node_t* np_node){
//	assert(np_node != NULL);
//	return np_node->address;
//}

char* np_node_get_port (np_node_t* np_node) {
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

uint8_t np_node_check_address_validity (np_node_t* np_node) {
	assert(np_node != NULL);
	assert(np_node->network != NULL);

	return np_node->dns_name && np_node->port && np_node->network->addr_in;
}
