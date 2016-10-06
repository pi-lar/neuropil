//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
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

#include "sodium.h"

#include "np_node.h"

#include "np_log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_tree.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_network.h"
#include "np_threads.h"
#include "np_util.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_node_t);

static const char* NP_NODE_KEY          = "_np.node.key";
static const char* NP_NODE_PROTOCOL     = "_np.node.protocol";
static const char* NP_NODE_DNS_NAME     = "_np.node.dns_name";
static const char* NP_NODE_PORT         = "_np.node.port";
static const char* NP_NODE_FAILURETIME  = "_np.node.failuretime";
static const char* NP_NODE_SUCCESS_AVG  = "_np.node.success_avg";
static const char* NP_NODE_LATENCY      = "_np.node.latency";
static const char* NP_NODE_LAST_SUCCESS = "_np.node.last_success";

void _np_node_t_new(void* node)
{
	np_node_t* entry = (np_node_t *) node;

	entry->dns_name = NULL;
	entry->port = 0;

	entry->failuretime = 0.0;
	entry->last_success = ev_time();
	entry->success_win_index = 0;
	entry->success_avg = 0.5;
	entry->handshake_status = HANDSHAKE_UNKNOWN;
	entry->joined_network = FALSE;

	for (uint8_t i = 0; i < SUCCESS_WINDOW / 2; i++)
    	entry->success_win[i] = 0;
    for (uint8_t i = SUCCESS_WINDOW / 2; i < SUCCESS_WINDOW; i++)
    	entry->success_win[i] = 1;
    for (uint8_t i = 0; i < SUCCESS_WINDOW; i++)
    	entry->latency_win[i] = 0.031415;
    entry->latency = 0.031415;
}

void _np_node_t_del(void* node)
{
	np_node_t* entry = (np_node_t *) node;
	if (entry->dns_name) free (entry->dns_name);
	if (entry->port) free (entry->port);
}

/** np_node_encode:
 ** encodes the #node# into a string, putting it in #s#, which has
 ** #len# bytes in it.
 **/
void _np_node_encode_to_str (char *s, uint16_t len, np_key_t* key)
{
    snprintf (s, len, "%s:", _key_as_str(key));

    if (NULL != key->node->dns_name) {
    	snprintf (s + strlen (s), len - strlen (s), "%s:", np_get_protocol_string(key->node->protocol));
    	snprintf (s + strlen (s), len - strlen (s), "%s:", key->node->dns_name);
    	snprintf (s + strlen (s), len - strlen (s), "%s",  key->node->port);
    }
}

void _np_node_encode_to_jrb (np_tree_t* data, np_node_t* node, np_bool include_stats)
{
	// char* keystring = (char*) _key_as_str (key);

	// tree_insert_str(data, NP_NODE_KEY, new_val_s(keystring));
	tree_insert_str(data, NP_NODE_PROTOCOL, new_val_ush(node->protocol));
	tree_insert_str(data, NP_NODE_DNS_NAME, new_val_s(node->dns_name));
	tree_insert_str(data, NP_NODE_PORT, new_val_s(node->port));

	if (node->failuretime > 0.0)
		tree_insert_str(data, NP_NODE_FAILURETIME,
				new_val_d(node->failuretime));

	if (TRUE == include_stats)
	{
		tree_insert_str(data, NP_NODE_SUCCESS_AVG,
				new_val_f(node->success_avg));
		tree_insert_str(data, NP_NODE_LATENCY,
				new_val_d(node->latency));
		tree_insert_str(data, NP_NODE_LAST_SUCCESS,
				new_val_d(node->last_success));
	}
}

/** np_node_decode
 * decodes a string into a node structure. This acts as a
 * np_node_get, and should be followed eventually by a np_node_release.
 **/
np_key_t* _np_node_decode_from_str (const char *key)
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

	if (iLen > strlen(s_hostkey))
	{
		s_hostproto = strtok(NULL, ":");
		s_hostname  = strtok(NULL, ":");
		s_hostport  = strtok(NULL, ":");
	}

	// string encoded data contains key, eventually plus hostname and hostport
	// key string is mandatory !
	log_msg(LOG_WARN, "s_hostkey %s / %s : %s : %s", s_hostkey, s_hostproto, s_hostname, s_hostport);

	np_dhkey_t search_key = dhkey_create_from_hash(s_hostkey);
	np_key_t* node_key    = _np_key_find_create(search_key);

	if (NULL == node_key->node)
	{
		np_new_obj(np_node_t, node_key->node);
	}

	if (NULL != s_hostname &&
		NULL == node_key->node->dns_name)
	{	// overwrite hostname only if it is not set yet
		uint8_t proto = np_parse_protocol_string(s_hostproto);
		np_node_update(node_key->node, proto, s_hostname, s_hostport);
	}

	free (key_dup);

	return (node_key);
}

np_node_t* _np_node_decode_from_jrb (np_tree_t* data)
{
	// MANDATORY paramter
	uint8_t i_host_proto = tree_find_str(data, NP_NODE_PROTOCOL)->val.value.ush;
	char* s_host_name  = tree_find_str(data, NP_NODE_DNS_NAME)->val.value.s;
	char* s_host_port  = tree_find_str(data, NP_NODE_PORT)->val.value.s;

	np_node_t* new_node = NULL;
	np_new_obj(np_node_t, new_node);

	if (NULL != s_host_name &&
		NULL == new_node->dns_name)
	{
		// uint8_t proto = np_parse_protocol_string(s_host_proto);
		np_node_update(new_node, i_host_proto, s_host_name, s_host_port);
		log_msg(LOG_DEBUG, "decoded node from jrb %d:%s:%s",
				i_host_proto, s_host_name, s_host_port);
	}

	// OPTIONAL parameter
	np_tree_elem_t* failure = tree_find_str(data, NP_NODE_FAILURETIME);
	if (NULL != failure)
	{
		new_node->failuretime = failure->val.value.d;
	}

	// np_jrb_t* latency = tree_find_str(data, "_np.node.latency");
	// if (latency) node->latency = latency->val.value.d;

	return (new_node);
}


uint16_t _np_encode_nodes_to_jrb (np_tree_t* data, np_sll_t(np_key_t, node_keys), np_bool include_stats)
{
	uint16_t j=0;
    np_key_t* current;
    while(NULL != sll_first(node_keys))
	{
    	current = sll_head(np_key_t, node_keys);
    	if (current->node)
    	{
    		np_tree_t* node_jrb = make_nptree();
    		// log_msg(LOG_DEBUG, "c: %p -> adding np_node to jrb", node);
    		_np_node_encode_to_jrb(node_jrb, current->node, include_stats);
    		tree_insert_str(node_jrb, NP_NODE_KEY, new_val_s(_key_as_str(current)));

    		tree_insert_int(data, j, new_val_tree(node_jrb));
    		j++;
    		np_free_tree(node_jrb);
    	}
    }
    return (j);
}

sll_return(np_key_t) _np_decode_nodes_from_jrb (np_tree_t* data)
{
    uint16_t nodenum = data->size;

    np_sll_t(np_key_t, node_list);
	sll_init(np_key_t, node_list);

    /* gets the number of hosts in the lists and goes through them 1 by 1 */
    for (uint16_t i = 0; i < nodenum; i++)
	{
    	np_tree_elem_t* node_data = tree_find_int(data, i);

    	char* s_key = tree_find_str(node_data->val.value.tree, NP_NODE_KEY)->val.value.s;
    	np_dhkey_t search_key = dhkey_create_from_hash(s_key);
    	np_key_t* node_key    = _np_key_find_create(search_key);
    	if (NULL == node_key->node)
    	{
    		node_key->node = _np_node_decode_from_jrb(node_data->val.value.tree);
    	}
    	sll_append(np_key_t, node_list, node_key);
	}

    return (node_list);
}

np_key_t* _np_create_node_from_token(np_aaatoken_t* token)
{
	// TODO: check whether metadata is used as a hash key in general
	np_dhkey_t search_key = _np_create_dhkey_for_token(token);
	np_key_t* node_key    = _np_key_find_create(search_key);
	if (NULL == node_key->node)
	{
		node_key->node = _np_node_decode_from_jrb(token->extensions);
	}
	return (node_key);
}

np_aaatoken_t* _np_create_node_token(np_node_t* node)
{
	log_msg(LOG_TRACE, ".start.np_create_node_token");
	np_state_t* state = _np_state();

	np_aaatoken_t* node_token = NULL;
	np_new_obj(np_aaatoken_t, node_token);

	char node_subject[255];
	snprintf(node_subject, 255, "urn:np:node:%s:%s:%s",
			np_get_protocol_string(node->protocol), node->dns_name, node->port);

	// create token
	if (NULL != state->realm_name)
	{
		strncpy(node_token->realm, state->realm_name, 255);
	}
	strncpy(node_token->issuer, node_subject, 255);
	strncpy(node_token->subject, node_subject, 255);
	// strncpy(node_token->audience, (char*) _key_as_str(state->my_identity->aaa_token->realm), 255);

	node_token->uuid = np_create_uuid(node_subject, 0);

	node_token->not_before = ev_time();
	node_token->expiration = ev_time() + 3600.0; // 1 hour valid token

    crypto_sign_keypair(node_token->public_key, node_token->private_key);   // ed25519

	tree_insert_str(node_token->extensions, NP_NODE_DNS_NAME,
			new_val_s(node->dns_name));
	tree_insert_str(node_token->extensions, NP_NODE_PORT,
			new_val_s(node->port));
	tree_insert_str(node_token->extensions, NP_NODE_PROTOCOL,
			new_val_ush(node->protocol));

	_np_aaatoken_add_signature(node_token);

	log_msg(LOG_TRACE, ".end  .np_create_node_token");
	return (node_token);
}

void np_node_update (np_node_t* node, uint8_t proto, char *hn, char* port)
{
	node->protocol = proto;

	if (NULL != node->dns_name) free(node->dns_name);
	node->dns_name = strndup (hn, strlen(hn));

	if (NULL != node->port) free(node->port);
	node->port = strndup(port, strlen(port));
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

    if (0 < success) node->last_success = ev_time();

	log_msg(LOG_INFO, "node %s:%s success rate now: %1.1f",
			node->dns_name, node->port, node->success_avg);
}

void np_node_update_latency (np_node_t* node, double new_latency)
{
	if (new_latency > 0.0)
	{
	    node->latency_win[node->latency_win_index++ % SUCCESS_WINDOW] = new_latency;

	    if (node->latency <= 0.0)
	    {
			node->latency = new_latency;
		}
	    else
	    {
	    	double total = 0.0;
		    for (uint8_t i = 0; i < SUCCESS_WINDOW; i++)
		    {
		    	// log_msg(LOG_DEBUG, "latency for node now: %1.1f / %1.1f ", total, node->latency_win[i]);
		    	total += node->latency_win[i];
		    }
			node->latency = total / SUCCESS_WINDOW;
			log_msg(LOG_INFO, "node %s:%s latency now: %1.3f",
					node->dns_name, node->port, node->latency);
	    	// log_msg(LOG_DEBUG, "latency for node now: %1.1f / %1.1f ", total, node->latency);
		}
	}
}

char* np_node_get_dns_name (np_node_t* np_node)
{
	assert(np_node != NULL);
	return (np_node->dns_name);
}

char* np_node_get_port (np_node_t* np_node)
{
	assert(np_node != NULL);
	return (np_node->port);
}

float np_node_get_success_avg (np_node_t* np_node)
{
	assert(np_node != NULL);
	return (np_node->success_avg);
}

float np_node_get_latency (np_node_t* np_node)
{
	assert(np_node != NULL);
	return (np_node->latency);
}

uint8_t np_node_check_address_validity (np_node_t* np_node)
{
	assert(np_node != NULL);
	// assert(np_node->network != NULL);

	return (np_node->dns_name && np_node->port);
}
