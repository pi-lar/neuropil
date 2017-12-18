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
#include "np_memory.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_keycache.h"
#include "np_network.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_settings.h"
#include "np_constants.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_node_t);


void _np_node_t_new(void* node)
{
	log_msg(LOG_TRACE, "start: void _np_node_t_new(void* node){");
	np_node_t* entry = (np_node_t *) node;

	_np_threads_mutex_init(&entry->lock,"node lock");
	_np_threads_mutex_init(&entry->latency_lock,"node latency lock");

	entry->dns_name = NULL;
	entry->protocol = 0;
	entry->port = 0;

	memset(entry->session_key, 0, crypto_scalarmult_SCALARBYTES*(sizeof(unsigned char)));
	entry->session_key_is_set = FALSE;

	entry->last_success = np_time_now();
	entry->success_win_index = 0;
	entry->is_handshake_send = FALSE;
	entry->is_handshake_received = FALSE;
	entry->joined_network = FALSE;

	for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
		entry->success_win[i] = i%2 == 0;
	entry->success_avg = 0.5;
	
	for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
		entry->latency_win[i] = 0.031415;
	entry->latency = 0.031415;
}

void _np_node_t_del(void* node)
{
	log_msg(LOG_TRACE, "start: void _np_node_t_del(void* node){");
	np_node_t* entry = (np_node_t *) node;
	if (entry->dns_name) free (entry->dns_name);
	if (entry->port) free (entry->port);

	_np_threads_mutex_destroy(&entry->latency_lock);
	_np_threads_mutex_destroy(&entry->lock);
}

/** np_node_encode:
 ** encodes the #node# into a string, putting it in #s#, which has
 ** #len# bytes in it.
 **/
void _np_node_encode_to_str (char *s, uint16_t len, np_key_t* key)
{
	snprintf (s, len, "%s:", _np_key_as_str(key));

	if (NULL != key->node->dns_name) {
		snprintf (s + strlen (s), len - strlen (s), "%s:", _np_network_get_protocol_string(key->node->protocol));
		snprintf (s + strlen (s), len - strlen (s), "%s:", key->node->dns_name);
		snprintf (s + strlen (s), len - strlen (s), "%s",  key->node->port);
	}
} 
void _np_node_encode_to_jrb (np_tree_t* data, np_key_t* node_key, np_bool include_stats)
{
	np_tree_insert_str(data, NP_SERIALISATION_NODE_PROTOCOL, np_treeval_new_ush(node_key->node->protocol));
	np_tree_insert_str(data, NP_SERIALISATION_NODE_DNS_NAME, np_treeval_new_s(node_key->node->dns_name));
	np_tree_insert_str(data, NP_SERIALISATION_NODE_PORT, np_treeval_new_s(node_key->node->port));

	if (TRUE == include_stats)
	{		
		np_tree_insert_str(data, NP_SERIALISATION_NODE_CREATED_AT, np_treeval_new_d(node_key->created_at));
		np_tree_insert_str(data, NP_SERIALISATION_NODE_KEY, np_treeval_new_s(_np_key_as_str(node_key)));

		if(node_key->node != NULL){

			np_tree_insert_str(data, NP_SERIALISATION_NODE_SUCCESS_AVG,
					np_treeval_new_f(node_key->node->success_avg));
			np_tree_insert_str(data, NP_SERIALISATION_NODE_LATENCY,
					np_treeval_new_d(node_key->node->latency));
			np_tree_insert_str(data, NP_SERIALISATION_NODE_LAST_SUCCESS,
					np_treeval_new_d(node_key->node->last_success));
		}
	}
}

/** np_node_decode
 * decodes a string into a node structure. This acts as a
 * np_node_get, and should be followed eventually by a np_node_release.
 *
 * Example: _np_node_decode_from_str("04436571312f73109f697851cfd0529a06ae66080dc9f07581f45526691d4290:udp4:example.com:1234");
 * The key always requires a 64 char hash value as first parameter
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
	// log_debug_msg(LOG_DEBUG, "node decoded, extracted hostkey %s", sHostkey);

	if (iLen > strlen(s_hostkey))
	{
		s_hostproto = strtok(NULL, ":");
		s_hostname  = strtok(NULL, ":");
		s_hostport  = strtok(NULL, ":");
	}

	// string encoded data contains key, eventually plus hostname and hostport
	// key string is mandatory !
	log_debug_msg(LOG_DEBUG, "s_hostkey %s / %s : %s : %s", s_hostkey, s_hostproto, s_hostname, s_hostport);

	np_dhkey_t search_key = np_dhkey_create_from_hash(s_hostkey);
	np_key_t* node_key    = _np_keycache_find_or_create(search_key);

	if (NULL == node_key->node)
	{
		np_new_obj(np_node_t, node_key->node);
		ref_replace_reason(np_node_t, node_key->node, ref_obj_creation, ref_key_node);
	}

	if (NULL != s_hostname &&
		NULL == node_key->node->dns_name)
	{	// overwrite hostname only if it is not set yet
		uint8_t proto = _np_network_parse_protocol_string(s_hostproto);
		_np_node_update(node_key->node, proto, s_hostname, s_hostport);
	}

	free (key_dup);

	ref_replace_reason(np_key_t, node_key, "_np_keycache_find_or_create", __func__);

	return (node_key);
}

np_node_t* _np_node_decode_from_jrb (np_tree_t* data)
{
	// MANDATORY paramter
	uint8_t i_host_proto;
	char* s_host_name = NULL;
	char* s_host_port = NULL;
	np_tree_elem_t* ele;
	if (NULL != (ele = np_tree_find_str(data, NP_SERIALISATION_NODE_PROTOCOL))) {
		i_host_proto = ele->val.value.ush;
	}
	else { return NULL; }

	if (NULL != (ele = np_tree_find_str(data, NP_SERIALISATION_NODE_DNS_NAME))) {
		s_host_name = np_treeval_to_str(ele->val,NULL);
	}
	else { return NULL; }

	if (NULL != (ele = np_tree_find_str(data, NP_SERIALISATION_NODE_PORT))) {
		s_host_port = np_treeval_to_str(ele->val, NULL);
	}
	else { return NULL; }

	np_node_t* new_node = NULL;
	np_new_obj(np_node_t, new_node);

	if (NULL != s_host_name &&
		NULL == new_node->dns_name)
	{
		// uint8_t proto = _np_network_parse_protocol_string(s_host_proto);
		_np_node_update(new_node, i_host_proto, s_host_name, s_host_port);
		log_debug_msg(LOG_DEBUG, "decoded node from jrb %d:%s:%s",
				i_host_proto, s_host_name, s_host_port);
	}

	ref_replace_reason(np_node_t, new_node, ref_obj_creation, __func__);

	return (new_node);
}


uint16_t _np_node_encode_multiple_to_jrb (np_tree_t* data, np_sll_t(np_key_ptr, node_keys), np_bool include_stats)
{
	uint16_t j=0;
	np_key_t* current;

	sll_clone(np_key_ptr, node_keys, node_keys_to_encode)

	while(NULL != (current = sll_head(np_key_ptr, node_keys_to_encode)))
	{		
		if (current->node)
		{
			np_tree_t* node_jrb = np_tree_create();
			// log_debug_msg(LOG_DEBUG, "c: %p -> adding np_node to jrb", node);
			_np_node_encode_to_jrb(node_jrb, current, include_stats);
			np_tree_insert_str(node_jrb, NP_SERIALISATION_NODE_KEY, np_treeval_new_s(_np_key_as_str(current)));

			np_tree_insert_int(data, j, np_treeval_new_tree(node_jrb));
			j++;
			np_tree_free(node_jrb);
		}
	}
	sll_free(np_key_ptr, node_keys_to_encode);
	return (j);
}

sll_return(np_key_ptr) _np_node_decode_multiple_from_jrb (np_tree_t* data)
{
	uint16_t nodenum = data->size;

	np_sll_t(np_key_ptr, node_list);
	sll_init(np_key_ptr, node_list);

	/* gets the number of hosts in the lists and goes through them 1 by 1 */
	for (uint16_t i = 0; i < nodenum; i++)
	{
		np_tree_elem_t* node_data = np_tree_find_int(data, i);

		np_bool free_s_key = FALSE;
		char* s_key = np_treeval_to_str(np_tree_find_str(node_data->val.value.tree, NP_SERIALISATION_NODE_KEY)->val,&free_s_key);
		np_dhkey_t search_key = np_dhkey_create_from_hash(s_key);
		if (free_s_key == TRUE) {
			free(s_key);
		}
		np_key_t* node_key    = _np_keycache_find_or_create(search_key);
		if (NULL == node_key->node)
		{
			node_key->node = _np_node_decode_from_jrb(node_data->val.value.tree);
			ref_replace_reason(np_node_t, node_key->node, "_np_node_decode_from_jrb", ref_key_node);
		} 
		
		ref_replace_reason(np_key_t, node_key, "_np_keycache_find_or_create", __func__);
		
		sll_append(np_key_ptr, node_list, node_key);
	}
	return (node_list);
}

np_key_t* _np_key_create_from_token(np_aaatoken_t* token)
{
	log_msg(LOG_TRACE, "start: np_key_t* _np_key_create_from_token(np_aaatoken_t* token){");
	// TODO: check whether metadata is used as a hash key in general
	np_dhkey_t search_key = _np_aaatoken_create_dhkey(token);
	np_key_t* node_key    = _np_keycache_find_or_create(search_key);
	
	if (NULL == node_key->node && token->extensions != NULL && token->extensions->size > 0){
	
		node_key->node = _np_node_decode_from_jrb(token->extensions);
		if(node_key->node != NULL){
			ref_replace_reason(
				np_node_t, node_key->node,
				"_np_node_decode_from_jrb",
				ref_key_node		
			);
		}
	}
	ref_replace_reason(
			np_key_t, node_key,
			"_np_keycache_find_or_create",
			__func__
	);
	
	return (node_key);
}

np_aaatoken_t* _np_node_create_token(np_node_t* node)
{
	log_msg(LOG_TRACE, "start: np_aaatoken_t* _np_node_create_token(np_node_t* node){");
	np_state_t* state = _np_state();

	np_aaatoken_t* node_token = NULL;
	np_new_obj(np_aaatoken_t, node_token);

	char node_subject[255];
	snprintf(node_subject, 255, "urn:np:node:%s:%s:%s",
			_np_network_get_protocol_string(node->protocol), node->dns_name, node->port);

	// create token
	if (NULL != state->realm_name)
	{
		strncpy(node_token->realm, state->realm_name, 255);
	}
	strncpy(node_token->issuer, node_subject, 64);
	strncpy(node_token->subject, node_subject, 255);
	// strncpy(node_token->audience, (char*) _np_key_as_str(state->my_identity->aaa_token->realm), 255);

	char* old = node_token->uuid;
	node_token->uuid = np_uuid_create(node_subject, 0);
	free(old);

	node_token->not_before = np_time_now();

	int rand_interval =  ((int)randombytes_uniform(NODE_MAX_TTL_SEC-NODE_MIN_TTL_SEC)+NODE_MIN_TTL_SEC);
	node_token->expires_at = node_token->not_before + rand_interval ;

	crypto_sign_keypair(node_token->public_key, node_token->private_key);   // ed25519
	node_token->private_key_is_set = TRUE;
	/*
	np_tree_insert_str(node_token->extensions, NP_SERIALISATION_NODE_DNS_NAME,
			np_treeval_new_s(node->dns_name));
	np_tree_insert_str(node_token->extensions, NP_SERIALISATION_NODE_PORT,
			np_treeval_new_s(node->port));
	np_tree_insert_str(node_token->extensions, NP_SERIALISATION_NODE_PROTOCOL,
			np_treeval_new_ush(node->protocol));
	*/
	//_np_aaatoken_add_signature(node_token);
	return (node_token);
}

void _np_node_update (np_node_t* node, uint8_t proto, char *hn, char* port)
{
	node->protocol = proto;

	if (NULL != node->dns_name) free(node->dns_name);
	node->dns_name = strndup (hn, strlen(hn));

	if (NULL != node->port) free(node->port);
	node->port = strndup(port, strlen(port));
}


/** _np_node_update_stat:
 ** updates the responded rate to the host based on the NP_NODE_SUCCESS_WINDOW average
 **/
void _np_node_update_stat (np_node_t* node, np_bool responded)
{
	float total = 0;
	np_ref_obj(np_node_t, node,"usage");
	 {
		_LOCK_ACCESS(&node->lock) {

			node->success_win[node->success_win_index++ % NP_NODE_SUCCESS_WINDOW] = responded;

			for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
			{
				total += node->success_win[i];
			}
			node->success_avg = total / NP_NODE_SUCCESS_WINDOW;

			if (0 < responded) node->last_success = np_time_now();
		}
		log_msg(LOG_INFO, "node %s:%s success rate now: %1.1f",
				node->dns_name, node->port, node->success_avg);

		np_unref_obj(np_node_t, node,"usage");
	}
}

void _np_node_update_latency (np_node_t* node, double new_latency)
{
	if (new_latency > 0.0)
	{
		np_ref_obj(np_node_t, node, "usage");
		{
			_LOCK_ACCESS(&node->latency_lock) {
				node->latency_win[node->latency_win_index++ % NP_NODE_SUCCESS_WINDOW] = new_latency;
				
				double total = 0.0;
				for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
				{
					// log_debug_msg(LOG_DEBUG, "latency for node now: %1.1f / %1.1f ", total, node->latency_win[i]);
					total += node->latency_win[i];
				}
				node->latency = total / NP_NODE_SUCCESS_WINDOW;
				log_msg(LOG_INFO, "node %s:%s latency now: %1.3f",
						node->dns_name, node->port, node->latency);					
				
			}
			np_unref_obj(np_node_t, node,"usage");
		}
	}
}

char* _np_node_get_dns_name (np_node_t* np_node)
{
	assert(np_node != NULL);
	return (np_node->dns_name);
}

char* _np_node_get_port (np_node_t* np_node)
{
	assert(np_node != NULL);
	return (np_node->port);
}

float _np_node_get_success_avg (np_node_t* np_node)
{
	assert(np_node != NULL);
	return (np_node->success_avg);
}

float _np_node_get_latency (np_node_t* np_node)
{
	assert(np_node != NULL);
	return (np_node->latency);
}

uint8_t _np_node_check_address_validity (np_node_t* np_node)
{
	assert(np_node != NULL);
	// assert(np_node->network != NULL);

	return (np_node->dns_name && np_node->port);
}


