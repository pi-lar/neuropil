//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "neuropil.h"

#include "event/ev.h"
#include "sodium.h"

#include "np_log.h"
#include "np_tree.h"
#include "np_types.h"
#include "np_treeval.h"
#include "np_keycache.h"
#include "np_aaatoken.h"
#include "np_network.h"
#include "np_node.h"
#include "np_msgproperty.h"
#include "np_key.h"
#include "np_route.h"
#include "np_jobqueue.h"
#include "np_constants.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_key_t);

NP_SLL_GENERATE_IMPLEMENTATION(np_key_ptr);
NP_PLL_GENERATE_IMPLEMENTATION(np_key_ptr);

int8_t _np_key_cmp(np_key_t* const k1, np_key_t* const k2)
{
	log_msg(LOG_TRACE | LOG_KEY, "start: int8_t _np_key_cmp(np_key_t* const k1, np_key_t* const k2){");
	if (k1 == NULL) return -1;
	if (k2 == NULL) return  1;

	return _np_dhkey_comp(&k1->dhkey,&k2->dhkey);
}

int8_t _np_key_cmp_inv(np_key_t* const k1, np_key_t* const k2)
{
	log_msg(LOG_TRACE | LOG_KEY, "start: int8_t _np_key_cmp_inv(np_key_t* const k1, np_key_t* const k2){");
	return -1 * _np_key_cmp(k1, k2);
}

char* _np_key_as_str(np_key_t* key)
{
	log_msg(LOG_TRACE | LOG_KEY, "start: char* _np_key_as_str(np_key_t* key){");
	if (NULL == key->dhkey_str)
	{
		key->dhkey_str = (char*) malloc(65);
		CHECK_MALLOC(key->dhkey_str);

		_np_dhkey_to_str(&key->dhkey, key->dhkey_str);
		log_debug_msg(LOG_KEY | LOG_DEBUG, "dhkey_str = %lu (%s)", strlen(key->dhkey_str), key->dhkey_str);
	}

	return key->dhkey_str;
}

void np_ref_list(np_sll_t(np_key_ptr, sll_list), const char* reason, const char* reason_desc)
{
	sll_iterator(np_key_ptr) iter = sll_first(sll_list);
	while (NULL != iter)
	{
		np_ref_obj(np_key_t, (iter->val), reason, reason_desc);
		sll_next(iter);
	}
}

void np_unref_list(np_sll_t(np_key_ptr, sll_list) , const char* reason)
{
	sll_iterator(np_key_ptr) iter = sll_first(sll_list);
	while (NULL != iter)
	{
		np_unref_obj(np_key_t, (iter->val), reason);
		sll_next(iter);
	}
}

/**
 * Destroys a key with all resources
 */
void _np_key_destroy(np_key_t* to_destroy) {
	log_msg(LOG_TRACE | LOG_KEY, "start: void _np_key_destroy(np_key_t* to_destroy) {");

	np_tryref_obj(np_key_t, to_destroy, to_destroyExists,"np_tryref_key");
	if(to_destroyExists) {
		to_destroy->in_destroy = TRUE;

		_LOCK_ACCESS(to_destroy->obj->lock) {

			char* keyident = _np_key_as_str(to_destroy);
			log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key and associated data structures: %s", keyident);
		
			log_debug_msg( LOG_DEBUG, "refcount of key %s at destroy: %d", keyident, to_destroy->obj == NULL ? 0 : to_destroy->obj->ref_count);
			
			np_key_t* deleted;
			np_key_t* added;

			_np_route_leafset_update(to_destroy,FALSE,&deleted,&added);
			_np_route_update(to_destroy,FALSE,&deleted,&added);
			_np_network_stop(to_destroy->network);

			_np_keycache_remove(to_destroy->dhkey);

			// delete old receive tokens
			if (NULL != to_destroy->recv_tokens)
			{
				if(to_destroy->recv_property != NULL) {
					_LOCK_ACCESS(&to_destroy->recv_property->lock)
					{
						pll_iterator(np_aaatoken_ptr) iter = pll_first(to_destroy->recv_tokens);
						while (NULL != iter)
						{
							np_unref_obj(np_aaatoken_t, iter->val,"recv_tokens");
							pll_next(iter);
						}
						pll_free(np_aaatoken_ptr, to_destroy->recv_tokens);
						to_destroy->recv_tokens = NULL;
					}
				}
			}

			// delete send tokens
			if (NULL != to_destroy->send_tokens)
			{
				if(to_destroy->send_property != NULL) {
					_LOCK_ACCESS(&to_destroy->send_property->lock)
					{
						pll_iterator(np_aaatoken_ptr) iter = pll_first(to_destroy->send_tokens);
						while (NULL != iter)
						{
							np_unref_obj(np_aaatoken_t, iter->val,"send_tokens");
							pll_next(iter);
						}
						pll_free(np_aaatoken_ptr, to_destroy->send_tokens);
						to_destroy->send_tokens = NULL;
					}
				}
			}
		}

		np_sll_t(np_key_ptr, aliasse)  = _np_keycache_find_aliase(to_destroy);
		sll_iterator(np_key_ptr) iter = sll_first(aliasse);

		while(iter != NULL) {
			_np_key_destroy(iter->val);
			np_unref_obj(np_key_t, iter->val,"_np_keycache_find_aliase");
			sll_next(iter);
		}
		sll_free(np_key_ptr, aliasse);

		if(to_destroy->parent != NULL){
			np_unref_obj(np_key_t, to_destroy->parent, ref_key_parent);
			to_destroy->parent = NULL;
		}

		np_unref_obj(np_key_t, to_destroy,"np_tryref_key");
		log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key and associated data structures done.");
	} else {
		log_debug_msg(LOG_KEY | LOG_DEBUG, "no key provided for cleanup");
	}
}


void _np_key_t_new(void* key)
{
	log_msg(LOG_TRACE | LOG_KEY, "start: void _np_key_t_new(void* key){");
	np_key_t* new_key = (np_key_t*) key;

	new_key->in_destroy = FALSE;
	new_key->last_update = np_time_now();

	new_key->dhkey_str = NULL;
	new_key->node = NULL;		  // link to a neuropil node if this key represents a node
	new_key->network = NULL;      // link to a neuropil node if this key represents a node
	
	new_key->aaa_token = NULL;

	// used internally only
	new_key->recv_property = NULL;
	new_key->send_property = NULL;

	new_key->local_mx_tokens = NULL; // link to runtime interest data on which this node is interested in

	new_key->send_tokens = NULL; // link to runtime interest data on which this node is interested in
	new_key->recv_tokens = NULL; // link to runtime interest data on which this node is interested in

	new_key->parent = NULL;
	new_key->created_at = np_time_now();
	log_debug_msg(LOG_KEY | LOG_DEBUG, "Created new key");

}

void _np_key_t_del(void* key)
{
	log_msg(LOG_TRACE | LOG_KEY, "start: void _np_key_t_del(void* key){");
	np_key_t* old_key = (np_key_t*) key;

	_np_key_destroy(old_key);

	// delete string presentation of key
	if (NULL != old_key->dhkey_str)
	{
		free (old_key->dhkey_str);
		old_key->dhkey_str = NULL;
	}

	// unref and delete of other object pointers has to be done outside of this function
	// otherwise double locking the memory pool will lead to a deadlock

	np_unref_obj(np_msgproperty_t, 	old_key->recv_property,ref_key_recv_property);
	np_unref_obj(np_msgproperty_t, 	old_key->send_property,ref_key_send_property);
	np_unref_obj(np_aaatoken_t,		old_key->aaa_token,ref_key_aaa_token);
	np_unref_obj(np_node_t,     	old_key->node,ref_key_node);
	np_unref_obj(np_network_t,  	old_key->network,ref_key_network);
}

void np_key_renew_token() {

	_LOCK_MODULE(np_node_renewal_t) 
	{
		np_state_t* state = _np_state();

		np_key_t* new_node_key = NULL;
		np_key_t* old_node_key = state->my_node_key;

		np_ref_obj(np_key_t, old_node_key,"np_key_renew_token");

		log_debug_msg(LOG_DEBUG, "step ._np_renew_node_token_jobexec.Creating new node key");

		np_aaatoken_t* new_token = _np_node_create_token(old_node_key->node);
		new_node_key = _np_key_create_from_token(new_token);

		np_ref_obj(np_aaatoken_t, new_token,ref_key_aaa_token);
		new_node_key->aaa_token = new_token;

		// find closest member according to old routing table
		log_debug_msg(LOG_DEBUG, "step ._np_renew_node_token_jobexec.get routing table");
		np_sll_t(np_key_ptr, table) = _np_route_get_table();

		// sort to get potential closest neighbor first
		_np_keycache_sort_keys_kd(table, &new_node_key->dhkey);
		sll_iterator(np_key_ptr) iterator = sll_first(table);

		np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _NP_MSG_UPDATE_REQUEST);
		np_message_t* msg_out_update = NULL;

		np_tree_t* jrb_new = np_tree_create(FALSE);
		np_aaatoken_encode(jrb_new, new_node_key->aaa_token);
		np_tree_t* jrb_old = np_tree_create(FALSE);
		np_aaatoken_encode(jrb_old, old_node_key->aaa_token);

		log_debug_msg(LOG_DEBUG, "step ._np_renew_node_token_jobexec.Sending new aaatoken to old known nodes");
		iterator = sll_first(table);
		while (NULL != iterator)
		{
			//_np_route_update(iterator->val, TRUE, &deleted, &added);
			//_np_route_leafset_update(iterator->val, TRUE, &deleted, &added);

			// send join messages to entries of the routing	 table to re-arrange internal routing
			/* request update from join with peer */
			np_tree_t* jrb_new_me = np_tree_clone(jrb_new);
			np_new_obj(np_message_t, msg_out_update);
			log_debug_msg(LOG_DEBUG, "step ._np_renew_node_token_jobexec.submitting update request to target key %s", _np_key_as_str(iterator->val));
			_np_message_create(msg_out_update, iterator->val, old_node_key, _NP_MSG_UPDATE_REQUEST, jrb_new_me);

			_np_job_submit_msgout_event(0.0, prop, iterator->val, msg_out_update);
			np_unref_obj(np_message_t, msg_out_update, ref_obj_creation);

			/*
			np_tree_t* jrb_old_me = np_tree_clone(jrb_old);
			np_new_obj(np_message_t, msg_out_leave);
			_np_message_create(msg_out_leave, iterator->val, new_node_key, _NP_MSG_LEAVE_REQUEST, jrb_old_me);
			_np_job_submit_msgout_event(0.0, prop, iterator->val, msg_out_leave);
			np_unref_obj(np_message_t, msg_out_leave);
			 */

			sll_next(iterator);
		}
		np_tree_free(jrb_new);
		np_tree_free(jrb_old);

		log_debug_msg(LOG_DEBUG, "step ._np_renew_node_token_jobexec.replacing identity");
		// _np_job_yield(state->my_node_key->aaa_token->expires_at - ev_time());
		// exchange identity if required
		if (state->my_identity == old_node_key)
		{
			np_ref_switch(np_key_t, state->my_identity, ref_state_identity, new_node_key);
		}
		else
		{
			np_tree_replace_str(state->my_identity->aaa_token->extensions, "target_node", np_treeval_new_s(_np_key_as_str(new_node_key)) );
		}
		log_debug_msg(LOG_DEBUG, "step ._np_renew_node_token_jobexec.replacing key");


		log_debug_msg(LOG_DEBUG, "step ._np_renew_node_token_jobexec.Updating network");
		_LOCK_ACCESS(&old_node_key->network->send_data_lock)
		{
			// save old network setup
			_np_network_remap_network(new_node_key, old_node_key);

			np_ref_switch(np_key_t, state->my_node_key->network->watcher.data, ref_network_watcher, new_node_key);
			state->my_node_key->node->joined_network = old_node_key->node->joined_network;
		}

		_LOCK_MODULE(np_routeglobal_t)
		{
			log_debug_msg(LOG_DEBUG, "step ._np_renew_node_token_jobexec.got _LOCK_MODULE(np_routeglobal_t)");

			// exchange node key
			np_ref_obj(np_key_t, new_node_key );
			state->my_node_key = new_node_key;

			log_debug_msg(LOG_DEBUG, "step ._np_renew_node_token_jobexec._np_route_clear");
			// clear the table
			_np_route_clear();

			log_debug_msg(LOG_DEBUG, "step ._np_renew_node_token_jobexec.set key");
			// re-set routing table midpoint
			_np_route_set_key(state->my_node_key);

			// re-arrange routing table and leafset
			np_key_t* deleted = NULL;
			np_key_t* added = NULL;
			iterator = sll_first(table);
			while (NULL != iterator)
			{
				_np_route_update(iterator->val, TRUE, &deleted, &added);
				_np_route_leafset_update(iterator->val, TRUE, &deleted, &added);

				sll_next(iterator);
			}
		}

		log_debug_msg(LOG_DEBUG, "step ._np_renew_node_token_jobexec.Completed node renewal. cleaning up now");

		// clean up
		np_unref_list(table,"_np_route_get_table");
		sll_free(np_key_ptr, table);

		_np_key_destroy(old_node_key);

		np_unref_obj(np_key_t, old_node_key,"np_key_renew_token");
	}
}
