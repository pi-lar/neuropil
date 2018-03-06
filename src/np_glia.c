//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netdb.h>
#include <inttypes.h>

#include "sodium.h"
#include "event/ev.h"

#include "np_glia.h"

#include "neuropil.h"

#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_dendrit.h"
#include "np_dhkey.h"
#include "np_event.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_list.h"
#include "np_log.h"
#include "np_message.h"
#include "np_memory.h"
#include "np_memory_v2.h"
#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_route.h"
#include "np_threads.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "np_types.h"
#include "np_util.h"
#include "np_settings.h"
#include "np_constants.h"
#include "np_responsecontainer.h"

// TODO: make these configurable (via struct np_config)
/**
 *  neuropil is copyright 2015 by pi-lar GmbH
 */


/**
 ** np_route:
 ** routes a message one step closer to its destination key. Delivers
 ** the message to its destination if it is the current host through the
 ** deliver upcall, otherwise it makes the route upcall
 **/
void _np_glia_route_lookup(np_jobargs_t* args)
{
	log_trace_msg(LOG_TRACE, "start: void _np_glia_route_lookup(np_jobargs_t* args){");

	np_waitref_obj(np_key_t, np_state()->my_node_key, my_key, "np_waitref_obj");
	
	np_sll_t(np_key_ptr, tmp) = NULL;
	np_key_t* target_key = NULL;
	np_message_t* msg_in = args->msg;

	char* msg_subject = np_treeval_to_str(np_tree_find_str(msg_in->header, _NP_MSG_HEADER_SUBJECT)->val, NULL);
	char* msg_target = np_treeval_to_str(np_tree_find_str(msg_in->header, _NP_MSG_HEADER_TO)->val, NULL);

	np_bool is_a_join_request = FALSE;
	if (0 == strncmp(msg_subject, _NP_MSG_JOIN_REQUEST, strlen(_NP_MSG_JOIN_REQUEST)) )
	{
		is_a_join_request = TRUE;
	}

	np_dhkey_t search_key;
	_np_dhkey_from_str(msg_target, &search_key);

	// 1 means: always send out message to another node first, even if it returns
	tmp = _np_route_lookup(search_key, 1);
	if ( 0 < sll_size(tmp) )
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "route_lookup result 1 = %s", _np_key_as_str(sll_first(tmp)->val));


	if ( NULL != tmp                &&
		 0    < sll_size(tmp)       &&
		 FALSE == is_a_join_request &&
		 (_np_dhkey_equal(&sll_first(tmp)->val->dhkey, &my_key->dhkey)) )
	{
		// the result returned the sending node, try again with a higher count parameter
		np_unref_list(tmp, "_np_route_lookup");
		sll_free(np_key_ptr, tmp);

		tmp = _np_route_lookup(search_key, 2);
		if (0 < sll_size(tmp))
			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "route_lookup result 2 = %s", _np_key_as_str(sll_first(tmp)->val));

		// TODO: increase count parameter again ?
	}

	if (NULL  != tmp           &&
		0     <  sll_size(tmp) &&
		FALSE == _np_dhkey_equal(&sll_first(tmp)->val->dhkey, &my_key->dhkey))
	{
		target_key = sll_first(tmp)->val;
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "route_lookup result   = %s", _np_key_as_str(target_key));
	}
	else {
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "route_lookup result   = myself");
	}
	
	/* if I am the only host or the closest host is me, deliver the message */
	if (NULL == target_key && FALSE == is_a_join_request)
	{
		// the message has to be handled by this node (e.g. msg interest messages)
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "internal routing for subject '%s'", msg_subject);
				
		np_msgproperty_t* prop = np_msgproperty_get(INBOUND, msg_subject);
		if(prop != NULL) {
			_np_job_submit_msgin_event(0.0, prop, my_key, args->msg, NULL);
		}	
	} else {
		/* hand it over to the np_axon sending unit */
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "forward routing for subject '%s'", msg_subject);

		if (NULL == target_key || TRUE == is_a_join_request)
		{
			target_key = args->target;
		}

		np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, msg_subject);
		if (NULL == prop) {
			prop = np_msgproperty_get(OUTBOUND, _DEFAULT);
		}

		if (args->is_resend == TRUE) {
			_np_job_resubmit_msgout_event(0.0, prop, target_key, args->msg);
		} else {
			_np_job_submit_msgout_event(0.0, prop, target_key, args->msg);
		}
	}
	np_unref_list(tmp, "_np_route_lookup");
	sll_free(np_key_ptr, tmp);
	np_unref_obj(np_key_t, my_key, "np_waitref_obj");
}

void __np_glia_check_connections(np_sll_t(np_key_ptr, connections), __np_glia_check_connections_handler fn) {

	np_key_t *tmp_node_key = NULL;

	sll_iterator(np_key_ptr) iter_keys = sll_first(connections);
	while (iter_keys != NULL)
	{
		tmp_node_key = iter_keys->val;

		// check for bad link nodes
		if (NULL != tmp_node_key->node &&
			tmp_node_key->node->success_avg < BAD_LINK &&
			(np_time_now() - tmp_node_key->node->last_success) >= BAD_LINK_REMOVE_GRACETIME  &&
			tmp_node_key->node->is_handshake_send == TRUE
			)
		{
			log_msg(LOG_INFO, "deleted from table/leafset: %s:%s:%s / %f / %1.2f",
								_np_key_as_str(tmp_node_key),
								tmp_node_key->node->dns_name, tmp_node_key->node->port,
								tmp_node_key->node->last_success,
								tmp_node_key->node->success_avg);

			np_key_t *added = NULL, *deleted = NULL;
			fn(tmp_node_key, FALSE, &deleted, &added);
			if (deleted != tmp_node_key)
			{
				log_msg(LOG_ROUTING | LOG_WARN, "deleting from table returned different key");
			}
		}

		sll_next(iter_keys);
	}
}

/** _np_route_check_leafset_jobexec:
 ** sends a PING message to each member of the leafset and routing table frequently and
 ** sends the leafset to other members of its leafset periodically.
 ** uses _np_job_yield between pings to different nodes
 ** _np_route_check_leafset_jobexec frequency is LEAFSET_CHECK_PERIOD.
 **/
void _np_glia_check_neighbours(NP_UNUSED np_jobargs_t* args) {
	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "leafset check for table started");

	np_sll_t(np_key_ptr, table) = NULL;
	table = _np_route_neighbors();
	__np_glia_check_connections(table, _np_route_leafset_update);
	np_unref_list(table, "_np_route_neighbors");
	sll_free(np_key_ptr, table);
}

void _np_glia_check_routes(NP_UNUSED np_jobargs_t* args) {
	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "leafset check for table started");

	np_sll_t(np_key_ptr, table) = NULL;
	table = _np_route_get_table();
	__np_glia_check_connections(table, _np_route_update);
	np_unref_list(table, "_np_route_get_table");
	sll_free(np_key_ptr, table);
}

void _np_glia_send_pings(NP_UNUSED np_jobargs_t* args) {

	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "leafset check for table started");

	// TODO: do a dynamic selection of keys
	np_sll_t(np_key_ptr, routing_keys) = _np_route_get_table();
	np_sll_t(np_key_ptr, neighbour_keys) = _np_route_neighbors();

	np_sll_t(np_key_ptr, keys) = sll_merge(np_key_ptr, neighbour_keys, routing_keys, _np_key_cmp);

	sll_iterator(np_key_ptr) iter = sll_first(keys);

	while (iter != NULL) {

		if(iter->val != np_state()->my_node_key){
			np_tryref_obj(np_node_t, iter->val->node, node_exists);
			if(node_exists) {
				if (iter->val->node->joined_network) {
					_np_ping_send(iter->val);
				}
				np_unref_obj(np_node_t, iter->val->node, __func__);
			}
		}
		sll_next(iter);
	}
	sll_free(np_key_ptr, keys); // no ref
	np_unref_list(routing_keys, "_np_route_get_table");
	sll_free(np_key_ptr, routing_keys);
	np_unref_list(neighbour_keys, "_np_route_neighbors");
	sll_free(np_key_ptr, neighbour_keys);
}

void _np_glia_log_flush(NP_UNUSED np_jobargs_t* args) {
	_np_log_fflush(TRUE);
}

void _np_glia_send_piggy_requests(NP_UNUSED np_jobargs_t* args) {

	/* send leafset exchange data every 3 times that pings the leafset */
	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "leafset exchange for neighbours started");

	np_sll_t(np_key_ptr, routing_keys) = _np_route_get_table();;
	np_sll_t(np_key_ptr, neighbour_keys) = _np_route_neighbors();
	np_sll_t(np_key_ptr, keys_merged) = sll_merge(np_key_ptr, routing_keys, neighbour_keys, _np_key_cmp);

	int i = 0;
	sll_iterator(np_key_ptr) iter_keys = sll_first(keys_merged);
	while (iter_keys != NULL)
	{
		// send a piggy message to the the nodes in our routing table
		np_msgproperty_t* piggy_prop = np_msgproperty_get(TRANSFORM, _NP_MSG_PIGGY_REQUEST);
		_np_job_submit_transform_event(i*0.031415, piggy_prop, iter_keys->val, NULL);

		i++;
		sll_next(iter_keys);
	}

	sll_free(np_key_ptr, keys_merged);
	np_unref_list(routing_keys, "_np_route_get_table");
	sll_free(np_key_ptr, routing_keys);
	np_unref_list(neighbour_keys, "_np_route_neighbors");
	sll_free(np_key_ptr, neighbour_keys);
}

/**
 ** np_retransmit_tokens
 ** retransmit tokens on a regular interval
 ** default ttl value for message exchange tokens is ten seconds, afterwards they will be invalid
 ** and a new token is required. this also ensures that the correct encryption key will be transmitted
 **/
void _np_retransmit_message_tokens_jobexec(NP_UNUSED np_jobargs_t* args)
{
	log_trace_msg(LOG_TRACE, "start: void _np_retransmit_message_tokens_jobexec(NP_UNUSED np_jobargs_t* args){");
	np_state_t* state = np_state();

	np_tree_elem_t *iter = NULL;
	np_msgproperty_t* msg_prop = NULL;
	_LOCK_MODULE(np_state_message_tokens_t){
		RB_FOREACH(iter, np_tree_s, state->msg_tokens)
		{
			// double now = dtime();
			// double last_update = iter->val.value.d;

			const char* subject = NULL;
			if (iter->key.type == np_treeval_type_char_ptr)
				subject =  np_treeval_to_str(iter->key, NULL);
			else if (iter->key.type == np_treeval_type_special_char_ptr)
				subject = _np_tree_get_special_str(iter->key.value.ush);
			else {
				ASSERT(FALSE,"key type %"PRIu8" is not recognized.", iter->key.type)
			}

			np_dhkey_t target_dhkey = np_dhkey_create_from_hostport(subject, "0");
			np_key_t* target = NULL;
			target = _np_keycache_find_or_create(target_dhkey);

			msg_prop = np_msgproperty_get(TRANSFORM, subject);
			if (NULL != msg_prop)
			{
				_np_job_submit_transform_event(0.0, msg_prop, target, NULL);
				np_unref_obj(np_key_t, target,"_np_keycache_find_or_create");
			}
			else
			{
				// deleted = RB_REMOVE(np_tree_s, state->msg_tokens, iter);
				// free( np_treeval_to_str(deleted->key));
				// free(deleted);
				np_unref_obj(np_key_t,target,"_np_keycache_find_or_create");
				break;
			}
		}

	}

	if (TRUE == state->enable_realm_master)
	{
		np_msgproperty_t* msg_prop = NULL;

		np_dhkey_t target_dhkey = np_dhkey_create_from_hostport(state->my_identity->aaa_token->realm, "0");
		np_key_t* target = NULL;
		target = _np_keycache_find_or_create(target_dhkey);

		msg_prop = np_msgproperty_get(INBOUND, _NP_MSG_AUTHENTICATION_REQUEST);
		if (FALSE == sll_contains(np_callback_t, msg_prop->clb_transform, _np_out_sender_discovery, np_callback_t_sll_compare_type)) {
			sll_append(np_callback_t, msg_prop->clb_transform, _np_out_sender_discovery);
		}
		// _np_out_sender_discovery(0.0, msg_prop, target, NULL);
		_np_job_submit_transform_event(0.0, msg_prop, target, NULL);

		msg_prop = np_msgproperty_get(INBOUND, _NP_MSG_AUTHORIZATION_REQUEST);
		if (FALSE == sll_contains(np_callback_t, msg_prop->clb_transform, _np_out_sender_discovery, np_callback_t_sll_compare_type)) {
			sll_append(np_callback_t, msg_prop->clb_transform, _np_out_sender_discovery);
		}
		_np_job_submit_transform_event(0.0, msg_prop, target, NULL);

		msg_prop = np_msgproperty_get(INBOUND, _NP_MSG_ACCOUNTING_REQUEST);
		if (FALSE == sll_contains(np_callback_t, msg_prop->clb_transform, _np_out_sender_discovery, np_callback_t_sll_compare_type)) {
			sll_append(np_callback_t, msg_prop->clb_transform, _np_out_sender_discovery);
		}
		_np_job_submit_transform_event(0.0, msg_prop, target, NULL);

		np_unref_obj(np_key_t, target,"_np_keycache_find_or_create");
	}
}

void _np_renew_node_token_jobexec(NP_UNUSED np_jobargs_t* args)
{
	log_trace_msg(LOG_TRACE, "start: void _np_renew_node_token_jobexec(NP_UNUSED np_jobargs_t* args){");

	_LOCK_MODULE(np_node_renewal_t) {
		np_state_t* state = np_state();

		// check an refresh my own identity + node tokens if required
		double exp_ts = np_time_now() + NODE_RENEW_BEFORE_EOL_SEC;

		if (state->my_node_key->aaa_token->expires_at < exp_ts)
		{
			log_msg(LOG_WARN, "---------- expiration of own node token reached ----------");

			np_key_renew_token();
		}

		if (state->my_identity->aaa_token->expires_at < exp_ts)
		{
			// if the user has set a aaatoken manually, he is responsible to refresh it in time
			log_msg(LOG_ERROR, "your identity aaatoken has expired, please refresh !!!");
		}
	}
}

/**
 ** _np_cleanup
 ** general resend mechanism. all message which have an acknowledge indicator set are stored in
 ** memory. If the acknowledge has not been send in time, we try to redeliver the message, otherwise
 ** the message gets deleted or dropped (if max redelivery has been reached)
 ** redelivery has two aspects -> simple resend or reroute because of bad link nodes in the routing table
 **/
void _np_cleanup_ack_jobexec(NP_UNUSED np_jobargs_t* args)
{
	log_trace_msg(LOG_TRACE, "start: void _np_cleanup_ack_jobexec(NP_UNUSED np_jobargs_t* args){");

	np_waitref_obj(np_key_t, np_state()->my_node_key, my_key, "np_waitref_obj");
	np_network_t* ng = my_key->network;

	np_tree_elem_t *jrb_ack_node = NULL;

	// wake up and check for acknowledged messages

	np_tree_elem_t* iter = NULL;
	int c = 0;
	do {
		if (c++ > 10) {
			break;
		}
		_LOCK_ACCESS(&ng->waiting_lock)
		{
			iter = RB_MIN(np_tree_s, ng->waiting);

			while (iter != NULL)
			{
				jrb_ack_node = iter;
				iter = RB_NEXT(np_tree_s, ng->waiting, iter);

				np_responsecontainer_t *responsecontainer = (np_responsecontainer_t *)jrb_ack_node->val.value.v;
				if (responsecontainer != NULL) {
					if (np_time_now() > responsecontainer->expires_at || _np_responsecontainer_is_fully_acked(responsecontainer))
					{
						if (!_np_responsecontainer_is_fully_acked(responsecontainer)) {

							_np_responsecontainer_set_timeout(responsecontainer);
							log_msg(LOG_WARN, "ACK_HANDLING timeout (table size: %3d) message (%s) not acknowledged (IN TIME %f/%f)",
								ng->waiting->size,
								jrb_ack_node->key.value.s,
								np_time_now(), responsecontainer->expires_at
							);
						}

						np_tree_del_str(ng->waiting, jrb_ack_node->key.value.s);
						np_unref_obj(np_responsecontainer_t, responsecontainer, ref_ack_obj);
						break;
					}
				}
				else {
					log_debug_msg(LOG_DEBUG, "ACK_HANDLING (table size: %3d) message (%s) not found",
						ng->waiting->size,
						jrb_ack_node->key.value.s);

				}
			}
		}
	} while (iter != NULL);

	np_unref_obj(np_key_t, my_key,"np_waitref_obj");
}

void _np_cleanup_keycache_jobexec(NP_UNUSED np_jobargs_t* args)
{
	log_trace_msg(LOG_TRACE, "start: void _np_cleanup_keycache_jobexec(NP_UNUSED np_jobargs_t* args){");

	np_key_t* old = NULL;
	double now = np_time_now();

	old = _np_keycache_find_deprecated();

	if (NULL != old)
	{
		log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup check started for key : %p -> %s", old, _np_key_as_str(old));
		np_bool delete_key = TRUE;

		if (NULL != old->node)
		{
			// found a node key, check last_success value
			if ((np_time_now() - old->node->last_success) < 60. )
			{
				// 60 sec no success full msg received
				log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key cancelled because of valid node last_success value: %s", _np_key_as_str(old));
				delete_key &= FALSE;
			}
		}

		np_tryref_obj(np_aaatoken_t, old->aaa_token, tokenExists,"np_tryref_old->aaa_token");
		if(tokenExists) {
			if (TRUE == _np_aaatoken_is_valid(old->aaa_token, np_aaatoken_type_undefined))
			{
				log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key cancelled because of valid aaa_token structure: %s", _np_key_as_str(old));
				delete_key &= FALSE;
			}
			np_unref_obj(np_aaatoken_t, old->aaa_token,"np_tryref_old->aaa_token");
		}

		if (NULL != old->recv_tokens)
		{
			_LOCK_ACCESS(&old->recv_property->lock)
			{
				// check old receiver token structure
				pll_iterator(np_aaatoken_ptr) iter = pll_first(old->recv_tokens);
				while (NULL != iter)
				{
					np_aaatoken_t* tmp_token = iter->val;
					if (TRUE == _np_aaatoken_is_valid(tmp_token, np_aaatoken_type_message_intent))
					{
						log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key cancelled because of valid receiver tokens: %s", _np_key_as_str(old));
						delete_key &= FALSE;
						break;
					}
					pll_next(iter);
				}
			}
		}

		if (NULL != old->send_tokens)
		{
			_LOCK_ACCESS(&old->send_property->lock)
			{
				// check old sender token structure
				pll_iterator(np_aaatoken_ptr) iter = pll_first(old->send_tokens);
				while (NULL != iter)
				{
					np_aaatoken_t* tmp_token = iter->val;
					if (TRUE == _np_aaatoken_is_valid(tmp_token, np_aaatoken_type_message_intent))
					{
						log_debug_msg(LOG_KEY | LOG_DEBUG, "cleanup of key cancelled because of valid sender tokens: %s", _np_key_as_str(old));
						delete_key &= FALSE;
						break;
					}
					pll_next(iter);
				}
			}
		}

		// last sanity check if we should delete
		if (TRUE == delete_key &&
			now > old->last_update)
		{
			_np_key_destroy(old);
		}
		else
		{
			// update timestamp so that the same key cannot be evaluated twice
			old->last_update = np_time_now();
		}
		np_unref_obj(np_key_t, old, "_np_keycache_find_deprecated");
	}
}

/**
 ** np_send_rowinfo:
 ** sends matching row of its table to the target node
 **/
void _np_send_rowinfo_jobexec(np_jobargs_t* args)
{
	log_trace_msg(LOG_TRACE, "start: void _np_send_rowinfo_jobexec(np_jobargs_t* args){");

	np_state_t* state = np_state();
	np_key_t* target_key = args->target;

	// check for correct target
	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "job submit route row info to %s:%s!",
			target_key->node->dns_name, target_key->node->port);

	np_sll_t(np_key_ptr, sll_of_keys) = NULL;
	/* send one row of our routing table back to joiner #host# */

	sll_of_keys = _np_route_row_lookup(target_key);
	char* source_sll_of_keys = "_np_route_row_lookup";
	if (sll_size(sll_of_keys) <= 1)
	{
		// nothing found, send leafset to exchange some data at least
		// prevents small clusters from not exchanging all data
		np_unref_list(sll_of_keys, "_np_route_row_lookup"); // only for completion
		sll_free(np_key_ptr, sll_of_keys);
		sll_of_keys = _np_route_neighbors();
		source_sll_of_keys = "_np_route_neighbors";
	}

	if (sll_size(sll_of_keys) > 0)
	{
		np_tree_t* msg_body = np_tree_create();
		_np_node_encode_multiple_to_jrb(msg_body, sll_of_keys, FALSE);
		np_msgproperty_t* outprop = np_msgproperty_get(OUTBOUND, _NP_MSG_PIGGY_REQUEST);
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending piggy msg (%"PRIu32" nodes) to %s", sll_size(sll_of_keys), _np_key_as_str(target_key));

		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		_np_message_create(msg_out, target_key, state->my_node_key, _NP_MSG_PIGGY_REQUEST, msg_body);
		_np_job_submit_msgout_event(0.0, outprop, target_key, msg_out);
		np_unref_obj(np_message_t, msg_out, ref_obj_creation);
	}

	np_unref_list(sll_of_keys, source_sll_of_keys);
	sll_free(np_key_ptr, sll_of_keys);
}

void _np_send_subject_discovery_messages(np_msg_mode_type mode_type, const char* subject)
{
	log_trace_msg(LOG_TRACE, "start: void _np_send_subject_discovery_messages(np_msg_mode_type mode_type, const char* subject){");

	//TODO: msg_tokens for either
	// insert into msg token token renewal queue
	_LOCK_MODULE(np_state_message_tokens_t) {
		if (NULL == np_tree_find_str(np_state()->msg_tokens, subject))
		{
			np_tree_insert_str(np_state()->msg_tokens, subject, np_treeval_new_v(NULL));

			np_msgproperty_t* msg_prop = np_msgproperty_get(mode_type, subject);
			msg_prop->mode_type |= TRANSFORM;
			if (FALSE == sll_contains(np_callback_t, msg_prop->clb_transform, _np_out_discovery_messages, np_callback_t_sll_compare_type)) {
				sll_append(np_callback_t, msg_prop->clb_transform, _np_out_discovery_messages);
			}

			np_dhkey_t target_dhkey = np_dhkey_create_from_hostport(subject, "0");
			np_key_t* target = NULL;
			target = _np_keycache_find_or_create(target_dhkey);

			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "registering for message discovery token handling (%s)", subject);
			_np_job_submit_transform_event(0.0, msg_prop, target, NULL);
			np_unref_obj(np_key_t, target, "_np_keycache_find_or_create");
		}
	}
}

// TODO: add a wrapper function which can be scheduled via jobargs
np_bool _np_send_msg (char* subject, np_message_t* msg, np_msgproperty_t* msg_prop, np_dhkey_t* target)
{
	// np_aaatoken_t* tmp_token = _np_aaatoken_get_receiver(subject, &target_key);
	np_message_intent_public_token_t* tmp_token = _np_aaatoken_get_receiver(subject, target);	
	if (NULL != tmp_token && _np_aaatoken_is_valid(tmp_token, np_aaatoken_type_message_intent)) {
		_np_msgproperty_threshold_increase(msg_prop);
		log_msg(LOG_INFO | LOG_ROUTING, "(msg: %s) for subject \"%s\" has valid token", msg->uuid, subject);	

		np_bool free_target_node_str = FALSE;
		char* target_node_str = NULL;
		np_tree_elem_t* tn_node = np_tree_find_str(tmp_token->extensions,  "target_node");
		if (NULL != tn_node)
		{
			target_node_str =  np_treeval_to_str(tn_node->val, &free_target_node_str);
		}
		else
		{
			target_node_str = tmp_token->issuer;
		}

		//TODO: instead of token threshold a local copy of the value should be increased
		np_tree_find_str(tmp_token->extensions_local, "msg_threshold")->val.value.ui++;

		np_key_t*  receiver_key = NULL;
		np_dhkey_t receiver_dhkey;

		_np_dhkey_from_str(target_node_str, &receiver_dhkey);
		receiver_key = _np_keycache_find_or_create(receiver_dhkey);

		if (_np_key_cmp(np_state()->my_node_key, receiver_key) == 0) {
			np_msgproperty_t* handler = np_msgproperty_get(INBOUND, msg->msg_property->msg_subject);
			if(handler != NULL) {
				_np_in_new_msg_received(msg, handler);
			}

		} else {
			// encrypt the relevant message part itself
			_np_message_encrypt_payload(msg, tmp_token);

			np_tree_replace_str(msg->header, _NP_MSG_HEADER_TO, np_treeval_new_s(target_node_str));
			if (free_target_node_str == TRUE && msg->header->attr.in_place == FALSE) {
				free(target_node_str);
			}

			np_msgproperty_t* out_prop = np_msgproperty_get(OUTBOUND, subject);
			_np_job_submit_route_event(0.0, out_prop, receiver_key, msg);

			if (NULL != msg_prop->rep_subject &&
				STICKY_REPLY == (msg_prop->mep_type & STICKY_REPLY))
			{
				_np_aaatoken_add_sender(msg_prop->rep_subject, tmp_token);
			}
		}

		// decrease threshold counters
		_np_msgproperty_threshold_decrease(msg_prop);

		np_unref_obj(np_aaatoken_t, tmp_token,"_np_aaatoken_get_receiver");
		np_unref_obj(np_key_t, receiver_key,"_np_keycache_find_or_create");
		
		return (TRUE);
	}
	else
	{
		log_msg(LOG_INFO, "(msg: %s) for subject \"%s\" has NO valid token", msg->uuid, subject);
		_np_msgproperty_add_msg_to_send_cache(msg_prop, msg);
	}
	return (FALSE);
}
