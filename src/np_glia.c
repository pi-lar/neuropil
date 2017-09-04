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

#include "dtime.h"
#include "neuropil.h"

#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_dhkey.h"
#include "np_event.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_list.h"
#include "np_log.h"
#include "np_message.h"
#include "np_memory.h"
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

// TODO: make these configurable (via struct np_config)
/**
 *  neuropil is copyright 2015 by pi-lar GmbH
 */

static uint8_t __leafset_check_type = 0;
static double  __leafset_check_period = 3.1415;
static double  __leafset_yield_period = 0.031415;

static double  __rowinfo_send_delay = 0.03141;

static double  __token_retransmit_period = 3.1415;

static double  __cleanup_interval = 0.31415;

/**
 ** np_route:
 ** routes a message one step closer to its destination key. Delivers
 ** the message to its destination if it is the current host through the
 ** deliver upcall, otherwise it makes the route upcall
 **/
void _np_route_lookup_jobexec(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_route_lookup_jobexec(np_jobargs_t* args){");

	np_waitref_obj(np_key_t, _np_state()->my_node_key, my_key, "np_waitref_obj");

	np_sll_t(np_key_ptr, tmp) = NULL;
	np_key_t* target_key = NULL;
	np_message_t* msg_in = args->msg;

	char* msg_subject = np_tree_find_str(msg_in->header, _NP_MSG_HEADER_SUBJECT)->val.value.s;
	char* msg_target = np_tree_find_str(msg_in->header, _NP_MSG_HEADER_TO)->val.value.s;

	np_bool is_a_join_request = FALSE;
	if (0 == strncmp(msg_subject, _NP_MSG_JOIN_REQUEST, strlen(_NP_MSG_JOIN_REQUEST)) )
	{
		is_a_join_request = TRUE;
	}

	np_dhkey_t search_key;
	_np_dhkey_from_str(msg_target, &search_key);
	np_key_t k_msg_address = { .dhkey = search_key };

	// first lookup call for target key
	log_debug_msg(LOG_DEBUG, "message target is key %s", _np_key_as_str(&k_msg_address));


	// 1 means: always send out message to another node first, even if it returns
	tmp = _np_route_lookup(&k_msg_address, 1);
	if ( 0 < sll_size(tmp) )
		log_debug_msg(LOG_DEBUG, "route_lookup result 1 = %s", _np_key_as_str(sll_first(tmp)->val));


	if ( NULL != tmp                &&
		 0    < sll_size(tmp)       &&
		 FALSE == is_a_join_request &&
		 (_np_dhkey_equal(&sll_first(tmp)->val->dhkey, &my_key->dhkey)) )
	{
		// the result returned the sending node, try again with a higher count parameter
		np_unref_list(tmp, "_np_route_lookup"); 
		sll_free(np_key_ptr, tmp);

		tmp = _np_route_lookup(&k_msg_address, 2);
		if (0 < sll_size(tmp))
			log_debug_msg(LOG_DEBUG, "route_lookup result 2 = %s", _np_key_as_str(sll_first(tmp)->val));

		// TODO: increase count parameter again ?
	}

	//_np_key_t_del(&k_msg_address);

	if (NULL  != tmp           &&
		0     <  sll_size(tmp) &&
		FALSE == _np_dhkey_equal(&sll_first(tmp)->val->dhkey, &my_key->dhkey))
	{
		target_key = sll_first(tmp)->val;
		log_debug_msg(LOG_DEBUG, "route_lookup result   = %s", _np_key_as_str(target_key));
	}

	/* if I am the only host or the closest host is me, deliver the message */
	// TODO: not working ?
	if (NULL == target_key && FALSE == is_a_join_request)
	{
		// the message has to be handled by this node (e.g. msg interest messages)
		log_debug_msg(LOG_DEBUG, "internal routing for subject '%s'", msg_subject);
		np_message_t* msg_to_submit = NULL;

		if (TRUE == args->msg->is_single_part)
		{
			// sum up message parts if the message is for this node
			msg_to_submit = _np_message_check_chunks_complete(args->msg);
			if (NULL == msg_to_submit)
			{
				np_unref_list(tmp, "_np_route_lookup");
				sll_free(np_key_ptr, tmp);
				np_unref_obj(np_key_t, my_key, "np_waitref_obj");
				return;
			}
			_np_message_deserialize_chunked(msg_to_submit);
			np_unref_obj(np_message_t, msg_to_submit, "_np_message_check_chunks_complete");
		}
		else
		{
			msg_to_submit = args->msg;
		}

		np_msgproperty_t* prop = np_msgproperty_get(INBOUND, msg_subject);
		if (prop != NULL)
		{
			_np_job_submit_msgin_event(0.0, prop, my_key, msg_to_submit);
		}

	} else {
		/* hand it over to the np_axon sending unit */
		log_debug_msg(LOG_DEBUG, "forward routing for subject '%s'", msg_subject);

		if (NULL == target_key || TRUE == is_a_join_request)
		{
			target_key = args->target;
		}

		np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, msg_subject);
		if (NULL == prop) {
			prop = np_msgproperty_get(OUTBOUND, _DEFAULT);
		}

		if (TRUE == args->is_resend) {
			_np_job_resubmit_msgout_event(0.0, prop, target_key, args->msg);
		} else {
			_np_job_submit_msgout_event(0.0, prop, target_key, args->msg);
		}
	}
	np_unref_list(tmp, "_np_route_lookup");
	sll_free(np_key_ptr, tmp);
	np_unref_obj(np_key_t, my_key, "np_waitref_obj");
}
void _np_never_called_jobexec_transform(np_jobargs_t* args)
{
	_np_never_called_jobexec(args,"transform");
}
void _np_never_called_jobexec_route(np_jobargs_t* args)
{
	_np_never_called_jobexec(args,"route");
}
void _np_never_called_jobexec_inbound(np_jobargs_t* args)
{
	_np_never_called_jobexec(args,"inbound");
}
void _np_never_called_jobexec_outbound(np_jobargs_t* args)
{
	_np_never_called_jobexec(args,"outbound");
}
void _np_never_called_jobexec(np_jobargs_t* args,char* category)
{
	log_msg(LOG_TRACE, "start: void _np_never_called_jobexec(np_jobargs_t* args){");
	log_msg(LOG_WARN, "!!!                               !!!");
	log_msg(LOG_WARN, "!!! wrong job execution requested (%s) !!!",category);
	if (NULL != args)
	{
		log_msg(LOG_WARN, "!!! a: %p m: %p p: %p t: %p", args, args->msg, args->properties, args->target);
		if (args->properties)
			log_msg(LOG_WARN, "!!! properties: %s ", args->properties->msg_subject);
		if (args->target)
			log_msg(LOG_WARN, "!!! target: %s ", _np_key_as_str(args->target));
	}
	log_msg(LOG_WARN, "!!!                               !!!");
	log_msg(LOG_WARN, "!!!                               !!!");
}

/** _np_route_check_leafset_jobexec:
 ** sends a PING message to each member of the leafset and routing table frequently and
 ** sends the leafset to other members of its leafset periodically.
 ** uses _np_job_yield between pings to different nodes
 ** _np_route_check_leafset_jobexec frequency is LEAFSET_CHECK_PERIOD.
 **/
void _np_route_check_leafset_jobexec(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_route_check_leafset_jobexec(NP_UNUSED np_jobargs_t* args){");

	np_sll_t(np_key_ptr, leafset) = NULL;
	np_key_t *tmp_node_key = NULL;

	log_debug_msg(LOG_DEBUG, "leafset check for neighbours started");

	// each time to try to ping our leafset hosts
	leafset = _np_route_neighbors();

	double now = ev_time();
	while (NULL != (tmp_node_key = sll_head(np_key_ptr, leafset)))
	{
		// check for bad link nodes
		if (NULL != tmp_node_key->node &&
			tmp_node_key->node->success_avg < BAD_LINK &&
			(now - tmp_node_key->node->last_success) >= BAD_LINK_REMOVE_GRACETIME  &&
			tmp_node_key->node->handshake_status > HANDSHAKE_UNKNOWN)
		{
			log_debug_msg(LOG_DEBUG, "deleting from neighbours: %s", _np_key_as_str(tmp_node_key));
			// request a new handshake with the node
			if (NULL != tmp_node_key->aaa_token)
				tmp_node_key->aaa_token->state &= AAA_INVALID;
			tmp_node_key->node->handshake_status = HANDSHAKE_UNKNOWN;

			np_key_t *added = NULL, *deleted = NULL;
			_np_route_leafset_update(tmp_node_key, FALSE, &deleted, &added);
			if (deleted != tmp_node_key)
			{
				log_msg(LOG_ERROR, "deleting from neighbours returned different key");
				// log_msg(LOG_WARN, "deleting from neighbours returned different key: %s", _np_key_as_str(deleted));
			}
			//np_unref_obj(np_key_t, tmp_node_key,"?");
		}
		else
		{
			/* otherwise request reevaluation of peer */
			double delta = ev_time() - tmp_node_key->node->last_success;
			if (delta > __leafset_check_period)
			{
				_np_ping(tmp_node_key);
				_np_job_yield(__leafset_yield_period);
			}
		}
		np_unref_obj(np_key_t, tmp_node_key,"_np_route_neighbors");
	}
	sll_free(np_key_ptr, leafset);


	if (__leafset_check_type == 1)
	{
		log_debug_msg(LOG_DEBUG, "leafset check for table started");
		np_sll_t(np_key_ptr, table) = NULL;
		table = _np_route_get_table();

		while ( NULL != (tmp_node_key = sll_head(np_key_ptr, table)))
		{
			// send update of new node to all nodes in my routing table
			/* first check for bad link nodes */
			if (NULL != tmp_node_key->node &&
				tmp_node_key->node->success_avg < BAD_LINK &&
				(now - tmp_node_key->node->last_success) >= BAD_LINK_REMOVE_GRACETIME  &&
				tmp_node_key->node->handshake_status > HANDSHAKE_UNKNOWN)
			{
				log_debug_msg(LOG_DEBUG, "deleting from table: %s", _np_key_as_str(tmp_node_key));

				// request a new handshake with the node
				if (NULL != tmp_node_key->aaa_token)
					tmp_node_key->aaa_token->state &= AAA_INVALID;

				tmp_node_key->node->handshake_status = HANDSHAKE_UNKNOWN;

				np_key_t *added = NULL, *deleted = NULL;
				_np_route_update(tmp_node_key, FALSE, &deleted, &added);
				if (deleted != tmp_node_key)
				{
					log_msg(LOG_WARN, "deleting from table returned different key");
					// log_msg(LOG_WARN, "deleting from neighbours returned different key: %s", _np_key_as_str(deleted));
				}
				//np_unref_obj(np_key_t, tmp_node_key,"?");
			}
			else
			{
				/* otherwise request re-evaluation of node stats */
				double delta = ev_time() - tmp_node_key->node->last_success;
				if (delta > (3 * __leafset_check_period))
				{
					_np_ping(tmp_node_key);
					_np_job_yield(__leafset_yield_period);
				}
			}
			np_unref_obj(np_key_t, tmp_node_key,"_np_route_get_table");
		}
		sll_free(np_key_ptr, table);
	}

	if (__leafset_check_type == 2)
	{
		/* send leafset exchange data every 3 times that pings the leafset */
		log_debug_msg(LOG_DEBUG, "leafset exchange for neighbours started");

		leafset = _np_route_neighbors();
		int i=0;
		while ( NULL != (tmp_node_key = sll_head(np_key_ptr, leafset)))
		{
			// send a piggy message to the the nodes in our routing table
			np_msgproperty_t* piggy_prop = np_msgproperty_get(TRANSFORM, _NP_MSG_PIGGY_REQUEST);
			_np_job_submit_transform_event(__leafset_yield_period*i, piggy_prop, tmp_node_key, NULL);
			// _np_job_yield(__leafset_yield_period);
			np_unref_obj(np_key_t, tmp_node_key,"_np_route_neighbors");
			i++;
		}
		__leafset_check_type = 0;
		sll_free(np_key_ptr, leafset);
	}
	else
	{
		__leafset_check_type++;
	}
	// np_mem_printpool();
	np_job_submit_event(__leafset_check_period, _np_route_check_leafset_jobexec);
}

/**
 ** np_retransmit_tokens
 ** retransmit tokens on a regular interval
 ** default ttl value for message exchange tokens is ten seconds, afterwards they will be invalid
 ** and a new token is required. this also ensures that the correct encryption key will be transmitted
 **/
void _np_retransmit_message_tokens_jobexec(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_retransmit_message_tokens_jobexec(NP_UNUSED np_jobargs_t* args){");
	np_state_t* state = _np_state();

	np_tree_elem_t *iter = NULL;
	np_msgproperty_t* msg_prop = NULL;

	RB_FOREACH(iter, np_tree_s, state->msg_tokens)
	{
		// double now = dtime();
		// double last_update = iter->val.value.d;
		np_dhkey_t target_dhkey = np_dhkey_create_from_hostport(iter->key.value.s, "0");
		np_key_t* target = NULL;

		target = _np_keycache_find_or_create(target_dhkey);

		msg_prop = np_msgproperty_get(TRANSFORM, iter->key.value.s);
		if (NULL != msg_prop)
		{
			_np_job_submit_transform_event(0.0, msg_prop, target, NULL);
			np_unref_obj(np_key_t, target,"_np_keycache_find_or_create");
		}
		else
		{
			// deleted = RB_REMOVE(np_tree_s, state->msg_tokens, iter);
			// free(deleted->key.value.s);
			// free(deleted);
			np_unref_obj(np_key_t,target,"_np_keycache_find_or_create");
			break;
		}
	}

	if (TRUE == state->enable_realm_master)
	{
		np_msgproperty_t* msg_prop = NULL;

		np_dhkey_t target_dhkey = np_dhkey_create_from_hostport(state->my_identity->aaa_token->realm, "0");
		np_key_t* target = NULL;
		target = _np_keycache_find_or_create(target_dhkey);

		msg_prop = np_msgproperty_get(INBOUND, _NP_MSG_AUTHENTICATION_REQUEST);
		msg_prop->clb_transform = _np_send_sender_discovery;
		// _np_send_sender_discovery(0.0, msg_prop, target, NULL);
		_np_job_submit_transform_event(0.0, msg_prop, target, NULL);

		msg_prop = np_msgproperty_get(INBOUND, _NP_MSG_AUTHORIZATION_REQUEST);
		msg_prop->clb_transform = _np_send_sender_discovery;
		_np_job_submit_transform_event(0.0, msg_prop, target, NULL);

		msg_prop = np_msgproperty_get(INBOUND, _NP_MSG_ACCOUNTING_REQUEST);
		msg_prop->clb_transform = _np_send_sender_discovery;
		_np_job_submit_transform_event(0.0, msg_prop, target, NULL);

		np_unref_obj(np_key_t, target,"_np_keycache_find_or_create");
	}

	// retrigger execution
	np_job_submit_event(__token_retransmit_period, _np_retransmit_message_tokens_jobexec);
}


void _np_renew_node_token_jobexec(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_renew_node_token_jobexec(NP_UNUSED np_jobargs_t* args){");

	_LOCK_MODULE(np_node_renewal_t) {
		np_state_t* state = _np_state();

		// check an refresh my own identity + node tokens if required
		double exp_ts = ev_time() + NODE_RENEW_BEFORE_EOL_SEC;

		if (state->my_node_key->aaa_token->expiration < exp_ts)
		{
			log_msg(LOG_WARN, "---------- expiration of own node token reached ----------");

			np_key_renew_token();
		}

		if (state->my_identity->aaa_token->expiration < exp_ts)
		{
			// if the user has set a aaatoken manually, he is responsible to refresh it in time
			log_msg(LOG_ERROR, "your identity aaatoken has expired, please refresh !!!");
		}

		// retrigger execution
		np_job_submit_event(__token_retransmit_period, _np_renew_node_token_jobexec);
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
	log_msg(LOG_TRACE, "start: void _np_cleanup_ack_jobexec(NP_UNUSED np_jobargs_t* args){");

	np_waitref_obj(np_key_t, _np_state()->my_node_key, my_key,"np_waitref_obj");
	np_network_t* ng = my_key->network;

	np_tree_elem_t *jrb_ack_node = NULL;

	// wake up and check for acknowledged messages
	_LOCK_ACCESS(&ng->lock)
	{
		np_tree_elem_t* iter = RB_MIN(np_tree_s, ng->waiting);
		while (iter != NULL)
		{
			jrb_ack_node = iter;
			iter = RB_NEXT(np_tree_s, ng->waiting, iter);

			np_ackentry_t *ackentry = (np_ackentry_t *) jrb_ack_node->val.value.v;
			if (TRUE == ackentry->acked &&
				ackentry->expected_ack == ackentry->received_ack)
			{
				// update latency and statistics for a node
				double latency = ackentry->acktime - ackentry->transmittime;

				_np_node_update_latency(ackentry->dest_key->node, latency);
				_np_node_update_stat(ackentry->dest_key->node, 1);

				RB_REMOVE(np_tree_s, ng->waiting, jrb_ack_node);
				np_unref_obj(np_key_t, ackentry->dest_key, ref_message_ack);

				free(ackentry);
				free(jrb_ack_node->key.value.s);
				free(jrb_ack_node);
			}
			else if (ev_time() > ackentry->expiration)
			{
				_np_node_update_stat(ackentry->dest_key->node, 0);

				RB_REMOVE(np_tree_s, ng->waiting, jrb_ack_node);
				np_unref_obj(np_key_t, ackentry->dest_key,ref_message_ack);

				free(ackentry);
				free(jrb_ack_node->key.value.s);
				free(jrb_ack_node);
			}
		}
	}
	np_unref_obj(np_key_t, my_key,"np_waitref_obj");
	// submit the function itself for additional execution
	np_job_submit_event(__cleanup_interval, _np_cleanup_ack_jobexec);
}

void _np_cleanup_keycache_jobexec(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_cleanup_keycache_jobexec(NP_UNUSED np_jobargs_t* args){");

	np_key_t* old = NULL;
	double now = ev_time();

	old = _np_keycache_find_deprecated();

	if (NULL != old)
	{
		log_debug_msg(LOG_DEBUG, "cleanup check started for key : %p -> %s", old, _np_key_as_str(old));
		np_bool delete_key = TRUE;

		if (NULL != old->node)
		{
			// found a node key, check last_success value
			double delta = ev_time() - old->node->last_success;
			if (delta < (31.415 * __leafset_check_period))
			{
				log_debug_msg(LOG_DEBUG, "cleanup of key cancelled because of valid node last_success value: %s", _np_key_as_str(old));
				delete_key &= FALSE;
			}
		}

		np_tryref_obj(np_aaatoken_t, old->aaa_token, tokenExists,"np_tryref_old->aaa_token");
		if(tokenExists) {
			if (TRUE == _np_aaatoken_is_valid(old->aaa_token) )
			{
				log_debug_msg(LOG_DEBUG, "cleanup of key cancelled because of valid aaa_token structure: %s", _np_key_as_str(old));
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
					log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "checking receiver msg tokens %p/%p", iter, iter->val);
					np_aaatoken_t* tmp_token = iter->val;
					if (TRUE == _np_aaatoken_is_valid(tmp_token))
					{
						log_debug_msg(LOG_DEBUG, "cleanup of key cancelled because of valid receiver tokens: %s", _np_key_as_str(old));
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
					log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "checking sender msg tokens %p/%p", iter, iter->val);
					np_aaatoken_t* tmp_token = iter->val;
					if (TRUE == _np_aaatoken_is_valid(tmp_token))
					{
						log_debug_msg(LOG_DEBUG, "cleanup of key cancelled because of valid sender tokens: %s", _np_key_as_str(old));
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
			old->last_update = ev_time();
		}
		np_unref_obj(np_key_t, old, "_np_keycache_find_deprecated");
	}

	// submit the function itself for additional execution
	np_job_submit_event(__cleanup_interval, _np_cleanup_keycache_jobexec);
}

/**
 ** np_send_rowinfo:
 ** sends matching row of its table to the target node
 **/
void _np_send_rowinfo_jobexec(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_send_rowinfo_jobexec(np_jobargs_t* args){");

	np_state_t* state = _np_state();
	np_key_t* target_key = args->target;

	// check for correct target
	log_debug_msg(LOG_DEBUG, "job submit route row info to %s:%s!",
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


	if (0 < sll_size(sll_of_keys))
	{
		np_tree_t* msg_body = np_tree_create();
		_np_node_encode_multiple_to_jrb(msg_body, sll_of_keys, FALSE);
		np_msgproperty_t* outprop = np_msgproperty_get(OUTBOUND, _NP_MSG_PIGGY_REQUEST);

		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		_np_message_create(msg_out, target_key, state->my_node_key, _NP_MSG_PIGGY_REQUEST, msg_body);
		_np_job_submit_route_event(0.0, outprop, target_key, msg_out);
		np_unref_obj(np_message_t, msg_out, ref_obj_creation);		
	}

	np_unref_list(sll_of_keys, source_sll_of_keys);
	sll_free(np_key_ptr, sll_of_keys);
}

np_aaatoken_t* _np_create_msg_token(np_msgproperty_t* msg_request)
{
	log_msg(LOG_TRACE, "start: np_aaatoken_t* _np_create_msg_token(np_msgproperty_t* msg_request){");

	np_state_t* state = _np_state();

	np_aaatoken_t* msg_token = NULL;
	np_new_obj(np_aaatoken_t, msg_token);

	char msg_uuid_subject[255];
	snprintf(msg_uuid_subject, 255, "urn:np:msg:%s", msg_request->msg_subject);

	np_waitref_obj(np_key_t, state->my_identity, my_identity,"np_waitref_obj");

	// create token
	strncpy(msg_token->realm, my_identity->aaa_token->realm, 255);
	strncpy(msg_token->issuer, (char*) _np_key_as_str(my_identity), 255);
	strncpy(msg_token->subject, msg_request->msg_subject, 255);
	if (NULL != msg_request->msg_audience)
	{
		strncpy(msg_token->audience, (char*) msg_request->msg_audience, 255);
	}

	msg_token->uuid =  np_uuid_create(msg_uuid_subject, 0);

	msg_token->not_before = ev_time();

	// how to allow the possible transmit jitter ?
	int expire_sec =  ((int)randombytes_uniform(msg_request->token_max_ttl - msg_request->token_min_ttl)+msg_request->token_min_ttl);

	log_debug_msg(LOG_DEBUG,"setting msg token EXPIRY to: %d",expire_sec);
	msg_token->expiration = msg_token->not_before + expire_sec;
	if(my_identity->aaa_token->expiration < msg_token->expiration ){
		msg_token->expiration = my_identity->aaa_token->expiration ;
	}

	// add e2e encryption details for sender
	memcpy((char*) msg_token->public_key,
		   (char*) my_identity->aaa_token->public_key,
		   crypto_sign_PUBLICKEYBYTES);
	// private key is only required for signing later, will not be send over the wire
	memcpy((char*) msg_token->private_key,
		   (char*) state->my_identity->aaa_token->private_key,
		   crypto_sign_SECRETKEYBYTES);

	np_tree_insert_str(msg_token->extensions, "mep_type",
			np_treeval_new_ul(msg_request->mep_type));
	np_tree_insert_str(msg_token->extensions, "ack_mode",
			np_treeval_new_ush(msg_request->ack_mode));
	np_tree_insert_str(msg_token->extensions, "max_threshold",
			np_treeval_new_ui(msg_request->max_threshold));
	np_tree_insert_str(msg_token->extensions, "msg_threshold",
			np_treeval_new_ui( msg_request->msg_threshold ));

	// TODO: insert value based on msg properties / respect (sticky) reply
	np_tree_insert_str(msg_token->extensions, "target_node",
			np_treeval_new_s((char*) _np_key_as_str(my_identity)));

	// fingerprinting and signing the token
	_np_aaatoken_add_signature(msg_token);

	msg_token->state = AAA_AUTHORIZED | AAA_AUTHENTICATED | AAA_VALID;
	np_unref_obj(np_key_t, my_identity, "np_waitref_obj");
	return (msg_token);
}

void _np_send_subject_discovery_messages(np_msg_mode_type mode_type, const char* subject)
{
	log_msg(LOG_TRACE, "start: void _np_send_subject_discovery_messages(np_msg_mode_type mode_type, const char* subject){");

	//TODO: msg_tokens for either
	// insert into msg token token renewal queue
	if (NULL == np_tree_find_str(_np_state()->msg_tokens, subject))
	{
		np_tree_insert_str(_np_state()->msg_tokens, subject, np_treeval_new_v(NULL));

		np_msgproperty_t* msg_prop = np_msgproperty_get(mode_type, subject);
		msg_prop->mode_type |= TRANSFORM;
		msg_prop->clb_transform = _np_send_discovery_messages;

		np_dhkey_t target_dhkey = np_dhkey_create_from_hostport(subject, "0");
		np_key_t* target = NULL;
		target = _np_keycache_find_or_create(target_dhkey);

		log_debug_msg(LOG_DEBUG, "registering for message discovery token handling (%s)", subject);
		_np_job_submit_transform_event(0.0, msg_prop, target, NULL);
		np_unref_obj(np_key_t, target, "_np_keycache_find_or_create");
	}
}

// TODO: add a wrapper function which can be scheduled via jobargs
np_bool _np_send_msg (char* subject, np_message_t* msg, np_msgproperty_t* msg_prop, np_dhkey_t* target)
{
	msg_prop->msg_threshold++;

	// np_aaatoken_t* tmp_token = _np_aaatoken_get_receiver(subject, &target_key);
	np_aaatoken_t* tmp_token = _np_aaatoken_get_receiver(subject, target);

	if (NULL != tmp_token)
	{
		log_msg(LOG_INFO, "(msg: %s) for subject \"%s\" has valid token", msg->uuid, subject);

		np_tree_find_str(tmp_token->extensions, "msg_threshold")->val.value.ui++;

		// first encrypt the relevant message part itself
		_np_message_encrypt_payload(msg, tmp_token);

		char* target_node_str = NULL;

		np_tree_elem_t* tn_node = np_tree_find_str(tmp_token->extensions, "target_node");
		if (NULL != tn_node)
		{
			target_node_str = tn_node->val.value.s;
		}
		else
		{
			target_node_str = tmp_token->issuer;
		}

		np_key_t* receiver_key = NULL;

		np_dhkey_t receiver_dhkey;
		_np_dhkey_from_str(target_node_str, &receiver_dhkey);
		receiver_key = _np_keycache_find_or_create(receiver_dhkey);


		np_tree_replace_str(msg->header, _NP_MSG_HEADER_TO, np_treeval_new_s(target_node_str));
		np_msgproperty_t* out_prop = np_msgproperty_get(OUTBOUND, subject);
		_np_job_submit_route_event(0.0, out_prop, receiver_key, msg);

		// decrease threshold counters
		msg_prop->msg_threshold--;

		if (NULL != msg_prop->rep_subject &&
			STICKY_REPLY == (msg_prop->mep_type & STICKY_REPLY))
		{
			_np_aaatoken_add_sender(msg_prop->rep_subject, tmp_token);
		}
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
