//
// neuropil is copyright 2016 by pi-lar GmbH
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
#include "np_log.h"
#include "neuropil.h"
#include "np_axon.h"
#include "np_aaatoken.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_keycache.h"
#include "np_list.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_route.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_val.h"
#include "np_key.h"


// TODO: make these configurable (via struct np_config)
/**
 *  neuropil is copyright 2015 by pi-lar GmbH
 */


static uint8_t __leafset_check_type = 0;
static double  __leafset_check_period = 3.1415;
static double  __leafset_yield_period = 0.0031415;

static double  __rowinfo_send_delay = 0.03141;

static double  __token_retransmit_period = 3.1415;

static double  __logfile_flush_period = 0.31415;

static double  __cleanup_interval = 0.31415;

/**
 ** np_route:
 ** routes a message one step closer to its destination key. Delivers
 ** the message to its destination if it is the current host through the
 ** deliver upcall, otherwise it makes the route upcall
 **/
void _np_route_lookup(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_route_lookup");
	np_state_t* state = _np_state();

	np_sll_t(np_key_t, tmp) = NULL;
	np_key_t* target_key = NULL;
	np_message_t* msg_in = args->msg;

	char* msg_subject = tree_find_str(msg_in->header, _NP_MSG_HEADER_SUBJECT)->val.value.s;
	char* msg_address = tree_find_str(msg_in->header, _NP_MSG_HEADER_TO)->val.value.s;

	np_bool is_a_join_request = FALSE;
	if (0 == strncmp(msg_subject, _NP_MSG_JOIN_REQUEST, strlen(_NP_MSG_JOIN_REQUEST)) )
	{
		is_a_join_request = TRUE;
	}

	np_dhkey_t search_key;
	_np_dhkey_from_str(msg_address, &search_key);
	np_key_t k_msg_address = { .dhkey = search_key };

	// first lookup call for target key
	log_msg(LOG_DEBUG, "message target is key %s", _np_key_as_str(&k_msg_address));

	_LOCK_MODULE(np_routeglobal_t)
	{
		// 1 means: always send out message to another node first, even if it returns
		tmp = route_lookup(&k_msg_address, 1);
		if ( 0 < sll_size(tmp) )
			log_msg(LOG_DEBUG, "route_lookup result 1 = %s", _np_key_as_str(sll_first(tmp)->val));
	}

	if ( NULL != tmp                &&
		 0    < sll_size(tmp)       &&
		 FALSE == is_a_join_request &&
		 (_np_dhkey_equal(&sll_first(tmp)->val->dhkey, &state->my_node_key->dhkey)) )
	{
		// the result returned the sending node, try again with a higher count parameter
		sll_free(np_key_t, tmp);

		_LOCK_MODULE(np_routeglobal_t)
		{
			tmp = route_lookup(&k_msg_address, 2);
			if (0 < sll_size(tmp))
				log_msg(LOG_DEBUG, "route_lookup result 2 = %s", _np_key_as_str(sll_first(tmp)->val));
		}
		// TODO: increase count parameter again ?
	}

	_np_key_t_del(&k_msg_address);

	if (NULL  != tmp           &&
		0     <  sll_size(tmp) &&
		FALSE == _np_dhkey_equal(&sll_first(tmp)->val->dhkey, &state->my_node_key->dhkey))
	{
		target_key = sll_first(tmp)->val;
		log_msg(LOG_DEBUG, "route_lookup result   = %s", _np_key_as_str(target_key));
	}

	/* if I am the only host or the closest host is me, deliver the message */
	// TODO: not working ?
	if (NULL  == target_key &&
		FALSE == is_a_join_request)
	{
		// the message has to be handled by this node (e.g. msg interest messages)
		log_msg(LOG_DEBUG, "internal routing for subject '%s'", msg_subject);
		np_message_t* msg_to_submit = NULL;

		if (TRUE == args->msg->is_single_part)
		{
			_LOCK_MODULE(np_messagesgpart_cache_t)
			{
				// sum up message parts if the message is for this node
				msg_to_submit = _np_message_check_chunks_complete(args->msg);
			}
			if (NULL == msg_to_submit)
			{
				sll_free(np_key_t, tmp);
				log_msg(LOG_TRACE, ".end  .np_route_lookup");
				return;
			}
			if (msg_in == msg_to_submit) np_ref_obj(np_message_t, msg_to_submit);

			_np_message_deserialize_chunked(msg_to_submit);
			np_unref_obj(np_message_t, msg_to_submit);
		}
		else
		{
			msg_to_submit = args->msg;
		}

		np_msgproperty_t* prop = np_msgproperty_get(INBOUND, msg_subject);
		if (prop != NULL)
		{
			_np_job_submit_msgin_event(0.0, prop, state->my_node_key, msg_to_submit);
		}
	}
	else /* otherwise, hand it over to the np_axon sending unit */
	{
		log_msg(LOG_DEBUG, "forward routing for subject '%s'", msg_subject);

		if (NULL == target_key || TRUE == is_a_join_request)
		{
			target_key = args->target;
		}

		np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, msg_subject);
		if (NULL == prop)
			prop = np_msgproperty_get(OUTBOUND, _DEFAULT);

		if (TRUE == args->is_resend)
			_np_job_resubmit_msgout_event(0.0, prop, target_key, args->msg);
		else
			_np_job_submit_msgout_event(0.0, prop, target_key, args->msg);

		/* set next hop to the next node */
// 		// TODO: already routed by forward message call ?
// 		// why is there an additional message_send directive here ?
//	    while (!message_send (state->messages, host, message, TRUE, 1))
//		{
//		    host->failuretime = dtime ();
//		    log_msg(LOG_WARN,
//				    "message send to host: %s:%hd at time: %f failed!",
//				    host->dns_name, host->port, host->failuretime);
//
//		    /* remove the faulty node from the routing table */
//		    if (host->success_avg < BAD_LINK) route_update (state->routes, host, 0);
//		    if (tmp != NULL) free (tmp);
//		    tmp = route_lookup (state->routes, *key, 1, 0);
//		    host = tmp[0];
//		    log_msg(LOG_WARN, "re-route through %s:%hd!", host->dns_name, host->port);
//		}
	}

	sll_free(np_key_t, tmp);
	log_msg(LOG_TRACE, ".end  .np_route_lookup");
}

void _np_never_called(np_jobargs_t* args)
{
	log_msg(LOG_WARN, "!!!                               !!!");
	log_msg(LOG_WARN, "!!! wrong job execution requested !!!");
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

/** _np_check_leafset:
 ** sends a PING message to each member of the leafset and routing table frequently and
 ** sends the leafset to other members of its leafset periodically.
 ** uses _np_job_yield between pings to different nodes
 ** _np_check_leafset frequency is LEAFSET_CHECK_PERIOD.
 **/
void _np_check_leafset(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_check_leafset");

	np_sll_t(np_key_t, leafset) = NULL;
	np_key_t *tmp_node_key = NULL;

	log_msg(LOG_DEBUG, "leafset check for neighbours started");

	// each time to try to ping our leafset hosts
	_LOCK_MODULE(np_routeglobal_t)
	{
		leafset = route_neighbors();
		_np_keycache_ref_keys(leafset);
	}

	while (NULL != (tmp_node_key = sll_head(np_key_t, leafset)))
	{
		// check for bad link nodes
		if (NULL != tmp_node_key->node &&
			tmp_node_key->node->success_avg < BAD_LINK &&
			tmp_node_key->node->handshake_status > HANDSHAKE_UNKNOWN)
		{
			log_msg(LOG_DEBUG, "deleting from neighbours: %s", _np_key_as_str(tmp_node_key));
			// request a new handshake with the node
			if (NULL != tmp_node_key->aaa_token)
				tmp_node_key->aaa_token->state &= AAA_INVALID;
			tmp_node_key->node->handshake_status = HANDSHAKE_UNKNOWN;

			np_key_t *added = NULL, *deleted = NULL;
			leafset_update(tmp_node_key, FALSE, &deleted, &added);
			if (deleted == tmp_node_key)
			{
				np_unref_obj(np_key_t, deleted);
			}
			else
			{
				log_msg(LOG_WARN, "deleting from neighbours returned different key: %s", _np_key_as_str(deleted));
			}
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
		np_unref_obj(np_key_t, tmp_node_key);
	}
	sll_free(np_key_t, leafset);

	if (__leafset_check_type == 1)
	{
		log_msg(LOG_DEBUG, "leafset check for table started");
		np_sll_t(np_key_t, table) = NULL;
		_LOCK_MODULE(np_routeglobal_t)
		{
			table = _np_route_get_table();
			_np_keycache_ref_keys(table);
		}

		while ( NULL != (tmp_node_key = sll_head(np_key_t, table)))
		{
			// send update of new node to all nodes in my routing table
			/* first check for bad link nodes */
			if (NULL != tmp_node_key->node &&
				tmp_node_key->node->success_avg < BAD_LINK &&
				tmp_node_key->node->handshake_status > HANDSHAKE_UNKNOWN)
			{
				log_msg(LOG_DEBUG, "deleting from table: %s", _np_key_as_str(tmp_node_key));
				// request a new handshake with the node
				if (NULL != tmp_node_key->aaa_token)
					tmp_node_key->aaa_token->state &= AAA_INVALID;
				tmp_node_key->node->handshake_status = HANDSHAKE_UNKNOWN;

				np_key_t *added = NULL, *deleted = NULL;
				route_update(tmp_node_key, FALSE, &deleted, &added);
				if (deleted == tmp_node_key)
				{
					np_unref_obj(np_key_t, deleted);
				}
				else
				{
					log_msg(LOG_WARN, "deleting from neighbours returned different key: %s", _np_key_as_str(deleted));
				}
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
			np_unref_obj(np_key_t, tmp_node_key);
		}
		sll_free(np_key_t, table);
	}

	if (__leafset_check_type == 2)
	{
		/* send leafset exchange data every 3 times that pings the leafset */
		log_msg(LOG_DEBUG, "leafset exchange for neighbours started");

		_LOCK_MODULE(np_routeglobal_t)
		{
			leafset = route_neighbors();
			_np_keycache_ref_keys(leafset);
		}

		while ( NULL != (tmp_node_key = sll_head(np_key_t, leafset)))
		{
			// send a piggy message to the the nodes in our routing table
			np_msgproperty_t* piggy_prop = np_msgproperty_get(TRANSFORM, _NP_MSG_PIGGY_REQUEST);
			_np_job_submit_transform_event(0.0, piggy_prop, tmp_node_key, NULL);
			_np_job_yield(__leafset_yield_period);
			np_unref_obj(np_key_t, tmp_node_key);
		}
		__leafset_check_type = 0;
		sll_free(np_key_t, leafset);
	}
	else
	{
		__leafset_check_type++;
	}
	// np_mem_printpool();
	np_job_submit_event(__leafset_check_period, _np_check_leafset);
	log_msg(LOG_TRACE, ".end  .np_check_leafset");
}

/**
 ** np_retransmit_tokens
 ** retransmit tokens on a regular interval
 ** default ttl value for message exchange tokens is ten seconds, afterwards they will be invalid
 ** and a new token is required. this also ensures that the correct encryption key will be transmitted
 **/
void _np_retransmit_tokens(NP_UNUSED np_jobargs_t* args)
{
	// log_msg(LOG_TRACE, "start np_retransmit_tokens");
	np_state_t* state = _np_state();

	np_tree_elem_t *iter = NULL;
	np_tree_elem_t *deleted = NULL;
	np_msgproperty_t* msg_prop = NULL;

	// TODO: crashes sometimes ??
	RB_FOREACH(iter, np_tree_s, state->msg_tokens)
	{
		// double now = dtime();
		// double last_update = iter->val.value.d;
		np_dhkey_t target_dhkey = np_dhkey_create_from_hostport(iter->key.value.s, "0");
		np_key_t* target = NULL;
		np_new_obj(np_key_t, target);
		target->dhkey = target_dhkey;

		msg_prop = np_msgproperty_get(TRANSFORM, iter->key.value.s);
		if (NULL != msg_prop)
		{
			_np_job_submit_transform_event(0.0, msg_prop, target, NULL);
		}
		else
		{
			deleted = RB_REMOVE(np_tree_s, state->msg_tokens, iter);
			free(deleted->key.value.s);
			free(deleted);
			break;
		}
	}

	if (TRUE == state->enable_realm_master)
	{
		np_msgproperty_t* msg_prop = NULL;

		np_dhkey_t target_dhkey = np_dhkey_create_from_hostport(state->my_identity->aaa_token->realm, "0");
		np_key_t* target = NULL;
		np_new_obj(np_key_t, target);
		target->dhkey = target_dhkey;

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

		np_free_obj(np_key_t, target);
	}

	// TODO: test the node token renewal
	// check an refresh my own identity + node tokens if required
	double exp_ts = ev_time() + 10.0; // now plus 10s for handshake etc.
	if (state->my_node_key->aaa_token->expiration < exp_ts)
	{
		log_msg(LOG_WARN, "---------- expiration of own node token reached ----------");

		np_aaatoken_t* new_token = _np_create_node_token(state->my_node_key->node);
		np_key_t* new_key = NULL;
		np_dhkey_t my_dhkey = _np_aaatoken_create_dhkey(new_token);
		_LOCK_MODULE(np_keycache_t)
		{
			new_key = _np_keycache_find_or_create(my_dhkey);
			if (state->my_identity == state->my_node_key)
			{
				state->my_identity = new_key;
			}
			state->my_node_key = new_key;
		}

		np_sll_t(np_key_t, leafset) = NULL;
		np_key_t *tmp_node_key = NULL;
		_LOCK_MODULE(np_routeglobal_t)
		{
			_np_route_set_key(state->my_node_key);
			leafset = route_neighbors();
		}

		while (NULL != (tmp_node_key = sll_head(np_key_t, leafset)))
		{
			// send join messages to all surviving neighbours
			_LOCK_MODULE(np_keycache_t)
			{
				tmp_node_key->node->handshake_status = HANDSHAKE_UNKNOWN;
				/* otherwise request reevaluation of peer */

				np_tree_t* jrb_me = make_nptree();
				np_aaatoken_encode(jrb_me, state->my_identity->aaa_token);

				np_message_t* msg_out = NULL;
				np_new_obj(np_message_t, msg_out);

				_np_message_create(msg_out, tmp_node_key, state->my_node_key, _NP_MSG_JOIN_REQUEST, jrb_me);
				log_msg(LOG_DEBUG, "submitting join request to target key %s", _np_key_as_str(tmp_node_key));
				np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _NP_MSG_JOIN_REQUEST);
				_np_job_submit_msgout_event(0.0, prop, tmp_node_key, msg_out);

				np_free_obj(np_message_t, msg_out);
			}
		}
	}

	if (state->my_identity->aaa_token->expiration < exp_ts)
	{
		// if the user has set a aaatoken manually, he is responsible to refresh it in time
		log_msg(LOG_ERROR, "your identity aaatoken has expired, please refresh !!!");
	}

	// retrigger execution
	np_job_submit_event(__token_retransmit_period, _np_retransmit_tokens);
}

/**
 ** _np_cleanup
 ** general resend mechanism. all message which have an acknowledge indicator set are stored in
 ** memory. If the acknowledge has not been send in time, we try to redeliver the message, otherwise
 ** the message gets deleted or dropped (if max redelivery has been reached)
 ** redelivery has two aspects -> simple resend or reroute because of bad link nodes in the routing table
 **/
void _np_cleanup_ack(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_cleanup");

	np_state_t* state = _np_state();
	np_network_t* ng = state->my_node_key->network;

	np_tree_elem_t *jrb_ack_node = NULL;

	// wake up and check for acknowledged messages
	pthread_mutex_lock(&ng->lock);

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
			np_unref_obj(np_key_t, ackentry->dest_key);

			free(ackentry);
			free(jrb_ack_node->key.value.s);
			free(jrb_ack_node);
		}
		else if (ev_time() > ackentry->expiration)
		{
			_np_node_update_stat(ackentry->dest_key->node, 0);

			RB_REMOVE(np_tree_s, ng->waiting, jrb_ack_node);
			np_unref_obj(np_key_t, ackentry->dest_key);

			free(ackentry);
			free(jrb_ack_node->key.value.s);
			free(jrb_ack_node);
		}
	}
	pthread_mutex_unlock(&ng->lock);

	// submit the function itself for additional execution
	np_job_submit_event(__cleanup_interval, _np_cleanup_ack);
	log_msg(LOG_TRACE, ".end  .np_cleanup");
}

void _np_cleanup_keycache(NP_UNUSED np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_cleanup_keycache");

	np_key_t* old = NULL;
	double now = ev_time();

	_LOCK_MODULE(np_keycache_t)
	{
		old = _np_keycache_find_deprecated();
	}

	if (NULL != old)
	{
		log_msg(LOG_DEBUG, "cleanup check started for key : %p -> %s", old, _np_key_as_str(old));
		np_bool delete_key = TRUE;

		if (NULL != old->node)
		{
			// found a node key, check last_success value
			double delta = ev_time() - old->node->last_success;
			if (delta < (31.415 * __leafset_check_period))
			{
				log_msg(LOG_DEBUG, "cleanup of key cancelled because of valid node last_success value: %s", _np_key_as_str(old));
				delete_key &= FALSE;
			}
		}

		if (NULL != old->aaa_token                  &&
			TRUE == _np_aaatoken_is_valid(old->aaa_token) )
		{
			log_msg(LOG_DEBUG, "cleanup of key cancelled because of valid aaa_token structure: %s", _np_key_as_str(old));
			delete_key &= FALSE;
		}

		if (NULL != old->recv_tokens)
		{
			LOCK_CACHE(old->recv_property)
			{
				// check old receiver token structure
				pll_iterator(np_aaatoken_ptr) iter = pll_first(old->recv_tokens);
				while (NULL != iter)
				{
					log_msg(LOG_AAATOKEN | LOG_DEBUG, "checking receiver msg tokens %p/%p", iter, iter->val);
					np_aaatoken_t* tmp_token = iter->val;
					if (TRUE == _np_aaatoken_is_valid(tmp_token))
					{
						log_msg(LOG_DEBUG, "cleanup of key cancelled because of valid receiver tokens: %s", _np_key_as_str(old));
						delete_key &= FALSE;
						break;
					}
					pll_next(iter);
				}
			}
		}

		if (NULL != old->send_tokens)
		{
			LOCK_CACHE(old->send_property)
			{
				// check old sender token structure
				pll_iterator(np_aaatoken_ptr) iter = pll_first(old->send_tokens);
				while (NULL != iter)
				{
					log_msg(LOG_AAATOKEN | LOG_DEBUG, "checking sender msg tokens %p/%p", iter, iter->val);
					np_aaatoken_t* tmp_token = iter->val;
					if (TRUE == _np_aaatoken_is_valid(tmp_token))
					{
						log_msg(LOG_DEBUG, "cleanup of key cancelled because of valid sender tokens: %s", _np_key_as_str(old));
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
	}

	// submit the function itself for additional execution
	np_job_submit_event(__cleanup_interval, _np_cleanup_keycache);
	log_msg(LOG_TRACE, ".end  ._np_cleanup_keycache");
}

/**
 ** np_send_rowinfo:
 ** sends matching row of its table to the target node
 **/
void _np_send_rowinfo(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start np_send_rowinfo");

	np_state_t* state = _np_state();
	np_key_t* target_key = args->target;

	// check for correct target
	log_msg(LOG_DEBUG, "job submit route row info to %s:%s!",
			target_key->node->dns_name, target_key->node->port);

	np_sll_t(np_key_t, sll_of_keys) = NULL;
	/* send one row of our routing table back to joiner #host# */
	_LOCK_MODULE(np_routeglobal_t)
	{
		sll_of_keys = route_row_lookup(target_key);
		if (0 == sll_size(sll_of_keys))
		{
			// nothing found, send leafset to exchange some data at least
			// prevents small clusters from not exchanging all data
			sll_free(np_key_t, sll_of_keys);
			sll_of_keys = route_neighbors();
		}
	}

	if (0 < sll_size(sll_of_keys))
	{
		np_tree_t* msg_body = make_nptree();
		_np_encode_nodes_to_jrb(msg_body, sll_of_keys, FALSE);
		np_msgproperty_t* outprop = np_msgproperty_get(OUTBOUND, _NP_MSG_PIGGY_REQUEST);

		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		_np_message_create(msg_out, target_key, state->my_node_key, _NP_MSG_PIGGY_REQUEST, msg_body);
		_np_job_submit_route_event(0.0, outprop, target_key, msg_out);
		np_free_obj(np_message_t, msg_out);

		_np_job_yield(__rowinfo_send_delay);
	}

	sll_free(np_key_t, sll_of_keys);
}

np_aaatoken_t* _np_create_msg_token(np_msgproperty_t* msg_request)
{	log_msg(LOG_TRACE, ".start.np_create_msg_token");

	np_state_t* state = _np_state();

	np_aaatoken_t* msg_token = NULL;
	np_new_obj(np_aaatoken_t, msg_token);

	char msg_uuid_subject[255];
	snprintf(msg_uuid_subject, 255, "urn:np:msg:%s", msg_request->msg_subject);

	// create token
	strncpy(msg_token->realm, state->my_identity->aaa_token->realm, 255);
	strncpy(msg_token->issuer, (char*) _np_key_as_str(state->my_identity), 255);
	strncpy(msg_token->subject, msg_request->msg_subject, 255);
	if (NULL != msg_request->msg_audience)
	{
		strncpy(msg_token->audience, (char*) msg_request->msg_audience, 255);
	}

	msg_token->uuid =  np_create_uuid(msg_uuid_subject, 0);

	msg_token->not_before = ev_time();
	// TODO: make it configurable for the user
	// how to allow the possible transmit jitter ?
	msg_token->expiration = ev_time() + (3.1415*msg_request->ttl);

	// add e2e encryption details for sender
	memcpy((char*) msg_token->public_key,
		   (char*) state->my_identity->aaa_token->public_key,
		   crypto_sign_PUBLICKEYBYTES);
	// private key is only required for signing later, will not be send over the wire
	memcpy((char*) msg_token->private_key,
		   (char*) state->my_identity->aaa_token->private_key,
		   crypto_sign_SECRETKEYBYTES);

	tree_insert_str(msg_token->extensions, "mep_type",
			new_val_ul(msg_request->mep_type));
	tree_insert_str(msg_token->extensions, "ack_mode",
			new_val_ush(msg_request->ack_mode));
	tree_insert_str(msg_token->extensions, "max_threshold",
			new_val_ui(msg_request->max_threshold));
	tree_insert_str(msg_token->extensions, "msg_threshold",
			new_val_ui(msg_request->msg_threshold));

	// TODO: insert value based on msg properties / respect (sticky) reply
	tree_insert_str(msg_token->extensions, "target_node",
			new_val_s((char*) _np_key_as_str(state->my_node_key)));

	// fingerprinting and signing the token
	_np_aaatoken_add_signature(msg_token);

	msg_token->state = AAA_AUTHORIZED | AAA_AUTHENTICATED | AAA_VALID;

	log_msg(LOG_TRACE, ".end  .np_create_msg_token");
	return (msg_token);
}

void _np_send_subject_discovery_messages(np_msg_mode_type mode_type, const char* subject)
{
	log_msg(LOG_TRACE, ".start._np_send_subject_discovery_messages");

	// insert into msg token token renewal queue
	if (NULL == tree_find_str(_np_state()->msg_tokens, subject))
	{
		tree_insert_str(_np_state()->msg_tokens, subject, new_val_v(NULL));

		np_msgproperty_t* msg_prop = np_msgproperty_get(mode_type, subject);
		msg_prop->mode_type |= TRANSFORM;
		msg_prop->clb_transform = _np_send_discovery_messages;

		np_dhkey_t target_dhkey = np_dhkey_create_from_hostport(subject, "0");
		np_key_t* target = NULL;
		np_new_obj(np_key_t, target);
		target->dhkey = target_dhkey;

		log_msg(LOG_DEBUG, "registering for message discovery token handling (%s)", subject);
		_np_job_submit_transform_event(0.0, msg_prop, target, NULL);
		np_free_obj(np_key_t, target);
	}

	log_msg(LOG_TRACE, ".end  ._np_send_subject_discovery_messages");
}

// deprecated
void _np_send_msg_interest(const char* subject)
{
	log_msg(LOG_TRACE, ".start.np_send_msg_interest");

	// insert into msg token token renewal queue
	if (NULL == tree_find_str(_np_state()->msg_tokens, subject))
	{
		tree_insert_str(_np_state()->msg_tokens, subject, new_val_v(NULL));

		np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, subject);
		msg_prop->mode_type |= TRANSFORM;
		msg_prop->clb_transform = _np_send_discovery_messages;

		np_dhkey_t target_dhkey = np_dhkey_create_from_hostport(subject, "0");
		np_key_t* target = NULL;
		np_new_obj(np_key_t, target);
		target->dhkey = target_dhkey;

		log_msg(LOG_DEBUG, "registering for message interest token handling");
		_np_job_submit_transform_event(0.0, msg_prop, target, NULL);
		np_free_obj(np_key_t, target);
	}

	log_msg(LOG_TRACE, ".end  .np_send_msg_interest");
}

// TODO: add a wrapper function which can be scheduled via jobargs
np_bool _np_send_msg (char* subject, np_message_t* msg, np_msgproperty_t* msg_prop, np_dhkey_t* target)
{
	msg_prop->msg_threshold++;

	if(NULL != target) {
		tree_replace_str(msg->header, _NP_MSG_HEADER_TARGET, new_val_key(*target));
	}else{
		np_tree_elem_t* target_container = 	tree_find_str(msg->header, _NP_MSG_HEADER_TARGET);
		if(NULL != target_container) {
			target = &(target_container->val.value.key);
		}
	}

	np_aaatoken_t* tmp_token = _np_aaatoken_get_receiver(subject, target);

	if (NULL != tmp_token)
	{
		tree_del_str(msg->header, _NP_MSG_HEADER_TARGET);

		tree_find_str(tmp_token->extensions, "msg_threshold")->val.value.ui++;

		// first encrypt the relevant message part itself
		_np_message_encrypt_payload(msg, tmp_token);

		char* target_node_str = NULL;

		np_tree_elem_t* tn_node = tree_find_str(tmp_token->extensions, "target_node");
		if (NULL != tn_node)
		{
			target_node_str = tn_node->val.value.s;
		}
		else
		{
			target_node_str = tmp_token->issuer;
		}

		np_key_t* receiver_key = NULL;
		np_new_obj(np_key_t, receiver_key);

		np_dhkey_t receiver_dhkey;
		_np_dhkey_from_str(target_node_str, &receiver_dhkey);
		receiver_key->dhkey = receiver_dhkey;

		tree_replace_str(msg->header, _NP_MSG_HEADER_TO, new_val_s(target_node_str));
		// tree_replace_str(msg->header, NP_MSG_HEADER_TO, new_val_s(tmp_token->issuer));
		np_msgproperty_t* out_prop = np_msgproperty_get(OUTBOUND, subject);
		_np_job_submit_route_event(0.0, out_prop, receiver_key, msg);

		// decrease threshold counters
		msg_prop->msg_threshold--;

		if (NULL != msg_prop->rep_subject &&
			STICKY_REPLY == (msg_prop->mep_type & STICKY_REPLY))
		{
			_np_aaatoken_add_sender(msg_prop->rep_subject, tmp_token);
		}
		np_unref_obj(np_aaatoken_t, tmp_token);
		np_free_obj(np_key_t, receiver_key);

		return (TRUE);
	}
	else
	{
		_np_msgproperty_add_msg_to_send_cache(msg_prop, msg);
	}
	return (FALSE);
}
