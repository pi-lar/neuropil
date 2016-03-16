/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
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

#include "np_glia.h"

#include "dtime.h"
#include "event/ev.h"
#include "jval.h"
#include "log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_container.h"
#include "np_jobqueue.h"
#include "np_jtree.h"
#include "np_key.h"
#include "np_list.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_route.h"
#include "np_threads.h"

static np_bool __exit_libev_loop = FALSE;

static pthread_mutex_t __libev_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint8_t __suspended_libev_loop = 0;
static double  __libev_interval = 0.0031415;

static uint8_t __leafset_check_type = 0;
static double  __leafset_check_period = 3.1415;

static double  __token_retransmit_period = 3.1415;

static double  __logfile_flush_period = 0.31415;

static double  __cleanup_interval = 0.31415;

/**
 ** np_route:
 ** routes a message one step closer to its destination key. Delivers
 ** the message to its destination if it is the current host through the
 ** deliver upcall, otherwise it makes the route upcall
 **/
void np_route_lookup(np_state_t* state, np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_route_lookup");
	np_sll_t(np_key_t, tmp) = NULL;
	np_key_t* target_key = NULL;
	np_message_t* msg_in = args->msg;

	char* msg_subject = jrb_find_str(msg_in->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
	char* msg_address = jrb_find_str(msg_in->header, NP_MSG_HEADER_TO)->val.value.s;

	np_bool is_a_join_request = FALSE;
	if (0 == strncmp(msg_subject, NP_MSG_JOIN_REQUEST, strlen(NP_MSG_JOIN_REQUEST)) )
	{
		is_a_join_request = TRUE;
	}

	np_key_t k_msg_address;
	str_to_key(&k_msg_address, msg_address);

	// first lookup call for target key
	log_msg(LOG_DEBUG, "message target is key %s", key_get_as_string(&k_msg_address));

	_LOCK_MODULE(np_routeglobal_t)
	{
		// 1 means: always send out message to another node first, even if it returns
		tmp = route_lookup(&k_msg_address, 1);
		if ( 0 < sll_size(tmp) )
			log_msg(LOG_DEBUG, "route_lookup result 1 = %s", key_get_as_string(sll_first(tmp)->val));
	}

	if ( NULL != tmp                &&
		 0    < sll_size(tmp)       &&
		 FALSE == is_a_join_request &&
		 (key_equal(sll_first(tmp)->val, state->my_node_key)) )
	{
		// the result returned the sending node, try again with a higher count parameter
		sll_free(np_key_t, tmp);

		_LOCK_MODULE(np_routeglobal_t)
		{
			tmp = route_lookup(&k_msg_address, 2);
			log_msg(LOG_DEBUG, "route_lookup result 2 = %s", key_get_as_string(sll_first(tmp)->val));
		}
		// TODO: increase count parameter ?
		// if (tmp[1] != NULL && key_equal(tmp[0], &k_msg_address))
		// tmp[0] = tmp[1];
	}

	if (NULL  != tmp           &&
		0     <  sll_size(tmp) &&
		FALSE == key_equal(sll_first(tmp)->val, state->my_node_key))
	{
		target_key = sll_first(tmp)->val;
		log_msg(LOG_DEBUG, "route_lookup result   = %s", key_get_as_string(target_key));
	}

	/* if I am the only host or the closest host is me, deliver the message */
	if (NULL  == target_key &&
		FALSE == is_a_join_request)
	{
		// the message has to be handled by this node (e.g. msg interest messages)
		log_msg(LOG_DEBUG, "internal routing for subject '%s'", msg_subject);

		// sum up message parts if the message is for this node
		np_message_t* msg_to_submit = np_message_check_chunks_complete(state, args);
		if (NULL == msg_to_submit)
		{
			sll_free(np_key_t, tmp);
			log_msg(LOG_TRACE, ".end  .np_route_lookup");
			return;
		}
		np_message_deserialize_chunked(msg_to_submit);

		np_msgproperty_t* prop = np_msgproperty_get(state, INBOUND, msg_subject);
		if (prop != NULL)
			np_job_submit_msg_event(0.0, prop, state->my_node_key, msg_to_submit);

		np_unref_obj(np_message_t, msg_to_submit);
	}
	else /* otherwise, hand it over to the np_axon sending unit */
	{
		log_msg(LOG_DEBUG, "forward routing for subject '%s'", msg_subject);

		if (NULL == target_key || TRUE == is_a_join_request) target_key = args->target;

		np_msgproperty_t* prop = np_msgproperty_get(state, OUTBOUND, msg_subject);
		if (NULL == prop)
			prop = np_msgproperty_get(state, OUTBOUND, DEFAULT);

		if (TRUE == args->is_resend)
			_np_job_resubmit_msg_event(0.0, prop, target_key, args->msg);
		else
			np_job_submit_msg_event(0.0, prop, target_key, args->msg);

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

/**
 ** flushes the data of the log buffer to the filesystem in a async callback way
 **/
void _np_write_log(np_state_t* state, np_jobargs_t* args)
{
	// log_msg(LOG_TRACE, "start np_write_log");
	log_fflush();
	np_job_submit_event(__logfile_flush_period, _np_write_log);
	// log_msg(LOG_TRACE, "end   np_write_log");
}

/** np_check_leafset: runs as a separate thread.
 ** it should send a PING message to each member of the leafset frequently and
 ** sends the leafset to other members of its leafset periodically.
 ** pinging frequency is LEAFSET_CHECK_PERIOD.
 **/
void _np_check_leafset(np_state_t* state, np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_check_leafset");

	np_sll_t(np_key_t, leafset) = NULL;
	np_key_t *tmp_node_key = NULL;

	log_msg(LOG_INFO, "leafset check for neighbours started");
	// each time to try to ping our leafset hosts
	_LOCK_MODULE(np_routeglobal_t)
	{
		leafset = route_neighbors(state);
	}

	while (NULL != (tmp_node_key = sll_head(np_key_t, leafset)))
	{
		// check for bad link nodes
		if (tmp_node_key->node->success_avg < BAD_LINK
				&& tmp_node_key->node->handshake_status > HANDSHAKE_UNKNOWN)
		{
			log_msg(LOG_DEBUG, "deleting from neighbours: %s",
					key_get_as_string(tmp_node_key));
			// request a new handshake with the node
			tmp_node_key->authentication->valid = FALSE;
			tmp_node_key->node->handshake_status = HANDSHAKE_UNKNOWN;

			np_key_t *added, *deleted;
			_LOCK_MODULE(np_routeglobal_t)
			{
				leafset_update(tmp_node_key, 0, &deleted, &added);
				if (deleted)
				{
					np_unref_obj(np_key_t, deleted);
				}
			}

		}
		else
		{
			/* otherwise request reevaluation of peer */
			double delta = ev_time() - tmp_node_key->node->last_success;
			if (delta > (3 * __leafset_check_period))
				_np_ping(state, tmp_node_key);
		}
	}
	sll_free(np_key_t, leafset);

	if (__leafset_check_type == 1)
	{
		log_msg(LOG_INFO, "leafset check for table started");
		np_sll_t(np_key_t, table) = NULL;
		_LOCK_MODULE(np_routeglobal_t)
		{
			table = route_get_table(state->routes);
		}

		while ( NULL != (tmp_node_key = sll_head(np_key_t, table)))
		{
			// send update of new node to all nodes in my routing table
			/* first check for bad link nodes */
			if (tmp_node_key->node->success_avg < BAD_LINK
					&& tmp_node_key->node->handshake_status
							> HANDSHAKE_UNKNOWN)
			{
				log_msg(LOG_DEBUG, "Deleting from table: %s",
						key_get_as_string(tmp_node_key));
				// request a new handshake with the node
				tmp_node_key->authentication->valid = FALSE;
				tmp_node_key->node->handshake_status = HANDSHAKE_UNKNOWN;

				np_key_t *added, *deleted;
				_LOCK_MODULE(np_routeglobal_t)
				{
					route_update(tmp_node_key, FALSE, &deleted, &added);
					if (deleted)
					{
						np_unref_obj(np_key_t, deleted);
					}
				}
			}
			else
			{
				/* otherwise request re-evaluation of node stats */
				double delta = ev_time() - tmp_node_key->node->last_success;
				if (delta > (3 * __leafset_check_period))
					_np_ping(state, tmp_node_key);
			}
		}
		sll_free(np_key_t, table);
	}

	/* send leafset exchange data every 3 times that pings the leafset */
	if (__leafset_check_type == 2)
	{
		log_msg(LOG_INFO, "leafset exchange for neighbours started");
		__leafset_check_type = 0;

		_LOCK_MODULE(np_routeglobal_t)
		{
			leafset = route_neighbors(state);
		}

		while ( NULL != (tmp_node_key = sll_head(np_key_t, leafset)))
		{
			// send a piggy message to the the nodes in our routing table
			np_msgproperty_t* piggy_prop = np_msgproperty_get(state,
					TRANSFORM, NP_MSG_PIGGY_REQUEST);
			np_job_submit_msg_event(0.0, piggy_prop, tmp_node_key, NULL);
		}
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
 ** np_retransmit_messages
 ** retransmit tokens on a regular interval
 ** default ttl value for message exchange tokens is ten seconds, afterwards they will be invalid
 ** and a new token is required. this also ensures that the correct encryption key will be transmitted
 **/
void _np_retransmit_tokens(np_state_t* state, np_jobargs_t* args)
{
	// log_msg(LOG_TRACE, "start np_retransmit_tokens");

	np_jtree_elem_t *iter = NULL;
	np_jtree_elem_t *deleted = NULL;

	RB_FOREACH(iter, np_jtree, state->msg_tokens)
	{
		// double now = dtime();
		// double last_update = iter->val.value.d;
		if (NULL != np_msgproperty_get(state, INBOUND, iter->key.value.s))
		{
			_np_send_msg_interest(state, iter->key.value.s);
		}
		else if (NULL != np_msgproperty_get(state, OUTBOUND, iter->key.value.s))
		{
			_np_send_msg_availability(state, iter->key.value.s);
		}
		else
		{
			deleted = RB_REMOVE(np_jtree, state->msg_tokens, iter);
			free(deleted->key.value.s);
			free(deleted);
			break;
		}
	}

	np_job_submit_event(__token_retransmit_period, _np_retransmit_tokens);
}

/**
 ** _np_events_read
 ** schedule the libev event loop one time and reschedule again
 **/
void _np_events_read(np_state_t* state, np_jobargs_t* args)
{
	if (TRUE == __exit_libev_loop) return;

	pthread_mutex_lock(&__libev_mutex);
	if (__suspended_libev_loop == 0)
	{
		EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
		ev_run(EV_A_ (EVRUN_ONCE | EVRUN_NOWAIT));
		// ev_run(EV_A_ 0);
	}
	pthread_mutex_unlock(&__libev_mutex);

	np_job_submit_event(__libev_interval, _np_events_read);
}

void _np_suspend_event_loop()
{
	pthread_mutex_lock(&__libev_mutex);
	__suspended_libev_loop++;
	pthread_mutex_unlock(&__libev_mutex);
}

void _np_resume_event_loop()
{
	pthread_mutex_lock(&__libev_mutex);
	__suspended_libev_loop--;
	pthread_mutex_unlock(&__libev_mutex);
}
/**
 ** _np_cleanup
 ** general resend mechanism. all message which have an acknowledge indicator set are stored in
 ** memory. If the acknowledge has not been send in time, we try to redeliver the message, otherwise
 ** the message gets deleted or dropped (if max redelivery has been reached)
 ** redelivery has two aspects -> simple resend or reroute because of bad link nodes in the routing table
 **/
void _np_cleanup(np_state_t* state, np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_cleanup");

	np_network_t* ng = state->my_node_key->network;

	np_jtree_elem_t *jrb_ack_node = NULL;

	// wake up and check for acknowledged messages
	pthread_mutex_lock(&ng->lock);

	np_jtree_elem_t* iter = RB_MIN(np_jtree, ng->waiting);
	while (iter != NULL)
	{
		jrb_ack_node = iter;
		iter = RB_NEXT(np_jtree, ng->waiting, iter);

		np_ackentry_t *ackentry = (np_ackentry_t *) jrb_ack_node->val.value.v;
		if (TRUE == ackentry->acked &&
			ackentry->expected_ack == ackentry->received_ack)
		{
			// update latency and statistics for a node
			double latency = ackentry->acktime - ackentry->transmittime;

			np_node_update_latency(ackentry->dest_key->node, latency);
			np_node_update_stat(ackentry->dest_key->node, 1);

			np_unref_obj(np_key_t, ackentry->dest_key);

			RB_REMOVE(np_jtree, ng->waiting, jrb_ack_node);
			free(ackentry);
			free(jrb_ack_node->key.value.s);
			free(jrb_ack_node);

			continue;
		}

		if (ev_time() > ackentry->expiration)
		{
			np_node_update_stat(ackentry->dest_key->node, 0);
			np_unref_obj(np_key_t, ackentry->dest_key);

			RB_REMOVE(np_jtree, ng->waiting, jrb_ack_node);
			free(ackentry);
			free(jrb_ack_node->key.value.s);
			free(jrb_ack_node);

			continue;
		}
	}
	pthread_mutex_unlock(&ng->lock);

	// submit the function itself for additional execution
	np_job_submit_event(__cleanup_interval, _np_cleanup);
	log_msg(LOG_TRACE, ".end  .np_cleanup");

	// np_mem_printpool();
}

/**
 ** np_network_read:
 ** puts the network layer into listen mode. This thread manages acknowledgements,
 ** delivers incoming messages to the message handlers, and drives the network layer.
 **/
// void _np_network_read(np_state_t* state, np_jobargs_t* args)
// {

/**
 ** np_send_rowinfo:
 ** sends matching row of its table to the target node
 **/
void _np_send_rowinfo(np_state_t* state, np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start np_send_rowinfo");

	np_key_t* target_key = args->target;
	// check for correct target
	log_msg(LOG_INFO, "job submit route row info to %s:%s!",
			target_key->node->dns_name, target_key->node->port);

	np_sll_t(np_key_t, sll_of_keys) = NULL;
	/* send one row of our routing table back to joiner #host# */
	_LOCK_MODULE(np_routeglobal_t)
	{
		sll_of_keys = route_row_lookup(target_key);
	}

	if (0 < sll_size(sll_of_keys))
	{
		np_jtree_t* msg_body = make_jtree();
		LOCK_CACHE(state)
		{
			// TODO: maybe locking the cache is not enough and we have to do it more fine grained
			np_encode_nodes_to_jrb(msg_body, sll_of_keys, FALSE);
		}
		np_msgproperty_t* outprop = np_msgproperty_get(state, OUTBOUND, NP_MSG_PIGGY_REQUEST);

		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, target_key, state->my_node_key, NP_MSG_PIGGY_REQUEST, msg_body);
		np_job_submit_msg_event(0.0, outprop, target_key, msg_out);
		np_free_obj(np_message_t, msg_out);
	}
	sll_free(np_key_t, sll_of_keys);
}

np_aaatoken_t* _np_create_node_token(np_state_t* state, np_node_t* node, np_key_t* node_key)
{	log_msg(LOG_TRACE, ".start.np_create_node_token");

	np_aaatoken_t* node_token = NULL;
	np_new_obj(np_aaatoken_t, node_token);

	// create token
	strncpy(node_token->realm, state->my_identity->authentication->realm, 255);

	char node_subject[255];
	snprintf(node_subject, 255, "urn:np:node:%s:%s:%s",
			 np_get_protocol_string(node->protocol), node->dns_name, node->port);

	strncpy(node_token->issuer, (char*) key_get_as_string(node_key), 255);
	strncpy(node_token->subject, node_subject, 255);
	// TODO:
	// strncpy(msg_token->audience, (char*) key_get_as_string(state->my_identity), 255);

	node_token->not_before = ev_time();
	node_token->expiration = ev_time() + 10.0; // 10 second valid token

	// add e2e encryption details for sender
	strncpy((char*) node_token->public_key,
			(char*) node_key->authentication->public_key,
			crypto_sign_BYTES);

	jrb_insert_str(node_token->extensions, "dns_name",
			new_jval_s(node->dns_name));
	jrb_insert_str(node_token->extensions, "port",
			new_jval_s(node->port));
	jrb_insert_str(node_token->extensions, "protocol",
			new_jval_ush(node->protocol));

	// TODO: useful extension ?
	// unsigned char key[crypto_generichash_KEYBYTES];
	// randombytes_buf(key, sizeof key);

	unsigned char hash[crypto_generichash_BYTES];
	crypto_generichash_state gh_state;
	crypto_generichash_init(&gh_state, NULL, 0, sizeof hash);
	crypto_generichash_update(&gh_state, (unsigned char*) node_token->realm, strlen(node_token->realm));
	crypto_generichash_update(&gh_state, (unsigned char*) node_token->issuer, strlen(node_token->issuer));
	crypto_generichash_update(&gh_state, (unsigned char*) node_token->subject, strlen(node_token->subject));
	// crypto_generichash_update(&gh_state, (unsigned char*) node_token->audience, strlen(node_token->audience));
	crypto_generichash_update(&gh_state, (unsigned char*) node_token->public_key, crypto_sign_BYTES);
	// TODO: hash 'not_before' and 'expiration' values as well ?
	crypto_generichash_final(&gh_state, hash, sizeof hash);

	char signature[crypto_sign_BYTES];
	uint64_t signature_len;
	int16_t ret = crypto_sign_detached((unsigned char*)       signature,  &signature_len,
							           (const unsigned char*) hash,  crypto_generichash_BYTES,
									   state->my_identity->authentication->private_key);
	if (ret < 0) {
		log_msg(LOG_WARN, "checksum creation for node token failed, using unsigned node token");
		log_msg(LOG_TRACE, ".end  .np_create_node_token");
		return node_token;
	}
	// TODO: refactor name NP_HS_SIGNATURE to a common name NP_SIGNATURE
	jrb_insert_str(node_token->extensions, NP_HS_SIGNATURE, new_jval_bin(signature, signature_len));

	log_msg(LOG_TRACE, ".end  .np_create_node_token");
	return node_token;
}


np_aaatoken_t* _np_create_msg_token(np_state_t* state, const char* subject, np_msgproperty_t* msg_request)
{	log_msg(LOG_TRACE, ".start.np_create_msg_token");

	np_aaatoken_t* msg_token = NULL;
	np_new_obj(np_aaatoken_t, msg_token);

	// create token
	strncpy(msg_token->realm, state->my_identity->authentication->realm, 255);

	strncpy(msg_token->issuer, (char*) key_get_as_string(state->my_identity), 255);
	strncpy(msg_token->subject, subject, 255);
	// TODO:
	// strncpy(msg_token->audience, (char*) key_get_as_string(state->my_identity), 255);

	msg_token->not_before = ev_time();
	msg_token->expiration = ev_time() + 10.0; // 10 second valid token

	// add e2e encryption details for sender
	strncpy((char*) msg_token->public_key,
			(char*) state->my_identity->authentication->public_key,
			crypto_sign_BYTES);

	jrb_insert_str(msg_token->extensions, "mep_type",
			new_jval_ush(msg_request->mep_type));
	jrb_insert_str(msg_token->extensions, "ack_mode",
			new_jval_ush(msg_request->ack_mode));
	jrb_insert_str(msg_token->extensions, "max_threshold",
			new_jval_ui(msg_request->max_threshold));
	jrb_insert_str(msg_token->extensions, "msg_threshold",
			new_jval_ui(msg_request->msg_threshold));

	jrb_insert_str(msg_token->extensions, "target_node",
			new_jval_s((char*) key_get_as_string(state->my_node_key)));

	// TODO: useful extension ?
	// unsigned char key[crypto_generichash_KEYBYTES];
	// randombytes_buf(key, sizeof key);

	unsigned char hash[crypto_generichash_BYTES];
	crypto_generichash_state gh_state;
	crypto_generichash_init(&gh_state, NULL, 0, sizeof hash);
	crypto_generichash_update(&gh_state, (unsigned char*) msg_token->realm, strlen(msg_token->realm));
	crypto_generichash_update(&gh_state, (unsigned char*) msg_token->issuer, strlen(msg_token->issuer));
	crypto_generichash_update(&gh_state, (unsigned char*) msg_token->subject, strlen(msg_token->subject));
	// crypto_generichash_update(&gh_state, (unsigned char*) msg_token->audience, strlen(msg_token->audience));
	crypto_generichash_update(&gh_state, (unsigned char*) msg_token->public_key, crypto_sign_BYTES);
	// TODO: hash 'not_before' and 'expiration' values as well ?
	crypto_generichash_final(&gh_state, hash, sizeof hash);

	char signature[crypto_sign_BYTES];
	uint64_t signature_len;
	int16_t ret = crypto_sign_detached((unsigned char*)       signature,  &signature_len,
							           (const unsigned char*) hash,  crypto_generichash_BYTES,
									   state->my_identity->authentication->private_key);
	if (ret < 0) {
		log_msg(LOG_WARN, "checksum creation for msgtoken failed, using unsigned msgtoken");
		log_msg(LOG_TRACE, ".end  .np_create_msg_token");
		return msg_token;
	}
	// TODO: refactor name NP_HS_SIGNATURE to a common name NP_SIGNATURE
	jrb_insert_str(msg_token->extensions, NP_HS_SIGNATURE, new_jval_bin(signature, signature_len));

	log_msg(LOG_TRACE, ".end  .np_create_msg_token");
	return msg_token;
}

void _np_send_msg_interest(np_state_t* state, const char* subject) {
	log_msg(LOG_TRACE, ".start.np_send_msg_interest");

	np_message_t* msg_out = NULL;
	np_aaatoken_t* msg_token = NULL;

	np_msgproperty_t* msg_request = np_msgproperty_get(state, INBOUND, subject);
	np_key_t* target = key_create_from_hostport(subject, "0");

	log_msg(LOG_DEBUG, "encoding and storing interest token");

	// insert into msg token token renewal queue
	msg_token = _np_create_msg_token(state, subject, msg_request);
	jrb_insert_str(state->msg_tokens, subject, new_jval_v(NULL));

	log_msg(LOG_DEBUG, "encoding and sending interest token");
	// and create a token to send it over the wire
	np_jtree_t* interest_data = make_jtree();
	// msg_token = create_msg_token(state, subject, msg_request);
	np_encode_aaatoken(interest_data, msg_token);
	// directly send interest
	np_new_obj(np_message_t, msg_out);
	np_message_create(msg_out, target, state->my_node_key, NP_MSG_INTEREST, interest_data);
	np_msgproperty_t* prop_route = np_msgproperty_get(state, TRANSFORM, ROUTE_LOOKUP);
	np_job_submit_msg_event(0.0, prop_route, target, msg_out);

	np_free_obj(np_aaatoken_t, msg_token);
	np_free_obj(np_message_t, msg_out);
	np_free_obj(np_key_t, target);

	log_msg(LOG_TRACE, ".end  .np_send_msg_interest");
}

void _np_send_msg_availability(np_state_t* state, const char* subject)
{
	log_msg(LOG_TRACE, ".start.np_send_msg_availability");
	np_message_t* msg_out = NULL;
	np_aaatoken_t* msg_token = NULL;

	np_msgproperty_t* msg_interest = np_msgproperty_get(state, OUTBOUND, subject);
	np_key_t* target = key_create_from_hostport(subject, "0");

	msg_token = _np_create_msg_token(state, subject, msg_interest);

	log_msg(LOG_DEBUG, "encoding and storing available token");
	jrb_insert_str(state->msg_tokens, subject, new_jval_v(NULL));

	log_msg(LOG_DEBUG, "encoding and sending available token");
	np_jtree_t* available_data = make_jtree();
	np_encode_aaatoken(available_data, msg_token);

	// create message interest message
	np_new_obj(np_message_t, msg_out);
	np_message_create(msg_out, target, state->my_node_key, NP_MSG_AVAILABLE, available_data);
	// send message availability
	np_msgproperty_t* prop_route = np_msgproperty_get(state, TRANSFORM, ROUTE_LOOKUP);
	np_job_submit_msg_event(0.0, prop_route, target, msg_out);

	np_free_obj(np_aaatoken_t, msg_token);
	np_free_obj(np_message_t, msg_out);
	np_free_obj(np_key_t, target);
	log_msg(LOG_TRACE, ".end  .np_send_msg_availability");
}

// TODO: move this to a function which can be scheduled via jobargs
np_bool _np_send_msg (np_state_t* state, char* subject, np_message_t* msg, np_msgproperty_t* msg_prop)
{
	np_aaatoken_t* tmp_token = _np_get_receiver_token(state, subject);

	if (NULL != tmp_token)
	{
		// first encrypt the relevant message part itself
		np_message_encrypt_payload(state, msg, tmp_token);

		char* target_node_str = NULL;

		np_jtree_elem_t* tn_node = jrb_find_str(tmp_token->extensions, "target_node");
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
		str_to_key(receiver_key, target_node_str);

		jrb_insert_str(msg->header, NP_MSG_HEADER_TO, new_jval_s(tmp_token->issuer));
		np_msgproperty_t* out_prop = np_msgproperty_get(state, TRANSFORM, ROUTE_LOOKUP);
		np_job_submit_msg_event(0.0, out_prop, receiver_key, msg);

		// decrease threshold counters
		msg_prop->msg_threshold--;
		np_free_obj(np_key_t, receiver_key);

		return TRUE;
	}
	else
	{
		LOCK_CACHE(msg_prop)
		{
			// cache already full ?
			if (msg_prop->max_threshold <= msg_prop->msg_threshold)
			{
				log_msg(LOG_DEBUG,
						"msg cache full, checking overflow policy ...");

				if (0 < (msg_prop->cache_policy & OVERFLOW_PURGE))
				{
					log_msg(LOG_DEBUG,
							"OVERFLOW_PURGE: discarding first message");
					np_message_t* old_msg = NULL;

					if (0 < (msg_prop->cache_policy & FIFO))
						old_msg = sll_tail(np_message_t, msg_prop->msg_cache);
					if (0 < (msg_prop->cache_policy & FILO))
						old_msg = sll_head(np_message_t, msg_prop->msg_cache);

					msg_prop->msg_threshold--;
					np_unref_obj(np_message_t, old_msg);
				}

				if (0 < (msg_prop->cache_policy & OVERFLOW_REJECT))
				{
					log_msg(LOG_DEBUG,
							"rejecting new message because cache is full");
					// np_free_obj(np_message_t, msg);
					// jump out of LOCK_CACHE
					continue;
				}
			}

			// always prepend, FIFO / FILO handling done when fetching messages
			sll_prepend(np_message_t, msg_prop->msg_cache, msg);

			log_msg(LOG_DEBUG, "added message to the msgcache (%p / %d) ...",
					msg_prop->msg_cache, sll_size(msg_prop->msg_cache));
			np_ref_obj(np_message_t, msg);
		}
	}
	return FALSE;
}
