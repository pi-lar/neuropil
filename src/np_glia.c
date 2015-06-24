#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netdb.h>

#include "sodium.h"

#include "np_glia.h"

#include "aaatoken.h"
#include "dtime.h"
#include "job_queue.h"
#include "jrb.h"
#include "jval.h"
#include "key.h"
#include "log.h"
#include "message.h"
#include "network.h"
#include "neuropil.h"
#include "node.h"
#include "np_threads.h"
#include "np_util.h"
#include "route.h"

static int check_leafset_count = 0;

#define LEAFSET_CHECK_PERIOD 20	/* seconds */

/**
 ** np_route:
 ** routes a message one step closer to its destination key. Delivers
 ** the message to its destination if it is the current host through the
 ** deliver upcall, otherwise it makes the route upcall
 **/
void np_route_lookup (np_state_t* state, np_jobargs_t* args)
{
    np_key_t** tmp;
    np_key_t* target_key = NULL;
    np_message_t* msg_in;

    np_bind(np_message_t, args->msg, msg_in);

	char* msg_subject =
			jrb_find_str(msg_in->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
	char* msg_address =
			jrb_find_str(msg_in->header, NP_MSG_HEADER_TO)->val.value.s;

	np_key_t k_msg_address;
	str_to_key(&k_msg_address, msg_address);

    // first lookup call for target key
	log_msg(LOG_DEBUG, "target is key %s", key_get_as_string(args->target));
	LOCK_CACHE(state->nodes) {
		tmp = route_lookup (state, &k_msg_address, 1, 0);
	}
    log_msg(LOG_DEBUG, "route_lookup result 1 = %s", key_get_as_string(tmp[0]));

    if ((tmp[0] != NULL) && (key_equal (tmp[0], state->neuropil->my_key)))
    {
    	// the result returned the sending node, try again with a higher count parameter
	    free (tmp);
		LOCK_CACHE(state->nodes) {
			tmp = route_lookup (state, &k_msg_address, 2, 0);
		}
		log_msg(LOG_DEBUG, "route_lookup result 2 = %s", key_get_as_string(tmp[0]));
	    if (tmp[1] != NULL && key_equal (tmp[0], &k_msg_address))
	    	tmp[0] = tmp[1];
	}

    if (tmp[0] != state->neuropil->my_key)
	{
    	target_key = tmp[0];
	    log_msg(LOG_DEBUG, "route_lookup result   = %s", key_get_as_string(target_key));
	}
    /*if (tmp[0] == state->neuropil->me)
	{
    	targetNode = NULL;
	}*/

    free (tmp);
    tmp = NULL;

	/* if I am the only host or the closest host is me, deliver the message */
    if (target_key == NULL)
	{
    	// the message has to be handled by this node (e.g. msg interest messages)
    	log_msg(LOG_DEBUG, "internal routing for %s", msg_subject);
    	np_msgproperty_t* prop = np_message_get_handler(state->messages, INBOUND, msg_subject);
    	// job_submit_msg_event(state->jobq, prop, target_key, args->msg);
    	job_submit_msg_event(state->jobq, prop, state->neuropil->my_key, args->msg);
	}
    else /* otherwise, hand it over to the np_axon sending unit */
	{
        log_msg(LOG_DEBUG, "external forward routing for %s: %s", msg_subject, key_get_as_string(target_key) );
    	np_msgproperty_t* prop = np_message_get_handler(state->messages, OUTBOUND, msg_subject);
    	job_submit_msg_event(state->jobq, prop, target_key, args->msg);

    	/* set next hop to the next node */
// 		// TODO: already routed by forward message call ?
// 		// why is there an additional message_send directive here ?
//	    while (!message_send (state->messages, host, message, TRUE, 1))
//		{
//		    host->failuretime = dtime ();
//		    log_msg(LOG_WARN,
//				    "message send to host: %s:%d at time: %f failed!",
//				    host->dns_name, host->port, host->failuretime);
//
//		    /* remove the faulty node from the routing table */
//		    if (host->success_avg < BAD_LINK) route_update (state->routes, host, 0);
//		    if (tmp != NULL) free (tmp);
//		    tmp = route_lookup (state->routes, *key, 1, 0);
//		    host = tmp[0];
//		    log_msg(LOG_WARN, "re-route through %s:%d!", host->dns_name, host->port);
//		}

	    if (tmp) free (tmp);
	}
    np_unbind(np_message_t, args->msg, msg_in);
}

/**
 ** flushes the data of the log buffer to the filesystem in a async callback way
 **/
void np_write_log(np_state_t* state, np_jobargs_t* args) {
	log_fflush();
	job_submit_event(state->jobq, np_write_log);
	dsleep(0.1);
}

/**
 ** np_check_leafset: runs as a separate thread.
 ** it should send a PING message to each member of the leafset frequently and
 ** sends the leafset to other members of its leafset periodically.
 ** pinging frequency is LEAFSET_CHECK_PERIOD.
 **/
void np_check_leafset(np_state_t* state, np_jobargs_t* args) {

	np_sll_t(np_key_t, leafset);
	np_key_t *tmp_node_key;
	np_node_t* tmp_node;
	np_obj_t* o_tmp_node;

	log_msg(LOG_INFO, "leafset check for neighbours started");

	// each time to try to ping our leafset hosts
	LOCK_CACHE(state->nodes) {
		leafset = route_neighbors(state->routes, LEAFSET_SIZE);
	}

	while (NULL != (tmp_node_key = sll_head(np_key_t, leafset))) {

		LOCK_CACHE(state->nodes) {
			o_tmp_node = np_node_lookup(state->nodes, tmp_node_key, 0);
			np_bind(np_node_t, o_tmp_node, tmp_node);
		}
		// check for bad link nodes
		if (tmp_node->success_avg < BAD_LINK &&
			tmp_node->handshake_status > HANDSHAKE_UNKNOWN)
		{
			log_msg(LOG_DEBUG, "Deleting from neighbours: %s", key_get_as_string(tmp_node->key));
	    	// request a new handshake with the node
			np_obj_t* o_my_id_token;
			np_aaatoken_t* my_id_token;
			LOCK_CACHE(state->aaa_cache) {
				o_my_id_token = np_get_authentication_token(state->aaa_cache, tmp_node->key);
				np_bind(np_aaatoken_t, o_my_id_token, my_id_token);
			}
			my_id_token->valid = 0;
			tmp_node->handshake_status = HANDSHAKE_UNKNOWN;
			np_unbind(np_aaatoken_t, o_my_id_token, my_id_token);

			np_unbind(np_node_t, o_tmp_node, tmp_node);

			np_key_t *added, *deleted;
			LOCK_CACHE(state->nodes) {
				leafset_update(state, tmp_node_key, 0, &deleted, &added);
				if (deleted) np_node_release(state->nodes, deleted);
			}

		} else {
			/* otherwise request reevaluation of peer */
			/* assume failure of the node now, will be reset with ping reply */
			tmp_node->failuretime = dtime();
			np_node_update_stat(tmp_node, 0);
			np_unbind(np_node_t, o_tmp_node, tmp_node);

			np_ping(state, tmp_node_key);
		}
	}
	sll_free(np_key_t, leafset);


	if (check_leafset_count == 1) {

		log_msg(LOG_INFO, "leafset check for table started");
		np_sll_t(np_key_t, table);
		LOCK_CACHE(state->nodes) {
			table = route_get_table(state->routes);
		}

		while ( NULL != (tmp_node_key = sll_head(np_key_t, table)))
		{
			// send update of new node to all nodes in my routing table
			LOCK_CACHE(state->nodes) {
				o_tmp_node = np_node_lookup(state->nodes, tmp_node_key, 0);
				np_bind(np_node_t, o_tmp_node, tmp_node);
			}

			/* first check for bad link nodes */
			if (tmp_node->success_avg < BAD_LINK &&
				tmp_node->handshake_status > HANDSHAKE_UNKNOWN)
			{
				log_msg(LOG_DEBUG, "Deleting from table: %s", key_get_as_string(tmp_node_key));
				// request a new handshake with the node
				np_obj_t* o_my_id_token;
				np_aaatoken_t* my_id_token;
				LOCK_CACHE(state->aaa_cache) {
					o_my_id_token = np_get_authentication_token(state->aaa_cache, tmp_node_key);
					np_bind(np_aaatoken_t, o_my_id_token, my_id_token);
				}
				my_id_token->valid = 0;
				tmp_node->handshake_status = HANDSHAKE_UNKNOWN;
				np_unbind(np_aaatoken_t, o_my_id_token, my_id_token);
				np_unbind(np_node_t, o_tmp_node, tmp_node);

				np_key_t *added, *deleted;
				LOCK_CACHE(state->nodes) {
					route_update(state, tmp_node_key, 0, &deleted, &added);
					if (added)   np_node_lookup(state->nodes, added, 1);
					if (deleted) np_node_release(state->nodes, deleted);
				}
			} else {
				/* otherwise request re-evaluation of node stats */
				/* weired: assume failure of the node now, will be reset with ping reply later */
				tmp_node->failuretime = dtime();
				np_node_update_stat(tmp_node, 0);
				np_unbind(np_node_t, o_tmp_node, tmp_node);

				np_ping(state, tmp_node_key);
			}
		}
		sll_free(np_key_t, table);
	}

	/* send leafset exchange data every 3 times that pings the leafset */
	if (check_leafset_count == 2) {
		check_leafset_count = 0;

		log_msg(LOG_INFO, "leafset exchange for neighbours started");
		leafset = route_neighbors(state->routes, LEAFSET_SIZE);

		while ( NULL != (tmp_node_key = sll_head(np_key_t, leafset))) {
			// for (i = 0; leafset[i] != NULL ; i++) {
			// send a piggy message to the the nodes in our routing table
			np_msgproperty_t* piggy_prop = np_message_get_handler(state->messages, TRANSFORM, NP_MSG_PIGGY_REQUEST);
			job_submit_msg_event(state->jobq, piggy_prop, tmp_node_key, NULL);
		}
		sll_free(np_key_t, leafset);

	} else {
		check_leafset_count++;
	}

	dsleep(LEAFSET_CHECK_PERIOD);
	// np_printpool;
	job_submit_event(state->jobq, np_check_leafset);
}

/**
 ** np_retransmit_messages
 ** general resend mechanism. all message which have an acknowledge indicator set are stored in
 ** memory. If the acknowledge has not been send in time, we try to redeliver the message, otherwise
 ** the message gets deleted or dropped (if max redelivery has been reached)
 ** redelivery has two aspects -> simple resend or reroute because of bad link nodes in the routing table
 **/
void np_retransmit_messages(np_state_t* state, np_jobargs_t* args) {

	double now = 0.0;
	double sleeptime = RETRANSMIT_THREAD_SLEEP;

	np_jrb_t *pqnode, *jrb_ack_node;
	PQEntry* pqentry;
	np_networkglobal_t* ng = state->network;

	np_node_t* dest_node;
	np_obj_t* o_dest_node;

	pthread_mutex_lock(&ng->lock);

	// wake up, get all the packets to be transmitted by now, send them again or delete them from the priqueue
	if (jrb_empty(ng->retransmit)) {
		dsleep(sleeptime);
		job_submit_event(state->jobq, np_retransmit_messages);
		pthread_mutex_unlock(&ng->lock);
		return;
	}

	now = dtime();
	double min_sleep_time = 0.0;
	pqnode = jrb_first(ng->retransmit);

	do {
		min_sleep_time = pqnode->key.value.d - now;
		if (min_sleep_time < sleeptime ) sleeptime = min_sleep_time;

		if (pqnode->key.value.d <= now) break;
		pqnode = jrb_next(pqnode);

	} while ( pqnode != jrb_nil(ng->retransmit) );

	// queue was not empty, but time comparison said: no element ready for retransmit
	if (pqnode == jrb_nil(ng->retransmit)) {
		dsleep(sleeptime);
		job_submit_event(state->jobq, np_retransmit_messages);
		pthread_mutex_unlock(&ng->lock);
	 	return;
	}

	// found element to retransmit
	pqentry = (PQEntry *) pqnode->val.value.v;
	// log_msg(LOG_INFO, "retransmission check for message %i (now: %f / rtt: %f)", pqentry->seqnum, now, pqnode->key.d);
	jrb_ack_node = jrb_find_ulong(ng->waiting, pqentry->seqnum);
	assert(jrb_ack_node != NULL);

	np_ackentry_t *ackentry = (np_ackentry_t *) jrb_ack_node->val.value.v;

	np_message_t* re_msg;
	np_bind(np_message_t, pqentry->msg, re_msg);

	pthread_mutex_unlock(&ng->lock);

	LOCK_CACHE(state->nodes) {
		o_dest_node = np_node_lookup(state->nodes, pqentry->dest_key, 0);
		np_bind(np_node_t, o_dest_node, dest_node);
	}

	if (ackentry->acked == 0) // means, if the packet is not yet acknowledged
	{
		log_msg(LOG_INFO, "retransmission check for message %i -> no ack found", pqentry->seqnum);

		if (pqentry->retry <= MAX_RETRY)
		{
			if (dest_node->success_avg < BAD_LINK) {
		    	// reroute for bad link nodes
				np_node_update_stat(dest_node, 0);
				// adjust resend count, otherwise it is forgotten because we re-route
				np_jrb_t* jrb_retry_count = jrb_find_str(re_msg->instructions, "_np.resend_count");
				jrb_retry_count->val.value.ui = pqentry->retry;

				np_msgproperty_t* prop = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
				job_submit_msg_event(state->jobq, prop, dest_node->key, pqentry->msg);

				np_unref(np_message_t, pqentry->msg);
				np_unref(np_node_t, o_dest_node);

				pthread_mutex_lock(&ng->lock);
				free(ackentry);
				jrb_delete_node(jrb_ack_node);
				free(pqentry);
				jrb_delete_node(pqnode);
				pthread_mutex_unlock(&ng->lock);

			} else {
				double transmittime = dtime();

				// prepare a resend later
				PQEntry *newentry = get_new_pqentry();
				newentry->dest_key = pqentry->dest_key;
				newentry->msg = pqentry->msg;
				newentry->retry = ++pqentry->retry;
				newentry->seqnum = pqentry->seqnum;
				newentry->transmittime = transmittime;

				pthread_mutex_lock(&ng->lock);
				jrb_insert_dbl(ng->retransmit, (transmittime + RETRANSMIT_INTERVAL), new_jval_v(newentry));
				free(pqentry);
				jrb_delete_node(pqnode);
				pthread_mutex_unlock(&ng->lock);

				// and try to deliver the message now
				network_send_udp(state, dest_node, re_msg);
			}
			np_unbind(np_node_t, o_dest_node, dest_node);

		} else {
			// max retransmission has expired -- update the host stats, free up the resources
			// pthread_mutex_lock(&ng->lock);
			log_msg(LOG_WARN, "max retries exceeded, dropping message: %d", pqentry->seqnum);
	    	np_node_update_stat(dest_node, 0);

	    	np_unref(np_message_t, pqentry->msg);
			// TODO: implement dead letter queue handling ?
			np_unbind(np_node_t, o_dest_node, dest_node);
			np_unref(np_node_t, o_dest_node);
			np_free(np_node_t, o_dest_node);

			np_unbind(np_message_t, pqentry->msg, re_msg);
			np_free(np_message_t, pqentry->msg);

			pthread_mutex_lock(&ng->lock);
			free(ackentry);
			jrb_delete_node(jrb_ack_node);
			free(pqentry);
			jrb_delete_node(pqnode);
			pthread_mutex_unlock(&ng->lock);
		}

	} else {
		// log_msg(LOG_DEBUG, "message acknowledged, no further retry: %d", pqentry->seqnum);
		// packet is acked;
		// update the host latency and the success measurements
		// and decrease reference counter again
		// pthread_mutex_lock(&ng->lock);

		// increase threshold counter again
		char* msg_subject = jrb_find_str(re_msg->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
		np_msginterest_t* interested = np_message_interest_match(state->messages, msg_subject);

		if (interested) {
			pthread_mutex_lock(&state->messages->interest_lock);
			interested->msg_threshold++;
			pthread_mutex_unlock(&state->messages->interest_lock);
		}

		double latency = ackentry->acktime - pqentry->transmittime;
		if (latency > 0) {
			if (dest_node->latency == 0.0) {
				dest_node->latency = latency;
			} else {
				dest_node->latency = (0.9 * dest_node->latency) + (0.1 * latency);
			}
		}
		np_node_update_stat(dest_node, 1);

		np_unbind(np_node_t, o_dest_node, dest_node);
		np_unref(np_node_t, o_dest_node);
		np_free(np_node_t, o_dest_node);

		np_unref(np_message_t, pqentry->msg);

		np_unbind(np_message_t, pqentry->msg, re_msg);
		np_free(np_message_t, pqentry->msg);

		pthread_mutex_lock(&ng->lock);
		free(ackentry);
		jrb_delete_node(jrb_ack_node);
		free(pqentry);
		jrb_delete_node(pqnode);
		pthread_mutex_unlock(&ng->lock);
	}

	// submit the function itself for additional execution
	job_submit_event(state->jobq, np_retransmit_messages);
}

/**
 ** np_network_read:
 ** puts the network layer into listen mode. This thread manages acknowledgements,
 ** delivers incoming messages to the message handlers, and drives the network layer.
 **/
void np_network_read(np_state_t* state, np_jobargs_t* args) {

	fd_set fds;
	int ret;
	char data[NETWORK_PACK_SIZE];
	struct sockaddr from;
	socklen_t fromlen = sizeof (from);
	int ack = 0;
	uint32_t seq = 0;

	np_networkglobal_t* ng = state->network;

	FD_ZERO(&fds);
	FD_SET(ng->sock, &fds);

	// timeout.tv_usec = 5000;
	ret = select(FD_SETSIZE, &fds, NULL, NULL, NULL );
	if (ret < 0) {
		log_msg(LOG_ERROR, "select: %s", strerror(errno));
		job_submit_event(state->jobq, np_network_read);
		return;
	}

	/* receive the new data */
	int in_msg_len = recvfrom(ng->sock, data, NETWORK_PACK_SIZE, 0, &from, &fromlen);
	if (!in_msg_len) {
		log_msg(LOG_ERROR, "recvfrom failed: %s", strerror(errno));
		job_submit_event(state->jobq, np_network_read);
		return;
	}
	// get calling address and port
	char ipstr[INET6_ADDRSTRLEN];
	int port;

	if (from.sa_family == PF_INET) {
		inet_ntop(from.sa_family, &(((struct sockaddr_in *)&from)->sin_addr), ipstr, sizeof ipstr);
		port = ((struct sockaddr_in *)&from)->sin_port;
	} else {
		inet_ntop(from.sa_family, &(((struct sockaddr_in6 *)&from)->sin6_addr), ipstr, sizeof ipstr);
		port = ((struct sockaddr_in6 *)&from)->sin6_port;
	}

	log_msg(LOG_DEBUG, "received message from %s:%d (size: %d)", ipstr, port, in_msg_len);

	// we registered this token info before in the first handshake message
	np_key_t* alias_key = key_create_from_hostport(ipstr, port);
	np_obj_t* o_session_token;
	np_aaatoken_t* session_token;
	void* data_ptr = data;

	LOCK_CACHE(state->aaa_cache) {
		o_session_token = np_get_authentication_token(state->aaa_cache, alias_key);
		np_bind(np_aaatoken_t, o_session_token, session_token);
	}

	if (session_token->valid) {
		// log_msg(LOG_DEBUG, "now decrypting to np_message_t (size %d)", ret);
		unsigned char  nonce[crypto_secretbox_NONCEBYTES];
		unsigned char* dec_msg = (unsigned char*) malloc(in_msg_len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);

		memcpy(nonce, data_ptr, crypto_secretbox_NONCEBYTES);

		// log_msg(LOG_DEBUG, "now nonce (%s)", nonce);
		ret = crypto_secretbox_open_easy(
					dec_msg,
					(const unsigned char *) data_ptr + crypto_secretbox_NONCEBYTES,
					in_msg_len - crypto_secretbox_NONCEBYTES,
					nonce,
					session_token->session_key);

		if (ret != 0) {
			log_msg(LOG_ERROR,
					"incorrect decryption of message (send from %s:%d), resetting session token",
					ipstr, port);
		} else {
			// data_ptr = dec_msg;
			memset(data_ptr, 0, NETWORK_PACK_SIZE);
			memcpy(data_ptr, dec_msg, in_msg_len - crypto_secretbox_NONCEBYTES);
		}
		free (dec_msg);
	}
	np_unbind(np_aaatoken_t, o_session_token, session_token);

	np_obj_t* o_msg_in;
	np_message_t* msg_in;

	np_new(np_message_t, o_msg_in);
	np_bind(np_message_t, o_msg_in, msg_in);

	ret = np_message_deserialize(msg_in, data_ptr);
	if (0 == ret) {
		log_msg(LOG_ERROR, "error de-serializing message");
		np_unbind(np_message_t, o_msg_in, msg_in);
		np_free(np_message_t, o_msg_in);

		job_submit_event(state->jobq, np_network_read);
		return;
	}

	if (0 == msg_in->header->size &&
		0 == msg_in->instructions->size &&
		0 == msg_in->properties->size &&
		0 == msg_in->footer->size)
	{
		log_msg(LOG_DEBUG, "identified handshake message ...");
		// np_bind(np_aaatoken_t, o_session_token, session_token);
		np_bind(np_aaatoken_t, o_session_token, session_token);
		if (!session_token->valid) {
			jrb_insert_str(msg_in->footer, NP_MSG_FOOTER_ALIAS_KEY, new_jval_s((char*) key_get_as_string(alias_key)));
			np_msgproperty_t* msg_prop = np_message_get_handler(state->messages, INBOUND, NP_MSG_HANDSHAKE);
			job_submit_msg_event(state->jobq, msg_prop, state->neuropil->my_key, o_msg_in);

		} else {
			log_msg(LOG_DEBUG, "... but handshake is already complete");
		}
		np_unbind(np_aaatoken_t, o_session_token, session_token);

	} else {
		// TODO: stop doing message handling following this line, ack handling may still be fine
		// TODO: hook in policy for accessing the system ? evaluate 'from' field ?

		// read now decrypted header
		char* subject  = jrb_find_str(msg_in->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
		// char* reply_to = jrb_find_str(msg->header, NP_MSG_HEADER_REPLY_TO)->val.value.s;

		// read neuropil related message instructions
		seq = jrb_find_str(msg_in->instructions, "_np.seq")->val.value.ul;
		ack = jrb_find_str(msg_in->instructions, "_np.ack")->val.value.ui;
		// parts = jrb_find_str(newmsg->instructions, "_np.part")->val.value.i;

		if (0 == strncmp(NP_MSG_ACK, subject, strlen(NP_MSG_ACK)) )
		{
			np_jrb_t *jrb_node;
			/* just an acknowledgement of own messages send out earlier */
			/* TODO: trigger update of node stats ? */
			pthread_mutex_lock(&(ng->lock));
			jrb_node = jrb_find_ulong(ng->waiting, seq);
			if (jrb_node != NULL ) {
				np_ackentry_t *entry = (np_ackentry_t *) jrb_node->val.value.v;
				entry->acked = 1;
				entry->acktime = dtime();
				log_msg(LOG_DEBUG, "received acknowledgment of seq=%lu", seq);
			}
			pthread_mutex_unlock(&(ng->lock));

			np_unbind(np_message_t, o_msg_in, msg_in);
			np_free(np_message_t, o_msg_in);

			job_submit_event(state->jobq, np_network_read);
			return;
		}

		log_msg(LOG_DEBUG, "received message for subject: %s (seq=%ul, ack=%d)", subject, seq, ack );

		if (ack == ACK_EACHHOP && state->joined_network) {
			/* acknowledge part, each hop has to acknowledge the message */
			// TODO: move this ack after a) a message handler has been found or b) the message has been forwarded
			np_obj_t* o_ack_msg_out;
			np_obj_t* o_ack_node;
			np_node_t* ack_node;
			np_message_t* ack_msg_out;

			char* ack_to = jrb_find_str(msg_in->instructions, "_np.ack_to")->val.value.s;

			np_msgproperty_t* ack_prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_ACK);
			LOCK_CACHE(state->nodes) {
				o_ack_node = np_node_decode_from_str(state->nodes, ack_to);
				np_bind(np_node_t, o_ack_node, ack_node);
			}

			np_new(np_message_t, o_ack_msg_out)
			np_bind(np_message_t, o_ack_msg_out, ack_msg_out);

			np_message_create(ack_msg_out, ack_node->key, state->neuropil->my_key, NP_MSG_ACK, NULL);
			/* create network header */
			jrb_insert_str(ack_msg_out->instructions, "_np.ack", new_jval_ui(ack_prop->ack_mode));
			jrb_insert_str(ack_msg_out->instructions, "_np.seq", new_jval_ul(seq));
			// direct acknowledge
			if (np_node_check_address_validity(ack_node)) {
				job_submit_msg_event(state->jobq, ack_prop, ack_node->key, o_ack_msg_out);
			}
			np_unbind(np_message_t, o_ack_msg_out, ack_msg_out);
			np_free(np_message_t, o_ack_msg_out);

			np_unbind(np_node_t, o_ack_node, ack_node);
			// user space acknowledgement handled later, also for join messages
		}

		/* receive part, plus final delivery ack */
		char* address  = jrb_find_str(msg_in->header, NP_MSG_HEADER_TO)->val.value.s;

		np_key_t* target_key;
		np_new_obj(np_key_t, target_key);
		str_to_key(target_key, address);

		np_msgproperty_t* prop = np_message_get_handler(state->messages, INBOUND, DEFAULT);
		job_submit_msg_event(state->jobq, prop, target_key, o_msg_in);
	}

	np_unbind(np_message_t, o_msg_in, msg_in);
	np_free(np_message_t, o_msg_in);

	np_free_obj(np_key_t, alias_key);

	// schedule new network read event
	job_submit_event(state->jobq, np_network_read);
}


/**
 ** np_send_rowinfo:
 ** sends matching row of its table to the target node
 **/
void np_send_rowinfo (np_state_t* state, np_jobargs_t* args)
{
    np_obj_t* o_msg_out;
	np_message_t* msg_out;

	np_obj_t* o_target_node;
	np_node_t* target_node;
	np_jrb_t* msg_body;
    np_sll_t(np_key_t, sll_of_keys);

	// check for correct target
	LOCK_CACHE(state->nodes) {
		o_target_node = np_node_lookup(state->nodes, args->target, 0);
		np_bind(np_node_t, o_target_node, target_node);
	}

	log_msg(LOG_INFO, "job submit route row info to %s:%d!", target_node->dns_name, target_node->port);
    np_key_t* target_key = target_node->key;
    np_unbind(np_node_t, o_target_node, target_node);

    /* send one row of our routing table back to joiner #host# */
    sll_of_keys = route_row_lookup (state, target_key);

    msg_body = make_jrb();
    LOCK_CACHE(state->nodes) {
		// TODO: maybe locking the cache is not enough and we have to do it more fine grained
		np_encode_nodes_to_jrb(state->nodes, msg_body, sll_of_keys);
	}
	np_msgproperty_t* outprop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_PIGGY_REQUEST);

    np_new(np_message_t, o_msg_out);
	np_bind(np_message_t, o_msg_out, msg_out);

	np_message_create (msg_out, target_key, state->neuropil->my_key, NP_MSG_PIGGY_REQUEST, msg_body);
    job_submit_msg_event(state->jobq, outprop, target_key, o_msg_out);

    np_unbind(np_message_t, o_msg_out, msg_out);
    sll_free(np_key_t, sll_of_keys);
}


void np_send_msg_interest(const np_state_t* state, np_msginterest_t* interest) {

	np_obj_t* o_msg_out;
	np_message_t* msg_out;
	np_obj_t* o_auth_token;
	np_aaatoken_t* auth_token;

	// add e2e encryption details for receiver
	np_jrb_t* interest_data = make_jrb();
	np_message_encode_interest(interest_data, interest);
	LOCK_CACHE(state->aaa_cache) {
		o_auth_token = np_get_authentication_token(state->aaa_cache, interest->key);
		np_bind(np_aaatoken_t, o_auth_token, auth_token);
	}
	np_encode_aaatoken(interest_data, auth_token);
	np_unbind(np_aaatoken_t, o_auth_token, auth_token);

	np_key_t* target = key_create_from_hostport(interest->msg_subject, 0);

	np_new(np_message_t, o_msg_out);
	np_bind(np_message_t, o_msg_out, msg_out);

	np_message_create(msg_out, target, state->neuropil->my_key, NP_MSG_INTEREST, interest_data);
	// send interest
	np_msgproperty_t* prop_route = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
	job_submit_msg_event(state->jobq, prop_route, target, o_msg_out);

	np_unbind(np_message_t, o_msg_out, msg_out);
}

void np_send_msg_availability(const np_state_t* state, np_msginterest_t* available) {

	np_obj_t* o_msg_out;
	np_message_t* msg_out;

	np_jrb_t* available_data = make_jrb();
	np_message_encode_interest(available_data, available);

	// add e2e encryption details for sender
	np_obj_t* o_auth_token;
	np_aaatoken_t* auth_token;

	LOCK_CACHE(state->aaa_cache) {
		o_auth_token = np_get_authentication_token(state->aaa_cache, available->key);
		np_bind(np_aaatoken_t, o_auth_token, auth_token);
	}
	np_encode_aaatoken(available_data, auth_token);

	np_unbind(np_aaatoken_t, o_auth_token, auth_token);

	// create message interest message
	np_key_t* target = key_create_from_hostport(available->msg_subject, 0);

	np_new(np_message_t, o_msg_out);
	np_bind(np_message_t, o_msg_out, msg_out);

	np_message_create(msg_out, target, state->neuropil->my_key, NP_MSG_AVAILABLE, available_data);
	// send message availability
	np_msgproperty_t* prop_route = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
	job_submit_msg_event(state->jobq, prop_route, target, o_msg_out);

	np_unbind(np_message_t, o_msg_out, msg_out);
}
