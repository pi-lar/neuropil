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
#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_route.h"

static int8_t check_leafset_count = 0;

#define LEAFSET_CHECK_PERIOD 20	/* seconds */

/**
 ** np_route:
 ** routes a message one step closer to its destination key. Delivers
 ** the message to its destination if it is the current host through the
 ** deliver upcall, otherwise it makes the route upcall
 **/
void np_route_lookup(np_state_t* state, np_jobargs_t* args) {

	log_msg(LOG_TRACE, ".start.np_route_lookup");
	np_sll_t(np_key_t, tmp);
	np_key_t* target_key = NULL;
	np_message_t* msg_in = args->msg;

	char* msg_subject = jrb_find_str(msg_in->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
	unsigned char* msg_address = (unsigned char*) jrb_find_str(msg_in->header, NP_MSG_HEADER_TO)->val.value.s;

	np_key_t k_msg_address;
	str_to_key(&k_msg_address, msg_address);

	// first lookup call for target key
	log_msg(LOG_DEBUG, "message target is key %s", key_get_as_string(&k_msg_address));


	LOCK_CACHE(state->routes)
	{
		tmp = route_lookup(state, &k_msg_address, 1);
		log_msg(LOG_DEBUG, "route_lookup result 1 = %s", key_get_as_string(sll_first(tmp)->val));
	}

	if (sll_size(tmp) > 0 && (key_equal(sll_first(tmp)->val, state->my_key))) {
		// the result returned the sending node, try again with a higher count parameter
		sll_free(np_key_t, tmp);

		LOCK_CACHE(state->routes)
		{
			tmp = route_lookup(state, &k_msg_address, 2);
			log_msg(LOG_DEBUG, "route_lookup result 2 = %s", key_get_as_string(sll_first(tmp)->val));
		}
		// TODO: ???
		// if (tmp[1] != NULL && key_equal(tmp[0], &k_msg_address))
		// tmp[0] = tmp[1];
	}

	if (!key_equal(sll_first(tmp)->val, state->my_key)) {
		target_key = sll_first(tmp)->val;
		log_msg(LOG_DEBUG, "route_lookup result   = %s", key_get_as_string(target_key));
	}

	/* if I am the only host or the closest host is me, deliver the message */
	if (target_key == NULL) {
		// the message has to be handled by this node (e.g. msg interest messages)
		log_msg(LOG_DEBUG, "internal routing for subject '%s'", msg_subject);
		np_msgproperty_t* prop = np_message_get_handler(state, INBOUND, msg_subject);

		// job_submit_msg_event(state->jobq, prop, target_key, args->msg);
		if (prop != NULL)
			job_submit_msg_event(state->jobq, prop, state->my_key, args->msg);

	}
	else /* otherwise, hand it over to the np_axon sending unit */
	{
		log_msg(LOG_DEBUG, "forward routing for subject '%s': %s", msg_subject,
				key_get_as_string(target_key));

		np_msgproperty_t* prop = np_message_get_handler(state, OUTBOUND, msg_subject);
		if (NULL == prop)
			prop = np_message_get_handler(state, OUTBOUND, DEFAULT);
		job_submit_msg_event(state->jobq, prop, target_key, args->msg);

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
void np_write_log(np_state_t* state, np_jobargs_t* args) {
	// log_msg(LOG_TRACE, "start np_write_log");
	log_fflush();
	dsleep(0.31415);
	job_submit_event(state->jobq, np_write_log);
	// log_msg(LOG_TRACE, "end   np_write_log");
}

/**
 ** np_check_leafset: runs as a separate thread.
 ** it should send a PING message to each member of the leafset frequently and
 ** sends the leafset to other members of its leafset periodically.
 ** pinging frequency is LEAFSET_CHECK_PERIOD.
 **/
void np_check_leafset(np_state_t* state, np_jobargs_t* args) {
	log_msg(LOG_TRACE, ".start.np_check_leafset");

	np_sll_t(np_key_t, leafset);
	np_key_t *tmp_node_key;

	log_msg(LOG_INFO, "leafset check for neighbours started");
	// each time to try to ping our leafset hosts
	LOCK_CACHE(state->routes)
	{
		leafset = route_neighbors(state, LEAFSET_SIZE);
	}

	while (NULL != (tmp_node_key = sll_head(np_key_t, leafset))) {

		// check for bad link nodes
		if (tmp_node_key->node->success_avg < BAD_LINK
				&& tmp_node_key->node->handshake_status > HANDSHAKE_UNKNOWN) {
			log_msg(LOG_DEBUG, "Deleting from neighbours: %s",
					key_get_as_string(tmp_node_key));
			// request a new handshake with the node
			tmp_node_key->authentication->valid = 0;
			tmp_node_key->node->handshake_status = HANDSHAKE_UNKNOWN;

			np_key_t *added, *deleted;
			LOCK_CACHE(state->routes)
			{
				leafset_update(state, tmp_node_key, 0, &deleted, &added);
				if (deleted) {
					np_unref_obj(np_key_t, tmp_node_key);
					np_free_obj(np_key_t, deleted);
				}
			}

		} else {
			/* otherwise request reevaluation of peer */
			/* assume failure of the node now, will be reset with ping reply */
			tmp_node_key->node->failuretime = dtime();
			np_node_update_stat(tmp_node_key->node, 0);

			np_ping(state, tmp_node_key);
		}
	}
	sll_free(np_key_t, leafset);

	if (check_leafset_count == 1) {

		log_msg(LOG_INFO, "leafset check for table started");
		np_sll_t(np_key_t, table);
		LOCK_CACHE(state->routes)
		{
			table = route_get_table(state->routes);
		}

		while ( NULL != (tmp_node_key = sll_head(np_key_t, table))) {
			// send update of new node to all nodes in my routing table

			/* first check for bad link nodes */
			if (tmp_node_key->node->success_avg < BAD_LINK
					&& tmp_node_key->node->handshake_status
							> HANDSHAKE_UNKNOWN) {
				log_msg(LOG_DEBUG, "Deleting from table: %s",
						key_get_as_string(tmp_node_key));
				// request a new handshake with the node
				tmp_node_key->authentication->valid = 0;
				tmp_node_key->node->handshake_status = HANDSHAKE_UNKNOWN;

				np_key_t *added, *deleted;
				LOCK_CACHE(state->routes)
				{
					route_update(state, tmp_node_key, 0, &deleted, &added);
					if (added)
						np_ref_obj(np_key_t, added);
					if (deleted) {
						np_unref_obj(np_key_t, deleted);
						np_free_obj(np_key_t, deleted);
					}
				}
			} else {
				/* otherwise request re-evaluation of node stats */
				/* weired: assume failure of the node now, will be reset with ping reply later */
				tmp_node_key->node->failuretime = dtime();
				np_node_update_stat(tmp_node_key->node, 0);

				np_ping(state, tmp_node_key);
			}
		}
		sll_free(np_key_t, table);
	}

	/* send leafset exchange data every 3 times that pings the leafset */
	if (check_leafset_count == 2) {
		check_leafset_count = 0;

		log_msg(LOG_INFO, "leafset exchange for neighbours started");

		LOCK_CACHE(state->routes)
		{
			leafset = route_neighbors(state, LEAFSET_SIZE);
		}

		while ( NULL != (tmp_node_key = sll_head(np_key_t, leafset))) {
			// for (i = 0; leafset[i] != NULL ; i++) {
			// send a piggy message to the the nodes in our routing table
			np_msgproperty_t* piggy_prop = np_message_get_handler(state,
					TRANSFORM, NP_MSG_PIGGY_REQUEST);
			job_submit_msg_event(state->jobq, piggy_prop, tmp_node_key, NULL);
		}
		sll_free(np_key_t, leafset);

	} else {
		check_leafset_count++;
	}

	dsleep(LEAFSET_CHECK_PERIOD);
	// np_printpool;
	job_submit_event(state->jobq, np_check_leafset);
	log_msg(LOG_TRACE, ".end  .np_check_leafset");
}

/**
 ** np_retransmit_messages
 ** retransmit tokens on a regular interval
 ** default ttl value for message exchange tokens is ten seconds, afterwards they will be invalid
 ** and a new token is required. this also ensures that the correct encryption key will be transmitted
 **/
void np_retransmit_tokens(np_state_t* state, np_jobargs_t* args) {
	// log_msg(LOG_TRACE, "start np_retransmit_tokens");

	np_jtree_elem_t *iter = NULL;
	np_jtree_elem_t *deleted = NULL;

	RB_FOREACH(iter, np_jtree, state->msg_tokens)
	{
		np_aaatoken_t* current = iter->val.value.v;

		if (TRUE == token_is_valid(current)) {
			// log_msg(LOG_DEBUG, "token still valid, skipping ...");
			continue;

		} else {
			log_msg(LOG_DEBUG, "found invalid msg token for subject %s, renewing ...", current->subject);

			// remove the token first, otherwise it cannot be added in again
			deleted = RB_REMOVE(np_jtree, state->msg_tokens, iter);
			free(deleted);

			if (NULL != np_message_get_handler(state, INBOUND, current->subject))
				np_send_msg_interest(state, current->subject);

			if (NULL != np_message_get_handler(state, OUTBOUND, current->subject))
				np_send_msg_availability(state, current->subject);

			np_unref_obj(np_aaatoken_t, current);
			np_free_obj(np_aaatoken_t, current);
			// we deleted a node in the tree, better take a jump and continue later
			break;
		}
	}

	dsleep(0.31415);
	job_submit_event(state->jobq, np_retransmit_tokens);
}

/**
 ** np_retransmit_messages
 ** general resend mechanism. all message which have an acknowledge indicator set are stored in
 ** memory. If the acknowledge has not been send in time, we try to redeliver the message, otherwise
 ** the message gets deleted or dropped (if max redelivery has been reached)
 ** redelivery has two aspects -> simple resend or reroute because of bad link nodes in the routing table
 **/
void np_retransmit_messages(np_state_t* state, np_jobargs_t* args) {
	log_msg(LOG_TRACE, ".start.np_retransmit_messages");

	double now = 0.0;
	double sleeptime = RETRANSMIT_THREAD_SLEEP;

	np_network_t* ng = state->my_key->node->network;

	np_jtree_elem_t *pqnode, *jrb_ack_node;
	np_prioq_t *pqentry;

	pthread_mutex_lock(&ng->lock);

	// wake up, get all the packets to be transmitted by now, send them again or delete them from the priqueue
	now = dtime();
	double min_sleep_time = 0.0;

	RB_FOREACH(pqnode, np_jtree, ng->retransmit)
	{
		if (now >= pqnode->key.value.d)
			break;

		min_sleep_time = pqnode->key.value.d - now;
		if (min_sleep_time < sleeptime)
			sleeptime = min_sleep_time;
	};

	// queue was not empty, but time comparison said: no element ready for retransmit
	if (NULL == pqnode) {
		pthread_mutex_unlock(&ng->lock);
		dsleep(sleeptime);
		job_submit_event(state->jobq, np_retransmit_messages);
		log_msg(LOG_TRACE, ".end  .np_retransmit_messages");
		return;
	}

	// found element to retransmit
	pqentry = (np_prioq_t *) pqnode->val.value.v;
	// log_msg(LOG_INFO, "retransmission check for message %i (now: %f / rtt: %f)", pqentry->seqnum, now, pqnode->key.d);
	jrb_ack_node = jrb_find_ulong(ng->waiting, pqentry->seqnum);
	assert(jrb_ack_node != NULL);

	np_ackentry_t *ackentry = (np_ackentry_t *) jrb_ack_node->val.value.v;
	np_message_t* re_msg = pqentry->msg;

	pthread_mutex_unlock(&ng->lock);

	if (FALSE == ackentry->acked) // means, if the packet is not yet acknowledged
	{
		log_msg(LOG_INFO, "retransmission check for message %i -> no ack found",
				pqentry->seqnum);

		if (MAX_ENTRY >= pqentry->retry) {
			if (BAD_LINK > pqentry->dest_key->node->success_avg) {
				log_msg(LOG_DEBUG, "re-routing: failed delivery attempt %u", pqentry->seqnum);
				// re-route for nodes which had some failures in the past
				np_node_update_stat(pqentry->dest_key->node, 0);

				np_key_t* real_dest = key_create_from_hash(
						(unsigned char*) jrb_find_str(re_msg->header,
								NP_MSG_HEADER_TO)->val.value.s);

				// adjust resend count, otherwise it is forgotten because we re-route
				np_jtree_elem_t* jrb_retry_count = jrb_find_str(
						re_msg->instructions, NP_MSG_INST_RESEND_COUNT);
				jrb_retry_count->val.value.ush = pqentry->retry;

				np_msgproperty_t* prop = np_message_get_handler(state, TRANSFORM, ROUTE_LOOKUP);
				job_submit_msg_event(state->jobq, prop, real_dest, pqentry->msg);

				np_unref_obj(np_message_t, pqentry->msg);
				np_unref_obj(np_key_t, pqentry->dest_key);

				pthread_mutex_lock(&ng->lock);
				free(ackentry);
				RB_REMOVE(np_jtree, ng->waiting, jrb_ack_node);
				free(pqentry);
				RB_REMOVE(np_jtree, ng->retransmit, pqnode);
				pthread_mutex_unlock(&ng->lock);

			} else {
				log_msg(LOG_DEBUG, "re-sending: failed delivery attempt %u", pqentry->seqnum);
				double transmittime = dtime();

				// prepare a resend later
				np_prioq_t *newentry = get_new_pqentry();
				newentry->dest_key = pqentry->dest_key;
				newentry->msg = pqentry->msg;
				newentry->retry = ++pqentry->retry;
				newentry->seqnum = pqentry->seqnum;
				newentry->transmittime = transmittime;

				pthread_mutex_lock(&ng->lock);
				jrb_insert_dbl(ng->retransmit, (transmittime + RETRANSMIT_INTERVAL), new_jval_v(newentry));
				pthread_mutex_unlock(&ng->lock);

				// try to deliver the message now
				network_send_udp(state, pqentry->dest_key, re_msg);

				pthread_mutex_lock(&ng->lock);
				free(pqentry);
				RB_REMOVE(np_jtree, ng->retransmit, pqnode);
				pthread_mutex_unlock(&ng->lock);
			}

		} else {
			// max retransmission has expired -- update the host stats, free up the resources
			// pthread_mutex_lock(&ng->lock);
			// log_msg(LOG_WARN, "max retries exceeded, dropping message: %u", pqentry->seqnum);
			np_node_update_stat(pqentry->dest_key->node, 0);

			np_unref_obj(np_key_t, pqentry->dest_key);
			// TODO: implement dead letter queue handling ?
			np_unref_obj(np_message_t, pqentry->msg);
			np_free_obj(np_message_t, pqentry->msg);

			pthread_mutex_lock(&ng->lock);
			free(ackentry);
			RB_REMOVE(np_jtree, ng->waiting, jrb_ack_node);
			free(pqentry);
			RB_REMOVE(np_jtree, ng->retransmit, pqnode);
			pthread_mutex_unlock(&ng->lock);
		}

	} else {
		// log_msg(LOG_DEBUG, "message acknowledged, no further retry: %u", pqentry->seqnum);
		// packet is acked;
		// update the host latency and the success measurements
		// and decrease reference counter again
		// pthread_mutex_lock(&ng->lock);
		// log_msg(LOG_DEBUG, "ack found, updating node stats ..., %u", pqentry->seqnum);
		double latency = ackentry->acktime - pqentry->transmittime;
		if (latency > 0) {
			if (pqentry->dest_key->node->latency == 0.0) {
				pqentry->dest_key->node->latency = latency;
			} else {
				// TODO: this is wrong to calculate the average latency
				pqentry->dest_key->node->latency = (0.9
						* pqentry->dest_key->node->latency) + (0.1 * latency);
			}
		}
		np_node_update_stat(pqentry->dest_key->node, 1);

		np_unref_obj(np_key_t, pqentry->dest_key);
		np_unref_obj(np_message_t, pqentry->msg);
		np_free_obj(np_message_t, pqentry->msg);

		pthread_mutex_lock(&ng->lock);
		free(ackentry);
		RB_REMOVE(np_jtree, ng->waiting, jrb_ack_node);
		free(pqentry);
		RB_REMOVE(np_jtree, ng->retransmit, pqnode);
		pthread_mutex_unlock(&ng->lock);
	}

	// submit the function itself for additional execution
	job_submit_event(state->jobq, np_retransmit_messages);
	log_msg(LOG_TRACE, ".end  .np_retransmit_messages");
}

/**
 ** np_network_read:
 ** puts the network layer into listen mode. This thread manages acknowledgements,
 ** delivers incoming messages to the message handlers, and drives the network layer.
 **/
void np_network_read(np_state_t* state, np_jobargs_t* args) {
	log_msg(LOG_TRACE, ".start.np_network_read");

	fd_set fds;
	int8_t ret;
	char data[NETWORK_PACK_SIZE];
	struct sockaddr from;
	socklen_t fromlen = sizeof(from);
	int8_t ack = 0;
	uint32_t seq = 0;

	np_network_t* ng = state->my_key->node->network;

	FD_ZERO(&fds);
	FD_SET(ng->socket, &fds);

	// timeout.tv_usec = 5000;
	ret = select(FD_SETSIZE, &fds, NULL, NULL, NULL);
	if (ret < 0) {
		log_msg(LOG_ERROR, "select: %s", strerror(errno));
		job_submit_event(state->jobq, np_network_read);
		log_msg(LOG_TRACE, ".end  .np_network_read");
		return;
	}

	/* receive the new data */
	int16_t in_msg_len = recvfrom(ng->socket, data, NETWORK_PACK_SIZE, 0, &from, &fromlen);
	if (!in_msg_len) {
		log_msg(LOG_ERROR, "recvfrom failed: %s", strerror(errno));
		job_submit_event(state->jobq, np_network_read);
		log_msg(LOG_TRACE, ".end  .np_network_read");
		return;
	}
	// get calling address and port
	char ipstr[INET6_ADDRSTRLEN];
	int16_t port;

	if (from.sa_family == PF_INET) {
		inet_ntop(from.sa_family, &(((struct sockaddr_in *) &from)->sin_addr),
				ipstr, sizeof ipstr);
		port = ((struct sockaddr_in *) &from)->sin_port;
	} else {
		inet_ntop(from.sa_family, &(((struct sockaddr_in6 *) &from)->sin6_addr),
				ipstr, sizeof ipstr);
		port = ((struct sockaddr_in6 *) &from)->sin6_port;
	}
	void* data_ptr = data;
	log_msg(LOG_DEBUG, "received message from %s:%hd (size: %hd)", ipstr, port, in_msg_len);

	// we registered this token info before in the first handshake message
	np_key_t* alias_key = NULL;
	np_key_t* search_key = key_create_from_hostport(ipstr, port);

	LOCK_CACHE(state)
	{
		if (NULL == (alias_key = SPLAY_FIND(spt_key, &state->key_cache, search_key))) {
			SPLAY_INSERT(spt_key, &state->key_cache, search_key);
			alias_key = search_key;
			np_ref_obj(np_key_t, alias_key);
		} else {
			np_free_obj(np_key_t, search_key);
		}
	}

	if ((NULL != alias_key->authentication)
			&& alias_key->authentication->valid) {
		// log_msg(LOG_DEBUG, "now decrypting to np_message_t (size %hd)", in_msg_len);
		unsigned char nonce[crypto_secretbox_NONCEBYTES];
		unsigned char* dec_msg = (unsigned char*) malloc(
				in_msg_len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);
		memcpy(nonce, data_ptr, crypto_secretbox_NONCEBYTES);

		// log_msg(LOG_DEBUG, "now nonce (%s)", nonce);
		ret = crypto_secretbox_open_easy(dec_msg,
				(const unsigned char *) data_ptr + crypto_secretbox_NONCEBYTES,
				in_msg_len - crypto_secretbox_NONCEBYTES, nonce,
				alias_key->authentication->session_key);

		if (ret != 0) {
			log_msg(LOG_ERROR,
					"incorrect decryption of message (send from %s:%hd)", ipstr, port);
		} else {
			// data_ptr = dec_msg;
			memset(data_ptr, 0, NETWORK_PACK_SIZE);
			memcpy(data_ptr, dec_msg, in_msg_len - crypto_secretbox_NONCEBYTES);
		}
		free(dec_msg);
	}

	np_message_t* msg_in;
	np_new_obj(np_message_t, msg_in);

	ret = np_message_deserialize(msg_in, data_ptr);

	if (0 == ret) {
		log_msg(LOG_ERROR, "error de-serializing message");
		np_free_obj(np_message_t, msg_in);
		job_submit_event(state->jobq, np_network_read);
		log_msg(LOG_TRACE, ".end  .np_network_read");
		return;
	}

	if (0 == msg_in->header->size && 0 == msg_in->instructions->size
			&& 0 == msg_in->properties->size && 0 == msg_in->footer->size) {
		// log_msg(LOG_DEBUG, "identified handshake message ...");

		if ((NULL == alias_key->authentication)
				|| !alias_key->authentication->valid) {
			jrb_insert_str(msg_in->footer, NP_MSG_FOOTER_ALIAS_KEY,
					new_jval_s((char*) key_get_as_string(alias_key)));
			np_msgproperty_t* msg_prop = np_message_get_handler(state, INBOUND, NP_MSG_HANDSHAKE);
			job_submit_msg_event(state->jobq, msg_prop, state->my_key, msg_in);

		} else {
			log_msg(LOG_DEBUG, "... handshake is already complete");
		}

	} else {
		// TODO: stop doing message handling following this line, ack handling may still be fine
		// TODO: hook in policy for accessing the system ? evaluate 'from' field ?

		// read now decrypted header
		char* subject =
				jrb_find_str(msg_in->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
		// char* reply_to = jrb_find_str(msg->header, NP_MSG_HEADER_REPLY_TO)->val.value.s;

		// read neuropil related message instructions
		seq = jrb_find_str(msg_in->instructions, NP_MSG_INST_SEQ)->val.value.ul;
		ack = jrb_find_str(msg_in->instructions, NP_MSG_INST_ACK)->val.value.ush;
		// parts = jrb_find_str(newmsg->instructions, "_np.part")->val.value.i;

		if (0 == strncmp(NP_MSG_ACK, subject, strlen(NP_MSG_ACK))) {
			np_jtree_elem_t *jrb_node;
			/* just an acknowledgement of own messages send out earlier */
			/* TODO: trigger update of node stats ? */
			pthread_mutex_lock(&(ng->lock));
			jrb_node = jrb_find_ulong(ng->waiting, seq);
			if (jrb_node != NULL) {
				np_ackentry_t *entry = (np_ackentry_t *) jrb_node->val.value.v;
				entry->acked = TRUE;
				entry->acktime = dtime();
				log_msg(LOG_DEBUG, "received acknowledgment of seq=%u", seq);
			}
			pthread_mutex_unlock(&(ng->lock));

			np_free_obj(np_message_t, msg_in);
			job_submit_event(state->jobq, np_network_read);

			log_msg(LOG_TRACE, ".end  .np_network_read");
			return;
		}

		log_msg(LOG_DEBUG, "received message for subject: %s (seq=%u, ack=%hhd)",
				subject, seq, ack);

		if (0 < (ack & ACK_EACHHOP)) {
			/* acknowledge part, each hop has to acknowledge the message */
			// TODO: move this ack after a) a message handler has been found or b) the message has been forwarded
			np_key_t* ack_key;
			unsigned char* ack_to = (unsigned char*) jrb_find_str(
					msg_in->instructions, NP_MSG_INST_ACK_TO)->val.value.s;
			search_key = key_create_from_hash(ack_to);

			LOCK_CACHE(state)
			{
				if (NULL == (ack_key = SPLAY_FIND(spt_key, &state->key_cache, search_key))) {
					SPLAY_INSERT(spt_key, &state->key_cache, search_key);
					ack_key = search_key;
					np_ref_obj(np_key_t, ack_key);
				} else {
					np_free_obj(np_key_t, search_key);
				}
			}

			if (TRUE == ack_key->node->joined_network &&
				np_node_check_address_validity(ack_key->node)) {

				np_message_t* ack_msg_out;
				np_new_obj(np_message_t, ack_msg_out);
				np_msgproperty_t* ack_prop = np_message_get_handler(state, OUTBOUND, NP_MSG_ACK);
				np_message_create(ack_msg_out, ack_key, state->my_key, NP_MSG_ACK, NULL);

				/* create network header */
				jrb_insert_str(ack_msg_out->instructions, NP_MSG_INST_ACK, new_jval_ush(ack_prop->ack_mode));
				jrb_insert_str(ack_msg_out->instructions, NP_MSG_INST_SEQ, new_jval_ul(seq));

				log_msg(LOG_DEBUG, "sending back acknowledge for: %s (seq=%u, ack=%hhd)",
						subject, seq, ack);
				// direct acknowledge
				job_submit_msg_event(state->jobq, ack_prop, ack_key, ack_msg_out);
				np_free_obj(np_message_t, ack_msg_out);
				// user space acknowledgement handled later, also for join messages
			}
		}

		/* receive part, plus final delivery ack */
		unsigned char* to =
			(unsigned char*) jrb_find_str(msg_in->header, NP_MSG_HEADER_TO)->val.value.s;

		np_key_t* target_key;
		np_new_obj(np_key_t, target_key);
		str_to_key(target_key, to);

		np_msgproperty_t* prop = np_message_get_handler(state, INBOUND, DEFAULT);
		job_submit_msg_event(state->jobq, prop, target_key, msg_in);
	}

	np_free_obj(np_message_t, msg_in);
	np_free_obj(np_key_t, alias_key);

	// schedule new network read event
	job_submit_event(state->jobq, np_network_read);

	log_msg(LOG_TRACE, ".end  .np_network_read");
}

/**
 ** np_send_rowinfo:
 ** sends matching row of its table to the target node
 **/
void np_send_rowinfo(np_state_t* state, np_jobargs_t* args) {
	log_msg(LOG_TRACE, "start np_send_rowinfo");

	np_message_t* msg_out;
	np_jtree_t* msg_body;
	np_sll_t(np_key_t, sll_of_keys);

	np_key_t* target_key = args->target;
	// check for correct target
	log_msg(LOG_INFO, "job submit route row info to %s:%hd!",
			target_key->node->dns_name, target_key->node->port);

	/* send one row of our routing table back to joiner #host# */
	LOCK_CACHE(state->routes)
	{
		sll_of_keys = route_row_lookup(state, target_key);
	}

	msg_body = make_jtree();
	LOCK_CACHE(state)
	{
		// TODO: maybe locking the cache is not enough and we have to do it more fine grained
		np_encode_nodes_to_jrb(msg_body, sll_of_keys);
	}
	np_msgproperty_t* outprop = np_message_get_handler(state, OUTBOUND, NP_MSG_PIGGY_REQUEST);

	np_new_obj(np_message_t, msg_out);
	np_message_create(msg_out, target_key, state->my_key, NP_MSG_PIGGY_REQUEST, msg_body);
	job_submit_msg_event(state->jobq, outprop, target_key, msg_out);

	sll_free(np_key_t, sll_of_keys);
}

np_aaatoken_t* create_msg_token(np_state_t* state, const char* subject, np_msgproperty_t* msg_request) {
	log_msg(LOG_TRACE, ".start.create_msg_token");

	np_aaatoken_t* msg_token;
	np_new_obj(np_aaatoken_t, msg_token);

	// create token
	strncpy(msg_token->realm, state->my_key->authentication->realm, 255);
	strncpy(msg_token->subject, subject, 255);
	strncpy(msg_token->issuer, (char*) key_get_as_string(state->my_key), 255);
	msg_token->not_before = dtime();
	msg_token->expiration = dtime() + 10.0; // 10 second valid token

	// add e2e encryption details for sender
	unsigned char curve25519_pk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_pk_to_curve25519(curve25519_pk,
										 state->my_key->authentication->public_key);
	strncpy((char*) msg_token->public_key, (const char*) curve25519_pk,
			crypto_scalarmult_curve25519_BYTES);

	jrb_insert_str(msg_token->extensions, "mep_type",
			new_jval_ush(msg_request->mep_type));
	jrb_insert_str(msg_token->extensions, "ack_mode",
			new_jval_ush(msg_request->ack_mode));
	jrb_insert_str(msg_token->extensions, "max_threshold",
			new_jval_ui(msg_request->max_threshold));
	jrb_insert_str(msg_token->extensions, "msg_threshold",
			new_jval_ui(msg_request->msg_threshold));

	log_msg(LOG_TRACE, ".end  .create_msg_token");
	return msg_token;
}

void np_send_msg_interest(np_state_t* state, const char* subject) {
	log_msg(LOG_TRACE, ".start.np_send_msg_interest");

	np_message_t* msg_out;
	np_aaatoken_t* msg_token;

	np_msgproperty_t* msg_request = np_message_get_handler(state, INBOUND, subject);
	np_key_t* target = key_create_from_hostport(subject, 0);

	log_msg(LOG_DEBUG, "encoding and storing interest token");
	// insert into msg token token renewal queue
	msg_token = create_msg_token(state, subject, msg_request);
	jrb_insert_str(state->msg_tokens, subject, new_jval_v(msg_token));
	np_ref_obj(np_aaatoken_t, msg_token);

	// if (msg_request->msg_threshold < msg_request->max_threshold) {
		log_msg(LOG_DEBUG, "encoding and sending interest token");
		// and create a token to send it over the wire
		np_jtree_t* interest_data = make_jtree();
		msg_token = create_msg_token(state, subject, msg_request);
		np_encode_aaatoken(interest_data, msg_token);
		// directly send interest
		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, target, state->my_key, NP_MSG_INTEREST, interest_data);
		np_msgproperty_t* prop_route = np_message_get_handler(state, TRANSFORM, ROUTE_LOOKUP);
		job_submit_msg_event(state->jobq, prop_route, target, msg_out);
	// }
	log_msg(LOG_TRACE, ".end  .np_send_msg_interest");
}

void np_send_msg_availability(np_state_t* state, const char* subject)
{
	log_msg(LOG_TRACE, ".start.np_send_msg_availability");
	np_message_t* msg_out;
	np_aaatoken_t* msg_token;

	np_msgproperty_t* msg_interest = np_message_get_handler(state, OUTBOUND, subject);
	np_key_t* target = key_create_from_hostport(subject, 0);

	log_msg(LOG_DEBUG, "encoding and storing available token");
	msg_token = create_msg_token(state, subject, msg_interest);
	jrb_insert_str(state->msg_tokens, subject, new_jval_v(msg_token));
	np_ref_obj(np_aaatoken_t, msg_token);

	log_msg(LOG_DEBUG, "encoding and sending available token");
	np_jtree_t* available_data = make_jtree();
	msg_token = create_msg_token(state, subject, msg_interest);
	np_encode_aaatoken(available_data, msg_token);
	// create message interest message
	np_new_obj(np_message_t, msg_out);
	np_message_create(msg_out, target, state->my_key, NP_MSG_AVAILABLE, available_data);
	// send message availability
	np_msgproperty_t* prop_route = np_message_get_handler(state, TRANSFORM, ROUTE_LOOKUP);
	job_submit_msg_event(state->jobq, prop_route, target, msg_out);

	log_msg(LOG_TRACE, ".end  .np_send_msg_availability");
}

// TODO: move this to a function which can be scheduled via jobargs
np_bool np_send_msg (np_state_t* state, char* subject, np_message_t* msg, np_msgproperty_t* msg_prop)
{
	np_aaatoken_t* tmp_token = np_get_receiver_token(state, subject);

	if (NULL != tmp_token) {
		// first encrypt the relevant message part itself
		np_message_encrypt_payload(state, msg, tmp_token);

		np_key_t* receiver_key;
		np_new_obj(np_key_t, receiver_key);
		str_to_key(receiver_key, (const unsigned char*) tmp_token->issuer);

		jrb_insert_str(msg->header, NP_MSG_HEADER_TO, new_jval_s(tmp_token->issuer));
		np_msgproperty_t* out_prop = np_message_get_handler(state, TRANSFORM, ROUTE_LOOKUP);
		job_submit_msg_event(state->jobq, out_prop, receiver_key, msg);

		// decrease threshold counters
		msg_prop->msg_threshold--;

		np_unref_obj(np_aaatoken_t, tmp_token);
		np_free_obj(np_aaatoken_t, tmp_token);

		return TRUE;
	} else {

		LOCK_CACHE(msg_prop)
		{
			// cache already full ?
			if (msg_prop->max_threshold <= msg_prop->msg_threshold) {
				log_msg(LOG_DEBUG,
						"msg cache full, checking overflow policy ...");

				if ((msg_prop->cache_policy & OVERFLOW_PURGE) > 0) {
					log_msg(LOG_DEBUG,
							"OVERFLOW_PURGE: discarding first message");
					np_message_t* old_msg = NULL;

					if (0 < (msg_prop->cache_policy & FIFO))
						old_msg = sll_tail(np_message_t, msg_prop->msg_cache);
					if (0 < (msg_prop->cache_policy & FILO))
						old_msg = sll_head(np_message_t, msg_prop->msg_cache);

					msg_prop->msg_threshold--;
					np_unref_obj(np_message_t, old_msg);
					np_free_obj(np_message_t, old_msg);
				}

				if ((msg_prop->cache_policy & OVERFLOW_REJECT) > 0) {
					log_msg(LOG_DEBUG,
							"rejecting new message because cache is full");
					np_free_obj(np_message_t, msg);
					continue;
				}
			}

			if ((msg_prop->cache_policy & FIFO))
				sll_prepend(np_message_t, msg_prop->msg_cache, msg);
			if ((msg_prop->cache_policy & FILO))
				sll_append(np_message_t, msg_prop->msg_cache, msg);

			log_msg(LOG_DEBUG, "added message to the msgcache (%p / %d) ...",
					msg_prop->msg_cache, sll_size(msg_prop->msg_cache));
			np_ref_obj(np_message_t, msg);
		}
	}
	return FALSE;
}
