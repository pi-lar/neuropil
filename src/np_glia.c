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

#include "np_util.h"
#include "aaatoken.h"
#include "route.h"
#include "job_queue.h"
#include "message.h"
#include "network.h"
#include "neuropil.h"
#include "node.h"
#include "dtime.h"
#include "log.h"
#include "jrb.h"
#include "jval.h"
#include "key.h"

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
    np_node_t** tmp;
    np_node_t* targetNode;
    // np_global_t *chglob = (np_global_t *) state->neuropil;

    // first lookup call for target key
	log_msg(LOG_DEBUG, "target is %p key %s", args->target, key_get_as_string(args->target));
    tmp = route_lookup (state->routes, args->target, 1, 0);

    /* this is to avoid sending JOIN request to the node that *
     * its information is already in the routing table        */
	char* msg_subject =
			jrb_find_str(args->msg->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
	char* msg_address =
			jrb_find_str(args->msg->header, NP_MSG_HEADER_TO)->val.value.s;
    int is_join_msg = (strcmp(msg_subject, NP_MSG_JOIN_REQUEST) == 0) ? 1 : 0;

    if ((tmp[0] != NULL) && is_join_msg && (key_equal (tmp[0]->key, args->target)))
	{
	    free (tmp);
	    tmp = route_lookup (state->routes, args->target, 2, 0);
	    if (tmp[1] != NULL && key_equal (tmp[0]->key, args->target))
	    	tmp[0] = tmp[1];
	}

    if (tmp[0] != state->neuropil->me)
	{
    	targetNode = tmp[0];
	}
    if (tmp[0] == state->neuropil->me)
	{
    	targetNode = NULL;
	}
    free (tmp);
    tmp = NULL;

	// const char * msg_subject = pn_message_get_subject(args->msg);

	/* if I am the only host or the closest host is me, deliver the message */
    if (targetNode == NULL)
	{
        log_msg(LOG_DEBUG, "internal routing for %s", msg_subject);
    	/* deliver the message to the correct handler function (if one exists) */
    	np_msgproperty_t* prop = np_message_get_handler(state->messages, INBOUND, msg_subject);

    	int nodes_equal = key_equal(args->target, state->neuropil->me->key);

    	if ( (is_join_msg && !(nodes_equal)) ) {
            /* send the JOIN message to a node, which is not yet available in the network */
    		/* therefore create an outbound message and send it directly via the network layer */
    		prop = np_message_get_handler(state->messages, OUTBOUND, msg_subject);
    		targetNode = np_node_decode_from_str(state->nodes, msg_address);
        	job_submit_msg_event(state->jobq, prop, targetNode->key, args->msg);
    	} else {
        	job_submit_msg_event(state->jobq, prop, state->neuropil->me->key, args->msg);
    	}
	}
    else /* otherwise, route it */
	{
        log_msg(LOG_DEBUG, "external forward routing for %s: %s", msg_subject, key_get_as_string(targetNode->key) );
    	np_msgproperty_t* prop = np_message_get_handler(state->messages, OUTBOUND, msg_subject);
    	job_submit_msg_event(state->jobq, prop, targetNode->key, args->msg);

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
}


/**
 ** np_check_leafset: runs as a separate thread.
 ** it should send a PING message to each member of the leafset frequently and
 ** sends the leafset to other members of its leafset periodically.
 ** pinging frequency is LEAFSET_CHECK_PERIOD.
 **/
void np_check_leafset(np_state_t* state, np_jobargs_t* args) {

	np_node_t **leafset;
	np_node_t **table;
	int i;

	log_msg(LOG_INFO, "leafset check for neighbours started");
	leafset = route_neighbors(state->routes, LEAFSET_SIZE);
	for (i = 0; leafset[i] != NULL ; i++) {
		if (leafset[i]->success_avg < BAD_LINK) {
			// check for bad link nodes
			log_msg(LOG_DEBUG, "Deleting from neighbours: %s", key_get_as_string(leafset[i]->key));
			route_update(state->routes, leafset[i], 0);

			job_submit_event(state->jobq, np_check_leafset);
			return;
		} else {
			/* otherwise request reevaluation of peer */
			/* weired: assume failure of the node now, will be reset with ping reply */
			leafset[i]->failuretime = dtime();
		    np_ping(state, leafset[i]->key);
		}
	}
	free(leafset);

	log_msg(LOG_INFO, "leafset check for table started");
	table = route_get_table(state->routes);
	for (i = 0; table[i] != NULL ; i++) {
		if (table[i]->success_avg < BAD_LINK) {
			/* first check for bad link nodes */
			log_msg(LOG_DEBUG, "Deleting from table: %s", key_get_as_string(table[i]->key));
			route_update(state->routes, table[i], 0);

			job_submit_event(state->jobq, np_check_leafset);
			return;
		} else {
			/* otherwise request re-evaluation of node stats */
			/* weired: assume failure of the node now, will be reset with ping reply */
			table[i]->failuretime = dtime();
			np_ping(state, table[i]->key);
		}
	}
	free(table);

	/* send leafset exchange data every 3 times that pings the leafset */
	if (check_leafset_count == 2) {
		check_leafset_count = 0;

		log_msg(LOG_INFO, "leafset exchange for neighbours started");
		np_global_t *chglob = (np_global_t *) state->neuropil;
		leafset = route_neighbors(state->routes, LEAFSET_SIZE);
		np_jrb_t* leaf_data = make_jrb();
		np_encode_nodes_to_amqp(leaf_data, leafset);

		for (i = 0; leafset[i] != NULL ; i++) {
			np_message_t* msg = np_message_create(state->messages, leafset[i]->key, chglob->me->key, NP_MSG_PIGGY_REQUEST, leaf_data);
			np_msgproperty_t* prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_PIGGY_REQUEST);
			job_submit_msg_event(state->jobq, prop, leafset[i]->key, msg);
		}
		free(leafset);
	} else {
		check_leafset_count++;
	}

	dsleep(LEAFSET_CHECK_PERIOD);
	job_submit_event(state->jobq, np_check_leafset);
}

void np_retransmit_messages(np_state_t* state, np_jobargs_t* args) {

	double now = 0.0;
	double sleeptime = RETRANSMIT_THREAD_SLEEP;

	np_jrb_t *pqnode, *jrb_node;
	PQEntry* pqentry;
	np_networkglobal_t* ng = state->network;

	// wake up, get all the packets to be transmitted by now, send them again or delete them from the priqueue
	pthread_mutex_lock(&ng->lock);
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
		// TODO: calculate the min sleep time
		min_sleep_time = pqnode->key.value.d - now;
		if (min_sleep_time < sleeptime ) sleeptime = min_sleep_time;

		if (pqnode->key.value.d <= now) break;
		pqnode = jrb_next(pqnode);

	} while ( pqnode != jrb_nil(ng->retransmit) );
	pthread_mutex_unlock(&ng->lock);

	// queue was not empty, but time comparison said: no element ready for retransmit
	if (pqnode == jrb_nil(ng->retransmit)) {
		dsleep(sleeptime);
		job_submit_event(state->jobq, np_retransmit_messages);
	 	return;
	}

	// found element to retransmit
	pqentry = (PQEntry *) pqnode->val.value.v;
	// fprintf(stderr, "processing a packet with retransmit time %f; looking for seqnum %d\n", pqnode->key.d, pqentry->seqnum);
	// log_msg(LOG_INFO, "retransmission check for message %i (now: %f / rtt: %f)", pqentry->seqnum, now, pqnode->key.d);

	jrb_node = jrb_find_ulong(ng->waiting, pqentry->seqnum);
	assert(jrb_node!=NULL);
	np_ackentry_t *ackentry = (np_ackentry_t *) jrb_node->val.value.v;

	if (ackentry->acked == 0) // means, if the packet is not yet acknowledged
	{
		log_msg(LOG_INFO, "retransmission check for message %i -> no ack found", pqentry->seqnum);
		//jrb_insert_dbl(tempjrb, pqnode->key.d, new_jval_v(pqentry));-- to try doing send outside the lock block
		double transmittime = dtime();

		if (pqentry->retry <= MAX_RETRY && pqentry->desthost)
		{
			// TODO: replace with general resend mechanism ???
			network_resend(state, pqentry->desthost, pqentry->data,
					pqentry->datasize, 1, pqentry->seqnum, &transmittime);
			pqentry->retry++;

			PQEntry *newentry = get_new_pqentry();
			newentry->desthost = pqentry->desthost;
			newentry->data = pqentry->data;
			newentry->datasize = pqentry->datasize;
			newentry->retry = ++pqentry->retry;
			newentry->seqnum = pqentry->seqnum;
			newentry->transmittime = transmittime;

			pthread_mutex_lock(&ng->lock);
			np_node_update_stat(pqentry->desthost, 0);
			jrb_insert_dbl(ng->retransmit, (transmittime + RETRANSMIT_INTERVAL), new_jval_v(newentry));
			pthread_mutex_unlock(&ng->lock);

		} else {
			// max retransmission has expired -- update the host stats, free up the resources
			log_msg(LOG_WARN, "max retries exceeded, dropping message: %d", pqentry->seqnum);
			np_node_release(state->nodes, pqentry->desthost->key);
			np_message_free(pqentry->data);
			// TODO: implement dead letter queue handling ?
		}

	} else {
		// log_msg(LOG_DEBUG, "message acknowledged, no further retry: %d", pqentry->seqnum);
		// packet is acked;
		// update the host latency and the success measurements
		// and decrease reference counter again
		pthread_mutex_lock(&ng->lock);
		np_node_release(state->nodes, pqentry->desthost->key);
		np_node_update_stat(pqentry->desthost, 1);
		double latency = ackentry->acktime - pqentry->transmittime;
		if (latency > 0) {
			if (pqentry->desthost->latency == 0.0) {
				pqentry->desthost->latency = latency;
			} else {
				pqentry->desthost->latency = (0.9 * pqentry->desthost->latency) + (0.1 * latency);
			}
		}
		free(ackentry);
		np_message_free(pqentry->data);
		jrb_delete_node(jrb_node);
		pthread_mutex_unlock(&ng->lock);
	}

	pthread_mutex_lock(&ng->lock);
	jrb_delete_node(pqnode);
	pthread_mutex_unlock(&ng->lock);
	// submit the function itself for additional execution
	job_submit_event(state->jobq, np_retransmit_messages);
}

/**
 ** network_activate:
 ** NEVER RETURNS. Puts the network layer into listen mode. This thread
 ** manages acknowledgements, delivers incomming messages to the message
 ** handler, and drives the network layer. It should only be called once.
 */
// #define SEND_SIZE NETWORK_PACK_SIZE

void np_network_read(np_state_t* np_state, np_jobargs_t* args) {

	// log_msg(LOG_INFO, "in network_read");

	fd_set fds; // , thisfds;
	int ret;
	char data[NETWORK_PACK_SIZE];
	struct sockaddr from;
	// struct sockaddr from;
	// struct sockaddr_in *from = (sockaddr_in*) malloc(sizeof(sockaddr_in));
	socklen_t fromlen = sizeof (from);
	int ack = 0;
	unsigned long seq = 0;
	np_jrb_t *jrb_node;
	// struct timeval timeout;

	np_state_t *state = (np_state_t *) np_state;
	np_networkglobal_t* ng = state->network;

	FD_ZERO(&fds);
	FD_SET(ng->sock, &fds);

	/* block until information becomes available */
	/* TODO: or timeout occurs */
	// memcpy(&thisfds, &fds, sizeof(fd_set));

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
	// char hn[255];
	// char serv[255];
	int port;

	// TODO use int getpeername(int sockfd, struct sockaddr *addr, int *addrlen); ???

	if (from.sa_family == PF_INET) {
		inet_ntop(from.sa_family, &(((struct sockaddr_in *)&from)->sin_addr), ipstr, sizeof ipstr);
		port = ((struct sockaddr_in *)&from)->sin_port;
	} else {
		inet_ntop(from.sa_family, &(((struct sockaddr_in6 *)&from)->sin6_addr), ipstr, sizeof ipstr);
		port = ((struct sockaddr_in6 *)&from)->sin6_port;
	}
	log_msg(LOG_DEBUG, "received message from %s:%d", ipstr, port);

//	int err = getnameinfo(&from, fromlen, hn, 255, serv, 255, 0);
//	if (err) {
//		log_msg(LOG_WARN, "getnameinfo() failed: %s", strerror(errno));
//	} else {
//		log_msg(LOG_DEBUG, "getnameinfo(): hostname->%s serv->%s", hn, serv);
//	}

	// we registered this token info before in the first handshake message
	np_key_t* alias_key = key_create_from_hostport(ipstr, port);
	np_aaatoken_t* session_token = np_get_authentication_token(state->aaa_cache, alias_key);
	np_message_t* newmsg = NULL;
	void* data_ptr = data;

	if (session_token && session_token->valid) {

		log_msg(LOG_DEBUG, "now decrypting to np_message_t (size %d)", ret);
		unsigned char  nonce[crypto_secretbox_NONCEBYTES];
		unsigned char* dec_msg = (unsigned char*) malloc(in_msg_len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);

		memcpy(nonce, data_ptr, crypto_secretbox_NONCEBYTES);

		log_msg(LOG_DEBUG, "now nonce (%s)", nonce);
		ret = crypto_secretbox_open_easy(
				dec_msg,
				(const unsigned char *) data_ptr + crypto_secretbox_NONCEBYTES,
				in_msg_len - crypto_secretbox_NONCEBYTES,
				nonce,
				session_token->session_key);

		if (ret != 0) {
			log_msg(LOG_ERROR,
					"incorrect decryption of message (send from %s:%d)",
					ipstr, port);
			job_submit_event(state->jobq, np_network_read);
			free (dec_msg);

			return;
		} else {
			data_ptr = dec_msg;
		}
	}

	newmsg = np_message_deserialize(data_ptr);

	if (!newmsg) {
		log_msg(LOG_ERROR, "error deserializing message");
		job_submit_event(state->jobq, np_network_read);
		return;
	}

	if (0 == newmsg->header->size &&
		0 == newmsg->instructions->size &&
		0 == newmsg->properties->size &&
		0 == newmsg->footer->size)
	{
		log_msg(LOG_DEBUG, "identified handshake message ...");
		if (!session_token || !session_token->valid) {
			// handle it in our own handshake callback function
			jrb_insert_str(newmsg->footer, "alias_key", new_jval_s((char*) key_get_as_string(alias_key)));
			np_msgproperty_t* msg_prop = np_message_get_handler(state->messages, INBOUND, NP_MSG_HANDSHAKE);
			job_submit_msg_event(state->jobq, msg_prop, state->neuropil->me->key, newmsg);
		} else {
			// np_message_free(newmsg);
			log_msg(LOG_DEBUG, "... but handshake is already complete");
		}
		// submit new network read event
		job_submit_event(state->jobq, np_network_read);
		return;

	} else {
		// TODO: stop doing message handling following this line, ack handling may still be fine

		// read now decrypted header
		char* subject  = jrb_find_str(newmsg->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
		char* address  = jrb_find_str(newmsg->header, NP_MSG_HEADER_TO)->val.value.s;
		char* reply_to = jrb_find_str(newmsg->header, NP_MSG_HEADER_REPLY_TO)->val.value.s;
		char* from     = jrb_find_str(newmsg->header, NP_MSG_HEADER_FROM)->val.value.s;

		// TODO: hook in policy for accessing the system ? evaluate 'from' field

		// read neuropil related message instructions
		seq = jrb_find_str(newmsg->instructions, "_np.seq")->val.value.ul;
		ack = jrb_find_str(newmsg->instructions, "_np.ack")->val.value.i;
		// parts = jrb_find_str(newmsg->instructions, "_np.part")->val.value.i;

		if (0 == strncmp(NP_MSG_ACK, subject, strlen(NP_MSG_ACK)) )
		{
			/* just an acknowledgement of own messages send out earlier */
			/* TODO: trigger update of node stats ? */
			pthread_mutex_lock(&(ng->lock));
			// log_msg(LOG_DEBUG, "looking up acknowledge for seq=%lu", seq);
			jrb_node = jrb_find_ulong(ng->waiting, seq);
			if (jrb_node != NULL ) {
				np_ackentry_t *entry = (np_ackentry_t *) jrb_node->val.value.v;
				entry->acked = 1;
				entry->acktime = dtime();
				log_msg(LOG_DEBUG, "acknowledged seq=%lu", seq);
			}
			pthread_mutex_unlock(&(ng->lock));
			job_submit_event(state->jobq, np_network_read);

			np_message_free(newmsg);
			return;
		}

		log_msg(LOG_DEBUG, "received message for subject: %s (seq=%ul, ack=%d)", subject, seq, ack );

		if (ack >= 1 && state->joined_network) {
			/* acknowledge part, each hop has to acknowledge the message */
			// TODO: move this ack after a) a message handler has been found or b) the message has been forwarded
			np_msgproperty_t* ack_prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_ACK);
			np_node_t* ack_node = np_node_decode_from_str(state->nodes, reply_to);
			np_message_t* ack_msg = np_message_create(state->messages, ack_node->key, state->neuropil->me->key, NP_MSG_ACK, NULL);

			/* create network header */
			jrb_insert_str(ack_msg->instructions, "_np.ack", new_jval_i(ack_prop->ack_mode));
			jrb_insert_str(ack_msg->instructions, "_np.seq", new_jval_i(seq));

			// direct acknowledge
			if (ack == 1 && state->joined_network && np_node_check_address_validity(ack_node)) {
				job_submit_msg_event(state->jobq, ack_prop, ack_node->key, ack_msg);
			}
			// user space acknowledgement handled later, also for join messages
		}

		/* receive part, plus final delivery ack */
        np_key_t* targetKey = (np_key_t*) malloc(sizeof(np_key_t));
		str_to_key(targetKey, address);
		np_msgproperty_t* prop = np_message_get_handler(state->messages, INBOUND, DEFAULT);
		job_submit_msg_event(state->jobq, prop, targetKey, newmsg);
		// log_msg(LOG_DEBUG, "finally rescheduling new network read event");

		job_submit_event(state->jobq, np_network_read);
	}
}


/**
 ** np_send_rowinfo:
 ** sends matching row of its table to the target node
 **/
void np_send_rowinfo (np_state_t* state, np_jobargs_t* args)
{
	// check for correct target
	np_node_t* targetNode = np_node_lookup(state->nodes, args->target, 0);

    /* send one row of our routing table back to joiner #host# */
    np_node_t** rowinfo = route_row_lookup (state->routes, targetNode->key);

    np_jrb_t* msg_body = make_jrb();
    np_encode_nodes_to_amqp(msg_body, rowinfo);
    np_message_t* msg = np_message_create (state->messages, targetNode->key, state->neuropil->me->key, NP_MSG_PIGGY_REQUEST, msg_body);
    np_msgproperty_t* outprop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_PIGGY_REQUEST);

    job_submit_msg_event(state->jobq, outprop, targetNode->key, msg);
    log_msg(LOG_INFO, "job submit route row info to %s:%d!", targetNode->dns_name, targetNode->port);


    free (rowinfo);
}


void np_send_msg_interest(const np_state_t* state, np_msginterest_t* interest) {

	np_jrb_t* interest_data = make_jrb();
	np_message_encode_interest(interest_data, interest);
	// TODO: use the seqnum as the port to create always changing node responsibility ?
	np_key_t* target = key_create_from_hostport(interest->msg_subject, 0);
	np_message_t* new_msg = np_message_create(state->messages, target, state->neuropil->me->key, NP_MSG_INTEREST, interest_data);
	// send interest
	np_msgproperty_t* prop_route = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
	job_submit_msg_event(state->jobq, prop_route, target, new_msg);
}

void np_send_msg_availability(const np_state_t* state, np_msginterest_t* available) {

	np_jrb_t* available_data = make_jrb();
	np_message_encode_interest(available_data, available);
	// create message interest message
	np_key_t* target = key_create_from_hostport(available->msg_subject, 0);
	np_message_t* new_msg = np_message_create(state->messages, target, state->neuropil->me->key, NP_MSG_AVAILABLE, available_data);
	// send message availability
	np_msgproperty_t* prop_route = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
	job_submit_msg_event(state->jobq, prop_route, target, new_msg);
}


