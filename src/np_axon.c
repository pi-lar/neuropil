#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "np_axon.h"

#include "route.h"
#include "job_queue.h"
#include "message.h"
#include "network.h"
#include "neuropil.h"
#include "node.h"
#include "jrb.h"
#include "dtime.h"
#include "log.h"

// #define SEND_SIZE NETWORK_PACK_SIZE

/**
 ** network_send: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void hnd_msg_out_ack(np_state_t* state, np_jobargs_t* args) {

	size_t size = NETWORK_PACK_SIZE;
	struct sockaddr_in to;
	char s[NETWORK_PACK_SIZE];

	np_msgproperty_t* prop = args->properties;
	np_networkglobal_t* network = state->network;

	// TODO: check if teh node is really useful.
	// for now: assume a node really exists and is not only a "key"
	np_node_t* targetNode = np_node_lookup(state->nodes, args->target, 0);

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = targetNode->address;
	to.sin_port = htons ((short) targetNode->port);

	int err = pn_message_encode(args->msg, s, &size);
	assert(err != PN_OVERFLOW);
	assert(pn_message_errno(args->msg) == 0);
	assert(size<NETWORK_PACK_SIZE);

	if (size > NETWORK_PACK_SIZE) {
		log_msg(LOG_ERROR, "cannot send data over %lu bytes!",
				NETWORK_PACK_SIZE);
		return;
	}
	// TODO: send ack in pn_message_t format
	log_msg(LOG_NETWORKDEBUG, "sending ack back to %s:%d",
			targetNode->dns_name, targetNode->port);
	int ret = sendto(network->sock, s, size, 0, (struct sockaddr *) &to,
			sizeof(to));
	// log_msg(LOG_NETWORKDEBUG, "sent ack message: %s", &s);

	if (ret < 0) {
		log_msg(LOG_ERROR, "sendto: %s", strerror (errno));
		// np_node_update_stat(targetNode, 0);
		return;
	}
	return;
}

/**
 ** network_send: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void hnd_msg_out_send(np_state_t* state, np_jobargs_t* args) {

	size_t size = NETWORK_PACK_SIZE;
	struct sockaddr_in to;
	int ret, retval;
	unsigned long seq, seqnumbackup;
	int sizebackup;
	char s[NETWORK_PACK_SIZE];
	np_jrb_t *jrb_node;
	np_jrb_t *priqueue;
	double start;

	np_msgproperty_t* prop = args->properties;
	np_networkglobal_t* network = state->network;
	np_node_t* target_node = NULL;

	// TODO: check if the node is really useful.
	// for now: assume a node really exists and is not only a "key"
	if (prop->ack_mode != 1 && prop->ack_mode != 2) {
		log_msg(LOG_ERROR, "FAILED, unexpected message ack property %i !", prop->ack_mode);
		return;
	}

	pthread_mutex_lock(&(network->lock));


	/* get sequence number and initialize acknowledgement indicator*/
	if (prop->ack_mode > 0) {
		np_ackentry_t *ackentry = get_new_ackentry();
		jrb_node = jrb_insert_ulong(network->waiting, network->seqend, new_jval_v(ackentry));
		target_node = np_node_lookup(state->nodes, args->target, 1);
	} else {
		target_node = np_node_lookup(state->nodes, args->target, 0);
	}
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = target_node->address;
	to.sin_port = htons ((short) target_node->port);

	sizebackup = size;
	seqnumbackup = network->seqend;
	seq = network->seqend;
	network->seqend++; /* needs to be fixed to modplus */

	pthread_mutex_unlock(&(network->lock));

	/* create network header */
	pn_data_t* instructions = pn_message_instructions(args->msg);
	// pn_data_fill(instructions, "LL", prop->ack_mode, seq);
	pn_data_put_map(instructions);
	pn_data_enter(instructions);
	pn_data_put_symbol(instructions, pn_bytes(8, "_np.ack"));
	pn_data_put_int(instructions, prop->ack_mode);
	pn_data_put_symbol(instructions, pn_bytes(8, "_np.seq"));
	pn_data_put_ulong(instructions, seq);
	pn_data_exit(instructions);

	size_t size_backup = size;
	int err = pn_message_encode(args->msg, s, &size);
	assert(err != PN_OVERFLOW);
	assert(pn_message_errno(args->msg) == 0);
	assert(size<NETWORK_PACK_SIZE);

	if (size > NETWORK_PACK_SIZE) {
		log_msg(LOG_ERROR, "cannot send data over %lu bytes!", NETWORK_PACK_SIZE);
		return;
	}

	start = dtime();
	if (prop->ack_mode > 0) {
		// insert a record into the priority queue with the following information:
		// key: starttime + next retransmit time
		// other info: destination host, seq num, data, data size
		PQEntry *pqrecord = get_new_pqentry();
		pqrecord->desthost = target_node;
		pqrecord->data = args->msg;
		pqrecord->datasize = sizebackup;
		pqrecord->retry = 0;
		pqrecord->seqnum = seqnumbackup;
		pqrecord->transmittime = start;

		pthread_mutex_lock(&network->lock);
		priqueue = jrb_insert_dbl(network->retransmit,
				(start + RETRANSMIT_INTERVAL), new_jval_v(pqrecord));
		pthread_mutex_unlock(&network->lock);
	}

	/* send data */
	log_msg(LOG_NETWORKDEBUG, "sending message seq=%lu ack=%i to %s:%i",
			seq, prop->ack_mode, target_node->dns_name, target_node->port);
	pthread_mutex_lock(&network->lock);
	ret = sendto(network->sock, s, size, 0, (struct sockaddr *) &to, sizeof(to));
	if (ret < 0) {
		log_msg(LOG_ERROR, "sendto error: %s", strerror (errno));
		// np_node_update_stat(targetNode, 0);
		// TODO: add a statement to reroute the message on failure
	}
	pthread_mutex_unlock(&network->lock);
}

