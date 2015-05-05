#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "np_axon.h"

#include "np_util.h"
#include "aaatoken.h"
#include "include.h"
#include "sodium.h"
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
	char send_buffer[NETWORK_PACK_SIZE];
	void* send_buf_ptr = send_buffer;
	unsigned long send_buf_len = 0;

	np_networkglobal_t* network = state->network;

	// TODO: check if the node is really useful.
	// for now: assume a node really exists and is not only a "key"
	np_node_t* targetNode = np_node_lookup(state->nodes, args->target, 0);

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = targetNode->address;
	to.sin_port = htons ((short) targetNode->port);

	np_message_serialize(args->msg, send_buf_ptr, &send_buf_len);
	assert(send_buf_len <= NETWORK_PACK_SIZE);

	// TODO: send ack in np_message_t format
	log_msg(LOG_NETWORKDEBUG, "sending ack back to %s:%d",
			targetNode->dns_name, targetNode->port);
	int ret = sendto(network->sock, send_buffer, size, 0, (struct sockaddr *) &to,
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
	unsigned long seq, seqnumbackup;
	int sizebackup;

	np_jrb_t *jrb_node;
	np_jrb_t *priqueue;
	double start;

	int parts = 1;

	np_msgproperty_t* prop = args->properties;
	np_networkglobal_t* network = state->network;

	np_node_t* target_node = np_node_lookup(state->nodes, args->target, 1);

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
	jrb_insert_str(args->msg->instructions, "_np.ack", new_jval_i(prop->ack_mode));
	jrb_insert_str(args->msg->instructions, "_np.seq", new_jval_ul(seq));
	jrb_insert_str(args->msg->instructions, "_np.part", new_jval_i(parts));

	//
	// TODO: lookup sending node and shared key to decrypt level 1 of security
	//
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

	np_aaatoken_t* target_token = np_get_authentication_token(state->aaa_cache, target_node->key);
	// np_aaatoken_t* my_token = np_get_authentication_token(state->aaa_cache, state->neuropil->me->key);

	// check for crypto handshake
	if (!target_token || !target_token->valid) {
		// send out our own handshake data
		log_msg(LOG_DEBUG, "requesting initial handshake with %s:%i", target_node->dns_name, target_node->port);
		np_msgproperty_t* msg_prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_HANDSHAKE);
		job_submit_msg_event(state->jobq, msg_prop, args->target, NULL);
		return;
	}

	log_msg(LOG_DEBUG, "now serializing final message ...");
	int max_buffer_len = NETWORK_PACK_SIZE - crypto_secretbox_MACBYTES - crypto_secretbox_NONCEBYTES;
	unsigned long send_buf_len;
	unsigned char send_buffer[max_buffer_len];
	void* send_buffer_ptr = send_buffer;

	np_message_serialize(args->msg, send_buffer_ptr, &send_buf_len);
	assert(send_buf_len <= max_buffer_len);

	// add protection from replay attacks ...
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, sizeof(nonce));

	int enc_msg_len = send_buf_len + crypto_secretbox_MACBYTES;
	unsigned char enc_msg[enc_msg_len];
	int ret = crypto_secretbox_easy(enc_msg,
			(const unsigned char*) send_buffer,
			send_buf_len,
			nonce,
			target_token->session_key);
	if (ret != 0)
	{
		log_msg(LOG_WARN,
				"incorrect encryption of message (not sending to %s:%d)",
				target_node->dns_name, target_node->port);
		return;
	}

	int enc_buffer_len = enc_msg_len + crypto_secretbox_NONCEBYTES;
	char enc_buffer[enc_buffer_len];
	memcpy(enc_buffer, nonce, crypto_secretbox_NONCEBYTES);
	memcpy(enc_buffer + crypto_secretbox_NONCEBYTES, enc_msg, enc_msg_len);

	/* send data */
	log_msg(LOG_NETWORKDEBUG, "sending message seq=%lu ack=%i to %s:%i",
			seq, prop->ack_mode, target_node->dns_name, target_node->port);
	pthread_mutex_lock(&network->lock);
	ret = sendto(network->sock, enc_buffer, enc_buffer_len, 0, (struct sockaddr *) &to, sizeof(to));
	if (ret < 0) {
		log_msg(LOG_ERROR, "sendto error: %s", strerror (errno));
		// np_node_update_stat(targetNode, 0);
		// TODO: add a statement to reroute the message on failure
	}
	pthread_mutex_unlock(&network->lock);
}

void hnd_msg_out_handshake(np_state_t* state, np_jobargs_t* args) {
	// log_msg(LOG_DEBUG, "starting to send handshake message");

	// get our identity from the cache
	np_aaatoken_t* my_id_token = np_get_authentication_token(state->aaa_cache, state->neuropil->me->key);

	// convert to curve key
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_id_token->private_key);
	// calculate public key for dh key exchange
	unsigned char my_dh_pubkey[crypto_scalarmult_BYTES];
	crypto_scalarmult_base(my_dh_pubkey, curve25519_sk);

	// convert to curve key
	// unsigned char curve25519_pk[crypto_scalarmult_curve25519_BYTES];
	// crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_id_token->private_key);
	// crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, my_id_token->public_key);
	// crypto_sign_PUBLICKEYBYTES;

	// create handshake data
	np_jrb_t* hs_data = make_jrb();

	jrb_insert_str(hs_data, "dns_name", new_jval_s(state->neuropil->me->dns_name));
	jrb_insert_str(hs_data, "port", new_jval_ui(state->neuropil->me->port));
	jrb_insert_str(hs_data, "signature_key", new_jval_bin(my_id_token->public_key, crypto_sign_PUBLICKEYBYTES));
	jrb_insert_str(hs_data, "public_key", new_jval_bin(my_dh_pubkey, crypto_scalarmult_BYTES));
	jrb_insert_str(hs_data, "expiration", new_jval_d(my_id_token->expiration));
	jrb_insert_str(hs_data, "issued_at", new_jval_d(my_id_token->issued_at));

	// pre-serialize handshake data
	cmp_ctx_t cmp;
    unsigned char hs_payload[NP_MESSAGE_SIZE];
    void* hs_buf_ptr = hs_payload;

    cmp_init(&cmp, hs_buf_ptr, buffer_reader, buffer_writer);
	np_jrb_t* iter_node;

	if (!cmp_write_map(&cmp, hs_data->size*2 )) log_msg(LOG_WARN, cmp_strerror(&cmp));
	jrb_traverse(iter_node, hs_data) {
		serialize_jrb_node_t(iter_node, &cmp);
	}
	int hs_payload_len = cmp.buf-hs_buf_ptr;

	// sign the handshake payload with our private key
	char signature[crypto_sign_BYTES];
	unsigned long long signature_len;
	int ret = crypto_sign_detached((unsigned char*)       signature, &signature_len,
							       (const unsigned char*) hs_payload, hs_payload_len,
								   my_id_token->private_key);
	if (ret < 0) {
		log_msg(LOG_WARN, "checksum creation failed, not continuing with handshake");
		return;
	}

	// create real handshake message ...
	np_message_t* hs_message = np_message_create_empty();

	// ... add signature and payload to this message
	jrb_insert_str(hs_message->body, "signature", new_jval_bin(signature, signature_len));
	jrb_insert_str(hs_message->body, "payload", new_jval_bin(hs_payload, hs_payload_len));
	log_msg(LOG_DEBUG, "payload has length %d, signature length %d", hs_payload_len, signature_len);

	// serialize complete encrypted message
	unsigned long msg_size = 0;
    char hs_msg[NP_MESSAGE_SIZE];
    void* hs_msg_ptr = hs_msg;
	ret = np_message_serialize(hs_message, hs_msg_ptr, &msg_size);
	log_msg(LOG_DEBUG, "serialized handshake message (%p) msg_size %d", hs_msg_ptr, msg_size);

	// construct target address and send it out
	np_node_t* hs_node = np_node_lookup(state->nodes, args->target, 0);
	struct sockaddr_in to;
	memset(&to, 0, sizeof(to));

	pthread_mutex_lock(&(state->network->lock));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = hs_node->address;
	to.sin_port = htons ((short) hs_node->port);

	/* send data */
	log_msg(LOG_NETWORKDEBUG,
			"sending handshake message (length: %d) to (%s:%d)",
			msg_size, hs_node->dns_name, hs_node->port);
	ret = sendto(state->network->sock, hs_msg_ptr, msg_size, 0, (struct sockaddr *) &to, sizeof(to));
	if (ret < 0) {
		log_msg(LOG_ERROR, "handshake error: %s", strerror (errno));
		// nothing more to be done
	}
	pthread_mutex_unlock(&state->network->lock);
	// log_msg(LOG_DEBUG, "finished to send handshake message");
	jrb_free_tree(hs_data);
}


