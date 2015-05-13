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

	np_node_t* target_node = np_node_lookup(state->nodes, args->target, 0);
	int ret = network_send_udp(state, target_node, args->msg);
	if (ret == 0) {
		np_node_update_stat(target_node, 0);
	} else {
		np_node_update_stat(target_node, 1);
	}
	return;
}

/**
 ** network_send: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void hnd_msg_out_send(np_state_t* state, np_jobargs_t* args) {

	unsigned long seq;
	np_message_t* msg;
	np_node_t* target_node;
	np_jrb_t *jrb_node;
	np_jrb_t *priqueue;

	np_bind(np_message_t, args->msg, msg);

	double start;
	int parts = 1;

	np_msgproperty_t* prop = args->properties;
	np_networkglobal_t* network = state->network;

	// TODO: check if the node is really useful.
	// for now: assume a node really exists and is not only a "key"
	if (prop->ack_mode != 1 && prop->ack_mode != 2) {
		log_msg(LOG_ERROR, "FAILED, unexpected message ack property %i !", prop->ack_mode);
		np_unbind(np_message_t, args->msg, msg);
		return;
	}

	pthread_mutex_lock(&(network->lock));

	/* TODO needs to be fixed to modplus */
	/* create network header */
	if (!jrb_find_str(msg->instructions, "_np.ack"))
		jrb_insert_str(msg->instructions, "_np.ack", new_jval_ui(prop->ack_mode));

	/* get sequence number to initialize acknowledgement indicator*/
	if (!jrb_find_str(msg->instructions, "_np.seq")) {
		seq = network->seqend;
		jrb_insert_str(msg->instructions, "_np.seq", new_jval_ul(seq));
		network->seqend++;
	} else {
		seq = jrb_find_str(msg->instructions, "_np.seq")->val.value.ul;
	}

	if (!jrb_find_str(msg->instructions, "_np.resend_count"))
		jrb_insert_str(msg->instructions, "_np.resend_count", new_jval_ui(0));

	if (prop->ack_mode > 0) {
		np_ackentry_t *ackentry = get_new_ackentry();
		jrb_node = jrb_insert_ulong(network->waiting, seq, new_jval_v(ackentry));
		target_node = np_node_lookup(state->nodes, args->target, 1);
	} else {
		target_node = np_node_lookup(state->nodes, args->target, 0);
	}
	pthread_mutex_unlock(&(network->lock));

	// message part split-up informations
	if (!jrb_find_str(msg->instructions, "_np.part"))
		jrb_insert_str(msg->instructions, "_np.part", new_jval_ui(parts));
	// jrb_insert_str(args->msg->instructions, "_np.pseq", new_jval_i(parts));

	start = dtime();
	if (prop->ack_mode > 0) {
		// insert a record into the priority queue with the following information:
		// key: starttime + next retransmit time
		// other info: destination host, seq num, data, data size
		np_jrb_t* jrb_resend = jrb_find_str(msg->instructions, "_np.resend_count");

		PQEntry *pqrecord = get_new_pqentry();
		pqrecord->dest_key = target_node->key;
		pqrecord->msg = args->msg;
		// pqrecord->datasize = sizebackup;
		pqrecord->retry = jrb_resend->val.value.i;
		pqrecord->seqnum = seq;
		pqrecord->transmittime = start;

		if (pqrecord->retry == 0) {
			np_ref(np_message_t, args->msg);
		}

		pthread_mutex_lock(&network->lock);
		priqueue = jrb_insert_dbl(network->retransmit,
				(start + RETRANSMIT_INTERVAL), new_jval_v(pqrecord));
		pthread_mutex_unlock(&network->lock);
	}

	int ret = network_send_udp(state, target_node, args->msg);
	if (ret == 0) {
		np_node_update_stat(target_node, 0);
	} else {
		np_node_update_stat(target_node, 1);
	}
	np_unbind(np_message_t, args->msg, msg);
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

	// create handshake data
	np_jrb_t* hs_data = make_jrb();

	jrb_insert_str(hs_data, "_np.dns_name", new_jval_s(state->neuropil->me->dns_name));
	jrb_insert_str(hs_data, "_np.port", new_jval_ui(state->neuropil->me->port));
	jrb_insert_str(hs_data, "_np.signature_key", new_jval_bin(my_id_token->public_key, crypto_sign_PUBLICKEYBYTES));
	jrb_insert_str(hs_data, "_np.public_key", new_jval_bin(my_dh_pubkey, crypto_scalarmult_BYTES));
	jrb_insert_str(hs_data, "_np.expiration", new_jval_d(my_id_token->expiration));
	jrb_insert_str(hs_data, "_np.issued_at", new_jval_d(my_id_token->issued_at));

	// pre-serialize handshake data
	cmp_ctx_t cmp;
    unsigned char hs_payload[NP_MESSAGE_SIZE];
    void* hs_buf_ptr = hs_payload;

    cmp_init(&cmp, hs_buf_ptr, buffer_reader, buffer_writer);
	serialize_jrb_node_t(hs_data, &cmp);
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
	np_obj_t* hs_msg_obj;
	np_message_t*  hs_message;
	np_new(np_message_t, hs_msg_obj);
	np_bind(np_message_t, hs_msg_obj, hs_message);

	// ... add signature and payload to this message
	jrb_insert_str(hs_message->body, "_np.signature", new_jval_bin(signature, signature_len));
	jrb_insert_str(hs_message->body, "_np.payload", new_jval_bin(hs_payload, hs_payload_len));
	// log_msg(LOG_DEBUG, "payload has length %d, signature length %d", hs_payload_len, signature_len);

	// serialize complete encrypted message
	unsigned long msg_size = 0;
    char hs_msg[NP_MESSAGE_SIZE];
    void* hs_msg_ptr = hs_msg;
	ret = np_message_serialize(hs_message, hs_msg_ptr, &msg_size);
	// log_msg(LOG_DEBUG, "serialized handshake message (%p) msg_size %d", hs_msg_ptr, msg_size);

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
	np_unbind(np_message_t, hs_msg_obj, hs_message);
	np_unref(np_message_t, hs_msg_obj);
}


