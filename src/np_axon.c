#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "sodium.h"

#include "np_axon.h"

#include "aaatoken.h"
#include "dtime.h"
#include "include.h"
#include "job_queue.h"
#include "jrb.h"
#include "log.h"
#include "network.h"
#include "neuropil.h"
#include "node.h"
#include "np_util.h"
#include "np_threads.h"
#include "message.h"
#include "route.h"

// #define SEND_SIZE NETWORK_PACK_SIZE

/**
 ** network_send: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void hnd_msg_out_ack(np_state_t* state, np_jobargs_t* args) {

	np_message_t* msg;
	np_obj_t* o_target_node;
	np_node_t* target_node;

	LOCK_CACHE(state->nodes) {
		o_target_node = np_node_lookup(state->nodes, args->target, 0);
		np_bind(np_node_t, o_target_node, target_node);
	}
	np_bind(np_message_t, args->msg, msg);

	int ret = network_send_udp(state, target_node, msg);
	// ret is 1 or 0
	// np_node_update_stat(target_node, ret);

	np_unbind(np_message_t, args->msg, msg);
	np_free(np_message_t, args->msg);

	np_unbind(np_node_t, o_target_node, target_node);
}

/**
 ** network_send: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void hnd_msg_out_send(np_state_t* state, np_jobargs_t* args) {

	uint32_t seq;
	np_message_t* msg_out;

	np_obj_t*  o_target_node;
	np_node_t* target_node;

	np_jrb_t *jrb_node;
	np_jrb_t *priqueue;

	np_bind(np_message_t, args->msg, msg_out);

	double start;
	int parts = 1;
	int ack_to_is_me = 0;

	np_msgproperty_t* prop = args->properties;
	np_networkglobal_t* network = state->network;

	// TODO: check if the node is really useful.
	// for now: assume a node really exists and is not only a "key"
//	if (prop->ack_mode != ACK_EACHHOP && prop->ack_mode != ACK_DESTINATION) {
//		log_msg(LOG_ERROR, "FAILED, unexpected message ack property %i !", prop->ack_mode);
//		np_unbind(np_message_t, args->msg, msg_out);
//		np_free(np_message_t, args->msg);
//		return;
//	}
	pthread_mutex_lock(&(network->lock));

	/* create network header */
	unsigned char* ack_to_str = key_get_as_string(state->routes->me);
	if (prop->ack_mode == ACK_EACHHOP) {
		// we have to reset the existing ack_to field in case of forwarding
		np_jrb_t* jrb_node = jrb_find_str(msg_out->instructions, "_np.ack_to");
		if (jrb_node) jrb_delete_node(jrb_node);
		jrb_insert_str(msg_out->instructions, "_np.ack_to", new_jval_s((char*) ack_to_str));
		ack_to_is_me = 1;
	}
	if (prop->ack_mode == ACK_DESTINATION || prop->ack_mode == ACK_CLIENT) {
		// only set these two ack values if not yet set !
		if (NULL == jrb_find_str(msg_out->instructions, "_np.ack_to")) {
			jrb_insert_str(msg_out->instructions, "_np.ack_to", new_jval_s((char*) ack_to_str));
			ack_to_is_me = 1;
		} else {
			ack_to_is_me = 0;
		}
	}
	// if not yet present set the ack mode
	if (NULL == jrb_find_str(msg_out->instructions, "_np.ack"))
		jrb_insert_str(msg_out->instructions, "_np.ack", new_jval_ui(prop->ack_mode));

	/* get/set sequence number to initialize acknowledgement indicator correctly */
	np_jrb_t* jrb_seq = jrb_find_str(msg_out->instructions, "_np.seq");
	if (ack_to_is_me) {
		if (jrb_seq) jrb_delete_node(jrb_seq);
		seq = network->seqend;
		jrb_insert_str(msg_out->instructions, "_np.seq", new_jval_ul(seq));
		network->seqend++;
	} else {
		jrb_insert_str(msg_out->instructions, "_np.seq", new_jval_ul(0));
		// seq = jrb_find_str(msg_out->instructions, "_np.seq")->val.value.ul;
	}

	if (NULL == jrb_find_str(msg_out->instructions, "_np.resend_count"))
		jrb_insert_str(msg_out->instructions, "_np.resend_count", new_jval_ui(0));

	if (ack_to_is_me) {
		np_ackentry_t *ackentry = get_new_ackentry();
		jrb_node = jrb_insert_ulong(network->waiting, seq, new_jval_v(ackentry));
	}
	pthread_mutex_unlock(&(network->lock));

	LOCK_CACHE(state->nodes) {
		o_target_node = np_node_lookup(state->nodes, args->target, 0);
		np_bind(np_node_t, o_target_node, target_node);
	}

	// message part split-up informations
	if (NULL == jrb_find_str(msg_out->instructions, "_np.part"))
		jrb_insert_str(msg_out->instructions, "_np.part", new_jval_ui(parts));

	start = dtime();
	if (ack_to_is_me) {
		// insert a record into the priority queue with the following information:
		// key: starttime + next retransmit time
		// other info: destination host, seq num, data, data size
		// np_jrb_t* jrb_resend = jrb_find_str(msg_out->instructions, "_np.resend_count");

		PQEntry *pqrecord = get_new_pqentry();
		pqrecord->dest_key = target_node->key;
		pqrecord->msg = args->msg;
		pqrecord->retry = 0; // jrb_resend->val.value.ui;
		pqrecord->seqnum = seq;
		pqrecord->transmittime = start;

		pthread_mutex_lock(&network->lock);
		np_ref(np_message_t, args->msg);
		np_ref(np_node_t, o_target_node);
		priqueue = jrb_insert_dbl(network->retransmit,
								 (start + RETRANSMIT_INTERVAL), new_jval_v(pqrecord));
		pthread_mutex_unlock(&network->lock);
	}

	char* subj = jrb_find_str(msg_out->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
	log_msg(LOG_DEBUG, "message %s (%d) to %s", subj, seq, key_get_as_string(target_node->key));

	int ret = network_send_udp(state, target_node, msg_out);
	// ret is 1 or 0
	// np_node_update_stat(target_node, ret);

	np_unbind(np_node_t, o_target_node, target_node);

	np_unbind(np_message_t, args->msg, msg_out);
	np_free(np_message_t, args->msg);
}

void hnd_msg_out_handshake(np_state_t* state, np_jobargs_t* args) {

	// log_msg(LOG_DEBUG, "starting to send handshake message");
	np_node_t* me;
	np_bind(np_node_t, state->neuropil->me, me);

	// get our identity from the cache
	np_obj_t* o_my_id_token;
	np_aaatoken_t* my_id_token;

	LOCK_CACHE(state->aaa_cache) {
		o_my_id_token = np_get_authentication_token(state->aaa_cache, me->key);
		np_bind(np_aaatoken_t, o_my_id_token, my_id_token);
	}
	// convert to curve key
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_id_token->private_key);
	// calculate public key for dh key exchange
	unsigned char my_dh_pubkey[crypto_scalarmult_BYTES];
	crypto_scalarmult_base(my_dh_pubkey, curve25519_sk);

	// create handshake data
	np_jrb_t* hs_data = make_jrb();

	jrb_insert_str(hs_data, "_np.dns_name", new_jval_s(me->dns_name));
	jrb_insert_str(hs_data, "_np.port", new_jval_ui(me->port));
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
		np_unbind(np_aaatoken_t, o_my_id_token, my_id_token);
		np_unbind(np_node_t, state->neuropil->me, me);
		return;
	}

	np_unbind(np_aaatoken_t, o_my_id_token, my_id_token);
	np_unbind(np_node_t, state->neuropil->me, me);

	// create real handshake message ...
	np_obj_t* hs_msg_obj;
	np_message_t* hs_message;

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
	np_node_t* hs_node;
	np_obj_t* o_hs_node;
	LOCK_CACHE(state->nodes) {
		o_hs_node = np_node_lookup(state->nodes, args->target, 0);
		np_bind(np_node_t, o_hs_node, hs_node);
	}

	struct sockaddr_in to;
	memset(&to, 0, sizeof(to));

	pthread_mutex_lock(&(state->network->lock));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = hs_node->address;
	to.sin_port = htons ((short) hs_node->port);

	/* send data if handshake status is still just initialized or less */
// 	if (hs_node->handshake_status <= HANDSHAKE_INITIALIZED) {
		log_msg(LOG_NETWORKDEBUG,
				"sending handshake message (length: %d) to (%s:%d)",
				msg_size, hs_node->dns_name, hs_node->port);
		ret = sendto(state->network->sock, hs_msg_ptr, msg_size, 0, (struct sockaddr *) &to, sizeof(to));
		if (ret < 0) {
			log_msg(LOG_ERROR, "handshake error: %s", strerror (errno));
			// nothing more to be done
		}
// 	} else {
// 		log_msg(LOG_NETWORKDEBUG,
// 				"sending handshake message stopped, already completed (%s:%d)",
// 				hs_node->dns_name, hs_node->port);
// 	}

	pthread_mutex_unlock(&state->network->lock);
	// log_msg(LOG_DEBUG, "finished to send handshake message");
	np_unbind(np_node_t, o_hs_node, hs_node);

	np_unbind(np_message_t, hs_msg_obj, hs_message);
	np_free(np_message_t, hs_msg_obj);

	jrb_free_tree(hs_data);
}


