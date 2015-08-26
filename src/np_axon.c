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

#include "dtime.h"
#include "include.h"
#include "log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_jobqueue.h"
#include "np_jtree.h"
#include "np_message.h"
#include "np_memory.h"
#include "np_network.h"
#include "np_node.h"
#include "np_util.h"
#include "np_threads.h"
#include "np_route.h"

/**
 ** network_send: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void hnd_msg_out_ack(np_state_t* state, np_jobargs_t* args) {

	network_send_udp(state, args->target, args->msg);
	// ret is 1 or 0
	// np_node_update_stat(target_node, ret);
	np_free_obj(np_message_t, args->msg);
}

/**
 ** network_send: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void hnd_msg_out_send(np_state_t* state, np_jobargs_t* args) {

	log_msg(LOG_TRACE, "hnd_msg_out_send starting ...");

	uint32_t seq = 0;
	np_message_t* msg_out = args->msg;

	// np_jtree_elem_t *jrb_node;
	// np_jtree_t *priqueue;

	double start;
	uint16_t parts = 1;
	np_bool ack_to_is_me = FALSE;
	uint8_t ack_mode = ACK_NONE;

	np_msgproperty_t* prop = args->properties;
	np_network_t* network = state->my_key->node->network;

	// TODO: check if the node is really useful.
	// for now: assume a node really exists and is not only a "key"
//	if (prop->ack_mode != ACK_EACHHOP && prop->ack_mode != ACK_DESTINATION) {
//		log_msg(LOG_ERROR, "FAILED, unexpected message ack property %i !", prop->ack_mode);
//		np_unbind(np_message_t, args->msg, msg_out);
//		np_free(np_message_t, args->msg);
//		return;
//	}

	/* create network header */
	pthread_mutex_lock(&(network->lock));

	// find correct ack_mode, inspect message first because of forwarding
	if (NULL == jrb_find_str(msg_out->instructions, NP_MSG_INST_ACK)) {
		ack_mode = prop->ack_mode;
	} else {
		ack_mode = jrb_find_str(msg_out->instructions, NP_MSG_INST_ACK)->val.value.ush;
	}
	// if not yet present set the ack mode
	if (NULL != prop)
		jrb_insert_str(msg_out->instructions, NP_MSG_INST_ACK, new_jval_ush(prop->ack_mode));

	unsigned char* ack_to_str = key_get_as_string(state->my_key);
	if ( 0 < (ack_mode & ACK_EACHHOP) ) {
		// we have to reset the existing ack_to field in case of forwarding
		// np_jtree_elem_t* jrb_node = jrb_find_str(msg_out->instructions, NP_MSG_INST_ACK_TO);
		jrb_replace_str(msg_out->instructions, NP_MSG_INST_ACK_TO, new_jval_s((char*) ack_to_str));
		ack_to_is_me = TRUE;
	} else if ( 0 < (ack_mode & ACK_DESTINATION) || 0 < (ack_mode & ACK_CLIENT) ) {
		// only set these two ack values if not yet set !
		jrb_insert_str(msg_out->instructions, NP_MSG_INST_ACK_TO, new_jval_s((char*) ack_to_str));
		ack_to_is_me = TRUE;
	} else {
		ack_to_is_me = FALSE;
	}

	/* get/set sequence number to initialize acknowledgement indicator correctly */
	// np_jtree_elem_t* jrb_seq = jrb_find_str(msg_out->instructions, NP_MSG_INST_SEQ);
	if (ack_to_is_me) {
		seq = network->seqend;
		jrb_replace_str(msg_out->instructions, NP_MSG_INST_SEQ, new_jval_ul(seq));
		network->seqend++;

		np_ackentry_t *ackentry = get_new_ackentry();
		jrb_insert_ulong(network->waiting, seq, new_jval_v(ackentry));

	} else {
		jrb_insert_str(msg_out->instructions, NP_MSG_INST_SEQ, new_jval_ul(0));
	}

	// set resend count to zero if not yet present
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_RESEND_COUNT, new_jval_ush(0));

	pthread_mutex_unlock(&(network->lock));

	// message part split-up informations
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_PART, new_jval_ui(parts));

	start = dtime();
	if (ack_to_is_me) {
		// insert a record into the priority queue with the following information:
		// key: starttime + next retransmit time
		// other info: destination host, seq num, data, data size
		// np_jrb_t* jrb_resend = jrb_find_str(msg_out->instructions, "_np.resend_count");

		np_prioq_t *pqrecord = get_new_pqentry();
		pqrecord->dest_key = args->target;
		pqrecord->msg = args->msg;
		pqrecord->retry = 0; // jrb_resend->val.value.ui;
		pqrecord->seqnum = seq;
		pqrecord->transmittime = start;

		pthread_mutex_lock(&network->lock);
		np_ref_obj(np_message_t, args->msg);
		np_ref_obj(np_key_t, args->target);

		jrb_insert_dbl(network->retransmit,
					   (start + RETRANSMIT_INTERVAL), new_jval_v(pqrecord));
		pthread_mutex_unlock(&network->lock);
	}

	char* subj = jrb_find_str(msg_out->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
	log_msg(LOG_DEBUG, "message %s (%u) to %s", subj, seq, key_get_as_string(args->target));

	network_send_udp(state, args->target, msg_out);
	// ret is 1 or 0
	// np_node_update_stat(target_node, ret);

	np_free_obj(np_message_t, args->msg);
	log_msg(LOG_TRACE, "... hnd_msg_out_send finished");
}

void hnd_msg_out_handshake(np_state_t* state, np_jobargs_t* args) {

	// get our identity from the cache
	np_aaatoken_t* my_id_token = state->my_key->authentication;
	np_node_t* my_node = state->my_key->node;

	// convert to curve key
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_id_token->private_key);
	// calculate public key for dh key exchange
	unsigned char my_dh_pubkey[crypto_scalarmult_BYTES];
	crypto_scalarmult_base(my_dh_pubkey, curve25519_sk);

	// create handshake data
	np_jtree_t* hs_data = make_jtree();

	jrb_insert_str(hs_data, "_np.dns_name", new_jval_s(my_node->dns_name));
	jrb_insert_str(hs_data, "_np.port", new_jval_ui(my_node->port));
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
	uint64_t hs_payload_len = cmp.buf-hs_buf_ptr;

	// sign the handshake payload with our private key
	char signature[crypto_sign_BYTES];
	uint64_t signature_len;
	int16_t ret = crypto_sign_detached((unsigned char*)       signature, &signature_len,
							       (const unsigned char*) hs_payload, hs_payload_len,
								   my_id_token->private_key);
	if (ret < 0) {
		log_msg(LOG_WARN, "checksum creation failed, not continuing with handshake");
		return;
	}

	// create real handshake message ...
	np_message_t* hs_message;
	np_new_obj(np_message_t, hs_message);

	// ... add signature and payload to this message
	jrb_insert_str(hs_message->body, NP_HS_SIGNATURE,
			new_jval_bin(signature, (uint32_t) signature_len));
	jrb_insert_str(hs_message->body, NP_HS_PAYLOAD,
			new_jval_bin(hs_payload, (uint32_t) hs_payload_len));
	// log_msg(LOG_DEBUG, "payload has length %llu, signature length %llu", hs_payload_len, signature_len);

	// serialize complete encrypted message
	uint64_t msg_size = 0;
    char hs_msg[NP_MESSAGE_SIZE];
    void* hs_msg_ptr = hs_msg;
	ret = np_message_serialize(hs_message, hs_msg_ptr, &msg_size);
	// log_msg(LOG_DEBUG, "serialized handshake message (%p) msg_size %llu", hs_msg_ptr, msg_size);

	// construct target address and send it out
	np_node_t* hs_node = args->target->node;

	struct sockaddr_in to;
	memset(&to, 0, sizeof(to));

	pthread_mutex_lock(&(my_node->network->lock));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = hs_node->address;
	to.sin_port = htons ((short) hs_node->port);

	/* send data if handshake status is still just initialized or less */
// 	if (hs_node->handshake_status <= HANDSHAKE_INITIALIZED) {
	log_msg(LOG_NETWORKDEBUG,
			"sending handshake message (length: %llu) to (%s:%hd)",
			msg_size, hs_node->dns_name, hs_node->port);
	ret = sendto(my_node->network->socket, hs_msg_ptr, msg_size, 0, (struct sockaddr *) &to, sizeof(to));
	if (ret < 0) {
		log_msg(LOG_ERROR, "handshake error: %s", strerror (errno));
		// nothing more to be done
	}
// 	} else {
// 		log_msg(LOG_NETWORKDEBUG,
// 				"sending handshake message stopped, already completed (%s:%hd)",
// 				hs_node->dns_name, hs_node->port);
// 	}

	pthread_mutex_unlock(&my_node->network->lock);
	// log_msg(LOG_DEBUG, "finished to send handshake message");

	np_free_obj(np_message_t, hs_message);
	np_free_tree(hs_data);
}
