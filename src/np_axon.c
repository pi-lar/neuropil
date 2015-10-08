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

/** message split up maths
 ** message size = 1b (common header) + 40b (encryption) +
 **                msg (header + instructions) + msg (properties + body) + msg (footer)
 ** if (size > 1024)
 **     fixed_size = 1b + 40b + msg (header + instructions)
 **     payload_size = msg (properties) + msg(body) + msg(footer)
 **     #_of_chunks = int(payload_size / (1024 - fixed_size)) + 1
 **     chunk_size = payload_size / #_of_chunks
 **     garbage_size = #_of_chunks * (fixed_size + chunk_size) % 1024 // spezial behandlung garbage_size < 3
 **     add garbage
 ** else
 ** 	add garbage
 **/


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
void hnd_msg_out_send(np_state_t* state, np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.hnd_msg_out_send");

	uint32_t seq = 0;
	np_message_t* msg_out = args->msg;

	double start = dtime();
	uint16_t parts = 1;
	np_bool ack_to_is_me = FALSE;
	uint8_t ack_mode = ACK_NONE;
	np_bool ack_mode_from_msg = FALSE;

	np_msgproperty_t* prop = args->properties;
	np_network_t* network = state->my_node_key->node->network;

	if (!np_node_check_address_validity(args->target->node)) {
		log_msg(LOG_DEBUG, "attempt to send to an invalid node (key: %s)",
							key_get_as_string(args->target));
		np_free_obj(np_message_t, args->msg);
		log_msg(LOG_TRACE, ".end  .hnd_msg_out_send");
		return;
	}

	/* create network header */
	pthread_mutex_lock(&(network->lock));

	// find correct ack_mode, inspect message first because of forwarding
	if (NULL == jrb_find_str(msg_out->instructions, NP_MSG_INST_ACK)) {
		ack_mode = prop->ack_mode;
	} else {
		ack_mode = jrb_find_str(msg_out->instructions, NP_MSG_INST_ACK)->val.value.ush;
		ack_mode_from_msg = TRUE;
	}
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_ACK, new_jval_ush(prop->ack_mode));

	unsigned char* ack_to_str = key_get_as_string(state->my_node_key);
	if ( 0 < (ack_mode & ACK_EACHHOP) ) {
		// we have to reset the existing ack_to field in case of forwarding and each-hop acknowledge
		jrb_replace_str(msg_out->instructions, NP_MSG_INST_ACK_TO, new_jval_s((char*) ack_to_str));
		ack_to_is_me = TRUE;
	} else if ( 0 < (ack_mode & ACK_DESTINATION) || 0 < (ack_mode & ACK_CLIENT) ) {
		// only set ack_to for these two ack mode values if not yet set !
		jrb_insert_str(msg_out->instructions, NP_MSG_INST_ACK_TO, new_jval_s((char*) ack_to_str));
		if (FALSE == ack_mode_from_msg)
			ack_to_is_me = TRUE;
	} else {
		ack_to_is_me = FALSE;
	}

	/* get/set sequence number to initialize acknowledgement indicator correctly */
	if (TRUE == ack_to_is_me) {
		seq = network->seqend;
		jrb_replace_str(msg_out->instructions, NP_MSG_INST_SEQ, new_jval_ul(seq));
		network->seqend++;

		np_ackentry_t *ackentry = get_new_ackentry();
		jrb_insert_ulong(network->waiting, seq, new_jval_v(ackentry));

	} else {
		jrb_insert_str(msg_out->instructions, NP_MSG_INST_SEQ, new_jval_ul(0));
	}

	pthread_mutex_unlock(&(network->lock));

	// insert a uuid if not yet present
	char* new_uuid = np_create_uuid(args->properties->msg_subject, seq);
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_UUID, new_jval_s(new_uuid));

	// insert timestamp and time-to-live
	double now = dtime();
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_TSTAMP, new_jval_d(now));
	now += args->properties->ttl;
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_TTL, new_jval_d(now));

	// log_msg(LOG_DEBUG, "message ttl %s (tstamp: %f / ttl: %f) %s", new_uuid, now, args->properties->ttl, args->properties->msg_subject);

	free(new_uuid);

	// set resend count to zero if not yet present
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_RESEND_COUNT, new_jval_ush(0));

	// TODO: message part split-up informations
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_PARTS, new_jval_ui(parts));
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_PART, new_jval_ui(parts));

	if (TRUE == ack_to_is_me)
	{
		// insert a record into the priority queue with the following information:
		// key: starttime + next retransmit time
		// other info: destination host, seq num, data, data size
		np_prioq_t *pqrecord = get_new_pqentry();
		pqrecord->dest_key = args->target;
		pqrecord->msg = args->msg;
		pqrecord->max_retries = args->properties->retry;
		pqrecord->retry = 0; // jrb_resend->val.value.ui;
		pqrecord->seqnum = seq;
		pqrecord->transmittime = start;

		pthread_mutex_lock(&network->lock);
		np_ref_obj(np_message_t, args->msg);
		np_ref_obj(np_key_t, args->target);

		// double retransmit_interval = args->properties->ttl / args->properties->retry;
		jrb_insert_dbl(network->retransmit,
					   (start + RETRANSMIT_INTERVAL), new_jval_v(pqrecord));
		pthread_mutex_unlock(&network->lock);
		// log_msg(LOG_DEBUG, "ack handling requested for seq %u", seq);
	} else {
		// log_msg(LOG_DEBUG, "no ack handling required for seq %u", seq);
	}

	char* subj = jrb_find_str(msg_out->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
	log_msg(LOG_DEBUG, "message %s (%u) to %s", subj, seq, key_get_as_string(args->target));
	log_msg(LOG_DEBUG, "message part byte sizes: %u %u %u %u %u, total: %u",
				msg_out->header->byte_size, msg_out->instructions->byte_size,
				msg_out->properties->byte_size, msg_out->body->byte_size,
				msg_out->footer->byte_size,
				msg_out->header->byte_size + msg_out->instructions->byte_size + msg_out->properties->byte_size + msg_out->body->byte_size + msg_out->footer->byte_size);

	// np_print_tree(msg_out->header, 0);
	// np_print_tree(msg_out->instructions, 0);
	// np_print_tree(msg_out->properties, 0);
	// np_print_tree(msg_out->body, 0);
	// np_print_tree(msg_out->footer, 0);

	network_send_udp(state, args->target, msg_out);
	// ret is 1 or 0
	// np_node_update_stat(target_node, ret);

	np_free_obj(np_message_t, args->msg);
	log_msg(LOG_TRACE, ".end  .hnd_msg_out_send");
}

void hnd_msg_out_handshake(np_state_t* state, np_jobargs_t* args) {

	log_msg(LOG_TRACE, ".start.hnd_msg_out_handshake");

	if (!np_node_check_address_validity(args->target->node)) return;

	// get our identity from the cache
	np_aaatoken_t* my_id_token = state->my_node_key->authentication;
	np_node_t* my_node = state->my_node_key->node;

	// convert to curve key
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_id_token->private_key);
	// calculate public key for dh key exchange
	unsigned char my_dh_pubkey[crypto_scalarmult_BYTES];
	crypto_scalarmult_base(my_dh_pubkey, curve25519_sk);

	// create handshake data
	np_jtree_t* hs_data = make_jtree();

	jrb_insert_str(hs_data, "_np.protocol", new_jval_s(np_get_protocol_string(my_node->protocol)));
	jrb_insert_str(hs_data, "_np.dns_name", new_jval_s(my_node->dns_name));
	jrb_insert_str(hs_data, "_np.port", new_jval_s(my_node->port));
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
	int16_t ret = crypto_sign_detached((unsigned char*)       signature,  &signature_len,
							           (const unsigned char*) hs_payload,  hs_payload_len,
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
	pthread_mutex_lock(&(my_node->network->lock));

//	struct sockaddr_in6 to;
//	socklen_t to_size = sizeof to;
//	inet_pton(AF_INET6, hs_node->dns_name, &to.sin6_addr);
//	to.sin6_family = AF_INET6;
//	to.sin6_port = htons(atoi(hs_node->port));

	// struct sockaddr* to = hs_node->network->addr_in->ai_addr;
	// socklen_t to_size = hs_node->network->addr_in->ai_addrlen;

	/* send data if handshake status is still just initialized or less */
	log_msg(LOG_NETWORKDEBUG,
			"sending handshake message (length: %llu) to (%s:%s)",
			msg_size, hs_node->dns_name, hs_node->port);

	ret = send(hs_node->network->socket, hs_msg_ptr, msg_size, 0);
	// ret = sendto(my_node->network->socket, hs_msg_ptr, msg_size, 0, to, to_size);
	if (ret < 0) {
		log_msg(LOG_ERROR, "send handshake error: %s", strerror (errno));
	}

	pthread_mutex_unlock(&my_node->network->lock);

	np_free_obj(np_message_t, hs_message);
	np_free_tree(hs_data);
	log_msg(LOG_TRACE, ".end  .hnd_msg_out_handshake");
}
