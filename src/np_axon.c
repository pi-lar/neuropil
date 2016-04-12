/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
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
#include "np_msgproperty.h"
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
void hnd_msg_out_ack(np_state_t* state, np_jobargs_t* args)
{
	char* uuid = np_create_uuid(args->properties->msg_subject, 0);
	jrb_insert_str(args->msg->instructions, NP_MSG_INST_UUID, new_jval_s(uuid));
	free(uuid);

	jrb_insert_str(args->msg->instructions, NP_MSG_INST_PARTS, new_jval_iarray(1, 1));

	// chunking for 1024 bit message size
	np_message_calculate_chunking(args->msg);

	np_jobargs_t* chunk_args = (np_jobargs_t*) malloc(sizeof(np_jobargs_t));
	chunk_args->msg = args->msg;
	np_message_serialize_chunked(state, chunk_args);
	free(chunk_args);

	network_send(state, args->target, args->msg);
	// send_ok is 1 or 0
	// np_node_update_stat(args->target->node, send_ok);
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

	np_bool is_resend = args->is_resend;
	np_bool is_forward = args->msg->is_single_part;
	np_bool ack_to_is_me = FALSE;
	np_bool ack_mode_from_msg = FALSE;

	uint8_t ack_mode = ACK_NONE;
	char* uuid = NULL;

	np_msgproperty_t* prop = args->properties;
	np_network_t* network = state->my_node_key->network;

	if (!np_node_check_address_validity(args->target->node))
	{
		log_msg(LOG_DEBUG, "attempt to send to an invalid node (key: %s)",
							_key_as_str(args->target));
		// np_free_obj(np_message_t, args->msg);
		log_msg(LOG_TRACE, ".end  .hnd_msg_out_send");
		return;
	}

	// check ack indicator if this is a resend of a message
	if (TRUE == is_resend)
	{
		uuid = jrb_find_str(msg_out->instructions, NP_MSG_INST_UUID)->val.value.s;

		pthread_mutex_lock(&network->lock);
		// first find the uuid
		if (NULL == jrb_find_str(network->waiting, uuid))
		{
			// has been deleted already
			log_msg(LOG_DEBUG, "message %s (%s) acknowledged, not resending ...", prop->msg_subject, uuid);
			log_msg(LOG_TRACE, ".end  .hnd_msg_out_send");
			pthread_mutex_unlock(&network->lock);
			return;
		}
		else
		{
			// still there ? initiate resend ...
			log_msg(LOG_DEBUG, "message %s (%s) not acknowledged, resending ...", prop->msg_subject, uuid);
		}
		pthread_mutex_unlock(&network->lock);

		double initial_tstamp = jrb_find_str(msg_out->instructions, NP_MSG_INST_TSTAMP)->val.value.d;
		double now = ev_time();
		if (now > (initial_tstamp + args->properties->ttl)) {
			log_msg(LOG_DEBUG, "resend message %s (%s) expired, not resending ...", prop->msg_subject, uuid);
			return;
		}
	}

	// find correct ack_mode, inspect message first because of forwarding
	if (NULL == jrb_find_str(msg_out->instructions, NP_MSG_INST_ACK))
	{
		ack_mode = prop->ack_mode;
	}
	else
	{
		ack_mode = jrb_find_str(msg_out->instructions, NP_MSG_INST_ACK)->val.value.ush;
		ack_mode_from_msg = TRUE;
	}
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_ACK, new_jval_ush(prop->ack_mode));

	char* ack_to_str = _key_as_str(state->my_node_key);

	if ( 0 < (ack_mode & ACK_EACHHOP) )
	{
		// we have to reset the existing ack_to field in case of forwarding and each-hop acknowledge
		jrb_replace_str(msg_out->instructions, NP_MSG_INST_ACK_TO, new_jval_s(ack_to_str));
		ack_to_is_me = TRUE;
	}
	else if ( 0 < (ack_mode & ACK_DESTINATION) || 0 < (ack_mode & ACK_CLIENT) )
	{
		// only set ack_to for these two ack mode values if not yet set !
		jrb_insert_str(msg_out->instructions, NP_MSG_INST_ACK_TO, new_jval_s(ack_to_str));
		if (FALSE == ack_mode_from_msg) ack_to_is_me = TRUE;
	}
	else
	{
		ack_to_is_me = FALSE;
	}

	jrb_insert_str(msg_out->instructions, NP_MSG_INST_SEQ, new_jval_ul(0));
	if (TRUE == ack_to_is_me && FALSE == is_resend)
	{
		pthread_mutex_lock(&network->lock);
		/* get/set sequence number to initialize acknowledgement indicator correctly */
		seq = network->seqend;
		jrb_replace_str(msg_out->instructions, NP_MSG_INST_SEQ, new_jval_ul(seq));
		network->seqend++;
		pthread_mutex_unlock(&network->lock);
	}

	// insert a uuid if not yet present
	uuid = np_create_uuid(args->properties->msg_subject, seq);

	jrb_insert_str(msg_out->instructions, NP_MSG_INST_UUID, new_jval_s(uuid));
	free(uuid);

	// log_msg(LOG_DEBUG, "message ttl %s (tstamp: %f / ttl: %f) %s", uuid, now, args->properties->ttl, args->properties->msg_subject);

	// set resend count to zero if not yet present
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_SEND_COUNTER, new_jval_ush(0));
	// increase resend count by one
	// TODO: forwarding of message will also increase resend counter, ok ?
	np_jtree_elem_t* jrb_send_counter = jrb_find_str(msg_out->instructions, NP_MSG_INST_SEND_COUNTER);
	jrb_send_counter->val.value.ush++;
	// TODO: insert resend count check

	// insert timestamp and time-to-live
	double now = ev_time();
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_TSTAMP, new_jval_d(now));
	now += args->properties->ttl;
	jrb_insert_str(msg_out->instructions, NP_MSG_INST_TTL, new_jval_d(now));

	jrb_insert_str(msg_out->instructions, NP_MSG_INST_PARTS, new_jval_iarray(1, 1));
	if (FALSE == msg_out->is_single_part)
	{
		// dummy message part split-up informations
		np_message_calculate_chunking(msg_out);
	}

	if (TRUE == ack_to_is_me)
	{
		if (FALSE == is_resend) {
			uuid = jrb_find_str(msg_out->instructions, NP_MSG_INST_UUID)->val.value.s;

			pthread_mutex_lock(&network->lock);
			/* get/set sequence number to initialize acknowledgement indicator correctly */
			np_ackentry_t *ackentry = NULL;

			if (NULL != jrb_find_str(network->waiting, uuid))
			{
				ackentry = (np_ackentry_t*) jrb_find_str(network->waiting, uuid)->val.value.v;
			}
			else
			{
				ackentry = get_new_ackentry();
			}

			ackentry->acked = FALSE;
			ackentry->transmittime = ev_time();
			ackentry->expiration = ackentry->transmittime + (args->properties->ttl * args->properties->retry);
			ackentry->dest_key = args->target;
			np_ref_obj(np_key_t, args->target);

			if (TRUE == is_forward)
			{
				// single part message can only occur in intermediate hops
				ackentry->expected_ack++;
			}
			else
			{
				// full message can only occur when sending the original message
				ackentry->expected_ack = msg_out->no_of_chunks;
			}

			jrb_insert_str(network->waiting, uuid, new_jval_v(ackentry));
			log_msg(LOG_DEBUG, "ack handling (%p) requested for msg uuid: %s", network->waiting, uuid);
			pthread_mutex_unlock(&network->lock);
		}

		// insert a record into the priority queue with the following information:
		double retransmit_interval = args->properties->ttl / args->properties->retry;
		np_msgproperty_t* out_prop = np_msgproperty_get(TRANSFORM, ROUTE_LOOKUP);
		_np_job_resubmit_msg_event(retransmit_interval, out_prop, args->target, args->msg);
	}

	// char* subj = jrb_find_str(msg_out->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
	// log_msg(LOG_DEBUG, "message %s (%u) to %s", subj, seq, key_get_as_string(args->target));
	// log_msg(LOG_DEBUG, "message part byte sizes: %lu %lu %lu %lu %lu, total: %lu",
	// 			msg_out->header->byte_size, msg_out->instructions->byte_size,
	// 			msg_out->properties->byte_size, msg_out->body->byte_size,
	// 			msg_out->footer->byte_size,
	// 			msg_out->header->byte_size + msg_out->instructions->byte_size + msg_out->properties->byte_size + msg_out->body->byte_size + msg_out->footer->byte_size);

	// TODO: do this serialization in parallel in background
	np_jobargs_t chunk_args = { .msg = msg_out };

	// np_print_tree (msg_out->body, 0);
	if (TRUE == is_forward)
	{
		np_message_serialize(state, &chunk_args);
	}
	else
	{
		np_message_serialize_chunked(state, &chunk_args);
	}

	network_send(state, args->target, msg_out);
	// ret is 1 or 0
	// np_node_update_stat(args->target->node, send_ok);

	log_msg(LOG_TRACE, ".end  .hnd_msg_out_send");
}

void hnd_msg_out_handshake(np_state_t* state, np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.hnd_msg_out_handshake");

	if (!np_node_check_address_validity(args->target->node)) return;

	// get our identity from the cache
	np_aaatoken_t* my_id_token = state->my_node_key->aaa_token;
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
	// TODO:
    unsigned char hs_payload[65536];
    void* hs_buf_ptr = hs_payload;

    cmp_init(&cmp, hs_buf_ptr, buffer_reader, buffer_writer);
	serialize_jrb_node_t(hs_data, &cmp);
	uint64_t hs_payload_len = cmp.buf-hs_buf_ptr;

	np_free_tree(hs_data);

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
	np_message_t* hs_message = NULL;
	np_new_obj(np_message_t, hs_message);

	jrb_insert_str(hs_message->header, NP_MSG_HEADER_SUBJECT, new_jval_s(NP_MSG_HANDSHAKE));
	jrb_insert_str(hs_message->instructions, NP_MSG_INST_PARTS, new_jval_iarray(1, 1));

	// ... add signature and payload to this message
	jrb_insert_str(hs_message->body, NP_HS_SIGNATURE,
			new_jval_bin(signature, (uint32_t) signature_len));
	jrb_insert_str(hs_message->body, NP_HS_PAYLOAD,
			new_jval_bin(hs_payload, (uint32_t) hs_payload_len));
	// log_msg(LOG_DEBUG, "payload has length %llu, signature length %llu", hs_payload_len, signature_len);

    // TODO: do this serialization in parallel in background
	np_message_calculate_chunking(hs_message);

	np_jobargs_t* chunk_args = (np_jobargs_t*) malloc(sizeof(np_jobargs_t));
	chunk_args->msg = hs_message;
	np_bool serialize_ok = np_message_serialize_chunked(state, chunk_args);

	// log_msg(LOG_DEBUG, "serialized handshake message msg_size %llu", hs_msg_ptr, msg_size);
	free(chunk_args);

	if (TRUE == serialize_ok)
	{
		if (NULL == args->target->network)
		{
			// initialize network
			args->target->network =
					network_init(
							FALSE,
							args->target->node->protocol,
							args->target->node->dns_name,
							args->target->node->port);
			args->target->network->watcher.data = args->target;
		}

		// construct target address and send it out
		np_node_t* hs_node = args->target->node;
		pthread_mutex_lock(&(args->target->network->lock));

		/* send data if handshake status is still just initialized or less */
		log_msg(LOG_DEBUG,
				"sending handshake message to (%s:%s)",
				hs_node->dns_name, hs_node->port);

		log_msg(LOG_DEBUG, ": %d %p %p :",
				&args->target->network->socket,
				&args->target->network->watcher,
				&args->target->network->watcher.data);

		char* packet = (char*) malloc(1024);
		memset(packet, 0, 1024);
		memcpy(packet, pll_first(hs_message->msg_chunks)->val->msg_part, 984);

		sll_append(
				void_ptr,
				args->target->network->out_events,
				(void*) packet);
		// notify main ev loop
		// ev_async_cb();
		// ret = send(args->target->network->socket, pll_first(hs_message->msg_chunks)->val->msg_part, 984, 0);
		// ret = sendto(my_node->network->socket, hs_msg_ptr, msg_size, 0, to, to_size);

//		np_node_update_stat(hs_node, ret);
//		if (ret < 0) {
//			log_msg(LOG_ERROR, "send handshake error: %s", strerror (errno));
//		}

		pthread_mutex_unlock(&args->target->network->lock);
	}
	np_free_obj(np_message_t, hs_message);

	log_msg(LOG_TRACE, ".end  .hnd_msg_out_handshake");
}
