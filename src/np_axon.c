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
#include "np_log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
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
void _np_out_ack(np_jobargs_t* args)
{
	char* uuid = np_create_uuid(args->properties->msg_subject, 0);
	tree_insert_str(args->msg->instructions, NP_MSG_INST_UUID, new_val_s(uuid));
	free(uuid);

	tree_insert_str(args->msg->instructions, NP_MSG_INST_PARTS, new_val_iarray(1, 1));

	// chunking for 1024 bit message size
	np_message_calculate_chunking(args->msg);

	np_jobargs_t* chunk_args = (np_jobargs_t*) malloc(sizeof(np_jobargs_t));
	chunk_args->msg = args->msg;
	np_message_serialize_chunked(chunk_args);
	free(chunk_args);

	network_send(args->target, args->msg);
	// send_ok is 1 or 0
	// np_node_update_stat(args->target->node, send_ok);
}

/**
 ** network_send: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void _np_out_send(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_out_send");

	uint32_t seq = 0;
	np_message_t* msg_out = args->msg;

	np_bool is_resend = args->is_resend;
	np_bool is_forward = msg_out->is_single_part;
	np_bool ack_to_is_me = FALSE;
	np_bool ack_mode_from_msg = FALSE;

	uint8_t ack_mode = ACK_NONE;
	char* uuid = NULL;

	np_msgproperty_t* prop = args->properties;
	np_network_t* network = _np_state()->my_node_key->network;

	if (!np_node_check_address_validity(args->target->node))
	{
		log_msg(LOG_DEBUG, "attempt to send to an invalid node (key: %s)",
							_key_as_str(args->target));
		log_msg(LOG_TRACE, ".end  ._np_out_send");
		return;
	}

	// check ack indicator if this is a resend of a message
	if (TRUE == is_resend)
	{
		uuid = tree_find_str(msg_out->instructions, NP_MSG_INST_UUID)->val.value.s;

		pthread_mutex_lock(&network->lock);
		// first find the uuid
		if (NULL == tree_find_str(network->waiting, uuid))
		{
			// has been deleted already
			log_msg(LOG_DEBUG, "message %s (%s) acknowledged, not resending ...", prop->msg_subject, uuid);
			log_msg(LOG_TRACE, ".end  ._np_out_send");
			pthread_mutex_unlock(&network->lock);
			return;
		}
		else if (TRUE == ((np_ackentry_t*) tree_find_str(network->waiting, uuid)->val.value.v)->acked)
		{
			log_msg(LOG_DEBUG, "message %s (%s) acknowledged, not resending ...", prop->msg_subject, uuid);
			log_msg(LOG_TRACE, ".end  ._np_out_send");
			pthread_mutex_unlock(&network->lock);
			return;
		}
		else
		{
			// ack indicator still there ? initiate resend ...
			log_msg(LOG_DEBUG, "message %s (%s) not acknowledged, resending ...", prop->msg_subject, uuid);
		}
		pthread_mutex_unlock(&network->lock);

		double initial_tstamp = tree_find_str(msg_out->instructions, NP_MSG_INST_TSTAMP)->val.value.d;
		double now = ev_time();
		if (now > (initial_tstamp + args->properties->ttl) )
		{
			log_msg(LOG_DEBUG, "resend message %s (%s) expired, not resending ...", prop->msg_subject, uuid);
			return;
		}
		// only redeliver if ack_to has been initialized correctly, so this must be TRUE for a resend
		ack_to_is_me = TRUE;
	}

	// find correct ack_mode, inspect message first because of forwarding
	if (NULL == tree_find_str(msg_out->instructions, NP_MSG_INST_ACK))
	{
		ack_mode = prop->ack_mode;
	}
	else
	{
		ack_mode = tree_find_str(msg_out->instructions, NP_MSG_INST_ACK)->val.value.ush;
		ack_mode_from_msg = TRUE;
	}
	tree_insert_str(msg_out->instructions, NP_MSG_INST_ACK, new_val_ush(prop->ack_mode));

	char* ack_to_str = _key_as_str(_np_state()->my_node_key);

	if ( 0 < (ack_mode & ACK_EACHHOP) )
	{
		// we have to reset the existing ack_to field in case of forwarding and each-hop acknowledge
		tree_replace_str(msg_out->instructions, NP_MSG_INST_ACK_TO, new_val_s(ack_to_str));
		ack_to_is_me = TRUE;
	}
	else if ( 0 < (ack_mode & ACK_DESTINATION) || 0 < (ack_mode & ACK_CLIENT) )
	{
		// only set ack_to for these two ack mode values if not yet set !
		tree_insert_str(msg_out->instructions, NP_MSG_INST_ACK_TO, new_val_s(ack_to_str));
		if (FALSE == ack_mode_from_msg) ack_to_is_me = TRUE;
	}
	else
	{
		ack_to_is_me = FALSE;
	}

	tree_insert_str(msg_out->instructions, NP_MSG_INST_SEQ, new_val_ul(0));
	if (TRUE == ack_to_is_me && FALSE == is_resend)
	{
		pthread_mutex_lock(&network->lock);
		/* get/set sequence number to keep increasing sequence numbers per node */
		seq = network->seqend;
		tree_replace_str(msg_out->instructions, NP_MSG_INST_SEQ, new_val_ul(seq));
		network->seqend++;
		pthread_mutex_unlock(&network->lock);
	}

	// insert a uuid if not yet present
	uuid = np_create_uuid(args->properties->msg_subject, seq);
	tree_insert_str(msg_out->instructions, NP_MSG_INST_UUID, new_val_s(uuid));
	free(uuid);

	// log_msg(LOG_DEBUG, "message ttl %s (tstamp: %f / ttl: %f) %s", uuid, now, args->properties->ttl, args->properties->msg_subject);

	// set re-send count to zero if not yet present
	tree_insert_str(msg_out->instructions, NP_MSG_INST_SEND_COUNTER, new_val_ush(0));
	// and increase resend count by one
	// TODO: forwarding of message will also increase re-send counter, ok ?
	np_tree_elem_t* jrb_send_counter = tree_find_str(msg_out->instructions, NP_MSG_INST_SEND_COUNTER);
	jrb_send_counter->val.value.ush++;
	// TODO: insert resend count check

	// insert timestamp and time-to-live
	double now = ev_time();
	tree_insert_str(msg_out->instructions, NP_MSG_INST_TSTAMP, new_val_d(now));
	// now += args->properties->ttl;
	tree_insert_str(msg_out->instructions, NP_MSG_INST_TTL, new_val_d(args->properties->ttl));

	tree_insert_str(msg_out->instructions, NP_MSG_INST_PARTS, new_val_iarray(1, 1));
	if (FALSE == msg_out->is_single_part)
	{
		// dummy message part split-up informations
		np_message_calculate_chunking(msg_out);
	}

	if (TRUE == ack_to_is_me)
	{
		if (FALSE == is_resend)
		{
			uuid = tree_find_str(msg_out->instructions, NP_MSG_INST_UUID)->val.value.s;

			pthread_mutex_lock(&network->lock);
			/* get/set sequence number to initialize acknowledgement indicator correctly */
			np_ackentry_t *ackentry = NULL;

			if (NULL != tree_find_str(network->waiting, uuid))
			{
				ackentry = (np_ackentry_t*) tree_find_str(network->waiting, uuid)->val.value.v;
			}
			else
			{
				ackentry = get_new_ackentry();
			}

			ackentry->acked = FALSE;
			ackentry->transmittime = ev_time();
			// + 1.0 because of time delays for processing
			ackentry->expiration = ackentry->transmittime + args->properties->ttl + 1.0;
			ackentry->dest_key = args->target;
			np_ref_obj(np_key_t,  args->target);

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

			tree_insert_str(network->waiting, uuid, new_val_v(ackentry));
			log_msg(LOG_DEBUG, "ack handling (%p) requested for msg uuid: %s", network->waiting, uuid);
			pthread_mutex_unlock(&network->lock);
		}

		// insert a record into the priority queue with the following information:
		double retransmit_interval = args->properties->ttl / args->properties->retry;
		np_msgproperty_t* out_prop = np_msgproperty_get(OUTBOUND, args->properties->msg_subject);
		_np_job_resubmit_route_event(retransmit_interval, out_prop, args->target, args->msg);
	}

	// char* subj = tree_find_str(msg_out->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
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
		np_message_serialize(&chunk_args);
	}
	else
	{
		np_message_serialize_chunked(&chunk_args);
	}

	network_send(args->target, msg_out);
	// ret is 1 or 0
	// np_node_update_stat(args->target->node, send_ok);

	log_msg(LOG_TRACE, ".end  ._np_out_send");
}

void _np_out_handshake(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_out_handshake");

	if (!np_node_check_address_validity(args->target->node)) return;

	// get our node identity from the cache
	np_aaatoken_t* my_id_token = _np_state()->my_node_key->aaa_token;
	// np_node_t* my_node = _np_state()->my_node_key->node;

	// convert to curve key
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_id_token->private_key);
	// calculate session key for dh key exchange
	unsigned char my_dh_sessionkey[crypto_scalarmult_BYTES];
	crypto_scalarmult_base(my_dh_sessionkey, curve25519_sk);

	// create handshake data
	np_tree_t* hs_data = make_jtree();

	tree_insert_str(hs_data, "_np.session", new_val_bin(my_dh_sessionkey, crypto_scalarmult_BYTES));
	// tree_insert_str(hs_data, "_np.public_key", new_val_bin(my_id_token->public_key, crypto_sign_PUBLICKEYBYTES));

	np_encode_aaatoken(hs_data, my_id_token);

//	char pk_hex[crypto_sign_PUBLICKEYBYTES*2+1];
//	sodium_bin2hex(pk_hex, crypto_sign_PUBLICKEYBYTES*2+1, my_id_token->public_key, crypto_sign_PUBLICKEYBYTES);
//	log_msg(LOG_DEBUG, "public key fingerprint: %s", pk_hex);

//	tree_insert_str(hs_data, "_np.protocol", new_val_s(np_get_protocol_string(my_node->protocol)));
//	tree_insert_str(hs_data, "_np.dns_name", new_val_s(my_node->dns_name));
//	tree_insert_str(hs_data, "_np.port", new_val_s(my_node->port));
//	tree_insert_str(hs_data, "_np.expiration", new_val_d(my_id_token->expiration));
//	tree_insert_str(hs_data, "_np.issued_at", new_val_d(my_id_token->issued_at));

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
	memset(signature, '0', crypto_sign_BYTES);
	// uint64_t signature_len;
	int16_t ret = crypto_sign_detached((unsigned char*)       signature,  NULL,
							           (const unsigned char*) hs_payload,  hs_payload_len,
								       my_id_token->private_key);
	if (ret < 0)
	{
		log_msg(LOG_WARN, "signature creation failed, not continuing with handshake");
		return;
	}

//	char sign_hex[crypto_sign_BYTES*2+1];
//	sodium_bin2hex(sign_hex, crypto_sign_BYTES*2+1, (unsigned char*) signature, crypto_sign_BYTES);
//	log_msg(LOG_DEBUG, "signature key fingerprint: %s", sign_hex);

	// create real handshake message ...
	np_message_t* hs_message = NULL;
	np_new_obj(np_message_t, hs_message);

	tree_insert_str(hs_message->header, NP_MSG_HEADER_SUBJECT, new_val_s(_NP_MSG_HANDSHAKE));
	tree_insert_str(hs_message->instructions, NP_MSG_INST_PARTS, new_val_iarray(1, 1));

	// ... add signature and payload to this message
	tree_insert_str(hs_message->body, NP_HS_SIGNATURE,
			new_val_bin(signature, crypto_sign_BYTES));
	tree_insert_str(hs_message->body, NP_HS_PAYLOAD,
			new_val_bin(hs_payload, (uint32_t) hs_payload_len));
//	log_msg(LOG_DEBUG, "payload has length %llu, signature length %u", hs_payload_len, crypto_sign_BYTES);
//	log_msg(LOG_DEBUG, "header has length %llu, instructions length %llu",
//						hs_message->header->byte_size, hs_message->instructions->byte_size);

    // TODO: do this serialization in parallel in background
	np_message_calculate_chunking(hs_message);

	// log_msg(LOG_DEBUG, "msg chunks %u", hs_message->no_of_chunks);

	np_jobargs_t* chunk_args = (np_jobargs_t*) malloc(sizeof(np_jobargs_t));
	chunk_args->msg = hs_message;
	np_bool serialize_ok = np_message_serialize_chunked(chunk_args);

	// log_msg(LOG_DEBUG, "serialized handshake message msg_size %llu", hs_msg_ptr, msg_size);
	free(chunk_args);

	if (TRUE == serialize_ok)
	{
		if (NULL == args->target->network)
		{
			// initialize network
			np_new_obj(np_network_t, args->target->network);
			network_init(args->target->network,
						 FALSE,
						 args->target->node->protocol,
						 args->target->node->dns_name,
						 args->target->node->port);
			if (FALSE == args->target->network->initialized)
			{
				np_free_obj(np_message_t, hs_message);
				args->target->node->handshake_status = HANDSHAKE_UNKNOWN;
				return;
			}
			args->target->network->watcher.data = args->target;
		}

		// construct target address and send it out
		np_node_t* hs_node = args->target->node;

		pthread_mutex_lock(&(args->target->network->lock));
		/* send data if handshake status is still just initialized or less */
		log_msg(LOG_DEBUG,
				"sending handshake message to (%s:%s)",
				hs_node->dns_name, hs_node->port);

//		log_msg(LOG_DEBUG, ": %d %p %p :",
//				args->target->network->socket,
//				&args->target->network->watcher,
//				&args->target->network->watcher.data);

		char* packet = (char*) malloc(1024);
		memset(packet, 0, 1024);
		memcpy(packet, pll_first(hs_message->msg_chunks)->val->msg_part, 984);

		sll_append(
				void_ptr,
				args->target->network->out_events,
				(void*) packet);
		// notify main ev loop ? should be running already
		// ret = send(args->target->network->socket, pll_first(hs_message->msg_chunks)->val->msg_part, 984, 0);
		// ret = sendto(my_node->network->socket, hs_msg_ptr, msg_size, 0, to, to_size);

//		np_node_update_stat(hs_node, ret);
//		if (ret < 0) {
//			log_msg(LOG_ERROR, "send handshake error: %s", strerror (errno));
//		}

		pthread_mutex_unlock(&args->target->network->lock);
	}
	np_free_obj(np_message_t, hs_message);

	log_msg(LOG_TRACE, ".end  ._np_out_handshake");
}

void _np_send_receiver_discovery(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_send_receiver_discovery");
	// create message interest in authentication request
	np_aaatoken_t* msg_token = NULL;

	msg_token = _np_get_sender_token(args->properties->msg_subject,
			 	 	 	 	 	 	 _key_as_str(_np_state()->my_identity));
	if (NULL == msg_token)
	{
		log_msg(LOG_DEBUG, "creating new sender token for subject %s", args->properties->msg_subject);
		msg_token = _np_create_msg_token(args->properties);
		_np_add_sender_token(msg_token->subject, msg_token);
		// np_free_obj(np_aaatoken_t, msg_token);
	}

	if (NULL != msg_token)
	{
		np_tree_t* _data = make_jtree();
		np_encode_aaatoken(_data, msg_token);

		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, args->target, _np_state()->my_node_key, _NP_MSG_DISCOVER_RECEIVER, _data);
		// send message availability
		np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_DISCOVER_RECEIVER);
		_np_job_submit_route_event(0.0, prop_route, args->target, msg_out);
		np_free_obj(np_message_t, msg_out);
	}
	np_unref_obj(np_aaatoken_t, msg_token);

	log_msg(LOG_TRACE, ".end  ._np_send_receiver_discovery");
}

void _np_send_sender_discovery(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_send_sender_discovery");
	// create message interest in authentication request
	np_aaatoken_t* msg_token = NULL;

	msg_token = _np_get_receiver_token(args->properties->msg_subject);
	if (NULL == msg_token)
	{
		log_msg(LOG_DEBUG, "creating new receiver token for subject %s", args->properties->msg_subject);
		msg_token = _np_create_msg_token(args->properties);
		_np_add_receiver_token(msg_token->subject, msg_token);
		// np_free_obj(np_aaatoken_t, msg_token);
	}
//	else
//	{
//	}

	if (NULL != msg_token)
	{
		log_msg(LOG_DEBUG, "encoding receiver token for subject %p / %s", msg_token, msg_token->uuid);
		np_tree_t* _data = make_jtree();
		np_encode_aaatoken(_data, msg_token);

		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, args->target, _np_state()->my_node_key, _NP_MSG_DISCOVER_SENDER, _data);

		// send message availability
		np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_DISCOVER_SENDER);
		_np_job_submit_route_event(0.0, prop_route, args->target, msg_out);

		np_free_obj(np_message_t, msg_out);
		np_unref_obj(np_aaatoken_t, msg_token);
	}

	log_msg(LOG_TRACE, ".end  ._np_send_sender_discovery");
}

void np_send_authentication_request(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_send_authentication_request");

	np_state_t* state = _np_state();
	np_dhkey_t target_dhkey;

	if (0 < strlen(args->target->aaa_token->realm))
	{
		target_dhkey = dhkey_create_from_hostport(args->target->aaa_token->realm, "0");
	}
	else if (0 < strlen(state->my_identity->aaa_token->realm) )
	{
		target_dhkey = dhkey_create_from_hostport(state->my_identity->aaa_token->realm, "0");
	}
	else
	{
		log_msg(LOG_TRACE, ".end  .np_send_authentication_request");
		return;
	}

	log_msg(LOG_DEBUG, "encoding and sending authentication token");

	np_key_t* aaa_target;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->dhkey = target_dhkey;

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHENTICATION_REQUEST);
	if (NULL == aaa_props->msg_cache)
	{
		sll_init(np_message_t, aaa_props->msg_cache);
	}

	// create and send authentication request
	np_message_t* msg_out = NULL;
	np_new_obj(np_message_t, msg_out);

	np_tree_t* auth_data = make_jtree();
	np_encode_aaatoken(auth_data, args->target->aaa_token);

//	log_msg(LOG_DEBUG, "realm             : %s", args->target->aaa_token->realm);
//	log_msg(LOG_DEBUG, "issuer            : %s", args->target->aaa_token->issuer);
//	log_msg(LOG_DEBUG, "subject           : %s", args->target->aaa_token->subject);
//	log_msg(LOG_DEBUG, "audience          : %s", args->target->aaa_token->audience);
//	log_msg(LOG_DEBUG, "uuid              : %s", args->target->aaa_token->uuid);

	np_message_create(msg_out, aaa_target, state->my_node_key, _NP_MSG_AUTHENTICATION_REQUEST, auth_data);
	if (FALSE == _np_send_msg(_NP_MSG_AUTHENTICATION_REQUEST, msg_out, aaa_props))
	{
		log_msg(LOG_DEBUG, "sending authentication discovery");
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_send_receiver_discovery(&jargs);
	}
	np_free_obj(np_message_t, msg_out);

	np_free_obj(np_key_t, aaa_target);

	log_msg(LOG_TRACE, ".end  .np_send_authentication_request");
}

void np_send_authentication_reply(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_send_authentication_reply");

	np_dhkey_t target_dhkey;

	np_msg_mep_type mep_reply_sticky = tree_find_str(args->target->aaa_token->extensions, "mep_type")->val.value.ul & STICKY_REPLY;

	if (STICKY_REPLY != mep_reply_sticky &&
		0 < strlen(args->target->aaa_token->realm) )
	{
		target_dhkey = dhkey_create_from_hostport(args->target->aaa_token->realm, "0");
	}
	else
	{
		target_dhkey = dhkey_create_from_hash(args->target->aaa_token->issuer);
	}

	log_msg(LOG_DEBUG, "encoding and sending authentication reply");

	np_key_t* aaa_target;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->dhkey = target_dhkey;

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHENTICATION_REPLY);
	if (NULL == aaa_props->msg_cache)
	{
		sll_init(np_message_t, aaa_props->msg_cache);
	}

	// create and send authentication reply
	if (FALSE == _np_send_msg(_NP_MSG_AUTHENTICATION_REPLY, args->msg, aaa_props))
	{
		log_msg(LOG_DEBUG, "sending authentication reply discovery");
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_send_receiver_discovery(&jargs);
	}
	np_free_obj(np_key_t, aaa_target);

	log_msg(LOG_TRACE, ".end  .np_send_authentication_reply");
}

void np_send_authorization_request(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_send_authorization_request");

	np_state_t* state = _np_state();
	np_dhkey_t target_dhkey;

	if (0 < strlen(state->my_identity->aaa_token->realm) )
	{
		target_dhkey = dhkey_create_from_hostport(state->my_identity->aaa_token->realm, "0");
	}
	else
	{
		log_msg(LOG_TRACE, ".end  .np_send_authorization_request");
		return;
	}

	log_msg(LOG_DEBUG, "encoding and sending authorization token");
	np_key_t* aaa_target;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->dhkey = target_dhkey;

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHORIZATION_REQUEST);
	if (NULL == aaa_props->msg_cache)
	{
		sll_init(np_message_t, aaa_props->msg_cache);
	}

	// create and and send authorization request
	np_message_t* msg_out = NULL;
	np_new_obj(np_message_t, msg_out);
	np_tree_t* auth_data = make_jtree();
	np_encode_aaatoken(auth_data, args->target->aaa_token);

//	log_msg(LOG_DEBUG, "realm             : %s", args->target->aaa_token->realm);
//	log_msg(LOG_DEBUG, "issuer            : %s", args->target->aaa_token->issuer);
//	log_msg(LOG_DEBUG, "subject           : %s", args->target->aaa_token->subject);
//	log_msg(LOG_DEBUG, "audience          : %s", args->target->aaa_token->audience);
//	log_msg(LOG_DEBUG, "uuid              : %s", args->target->aaa_token->uuid);

	np_message_create(msg_out, aaa_target, state->my_node_key, _NP_MSG_AUTHORIZATION_REQUEST, auth_data);
	if (FALSE == _np_send_msg(_NP_MSG_AUTHORIZATION_REQUEST, msg_out, aaa_props))
	{
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_send_receiver_discovery(&jargs);
	}
	np_free_obj(np_message_t, msg_out);
	np_free_obj(np_key_t, aaa_target);

	log_msg(LOG_TRACE, ".end  .np_send_authorization_request");
}

void np_send_authorization_reply(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_send_authorization_reply");

	np_dhkey_t target_dhkey;

	np_msg_mep_type mep_reply_sticky = tree_find_str(args->target->aaa_token->extensions, "mep_type")->val.value.ul & STICKY_REPLY;

	if (STICKY_REPLY != mep_reply_sticky &&
		0 < strlen(args->target->aaa_token->realm) )
	{
		target_dhkey = dhkey_create_from_hostport(args->target->aaa_token->realm, "0");
	}
	else
	{
		target_dhkey = dhkey_create_from_hash(args->target->aaa_token->issuer);
	}

	log_msg(LOG_DEBUG, "encoding and sending authorization reply");

	np_key_t* aaa_target;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->dhkey = target_dhkey;

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHORIZATION_REPLY);
	if (NULL == aaa_props->msg_cache)
	{
		sll_init(np_message_t, aaa_props->msg_cache);
	}

	// create and send authentication reply
	if (FALSE == _np_send_msg(_NP_MSG_AUTHORIZATION_REPLY, args->msg, aaa_props))
	{
		log_msg(LOG_DEBUG, "sending authorization reply discovery");
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_send_receiver_discovery(&jargs);
	}
	np_free_obj(np_key_t, aaa_target);

	log_msg(LOG_TRACE, ".end  .np_send_authorization_reply");
}

void np_send_accounting_request(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_send_accounting_request");

	np_state_t* state = _np_state();
	np_dhkey_t target_dhkey;

	if (0 < strlen(state->my_identity->aaa_token->realm) )
	{
		target_dhkey = dhkey_create_from_hostport(state->my_identity->aaa_token->realm, "0");
	}
	else
	{
		log_msg(LOG_TRACE, ".end  .np_send_accounting_request");
		return;
	}

	log_msg(LOG_DEBUG, "encoding and sending accounting token");
	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_ACCOUNTING_REQUEST);
	if (NULL == aaa_props->msg_cache)
	{
		sll_init(np_message_t, aaa_props->msg_cache);
	}

	np_key_t* aaa_target;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->dhkey = target_dhkey;

	// create and and send authentication request
	np_message_t* msg_out = NULL;
	np_new_obj(np_message_t, msg_out);

	np_tree_t* auth_data = make_jtree();
	np_encode_aaatoken(auth_data, args->target->aaa_token);
	np_message_create(msg_out, aaa_target, state->my_node_key, _NP_MSG_ACCOUNTING_REQUEST, auth_data);

	if (FALSE == _np_send_msg(_NP_MSG_ACCOUNTING_REQUEST, msg_out, aaa_props))
	{
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_send_receiver_discovery(&jargs);
	}
	np_free_obj(np_message_t, msg_out);

	np_free_obj(np_key_t, aaa_target);
	log_msg(LOG_TRACE, ".end  .np_send_accounting_request");
}
