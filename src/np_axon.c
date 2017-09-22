//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/select.h>

#include "msgpack/cmp.h"
#include "event/ev.h"
#include "sodium.h"

#include "np_axon.h"

#include "dtime.h"
#include "np_log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_event.h"
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
#include "np_settings.h"
#include "np_types.h"
#include "np_constants.h"
#include "np_list.h"

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
 ** _np_network_send_msg: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void _np_out_ack(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_out_ack(np_jobargs_t* args){");
	//TODO: Was soll diese Methode machen?

	np_tree_insert_str(args->msg->instructions, _NP_MSG_INST_UUID, np_treeval_new_s(args->msg->uuid));
	np_tree_insert_str(args->msg->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(1, 1));

	// chunking for 1024 bit message size
	_np_message_calculate_chunking(args->msg);

	np_jobargs_t* chunk_args = _np_job_create_args(args->msg, NULL, NULL);
	_np_message_serialize_chunked(chunk_args);
	_np_job_free_args(chunk_args);

	_np_network_send_msg(args->target, args->msg);
	// send_ok is 1 or 0
	// np_node_update_stat(args->target->node, send_ok);
}

/**
 ** _np_network_send_msg: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void _np_send(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_send(np_jobargs_t* args){");

	uint32_t seq = 0;
	np_message_t* msg_out = args->msg;

	np_bool is_resend = args->is_resend;
	np_bool is_forward = msg_out->is_single_part;
	np_bool ack_to_is_me = FALSE;
	np_bool ack_mode_from_msg = FALSE;

	uint8_t ack_mode = ACK_NONE;
	char* uuid = NULL;

	np_msgproperty_t* prop = args->properties;

	if (msg_out != NULL && prop != NULL) {
		if (msg_out->msg_property != NULL) {
			np_unref_obj(np_msgproperty_t, prop, ref_message_msg_property);
		}
		msg_out->msg_property = prop;
		np_ref_obj(np_msgproperty_t, prop, ref_message_msg_property);
	}

	sll_iterator(np_usercallback_t) iter_usercallbacks = sll_first(msg_out->msg_property->user_send_clb);
	while (iter_usercallbacks != NULL)
	{
		iter_usercallbacks->val(msg_out, msg_out->properties, msg_out->body);
		sll_next(iter_usercallbacks);
	}

	if (!_np_node_check_address_validity(args->target->node))
	{
		log_debug_msg(LOG_DEBUG, "attempt to send to an invalid node (key: %s)",
							_np_key_as_str(args->target));
		return;
	}

	np_waitref_obj(np_key_t, _np_state()->my_node_key, my_key,"np_waitref_key");
	{
		np_waitref_obj(np_network_t, my_key->network, network,"np_waitref_network");
		{
			// check ack indicator if this is a resend of a message
			if (TRUE == is_resend)
			{
				uuid = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_UUID)->val.value.s;
				np_bool skip = FALSE;
				_LOCK_ACCESS(&network->lock)
				{
					// first find the uuid
					if (NULL == np_tree_find_str(network->waiting, uuid))
					{
						// has been deleted already
						log_debug_msg(LOG_DEBUG, "message %s (%s) acknowledged, not resending ...", prop->msg_subject, uuid);
						skip = TRUE;
					}
					else if (TRUE == ((np_ackentry_t*) np_tree_find_str(network->waiting, uuid)->val.value.v)->acked)
					{
						// uuid has been acked
						log_debug_msg(LOG_DEBUG, "message %s (%s) acknowledged, not resending ...", prop->msg_subject, uuid);
						skip = TRUE;
					}
					else
					{
						// ack indicator still there ! initiate resend ...
						log_debug_msg(LOG_DEBUG, "message %s (%s) not acknowledged, resending ...", prop->msg_subject, uuid);
					}
				}
				// TODO: ref counting on ack may differ (ref_message_ack) / key may not be the same more
				if (TRUE == skip) {
					np_unref_obj(np_network_t,network,"np_waitref_network");
					np_unref_obj(np_key_t,my_key,"np_waitref_key");
					return;
				}

				double initial_tstamp = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_TSTAMP)->val.value.d;
				double now = ev_time();
				if (now > (initial_tstamp + args->properties->msg_ttl) )
				{
					log_debug_msg(LOG_DEBUG, "resend message %s (%s) expired, not resending ...", prop->msg_subject, uuid);

					np_unref_obj(np_network_t,network,"np_waitref_network");
					np_unref_obj(np_key_t,my_key,"np_waitref_key");
					return;
				}
				// only redeliver if ack_to has been initialized correctly, so this must be TRUE for a resend
				ack_to_is_me = TRUE;
			}

			// find correct ack_mode, inspect message first because of forwarding
			if (NULL == np_tree_find_str(msg_out->instructions, _NP_MSG_INST_ACK))
			{
				ack_mode = prop->ack_mode;
			}
			else
			{
				ack_mode = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_ACK)->val.value.ush;
				ack_mode_from_msg = TRUE;
			}
			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop->ack_mode));

			char* ack_to_str = _np_key_as_str(my_key);

			if ( 0 < (ack_mode & ACK_EACHHOP) )
			{
				// we have to reset the existing ack_to field in case of forwarding and each-hop acknowledge
				np_tree_replace_str(msg_out->instructions, _NP_MSG_INST_ACK_TO, np_treeval_new_s(ack_to_str));
				ack_to_is_me = TRUE;
			}
			else if ( 0 < (ack_mode & ACK_DESTINATION) || 0 < (ack_mode & ACK_CLIENT) )
			{
				// only set ack_to for these two ack mode values if not yet set !
				np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK_TO, np_treeval_new_s(ack_to_str));
				if (FALSE == ack_mode_from_msg) ack_to_is_me = TRUE;
			}
			else
			{
				ack_to_is_me = FALSE;
			}

			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(0));
			if (TRUE == ack_to_is_me && FALSE == is_resend)
			{
				_LOCK_ACCESS(&network->lock)
				{
					/* get/set sequence number to keep increasing sequence numbers per node */
					seq = network->seqend;
					np_tree_replace_str(msg_out->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(seq));
					network->seqend++;
				}
			}

			// insert a uuid if not yet present
			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_UUID, np_treeval_new_s(msg_out->uuid));

			// log_debug_msg(LOG_DEBUG, "message ttl %s (tstamp: %f / ttl: %f) %s", uuid, now, args->properties->ttl, args->properties->msg_subject);

			// set re-send count to zero if not yet present
			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_SEND_COUNTER, np_treeval_new_ush(0));
			// and increase resend count by one
			// TODO: forwarding of message will also increase re-send counter, ok ?
			np_tree_elem_t* jrb_send_counter = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_SEND_COUNTER);
			jrb_send_counter->val.value.ush++;
			// TODO: insert resend count check

			// insert timestamp and time-to-live
			double now = ev_time();
			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d(now));
			// now += args->properties->ttl;
			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(args->properties->msg_ttl));

			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(1, 1));
			if (FALSE == msg_out->is_single_part)
			{
				// dummy message part split-up informations
				_np_message_calculate_chunking(msg_out);
			}

			if (TRUE == ack_to_is_me)
			{
				if (FALSE == is_resend)
				{
					uuid = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_UUID)->val.value.s;

					_LOCK_ACCESS(&network->lock)
					{
						/* get/set sequence number to initialize acknowledgement indicator correctly */
						np_ackentry_t *ackentry = NULL;

						if (NULL != np_tree_find_str(network->waiting, uuid))
						{
							ackentry = (np_ackentry_t*) np_tree_find_str(network->waiting, uuid)->val.value.v;
						}
						else
						{
							ackentry = _np_network_get_new_ackentry();
						}

						ackentry->acked = FALSE;
						ackentry->transmittime = ev_time();
						// + 1.0 because of time delays for processing
						ackentry->expiration = ackentry->transmittime + args->properties->msg_ttl + 1.0;
						if(ackentry->dest_key != args->target) {
							np_ref_obj(np_key_t, args->target, ref_message_ack);
							ackentry->dest_key = args->target;
						}

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

						np_tree_insert_str(network->waiting, uuid, np_treeval_new_v(ackentry));
						log_debug_msg(LOG_DEBUG, "ack handling (%p) requested for msg uuid: %s", network->waiting, uuid);
					}
				}

				// insert a record into the priority queue with the following information:
				double retransmit_interval = args->properties->msg_ttl / args->properties->retry;
				np_msgproperty_t* out_prop = np_msgproperty_get(OUTBOUND, args->properties->msg_subject);
				_np_job_resubmit_route_event(retransmit_interval, out_prop, args->target, args->msg);
			}

			// char* subj = np_tree_find_str(msg_out->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
			// log_debug_msg(LOG_DEBUG, "message %s (%u) to %s", subj, seq, key_get_as_string(args->target));
			// log_debug_msg(LOG_DEBUG, "message part byte sizes: %lu %lu %lu %lu %lu, total: %lu",
			// 			msg_out->header->byte_size, msg_out->instructions->byte_size,
			// 			msg_out->properties->byte_size, msg_out->body->byte_size,
			// 			msg_out->footer->byte_size,
			// 			msg_out->header->byte_size + msg_out->instructions->byte_size + msg_out->properties->byte_size + msg_out->body->byte_size + msg_out->footer->byte_size);

			// TODO: do this serialization in parallel in background
			np_jobargs_t chunk_args = { .msg = msg_out };

			// np_print_tree (msg_out->body, 0);
			if (TRUE == is_forward)
			{
				_np_message_serialize(&chunk_args);
			}
			else
			{
				_np_message_serialize_chunked(&chunk_args);
			}
			log_debug_msg(LOG_DEBUG, "Try sending message %s for subject \"%s\" to %s", msg_out->uuid, prop->msg_subject, _np_key_as_str(args->target));

			_np_network_send_msg(args->target, msg_out);
			// ret is 1 or 0
			// np_node_update_stat(args->target->node, send_ok);
			np_unref_obj(np_network_t,network,"np_waitref_network");
		}
		np_unref_obj(np_key_t,my_key,"np_waitref_key");
	}
}

void _np_send_handshake(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_send_handshake(np_jobargs_t* args){");

	if (!_np_node_check_address_validity(args->target->node)) return;

	// get our node identity from the cache
	np_aaatoken_t* my_id_token = _np_state()->my_node_key->aaa_token;
	// np_node_t* my_node = _np_state()->my_node_key->node;

	// convert to curve key
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_id_token->private_key);
	// calculate session key for dh key exchange
	unsigned char my_dh_sessionkey[crypto_scalarmult_BYTES] = { 0 };
	crypto_scalarmult_base(my_dh_sessionkey, curve25519_sk);

	// create handshake data
	np_tree_t* hs_data = np_tree_create();
	
	//	Required informations in this MSG
	//	 protocol
	//	 protocol-connection informations
	//		currently:
	//		- dns_name
	//		- port
	//	 expiration
	//	 issued_at
	//	 session key
	//	 public key
	//	 signature(fingerprint?) of full aaatoken
	//
	// -> will be hashed and this then signed

	np_tree_insert_str(hs_data, "_np.session", np_treeval_new_bin(my_dh_sessionkey, crypto_scalarmult_BYTES));	

	np_aaatoken_encode(hs_data, my_id_token);
	
	// pre-serialize handshake data
	cmp_ctx_t cmp;
	unsigned char hs_payload[65536] = { 0 };
	void* hs_buf_ptr = hs_payload;

	cmp_init(&cmp, hs_buf_ptr, _np_buffer_reader, _np_buffer_writer);

	_np_tree_serialize(hs_data, &cmp);
	uint32_t hs_payload_len = cmp.buf-hs_buf_ptr;

	np_tree_free(hs_data);

	// sign the handshake payload with our private key
	char signature[crypto_sign_BYTES] = { 0 };
	unsigned long long siglen = 0;
	// uint32_t signature_len;
	int16_t ret = crypto_sign_detached(
			(unsigned char*) signature,
			&siglen,
			(const unsigned char*) hs_payload,
			hs_payload_len,
		  my_id_token->private_key
		 );
	if (ret < 0)
	{
		log_msg(LOG_WARN, "signature creation failed, not continuing with handshake");
		return;
	}
#ifdef DEBUG
	log_debug_msg(LOG_DEBUG, "signature has %"PRIu32" bytes", crypto_sign_BYTES);
	char* signature_hex = calloc(1, crypto_sign_BYTES * 2 + 1);
	sodium_bin2hex(signature_hex, crypto_sign_BYTES * 2 + 1,
		signature, crypto_sign_BYTES);
	log_debug_msg(LOG_DEBUG, "signature: (payload size: %5"PRIu32") %s", hs_payload_len, signature_hex);
	free(signature_hex);
#endif


	// create real handshake message ...
	np_message_t* hs_message = NULL;
	np_new_obj(np_message_t, hs_message);
	np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _NP_MSG_HANDSHAKE);

	np_tree_insert_str(hs_message->header,			_NP_MSG_HEADER_SUBJECT,	np_treeval_new_s(_NP_MSG_HANDSHAKE));
	np_tree_insert_str(hs_message->header, 			_NP_MSG_HEADER_FROM,	np_treeval_new_s((char*) _np_key_as_str(_np_state()->my_node_key)));
	np_tree_insert_str(hs_message->instructions, 	_NP_MSG_INST_PARTS, 	np_treeval_new_iarray(1, 1));
	np_tree_insert_str(hs_message->instructions, 	_NP_MSG_INST_ACK,		np_treeval_new_ush(prop->ack_mode));
	np_tree_insert_str(hs_message->instructions, 	_NP_MSG_INST_TTL, 		np_treeval_new_d(prop->token_max_ttl+0.0));
	np_tree_insert_str(hs_message->instructions, 	_NP_MSG_INST_TSTAMP, 	np_treeval_new_d((double) ev_time()));


	// ... add signature and payload to this message
	np_tree_insert_str(hs_message->body, NP_HS_SIGNATURE,
			np_treeval_new_bin(signature, siglen));
	np_tree_insert_str(hs_message->body, NP_HS_PAYLOAD,
			np_treeval_new_bin(hs_payload, (uint32_t) hs_payload_len));

	// TODO: do this serialization in parallel in background
	_np_message_calculate_chunking(hs_message);

	np_jobargs_t* chunk_args = _np_job_create_args(hs_message, NULL, NULL);

	np_bool serialize_ok = _np_message_serialize_chunked(chunk_args);

	if (hs_message->is_single_part == FALSE || hs_message->no_of_chunks != 1) {
		log_msg(LOG_ERROR, "HANDSHAKE MESSAGE IS NOT 1024 BYTES IN SIZE! Message will be ignored from other nodes in the network");
	}

	_np_job_free_args(chunk_args);

	if (TRUE == serialize_ok)
	{
		_LOCK_MODULE(np_network_t)
		{
			if (NULL == args->target->network)
			{
				// initialize network
				np_new_obj(np_network_t, args->target->network);
				_np_network_init(args->target->network,
							 FALSE,
							 args->target->node->protocol,
							 args->target->node->dns_name,
							 args->target->node->port);
				if (FALSE == args->target->network->initialized)
				{
					np_unref_obj(np_message_t, hs_message, ref_obj_creation);
					log_debug_msg(LOG_DEBUG, "Setting handshake unknown");
					args->target->node->handshake_status = HANDSHAKE_UNKNOWN;
					return;
				}

				np_ref_obj(np_key_t, args->target,ref_network_watcher);
				args->target->network->watcher.data = args->target;
			}
		}
		// construct target address and send it out
		np_node_t* hs_node = args->target->node;

		/* send data if handshake status is still just initialized or less */
		log_debug_msg(LOG_DEBUG,
				"sending handshake message %s to (%s:%s)",
				hs_message->uuid, hs_node->dns_name, hs_node->port);

		char* packet = (char*) malloc(1024);
		CHECK_MALLOC(packet);

		memset(packet, 0, 1024);
		_LOCK_ACCESS(&hs_message->msg_chunks_lock){
			memcpy(packet, pll_first(hs_message->msg_chunks)->val->msg_part, 984);
		}

		_LOCK_ACCESS(&args->target->network->lock)
		{
			if(NULL != args->target->network->out_events) {
				sll_append(
						void_ptr,
						args->target->network->out_events,
						(void*) packet);
			} else {
				free (packet);
			}
		}
	}
	np_unref_obj(np_message_t, hs_message,ref_obj_creation);
}

void _np_send_discovery_messages(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_send_discovery_messages(np_jobargs_t* args){");
	np_aaatoken_t* msg_token = NULL;

	double now = ev_time();
	msg_token = _np_aaatoken_get_local_mx(args->properties->msg_subject);

	if ( ( NULL == msg_token ) ||
		 ( /* = lifetime */ (now - msg_token->issued_at ) >=
		   /* random time = */ (args->properties->token_min_ttl) ) )
	{
		log_msg(LOG_INFO | LOG_AAATOKEN, "---------- refresh for subject token: %s ----------", args->properties->msg_subject);
		log_debug_msg(LOG_DEBUG, "creating new token for subject %s", args->properties->msg_subject);
		np_aaatoken_t* msg_token_new  = _np_create_msg_token(args->properties);
		np_unref_obj(np_aaatoken_t, msg_token,"_np_aaatoken_get_local_mx");
		_np_aaatoken_add_local_mx(msg_token_new->subject, msg_token_new);
		msg_token = msg_token_new;
		ref_replace_reason(np_aaatoken_t, msg_token, ref_obj_creation,"_np_aaatoken_get_local_mx")
	}

	// args->target == Key of subject

	if (0 < (args->properties->mode_type & INBOUND))
	{
		log_debug_msg(LOG_DEBUG, ".step ._np_send_discovery_messages.inbound");

		np_tree_find_str(msg_token->extensions, "msg_threshold")->val.value.ui = args->properties->msg_threshold;

		log_debug_msg(LOG_DEBUG, "encoding token for subject %p / %s", msg_token, msg_token->uuid);
		np_tree_t* _data = np_tree_create();
		np_aaatoken_encode(_data, msg_token);

		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		_np_message_create(
				msg_out,
				args->target,
				_np_state()->my_node_key,
				_NP_MSG_DISCOVER_SENDER,
				_data
		);

		// send message availability
		np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_DISCOVER_SENDER);
		_np_job_submit_route_event(0.0, prop_route, args->target, msg_out);

		np_unref_obj(np_message_t, msg_out, ref_obj_creation);
	}

	if (0 < (args->properties->mode_type & OUTBOUND))
	{
		log_debug_msg(LOG_DEBUG, ".step ._np_send_discovery_messages.outbound");

		np_tree_find_str(msg_token->extensions, "msg_threshold")->val.value.ui = args->properties->msg_threshold;

		log_debug_msg(LOG_DEBUG, "encoding token for subject %p / %s", msg_token, msg_token->uuid);

		np_tree_t* _data = np_tree_create();
		np_aaatoken_encode(_data, msg_token);

		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);

		_np_message_create(
				msg_out,
				args->target,
				_np_state()->my_node_key,
				_NP_MSG_DISCOVER_RECEIVER,
				_data
		);
		// send message availability
		np_msgproperty_t* prop_route =
				np_msgproperty_get(
						OUTBOUND,
						_NP_MSG_DISCOVER_RECEIVER
				);
		_np_job_submit_route_event(0.0, prop_route, args->target, msg_out);
		np_unref_obj(np_message_t, msg_out, ref_obj_creation);
	}

	np_unref_obj(np_aaatoken_t, msg_token,"_np_aaatoken_get_local_mx");
}

// deprecated
void _np_send_receiver_discovery(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_send_receiver_discovery(np_jobargs_t* args){");
	// create message interest in authentication request
	np_aaatoken_t* msg_token = NULL;

	msg_token = _np_aaatoken_get_sender(args->properties->msg_subject,
									 _np_key_as_str(_np_state()->my_identity));

	if (NULL == msg_token)
	{
		log_debug_msg(LOG_DEBUG, "creating new sender token for subject %s", args->properties->msg_subject);
		np_aaatoken_t* msg_token_new = _np_create_msg_token(args->properties);
		np_ref_obj(np_aaatoken_t, msg_token_new); // usage ref
		_np_aaatoken_add_sender(msg_token_new->subject, msg_token_new);
		msg_token = msg_token_new;
		ref_replace_reason(np_aaatoken_t, msg_token, ref_obj_creation,"_np_aaatoken_get_sender")
	}

	np_tree_t* _data = np_tree_create();
	np_aaatoken_encode(_data, msg_token);

	np_message_t* msg_out = NULL;
	np_new_obj(np_message_t, msg_out);
	_np_message_create(msg_out, args->target, _np_state()->my_node_key, _NP_MSG_DISCOVER_RECEIVER, _data);
	// send message availability
	np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_DISCOVER_RECEIVER);
	_np_job_submit_route_event(0.0, prop_route, args->target, msg_out);
	np_unref_obj(np_message_t, msg_out,ref_obj_creation);

	np_unref_obj(np_aaatoken_t, msg_token,"_np_aaatoken_get_sender");
}

// deprecated
void _np_send_sender_discovery(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_send_sender_discovery(np_jobargs_t* args){");
	// create message interest in authentication request
	np_aaatoken_t* msg_token = NULL;

	msg_token = _np_aaatoken_get_receiver(args->properties->msg_subject, NULL);

	if (NULL == msg_token)
	{
		log_debug_msg(LOG_DEBUG, "creating new receiver token for subject %s", args->properties->msg_subject);
		np_aaatoken_t* msg_token_new = _np_create_msg_token(args->properties);
		np_ref_obj(np_aaatoken_t, msg_token_new); // usage ref
		_np_aaatoken_add_receiver(msg_token_new->subject, msg_token_new);
		msg_token = msg_token_new;
	}

	log_debug_msg(LOG_DEBUG, "encoding receiver token for subject %p / %s", msg_token, msg_token->uuid);
	np_tree_t* _data = np_tree_create();
	np_aaatoken_encode(_data, msg_token);

	np_message_t* msg_out = NULL;
	np_new_obj(np_message_t, msg_out);
	_np_message_create(msg_out, args->target, _np_state()->my_node_key, _NP_MSG_DISCOVER_SENDER, _data);

	// send message availability
	np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_DISCOVER_SENDER);
	_np_job_submit_route_event(0.0, prop_route, args->target, msg_out);

	np_unref_obj(np_message_t, msg_out,ref_obj_creation);

	np_unref_obj(np_aaatoken_t, msg_token, "_np_aaatoken_get_receiver");
}

void _np_send_authentication_request(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_send_authentication_request(np_jobargs_t* args){");

	np_state_t* state = _np_state();
	np_dhkey_t target_dhkey;

	if (0 < strlen(args->target->aaa_token->realm))
	{
		target_dhkey = np_dhkey_create_from_hostport(args->target->aaa_token->realm, "0");
	}
	else if (0 < strlen(state->my_identity->aaa_token->realm) )
	{
		// TODO: this is wrong, it should be the token issuer which we ask for authentication
		target_dhkey = np_dhkey_create_from_hostport(state->my_identity->aaa_token->realm, "0");
	}
	else
	{
		return;
	}

	log_debug_msg(LOG_DEBUG, "encoding and sending authentication token");

	np_key_t* aaa_target = NULL;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->dhkey = target_dhkey;

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHENTICATION_REQUEST);

	// create and send authentication request
	np_message_t* msg_out = NULL;
	np_new_obj(np_message_t, msg_out);

	np_tree_t* auth_data = np_tree_create();
	np_aaatoken_encode(auth_data, args->target->aaa_token);

//	log_debug_msg(LOG_DEBUG, "realm             : %s", args->target->aaa_token->realm);
//	log_debug_msg(LOG_DEBUG, "issuer            : %s", args->target->aaa_token->issuer);
//	log_debug_msg(LOG_DEBUG, "subject           : %s", args->target->aaa_token->subject);
//	log_debug_msg(LOG_DEBUG, "audience          : %s", args->target->aaa_token->audience);
//	log_debug_msg(LOG_DEBUG, "uuid              : %s", args->target->aaa_token->uuid);

	_np_message_create(msg_out, aaa_target, state->my_node_key, _NP_MSG_AUTHENTICATION_REQUEST, auth_data);
	if (FALSE == _np_send_msg(_NP_MSG_AUTHENTICATION_REQUEST, msg_out, aaa_props, NULL))
	{
		log_debug_msg(LOG_DEBUG, "sending authentication discovery");
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_send_receiver_discovery(&jargs);
	}
	np_unref_obj(np_message_t, msg_out,ref_obj_creation);

	np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
}

void _np_send_authentication_reply(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_send_authentication_reply(np_jobargs_t* args){");

	np_dhkey_t target_dhkey;

	np_msg_mep_type mep_reply_sticky = np_tree_find_str(args->target->aaa_token->extensions, "mep_type")->val.value.ul & STICKY_REPLY;

	if (STICKY_REPLY != mep_reply_sticky &&
		0 < strlen(args->target->aaa_token->realm) )
	{
		target_dhkey = np_dhkey_create_from_hostport(args->target->aaa_token->realm, "0");
	}
	else
	{
		target_dhkey = np_dhkey_create_from_hash(args->target->aaa_token->issuer);
	}

	log_debug_msg(LOG_DEBUG, "encoding and sending authentication reply");

	np_key_t* aaa_target = NULL;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->dhkey = target_dhkey;

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHENTICATION_REPLY);

	// create and send authentication reply
	if (FALSE == _np_send_msg(_NP_MSG_AUTHENTICATION_REPLY, args->msg, aaa_props, NULL))
	{
		log_debug_msg(LOG_DEBUG, "sending authentication reply discovery");
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_send_receiver_discovery(&jargs);
	}
	np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
}

void _np_send_authorization_request(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_send_authorization_request(np_jobargs_t* args){");

	np_state_t* state = _np_state();
	np_dhkey_t target_dhkey;

	if (0 < strlen(state->my_identity->aaa_token->realm) )
	{
		target_dhkey = np_dhkey_create_from_hostport(state->my_identity->aaa_token->realm, "0");
	}
	else
	{
		return;
	}

	log_debug_msg(LOG_DEBUG, "encoding and sending authorization token");
	np_key_t* aaa_target = NULL;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->dhkey = target_dhkey;

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHORIZATION_REQUEST);

	// create and and send authorization request
	np_message_t* msg_out = NULL;
	np_new_obj(np_message_t, msg_out);
	np_tree_t* auth_data = np_tree_create();
	np_aaatoken_encode(auth_data, args->target->aaa_token);

//	log_debug_msg(LOG_DEBUG, "realm             : %s", args->target->aaa_token->realm);
//	log_debug_msg(LOG_DEBUG, "issuer            : %s", args->target->aaa_token->issuer);
//	log_debug_msg(LOG_DEBUG, "subject           : %s", args->target->aaa_token->subject);
//	log_debug_msg(LOG_DEBUG, "audience          : %s", args->target->aaa_token->audience);
//	log_debug_msg(LOG_DEBUG, "uuid              : %s", args->target->aaa_token->uuid);

	_np_message_create(msg_out, aaa_target, state->my_node_key, _NP_MSG_AUTHORIZATION_REQUEST, auth_data);
	if (FALSE == _np_send_msg(_NP_MSG_AUTHORIZATION_REQUEST, msg_out, aaa_props, NULL))
	{
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_send_receiver_discovery(&jargs);
	}
	np_unref_obj(np_message_t, msg_out,ref_obj_creation);
	np_unref_obj(np_key_t, aaa_target, ref_obj_creation);
}

void _np_send_authorization_reply(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_send_authorization_reply(np_jobargs_t* args){");

	np_dhkey_t target_dhkey;

	np_msg_mep_type mep_reply_sticky = np_tree_find_str(args->target->aaa_token->extensions, "mep_type")->val.value.ul & STICKY_REPLY;

	if (STICKY_REPLY != mep_reply_sticky &&
		0 < strlen(args->target->aaa_token->realm) )
	{
		target_dhkey = np_dhkey_create_from_hostport(args->target->aaa_token->realm, "0");
	}
	else
	{
		target_dhkey = np_dhkey_create_from_hash(args->target->aaa_token->issuer);
	}

	log_debug_msg(LOG_DEBUG, "encoding and sending authorization reply");

	np_key_t* aaa_target = NULL;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->dhkey = target_dhkey;

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHORIZATION_REPLY);

	// create and send authentication reply
	if (FALSE == _np_send_msg(_NP_MSG_AUTHORIZATION_REPLY, args->msg, aaa_props, NULL))
	{
		log_debug_msg(LOG_DEBUG, "sending authorization reply discovery");
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_send_receiver_discovery(&jargs);
	}
	np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
}

void _np_send_accounting_request(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_send_accounting_request(np_jobargs_t* args){");

	np_state_t* state = _np_state();
	np_dhkey_t target_dhkey;

	if (0 < strlen(state->my_identity->aaa_token->realm) )
	{
		target_dhkey = np_dhkey_create_from_hostport(state->my_identity->aaa_token->realm, "0");
	}
	else
	{
		return;
	}

	log_debug_msg(LOG_DEBUG, "encoding and sending accounting token");
	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_ACCOUNTING_REQUEST);

	np_key_t* aaa_target = NULL;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->dhkey = target_dhkey;

	// create and and send authentication request
	np_message_t* msg_out = NULL;
	np_new_obj(np_message_t, msg_out);

	np_tree_t* auth_data = np_tree_create();
	np_aaatoken_encode(auth_data, args->target->aaa_token);
	_np_message_create(msg_out, aaa_target, state->my_node_key, _NP_MSG_ACCOUNTING_REQUEST, auth_data);

	if (FALSE == _np_send_msg(_NP_MSG_ACCOUNTING_REQUEST, msg_out, aaa_props, NULL))
	{
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_send_receiver_discovery(&jargs);
	}
	np_unref_obj(np_message_t, msg_out,ref_obj_creation);

	np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
}

void _np_send_simple_invoke_request(np_key_t* target, const char* type) {
	log_msg(LOG_TRACE, "start: void _np_send_simple_invoke_request(np_key_t* target, const char* type) {");

	np_state_t* state = _np_state();

	np_tree_t* jrb_me = np_tree_create();
	np_aaatoken_encode(jrb_me, state->my_identity->aaa_token);

	np_message_t* msg_out = NULL;
	np_new_obj(np_message_t, msg_out);
	_np_message_create(msg_out, target, state->my_node_key, type , jrb_me);

	log_debug_msg(LOG_DEBUG, "submitting join request to target key %s", _np_key_as_str(target));
	np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, type);
	_np_job_submit_msgout_event(0.0, prop, target, msg_out);

	np_unref_obj(np_message_t, msg_out,ref_obj_creation);
}
