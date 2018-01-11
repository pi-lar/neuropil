//
// neuropil is copyright 2016-2017 by pi-lar GmbH
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

#include "np_log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_event.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_message.h"
#include "np_memory_v2.h"
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
#include "np_ackentry.h"
#include "np_serialization.h"

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


void __np_axon_invoke_on_user_send_callbacks(np_message_t* msg_out, np_msgproperty_t* prop)
{
	if (msg_out->msg_property == NULL) {
		np_ref_obj(np_msgproperty_t, prop, ref_message_msg_property);
		msg_out->msg_property = prop;
	}
	// Call user handler for send msgs
	sll_iterator(np_usercallback_t) iter_usercallbacks = sll_first(prop->user_send_clb);
	while (iter_usercallbacks != NULL)
	{
		iter_usercallbacks->val(msg_out, ((msg_out == NULL) ? NULL : msg_out->properties), ((msg_out==NULL) ? NULL : msg_out->body));
		sll_next(iter_usercallbacks);
	}
}

/**
 ** _np_network_send_msg: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void _np_out_ack(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_send_ack(np_jobargs_t* args){");

	np_tree_elem_t* target_uuid = np_tree_find_str(args->msg->instructions, _NP_MSG_INST_ACKUUID);

	double now = np_time_now();
	np_tree_insert_str(args->msg->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(args->properties->ack_mode));
	np_tree_insert_str(args->msg->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(args->properties->msg_ttl));
	np_tree_insert_str(args->msg->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d(now));
	np_tree_insert_str(args->msg->instructions, _NP_MSG_INST_UUID, np_treeval_new_s(args->msg->uuid));
	np_tree_insert_str(args->msg->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(1, 1));
	np_tree_insert_str(args->msg->instructions, _NP_MSG_INST_SEND_COUNTER, np_treeval_new_ush(0));
	np_tree_elem_t* jrb_send_counter = np_tree_find_str(args->msg->instructions, _NP_MSG_INST_SEND_COUNTER);
	jrb_send_counter->val.value.ush++;

	// chunking for 1024 bit message size
	_np_message_calculate_chunking(args->msg);
	_np_message_serialize_chunked(args->msg);
	np_bool send_ok = _np_network_send_msg(args->target, args->msg);
	if(send_ok) {
		__np_axon_invoke_on_user_send_callbacks(args->msg, np_msgproperty_get(OUTBOUND, _NP_MSG_ACK));
	} else {
		log_msg(LOG_ERROR, "ACK_HANDLING sending of ack message (%s) to %s:%s failed", target_uuid->val.value.s,
				args->target->node->dns_name, args->target->node->port);
	}
}

/**
 ** _np_network_send_msg: host, data, size
 ** Sends a message to host, updating the measurement info.
 **/
void _np_out(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_out(np_jobargs_t* args){");

	uint32_t seq = 0;
	np_message_t* msg_out = args->msg;

	np_bool is_resend = args->is_resend;
	np_bool is_forward = msg_out->is_single_part;
	np_bool ack_to_is_me = FALSE;
	np_bool ack_mode_from_msg = FALSE;

	uint8_t ack_mode = ACK_NONE;
	char* uuid = NULL;

	np_msgproperty_t* prop = args->properties;

	// set msgproperty of msg 
	if (msg_out != NULL && prop != NULL) {
		np_ref_switch(np_msgproperty_t, msg_out->msg_property, ref_message_msg_property, prop);
	}

	// sanity check
	if (!_np_node_check_address_validity(args->target->node) &&
		 args->target->node->joined_network)
	{
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "attempt to send to an invalid node (key: %s)",
			_np_key_as_str(args->target));
		return;
	}

	// now we can try to send the msg
	np_waitref_obj(np_key_t, _np_state()->my_node_key, my_key,"np_waitref_key");
	{
		np_waitref_obj(np_network_t, my_key->network, my_network,"np_waitref_network");
		{
			// check ack indicator if this is a resend of a message
			if (TRUE == is_resend)
			{
				uuid = msg_out->uuid;
				np_bool skip = FALSE;

				_LOCK_ACCESS(&my_network->waiting_lock)
				{
					// first find the uuid
					np_tree_elem_t* uuid_ele = np_tree_find_str(my_network->waiting, uuid);
					if (NULL == uuid_ele)
					{
						// has been deleted already
						log_debug_msg(LOG_DEBUG, "ACK_HANDLING message %s (%s) assumed acknowledged, not resending ...", prop->msg_subject, uuid);
						skip = TRUE;
					}
					else if (TRUE == ((np_ackentry_t*)uuid_ele->val.value.v)->has_received_ack)
					{
						// uuid has been acked
						log_debug_msg(LOG_DEBUG, "ACK_HANDLING message %s (%s) acknowledged (ACK), not resending ...", prop->msg_subject, uuid);
						skip = TRUE;
					}
					else
					{
						// ack indicator still there ! initiate resend ...
						np_ackentry_t* entry = uuid_ele->val.value.v;
						if (_np_dhkey_comp(&entry->dest_key->dhkey, &args->target->dhkey) != 0) {
							// switch dest_key if routing is now pointing to a different key
							np_ref_switch(np_key_t, entry->dest_key, ref_ack_key, args->target);
							entry->dest_key = args->target;
						}
						log_msg(LOG_INFO, "ACK_HANDLING message %s (%s) not acknowledged, resending ...", prop->msg_subject, uuid);
					}
				}
				// TODO: ref counting on ack may differ (ref_message_ack) / key may not be the same more
				if (TRUE == skip) {
					np_unref_obj(np_network_t, my_network, "np_waitref_network");
					np_unref_obj(np_key_t, my_key, "np_waitref_key");
					return;
				}

				double initial_tstamp = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_TSTAMP)->val.value.d;
				uint8_t msg_resendcounter = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_SEND_COUNTER)->val.value.ush;
				double now = np_time_now();

				if (now > (initial_tstamp + args->properties->msg_ttl) || msg_resendcounter > 31)
				{
					log_debug_msg(LOG_ROUTING | LOG_MESSAGE | LOG_DEBUG, "resend message %s (%s) expired, not resending ...", prop->msg_subject, uuid);

					np_unref_obj(np_network_t, my_network, "np_waitref_network");
					np_unref_obj(np_key_t, my_key, "np_waitref_key");
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

			if (ACK_EACHHOP == (ack_mode & ACK_EACHHOP))
			{
				// we have to reset the existing ack_to field in case of forwarding and each-hop acknowledge
				np_tree_replace_str(msg_out->instructions, _NP_MSG_INST_ACK_TO, np_treeval_new_s(ack_to_str));
				ack_to_is_me = TRUE;
			}
			else if (ACK_DESTINATION == (ack_mode & ACK_DESTINATION) || ACK_CLIENT == (ack_mode & ACK_CLIENT))
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
				_LOCK_ACCESS(&my_network->send_data_lock)
				{
					/* get/set sequence number to keep increasing sequence numbers per node */
					seq = my_network->seqend;
					np_tree_replace_str(msg_out->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(seq));
					my_network->seqend++;
				}
			}

			// insert a uuid if not yet present
			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_UUID, np_treeval_new_s(msg_out->uuid));

			// set re-send count to zero if not yet present
			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_SEND_COUNTER, np_treeval_new_ush(0));
			// and increase resend count by one
			// TODO: forwarding of message will also increase re-send counter, ok ?
			np_tree_elem_t* jrb_send_counter = np_tree_find_str(msg_out->instructions, _NP_MSG_INST_SEND_COUNTER);
			jrb_send_counter->val.value.ush++;
			// TODO: insert resend count check

			// insert timestamp and time-to-live
			double now = np_time_now();
			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d(now));
			// now += args->properties->ttl;
			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(args->properties->msg_ttl));

			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(1, 1));
			if (FALSE == msg_out->is_single_part)
			{
				_np_message_calculate_chunking(msg_out);
			}

			np_bool reschedule_msg_transmission = FALSE;

			if (TRUE == ack_to_is_me)
			{
				if (FALSE == is_resend)
				{
					uuid = np_treeval_to_str(np_tree_find_str(msg_out->instructions, _NP_MSG_INST_UUID)->val, NULL);

					np_ackentry_t *ackentry = NULL;
					// get/set sequence number to initialize acknowledgement indicator correctly
					np_new_obj(np_ackentry_t, ackentry, ref_ack_obj);

					ackentry->send_at = np_time_now();
					ackentry->expires_at = ackentry->send_at + args->properties->msg_ttl + np_msgproperty_get(INBOUND, _NP_MSG_ACK)->msg_ttl;
					ackentry->dest_key = args->target;
					np_ref_obj(np_key_t, ackentry->dest_key, ref_ack_key);

					if (sll_size(args->msg->on_ack) > 0 ||
						sll_size(args->msg->on_timeout) > 0) {
						ackentry->msg = args->msg;
						np_ref_obj(np_message_t, ackentry->msg, ref_ack_msg);
					}
					// ackentry->expected_ack = 1; // msg_out->no_of_chunks ?
					log_debug_msg(LOG_DEBUG, "initial sending of message (%s/%s) with acknowledge",
											 args->properties->msg_subject, args->msg->uuid);

#ifdef DEBUG
					CHECK_STR_FIELD(args->msg->header, _NP_MSG_HEADER_TO, msg_to);
					{
						log_debug_msg(LOG_DEBUG, "ACK_HANDLING                   message (%s/%s) %s < - > %s / %d:%s:%s",
								uuid, args->properties->msg_subject,
								args->target->dhkey_str, msg_to.value.s,
								args->target->node->joined_network, args->target->node->dns_name, args->target->node->port);
					}
					__np_cleanup__:
						{}
#endif

					_LOCK_ACCESS(&my_network->waiting_lock)
					{
						np_tree_insert_str(my_network->waiting, uuid, np_treeval_new_v(ackentry));
					}
					// log_msg(LOG_ERROR, "ACK_HANDLING ack handling requested for msg uuid: %s/%s", uuid, args->properties->msg_subject);
					log_debug_msg(LOG_ROUTING | LOG_MESSAGE | LOG_DEBUG, "ack handling (%p) requested for msg uuid: %s", my_network->waiting, uuid);
				}
				reschedule_msg_transmission = TRUE;
			}

			np_jobargs_t chunk_args = { .msg = msg_out };

			if (TRUE == is_forward)
			{
				_np_message_serialize_header_and_instructions(&chunk_args);
			}
			else
			{
				_np_message_serialize_chunked(msg_out);
			}

			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "Try sending message for subject \"%s\" (msg id: %s) to %s", prop->msg_subject, msg_out->uuid, _np_key_as_str(args->target));

			np_bool send_completed = _np_network_send_msg(args->target, msg_out);

			if(send_completed == TRUE) {
				__np_axon_invoke_on_user_send_callbacks(msg_out, msg_out->msg_property);
			}

			if (send_completed == FALSE || (args->properties->retry > 0 && reschedule_msg_transmission == TRUE) ) {
				double retransmit_interval = args->properties->msg_ttl / (args->properties->retry+1);
				// np_msgproperty_t* out_prop = np_msgproperty_get(OUTBOUND, args->properties->msg_subject);
				if (send_completed == FALSE && reschedule_msg_transmission == FALSE) {
					log_msg(LOG_WARN, "np_network returned error, and no re-sending of message (%s) has been scheduled", args->msg->uuid);
					// todo: define behaviour first
					// _np_job_resubmit_msgout_event(retransmit_interval, out_prop, args->target, args->msg);
				}
				else {
					_np_job_resubmit_route_event(retransmit_interval, args->properties, args->target, args->msg);
					log_debug_msg(LOG_DEBUG, "ACK_HANDLING re-sending of message (%s) scheduled", args->msg->uuid);
				}
			}			

			np_unref_obj(np_network_t, my_network,"np_waitref_network");
		}
		np_unref_obj(np_key_t,my_key,"np_waitref_key");
	}
}

void _np_out_handshake(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_out_handshake(np_jobargs_t* args){");

	_LOCK_MODULE(np_handshake_t) 
	{
		
		if (_np_node_check_address_validity(args->target->node))
		{
			// get our node identity from the cache
			np_key_t* my_key = _np_state()->my_node_key;
			np_aaatoken_t* my_token = my_key->aaa_token;

			// TODO: reffing of key, node token in function context

			// convert to curve key
			unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
			crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_token->private_key);
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
			//	 expires_at
			//	 issued_at
			//	 session key
			//	 public key
			//	 signature(fingerprint?) of full aaatoken
			//
			// -> will be hashed and this then signed

			np_tree_insert_str(hs_data, "_np.session", np_treeval_new_bin(my_dh_sessionkey, crypto_scalarmult_BYTES));

			np_aaatoken_core_encode(hs_data, my_token, TRUE);
			_np_node_encode_to_jrb(hs_data, my_key, FALSE);

			// pre-serialize handshake data
			cmp_ctx_t cmp;
			unsigned char hs_payload[65536] = { 0 };
			void* hs_buf_ptr = hs_payload;

			cmp_init(&cmp, hs_buf_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);

			np_tree_serialize(hs_data, &cmp);
			uint32_t hs_payload_len = cmp.buf - hs_buf_ptr;

			np_tree_free(hs_data);

			// sign the handshake payload with our private key
			unsigned char signature[crypto_sign_BYTES] = { 0 };
			unsigned long long siglen = 0;
			// uint32_t signature_len;
			int16_t ret = crypto_sign_detached(
				(unsigned char*)signature,
				&siglen,
				(const unsigned char*)hs_payload,
				hs_payload_len,
				my_token->private_key
			);
			if (ret < 0)
			{
				log_msg(LOG_WARN, "signature creation failed, not continuing with handshake");
				_np_threads_unlock_module(np_handshake_t_lock);
				return;
			}
#ifdef DEBUG
			log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "signature has %"PRIu32" bytes", crypto_sign_BYTES);
			char* signature_hex = calloc(1, crypto_sign_BYTES * 2 + 1);
			sodium_bin2hex(signature_hex, crypto_sign_BYTES * 2 + 1,
				signature, crypto_sign_BYTES);
			log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "signature: (payload size: %5"PRIu32") %s", hs_payload_len, signature_hex);
			free(signature_hex);
#endif

			// create real handshake message ...
			np_message_t* hs_message = NULL;
			np_new_obj(np_message_t, hs_message);
			np_msgproperty_t* hs_prop = np_msgproperty_get(OUTBOUND, _NP_MSG_HANDSHAKE);

			np_tree_insert_str(hs_message->header, _NP_MSG_HEADER_SUBJECT, np_treeval_new_s(_NP_MSG_HANDSHAKE));
			np_tree_insert_str(hs_message->header, _NP_MSG_HEADER_FROM, np_treeval_new_s((char*)_np_key_as_str(_np_state()->my_node_key)));
			np_tree_insert_str(hs_message->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(1, 1));
			np_tree_insert_str(hs_message->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(hs_prop->ack_mode));
			np_tree_insert_str(hs_message->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(hs_prop->token_max_ttl + 0.0));
			np_tree_insert_str(hs_message->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d((double)np_time_now()));


			// ... add signature and payload to this message
			np_tree_insert_str(hs_message->body, NP_HS_SIGNATURE,
				np_treeval_new_bin(signature, siglen));
			np_tree_insert_str(hs_message->body, NP_HS_PAYLOAD,
				np_treeval_new_bin(hs_payload, (uint32_t)hs_payload_len));

			_np_message_calculate_chunking(hs_message);
		
			np_bool serialize_ok = _np_message_serialize_chunked(hs_message);			

			if (hs_message->no_of_chunks != 1) {
				log_msg(LOG_ERROR, "HANDSHAKE MESSAGE IS NOT 1024 BYTES IN SIZE! Message will not be send");
				np_unref_obj(np_message_t, hs_message, ref_obj_creation);
				_np_threads_unlock_module(np_handshake_t_lock);
				return;
			}

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
							//log_debug_msg(LOG_DEBUG, "Setting handshake unknown");
							//args->target->node->is_handshake_send = HANDSHAKE_UNKNOWN;
							_np_threads_unlock_module(np_handshake_t_lock);
							return;
						}

						np_ref_obj(np_key_t, args->target, ref_network_watcher);
						args->target->network->watcher.data = args->target;
					}
				}
				// construct target address and send it out
				//np_node_t* hs_node = args->target->node;

				/* send data if handshake status is still just initialized or less */
				log_debug_msg(LOG_ROUTING | LOG_DEBUG,
					"sending handshake message %s to %s",// (%s:%s)",
					hs_message->uuid, _np_key_as_str(args->target)/*, hs_node->dns_name, hs_node->port*/);

				char* packet = np_memory_new(np_memory_types_BLOB_1024);

				memset(packet, 0, 1024);
				_LOCK_ACCESS(&hs_message->msg_chunks_lock) {
					memcpy(packet, pll_first(hs_message->msg_chunks)->val->msg_part, 984);
				}

				_LOCK_ACCESS(&args->target->network->send_data_lock)
				{
					if (NULL != args->target->network->out_events) {						
						sll_append(
							void_ptr,
							args->target->network->out_events,
							(void*)packet);
						_np_network_start(args->target->network);
					}
					else {
						np_memory_free(packet);
					}
				}
				__np_axon_invoke_on_user_send_callbacks(hs_message, hs_prop);
			}
			np_unref_obj(np_message_t, hs_message, ref_obj_creation);
		}
	}
}

void _np_out_discovery_messages(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_out_discovery_messages(np_jobargs_t* args){");
	np_aaatoken_t* msg_token = NULL;

	if (_np_route_my_key_has_connection()) {

		double now = np_time_now();

		msg_token = _np_aaatoken_get_local_mx(args->properties->msg_subject);

		if (	NULL == msg_token
			 || _np_aaatoken_is_valid(msg_token) == FALSE
			)
		{
			// Create a new msg token
			log_msg(LOG_INFO | LOG_AAATOKEN, "--- refresh for subject token: %25s --------", args->properties->msg_subject);
			log_debug_msg(LOG_AAATOKEN | LOG_ROUTING | LOG_DEBUG, "creating new token for subject %s", args->properties->msg_subject);
			np_aaatoken_t* msg_token_new = _np_create_msg_token(args->properties);
			np_unref_obj(np_aaatoken_t, msg_token, "_np_aaatoken_get_local_mx");
			_np_aaatoken_add_local_mx(msg_token_new->subject, msg_token_new);
			msg_token = msg_token_new;
			ref_replace_reason(np_aaatoken_t, msg_token, ref_obj_creation, "_np_aaatoken_get_local_mx")
			log_debug_msg(LOG_DEBUG| LOG_AAATOKEN, "--- done refresh for subject token: %25s new token has uuid %s", args->properties->msg_subject, msg_token_new->uuid);
		}
		
		// args->target == Key of subject

		if (INBOUND == (args->properties->mode_type & INBOUND))
		{
			// cleanup of msgs in property receiver msg cache
			_np_msgproperty_cleanup_receiver_cache(args->properties);

			np_tree_find_str(msg_token->extensions, "msg_threshold")->val.value.ui = args->properties->msg_threshold;

			log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding token for subject %p / %s", msg_token, msg_token->uuid);
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
			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop_route->ack_mode));
			_np_job_submit_route_event(0.0, prop_route, args->target, msg_out);

			np_unref_obj(np_message_t, msg_out, ref_obj_creation);
			log_msg(LOG_INFO, "send  INBOUND discovery message for: %s", args->properties->msg_subject);
		}

		if (OUTBOUND == (args->properties->mode_type & OUTBOUND))
		{
			np_tree_find_str(msg_token->extensions, "msg_threshold")->val.value.ui = args->properties->msg_threshold;

			log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding token for subject %p / %s", msg_token, msg_token->uuid);

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
			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop_route->ack_mode));

			_np_job_submit_route_event(0.0, prop_route, args->target, msg_out);
			np_unref_obj(np_message_t, msg_out, ref_obj_creation);

			log_msg(LOG_INFO, "send OUTBOUND discovery message for: %s", args->properties->msg_subject);
		}
		np_unref_obj(np_aaatoken_t, msg_token, "_np_aaatoken_get_local_mx");
	} else {
		log_msg(LOG_INFO, "no connections, no discovery for: %s", args->properties->msg_subject);
	}
}

// deprecated
void _np_out_receiver_discovery(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_out_receiver_discovery(np_jobargs_t* args){");
	// create message interest in authentication request
	np_aaatoken_t* msg_token = NULL;

	msg_token = _np_aaatoken_get_sender(args->properties->msg_subject,
									 _np_key_as_str(_np_state()->my_node_key));

	if (NULL == msg_token)
	{
		log_debug_msg(LOG_ROUTING | LOG_AAATOKEN | LOG_DEBUG, "creating new sender token for subject %s", args->properties->msg_subject);
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

	np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_DISCOVER_RECEIVER);
	_np_message_create(msg_out, args->target, _np_state()->my_node_key, _NP_MSG_DISCOVER_RECEIVER, _data);
	np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop_route->ack_mode));

	// send message availability
	_np_job_submit_route_event(0.0, prop_route, args->target, msg_out);
	np_unref_obj(np_message_t, msg_out,ref_obj_creation);

	np_unref_obj(np_aaatoken_t, msg_token,"_np_aaatoken_get_sender");
}

// deprecated
void _np_out_sender_discovery(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_out_sender_discovery(np_jobargs_t* args){");
	// create message interest in authentication request
	np_aaatoken_t* msg_token = NULL;

	msg_token = _np_aaatoken_get_receiver(args->properties->msg_subject, NULL);

	if (NULL == msg_token)
	{
		log_debug_msg(LOG_ROUTING | LOG_AAATOKEN | LOG_DEBUG, "creating new receiver token for subject %s", args->properties->msg_subject);
		np_aaatoken_t* msg_token_new = _np_create_msg_token(args->properties);
		np_ref_obj(np_aaatoken_t, msg_token_new); // usage ref
		_np_aaatoken_add_receiver(msg_token_new->subject, msg_token_new);
		msg_token = msg_token_new;
	}

	log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding receiver token for subject %p / %s", msg_token, msg_token->uuid);
	np_tree_t* _data = np_tree_create();
	np_aaatoken_encode(_data, msg_token);

	np_message_t* msg_out = NULL;
	np_new_obj(np_message_t, msg_out);
	_np_message_create(msg_out, args->target, _np_state()->my_node_key, _NP_MSG_DISCOVER_SENDER, _data);
	np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_DISCOVER_SENDER);
	np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop_route->ack_mode));

	// send message availability
	_np_job_submit_route_event(0.0, prop_route, args->target, msg_out);

	np_unref_obj(np_message_t, msg_out,ref_obj_creation);

	np_unref_obj(np_aaatoken_t, msg_token, "_np_aaatoken_get_receiver");
}

void _np_out_authentication_request(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_out_authentication_request(np_jobargs_t* args){");

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

	log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding and sending authentication token");

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
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending authentication discovery");
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_out_receiver_discovery(&jargs);
	}
	np_unref_obj(np_message_t, msg_out,ref_obj_creation);

	np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
}

void _np_out_authentication_reply(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_out_authentication_reply(np_jobargs_t* args){");

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

	log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding and sending authentication reply");

	np_key_t* aaa_target = NULL;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->dhkey = target_dhkey;

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHENTICATION_REPLY);

	// create and send authentication reply
	if (FALSE == _np_send_msg(_NP_MSG_AUTHENTICATION_REPLY, args->msg, aaa_props, NULL))
	{
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending authentication reply discovery");
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_out_receiver_discovery(&jargs);
	}
	np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
}

void _np_out_authorization_request(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_out_authorization_request(np_jobargs_t* args){");

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

	log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding and sending authorization token");
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
		_np_out_receiver_discovery(&jargs);
	}
	np_unref_obj(np_message_t, msg_out,ref_obj_creation);
	np_unref_obj(np_key_t, aaa_target, ref_obj_creation);
}

void _np_out_authorization_reply(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_out_authorization_reply(np_jobargs_t* args){");

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

	log_debug_msg(LOG_SERIALIZATION| LOG_DEBUG, "encoding and sending authorization reply");

	np_key_t* aaa_target = NULL;
	np_new_obj(np_key_t, aaa_target);
	aaa_target->dhkey = target_dhkey;

	np_msgproperty_t* aaa_props = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHORIZATION_REPLY);

	// create and send authentication reply
	if (FALSE == _np_send_msg(_NP_MSG_AUTHORIZATION_REPLY, args->msg, aaa_props, NULL))
	{
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending authorization reply discovery");
		np_jobargs_t jargs = { .target = aaa_target, .properties = aaa_props };
		_np_out_receiver_discovery(&jargs);
	}
	np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
}

void _np_out_accounting_request(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_out_accounting_request(np_jobargs_t* args){");

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

	log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "encoding and sending accounting token");
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
		_np_out_receiver_discovery(&jargs);
	}
	np_unref_obj(np_message_t, msg_out,ref_obj_creation);

	np_unref_obj(np_key_t, aaa_target,ref_obj_creation);
}
