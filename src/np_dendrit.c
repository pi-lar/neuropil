//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "sodium.h"
#include "event/ev.h"
#include "msgpack/cmp.h"

#include "np_dendrit.h"

#include "np_axon.h"
#include "np_log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_memory.h"
#include "np_list.h"
#include "np_route.h"
#include "np_util.h"
#include "np_types.h"
#include "np_threads.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "np_axon.h"
#include "np_event.h"
#include "np_constants.h"
#include "np_ackentry.h"
#include "np_serialization.h"

/*
will always call all handlers, but will return false if any of the handlers returns false
*/
np_bool _np_in_invoke_user_receive_callbacks(np_message_t * msg_in, np_msgproperty_t* msg_prop) {
	np_bool ret = TRUE;

	if (msg_in->msg_property == NULL) {
		np_ref_obj(np_msgproperty_t, msg_prop, ref_message_msg_property);
		msg_in->msg_property = msg_prop;
	}

	sll_iterator(np_usercallback_t) iter_usercallbacks = sll_first(msg_prop->user_receive_clb);
	while (iter_usercallbacks != NULL)
	{
		ret = iter_usercallbacks->val(msg_in, msg_in->properties, msg_in->body) && ret;
		sll_next(iter_usercallbacks);
	}
	return ret;
}

/**
 ** message_received:
 ** is called by network_activate and will be passed received data and size from socket
 */
void _np_in_received(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_received(np_jobargs_t* args){");
	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "received msg");
	void* raw_msg = NULL;

	np_state_t* state = _np_state();

	np_waitref_obj(np_key_t, state->my_node_key, my_key,"np_waitref_key");
	{
		np_waitref_obj(np_network_t, my_key->network, my_network,"np_waitref_network");
		{
			np_message_t* msg_in = NULL;
			np_key_t* target_key = NULL;

			int ret;

			// we registered this token info before in the first handshake message
			np_key_t* alias_key = args->target;

			
			raw_msg = args->custom_data;

			if (NULL == raw_msg)
			{
					goto __np_cleanup__;
			}
			log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "alias_key %s", _np_key_as_str(alias_key));

			np_bool is_decryption_successful = FALSE;
			if (NULL != alias_key &&
				NULL != alias_key->aaa_token &&
				IS_VALID (alias_key->aaa_token->state) &&
				alias_key->node->session_key_is_set == TRUE
				)
			{
				log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "/start decrypting message with alias %s", _np_key_as_str(alias_key));
				unsigned char nonce[crypto_secretbox_NONCEBYTES];

				unsigned char dec_msg[1024 - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES];
				memcpy(nonce, raw_msg, crypto_secretbox_NONCEBYTES);

				char nonce_hex[crypto_secretbox_NONCEBYTES*2+1];
				sodium_bin2hex(nonce_hex, crypto_secretbox_NONCEBYTES*2+1, nonce, crypto_secretbox_NONCEBYTES);

				int ret = crypto_secretbox_open_easy(dec_msg,
						(const unsigned char *) raw_msg + crypto_secretbox_NONCEBYTES,
						1024 - crypto_secretbox_NONCEBYTES,
						nonce,
						alias_key->node->session_key);

				if (ret == 0)
				{
					is_decryption_successful = TRUE;
					log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
							"correct decryption of message (send from %s)", _np_key_as_str(alias_key));
					memset(raw_msg, 0, 1024);
					memcpy(raw_msg, dec_msg, 1024 - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);
				}
			}

			np_new_obj(np_message_t, msg_in);
			_np_message_mark_as_incomming(msg_in);

			ret = _np_message_deserialize_header_and_instructions(msg_in, raw_msg);

			if (ret == FALSE) {
				np_memory_free(raw_msg);
				if(is_decryption_successful == TRUE){
					log_msg(LOG_ERROR,
						"error deserializing message %s after   successful decryption (source: \"%s:%s\")",
						msg_in->uuid, np_network_get_ip(alias_key), np_network_get_port(alias_key));
				}
				else {
					log_msg(LOG_WARN,
						"error deserializing message %s after unsuccessful decryption (source: \"%s:%s\")",
						msg_in->uuid, np_network_get_ip(alias_key), np_network_get_port(alias_key));
				}
				goto __np_cleanup__;
			}

			log_debug_msg(LOG_SERIALIZATION | LOG_MESSAGE | LOG_DEBUG,
				"deserialized message %s (source: \"%s:%s\")",
				msg_in->uuid, np_network_get_ip(alias_key), np_network_get_port(alias_key));

			// now read decrypted (or handshake plain text) message
			CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_SUBJECT, msg_subject);
			CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_from);

			np_bool free_msg_from_str = TRUE;
			char * msg_from_str = np_treeval_to_str(msg_from, &free_msg_from_str);
			log_msg(LOG_ROUTING | LOG_INFO, "received message for subject: %s (uuid=%s) from %s",
				np_treeval_to_str(msg_subject,NULL), msg_in->uuid, msg_from_str);

			if (free_msg_from_str == TRUE) {
				free(msg_from_str);
			}

			np_bool is_handshake_msg = 0 == strncmp(np_treeval_to_str(msg_subject, NULL), _NP_MSG_HANDSHAKE, strlen(_NP_MSG_HANDSHAKE));

			if (is_handshake_msg)
			{
				np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, _NP_MSG_HANDSHAKE);
				_np_job_submit_msgin_event(0.0, msg_prop, alias_key, msg_in, NULL);
			}
			else if (is_decryption_successful == FALSE) {
				log_msg(LOG_WARN,
					"incorrect decryption of message (send from %s / %s:%s)",
					_np_key_as_str(alias_key), np_network_get_ip(alias_key),
					np_network_get_port(alias_key));
			}
			else if(
				TRUE == alias_key->node->joined_network ||
				0 == strncmp(np_treeval_to_str(msg_subject, NULL), _NP_MSG_ACK, strlen(_NP_MSG_ACK)) ||
				0 == strncmp(np_treeval_to_str(msg_subject, NULL), _NP_MSG_JOIN, strlen(_NP_MSG_JOIN)) ||
				0 == strncmp(np_treeval_to_str(msg_subject, NULL), _NP_MSG_JOIN_REQUEST, strlen(_NP_MSG_JOIN_REQUEST)) ||
				0 == strncmp(np_treeval_to_str(msg_subject, NULL), _NP_MSG_JOIN_NACK, strlen(_NP_MSG_JOIN_NACK)) ||
				0 == strncmp(np_treeval_to_str(msg_subject, NULL), _NP_MSG_JOIN_ACK, strlen(_NP_MSG_JOIN_ACK)))
			{
				/* real receive part */
				CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_TO, msg_to);
				CHECK_STR_FIELD(msg_in->instructions, _NP_MSG_INST_ACK, msg_ack);
				CHECK_STR_FIELD(msg_in->instructions, _NP_MSG_INST_TTL, msg_ttl);
				CHECK_STR_FIELD(msg_in->instructions, _NP_MSG_INST_TSTAMP, msg_tstamp);
				CHECK_STR_FIELD(msg_in->instructions, _NP_MSG_INST_SEND_COUNTER, msg_resendcounter);

				// check time-to-live for message and expiry if neccessary
				if (TRUE == _np_message_is_expired(msg_in))
				{
						log_msg(LOG_ROUTING | LOG_INFO, "message ttl expired, dropping message (part) %s / %s",
						msg_in->uuid, np_treeval_to_str(msg_subject, NULL));
				}
				else if (msg_resendcounter.value.ush > 31) {
					log_msg(LOG_WARN, "message resend count (%d) too high, dropping message (part) %s / %s",
							msg_resendcounter.value.ush, msg_in->uuid, np_treeval_to_str(msg_subject, NULL));
				}
				else {
						log_debug_msg(LOG_ROUTING | LOG_DEBUG, "(msg: %s) message ttl not expired", msg_in->uuid);

					np_dhkey_t target_dhkey;
					_np_dhkey_from_str( np_treeval_to_str(msg_to, NULL), &target_dhkey);

					target_key = _np_keycache_find_or_create(target_dhkey);
						log_debug_msg(LOG_ROUTING | LOG_DEBUG, "target of msg is %s", _np_key_as_str(target_key));

					np_bool is_ack_msg = (0 == strncmp(np_treeval_to_str(msg_subject, NULL), _NP_MSG_ACK, strlen(_NP_MSG_ACK)) );

					// check if inbound subject handler exists
					np_msgproperty_t* handler = np_msgproperty_get(INBOUND, np_treeval_to_str(msg_subject, NULL));

					if (_np_key_cmp(target_key, my_key) == 0 && is_ack_msg) {
						// we shortcut the process here
						// handle the actual ack
						__np_in_ack_handle(msg_in);
						// call the receive callbacks (statistics etc)
						_np_in_invoke_user_receive_callbacks(msg_in, handler);						
						goto __np_cleanup__;
					}					

					// redirect message if
					// msg is not for my dhkey
					// no handler is present
					if (_np_key_cmp(args->target, my_key) != 0 || handler == NULL)
					{
						// perform a route lookup
						np_sll_t(np_key_ptr, tmp) = NULL;

						// zero as "consider this node as final target"
						tmp = _np_route_lookup(target_dhkey, 0);

						if (0 < sll_size(tmp))
							log_debug_msg(LOG_MESSAGE | LOG_ROUTING | LOG_DEBUG, "route_lookup result 1 = %s", _np_key_as_str(sll_first(tmp)->val));

						if (NULL != tmp &&
							sll_size(tmp) > 0 &&
							(FALSE == _np_dhkey_equal(&sll_first(tmp)->val->dhkey, &my_key->dhkey)))
						{
							log_msg(LOG_DEBUG,
								"forwarding message for subject: %s / uuid: %s", np_treeval_to_str(msg_subject, NULL), msg_in->uuid);
							np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _DEFAULT);
							// forwarding with a small penalty to prevent infinite loops
							_np_job_submit_route_event(0.031415, prop, args->target, msg_in);

							np_unref_list(tmp, "_np_route_lookup");
							sll_free(np_key_ptr, tmp);
							goto __np_cleanup__;
						}
						np_unref_list(tmp, "_np_route_lookup");
						if (NULL != tmp) sll_free(np_key_ptr, tmp);
						log_debug_msg(LOG_MESSAGE | LOG_ROUTING | LOG_DEBUG, "internal routing for subject '%s'", np_treeval_to_str(msg_subject, NULL));
					}
					// we know now: this node is the node nearest to the dhkey

					// if this message really has to be handled by this node, does a handler exists ?
					if (NULL == handler)
					{
						log_msg(LOG_WARN,
							"no incoming callback function was found for type %s, dropping message %s",
							np_treeval_to_str(msg_subject, NULL), msg_in->uuid);
					}
					else {
						// sum up message parts if the message is for this node
						np_message_t* msg_to_submit = _np_message_check_chunks_complete(msg_in);

						if (NULL != msg_to_submit)
						{
							if (TRUE == my_key->node->joined_network ||
								0 == strncmp(np_treeval_to_str(msg_subject, NULL), _NP_MSG_JOIN, strlen(_NP_MSG_JOIN)))
							{
								log_msg(LOG_INFO,
									"handling message for subject: %s / uuid: %s",
									np_treeval_to_str(msg_subject, NULL), msg_to_submit->uuid);

								// finally submit msg job for later execution
								if (_np_message_deserialize_chunked(msg_to_submit) == FALSE) {
									log_msg(LOG_WARN,
										"could not deserialize chunked msg (uuid: %s)", msg_to_submit->uuid);
								} else {
									_np_job_submit_msgin_event(0.0, handler, my_key, msg_to_submit, NULL);
									if (ACK_DESTINATION == (msg_ack.value.ush & ACK_DESTINATION)  )
									{
										_np_send_ack(msg_to_submit);
									}
								}
							}
							np_unref_obj(np_message_t, msg_to_submit, "_np_message_check_chunks_complete");
						}
					}
				}
			}
			else {
				log_debug_msg(LOG_MESSAGE | LOG_ROUTING | LOG_DEBUG, "ignoring msg as it is not in protocol to receive a %s msg now.", np_treeval_to_str(msg_subject, NULL));
			}
			// clean the mess up
		__np_cleanup__:			
			np_unref_obj(np_key_t, target_key,"_np_keycache_find_or_create");
			np_unref_obj(np_message_t, msg_in, ref_obj_creation);

		}
		np_unref_obj(np_network_t,my_network,"np_waitref_network");
	}
	np_unref_obj(np_key_t, my_key,"np_waitref_key");
	// __np_return__:
	return;
}

/**
 ** neuropil_piggy_message:
 ** This function is responsible to add the piggy backing node information that is sent along with
 ** other ctrl messages or separately to the routing table. the PIGGY message type is a separate
 ** message type.
 **/
void _np_in_piggy(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_piggy(np_jobargs_t* args) {");
	np_state_t* state = _np_state();
	np_key_t* node_entry = NULL;
	// double tmp_ft;
	np_sll_t(np_key_ptr, o_piggy_list) = NULL;

	o_piggy_list = _np_node_decode_multiple_from_jrb(args->msg->body);

	np_waitref_obj(np_key_t, state->my_node_key, my_key, "np_waitref_key");

	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "received piggy msg (%"PRIu32" nodes)", sll_size(o_piggy_list));

	while (NULL != (node_entry = sll_head(np_key_ptr, o_piggy_list)))
	{
		// add entries in the message to our routing table
		// routing table is responsible to handle possible double entries
		// tmp_ft = node_entry->node->failuretime;

		// TODO: those new entries in the piggy message must be authenticated before sending join requests
		if (FALSE == _np_dhkey_equal(&node_entry->dhkey, &my_key->dhkey) &&
			FALSE == node_entry->node->joined_network)
		{
			// just record nodes in the network or send an join request as well ?
			// answer: only send join request !
			// if (GRACEPERIOD > (np_time_now() - tmp_ft))
			// {
			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "node %s is qualified for a piggy join.", _np_key_as_str(node_entry));
			_np_send_simple_invoke_request(node_entry, _NP_MSG_JOIN_REQUEST);
		}
		else if (TRUE == node_entry->node->joined_network &&
				node_entry->node->success_avg > BAD_LINK &&
				(np_time_now() - node_entry->node->last_success) <= BAD_LINK_REMOVE_GRACETIME) {
			// udpate table and leafset, as nodes could have left the network and we need to fill up entries
			np_key_t *added = NULL, *deleted = NULL;
			_np_route_leafset_update(node_entry, TRUE, &deleted, &added);

#ifdef DEBUG
			
			if (added != NULL && deleted != NULL) {
				log_msg(LOG_ROUTING | LOG_INFO, "STABILITY replaced in   leafset: %s:%s:%s / %f / %1.2f replaced %s:%s:%s / %f / %1.2f",
							_np_key_as_str(added),
							added->node->dns_name, deleted->node->port,
							added->node->last_success,
							added->node->success_avg,

							_np_key_as_str(deleted),
							deleted->node->dns_name, deleted->node->port,
							deleted->node->last_success,
							deleted->node->success_avg
				);
			}
			else if (added != NULL) {
				log_msg(LOG_ROUTING | LOG_INFO, "STABILITY added    to   leafset: %s:%s:%s / %f / %1.2f",
							_np_key_as_str(added),
							added->node->dns_name, added->node->port,
							added->node->last_success,
							added->node->success_avg);
			}
			else  if (deleted !=NULL){
				log_msg(LOG_ROUTING | LOG_INFO, "STABILITY deleted  from leafset: %s:%s:%s / %f / %1.2f",
							_np_key_as_str(deleted),
							deleted->node->dns_name, deleted->node->port,
							deleted->node->last_success,
							deleted->node->success_avg);
			}
#endif

			added = NULL, deleted = NULL;
			_np_route_update(node_entry, TRUE, &deleted, &added);

#ifdef DEBUG
			if (added != NULL && deleted != NULL) {
				log_msg(LOG_ROUTING | LOG_INFO, "STABILITY replaced in   table  : %s:%s:%s / %f / %1.2f replaced %s:%s:%s / %f / %1.2f",
							_np_key_as_str(added),
							added->node->dns_name, deleted->node->port,
							added->node->last_success,
							added->node->success_avg,

							_np_key_as_str(deleted),
							deleted->node->dns_name, deleted->node->port,
							deleted->node->last_success,
							deleted->node->success_avg
					);
			}else  if (added !=NULL){
				log_msg(LOG_ROUTING | LOG_INFO, "STABILITY added    to   table  : %s:%s:%s / %f / %1.2f",
							_np_key_as_str(added),
							added->node->dns_name, added->node->port,
							added->node->last_success,
							added->node->success_avg);
			} else if (deleted !=NULL){
				log_msg(LOG_ROUTING | LOG_INFO, "STABILITY deleted  from table  : %s:%s:%s / %f / %1.2f",
							_np_key_as_str(deleted),
							deleted->node->dns_name, deleted->node->port,
							deleted->node->last_success,
							deleted->node->success_avg);
			}
#endif
		} else {
			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "node %s is not qualified for a piggy join. (%s)", _np_key_as_str(node_entry), node_entry->node->joined_network ? "J":"NJ");
		}
		np_unref_obj(np_key_t, node_entry,"_np_node_decode_multiple_from_jrb");
	}
	np_unref_obj(np_key_t, my_key, "np_waitref_key");
	sll_free(np_key_ptr, o_piggy_list);

	// __np_cleanup__:
	// nothing to do
	// __np_return__:
	log_msg(LOG_TRACE, "end  : void _np_in_piggy(np_jobargs_t* args) }");
	return;
}

/** _np_in_signal_np_receive
 ** _np_in_signal_np_receive registered when np_receive function is used to receive message.
 ** it is invoked after a message has been send from the sender of messages and sends a signal to the
 ** np_receive function
 **/
void _np_in_signal_np_receive (np_jobargs_t* args)
{
	np_message_t* msg_in = args->msg;

	CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_SUBJECT, msg_subject);
	CHECK_STR_FIELD(msg_in->instructions, _NP_MSG_INST_ACK, msg_ack_mode);

	np_msgproperty_t* real_prop = np_msgproperty_get(INBOUND, np_treeval_to_str(msg_subject, NULL));

	real_prop->msg_threshold++;
	_np_msgproperty_add_msg_to_recv_cache(real_prop, msg_in);
	_np_threads_condition_signal(&real_prop->msg_received);

	// log_debug_msg(LOG_DEBUG, "pushing message into cache %p", real_prop);
	// _LOCK_MODULE(np_msgproperty_t)
	// {
	//		sll_append(np_message_t, real_prop->msg_cache_in, args->msg);
	//		np_ref_obj(np_message_t, args->msg);
	//		// signal the np_receive function that the message has arrived
	//		log_debug_msg(LOG_DEBUG, "signaling via available %p", real_prop);
	// }

	__np_cleanup__:
	// nothing to do
	// __np_return__:
	return;
}

/** _np_in_callback_wrapper
 ** _np_in_callback_wrapper is used when a callback function is used to receive messages
 ** The purpose is automated acknowledge handling in case of ACK_CLIENT message subjects
 ** the user defined callback has to return TRUE in case the ack can be send, or FALSE
 ** if e.g. validation of the message has failed.
 **/
void _np_in_callback_wrapper(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_callback_wrapper(np_jobargs_t* args){");
	np_aaatoken_t* sender_token = NULL;
	np_message_t* msg_in = args->msg;
	np_bool msg_has_expired = FALSE;	

	if (args->properties != NULL && args->properties->is_internal) {		
		_np_in_invoke_user_receive_callbacks(msg_in, args->properties);
		goto __np_cleanup__;
	}

	if(NULL == msg_in) {
		log_msg(LOG_ERROR, "message object null but in use! %s", 
			((args->properties == NULL)? "" : args->properties->msg_subject)
		);			
		
		goto __np_cleanup__;
	}

	char* subject = args->properties->msg_subject;
	np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, subject);
	msg_prop->msg_threshold++;

	CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_from);
	CHECK_STR_FIELD(msg_in->instructions, _NP_MSG_INST_ACK, msg_ack_mode);
	msg_has_expired = _np_message_is_expired(msg_in);
	sender_token = _np_aaatoken_get_sender((char*)subject,  np_treeval_to_str(msg_from, NULL));


	if (TRUE == msg_has_expired)
	{
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "discarding expired message %s / %s ...", msg_prop->msg_subject, msg_in->uuid);
	}
	else	
	{	
		if ( NULL == sender_token )
		{
			_np_msgproperty_add_msg_to_recv_cache(msg_prop, msg_in);
			log_msg(LOG_ROUTING | LOG_INFO,"No token to decrypt msg. Retrying later");
		}
		else
		{
			log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "decrypting message ...");
			np_tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;

			np_bool decrypt_ok = _np_message_decrypt_payload(msg_in, sender_token);
			if (FALSE == decrypt_ok)
			{
				np_tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui--;
				msg_prop->msg_threshold--;
			}
			else
			{
				np_bool result = _np_in_invoke_user_receive_callbacks(msg_in, msg_prop);
				msg_prop->msg_threshold--;

				// CHECK_STR_FIELD(msg_in->properties, NP_MSG_INST_SEQ, received);
				// log_msg(LOG_INFO, "handled message %u with result %d ", received.value.ul, result);

				if (ACK_CLIENT == (msg_ack_mode.value.ush & ACK_CLIENT) && (TRUE == result))
				{
					_np_send_ack(args->msg);
				}
			}
		}
	}

	__np_cleanup__:
	np_unref_obj(np_aaatoken_t, sender_token,"_np_aaatoken_get_sender"); // _np_aaatoken_get_sender

	return;
}
/** _np_in_leave_req:
 ** internal function that is called at the destination of a LEAVE message. This
 ** call encodes the leaf set of the current host and sends it to the joiner.
 **/
void _np_in_leave_req(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_leave_req(np_jobargs_t* args){");
	np_key_t* leave_req_key = NULL;
	np_aaatoken_t* node_token = NULL;

	np_new_obj(np_aaatoken_t, node_token);
	np_aaatoken_decode(args->msg->body, node_token);

	_LOCK_MODULE(np_keycache_t)
	{
		leave_req_key = _np_key_create_from_token(node_token);
	}
	if(_np_key_cmp(_np_state()->my_node_key,leave_req_key ) != 0
	&& _np_key_cmp(_np_state()->my_identity,leave_req_key ) != 0
	){
		_np_key_destroy(leave_req_key);
	}
	np_unref_obj(np_key_t, leave_req_key,"_np_key_create_from_token");

	return;
}

/** _np_in_join_req:
 ** internal function that is called at the destination of a JOIN message. This
 ** call encodes the leaf set of the current host and sends it to the joiner.
 **/
void _np_in_join_req(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_join_req(np_jobargs_t* args){");

	np_msgproperty_t *msg_prop = NULL;
	np_key_t* join_req_key = NULL;
	np_key_t* routing_key = NULL;
	np_message_t* msg_out = NULL;
	np_aaatoken_t* join_token = NULL;

	np_new_obj(np_aaatoken_t, join_token);
	np_aaatoken_decode(args->msg->body, join_token);

	log_debug_msg(LOG_AAATOKEN| LOG_DEBUG, "check token is valid");
	if (FALSE == _np_aaatoken_is_valid(join_token))
	{
		// silently exit join protocol for invalid tokens
		goto __np_cleanup__;
	}
	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token is valid");

	// build a hash to find a place in the dhkey table, not for signing !
	np_dhkey_t search_key = _np_aaatoken_create_dhkey(join_token);

	join_req_key = _np_keycache_find_or_create(search_key);

	if (join_req_key->node != NULL &&  TRUE == join_req_key->node->joined_network)
	{
		// silently exit join protocol as we already joined this key
		goto __np_cleanup__;
	}

	_np_aaatoken_upgrade_core_token(join_req_key, join_token);

	log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "find target node");
	if (NULL != np_tree_find_str(join_token->extensions, "target_node"))
	{
		np_dhkey_t search_key = np_dhkey_create_from_hash(np_treeval_to_str(np_tree_find_str(join_token->extensions, "target_node")->val, NULL));
		routing_key = _np_keycache_find_or_create(search_key);
	}
	else
	{
		routing_key = join_req_key;
	}

	// check for allowance of token by user defined function
	np_state_t* state = _np_state();
	np_bool send_reply = FALSE;
	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "JOIN request key %s", _np_key_as_str(join_req_key));

	if (NULL != join_req_key &&
		NULL != state->authenticate_func)
	{
		np_bool join_allowed = state->authenticate_func(join_req_key->aaa_token);

		if (FALSE == state->enable_realm_slave &&
			TRUE == join_allowed)
		{
			join_req_key->aaa_token->state |= AAA_AUTHENTICATED;
			// required ?
			routing_key->aaa_token->state |= AAA_AUTHENTICATED;
		}
	}

	CHECK_STR_FIELD(args->msg->instructions, _NP_MSG_INST_UUID, in_uuid);

	log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) reset uuid to %s", args->msg->uuid,  np_treeval_to_str(in_uuid, NULL));
	free(args->msg->uuid );
	args->msg->uuid = strdup( np_treeval_to_str(in_uuid, NULL));

	np_new_obj(np_message_t, msg_out);

	np_waitref_obj(np_key_t,_np_state()->my_node_key, my_key,"np_waitref_key");
	if (IS_AUTHENTICATED(join_req_key->aaa_token->state))
	{
		log_msg(LOG_ROUTING | LOG_INFO,
				"JOIN request approved, sending back join acknowledge for key %s",
				_np_key_as_str(join_req_key));

		np_tree_t* jrb_me = np_tree_create();
		np_aaatoken_encode(jrb_me, state->my_node_key->aaa_token);

		_np_message_create(msg_out, routing_key, my_key, _NP_MSG_JOIN_ACK, jrb_me);
		np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACKUUID, in_uuid);

		msg_prop = np_msgproperty_get(OUTBOUND, _NP_MSG_JOIN_ACK);
		my_key->node->joined_network = TRUE;
		routing_key->node->joined_network = TRUE;

		send_reply = TRUE;
	}

	if (FALSE == state->enable_realm_slave &&
		IS_NOT_AUTHENTICATED(join_req_key->aaa_token->state))
	{
		log_msg(LOG_ROUTING | LOG_INFO,
				"JOIN request denied by user implementation, rejected key %s",
				_np_key_as_str(join_req_key) );

		_np_message_create(msg_out, routing_key, my_key, _NP_MSG_JOIN_NACK, NULL );
		np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACKUUID, in_uuid);

		msg_prop = np_msgproperty_get(OUTBOUND, _NP_MSG_JOIN_NACK);
		send_reply = TRUE;
	}
	np_unref_obj(np_key_t,my_key,"np_waitref_key");

	// TODO: chicken egg problem, we have to insert the entry into the table to be able to send back the JOIN.NACK
	np_key_t *added = NULL, *deleted = NULL;
	_np_route_leafset_update(routing_key, TRUE, &deleted, &added);

#ifdef DEBUG
	if (added !=NULL)
		log_debug_msg(LOG_INFO, "added   to   leafset: %s:%s:%s / %f / %1.2f",
						_np_key_as_str(routing_key),
						routing_key->node->dns_name, routing_key->node->port,
						routing_key->node->last_success,
						routing_key->node->success_avg);
	if (deleted !=NULL)
		log_debug_msg(LOG_INFO, "deleted from leafset: %s:%s:%s / %f / %1.2f",
						_np_key_as_str(deleted),
						deleted->node->dns_name, deleted->node->port,
						deleted->node->last_success,
						deleted->node->success_avg);
#endif

	added = NULL, deleted = NULL;
	_np_route_update(routing_key, TRUE, &deleted, &added);

#ifdef DEBUG
	if (added !=NULL)
		log_debug_msg(LOG_INFO, "added   to   table  : %s:%s:%s / %f / %1.2f",
						_np_key_as_str(routing_key),
						routing_key->node->dns_name, routing_key->node->port,
						routing_key->node->last_success,
						routing_key->node->success_avg);
	if (deleted !=NULL)
		log_debug_msg(LOG_INFO, "deleted from table  : %s:%s:%s / %f / %1.2f",
						_np_key_as_str(deleted),
						deleted->node->dns_name, deleted->node->port,
						deleted->node->last_success,
						deleted->node->success_avg);
#endif

	// TODO: what happens if node is not added to leafset or routing table ?

	if (TRUE == send_reply)
	{
		_np_job_submit_msgout_event(0.0, msg_prop, routing_key, msg_out);

		if (IS_AUTHENTICATED(join_req_key->aaa_token->state)){
			np_msgproperty_t* piggy_prop = np_msgproperty_get(TRANSFORM, _NP_MSG_PIGGY_REQUEST);
			_np_job_submit_transform_event(0.0, piggy_prop, routing_key, NULL);
		}
		// _np_send_ack(args->msg);
	}

	__np_cleanup__:
	np_unref_obj(np_aaatoken_t, join_token, ref_obj_creation); // np_new_obj
	np_unref_obj(np_message_t, msg_out,ref_obj_creation);

	// __np_return__:
	if (routing_key != join_req_key)
		np_unref_obj(np_key_t, routing_key,"_np_keycache_find_or_create");
	np_unref_obj(np_key_t, join_req_key,"_np_keycache_find_or_create");

	return;
}

/** _np_in_join_ack:
 ** called when the current node is joining the network and has just received
 ** its leaf set. This function sends an update message to all nodes in its
 ** new leaf set to announce its arrival.
 **/
void _np_in_join_ack(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_join_ack(np_jobargs_t* args){");

	np_message_t* msg_out = NULL;
	np_key_t* join_key = NULL;
	np_msgproperty_t* out_props = NULL;
	np_aaatoken_t* join_token = NULL;

	np_new_obj(np_aaatoken_t, join_token);
	np_aaatoken_decode(args->msg->body, join_token);

	if (FALSE == _np_aaatoken_is_valid(join_token))
	{
		// silently exit join protocol for invalid tokens
		goto __np_cleanup__;
	}

	np_dhkey_t search_key = _np_aaatoken_create_dhkey(join_token);
	join_key = _np_keycache_find_or_create(search_key);

	if (NULL != join_key )
	{
		_np_aaatoken_upgrade_core_token(join_key, join_token);
		// if a join ack is received here, then this node has send the join request
		join_key->aaa_token->state |= AAA_AUTHENTICATED;
	}

	if (NULL == join_key)
	{
		goto __np_cleanup__;
	}

	np_key_t* routing_key = NULL;
	if (NULL != np_tree_find_str(join_token->extensions, "target_node"))
	{
		np_dhkey_t search_key = np_dhkey_create_from_hash(np_treeval_to_str(np_tree_find_str(join_token->extensions, "target_node")->val, NULL));
		routing_key = _np_keycache_find(search_key);
		routing_key->aaa_token->state |= AAA_AUTHENTICATED;
	}
	else
	{
		routing_key = join_key;
	}

	np_state_t* state = _np_state();
	np_waitref_obj(np_key_t, state->my_node_key, my_key);

	/* acknowledgement of join message send out earlier */
	/*
	//FIXME: Mixing of Transport ACK and BL ACK
	CHECK_STR_FIELD(args->msg->instructions, _NP_MSG_INST_ACKUUID, ack_uuid);

	np_network_t* ng = my_key->network;

	_LOCK_ACCESS(&ng->send_data_lock)
	{
		np_tree_elem_t *jrb_node = np_tree_find_str(ng->waiting,  np_treeval_to_str(ack_uuid));
		if (jrb_node != NULL)
		{
			np_ackentry_t *entry = (np_ackentry_t *) jrb_node->val.value.v;
			_np_ackentry_set_acked(entry, TRUE);
			log_debug_msg(LOG_DEBUG, "received acknowledgment of JOIN uuid=%s",  np_treeval_to_str(ack_uuid));
		}
	}
	*/

	// should never happen
	if (NULL == routing_key || NULL == routing_key->node)
	{
		goto __np_cleanup__;
	}

	if (NULL != routing_key->node)
	{
		// node cannot be NULL, but checker complains otherwise
		log_msg(LOG_ROUTING | LOG_INFO,
				"received join acknowledgement for node key %s", _np_key_as_str(routing_key));
	}

	/* announce arrival of new node to the nodes in my routing table */
	// TODO: check for protected node neighbours ?
	np_sll_t(np_key_ptr, node_keys) = NULL;

	node_keys = _np_route_get_table();
	_np_keycache_sort_keys_cpm(node_keys, &routing_key->dhkey);

	np_key_t* elem = NULL;
	int i = 0;
	while ( i++ <= 5 && NULL != (elem = sll_head(np_key_ptr, node_keys)))
	{
		// send update of new node to all nodes in my routing table
		if (_np_dhkey_equal(&elem->dhkey, &routing_key->dhkey)) continue;

		np_new_obj(np_message_t, msg_out);

		// encode informations -> has to be done for each update message new
		// otherwise there is a crash when deleting the message
		np_tree_t* jrb_join_node = np_tree_create();
		np_aaatoken_encode(jrb_join_node, join_token);

		_np_message_create(msg_out, elem, my_key, _NP_MSG_UPDATE_REQUEST, jrb_join_node);
		out_props = np_msgproperty_get(OUTBOUND, _NP_MSG_UPDATE_REQUEST);
		_np_job_submit_route_event(i*0.1, out_props, elem, msg_out);

		np_unref_obj(np_message_t, msg_out,ref_obj_creation);
		np_unref_obj(np_key_t, elem,"_np_route_get_table");
	}
	sll_free(np_key_ptr, node_keys);

	// remember key for routing table update
	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "join acknowledged and updates to other nodes send");

	// update table
	np_key_t* added = NULL;
	np_key_t* deleted = NULL;
	_np_route_update(routing_key, TRUE, &deleted, &added);
#ifdef DEBUG
	if (added !=NULL)
		log_debug_msg(LOG_INFO, "added   to   table  : %s:%s:%s / %f / %1.2f",
						_np_key_as_str(routing_key),
						routing_key->node->dns_name, routing_key->node->port,
						routing_key->node->last_success,
						routing_key->node->success_avg);
	if (deleted !=NULL)
		log_debug_msg(LOG_INFO, "deleted from table: %s:%s:%s / %f / %1.2f",
						_np_key_as_str(deleted),
						deleted->node->dns_name, deleted->node->port,
						deleted->node->last_success,
						deleted->node->success_avg);
#endif

	// update leafset
	added = NULL, deleted = NULL;
	_np_route_leafset_update(routing_key, TRUE, &deleted, &added);
#ifdef DEBUG
	if (added !=NULL)
		log_debug_msg(LOG_INFO, "added   to   leafset: %s:%s:%s / %f / %1.2f",
						_np_key_as_str(routing_key),
						routing_key->node->dns_name, routing_key->node->port,
						routing_key->node->last_success,
						routing_key->node->success_avg);
	if (deleted !=NULL)
		log_debug_msg(LOG_INFO, "deleted from leafset: %s:%s:%s / %f / %1.2f",
						_np_key_as_str(deleted),
						deleted->node->dns_name, deleted->node->port,
						deleted->node->last_success,
						deleted->node->success_avg);
#endif
	// send an initial piggy message to the new node in our routing table
	np_msgproperty_t* piggy_prop = np_msgproperty_get(TRANSFORM, _NP_MSG_PIGGY_REQUEST);
	_np_job_submit_transform_event(0.0, piggy_prop, routing_key, NULL);

	routing_key->node->joined_network = TRUE;
	// just in case it has not been set until now
	my_key->node->joined_network = TRUE;

	__np_cleanup__:
	np_unref_obj(np_key_t, my_key, __func__);
	np_unref_obj(np_aaatoken_t, join_token,ref_obj_creation);

	// __np_return__:
	if (routing_key != join_key)
		np_unref_obj(np_key_t, routing_key,"_np_keycache_find");
	np_unref_obj(np_key_t, join_key,"_np_keycache_find_or_create");

	return;
}

/**
 ** hnd_msg_join_nack
 ** internal function that is called when the sender of a JOIN message receives
 ** the JOIN_NACK message type which is join denial from the current key root
 ** in the network.
 **/
void _np_in_join_nack(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_join_nack(np_jobargs_t* args){");

	np_state_t* state = _np_state();
	np_waitref_obj(np_key_t, state->my_node_key, my_key,"np_waitref_key");

	// np_network_t* ng = my_key->network;
	np_key_t* nack_key = NULL;

	CHECK_STR_FIELD(args->msg->header, _NP_MSG_HEADER_FROM, msg_from);
	CHECK_STR_FIELD(args->msg->instructions, _NP_MSG_INST_ACKUUID, ack_uuid);

	np_dhkey_t search_key = np_dhkey_create_from_hash( np_treeval_to_str(msg_from, NULL));
	nack_key = _np_keycache_find(search_key);

	/*
	//FIXME: Mixing of Transport ACK and BL ACK
	_LOCK_ACCESS(&ng->send_data_lock)
	{
		np_tree_elem_t *jrb_node = np_tree_find_str(ng->waiting,  np_treeval_to_str(ack_uuid));
		if (jrb_node != NULL)
		{
			np_ackentry_t *entry = (np_ackentry_t *) jrb_node->val.value.v;
			entry->has_received_nack = TRUE;
			entry->received_at = np_time_now();
			//todo handle ack
			log_debug_msg(LOG_DEBUG, "received not-acknowledgment of JOIN uuid=%s",  np_treeval_to_str(ack_uuid));
		}
	}
	*/

	// should never happen
	if (NULL == nack_key || NULL == nack_key->node)
	{
		return;
	}

	log_msg(LOG_ROUTING | LOG_INFO, "JOIN request rejected from key %s !", _np_key_as_str(nack_key));

	// update table
	np_key_t* added = NULL;
	np_key_t* deleted = NULL;
	_np_route_update(nack_key, FALSE, &deleted, &added);
#ifdef DEBUG
	if (deleted !=NULL)
		log_debug_msg(LOG_INFO, "deleted from table  : %s:%s:%s / %f / %1.2f",
						_np_key_as_str(deleted),
						deleted->node->dns_name, deleted->node->port,
						deleted->node->last_success,
						deleted->node->success_avg);
#endif

	// update leafset
	added = NULL, deleted = NULL;
	_np_route_leafset_update(nack_key, FALSE, &deleted, &added);
#ifdef DEBUG
	if (deleted !=NULL)
		log_debug_msg(LOG_INFO, "deleted from leafset: %s:%s:%s / %f / %1.2f",
						_np_key_as_str(deleted),
						deleted->node->dns_name, deleted->node->port,
						deleted->node->last_success,
						deleted->node->success_avg);
#endif

	nack_key->aaa_token->state &= AAA_INVALID;
	nack_key->node->joined_network = FALSE;
	nack_key->node->is_handshake_send = FALSE;

	__np_cleanup__:
	// nothing to do
	// __np_return__:

	np_unref_obj(np_key_t, nack_key,"_np_keycache_find");
	np_unref_obj(np_key_t, my_key,"np_waitref_key");
	return;
}

void __np_in_ack_handle(np_message_t * msg)
{
	np_waitref_obj(np_key_t, _np_state()->my_node_key, my_key);
	np_waitref_obj(np_network_t, my_key->network, my_network);

	CHECK_STR_FIELD(msg->instructions, _NP_MSG_INST_ACKUUID, ack_uuid);

	np_ackentry_t *entry = NULL;
	/* just an acknowledgement of own messages send out earlier */
	_LOCK_ACCESS(&my_network->waiting_lock)
	{
		np_tree_elem_t *jrb_node = np_tree_find_str(my_network->waiting,  np_treeval_to_str(ack_uuid, NULL));
		if (jrb_node != NULL)
		{
			entry = (np_ackentry_t *)jrb_node->val.value.v;
			_np_ackentry_set_acked(entry);
			log_debug_msg(LOG_ROUTING | LOG_MESSAGE | LOG_DEBUG, "received acknowledgment of uuid=%s",  np_treeval_to_str(ack_uuid, NULL));
		}
	}

	__np_cleanup__:
	np_unref_obj(np_network_t, my_network,__func__);
	np_unref_obj(np_key_t, my_key, __func__);
}

void _np_in_ack(np_jobargs_t* args)
{
	__np_in_ack_handle(args->msg);
}

// TODO: write a function that handles path discovery
// TODO: if this is not the target node, add my own address to the update message
// TODO: if this is the target node, change target to sending instance and send again

// receive information about new nodes in the network and try to contact new nodes
void _np_in_update(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_update(np_jobargs_t* args){");

	np_key_t *update_key = NULL;
	np_aaatoken_t* update_token = NULL;

	np_new_obj(np_aaatoken_t, update_token);
	np_aaatoken_decode(args->msg->body, update_token);

	if (FALSE == _np_aaatoken_is_valid(update_token))
	{
		goto __np_cleanup__;
	}

	_LOCK_MODULE(np_keycache_t)
	{
		update_key = _np_key_create_from_token(update_token);
	}

	if (NULL == update_key->aaa_token)
	{
		np_ref_obj(np_aaatoken_t, update_token, ref_key_aaa_token);
		update_key->aaa_token = update_token;
	}

	if (NULL != update_key &&
		NULL != update_key->node &&
		FALSE == update_key->node->is_handshake_send &&
		FALSE == update_key->node->joined_network)
	{
		// do not join myself
		if(0 != _np_key_cmp(update_key,_np_state()->my_identity)
		&& 0 != _np_key_cmp(update_key,_np_state()->my_node_key))
		{

			char* connection_str = np_get_connection_string_from(
					update_key,FALSE);
			np_key_t* old_key = _np_keycache_find_by_details(
					connection_str, FALSE, FALSE,FALSE,
					FALSE, TRUE, TRUE, FALSE);
			free(connection_str);

			if(NULL != old_key)
			{
				log_msg(LOG_ROUTING | LOG_INFO,
					"Node %s replaces itself with node %s",
					_np_key_as_str(args->target),
					_np_key_as_str(update_key)
					);

				if(old_key->network != NULL)
				{
					_np_network_remap_network(update_key, old_key);
				}
				np_unref_obj(np_key_t, old_key,"_np_keycache_find_by_details");
			}

			log_debug_msg(LOG_ROUTING | LOG_DEBUG,
			"Sending join %s:%s",
			// np_network_get_ip(update_key), np_network_get_port(update_key); 
				args->target->node->dns_name, update_key->node->port);
			_np_send_simple_invoke_request(update_key, _NP_MSG_JOIN_REQUEST);
		}
	} else {
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "Sending no join");
	}

	// TODO: forward update token to other neighbours
	__np_cleanup__:
	np_unref_obj(np_key_t, update_key,"_np_key_create_from_token");
	np_unref_obj(np_aaatoken_t, update_token, ref_obj_creation);

	// nothing to do
	// __np_return__:
	return;
}

void _np_in_discover_sender(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_discover_sender(np_jobargs_t* args){");
	np_key_t *reply_to_key = NULL;

	assert(args != NULL);
	assert(args->msg != NULL);
	assert(args->msg->header != NULL);

	CHECK_STR_FIELD(args->msg->header, _NP_MSG_HEADER_FROM, msg_reply_to);

	reply_to_key = _np_keycache_find_or_create(np_dhkey_create_from_hash( np_treeval_to_str(msg_reply_to, NULL)));

	// extract e2e encryption details for sender
	np_aaatoken_t* msg_token = NULL;
	np_new_obj(np_aaatoken_t, msg_token);
	np_aaatoken_decode(args->msg->body, msg_token);

	if (TRUE == _np_aaatoken_is_valid(msg_token))
	{
		// just store the available tokens in memory and update them if new data arrives
		log_debug_msg(LOG_ROUTING | LOG_AAATOKEN | LOG_DEBUG, "received new receiver token %s for %s",msg_token->uuid, msg_token->subject);
		_np_aaatoken_add_receiver(msg_token->subject, msg_token);

		// this node is the man in the middle - inform receiver of sender token
		np_sll_t(np_aaatoken_ptr, available_list) =
				_np_aaatoken_get_all_sender(msg_token->subject);

		np_aaatoken_t* tmp_token = NULL;

		while (NULL != (tmp_token = sll_head(np_aaatoken_ptr, available_list)))
		{
			log_debug_msg(LOG_ROUTING | LOG_DEBUG,
					"discovery success: sending back message sender token ...");
			np_tree_t* available_data = np_tree_create();

			np_aaatoken_encode(available_data, tmp_token);

			np_message_t *msg_out = NULL;
			np_new_obj(np_message_t, msg_out);
			_np_message_create (
					msg_out,
					reply_to_key,
					_np_state()->my_node_key,
					_NP_MSG_AVAILABLE_SENDER,
					available_data
			);
			np_msgproperty_t* prop_route =
					np_msgproperty_get(
							OUTBOUND,
							_NP_MSG_AVAILABLE_SENDER
			);
			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop_route->ack_mode));

			_np_job_submit_route_event(
					0.0, prop_route, reply_to_key, msg_out);

			np_unref_obj(np_message_t, msg_out, ref_obj_creation);
			np_unref_obj(np_aaatoken_t, tmp_token,"_np_aaatoken_get_all_sender");
		}
		sll_free(np_aaatoken_ptr, available_list);
	}
	np_unref_obj(np_key_t, reply_to_key,"_np_keycache_find_or_create");

	__np_cleanup__:
		np_unref_obj(np_aaatoken_t, msg_token, ref_obj_creation);

	// __np_return__:
	return;
}

void _np_in_available_sender(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_available_sender(np_jobargs_t* args){");

	np_message_t *msg_in = args->msg;

	// extract e2e encryption details for sender
	np_aaatoken_t* msg_token = NULL;

	CHECK_STR_FIELD(args->msg->header, _NP_MSG_HEADER_TO, msg_to);

	np_new_obj(np_aaatoken_t, msg_token);
	np_aaatoken_decode(msg_in->body, msg_token);

	// always?: just store the available tokens in memory and update them if new data arrives
	if (FALSE == _np_aaatoken_is_valid(msg_token))
	{
		goto __np_cleanup__;
	}

	np_state_t* state = _np_state();

	np_dhkey_t sendtoken_issuer_key = np_dhkey_create_from_hash(msg_token->issuer);
	if (_np_dhkey_equal(&sendtoken_issuer_key, &state->my_node_key->dhkey) )
	{
		// only add the token if it is not from ourself (in case of IN/OUTBOUND on same subject)
		// TODO CHECK IF NESSECARY
		// goto __np_cleanup__;
	}	
	_np_aaatoken_add_sender(msg_token->subject, msg_token);

	np_dhkey_t to_key = np_dhkey_create_from_hash( np_treeval_to_str(msg_to, NULL));

	if ( _np_dhkey_equal(&to_key, &state->my_node_key->dhkey) )
	{
		if (TRUE == state->authenticate_func(msg_token))
			msg_token->state |= AAA_AUTHENTICATED;

		if (TRUE == state->authorize_func(msg_token))
			msg_token->state |= AAA_AUTHORIZED;
	}

	// check if some messages are left in the cache
	np_msgproperty_t* real_prop = np_msgproperty_get(INBOUND, msg_token->subject);
	// check if we are (one of the) receiving node(s) of this kind of message
	if ( NULL != real_prop)
	{
		_np_msgproperty_check_receiver_msgcache(real_prop);
	}

	__np_cleanup__:
	np_unref_obj(np_aaatoken_t, msg_token, ref_obj_creation);

	// __np_return__:
	return;
}

void _np_in_discover_receiver(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_discover_receiver(np_jobargs_t* args){");

	np_key_t *reply_to_key = NULL;
	np_aaatoken_t* msg_token = NULL;
	np_message_t *msg_in = args->msg;

	np_tryref_obj(np_message_t, msg_in, msg_exists);
	if(msg_exists){
		CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_reply_to);

		reply_to_key = _np_keycache_find_or_create(np_dhkey_create_from_hash( np_treeval_to_str(msg_reply_to, NULL)));

		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "reply key: %s", _np_key_as_str(reply_to_key) );

		// extract e2e encryption details for sender
		np_new_obj(np_aaatoken_t, msg_token);
		np_aaatoken_decode(msg_in->body, msg_token);

		// always?: just store the available messages in memory and update if new data arrives
		if (FALSE == _np_aaatoken_is_valid(msg_token))
		{
			goto __np_cleanup__;
		}

		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "received new sender token %s for %s",msg_token->uuid, msg_token->subject);

		_np_aaatoken_add_sender(msg_token->subject, msg_token);

		np_aaatoken_t* tmp_token = NULL;
		np_sll_t(np_aaatoken_ptr, receiver_list) = _np_aaatoken_get_all_receiver(msg_token->subject);

		while (NULL != (tmp_token = sll_head(np_aaatoken_ptr, receiver_list)))
		{
			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "discovery success: sending back message receiver token ...");
			np_tree_t* interest_data = np_tree_create();

			np_aaatoken_encode(interest_data, tmp_token);

			np_message_t *msg_out = NULL;
			np_new_obj(np_message_t, msg_out);
			_np_message_create(msg_out, reply_to_key, _np_state()->my_node_key, _NP_MSG_AVAILABLE_RECEIVER, interest_data);
			
			np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_AVAILABLE_RECEIVER);

			np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(prop_route->ack_mode));			

			log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending back msg interest to %s", _np_key_as_str(reply_to_key));
			_np_job_submit_route_event(0.0, prop_route, reply_to_key, msg_out);

			np_unref_obj(np_message_t, msg_out,ref_obj_creation);
			np_unref_obj(np_aaatoken_t, tmp_token,"_np_aaatoken_get_all_receiver");
		}
		sll_free(np_aaatoken_ptr, receiver_list);

	__np_cleanup__:
		np_unref_obj(np_message_t, msg_in, __func__);
		np_unref_obj(np_key_t, reply_to_key,"_np_keycache_find_or_create");
		np_unref_obj(np_aaatoken_t, msg_token,ref_obj_creation);
	}
	// __np_return__:
	return;
}

void _np_in_available_receiver(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_available_receiver(np_jobargs_t* args){");

	np_state_t* state = _np_state();
	np_waitref_obj(np_key_t, state->my_node_key, my_key,"np_waitref_key");
	np_waitref_obj(np_key_t, state->my_identity, my_identity,"np_waitref_identity");

	// extract e2e encryption details for sender
	np_aaatoken_t* msg_token = NULL;

	CHECK_STR_FIELD(args->msg->header, _NP_MSG_HEADER_TO, msg_to);
	np_dhkey_t to_key = np_dhkey_create_from_hash( np_treeval_to_str(msg_to, NULL));

	np_new_obj(np_aaatoken_t, msg_token);
	np_aaatoken_decode(args->msg->body, msg_token);

	if (FALSE == _np_aaatoken_is_valid(msg_token))
	{
		goto __np_cleanup__;
	}

	np_dhkey_t recvtoken_issuer_key = np_dhkey_create_from_hash(msg_token->issuer);
	if (_np_dhkey_equal(&recvtoken_issuer_key, &my_identity->dhkey) )
	{
		// only add the token if it is not from ourself (in case of IN/OUTBOUND on same subject)
		// TODO CHECK IF NESSECARY
		// goto __np_cleanup__;
	}

	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now handling message interest");
	_np_aaatoken_add_receiver(msg_token->subject, msg_token);

	// check if we are (one of the) sending node(s) of this kind of message
	if ( _np_dhkey_equal(&to_key, &my_key->dhkey) )
	{
		if (TRUE == state->authenticate_func(msg_token))
			msg_token->state |= AAA_AUTHENTICATED;

		if (TRUE == state->authorize_func(msg_token))
			msg_token->state |= AAA_AUTHORIZED;
	}

	// check if we are (one of the) sending node(s) of this kind of message
	// should not return NULL
	np_msgproperty_t* real_prop = np_msgproperty_get(OUTBOUND, msg_token->subject);
	if ( NULL != real_prop)
	{

		_np_msgproperty_check_sender_msgcache(real_prop);
	}

	__np_cleanup__:
	np_unref_obj(np_aaatoken_t, msg_token,ref_obj_creation);
	np_unref_obj(np_key_t, my_key,"np_waitref_key");
	np_unref_obj(np_key_t, my_identity,"np_waitref_identity");

	// __np_return__:
	return;
}

void _np_in_authenticate(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_authenticate(np_jobargs_t* args){");
	np_key_t *reply_to_key = NULL;
	np_aaatoken_t* sender_token = NULL;
	np_aaatoken_t* authentication_token = NULL;
	np_message_t *msg_in = args->msg;

	args->properties->msg_threshold++;

	CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_from);

	reply_to_key = _np_keycache_find_or_create(np_dhkey_create_from_hash( np_treeval_to_str(msg_from, NULL)));

	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "reply key: %s", _np_key_as_str(reply_to_key) );

	sender_token = _np_aaatoken_get_sender((char*) _NP_MSG_AUTHENTICATION_REQUEST,  np_treeval_to_str(msg_from, NULL));
	if (NULL == sender_token)
	{
		goto __np_cleanup__;
	}

	np_bool decrypt_ok = _np_message_decrypt_payload(msg_in, sender_token);
	if (FALSE == decrypt_ok)
	{
		goto __np_cleanup__;
	}
	np_tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;

	// extract e2e encryption details for sender
	np_new_obj(np_aaatoken_t, authentication_token);
	np_aaatoken_decode(msg_in->body, authentication_token);

	// always?: just store the available messages in memory and update if new data arrives
	if (FALSE == _np_aaatoken_is_valid(authentication_token))
	{
		goto __np_cleanup__;
	}

	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now checking authentication of token");
	if (TRUE == _np_state()->authenticate_func(authentication_token))
	{
		authentication_token->state |= AAA_AUTHENTICATED;
	}

	if (IS_AUTHENTICATED(authentication_token->state) )
	{
		_np_aaatoken_add_receiver(_NP_MSG_AUTHENTICATION_REPLY, sender_token);

		np_tree_t* token_data = np_tree_create();

		np_aaatoken_encode(token_data, authentication_token);
		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		_np_message_create(msg_out, reply_to_key, _np_state()->my_node_key, _NP_MSG_AUTHENTICATION_REPLY, token_data);
		np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHENTICATION_REPLY);

		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending back authenticated data to %s", _np_key_as_str(reply_to_key));
		if (NULL == reply_to_key->aaa_token)
		{
			np_ref_obj(np_aaatoken_t, sender_token, ref_key_aaa_token);
			reply_to_key->aaa_token = sender_token;
		}
		_np_job_submit_transform_event(0.0, prop_route, reply_to_key, msg_out);
		np_unref_obj(np_message_t, msg_out,ref_obj_creation);
	}
	else
	{
		log_msg(LOG_WARN, "unknown security token received for authentication, dropping token");
		log_msg(LOG_WARN, "i:%s s:%s", authentication_token->issuer, authentication_token->subject);
	}

	__np_cleanup__:
	np_unref_obj(np_key_t, reply_to_key,"_np_keycache_find_or_create");
	np_unref_obj(np_aaatoken_t, sender_token,"_np_aaatoken_get_sender");
	np_unref_obj(np_aaatoken_t, authentication_token,ref_obj_creation);

	// __np_return__:
	args->properties->msg_threshold--;
	return;
}

void _np_in_authenticate_reply(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_authenticate_reply(np_jobargs_t* args){");
	np_aaatoken_t* authentication_token = NULL;
	np_aaatoken_t* sender_token = NULL;
	np_key_t* subject_key = NULL;

	// args->properties->msg_threshold++;

	CHECK_STR_FIELD(args->msg->header, _NP_MSG_HEADER_FROM, msg_from);

	sender_token = _np_aaatoken_get_sender((char*) _NP_MSG_AUTHENTICATION_REPLY,  np_treeval_to_str(msg_from, NULL));
	if (NULL == sender_token)
	{
		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "no sender token for authentication reply found");
		goto __np_cleanup__;
	}

	// TODO: the following should not be required/possible, because it invalidates the token
	np_bool decrypt_ok = _np_message_decrypt_payload(args->msg, sender_token);
	if (FALSE == decrypt_ok)
	{
		log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "decryption of authentication reply failed");
		goto __np_cleanup__;
	}
	 np_tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;

	// extract e2e encryption details for sender
	np_new_obj(np_aaatoken_t, authentication_token);
	np_aaatoken_decode(args->msg->body, authentication_token);

	np_dhkey_t search_key;
	// TODO: validate token technically again
	if (0 == strncmp(authentication_token->subject, "urn:np:node:", 12))
	{
		search_key = np_dhkey_create_from_hash(authentication_token->issuer);
		// TODO: trigger JOIN request again if node has not joined ?

	} // TODO: add a token type to identify msg exchanges, nodes and real persons
	else /* if (0 == strncmp(authentication_token->subject, "urn:np:msg:", 11)) */
	{
		search_key = np_dhkey_create_from_hostport(authentication_token->subject, "0");
	}

	subject_key = _np_keycache_find_or_create(search_key);

	if (0 == strncmp(authentication_token->subject, "urn:np:node:", 12))
	{
		subject_key->aaa_token->state |= AAA_AUTHENTICATED;
	}
	else /* if (0 == strncmp(authentication_token->subject, "urn:np:msg:", 11)) */
	{
		_LOCK_ACCESS(&subject_key->recv_property->lock)
		{
			pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
			while (NULL != iter)
			{
				np_aaatoken_t* tmp_token = iter->val;
				if (0 == strncmp(tmp_token->uuid, authentication_token->uuid, 255) )
				{
					tmp_token->state |= AAA_AUTHENTICATED;
					_np_msgproperty_check_receiver_msgcache(subject_key->recv_property);
					break;
				}
				// TODO: move to msgcache.h and change parameter
				pll_next(iter);
			}
		}

		_LOCK_ACCESS(&subject_key->send_property->lock)
		{
			pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->send_tokens);
			while (NULL != iter)
			{
				np_aaatoken_t* tmp_token = iter->val;
				if (0 == strncmp(tmp_token->uuid, authentication_token->uuid, 255) )
				{
					tmp_token->state |= AAA_AUTHENTICATED;
					_np_msgproperty_check_sender_msgcache(subject_key->send_property);
					break;
				}
				// TODO: move to msgcache.h and change parameter
				pll_next(iter);
			}
		}
	}

	__np_cleanup__:
	np_unref_obj(np_aaatoken_t, authentication_token,ref_obj_creation);
	np_unref_obj(np_aaatoken_t, sender_token,"_np_aaatoken_get_sender");

	// __np_return__:
	// args->properties->msg_threshold--;
	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	return;
}

void _np_in_authorize(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_authorize(np_jobargs_t* args){");
	np_key_t *reply_to_key = NULL;
	np_aaatoken_t* sender_token = NULL;
	np_aaatoken_t* authorization_token = NULL;

	np_message_t *msg_in = args->msg;

	args->properties->msg_threshold++;

	CHECK_STR_FIELD(msg_in->header, _NP_MSG_HEADER_FROM, msg_from);

	reply_to_key = _np_keycache_find_or_create(np_dhkey_create_from_hash( np_treeval_to_str(msg_from, NULL)));

	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "reply key: %s", _np_key_as_str(reply_to_key) );

	sender_token = _np_aaatoken_get_sender((char*) _NP_MSG_AUTHORIZATION_REQUEST,  np_treeval_to_str(msg_from, NULL));
	if (NULL == sender_token)
	{
		goto __np_cleanup__;
	}

	np_bool decrypt_ok = _np_message_decrypt_payload(msg_in, sender_token);
	if (FALSE == decrypt_ok)
	{
		goto __np_cleanup__;
	}

	np_tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;
	// extract e2e encryption details for sender
	np_new_obj(np_aaatoken_t, authorization_token);
	np_aaatoken_decode(msg_in->body, authorization_token);

	// always?: just store the available messages in memory and update if new data arrives
	if (FALSE == _np_aaatoken_is_valid(authorization_token))
	{
		goto __np_cleanup__;
	}

	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now checking authorization of token");
	if (TRUE == _np_state()->authorize_func(authorization_token))
	{
		authorization_token->state |= AAA_AUTHORIZED;
	}

	if (IS_AUTHORIZED(authorization_token->state) )
	{
		_np_aaatoken_add_receiver(_NP_MSG_AUTHORIZATION_REPLY, sender_token);

		np_tree_t* token_data = np_tree_create();
		np_aaatoken_encode(token_data, authorization_token);

		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		_np_message_create(msg_out, reply_to_key, _np_state()->my_node_key, _NP_MSG_AUTHORIZATION_REPLY, token_data);
		np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHORIZATION_REPLY);

		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "sending back authorized data to %s", _np_key_as_str(reply_to_key));
		if (NULL == reply_to_key->aaa_token)
		{
			np_ref_obj(np_aaatoken_t, sender_token, ref_key_aaa_token);
			reply_to_key->aaa_token = sender_token;
		}
		_np_job_submit_transform_event(0.0, prop_route, reply_to_key, msg_out);
		np_unref_obj(np_message_t, msg_out,ref_obj_creation);
	}
	else
	{
		log_msg(LOG_WARN, "unknown security token received for authorization, dropping token");
		log_msg(LOG_WARN, "i:%s s:%s", authorization_token->issuer, authorization_token->subject);
	}

	__np_cleanup__:
	np_unref_obj(np_key_t, reply_to_key,"_np_keycache_find_or_create");
	np_unref_obj(np_aaatoken_t, sender_token, "_np_aaatoken_get_sender");
	np_unref_obj(np_aaatoken_t, authorization_token, ref_obj_creation);

	// __np_return__:
	args->properties->msg_threshold--;
	return;
}

void _np_in_authorize_reply(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_authorize_reply(np_jobargs_t* args){");
	np_aaatoken_t* authorization_token = NULL;
	np_aaatoken_t* sender_token = NULL;

	// args->properties->msg_threshold++;

	CHECK_STR_FIELD(args->msg->header, _NP_MSG_HEADER_FROM, msg_from);

	sender_token = _np_aaatoken_get_sender((char*) _NP_MSG_AUTHORIZATION_REPLY,  np_treeval_to_str(msg_from, NULL));
	if (NULL == sender_token)
	{
		goto __np_cleanup__;
	}

	np_bool decrypt_ok = _np_message_decrypt_payload(args->msg, sender_token);
	if (FALSE == decrypt_ok)
	{
		goto __np_cleanup__;
	}

	 np_tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;

	// extract e2e encryption details for sender
	np_new_obj(np_aaatoken_t, authorization_token);
	np_aaatoken_decode(args->msg->body, authorization_token);

	np_key_t* subject_key = NULL;
	np_dhkey_t search_key;

	// TODO: validate token technically again
	if (0 == strncmp(authorization_token->subject, "urn:np:node:", 12))
	{
		search_key = np_dhkey_create_from_hash(authorization_token->issuer);
	}
	else /* if (0 == strncmp(authorization_token->subject, "urn:np:msg:", 11)) */
	{
		search_key = np_dhkey_create_from_hostport(authorization_token->subject, "0");
	}

	subject_key = _np_keycache_find_or_create(search_key);

	if (0 == strncmp(authorization_token->subject, "urn:np:node:", 12))
	{
		subject_key->aaa_token->state |= AAA_AUTHORIZED;
	}
	else /* if (0 == strncmp(authorization_token->subject, "urn:np:msg:", 11)) */
	{
		_LOCK_ACCESS(&subject_key->recv_property->lock)
		{
			pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
			while (NULL != iter)
			{
				np_aaatoken_t* tmp_token = iter->val;
				if (0 == strncmp(tmp_token->uuid, authorization_token->uuid, 255) )
				{
					tmp_token->state |= AAA_AUTHORIZED;
					_np_msgproperty_check_receiver_msgcache(subject_key->recv_property);
					break;
				}
				// TODO: move to msgcache.h and change parameter
				pll_next(iter);
			}
		}

		_LOCK_ACCESS(&subject_key->send_property->lock)
		{
			pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->send_tokens);
			while (NULL != iter)
			{
				np_aaatoken_t* tmp_token = iter->val;
				if (0 == strncmp(tmp_token->uuid, authorization_token->uuid, 255) )
				{
					tmp_token->state |= AAA_AUTHORIZED;
					_np_msgproperty_check_sender_msgcache(subject_key->send_property);
					break;
				}
				pll_next(iter);
			}
		}
	}

	__np_cleanup__:
	np_unref_obj(np_aaatoken_t, authorization_token, ref_obj_creation);
	np_unref_obj(np_aaatoken_t, sender_token,"_np_aaatoken_get_sender");

	// __np_return__:
	// args->properties->msg_threshold--;
	np_unref_obj(np_key_t, subject_key,"_np_keycache_find_or_create");
	return;
}

void _np_in_account(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_account(np_jobargs_t* args){");
	np_aaatoken_t* sender_token = NULL;
	np_aaatoken_t* accounting_token = NULL;

	args->properties->msg_threshold++;

	CHECK_STR_FIELD(args->msg->header, _NP_MSG_HEADER_FROM, msg_from);

	sender_token = _np_aaatoken_get_sender((char*) _NP_MSG_ACCOUNTING_REQUEST,  np_treeval_to_str(msg_from, NULL));
	if (NULL == sender_token)
	{
		goto __np_cleanup__;
	}

	np_tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;
	np_bool decrypt_ok = _np_message_decrypt_payload(args->msg, sender_token);
	if (FALSE == decrypt_ok)
	{
		goto __np_cleanup__;
	}

	np_new_obj(np_aaatoken_t, accounting_token);
	np_aaatoken_decode(args->msg->body, accounting_token);

	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "now handling accounting for token");
	_np_state()->accounting_func(accounting_token);

	__np_cleanup__:
	np_unref_obj(np_aaatoken_t, accounting_token, ref_obj_creation);
	np_unref_obj(np_aaatoken_t, sender_token, "_np_aaatoken_get_sender");

	// __np_return__:
	args->properties->msg_threshold--;
	return;
}

void _np_in_handshake(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, "start: void _np_in_handshake(np_jobargs_t* args){");

	_LOCK_MODULE(np_handshake_t) {
		np_key_t* msg_source_key = NULL;
		np_key_t* hs_wildcard_key = NULL;
		np_key_t* alias_key = args->target;

		np_aaatoken_t* tmp_token = NULL;

		_np_message_deserialize_chunked(args->msg);

		// initial handshake message contains public encryption parameter
		CHECK_STR_FIELD(args->msg->body, NP_HS_SIGNATURE, signature);
		CHECK_STR_FIELD(args->msg->body, NP_HS_PAYLOAD, payload);

		cmp_ctx_t cmp = { 0,0,0,0,0 };
		cmp_init(&cmp, payload.value.bin, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
		np_tree_t* hs_payload = np_tree_create();
		hs_payload->attr.in_place = TRUE;

		if(np_tree_deserialize(hs_payload, &cmp) == FALSE) {
			goto __np_cleanup__;
		}
		// TODO: check if the complete buffer was read (byte count match)

		np_new_obj(np_aaatoken_t, tmp_token);
		np_aaatoken_decode(hs_payload, tmp_token);
		// TODO: check decoded content

		if (0 != crypto_sign_verify_detached(
				(const unsigned char*) signature.value.bin,
				(const unsigned char*) payload.value.bin,
				payload.size,
				tmp_token->public_key))
		{
			log_msg(LOG_ERROR, "incorrect signature in handshake message");

	#ifdef DEBUG
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "signature has %"PRIu32" bytes", signature.size);
			char* signature_hex = calloc(1,signature.size * 2 + 1);
			sodium_bin2hex(signature_hex, signature.size * 2 + 1,
				signature.value.bin, signature.size);
			log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "signature: (payload size: %5"PRIu32") %s", payload.size, signature_hex);
			free(signature_hex);
	#endif
			goto __np_cleanup__;
		}

		log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
				"decoding of handshake message from %s (i:%f/e:%f) complete",
				tmp_token->subject, tmp_token->issued_at, tmp_token->expires_at);

		// store the handshake data in the node cache,
		// use hostname/port for key generation
		// key could be changed later,
		// but we need a way to lookup the handshake data later

		np_node_t* tokens_node = _np_node_decode_from_jrb(hs_payload);
		msg_source_key = _np_key_create_from_token(tmp_token);


		log_debug_msg(LOG_ROUTING | LOG_DEBUG, "handshake for %s",_np_key_as_str(msg_source_key));

		// should never happen
		if (NULL == msg_source_key)
		{
			log_msg(LOG_ERROR, "Handshake key is NULL!");
			goto __np_cleanup__;
		}

		/*
			Handshake/Join worklfow:
				1. 1Node initiates the workflow with a Handshake msg
					Handshake msg contains a subset of the aaatoken data
					(named "core_token", data required for a cryptographic safe connection)
					and the node data to answer back as well as the session key
					and the signature of the full token
				2. 2Node receives Handshake msg and saves it into a key.
					2.Node now sends 1.Node his own Handshake msg
				3. Join msg is send from 1.Node to 2.Node
					Join msg contains the full token data of 1.Node
				4. 2.Node receives Join msg
					The new tokens signature will be matched with the signature of the core token
					If it does match the new token will replace the old one
					the appropiate aaa callbacks will be called
					and the Join ACK msg will contain the full token data of 2.Node
				5. 1.Node receives Join ACK msg and replaces the old token with the new one

			We are now in step 2.

			Stop the Handshake workflow now if
			the handshake data is already received (prevent handshake spamming)
		*/
		if (msg_source_key->node != NULL &&  msg_source_key->node->is_handshake_received == TRUE) {
			log_msg(LOG_ROUTING | LOG_INFO, "Handshake message already completed");
			np_unref_obj(np_node_t, tokens_node, "_np_node_decode_from_jrb");
			goto __np_cleanup__;
		}

		if (tokens_node != NULL) {
			ref_replace_reason(np_node_t, tokens_node, "_np_node_decode_from_jrb", ref_key_node);
			if (msg_source_key->node == NULL) {
				msg_source_key->node = tokens_node;				
			}
			else {
				tokens_node->is_handshake_send |= msg_source_key->node->is_handshake_send;
				tokens_node->is_handshake_received |= msg_source_key->node->is_handshake_received;
				tokens_node->joined_network |= msg_source_key->node->joined_network;
				np_node_t* old_node = msg_source_key->node;
				msg_source_key->node = tokens_node;
				np_unref_obj(np_node_t, old_node, ref_key_node);
			}
		}

		if (msg_source_key->node == NULL) {
			log_msg(LOG_ERROR, "Handshake message does not contain necessary node data");
			goto __np_cleanup__;
		}

		if(msg_source_key->node->joined_network == FALSE) {
			char* tmp_connection_str = np_get_connection_string_from(msg_source_key, FALSE);
			np_dhkey_t wildcard_dhkey = np_dhkey_create_from_hostport("*", tmp_connection_str );
			free(tmp_connection_str);

			_LOCK_MODULE ( np_network_t)
			{
				hs_wildcard_key = _np_keycache_find(wildcard_dhkey);
				if(NULL != hs_wildcard_key && NULL != hs_wildcard_key->network) {
					np_network_t* old_network = hs_wildcard_key->network;
					np_ref_obj(np_network_t, old_network, "usage_of_old_network");

					_LOCK_ACCESS(&old_network->send_data_lock)
					{
						// _np_network_stop(old_network);
						// Updating handshake key with already existing network
						// structure of the wildcard key
						log_debug_msg(LOG_ROUTING | LOG_DEBUG,
								"Updating wildcard key %s to %s",
								_np_key_as_str(hs_wildcard_key),
								_np_key_as_str(msg_source_key));

						msg_source_key->node->is_handshake_send |=
							hs_wildcard_key->node->is_handshake_send;
						msg_source_key->node->is_handshake_received |=
							hs_wildcard_key->node->is_handshake_received;

						// msg_source_key->aaa_token = hs_wildcard_key->aaa_token;
						hs_wildcard_key->aaa_token = NULL;

						if(msg_source_key->parent == NULL) {
							msg_source_key->parent = hs_wildcard_key->parent;
							hs_wildcard_key->parent = NULL;
						}
						_np_network_remap_network(msg_source_key, hs_wildcard_key);
					}
					np_unref_obj(np_network_t, old_network, "usage_of_old_network");
					_np_send_simple_invoke_request(msg_source_key, _NP_MSG_JOIN_REQUEST);
				}

				np_unref_obj(np_key_t, hs_wildcard_key, "_np_keycache_find");
			}
		}

		_LOCK_ACCESS(&msg_source_key->node->lock) {
			if (msg_source_key->node->is_handshake_received == TRUE) {
				log_msg(LOG_ROUTING | LOG_INFO, "Handshake message already completed (via wildcard)");
			}
			else {

				_LOCK_MODULE(np_network_t)
				{
					if (NULL == msg_source_key->network)
					{
						log_debug_msg(LOG_NETWORK | LOG_DEBUG, "handshake: init alias network");
						np_new_obj(np_network_t, msg_source_key->network);
						np_network_t* network = msg_source_key->network;
						ref_replace_reason(np_network_t, network, ref_obj_creation, ref_key_network);
						if (((msg_source_key->node->protocol & PASSIVE) != PASSIVE))
						{
							_np_network_init(
								network,
								FALSE,
								msg_source_key->node->protocol,
								msg_source_key->node->dns_name,
								msg_source_key->node->port);

							if (TRUE == network->initialized)
							{
								np_ref_obj(np_key_t, msg_source_key, ref_network_watcher);
								network->watcher.data = msg_source_key;
							}
							else
							{
								log_msg(LOG_ERROR, "could not initiate network to alias key for %s:%s", network->ip, network->port);

								np_unref_obj(np_network_t, network, ref_key_network);
								msg_source_key->network = NULL;
							}
						}
					}
					else {
						log_debug_msg(LOG_NETWORK | LOG_DEBUG, "handshake: alias network already present");
					}
				}

				np_state_t* state = _np_state();
				np_waitref_obj(np_aaatoken_t, state->my_node_key->aaa_token, my_id_token, "np_waitref_my_node_key->aaa_token");

				// get our own identity from the cache and convert to curve key
				unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
				crypto_sign_ed25519_sk_to_curve25519(
					curve25519_sk, my_id_token->private_key);

				np_unref_obj(np_aaatoken_t, my_id_token, "np_waitref_my_node_key->aaa_token");

				np_tree_elem_t* session_key = np_tree_find_str(
					hs_payload, "_np.session");

				ASSERT(session_key->val.type == bin_type, "_np.session should be a binary value but is of type: %"PRIu8, session_key->val.type);
				ASSERT(session_key->val.value.bin != NULL, "_np.session should be filled with data");

				// create shared secret
				unsigned char shared_secret[crypto_scalarmult_BYTES];
				crypto_scalarmult(
					shared_secret, curve25519_sk, session_key->val.value.bin);

				np_aaatoken_t* old_token = NULL;
				if (NULL != msg_source_key->aaa_token &&
					IS_VALID(msg_source_key->aaa_token->state)
					)
				{
					// print warning if overwrite happens
					log_msg(LOG_WARN,
						"found valid authentication token for node %s (%p), overwriting...",
						_np_key_as_str(msg_source_key), msg_source_key->node->obj);
					old_token = msg_source_key->aaa_token;
					// msg_source_key->node->joined_network = FALSE;
				}

				np_ref_obj(np_aaatoken_t, tmp_token, ref_key_aaa_token);
				msg_source_key->aaa_token = tmp_token;
				np_unref_obj(np_aaatoken_t, old_token, ref_key_aaa_token);

				// handle alias key, also in case a new connection has been established
				log_debug_msg(LOG_ROUTING | LOG_DEBUG, "handshake for alias %s", _np_key_as_str(alias_key));

				alias_key->aaa_token = msg_source_key->aaa_token;
				np_ref_obj(np_aaatoken_t, msg_source_key->aaa_token, ref_key_aaa_token);

				alias_key->node = msg_source_key->node;
				np_ref_obj(np_node_t, msg_source_key->node, ref_key_node);

				if ((alias_key->node->protocol & PASSIVE) == PASSIVE)
				{
					np_ref_obj(np_network_t, alias_key->network, ref_key_network);
					np_unref_obj(np_network_t, msg_source_key->network, ref_key_network);
					msg_source_key->network = alias_key->network;

					_np_network_stop(msg_source_key->network, TRUE);
					// TODO: split up in two libev callbacks (read/write)
					ev_io_init(
						&msg_source_key->network->watcher,
						_np_network_sendrecv,
						msg_source_key->network->socket,
						EV_WRITE | EV_READ);
					_np_network_start(msg_source_key->network);
				}
				else if ((alias_key->node->protocol & TCP) == TCP)
				{
					// with tcp we accepted the connection already and have an incoming channel defined
					// alias key and msg_source_key have different network_t structures, so there is nothing to do
				}
				else
				{
					if (IS_INVALID(msg_source_key->aaa_token->state)) {
						// new connection, setup alias key
						//alias_key->network = msg_source_key->network;
						//np_ref_obj(np_network_t, alias_key->network, ref_key_network);
					}
				}

				// copy over session key
				memcpy(msg_source_key->node->session_key, shared_secret, crypto_scalarmult_SCALARBYTES*(sizeof(unsigned char)));
				msg_source_key->node->session_key_is_set = TRUE;

				/* Implicit: as both keys share the same token
				memcpy(alias_key->node->session_key, shared_secret, crypto_scalarmult_SCALARBYTES*(sizeof(unsigned char)));
				alias_key->node->session_key_is_set = TRUE;
				*/

				// mark as valid to identify existing connections
				msg_source_key->aaa_token->state |= AAA_VALID;
				msg_source_key->node->is_handshake_received = TRUE;

				_np_network_send_handshake(msg_source_key);

				log_debug_msg(LOG_ROUTING | LOG_DEBUG, "handshake data successfully registered for node %s (alias %s)",
					_np_key_as_str(msg_source_key), _np_key_as_str(alias_key));
			}
		}

	__np_cleanup__:
		np_unref_obj(np_aaatoken_t, tmp_token, ref_obj_creation);

		// __np_return__:
		np_unref_obj(np_key_t, msg_source_key,"_np_key_create_from_token");
		np_tree_free(hs_payload);
	}
	return;
}