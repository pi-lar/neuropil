//
// neuropil is copyright 2016 by pi-lar GmbH
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

#include "sodium.h"
#include "event/ev.h"

#include "np_dendrit.h"

#include "dtime.h"
#include "np_log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_memory.h"
#include "np_route.h"
#include "np_util.h"
#include "np_threads.h"
#include "np_tree.h"
#include "np_val.h"

/**
 * convenience helper macros when messages are received
 * check the existence of a field and extracts it, otherwise continues with a goto __cleanup__
 */
#define CHECK_STR_FIELD(TREE, FIELD_NAME, VAR_NAME) \
np_val_t VAR_NAME = NP_VAL_NULL; \
if (NULL == tree_find_str(TREE, FIELD_NAME)) goto __np_cleanup__; \
else VAR_NAME = tree_find_str(TREE, FIELD_NAME)->val;

/**
 ** message_received:
 ** is called by network_activate and will be passed received data and size from socket
 */
void _np_in_received(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_in_received");
	void* raw_msg = NULL;

	np_state_t* state = _np_state();
	np_network_t* my_network = state->my_node_key->network;

	np_message_t* msg_in = NULL;
	np_key_t* target_key = NULL;

	int ret;

	// we registered this token info before in the first handshake message
	np_key_t* alias_key = args->target;

	LOCK_CACHE(my_network)
	{
		raw_msg = sll_head(void_ptr, my_network->in_events);
	}

	if (NULL == raw_msg)
	{
			goto __np_cleanup__;
	}
	 log_msg(LOG_DEBUG, "alias_key %s", _key_as_str(alias_key));

	if (NULL != alias_key &&
		NULL != alias_key->aaa_token &&
		IS_VALID (alias_key->aaa_token->state) )
	{
		 log_msg(LOG_DEBUG, "/start decrypting message with alias %s", _key_as_str(alias_key));
		unsigned char nonce[crypto_secretbox_NONCEBYTES];

		unsigned char dec_msg[1024 - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES];
		memcpy(nonce, raw_msg, crypto_secretbox_NONCEBYTES);

		char nonce_hex[crypto_secretbox_NONCEBYTES*2+1];
		sodium_bin2hex(nonce_hex, crypto_secretbox_NONCEBYTES*2+1, nonce, crypto_secretbox_NONCEBYTES);
		// log_msg(LOG_DEBUG, "decryption nonce %s", nonce_hex);

		// char session_hex[crypto_scalarmult_SCALARBYTES*2+1];
		// sodium_bin2hex(session_hex, crypto_scalarmult_SCALARBYTES*2+1, alias_key->aaa_token->session_key, crypto_scalarmult_SCALARBYTES);
		// log_msg(LOG_DEBUG, "session    key   %s", session_hex);

		// log_msg(LOG_DEBUG, "now nonce (%s)", nonce);
		int ret = crypto_secretbox_open_easy(dec_msg,
				(const unsigned char *) raw_msg + crypto_secretbox_NONCEBYTES,
				1024 - crypto_secretbox_NONCEBYTES,
				nonce,
				alias_key->aaa_token->session_key);
		// log_msg(LOG_DEBUG, "/stop  decrypting message with alias %s", _key_as_str(alias_key));

		if (ret != 0)
		{
			log_msg(LOG_WARN,
					"incorrect decryption of message (send from %s)", _key_as_str(alias_key));
		}
		else
		{
			memset(raw_msg, 0, 1024);
			memcpy(raw_msg, dec_msg, 1024 - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);
		}
	}

	np_new_obj(np_message_t, msg_in);

	ret = np_message_deserialize(msg_in, raw_msg);
	if (FALSE == ret)
	{
		log_msg(LOG_ERROR, "error de-serializing message");
		goto __np_cleanup__;
	}

	// now read decrypted (or handshake plain text) message
	// char* msg_subject =
	// tree_find_str(msg_in->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
	CHECK_STR_FIELD(msg_in->header, NP_MSG_HEADER_SUBJECT, msg_subject);

	if ( 0 == strncmp(msg_subject.value.s, _NP_MSG_HANDSHAKE, strlen(_NP_MSG_HANDSHAKE)) )
	{
		// log_msg(LOG_DEBUG, "identified handshake message ...");
		if ( (NULL == alias_key->aaa_token) ||
			  IS_INVALID(alias_key->aaa_token->state) )
		{
			tree_insert_str(msg_in->footer, NP_MSG_FOOTER_ALIAS_KEY,
					new_val_s(_key_as_str(alias_key)));
			np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, _NP_MSG_HANDSHAKE);
			_np_job_submit_msgin_event(0.0, msg_prop, state->my_node_key, msg_in);
		}
		else
		{
			log_msg(LOG_DEBUG, "... handshake is already complete");
		}

		goto __np_cleanup__;
	}

	/* real receive part */
	CHECK_STR_FIELD(msg_in->header, NP_MSG_HEADER_TO, msg_to);
	CHECK_STR_FIELD(msg_in->instructions, NP_MSG_INST_UUID, msg_uuid);
	CHECK_STR_FIELD(msg_in->instructions, NP_MSG_INST_TSTAMP, msg_tstamp);
	CHECK_STR_FIELD(msg_in->instructions, NP_MSG_INST_TTL, msg_ttl);
	CHECK_STR_FIELD(msg_in->instructions, NP_MSG_INST_ACK, msg_ack);

//	char*   msg_to      = tree_find_str(msg_in->header, NP_MSG_HEADER_TO)->val.value.s;
//	char*   msg_uuid    = tree_find_str(msg_in->instructions, NP_MSG_INST_UUID)->val.value.s;
//	double  msg_tstamp  = tree_find_str(msg_in->instructions, NP_MSG_INST_TSTAMP)->val.value.d;
//	double  msg_ttl     = tree_find_str(msg_in->instructions, NP_MSG_INST_TTL)->val.value.d;
//	uint8_t msg_ack     = tree_find_str(msg_in->instructions, NP_MSG_INST_ACK)->val.value.ush;

	if (0 == strncmp(_NP_MSG_ACK, msg_subject.value.s, strlen(_NP_MSG_ACK)))
	{
		CHECK_STR_FIELD(msg_in->instructions, NP_MSG_INST_ACKUUID, ack_uuid);

		/* just an acknowledgement of own messages send out earlier */
		LOCK_CACHE(my_network)
		{
			np_tree_elem_t *jrb_node = tree_find_str(my_network->waiting, ack_uuid.value.s);
			if (jrb_node != NULL)
			{
				np_ackentry_t *entry = (np_ackentry_t *) jrb_node->val.value.v;
				entry->received_ack++;
				if (entry->expected_ack == entry->received_ack)
				{
					entry->acked = TRUE;
					entry->acktime = ev_time();
				}
				log_msg(LOG_DEBUG, "received acknowledgment of uuid=%s", ack_uuid.value.s);
			}
		}
		goto __np_cleanup__;
	}

	log_msg(LOG_DEBUG, "received message for subject: %s (uuid=%s, ack=%hhd)",
			msg_subject.value.s, msg_uuid.value.s, msg_ack.value.ush);

	// check time-to-live for message and expiry if neccessary
	double now = ev_time();
	if (now > (msg_tstamp.value.d + msg_ttl.value.d))
	{
		log_msg(LOG_INFO, "message ttl expired, dropping message (part) %s / %s",
						  msg_uuid.value.s, msg_subject.value.s);
		log_msg(LOG_DEBUG, "now: %f, msg_ttl: %f", now, msg_ttl.value.d);
		goto __np_cleanup__;
	}

	// check if an acknowledge has to be send
	if (0 < (msg_ack.value.ush & ACK_EACHHOP))
	{
		/* acknowledge part, each hop has to acknowledge the message */
		// TODO: move this ack after a) a message handler has been found or b) the message has been forwarded
		np_key_t* ack_key = NULL;
		CHECK_STR_FIELD(msg_in->instructions, NP_MSG_INST_ACK_TO, ack_to);
		// char* ack_to = tree_find_str(msg_in->instructions, NP_MSG_INST_ACK_TO)->val.value.s;
		np_dhkey_t search_key = dhkey_create_from_hash(ack_to.value.s);

		_LOCK_MODULE(np_keycache_t)
		{
			ack_key = _np_key_find_create(search_key);
		}

		if (NULL != ack_key                       &&
			NULL != ack_key->node                 &&
			TRUE == ack_key->node->joined_network &&
			np_node_check_address_validity(ack_key->node))
		{
			np_message_t* ack_msg_out = NULL;
			np_new_obj(np_message_t, ack_msg_out);
			np_msgproperty_t* ack_prop = np_msgproperty_get(OUTBOUND, _NP_MSG_ACK);
			np_message_create(ack_msg_out, ack_key, state->my_node_key, _NP_MSG_ACK, NULL);

			/* add/create network header */
			tree_insert_str(ack_msg_out->instructions, NP_MSG_INST_ACK, new_val_ush(ack_prop->ack_mode));
			tree_insert_str(ack_msg_out->instructions, NP_MSG_INST_ACKUUID, new_val_s(msg_uuid.value.s));
			tree_insert_str(ack_msg_out->instructions, NP_MSG_INST_TSTAMP, new_val_d(ev_time()));
			tree_insert_str(ack_msg_out->instructions, NP_MSG_INST_TTL, new_val_d(1.0));

			log_msg(LOG_DEBUG, "sending back acknowledge for: %s (seq=%s, ack=%hhd)",
					msg_subject.value.s, msg_uuid.value.s, msg_ack.value.ush);

			_np_job_submit_route_event(0.0, ack_prop, ack_key, ack_msg_out);
			np_free_obj(np_message_t, ack_msg_out);
			// user space acknowledgement handled later, also for join messages
		}
	}

	np_dhkey_t target_dhkey;
	_str_to_dhkey(msg_to.value.s, &target_dhkey);

	np_new_obj(np_key_t, target_key);
	target_key->dhkey = target_dhkey;

	np_dhkey_t wildcard_key = dhkey_create_from_hostport("*","0");
	//	if () {
//		log_msg(LOG_DEBUG, "received wildcart msg");
//		char tmp[128];
//		_np_node_encode_to_str(tmp, 128, alias_key->node);
//		np_send_join(tmp);
//		goto __np_cleanup__;
//	}

	// check if inbound subject handler exists
	np_msgproperty_t* handler = np_msgproperty_get(INBOUND, msg_subject.value.s);

	// redirect message if
	// a: msg is not for my dhkey
	// b: is not for a wildcard key
	// no handler is present
	if (! (_dhkey_equal(&args->target->dhkey, &wildcard_key) || _dhkey_equal(&args->target->dhkey, &state->my_node_key->dhkey)) || handler == NULL)
	{
		log_msg(LOG_DEBUG, "perform route_lookup");

		// perform a route lookup
		np_sll_t(np_key_t, tmp) = NULL;

		_LOCK_MODULE(np_routeglobal_t)
		{	// zero as "consider this node as final target"
			tmp = route_lookup(target_key, 0);

			if (0 < sll_size(tmp))
				log_msg(LOG_DEBUG, "route_lookup result 1 = %s", _key_as_str(sll_first(tmp)->val));
		}

		if (NULL         != tmp &&
			sll_size(tmp) > 0   &&
			(!_dhkey_equal(&sll_first(tmp)->val->dhkey, &state->my_node_key->dhkey)) )
		{
			log_msg(LOG_DEBUG, "received unrecognized message type %s, requesting forwarding of message ...",
								msg_subject.value.s);
			np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _DEFAULT);
			_np_job_submit_route_event(0.0, prop, args->target, msg_in);

			sll_free(np_key_t, tmp);
			goto __np_cleanup__;
		}
		sll_free(np_key_t, tmp);
		log_msg(LOG_DEBUG, "internal routing for subject '%s'", msg_subject.value.s);
	}


	// if this message really has to be handled by this node, does a handler exists ?
	if ( NULL == handler )
	{
		log_msg(LOG_WARN,
				"no incoming callback function was found for type %s, dropping message %s",
				handler->msg_subject, msg_uuid.value.s);
		goto __np_cleanup__;
	}

	// sum up message parts if the message is for this node
	args->msg = msg_in;
	np_message_t* msg_to_submit = np_message_check_chunks_complete(args);
	args->msg = NULL;
	if (NULL == msg_to_submit)
	{
		goto __np_cleanup__;
	}

	if (TRUE == state->my_node_key->node->joined_network ||
		0 == strncmp(msg_subject.value.s, _NP_MSG_JOIN, strlen(_NP_MSG_JOIN)) )
	{
		// finally submit msg job for later execution
		np_message_deserialize_chunked(msg_to_submit);
		_np_job_submit_msgin_event(0.0, handler, state->my_node_key, msg_to_submit);
		np_unref_obj(np_message_t, msg_to_submit);
	}

	// clean the mess up
	__np_cleanup__:
	if (NULL != target_key) np_free_obj(np_key_t, target_key);
	if (NULL != msg_in)     np_free_obj(np_message_t, msg_in);

	// __np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_received");
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
	log_msg(LOG_TRACE, ".start._np_in_piggy");
	np_state_t* state = _np_state();
	np_key_t* node_entry = NULL;
	// double tmp_ft;
	np_sll_t(np_key_t, o_piggy_list) = NULL;

	_LOCK_MODULE(np_keycache_t)
	{
		o_piggy_list = _np_decode_nodes_from_jrb(args->msg->body);
	}

	while (NULL != (node_entry = sll_head(np_key_t, o_piggy_list)))
	{
		// add entries in the message to our routing table
		// routing table is responsible to handle possible double entries
		// tmp_ft = node_entry->node->failuretime;

		// TODO: those new entries in the piggy message must be authenticated before sending join requests

		if (!_dhkey_equal(&node_entry->dhkey, &state->my_node_key->dhkey) &&
			HANDSHAKE_INITIALIZED > node_entry->node->handshake_status &&
			FALSE == node_entry->node->joined_network)
		{
			// just record nodes in the network or send an join request as well ?
			// answer: only send join request !
			// if (GRACEPERIOD > (ev_time() - tmp_ft))
			// {
				np_tree_t* jrb_me = make_nptree();
				np_encode_aaatoken(jrb_me, state->my_identity->aaa_token);

				np_message_t* msg_out = NULL;
				np_new_obj(np_message_t, msg_out);
				np_message_create(msg_out, node_entry, state->my_node_key, _NP_MSG_JOIN_REQUEST, jrb_me);

				log_msg(LOG_DEBUG, "submitting join request to target key %s", _key_as_str(node_entry));
				np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _NP_MSG_JOIN_REQUEST);
				_np_job_submit_msgout_event(0.0, prop, node_entry, msg_out);

				np_free_obj(np_message_t, msg_out);
		}
	}
	sll_free(np_key_t, o_piggy_list);

	// __np_cleanup__:
	// nothing to do
	// __np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_piggy");
	return;
}

/** _np_signal
 ** np_signal registered when np_receive function is used to receive message.
 ** it is invoked after a message has been send from the sender of messages and sends a signal to the
 ** np_receive function
 **/
void _np_signal (np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_signal");
	np_message_t* msg_in = args->msg;

	CHECK_STR_FIELD(msg_in->header, NP_MSG_HEADER_SUBJECT, msg_subject);
	CHECK_STR_FIELD(msg_in->header, NP_MSG_INST_ACK, msg_ack_mode);

	np_msgproperty_t* real_prop = np_msgproperty_get(INBOUND, msg_subject.value.s);

	log_msg(LOG_DEBUG, "pushing message into cache %p", real_prop);
	_LOCK_MODULE(np_msgproperty_t)
	{
		real_prop->msg_threshold++;
		sll_append(np_message_t, real_prop->msg_cache_in, args->msg);
		np_ref_obj(np_message_t, args->msg);
		// signal the np_receive function that the message has arrived
		log_msg(LOG_DEBUG, "signaling via available %p", real_prop);
		pthread_cond_signal(&real_prop->msg_received);
	}

	// TODO: more detailed msg ack handling
	if (0 < (msg_ack_mode.value.ush & ACK_DESTINATION))
	{
		_np_send_ack(args->msg);
	}

	__np_cleanup__:
	// nothing to do
	// __np_return__:
	log_msg(LOG_TRACE, ".end  .np_signal");
	return;
}

/** _np_callback_wrapper
 ** _np_callback_wrapper is used when a callback function is used to receive messages
 ** The purpose is automated acknowledge handling in case of ACK_CLIENT message subjects
 ** the user defined callback has to return TRUE in case the ack can be send, or FALSE
 ** if e.g. validation of the message has failed.
 **/
void _np_callback_wrapper(np_jobargs_t* args)
{
	np_message_t* msg_in = args->msg;
	np_aaatoken_t* sender_token = NULL;

	char* subject = args->properties->msg_subject;
	np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, subject);
	msg_prop->msg_threshold++;

	CHECK_STR_FIELD(msg_in->header, NP_MSG_HEADER_FROM, msg_from);
	CHECK_STR_FIELD(msg_in->instructions, NP_MSG_INST_ACK, msg_ack_mode);

	sender_token = _np_get_sender_token((char*) subject, msg_from.value.s);
	if (NULL == sender_token)
	{
		_np_add_msg_to_recv_cache(msg_prop, msg_in);
		goto __np_return__;
	}

	log_msg(LOG_DEBUG, "decrypting message ...");
	tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;

	np_bool decrypt_ok = np_message_decrypt_payload(msg_in, sender_token);
	if (FALSE == decrypt_ok)
	{
		tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui--;
		goto __np_cleanup__;
	}

	if (0 < (msg_ack_mode.value.ush & ACK_DESTINATION))
	{
		_np_send_ack(args->msg);
	}

	np_bool result = msg_prop->user_clb(msg_in->properties, msg_in->body);
	msg_prop->msg_threshold--;

	// CHECK_STR_FIELD(msg_in->properties, NP_MSG_INST_SEQ, received);
	// log_msg(LOG_INFO, "handled message %u with result %d ", received.value.ul, result);

	if (0 < (msg_ack_mode.value.ush & ACK_CLIENT) && (TRUE == result))
	{
		_np_send_ack(args->msg);
	}

	__np_cleanup__:
	if (NULL != sender_token) np_unref_obj(np_aaatoken_t, sender_token);

	__np_return__:
	log_msg(LOG_TRACE, ".end  .np_signal");
	return;
}

/** _np_in_leave_req:
 ** internal function that is called at the destination of a JOIN message. This
 ** call encodes the leaf set of the current host and sends it to the joiner.
 **/
void _np_in_leave_req(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_in_leave_req");
	np_key_t* leave_req_key = NULL;
	np_aaatoken_t* node_token = NULL;

	np_new_obj(np_aaatoken_t, node_token);
	np_decode_aaatoken(args->msg->body, node_token);

	_LOCK_MODULE(np_keycache_t)
	{
		leave_req_key = _np_create_node_from_token(node_token);
	}

	np_key_t* deleted = NULL;
	_LOCK_MODULE(np_routeglobal_t)
	{
		leafset_update(leave_req_key, FALSE, &deleted, NULL);
		if (NULL != deleted)
		{
			np_unref_obj(np_key_t, deleted);
		}
	}

	deleted = NULL;
	_LOCK_MODULE(np_routeglobal_t)
	{
		route_update(leave_req_key, FALSE, &deleted, NULL);
		if (NULL != deleted)
		{
			np_unref_obj(np_key_t, deleted);
		}
	}

	// __np_cleanup__:
	// nothing to do
	// __np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_leave_req");
	return;
}
//
//void _np_in_join_wildcard_req(np_jobargs_t* args){
//	log_msg(LOG_TRACE, ".start._np_in_join_wildcard_req");
//
//	np_msgproperty_t *msg_prop = NULL;
//	np_key_t* join_req_key = NULL;
//	np_message_t* msg_out = NULL;
//	np_aaatoken_t* join_token = NULL;
//
//	np_new_obj(np_aaatoken_t, join_token);
//	np_decode_aaatoken(args->msg->body, join_token);
//
//	if (FALSE == token_is_valid(join_token))
//	{
//		// silently exit join protocol for invalid tokens
//		goto __np_cleanup__;
//	}
//
//    // build a hash to find a place in the dhkey table, not for signing !
//	np_dhkey_t search_key = _np_create_dhkey_for_token(join_token);
//	_LOCK_MODULE(np_keycache_t)
//	{
//		join_req_key = _np_key_find_create(search_key);
//		if (NULL == join_req_key->aaa_token)
//		{
//			join_req_key->aaa_token = join_token;
//			np_ref_obj(np_aaatoken_t, join_token);
//		}
//	}
//	np_send_join(_key_as_str( join_req_key));
//
//	__np_cleanup__:
//		if (NULL != join_token) np_free_obj(np_aaatoken_t, join_token);
//		if (NULL != msg_out)    np_free_obj(np_message_t, msg_out);
//
//		// __np_return__:
//		log_msg(LOG_TRACE, ".end  ._np_in_join_wildcard_req");
//}

/** _np_in_join_req:
 ** internal function that is called at the destination of a JOIN message. This
 ** call encodes the leaf set of the current host and sends it to the joiner.
 **/
void _np_in_join_req(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_in_join_req");

	np_msgproperty_t *msg_prop = NULL;
	np_key_t* join_req_key = NULL;
	np_message_t* msg_out = NULL;
	np_aaatoken_t* join_token = NULL;

	np_new_obj(np_aaatoken_t, join_token);
	np_decode_aaatoken(args->msg->body, join_token);

	log_msg(LOG_DEBUG, "check token is valid");
	if (FALSE == token_is_valid(join_token))
	{
		// silently exit join protocol for invalid tokens
		goto __np_cleanup__;
	}
	log_msg(LOG_DEBUG, "token is valid");

    // build a hash to find a place in the dhkey table, not for signing !
	np_dhkey_t search_key = _np_create_dhkey_for_token(join_token);
	_LOCK_MODULE(np_keycache_t)
	{
		join_req_key = _np_key_find_create(search_key);
		if (NULL == join_req_key->aaa_token)
		{
			join_req_key->aaa_token = join_token;
			np_ref_obj(np_aaatoken_t, join_token);
		}
	}

	log_msg(LOG_DEBUG, "find target node");
	np_key_t* routing_key = NULL;
	if (NULL != tree_find_str(join_token->extensions, "target_node"))
	{
		np_dhkey_t search_key = dhkey_create_from_hash(tree_find_str(join_token->extensions, "target_node")->val.value.s);
		routing_key = _np_key_find_create(search_key);
	}
	else
	{
		routing_key = join_req_key;
	}

	/* check to see if the node has just left the network or not */
	// double timeval = dtime();

	/* if ((timeval - sourceNode->failuretime) < GRACEPERIOD) {
		log_msg(LOG_WARN,
				"JOIN request for node: %s:%hd rejected, elapsed time since failure = %f-%f sec",
				sourceNode->dns_name, sourceNode->port, timeval, sourceNode->failuretime);

		np_new(np_message_t, o_msg_out);
		np_message_create(o_msg_out, sourceNode->key, state->neuropil->me->key, NP_MSG_JOIN_NACK, NULL );
		msg_prop = np_msgproperty_get(OUTBOUND, NP_MSG_JOIN_NACK);
		_np_job_submit_msg_event(msg_prop, sourceNode->key, o_msg_out);
		np_unref(np_message_t, o_msg_out);

		sourceNode->handshake_status = HANDSHAKE_UNKNOWN;
		// np_aaatoken_t* aaa_token = np_get_authentication_token(state->aaa_cache, sourceNode->key);
		// aaa_token->valid = 0;

		np_send_ack(state, args);

		np_unbind(np_message_t, args->msg, msg_in);
		return;
	} */

	// check for allowance of token by user defined function
	np_state_t* state = _np_state();
	np_bool send_reply = FALSE;
	log_msg(LOG_DEBUG, "JOIN request key %s", _key_as_str(join_req_key));

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

	CHECK_STR_FIELD(args->msg->instructions, NP_MSG_INST_UUID, in_uuid);

	np_new_obj(np_message_t, msg_out);

	if (IS_AUTHENTICATED(join_req_key->aaa_token->state))
	{
		log_msg(LOG_INFO,
				"JOIN request approved, sending back join acknowledge for key %s",
				_key_as_str(join_req_key));

		np_tree_t* jrb_me = make_nptree();
		np_encode_aaatoken(jrb_me, state->my_identity->aaa_token);

		np_message_create(msg_out, routing_key, state->my_node_key, _NP_MSG_JOIN_ACK, jrb_me);
		tree_insert_str(msg_out->instructions, NP_MSG_INST_ACKUUID, in_uuid);

		msg_prop = np_msgproperty_get(OUTBOUND, _NP_MSG_JOIN_ACK);
		state->my_node_key->node->joined_network = TRUE;
		routing_key->node->joined_network = TRUE;

		send_reply = TRUE;
	}

	if (FALSE == state->enable_realm_slave &&
		IS_NOT_AUTHENTICATED(join_req_key->aaa_token->state))
	{
		log_msg(LOG_INFO,
				"JOIN request denied by user implementation, rejected key %s",
				_key_as_str(join_req_key) );

		np_message_create(msg_out, routing_key, state->my_node_key, _NP_MSG_JOIN_NACK, NULL );
		tree_insert_str(msg_out->instructions, NP_MSG_INST_ACKUUID, in_uuid);
		msg_prop = np_msgproperty_get(OUTBOUND, _NP_MSG_JOIN_NACK);
		send_reply = TRUE;
	}

	// TODO: chicken egg problem, we have to insert the entry into the table to be able to send back the JOIN.NACK
	np_key_t *added = NULL, *deleted = NULL;
	_LOCK_MODULE(np_routeglobal_t)
	{
		leafset_update(routing_key, TRUE, &deleted, &added);
		if (routing_key == added)
		{
			np_ref_obj(np_key_t, added);
		}
		if (NULL != deleted && routing_key != deleted)
		{
			np_unref_obj(np_key_t, deleted);
		}
	}

	added = NULL, deleted = NULL;
	_LOCK_MODULE(np_routeglobal_t)
	{
		route_update(routing_key, TRUE, &deleted, &added);
		if (routing_key == added)
		{
			np_ref_obj(np_key_t, added);
		}
		if (NULL != deleted && routing_key != deleted)
		{
			np_unref_obj(np_key_t, deleted);
		}
	}

	if (TRUE == send_reply)
	{
		_np_job_submit_msgout_event(0.0, msg_prop, routing_key, msg_out);
		_np_send_ack(args->msg);
	}

	__np_cleanup__:
	if (NULL != join_token) np_free_obj(np_aaatoken_t, join_token);
	if (NULL != msg_out)    np_free_obj(np_message_t, msg_out);

	// __np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_join_req");
	return;
}

/** _np_in_join_ack:
 ** called when the current node is joining the network and has just received
 ** its leaf set. This function sends an update message to all nodes in its
 ** new leaf set to announce its arrival.
 **/
void _np_in_join_ack(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_in_join_ack");

	np_message_t* msg_out = NULL;
	np_key_t* join_key = NULL;
	np_msgproperty_t* out_props = NULL;
	np_aaatoken_t* join_token = NULL;

	np_new_obj(np_aaatoken_t, join_token);
	np_decode_aaatoken(args->msg->body, join_token);

	if (FALSE == token_is_valid(join_token))
	{
		// silently exit join protocol for invalid tokens
		goto __np_cleanup__;
	}

	np_dhkey_t search_key = _np_create_dhkey_for_token(join_token);
	_LOCK_MODULE(np_keycache_t)
	{
		join_key = _np_key_find_create(search_key);

		if (NULL != join_key &&
			NULL == join_key->aaa_token)
		{
			join_key->aaa_token = join_token;
			np_ref_obj(np_aaatoken_t, join_key->aaa_token);
			// if a join ack is received here, then this node has send the join request
			join_key->aaa_token->state |= AAA_AUTHENTICATED;
		}
	}

	if (NULL == join_key)
	{
		goto __np_cleanup__;
	}

	np_key_t* routing_key = NULL;
	if (NULL != tree_find_str(join_token->extensions, "target_node"))
	{
		np_dhkey_t search_key = dhkey_create_from_hash(tree_find_str(join_token->extensions, "target_node")->val.value.s);
		routing_key = _np_key_find(search_key);
		routing_key->aaa_token->state |= AAA_AUTHENTICATED;
	}
	else
	{
		routing_key = join_key;
	}

	/* acknowledgement of join message send out earlier */
	CHECK_STR_FIELD(args->msg->instructions, NP_MSG_INST_ACKUUID, ack_uuid);

	np_state_t* state = _np_state();
	np_network_t* ng = state->my_node_key->network;

	LOCK_CACHE(ng)
	{
		np_tree_elem_t *jrb_node = tree_find_str(ng->waiting, ack_uuid.value.s);
		if (jrb_node != NULL)
		{
			np_ackentry_t *entry = (np_ackentry_t *) jrb_node->val.value.v;
			entry->acked = TRUE;
			entry->acktime = ev_time();
			log_msg(LOG_DEBUG, "received acknowledgment of JOIN uuid=%s", ack_uuid.value.s);
		}
	}

	// should never happen
	if (NULL == routing_key || NULL == routing_key->node)
	{
		goto __np_cleanup__;
	}

	if (NULL != routing_key->node)
	{
		// node cannot be NULL, but checker complains otherwise
		log_msg(LOG_INFO,
				"received join acknowledgement for node key %s", _key_as_str(routing_key));
	}

	/* announce arrival of new node to the nodes in my routing table */
	// TODO: check for protected node neighbours ?
	np_sll_t(np_key_t, nodes) = NULL;

	_LOCK_MODULE(np_routeglobal_t)
	{
		nodes = _np_route_get_table();
	}

	np_key_t* elem = NULL;
	while ( NULL != (elem = sll_head(np_key_t, nodes)))
	{
		// send update of new node to all nodes in my routing table
		if (_dhkey_equal(&elem->dhkey, &routing_key->dhkey)) continue;

		np_new_obj(np_message_t, msg_out);

		// encode informations -> has to be done for each update message new
		// otherwise there is a crash when deleting the message
		np_tree_t* jrb_join_node = make_nptree();
		np_encode_aaatoken(jrb_join_node, join_token);

		np_message_create(msg_out, elem, state->my_node_key, _NP_MSG_UPDATE_REQUEST, jrb_join_node);
		out_props = np_msgproperty_get(OUTBOUND, _NP_MSG_UPDATE_REQUEST);
		_np_job_submit_route_event(0.0, out_props, elem, msg_out);
	}
	sll_free(np_key_t, nodes);

	// remember key for routing table update
	log_msg(LOG_DEBUG, "join acknowledged and updates to other nodes send");

	// update table
	np_key_t *added = NULL, *deleted = NULL;
	_LOCK_MODULE(np_routeglobal_t)
	{
		route_update(routing_key, TRUE, &deleted, &added);
		if (added == routing_key)
		{
			np_ref_obj(np_key_t, added);
		}
		if (deleted != NULL && deleted != routing_key)
		{
			np_unref_obj(np_key_t, deleted);
		}
	}

	// update leafset
	added = NULL, deleted = NULL;
	_LOCK_MODULE(np_routeglobal_t)
	{
		leafset_update(routing_key, TRUE, &deleted, &added);
		if (added == routing_key)
		{
			np_ref_obj(np_key_t, added);
		}
		if (deleted != NULL && deleted != routing_key)
		{
			np_unref_obj(np_key_t, deleted);
		}
	}

	// send an initial piggy message to the new node in our routing table
	np_msgproperty_t* piggy_prop = np_msgproperty_get(TRANSFORM, _NP_MSG_PIGGY_REQUEST);
	_np_job_submit_transform_event(0.0, piggy_prop, routing_key, NULL);

	routing_key->node->joined_network = TRUE;
	// just in case it has not been set until now
	state->my_node_key->node->joined_network = TRUE;

	__np_cleanup__:
	if (NULL != join_token) np_free_obj(np_aaatoken_t, join_token);

	// nothing to do
	// __np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_join_ack");
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
	log_msg(LOG_TRACE, ".start._np_in_join_nack");

	np_state_t* state = _np_state();
	np_network_t* ng = state->my_node_key->network;
	np_key_t* nack_key = NULL;

	CHECK_STR_FIELD(args->msg->header, NP_MSG_HEADER_FROM, msg_from);
	CHECK_STR_FIELD(args->msg->instructions, NP_MSG_INST_ACKUUID, ack_uuid);

	np_dhkey_t search_key = dhkey_create_from_hash(msg_from.value.s);
	_LOCK_MODULE(np_keycache_t)
	{
		nack_key = _np_key_find(search_key);
	}

	LOCK_CACHE(ng)
	{
		np_tree_elem_t *jrb_node = tree_find_str(ng->waiting, ack_uuid.value.s);
		if (jrb_node != NULL)
		{
			np_ackentry_t *entry = (np_ackentry_t *) jrb_node->val.value.v;
			entry->acked = TRUE;
			entry->acktime = ev_time();
			log_msg(LOG_DEBUG, "received not-acknowledgment of JOIN uuid=%s", ack_uuid.value.s);
		}
	}

	// should never happen
	if (NULL == nack_key || NULL == nack_key->node)
	{
		log_msg(LOG_TRACE, ".start._np_in_join_nack");
		return;
	}

	log_msg(LOG_INFO, "JOIN request rejected from key %s !", _key_as_str(nack_key));

	nack_key->aaa_token->state &= AAA_INVALID;
	nack_key->node->joined_network = FALSE;
	nack_key->node->handshake_status = HANDSHAKE_UNKNOWN;

	__np_cleanup__:
	// nothing to do
	// __np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_join_nack");
	return;
}

void _np_in_ping(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_in_ping");
	np_message_t *msg_out = NULL;
	np_key_t* ping_key = NULL;

	CHECK_STR_FIELD(args->msg->header, NP_MSG_HEADER_FROM, msg_from);

	np_dhkey_t search_key = dhkey_create_from_hash(msg_from.value.s);

	_LOCK_MODULE(np_keycache_t)
	{
		ping_key = _np_key_find(search_key);
	}

	// send out a ping reply if the hostname and port is known
	if (NULL               != ping_key                          &&
		NULL 			   != ping_key->node                    &&
		HANDSHAKE_COMPLETE == ping_key->node->handshake_status)
	{
		log_msg(LOG_DEBUG, "received a PING message from %s:%s !", ping_key->node->dns_name, ping_key->node->port);

		np_node_update_stat(ping_key->node, 1);

		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, ping_key, _np_state()->my_node_key, _NP_MSG_PING_REPLY, NULL );
		np_msgproperty_t* msg_pingreply_prop = np_msgproperty_get(OUTBOUND, _NP_MSG_PING_REPLY);
		_np_job_submit_msgout_event(0.0, msg_pingreply_prop, ping_key, msg_out);
		np_free_obj(np_message_t, msg_out);
	}
	else
	{
		log_msg(LOG_WARN, "received a PING message from unknown %s !", _key_as_str(ping_key));
	}

	__np_cleanup__:
		// nothing to do
	// __np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_ping");
	return;
}

void _np_in_pingreply(np_jobargs_t * args)
{
	np_key_t* pingreply_key = NULL;

	CHECK_STR_FIELD(args->msg->header, NP_MSG_HEADER_FROM, msg_from);

	np_dhkey_t search_key = dhkey_create_from_hash(msg_from.value.s);
	_LOCK_MODULE(np_keycache_t)
	{
		pingreply_key = _np_key_find(search_key);
	}

	if (NULL != pingreply_key &&
		NULL != pingreply_key->node &&
		0 < pingreply_key->node->failuretime)
	{
		double now = ev_time();

		if (now > pingreply_key->node->failuretime)
		{
			double latency = now - pingreply_key->node->failuretime;
			np_node_update_latency(pingreply_key->node, latency);
			// reset for next ping attempt
			pingreply_key->node->failuretime = 0;
		}
		np_node_update_stat(pingreply_key->node, 1);

		log_msg(LOG_DEBUG, "ping reply received from: %s:%s, latency now: %f!",
				pingreply_key->node->dns_name, pingreply_key->node->port,
			    pingreply_key->node->latency);
	}
	else
	{
		log_msg(LOG_DEBUG, "ignoring ping reply received from: %s:%s",
				pingreply_key->node->dns_name, pingreply_key->node->port);
	}

	__np_cleanup__:
	// nothing to do
	// __np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_pingreply");
	return;
}

// TODO: write a function that handles path discovery
// TODO: if this is not the target node, add my own address to the update message
// TODO: if this is the target node, change target to sending instance and send again

// receive information about new nodes in the network and try to contact new nodes
void _np_in_update(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_in_update");

	np_key_t *update_key = NULL;
	np_aaatoken_t* update_token = NULL;

	np_new_obj(np_aaatoken_t, update_token);
	np_decode_aaatoken(args->msg->body, update_token);
	if (FALSE == token_is_valid(update_token))
	{
		goto __np_cleanup__;
	}

	_LOCK_MODULE(np_keycache_t)
	{
		update_key = _np_create_node_from_token(update_token);
	}

	if (NULL == update_key->aaa_token)
	{
		update_key->aaa_token = update_token;
		np_ref_obj(np_aaatoken_t, update_token);
	}

	if (NULL != update_key &&
		NULL != update_key->node &&
		HANDSHAKE_INITIALIZED > update_key->node->handshake_status &&
		FALSE == update_key->node->joined_network)
	{
		np_tree_t* jrb_me = make_nptree();
		np_encode_aaatoken(jrb_me, _np_state()->my_identity->aaa_token);

		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, update_key, _np_state()->my_node_key, _NP_MSG_JOIN_REQUEST, jrb_me);

		log_msg(LOG_DEBUG, "submitting join request to target key %s", _key_as_str(update_key));
		np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _NP_MSG_JOIN_REQUEST);
		_np_job_submit_msgout_event(0.0, prop, update_key, msg_out);

		np_free_obj(np_message_t, msg_out);
	}
	goto __np_return__;

	// TODO: forward update token to other neighbours
	__np_cleanup__:
	if (NULL != update_token) np_free_obj(np_aaatoken_t, update_token);
	// nothing to do
	__np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_update");
	return;
}

void _np_in_discover_sender(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_in_discover_sender");
	np_key_t *reply_to_key = NULL;

	CHECK_STR_FIELD(args->msg->header, NP_MSG_HEADER_REPLY_TO, msg_reply_to);

	np_new_obj(np_key_t, reply_to_key);
	reply_to_key->dhkey = dhkey_create_from_hash(msg_reply_to.value.s);

	// extract e2e encryption details for sender
	np_aaatoken_t* msg_token = NULL;
	np_new_obj(np_aaatoken_t, msg_token);
	np_decode_aaatoken(args->msg->body, msg_token);

	if (FALSE == token_is_valid(msg_token))
	{
		goto __np_cleanup__;
	}

	// just store the available tokens in memory and update them if new data arrives
	_np_add_receiver_token(msg_token->subject, msg_token);

	// this node is the man in the middle - inform receiver of sender token
	np_sll_t(np_aaatoken_t, available_list) = _np_get_sender_token_all(msg_token->subject);
	np_aaatoken_t* tmp_token = NULL;

	while (NULL != (tmp_token = sll_head(np_aaatoken_t, available_list)))
	{
		log_msg(LOG_DEBUG, "found a sender of messages, sending back message availabilities ...");
		np_tree_t* available_data = make_nptree();

		np_encode_aaatoken(available_data, tmp_token);

		np_message_t *msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, reply_to_key, NULL, _NP_MSG_AVAILABLE_SENDER, available_data);
		np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_AVAILABLE_SENDER);
		_np_job_submit_route_event(0.0, prop_route, reply_to_key, msg_out);
		np_free_obj(np_message_t, msg_out);

		np_unref_obj(np_aaatoken_t, tmp_token);
	}
	sll_free(np_aaatoken_t, available_list);

	__np_cleanup__:
	if (NULL != reply_to_key) np_free_obj(np_key_t, reply_to_key);
	if (NULL != msg_token)    np_free_obj(np_aaatoken_t, msg_token);

	// __np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_discover_sender");
	return;
}

void _np_in_available_sender(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_in_available_sender");

	np_message_t *msg_in = args->msg;

	// extract e2e encryption details for sender
	np_aaatoken_t* msg_token = NULL;

	CHECK_STR_FIELD(args->msg->header, NP_MSG_HEADER_TO, msg_to);

	np_new_obj(np_aaatoken_t, msg_token);
	np_decode_aaatoken(msg_in->body, msg_token);

	// always?: just store the available tokens in memory and update them if new data arrives
	if (FALSE == token_is_valid(msg_token))
	{
		goto __np_cleanup__;
	}

	np_state_t* state = _np_state();

	np_dhkey_t sendtoken_issuer_key = dhkey_create_from_hash(msg_token->issuer);
	if (_dhkey_equal(&sendtoken_issuer_key, &state->my_identity->dhkey) )
	{
		// only add the token if it is not from ourself (in case of IN/OUTBOUND on same subject)
		goto __np_cleanup__;
	}

	log_msg(LOG_DEBUG, "now handling message availability");
	_np_add_sender_token(msg_token->subject, msg_token);

	np_dhkey_t to_key = dhkey_create_from_hash(msg_to.value.s);

	if ( _dhkey_equal(&to_key, &state->my_node_key->dhkey) )
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
		_np_check_receiver_msgcache(real_prop);
	}

	__np_cleanup__:
	if (NULL != msg_token)    np_free_obj(np_aaatoken_t, msg_token);

	// __np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_available_sender");
	return;
}

void _np_in_discover_receiver(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_in_discover_receiver");

	np_key_t *reply_to_key = NULL;
	np_aaatoken_t* msg_token = NULL;
	np_message_t *msg_in = args->msg;

	CHECK_STR_FIELD(msg_in->header, NP_MSG_HEADER_REPLY_TO, msg_reply_to);

	np_new_obj(np_key_t, reply_to_key);
	reply_to_key->dhkey = dhkey_create_from_hash(msg_reply_to.value.s);

	log_msg(LOG_DEBUG, "reply key: %s", _key_as_str(reply_to_key) );

	// extract e2e encryption details for sender
	np_new_obj(np_aaatoken_t, msg_token);
	np_decode_aaatoken(msg_in->body, msg_token);

	// always?: just store the available messages in memory and update if new data arrives
	if (FALSE == token_is_valid(msg_token))
	{
		goto __np_cleanup__;
	}

	log_msg(LOG_DEBUG, "now handling message availability");

	_np_add_sender_token(msg_token->subject, msg_token);

	np_aaatoken_t* tmp_token = NULL;
	np_sll_t(np_aaatoken_t, receiver_list) = _np_get_receiver_token_all(msg_token->subject);

	while (NULL != (tmp_token = sll_head(np_aaatoken_t, receiver_list)))
	{
		np_tree_t* interest_data = make_nptree();

		np_encode_aaatoken(interest_data, tmp_token);

		np_message_t *msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, reply_to_key, NULL, _NP_MSG_AVAILABLE_RECEIVER, interest_data);
		np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_AVAILABLE_RECEIVER);

		log_msg(LOG_DEBUG, "sending back msg interest to %s", _key_as_str(reply_to_key));
		_np_job_submit_route_event(0.0, prop_route, reply_to_key, msg_out);

		np_free_obj(np_message_t, msg_out);
		np_unref_obj(np_aaatoken_t, tmp_token);
	}
	sll_free(np_aaatoken_t, receiver_list);

	__np_cleanup__:
	if (NULL != reply_to_key) np_free_obj(np_key_t, reply_to_key);
	if (NULL != msg_token)    np_free_obj(np_aaatoken_t, msg_token);

	// __np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_discover_receiver");
	return;
}

void _np_in_available_receiver(np_jobargs_t* args)
{
	// extract e2e encryption details for sender
	np_aaatoken_t* msg_token = NULL;

	CHECK_STR_FIELD(args->msg->header, NP_MSG_HEADER_TO, msg_to);
	np_dhkey_t to_key = dhkey_create_from_hash(msg_to.value.s);

	np_new_obj(np_aaatoken_t, msg_token);
	np_decode_aaatoken(args->msg->body, msg_token);

	if (FALSE == token_is_valid(msg_token))
	{
		goto __np_cleanup__;
	}

	np_state_t* state = _np_state();

	np_dhkey_t recvtoken_issuer_key = dhkey_create_from_hash(msg_token->issuer);
	if (_dhkey_equal(&recvtoken_issuer_key, &state->my_identity->dhkey) )
	{
		// only add the token if it is not from ourself (in case of IN/OUTBOUND on same subject)
		goto __np_cleanup__;
	}

	log_msg(LOG_DEBUG, "now handling message interest");
	_np_add_receiver_token(msg_token->subject, msg_token);
	// check if we are (one of the) sending node(s) of this kind of message
	if ( _dhkey_equal(&to_key, &state->my_node_key->dhkey) )
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
		_np_check_sender_msgcache(real_prop);
	}

	__np_cleanup__:
	if (NULL != msg_token)    np_free_obj(np_aaatoken_t, msg_token);

	// __np_return__:
	log_msg(LOG_TRACE, ".end  ._np_in_discover_receiver");
	return;
}

void _np_in_authenticate(np_jobargs_t* args)
{
	np_key_t *reply_to_key = NULL;
	np_aaatoken_t* sender_token = NULL;
	np_aaatoken_t* authentication_token = NULL;
	np_message_t *msg_in = args->msg;

	args->properties->msg_threshold++;

	CHECK_STR_FIELD(msg_in->header, NP_MSG_HEADER_REPLY_TO, msg_reply_to);
	CHECK_STR_FIELD(msg_in->header, NP_MSG_HEADER_FROM, msg_from);

	np_new_obj(np_key_t, reply_to_key);
	reply_to_key->dhkey = dhkey_create_from_hash(msg_reply_to.value.s);
	log_msg(LOG_DEBUG, "reply key: %s", _key_as_str(reply_to_key) );

	sender_token = _np_get_sender_token((char*) _NP_MSG_AUTHENTICATION_REQUEST, msg_from.value.s);
	if (NULL == sender_token)
	{
		goto __np_cleanup__;
	}

	np_bool decrypt_ok = np_message_decrypt_payload(msg_in, sender_token);
	if (FALSE == decrypt_ok)
	{
		goto __np_cleanup__;
	}
	tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;

	// extract e2e encryption details for sender
	np_new_obj(np_aaatoken_t, authentication_token);
	np_decode_aaatoken(msg_in->body, authentication_token);

	// always?: just store the available messages in memory and update if new data arrives
	if (FALSE == token_is_valid(authentication_token))
	{
		goto __np_cleanup__;
	}

	log_msg(LOG_DEBUG, "now checking authentication of token");
	if (TRUE == _np_state()->authenticate_func(authentication_token))
	{
		authentication_token->state |= AAA_AUTHENTICATED;
	}

	if (IS_AUTHENTICATED(authentication_token->state) )
	{
		_np_add_receiver_token(_NP_MSG_AUTHENTICATION_REPLY, sender_token);

		np_tree_t* token_data = make_nptree();

		np_encode_aaatoken(token_data, authentication_token);
		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, reply_to_key, _np_state()->my_node_key, _NP_MSG_AUTHENTICATION_REPLY, token_data);
		np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHENTICATION_REPLY);

		log_msg(LOG_DEBUG, "sending back authenticated data to %s", _key_as_str(reply_to_key));
		if (NULL == reply_to_key->aaa_token)
		{
			reply_to_key->aaa_token = sender_token;
		}
		_np_job_submit_transform_event(0.0, prop_route, reply_to_key, msg_out);
		np_free_obj(np_message_t, msg_out);
	}
	else
	{
		log_msg(LOG_WARN, "unknown security token received for authentication, dropping token");
		log_msg(LOG_WARN, "i:%s s:%s", authentication_token->issuer, authentication_token->subject);
	}

	__np_cleanup__:
	if (NULL != reply_to_key) np_free_obj(np_key_t, reply_to_key);
	if (NULL != sender_token) np_unref_obj(np_aaatoken_t, sender_token);
	if (NULL != authentication_token) np_unref_obj(np_aaatoken_t, authentication_token);

	// __np_return__:
	args->properties->msg_threshold--;
	log_msg(LOG_TRACE, ".end  ._np_in_discover_receiver");
	return;
}

void _np_in_authenticate_reply(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_in_authenticate_reply");
	np_aaatoken_t* authentication_token = NULL;
	np_aaatoken_t* sender_token = NULL;
	np_key_t* subject_key = NULL;

	// args->properties->msg_threshold++;

	CHECK_STR_FIELD(args->msg->header, NP_MSG_HEADER_FROM, msg_from);

	sender_token = _np_get_sender_token((char*) _NP_MSG_AUTHENTICATION_REPLY, msg_from.value.s);
	if (NULL == sender_token)
	{
		log_msg(LOG_DEBUG, "no sender token for authentication reply found");
		goto __np_cleanup__;
	}

	// TODO: the following should not be required/possible, because it invalidates the token
	np_bool decrypt_ok = np_message_decrypt_payload(args->msg, sender_token);
	if (FALSE == decrypt_ok)
	{
		log_msg(LOG_DEBUG, "decryption of authentication reply failed");
		goto __np_cleanup__;
	}
	// tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;

	// extract e2e encryption details for sender
	np_new_obj(np_aaatoken_t, authentication_token);
	np_decode_aaatoken(args->msg->body, authentication_token);

	np_dhkey_t search_key;
	// TODO: validate token technically again
	if (0 == strncmp(authentication_token->subject, "urn:np:node:", 12))
	{
		search_key = dhkey_create_from_hash(authentication_token->issuer);
		// TODO: trigger JOIN request again if node has not joined ?

	} // TODO: add a token type to identify msg exchanges, nodes and real persons
	else /* if (0 == strncmp(authentication_token->subject, "urn:np:msg:", 11)) */
	{
		search_key = dhkey_create_from_hostport(authentication_token->subject, "0");
	}

	_LOCK_MODULE(np_keycache_t)
	{
		subject_key = _np_key_find_create(search_key);
	}

	if (0 == strncmp(authentication_token->subject, "urn:np:node:", 12))
	{
		subject_key->aaa_token->state |= AAA_AUTHENTICATED;
	}
	else /* if (0 == strncmp(authentication_token->subject, "urn:np:msg:", 11)) */
	{
		LOCK_CACHE(subject_key->recv_property)
		{
			pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
			while (NULL != iter)
			{
				np_aaatoken_t* tmp_token = iter->val;
				if (0 == strncmp(tmp_token->uuid, authentication_token->uuid, 255) )
				{
					tmp_token->state |= AAA_AUTHENTICATED;
					_np_check_receiver_msgcache(subject_key->recv_property);
					break;
				}
				// TODO: move to msgcache.h and change parameter
				pll_next(iter);
			}
		}

		LOCK_CACHE(subject_key->send_property)
		{
			pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->send_tokens);
			while (NULL != iter)
			{
				np_aaatoken_t* tmp_token = iter->val;
				if (0 == strncmp(tmp_token->uuid, authentication_token->uuid, 255) )
				{
					tmp_token->state |= AAA_AUTHENTICATED;
					_np_check_sender_msgcache(subject_key->send_property);
					break;
				}
				// TODO: move to msgcache.h and change parameter
				pll_next(iter);
			}
		}
	}

	__np_cleanup__:
	if (NULL != authentication_token) np_free_obj(np_aaatoken_t, authentication_token);
	if (NULL != sender_token)         np_unref_obj(np_aaatoken_t, sender_token);

	// __np_return__:
	// args->properties->msg_threshold--;
	log_msg(LOG_TRACE, ".end  ._np_in_authenticate_reply");
	return;
}

void _np_in_authorize(np_jobargs_t* args)
{
	np_key_t *reply_to_key = NULL;
	np_aaatoken_t* sender_token = NULL;
	np_aaatoken_t* authorization_token = NULL;

	np_message_t *msg_in = args->msg;

	args->properties->msg_threshold++;

	CHECK_STR_FIELD(msg_in->header, NP_MSG_HEADER_REPLY_TO, msg_reply_to);
	CHECK_STR_FIELD(msg_in->header, NP_MSG_HEADER_FROM, msg_from);

	np_new_obj(np_key_t, reply_to_key);
	reply_to_key->dhkey = dhkey_create_from_hash(msg_reply_to.value.s);
	log_msg(LOG_DEBUG, "reply key: %s", _key_as_str(reply_to_key) );

	sender_token = _np_get_sender_token((char*) _NP_MSG_AUTHORIZATION_REQUEST, msg_from.value.s);
	if (NULL == sender_token)
	{
		goto __np_cleanup__;
	}

	np_bool decrypt_ok = np_message_decrypt_payload(msg_in, sender_token);
	if (FALSE == decrypt_ok)
	{
		goto __np_cleanup__;
	}

	tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;
	// extract e2e encryption details for sender
	np_new_obj(np_aaatoken_t, authorization_token);
	np_decode_aaatoken(msg_in->body, authorization_token);

	// always?: just store the available messages in memory and update if new data arrives
	if (FALSE == token_is_valid(authorization_token))
	{
		goto __np_cleanup__;
	}

	log_msg(LOG_DEBUG, "now checking authorization of token");
	if (TRUE == _np_state()->authorize_func(authorization_token))
	{
		authorization_token->state |= AAA_AUTHORIZED;
	}

	if (IS_AUTHORIZED(authorization_token->state) )
	{
		_np_add_receiver_token(_NP_MSG_AUTHORIZATION_REPLY, sender_token);

		np_tree_t* token_data = make_nptree();
		np_encode_aaatoken(token_data, authorization_token);

		np_message_t* msg_out = NULL;
		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, reply_to_key, _np_state()->my_node_key, _NP_MSG_AUTHORIZATION_REPLY, token_data);
		np_msgproperty_t* prop_route = np_msgproperty_get(OUTBOUND, _NP_MSG_AUTHORIZATION_REPLY);

		log_msg(LOG_DEBUG, "sending back authorized data to %s", _key_as_str(reply_to_key));
		if (NULL == reply_to_key->aaa_token)
		{
			reply_to_key->aaa_token = sender_token;
		}
		_np_job_submit_transform_event(0.0, prop_route, reply_to_key, msg_out);
		np_free_obj(np_message_t, msg_out);
	}
	else
	{
		log_msg(LOG_WARN, "unknown security token received for authorization, dropping token");
		log_msg(LOG_WARN, "i:%s s:%s", authorization_token->issuer, authorization_token->subject);
	}

	__np_cleanup__:
	if (NULL != reply_to_key) np_free_obj(np_key_t, reply_to_key);
	if (NULL != sender_token) np_unref_obj(np_aaatoken_t, sender_token);
	if (NULL != authorization_token) np_unref_obj(np_aaatoken_t, authorization_token);

	// __np_return__:
	args->properties->msg_threshold--;
	log_msg(LOG_TRACE, ".end  ._np_in_discover_receiver");
	return;
}

void _np_in_authorize_reply(np_jobargs_t* args)
{
	np_aaatoken_t* authorization_token = NULL;
	np_aaatoken_t* sender_token = NULL;

	// args->properties->msg_threshold++;

	CHECK_STR_FIELD(args->msg->header, NP_MSG_HEADER_FROM, msg_from);

	sender_token = _np_get_sender_token((char*) _NP_MSG_AUTHORIZATION_REPLY, msg_from.value.s);
	if (NULL == sender_token)
	{
		goto __np_cleanup__;
	}

	np_bool decrypt_ok = np_message_decrypt_payload(args->msg, sender_token);
	if (FALSE == decrypt_ok)
	{
		goto __np_cleanup__;
	}

	// tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;

	// extract e2e encryption details for sender
	np_new_obj(np_aaatoken_t, authorization_token);
	np_decode_aaatoken(args->msg->body, authorization_token);

	np_key_t* subject_key = NULL;
	np_dhkey_t search_key;

	// TODO: validate token technically again
	if (0 == strncmp(authorization_token->subject, "urn:np:node:", 12))
	{
		search_key = dhkey_create_from_hash(authorization_token->issuer);
	}
	else /* if (0 == strncmp(authorization_token->subject, "urn:np:msg:", 11)) */
	{
		search_key = dhkey_create_from_hostport(authorization_token->subject, "0");
	}

	_LOCK_MODULE(np_keycache_t)
	{
		subject_key = _np_key_find_create(search_key);
	}

	if (0 == strncmp(authorization_token->subject, "urn:np:node:", 12))
	{
		subject_key->aaa_token->state |= AAA_AUTHORIZED;
	}
	else /* if (0 == strncmp(authorization_token->subject, "urn:np:msg:", 11)) */
	{
		LOCK_CACHE(subject_key->recv_property)
		{
			pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
			while (NULL != iter)
			{
				np_aaatoken_t* tmp_token = iter->val;
				if (0 == strncmp(tmp_token->uuid, authorization_token->uuid, 255) )
				{
					tmp_token->state |= AAA_AUTHORIZED;
					_np_check_receiver_msgcache(subject_key->recv_property);
					break;
				}
				// TODO: move to msgcache.h and change parameter
				pll_next(iter);
			}
		}

		LOCK_CACHE(subject_key->send_property)
		{
			pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->send_tokens);
			while (NULL != iter)
			{
				np_aaatoken_t* tmp_token = iter->val;
				if (0 == strncmp(tmp_token->uuid, authorization_token->uuid, 255) )
				{
					tmp_token->state |= AAA_AUTHORIZED;
					_np_check_sender_msgcache(subject_key->send_property);
					break;
				}
				pll_next(iter);
			}
		}
	}

	__np_cleanup__:
	if (NULL != authorization_token) np_free_obj(np_aaatoken_t, authorization_token);
	if (NULL != sender_token)        np_unref_obj(np_aaatoken_t, sender_token);

	// __np_return__:
	// args->properties->msg_threshold--;
	return;
}

void _np_in_account(np_jobargs_t* args)
{
	np_aaatoken_t* sender_token = NULL;
	np_aaatoken_t* accounting_token = NULL;

	args->properties->msg_threshold++;

	CHECK_STR_FIELD(args->msg->header, NP_MSG_HEADER_FROM, msg_from);

	sender_token = _np_get_sender_token((char*) _NP_MSG_ACCOUNTING_REQUEST, msg_from.value.s);
	if (NULL == sender_token)
	{
		goto __np_cleanup__;
	}

	tree_find_str(sender_token->extensions, "msg_threshold")->val.value.ui++;
	np_bool decrypt_ok = np_message_decrypt_payload(args->msg, sender_token);
	if (FALSE == decrypt_ok)
	{
		goto __np_cleanup__;
	}

	np_new_obj(np_aaatoken_t, accounting_token);
	np_decode_aaatoken(args->msg->body, accounting_token);

	log_msg(LOG_DEBUG, "now handling accounting for token");
	_np_state()->accounting_func(accounting_token);

	__np_cleanup__:
	if (NULL != accounting_token) np_free_obj(np_aaatoken_t, accounting_token);
	if (NULL != sender_token)        np_unref_obj(np_aaatoken_t, sender_token);

	// __np_return__:
	args->properties->msg_threshold--;
	return;
}

void _np_in_handshake(np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start._np_in_handshake");

	np_key_t* alias_key = NULL;
	np_aaatoken_t* tmp_token = NULL;
	np_tree_t* hs_payload = make_nptree();

	np_message_deserialize_chunked(args->msg);

	// initial handshake message contains public encryption parameter
	CHECK_STR_FIELD(args->msg->footer, NP_MSG_FOOTER_ALIAS_KEY, alias_dhkey);
	CHECK_STR_FIELD(args->msg->body, NP_HS_SIGNATURE, signature);
	CHECK_STR_FIELD(args->msg->body, NP_HS_PAYLOAD, payload);

	np_dhkey_t search_alias_key = dhkey_create_from_hash(alias_dhkey.value.s);

	cmp_ctx_t cmp;
	cmp_init(&cmp, payload.value.bin, buffer_reader, buffer_writer);
	deserialize_jrb_node_t(hs_payload, &cmp);

	np_new_obj(np_aaatoken_t, tmp_token);
	np_decode_aaatoken(hs_payload, tmp_token);

	char pk_hex[crypto_sign_PUBLICKEYBYTES*2+1];
	sodium_bin2hex(pk_hex, crypto_sign_PUBLICKEYBYTES*2+1, tmp_token->public_key, crypto_sign_PUBLICKEYBYTES);
	log_msg(LOG_DEBUG, "public key fingerprint: %s", pk_hex);

//	char* node_proto            = tree_find_str(hs_payload, "_np.protocol")->val.value.s;
//	char* node_hn               = tree_find_str(hs_payload, "_np.dns_name")->val.value.s;
//	char* node_port             = tree_find_str(hs_payload, "_np.port")->val.value.s;
//  np_tree_elem_t* public_key  = tree_find_str(hs_payload, "_np.public_key");
	np_tree_elem_t* session_key = tree_find_str(hs_payload, "_np.session");
//	double issued_at            = tree_find_str(hs_payload, "_np.issued_at")->val.value.d;
//	double expiration           = tree_find_str(hs_payload, "_np.expiration")->val.value.d;

	char sign_hex[crypto_sign_BYTES*2+1];
	sodium_bin2hex(sign_hex, crypto_sign_BYTES*2+1, signature.value.bin, crypto_sign_BYTES);
	log_msg(LOG_DEBUG, "signature key fingerprint: %s", sign_hex);

	if (0 != crypto_sign_verify_detached( (const unsigned char*) signature.value.bin,
			                              (const unsigned char*) payload.value.bin,
										  payload.size,
										  tmp_token->public_key) )
	{
		log_msg(LOG_ERROR, "incorrect signature in handshake message");
		goto __np_cleanup__;
	}

	log_msg(LOG_DEBUG, "decoding of handshake message from %s (i:%f/e:%f) complete",
			tmp_token->subject, tmp_token->issued_at, tmp_token->expiration);

	// store the handshake data in the node cache, use hostname/port for key generation
	// key could be changed later, but we need a way to lookup the handshake data later
	np_key_t* hs_key = NULL;
	_LOCK_MODULE(np_keycache_t)
	{
		hs_key = _np_create_node_from_token(tmp_token);
	}

	// should never happen
	if (NULL == hs_key)
	{
		goto __np_cleanup__;
	}

	if (NULL == hs_key->network)
	{
		np_new_obj(np_network_t, hs_key->network);
		if (!(hs_key->node->protocol & PASSIVE))
		{
			network_init(hs_key->network, FALSE, hs_key->node->protocol, hs_key->node->dns_name, hs_key->node->port);
			if (TRUE == hs_key->network->initialized)
			{
				hs_key->network->watcher.data = hs_key;
			}
			else
			{
				goto __np_cleanup__;
			}
		}
	}

	if (hs_key->node->handshake_status <= HANDSHAKE_INITIALIZED)
	{
		np_state_t* state = _np_state();

		np_aaatoken_t* my_id_token;
		my_id_token = state->my_node_key->aaa_token;

		// get our own identity from the cache and convert to curve key
		unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
		// unsigned char curve25519_pk[crypto_scalarmult_curve25519_BYTES];
		crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_id_token->private_key);
		// crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, my_id_token->public_key);

		// create shared secret
		unsigned char shared_secret[crypto_scalarmult_BYTES];
		crypto_scalarmult(shared_secret, curve25519_sk, session_key->val.value.bin);

		// TODO: renewal of token and encryption data ?
		// for now, use the token that has been send
		if (NULL == hs_key->aaa_token)
		{
			hs_key->aaa_token = tmp_token;
		}
		np_aaatoken_t* hs_token = hs_key->aaa_token;
		if (IS_VALID(hs_token->state))
		{
			// TODO: np_unref_obj ?
			log_msg(LOG_WARN, "found valid authentication token for node %s, overwriting ...", _key_as_str(hs_key));
			hs_key->aaa_token = tmp_token;
		}

		strncpy((char*) hs_key->aaa_token->session_key, (char*) shared_secret, crypto_scalarmult_BYTES);

//		char session_hex[crypto_scalarmult_SCALARBYTES*2+1];
//		sodium_bin2hex(session_hex, crypto_scalarmult_SCALARBYTES*2+1, hs_key->aaa_token->session_key, crypto_scalarmult_SCALARBYTES);
//		log_msg(LOG_DEBUG, "session key %s", session_hex);

		hs_key->aaa_token->state |= AAA_VALID;

		_LOCK_MODULE(np_keycache_t)
		{
			alias_key = _np_key_find_create(search_alias_key);
		}

		if (NULL != alias_key)
		{
			alias_key->aaa_token = hs_key->aaa_token;
			np_ref_obj(np_aaatoken_t, alias_key->aaa_token);

			alias_key->node = hs_key->node;
			np_ref_obj(np_node_t, alias_key->node);

			if (alias_key->node->protocol & PASSIVE)
			{
				np_free_obj(np_network_t, hs_key->network);

				hs_key->network = alias_key->network;
				np_ref_obj(np_network_t, hs_key->network);

				_np_suspend_event_loop();
				EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
				ev_io_stop(EV_A_ &hs_key->network->watcher);
				ev_io_init(&hs_key->network->watcher, _np_network_sendrecv, hs_key->network->socket, EV_WRITE | EV_READ);
	    		ev_io_start(EV_A_ &hs_key->network->watcher);
	        	_np_resume_event_loop();
			}
			else if (alias_key->node->protocol & TCP)
			{
				// with tcp we accepted the connection already and have an incoming channel defined
				// alias key and hs_key have different network_t structures, so there is nothing to do
			}
			else
			{
				alias_key->network = hs_key->network;
				np_ref_obj(np_network_t, alias_key->network);
			}
		}
		// sodium_bin2hex(session_hex, crypto_scalarmult_SCALARBYTES*2+1, alias_key->authentication->session_key, crypto_scalarmult_SCALARBYTES);
		// log_msg(LOG_DEBUG, "session a  key   %s", session_hex);

		hs_key->node->handshake_status = HANDSHAKE_COMPLETE;
		log_msg(LOG_DEBUG, "handshake data successfully registered for node %s (alias %s)",
				_key_as_str(hs_key), _key_as_str(alias_key));

		// send out our own handshake data
		np_msgproperty_t* hs_prop = np_msgproperty_get(TRANSFORM, _NP_MSG_HANDSHAKE);
		_np_job_submit_transform_event(0.0, hs_prop, hs_key, NULL);
	}
	goto __np_return__;

	__np_cleanup__:
	if (NULL != tmp_token)  np_free_obj(np_aaatoken_t, tmp_token);

	__np_return__:
	if (NULL != hs_payload) np_free_tree(hs_payload);
	return;
}
