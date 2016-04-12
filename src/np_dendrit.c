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
#include "log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_jtree.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_memory.h"
#include "np_route.h"
#include "np_util.h"
#include "np_threads.h"


#define SEND_SIZE NETWORK_PACK_SIZE

#define GRACEPERIOD  30		/* seconds */

/**
 ** message_received:
 ** is called by network_activate and will be passed received data and size from socket
 */
void hnd_msg_in_received(np_state_t* state, np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.hnd_msg_in_received");
	np_network_t* my_network = state->my_node_key->network;
	int ret;

	// we registered this token info before in the first handshake message
	np_key_t* alias_key = args->target;

	pthread_mutex_lock(&(my_network->lock));
	void* raw_msg = sll_head(void_ptr, my_network->in_events);
	pthread_mutex_unlock(&(my_network->lock));

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

		char session_hex[crypto_scalarmult_SCALARBYTES*2+1];
		sodium_bin2hex(session_hex, crypto_scalarmult_SCALARBYTES*2+1, alias_key->aaa_token->session_key, crypto_scalarmult_SCALARBYTES);
		// log_msg(LOG_DEBUG, "session    key   %s", session_hex);

		// log_msg(LOG_DEBUG, "now nonce (%s)", nonce);
		int ret = crypto_secretbox_open_easy(dec_msg,
				(const unsigned char *) raw_msg + crypto_secretbox_NONCEBYTES,
				1024 - crypto_secretbox_NONCEBYTES,
				nonce,
				alias_key->aaa_token->session_key);
		log_msg(LOG_DEBUG, "/stop  decrypting message with alias %s", _key_as_str(alias_key));

		if (ret != 0)
		{
			log_msg(LOG_ERROR,
					"incorrect decryption of message (send from %s)", _key_as_str(alias_key));
		}
		else
		{
			memset(raw_msg, 0, 1024);
			memcpy(raw_msg, dec_msg, 1024 - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);
		}
	}

	np_message_t* msg_in = NULL;
	np_new_obj(np_message_t, msg_in);

	ret = np_message_deserialize(msg_in, raw_msg);
	if (FALSE == ret)
	{
		log_msg(LOG_ERROR, "error de-serializing message");
		np_free_obj(np_message_t, msg_in);
		log_msg(LOG_TRACE, ".end  .hnd_msg_in_received");
		return;
	}

	// now read decrypted (or handshake plain text) message
	char* msg_subject =
			jrb_find_str(msg_in->header, NP_MSG_HEADER_SUBJECT)->val.value.s;

	if ( 0 == strncmp(msg_subject, NP_MSG_HANDSHAKE, strlen(NP_MSG_HANDSHAKE)) )
	{
		// log_msg(LOG_DEBUG, "identified handshake message ...");
		if ( (NULL == alias_key->aaa_token) ||
			 IS_INVALID(alias_key->aaa_token->state) )
		{
			jrb_insert_str(msg_in->footer, NP_MSG_FOOTER_ALIAS_KEY,
					new_jval_s(_key_as_str(alias_key)));
			np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, NP_MSG_HANDSHAKE);
			np_job_submit_msg_event(0.0, msg_prop, state->my_node_key, msg_in);
		}
		else
		{
			log_msg(LOG_DEBUG, "... handshake is already complete");
		}

		np_free_obj(np_message_t, msg_in);
		log_msg(LOG_TRACE, ".end  .hnd_msg_in_received");
		return;
	}

	/* real receive part */
	char*   msg_to      = jrb_find_str(msg_in->header, NP_MSG_HEADER_TO)->val.value.s;
	char*   msg_uuid    = jrb_find_str(msg_in->instructions, NP_MSG_INST_UUID)->val.value.s;
	double  msg_tstamp  = jrb_find_str(msg_in->instructions, NP_MSG_INST_TSTAMP)->val.value.d;
	double  msg_ttl     = jrb_find_str(msg_in->instructions, NP_MSG_INST_TTL)->val.value.d;
	uint8_t msg_ack     = jrb_find_str(msg_in->instructions, NP_MSG_INST_ACK)->val.value.ush;

	if (0 == strncmp(NP_MSG_ACK, msg_subject, strlen(NP_MSG_ACK)))
	{
		char* ack_uuid = jrb_find_str(msg_in->instructions, NP_MSG_INST_ACKUUID)->val.value.s;
		np_jtree_elem_t *jrb_node = NULL;

		/* just an acknowledgement of own messages send out earlier */
		pthread_mutex_lock(&(my_network->lock));
		jrb_node = jrb_find_str(my_network->waiting, ack_uuid);
		if (jrb_node != NULL)
		{
			np_ackentry_t *entry = (np_ackentry_t *) jrb_node->val.value.v;
			entry->received_ack++;
			if (entry->expected_ack == entry->received_ack)
			{
				entry->acked = TRUE;
				entry->acktime = ev_time();
			}
			log_msg(LOG_DEBUG, "received acknowledgment of uuid=%s", ack_uuid);
		}
		pthread_mutex_unlock(&(my_network->lock));

		np_free_obj(np_message_t, msg_in);
		log_msg(LOG_TRACE, ".end  .hnd_msg_in_received");
		return;
	}

	log_msg(LOG_DEBUG, "received message for subject: %s (uuid=%s, ack=%hhd)",
			msg_subject, msg_uuid, msg_ack);

	// check time-to-live for message and expiry if neccessary
	double now = ev_time();
	if (now > (msg_tstamp + msg_ttl))
	{
		log_msg(LOG_INFO, "message ttl expired, dropping message (part) %s / %s", msg_uuid, msg_subject);
		log_msg(LOG_DEBUG, "now: %f, msg_ttl: %f", now, msg_ttl);
		np_free_obj(np_message_t, msg_in);
		log_msg(LOG_TRACE, ".end  .hnd_msg_in_received");
		return;
	}

	// check if an acknowledge has to be send
	if (0 < (msg_ack & ACK_EACHHOP))
	{
		/* acknowledge part, each hop has to acknowledge the message */
		// TODO: move this ack after a) a message handler has been found or b) the message has been forwarded
		np_key_t* ack_key = NULL;
		char* ack_to = jrb_find_str(msg_in->instructions, NP_MSG_INST_ACK_TO)->val.value.s;
		np_dhkey_t search_key = dhkey_create_from_hash(ack_to);

		LOCK_CACHE(state)
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
			np_msgproperty_t* ack_prop = np_msgproperty_get(OUTBOUND, NP_MSG_ACK);
			np_message_create(ack_msg_out, ack_key, state->my_node_key, NP_MSG_ACK, NULL);

			/* create network header */
			jrb_insert_str(ack_msg_out->instructions, NP_MSG_INST_ACK, new_jval_ush(ack_prop->ack_mode));
			jrb_insert_str(ack_msg_out->instructions, NP_MSG_INST_ACKUUID, new_jval_s(msg_uuid));
			jrb_insert_str(ack_msg_out->instructions, NP_MSG_INST_TSTAMP, new_jval_d(ev_time()));
			jrb_insert_str(ack_msg_out->instructions, NP_MSG_INST_TTL, new_jval_d(1.0));

			log_msg(LOG_DEBUG, "sending back acknowledge for: %s (seq=%s, ack=%hhd)",
					msg_subject, msg_uuid, msg_ack);

			np_job_submit_msg_event(0.0, ack_prop, ack_key, ack_msg_out);
			np_free_obj(np_message_t, ack_msg_out);
			// user space acknowledgement handled later, also for join messages
		}
	}

	np_dhkey_t target_dhkey;
	_str_to_dhkey(msg_to, &target_dhkey);

	np_key_t* target_key;
	np_new_obj(np_key_t, target_key);
	target_key->dhkey = target_dhkey;

	// check if inbound subject handler exists
	np_msgproperty_t* handler = np_msgproperty_get(INBOUND, msg_subject);
	if (!_dhkey_equal(&args->target->dhkey, &state->my_node_key->dhkey) || handler == NULL)
	{
		// perform a route lookup
		np_sll_t(np_key_t, tmp) = NULL;

		_LOCK_MODULE(np_routeglobal_t)
		{
			// zero as "consider this node as final target"
			tmp = route_lookup(target_key, 0);
			log_msg(LOG_DEBUG, "route_lookup result 1 = %s", _key_as_str(sll_first(tmp)->val));
		}

		if (NULL         != tmp &&
			sll_size(tmp) > 0   &&
			(!_dhkey_equal(&sll_first(tmp)->val->dhkey, &state->my_node_key->dhkey)) )
		{
			log_msg(LOG_DEBUG, "received unrecognized message type %s, requesting forwarding  of message ...", msg_subject);
			np_msgproperty_t* prop = np_msgproperty_get(TRANSFORM, ROUTE_LOOKUP);
			np_job_submit_msg_event(0.0, prop, args->target, msg_in);

			np_free_obj(np_message_t, msg_in);
			np_free_obj(np_key_t, target_key);
			sll_free(np_key_t, tmp);
			log_msg(LOG_TRACE, ".end  .hnd_msg_in_received");
			return;
		}
		sll_free(np_key_t, tmp);
		log_msg(LOG_DEBUG, "internal routing for subject '%s'", msg_subject);
	}

	// if this message really has to be handled by this node, does a handler exists ?
	if ( NULL != handler      &&
		 NULL == handler->clb )
	{
		log_msg(LOG_WARN,
				"no incoming callback function was found for type %s, dropping message %s",
				handler->msg_subject, msg_uuid);

		np_free_obj(np_message_t, msg_in);
		np_free_obj(np_key_t, target_key);
		log_msg(LOG_TRACE, ".end  .hnd_msg_in_received");
		return;
	}

	// sum up message parts if the message is for this node
	args->msg = msg_in;
	np_message_t* msg_to_submit = np_message_check_chunks_complete(state, args);
	if (NULL == msg_to_submit)
	{
		log_msg(LOG_TRACE, ".end  .hnd_msg_in_received");
		args->msg = NULL;
		np_free_obj(np_message_t, msg_in);
		np_free_obj(np_key_t, target_key);
		return;
	}
	args->msg = NULL;

	np_message_deserialize_chunked(msg_to_submit);
	// finally submit msg job for later execution
	np_job_submit_msg_event(0.0, handler, state->my_node_key, msg_to_submit);

	np_unref_obj(np_message_t, msg_to_submit);

	np_free_obj(np_message_t, msg_in);
	np_free_obj(np_key_t, target_key);

	log_msg(LOG_TRACE, ".end  .hnd_msg_in_received");
}

/**
 ** neuropil_piggy_message:
 ** This function is responsible to add the piggy backing node information that is sent along with
 ** other ctrl messages or separately to the routing table. the PIGGY message type is a separate
 ** message type.
 **/
void hnd_msg_in_piggy(np_state_t* state, np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.hnd_msg_in_piggy");

	if (!state->my_node_key->node->joined_network)
	{
		log_msg(LOG_TRACE, ".end  .hnd_msg_in_piggy");
		return;
	}

	np_key_t* node_entry = NULL;

	double tmp_ft;
	np_sll_t(np_key_t, o_piggy_list) = NULL;

	LOCK_CACHE(state)
	{
		o_piggy_list = np_decode_nodes_from_jrb(state, args->msg->body);
	}

	while (NULL != (node_entry = sll_head(np_key_t, o_piggy_list)))
	{
		// add entries in the message to our routing table
		// routing table is responsible to handle possible double entries
		tmp_ft = node_entry->node->failuretime;
		np_key_t *added = NULL, *deleted = NULL;

		if (!_dhkey_equal(&node_entry->dhkey, &state->my_node_key->dhkey) )
		{
			// TODO: just record nodes in the network or send an join request as well ?
			if (GRACEPERIOD > (ev_time() - tmp_ft))
			{
				_LOCK_MODULE(np_routeglobal_t)
				{
					route_update(node_entry, 1, &deleted, &added);
					if (added)   np_ref_obj(np_key_t, added);
					if (deleted)
					{
						np_unref_obj(np_key_t, deleted);
					}
				}

				_LOCK_MODULE(np_routeglobal_t)
				{
					leafset_update(node_entry, 1, &deleted, &added);
					if (added)   np_ref_obj(np_key_t, added);
					if (deleted)
					{
						np_unref_obj(np_key_t, deleted);
						// np_free_obj(np_key_t, deleted);
					}
				}
			}
		}
		// np_free_obj(np_key_t, node_entry);
	}
	sll_free(np_key_t, o_piggy_list);
	// np_free_obj(np_message_t, args->msg);
	//
	// TODO: start cleanup job that removes unused element in state->key_cache
	//
	log_msg(LOG_TRACE, ".end  .hnd_msg_in_piggy");
}

/** np_signal
 ** np_signal registered when np_receive function is used to receive message.
 ** it is invoked after a message has been send from the sender of messages and sends a signal to the
 ** np_receive function
 **/
void np_signal (np_state_t* state, np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.np_signal");

	if (!state->my_node_key->node->joined_network)
	{
		// np_free_obj(np_message_t, args->msg);
		return;
	}

	np_message_t* msg_in = args->msg;

	const char* subject = jrb_find_str(msg_in->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
	uint8_t ack_mode = jrb_find_str(msg_in->instructions, NP_MSG_INST_ACK)->val.value.ush;

	np_msgproperty_t* real_prop = np_msgproperty_get(INBOUND, subject);

	log_msg(LOG_DEBUG, "pushing message into cache %p", real_prop);
	LOCK_CACHE(real_prop)
	{
		real_prop->msg_threshold++;
		sll_append(np_message_t, real_prop->msg_cache, args->msg);
		np_ref_obj(np_message_t, args->msg);
		// signal the np_receive function that the message has arrived
		log_msg(LOG_DEBUG, "signaling via available %p", real_prop);
		pthread_cond_signal(&real_prop->msg_received);
	}

	// TODO: more detailed msg ack handling
	if (0 < (ack_mode & ACK_DESTINATION))
	{
		_np_send_ack(state, args->msg);
	}

	// np_free_obj(np_message_t, args->msg);

	log_msg(LOG_TRACE, ".end  .np_signal");
}

/** np_callback_wrapper
 ** np_callback_wrapper is used when a callback function is used to receive messages
 ** The purpose is automated acknowledge handling in case of ACK_CLIENT message subjects
 ** the user defined callback has to return TRUE in case the ack can be send, or FALSE
 ** if e.g. validation of the message has failed.
 **/
void np_callback_wrapper(np_state_t* state, np_jobargs_t* args)
{
	np_message_t* msg_in = args->msg;
	char* subject = args->properties->msg_subject;
	char* sender = jrb_find_str(msg_in->header, NP_MSG_HEADER_FROM)->val.value.s;
	np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, subject);

	np_aaatoken_t* sender_token = _np_get_sender_token(state, (char*) subject, sender);
	uint32_t received = 0;

	msg_prop->msg_threshold++;

	if (NULL != sender_token)
	{
		log_msg(LOG_DEBUG, "decrypting message ...");
		np_bool decrypt_ok = np_message_decrypt_payload(state, msg_in, sender_token);

		if (FALSE == decrypt_ok)
		{
			// np_unref_obj(np_aaatoken_t, sender_token);
			// np_free_obj(np_aaatoken_t, sender_token);
			// np_unref_obj(np_message_t, msg_in);
			// np_free_obj(np_message_t, msg_in);
			msg_prop->msg_threshold--;
			return;
		}

		received = jrb_find_str(msg_in->properties, NP_MSG_INST_SEQ)->val.value.ul;
		uint8_t ack_mode  = jrb_find_str(msg_in->instructions, NP_MSG_INST_ACK)->val.value.ush;

		if (0 < (ack_mode & ACK_DESTINATION))
		{
			_np_send_ack(state, args->msg);
		}

		np_bool result = msg_prop->user_clb(msg_in->properties, msg_in->body);
		log_msg(LOG_INFO, "handled message %u with result %d ", received, result);

		if (0 < (ack_mode & ACK_CLIENT) && (TRUE == result))
		{
			_np_send_ack(state, args->msg);
		}

		// np_unref_obj(np_aaatoken_t, sender_token);
		// np_free_obj(np_aaatoken_t, sender_token);

		msg_prop->msg_threshold--;

	} else {

		LOCK_CACHE(msg_prop)
		{
			// cache already full ?
			if (msg_prop->max_threshold <= sll_size(msg_prop->msg_cache)) {
				log_msg(LOG_DEBUG, "msg cache full, checking overflow policy ...");

				if ( 0 < (msg_prop->cache_policy & OVERFLOW_PURGE))
				{
					log_msg(LOG_DEBUG, "OVERFLOW_PURGE: discarding first message");
					np_message_t* old_msg = NULL;

					if ((msg_prop->cache_policy & FIFO) > 0)
						old_msg = sll_head(np_message_t, msg_prop->msg_cache);
					if ((msg_prop->cache_policy & FILO) > 0)
						old_msg = sll_tail(np_message_t, msg_prop->msg_cache);

					msg_prop->msg_threshold--;
					np_unref_obj(np_message_t, old_msg);
					// np_free_obj(np_message_t, old_msg);
				}

				if ( 0 < (msg_prop->cache_policy & OVERFLOW_REJECT))
				{
					log_msg(LOG_DEBUG, "rejecting new message because cache is full");
					// np_free_obj(np_message_t, msg_in);
					continue;
				}
			}

			sll_prepend(np_message_t, msg_prop->msg_cache, msg_in);

			log_msg(LOG_DEBUG, "added message to the msgcache (%p / %d) ...",
								msg_prop->msg_cache, sll_size(msg_prop->msg_cache));
			np_ref_obj(np_message_t, msg_in);
		}
	}

	// np_unref_obj(np_message_t, msg_in);
	// np_free_obj(np_message_t, msg_in);
}

/** hnd_msg_in_join_req:
 ** internal function that is called at the destination of a JOIN message. This
 ** call encodes the leaf set of the current host and sends it to the joiner.
 **/
void hnd_msg_in_join_req(np_state_t* state, np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.hnd_msg_in_join_req");

	np_msgproperty_t *msg_prop = NULL;
	np_key_t* join_req_key = NULL;
	np_message_t* msg_out = NULL;
	np_aaatoken_t* node_token = NULL;

	np_new_obj(np_aaatoken_t, node_token);
	np_decode_aaatoken(args->msg->body, node_token);

	LOCK_CACHE(state)
	{
		join_req_key = _np_create_node_from_token(state, node_token);
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
		np_job_submit_msg_event(msg_prop, sourceNode->key, o_msg_out);
		np_unref(np_message_t, o_msg_out);

		sourceNode->handshake_status = HANDSHAKE_UNKNOWN;
		// np_aaatoken_t* aaa_token = np_get_authentication_token(state->aaa_cache, sourceNode->key);
		// aaa_token->valid = 0;

		np_send_ack(state, args);

		np_unbind(np_message_t, args->msg, msg_in);
		return;
	} */

	// check for allowance of node by user defined function
	if (NULL != join_req_key &&
		NULL != state->authorize_func)
	{
		np_bool join_allowed = state->authorize_func(state, join_req_key->aaa_token);
		np_new_obj(np_message_t, msg_out);

		char* in_uuid = jrb_find_str(args->msg->instructions, NP_MSG_INST_UUID)->val.value.s;

		if (join_allowed)
		{
			log_msg(LOG_INFO,
					"join request approved, sending back join acknowledge for key %s",
					_key_as_str(join_req_key));
			np_jtree_t* jrb_me = make_jtree();
			np_aaatoken_t* node_token = _np_create_node_token(state, state->my_node_key->node, state->my_node_key);
			np_encode_aaatoken(jrb_me, node_token);
			// np_node_encode_to_jrb(jrb_me, state->my_node_key, FALSE);
			// jrb_insert_str(jrb_me, NP_MSG_INST_ACKUUID, new_jval_s(in_uuid));
			np_message_create(msg_out, join_req_key, state->my_node_key, NP_MSG_JOIN_ACK, jrb_me);
			jrb_insert_str(msg_out->instructions, NP_MSG_INST_ACKUUID, new_jval_s(in_uuid));

			msg_prop = np_msgproperty_get(OUTBOUND, NP_MSG_JOIN_ACK);
			state->my_node_key->node->joined_network = TRUE;
			join_req_key->node->joined_network = TRUE;

			np_free_obj(np_aaatoken_t, node_token);
		}
		else
		{
			log_msg(LOG_INFO,
					"JOIN request denied by user implementation, rejected key %s",
					_key_as_str(join_req_key) );

			np_message_create(msg_out, join_req_key, state->my_node_key, NP_MSG_JOIN_NACK, NULL );
			jrb_insert_str(msg_out->instructions, NP_MSG_INST_ACKUUID, new_jval_s(in_uuid));
			msg_prop = np_msgproperty_get(OUTBOUND, NP_MSG_JOIN_NACK);

			// TODO: chicken egg problem, schedule a future event
			// without handshake we cannot send join.nack messages
			// but we have to delete the auth token after really sending the nack
			// np_aaatoken_t* aaa_token = np_get_authentication_token(state->aaa_cache, sourceNode->key);
			// aaa_token->valid = 0;
			// sourceNode->handshake_status = HANDSHAKE_UNKNOWN;
		}

		np_job_submit_msg_event(0.0, msg_prop, join_req_key, msg_out);

		np_key_t *added = NULL, *deleted = NULL;
		_LOCK_MODULE(np_routeglobal_t)
		{
			route_update(join_req_key, join_allowed, &deleted, &added);
			if (NULL != added)   np_ref_obj(np_key_t, added);
			if (NULL != deleted)
			{
				np_unref_obj(np_key_t, deleted);
				// np_free_obj(np_key_t, deleted);
			}
		}

		_LOCK_MODULE(np_routeglobal_t)
		{
			leafset_update(join_req_key, join_allowed, &deleted, &added);
			if (NULL != added)   np_ref_obj(np_key_t, added);
			if (NULL != deleted)
			{
				np_unref_obj(np_key_t, deleted);
				// np_free_obj(np_key_t, deleted);
			}
		}

	}
	else
	{
		log_msg(LOG_ERROR, "no join request function defined, exiting");
		exit(1);
	}

	_np_send_ack(state, args->msg);

	log_msg(LOG_TRACE, ".end  .hnd_msg_in_join_req");
}

/** hnd_msg_in_join_ack:
 ** called when the current node is joining the network and has just received
 ** its leaf set. This function sends an update message to all nodes in its
 ** new leaf set to announce its arrival.
 **/
void hnd_msg_in_join_ack(np_state_t* state, np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".start.hnd_msg_in_join_ack");

	np_message_t* msg_out = NULL;
	np_key_t* join_key = NULL;
	np_msgproperty_t* out_props = NULL;
	np_aaatoken_t* node_token = NULL;

	np_new_obj(np_aaatoken_t, node_token);
	np_decode_aaatoken(args->msg->body, node_token);

	LOCK_CACHE(state)
	{
		join_key = _np_create_node_from_token(state, node_token);
	}

	/* acknowledgement of join message send out earlier */
	char* ack_uuid = jrb_find_str(args->msg->instructions, NP_MSG_INST_ACKUUID)->val.value.s;
	np_network_t* ng = state->my_node_key->network;

	pthread_mutex_lock(&(ng->lock));
	np_jtree_elem_t *jrb_node = jrb_find_str(ng->waiting, ack_uuid);
	if (jrb_node != NULL)
	{
		np_ackentry_t *entry = (np_ackentry_t *) jrb_node->val.value.v;
		entry->acked = TRUE;
		entry->acktime = ev_time();
		log_msg(LOG_DEBUG, "received acknowledgment of JOIN uuid=%s", ack_uuid);
	}
	else
	{
		pthread_mutex_unlock(&(ng->lock));
		// np_free_obj(np_message_t, args->msg);
		log_msg(LOG_TRACE, ".end  .hnd_msg_in_join_ack");
		return;
	}
	pthread_mutex_unlock(&(ng->lock));

	// should never happen
	if (NULL == join_key)
	{
		return;
	}

	if (NULL != join_key->node)
	{
		// node cannot be NULL, but checker complains otherwise
		log_msg(LOG_INFO,
				"received join acknowledgement from key %s", _key_as_str(join_key));
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
		if (_dhkey_equal(&elem->dhkey, &join_key->dhkey)) continue;

		np_new_obj(np_message_t, msg_out);

		// encode informations -> has to be done for each update message new
		// otherwise there is a crash when deleting the message
		np_jtree_t* jrb_join_node = make_jtree();
		np_node_encode_to_jrb(jrb_join_node, join_key, FALSE);

		np_message_create(msg_out, elem, state->my_node_key,
				NP_MSG_UPDATE_REQUEST, jrb_join_node);
		out_props = np_msgproperty_get(OUTBOUND, NP_MSG_UPDATE_REQUEST);
		np_job_submit_msg_event(0.0, out_props, elem, msg_out);
	}
	sll_free(np_key_t, nodes);

	// remember key for routing table update
	log_msg(LOG_DEBUG, "join acknowledged and updates to other nodes send");

	np_key_t *added = NULL, *deleted = NULL;
	// update table
	_LOCK_MODULE(np_routeglobal_t)
	{
		route_update(join_key, 1, &deleted, &added);

		if (added)   np_ref_obj(np_key_t, added);

		if (NULL != deleted)
		{
			np_unref_obj(np_key_t, deleted);
		}
	}

	// update leafset
	_LOCK_MODULE(np_routeglobal_t)
	{
		leafset_update(join_key, 1, &deleted, &added);

		if (added)   np_ref_obj(np_key_t, added);

		if (NULL != deleted)
		{
			np_unref_obj(np_key_t, deleted);
		}
	}

	// send a piggy message to the new node in our routing table
	np_msgproperty_t* piggy_prop = np_msgproperty_get(TRANSFORM, NP_MSG_PIGGY_REQUEST);
	np_job_submit_msg_event(0.0, piggy_prop, join_key, NULL);

	join_key->node->joined_network = TRUE;
	state->my_node_key->node->joined_network = TRUE;

	log_msg(LOG_TRACE, ".end  .hnd_msg_in_join_ack");
}

/**
 ** hnd_msg_join_nack
 ** internal function that is called when the sender of a JOIN message receives
 ** the JOIN_NACK message type which is join denial from the current key root
 ** in the network.
 **/
void hnd_msg_in_join_nack(np_state_t* state, np_jobargs_t* args)
{
	np_key_t* nack_key = NULL;
	np_dhkey_t search_key = dhkey_create_from_hash(jrb_find_str(args->msg->header, NP_MSG_HEADER_FROM)->val.value.s);
	// _str_to_dhkey(&search_key, jrb_find_str(args->msg->header, NP_MSG_HEADER_FROM)->val.value.s);

	_LOCK_MODULE(np_keycache_t)
	{
		nack_key = _np_key_remove(search_key);
	}

	char* ack_uuid = jrb_find_str(args->msg->instructions, NP_MSG_INST_ACKUUID)->val.value.s;
	np_network_t* ng = state->my_node_key->network;

	pthread_mutex_lock(&(ng->lock));
	np_jtree_elem_t *jrb_node = jrb_find_str(ng->waiting, ack_uuid);
	if (jrb_node != NULL)
	{
		np_ackentry_t *entry = (np_ackentry_t *) jrb_node->val.value.v;
		entry->acked = TRUE;
		entry->acktime = ev_time();
		log_msg(LOG_DEBUG, "received not-acknowledgment of JOIN uuid=%s", ack_uuid);
	}
	pthread_mutex_unlock(&(ng->lock));

	// should never happen
	if (NULL == nack_key || NULL == nack_key->node)
	{
		// np_free_obj(np_message_t, args->msg);
		return;
	}

	log_msg(LOG_INFO, "JOIN request rejected from key %s !", _key_as_str(nack_key));

	nack_key->aaa_token->state &= AAA_INVALID;
	nack_key->node->joined_network = FALSE;
	nack_key->node->handshake_status = HANDSHAKE_UNKNOWN;

	np_unref_obj(np_key_t, nack_key);
	// np_free_obj(np_message_t, args->msg);
	log_msg(LOG_TRACE, ".end  .hnd_msg_in_join_nack");
}

void hnd_msg_in_ping(np_state_t* state, np_jobargs_t* args)
{
	if (!state->my_node_key->node->joined_network)
	{
		// np_free_obj(np_message_t, args->msg);
		return;
	}

	np_message_t *msg_out = NULL;
	np_key_t* ping_key = NULL;
	np_dhkey_t search_key = dhkey_create_from_hash(jrb_find_str(args->msg->header, NP_MSG_HEADER_FROM)->val.value.s);

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

		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, ping_key, state->my_node_key, NP_MSG_PING_REPLY, NULL );
		np_msgproperty_t* msg_pingreply_prop = np_msgproperty_get(OUTBOUND, NP_MSG_PING_REPLY);
		np_job_submit_msg_event(0.0, msg_pingreply_prop, ping_key, msg_out);
		np_free_obj(np_message_t, msg_out);
	}
	// np_free_obj(np_message_t, args->msg);
}

void hnd_msg_in_pingreply(np_state_t* state, np_jobargs_t * args)
{
	if (!state->my_node_key->node->joined_network)
	{
		// np_free_obj(np_message_t, args->msg);
		return;
	}

	np_key_t* pingreply_key = NULL;
	// np_key_t search_key;
	// _str_to_dhkey(&search_key, jrb_find_str(args->msg->header, NP_MSG_HEADER_FROM)->val.value.s);
	np_dhkey_t search_key = dhkey_create_from_hash(jrb_find_str(args->msg->header, NP_MSG_HEADER_FROM)->val.value.s);

	_LOCK_MODULE(np_keycache_t)
	{
		pingreply_key = _np_key_find(search_key);
	}

	if (NULL != pingreply_key &&
		NULL != pingreply_key->node &&
		0 < pingreply_key->node->failuretime)
	{
		double latency = ev_time() - pingreply_key->node->failuretime;
		np_node_update_latency(pingreply_key->node, latency);

		// reset for next ping attempt
		pingreply_key->node->failuretime = 0;
		np_node_update_stat(pingreply_key->node, 1);
		log_msg(LOG_DEBUG, "ping reply received from: %s:%s, latency now: %f!",
				pingreply_key->node->dns_name, pingreply_key->node->port,
			    pingreply_key->node->latency);
	}

	// np_free_obj(np_message_t, args->msg);
}

// TODO: write a function that handles path discovery
// TODO: if this is not the target node, add my own address to the update message
// TODO: if this is the target node, change target to sending instance and send again


// receive information about new nodes in the network and try to contact new nodes
void hnd_msg_in_update(np_state_t* state, np_jobargs_t* args)
{
	if (!state->my_node_key->node->joined_network)
	{
		return;
	}

	np_key_t *update_key = NULL;

	_LOCK_MODULE(np_keycache_t)
	{
		update_key = np_node_decode_from_jrb(state, args->msg->body);
	}

	if (NULL != update_key &&
		NULL != update_key->node &&
		HANDSHAKE_INITIALIZED > update_key->node->handshake_status &&
		FALSE == update_key->node->joined_network)
	{
		np_sendjoin(state, update_key);
		// np_jtree_t* jrb_me = make_jtree();
		// np_aaatoken_t* node_token = _np_create_node_token(state, state->my_node_key->node, state->my_node_key);
		// np_encode_aaatoken(jrb_me, node_token);
		// np_node_encode_to_jrb(jrb_me, state->my_node_key, FALSE);

		// np_new_obj(np_message_t, msg_out);
		// np_message_create(msg_out, update_key, state->my_node_key , NP_MSG_JOIN_REQUEST, jrb_me);
		// log_msg(LOG_DEBUG, "submitting welcome message to new node");
		// np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, NP_MSG_JOIN_REQUEST);
		// np_job_submit_msg_event(0.0, prop, update_key, msg_out);
		// np_free_obj(np_message_t, msg_out);
	}
}

void hnd_msg_in_interest(np_state_t* state, np_jobargs_t* args)
{
	if (!state->my_node_key->node->joined_network)
	{
		// np_free_obj(np_message_t, args->msg);
		return;
	}

	np_message_t *msg_out = NULL;

	np_key_t *reply_to_key = NULL;
	np_dhkey_t reply_to_dhkey;

	np_jtree_elem_t* reply = jrb_find_str(args->msg->header, NP_MSG_HEADER_REPLY_TO);
	if ( NULL != reply )
	{
		_str_to_dhkey(reply->val.value.s, &reply_to_dhkey);

		np_new_obj(np_key_t, reply_to_key);
		reply_to_key->dhkey = reply_to_dhkey;
		log_msg(LOG_DEBUG, "reply_to key: %s", _key_as_str(reply_to_key) );
	}

	// extract e2e encryption details for sender
	np_aaatoken_t* msg_token = NULL;
	np_new_obj(np_aaatoken_t, msg_token);
	// np_print_tree (args->msg->body, 0);
	np_decode_aaatoken(args->msg->body, msg_token);

	np_dhkey_t to_key;
	_str_to_dhkey(jrb_find_str(args->msg->header, NP_MSG_HEADER_TO)->val.value.s, &to_key);

	if ( NULL != reply_to_key && _dhkey_equal(&to_key, &state->my_node_key->dhkey) )
	{
		// check if we are (one of the) receiving node(s) of this kind of message
		np_bool aaa_val = TRUE;
		aaa_val &= state->authenticate_func(state, msg_token);
		aaa_val &= state->authorize_func(state, msg_token);

		if (FALSE == aaa_val)
		{
			np_free_obj(np_key_t, reply_to_key);
			np_free_obj(np_aaatoken_t, msg_token);
			return;
		}
	}

	if (TRUE == token_is_valid(msg_token))
	{
		log_msg(LOG_DEBUG, "now handling message interest");
		_np_add_receiver_token(state, msg_token->subject, msg_token);
	}

//	if (reply_to_key &&
//		!_dhkey_equal(reply_to_key, state->my_node_key)) {
	if (NULL != reply_to_key)
	{
		// this node is the man in the middle - inform receiver of sender token
		np_sll_t(np_aaatoken_t, available_list) = _np_get_sender_token_all(state, msg_token->subject);
		np_aaatoken_t* tmp_token = NULL;

		while (NULL != (tmp_token = sll_head(np_aaatoken_t, available_list)))
		{
			log_msg(LOG_DEBUG, "found a sender of messages, sending back message availabilities ...");
			np_jtree_t* available_data = make_jtree();

			np_encode_aaatoken(available_data, tmp_token);

			np_new_obj(np_message_t, msg_out);
			np_message_create(msg_out, reply_to_key, NULL, NP_MSG_AVAILABLE, available_data);
			np_msgproperty_t* prop_route = np_msgproperty_get(TRANSFORM, ROUTE_LOOKUP);
			np_job_submit_msg_event(0.0, prop_route, reply_to_key, msg_out);
			np_free_obj(np_message_t, msg_out);

			np_unref_obj(np_aaatoken_t, tmp_token);
		}
		sll_free(np_aaatoken_t, available_list);
	}

	np_msgproperty_t* real_prop = np_msgproperty_get(OUTBOUND, msg_token->subject);
	// check if we are (one of the) sending node(s) of this kind of message
	if ( NULL != real_prop )
	{
		log_msg(LOG_DEBUG,
				"this node is one sender of messages, checking msgcache (%p / %u) ...",
				real_prop->msg_cache, sll_size(real_prop->msg_cache));

		// get message from cache (maybe only for one way mep ?!)
		uint16_t msg_available = 0;

		LOCK_CACHE(real_prop)
		{
			msg_available = sll_size(real_prop->msg_cache);
		}
		np_bool sending_ok = TRUE;

		while (0    <  msg_available &&
			   TRUE == sending_ok)
		{
			LOCK_CACHE(real_prop)
			{
				// if messages are available in cache, send them !
				if (real_prop->cache_policy & FIFO)
					msg_out = sll_head(np_message_t, real_prop->msg_cache);
				if (real_prop->cache_policy & FILO)
					msg_out = sll_tail(np_message_t, real_prop->msg_cache);
				// check for more messages in cache after head/tail command
				msg_available = sll_size(real_prop->msg_cache);
			}

			sending_ok = _np_send_msg(state, real_prop->msg_subject, msg_out, real_prop);

			np_unref_obj(np_message_t, msg_out);
			log_msg(LOG_DEBUG, "message in cache found and re-send initialized");

		}
		// TODO send out the non availability of data to the sender node i.e. threshold doesn't match ???
		// 2) then send out the interest to the sender of messages
		// TODO: really needed ? it will get the update when sending his own interest
		// TODO: !!! behaviour is depending on mep !!!
		// send out the availability to the target of messages
	}

	if ( NULL != reply_to_key) np_free_obj(np_key_t, reply_to_key);
	np_free_obj(np_aaatoken_t, msg_token);
}

void hnd_msg_in_available(np_state_t* state, np_jobargs_t* args)
{
	if (!state->my_node_key->node->joined_network)
	{
		return;
	}

	np_message_t *msg_in = args->msg;

	np_key_t *reply_to_key = NULL;
	np_dhkey_t reply_to_dhkey;
	np_jtree_elem_t* reply = jrb_find_str(msg_in->header, NP_MSG_HEADER_REPLY_TO);
	if (NULL != reply)
	{
		_str_to_dhkey(reply->val.value.s, &reply_to_dhkey);

		np_new_obj(np_key_t, reply_to_key);
		reply_to_key->dhkey = reply_to_dhkey;
		log_msg(LOG_DEBUG, "reply key: %s", _key_as_str(reply_to_key) );
	}

	// extract e2e encryption details for sender
	np_aaatoken_t* msg_token = NULL;
	np_new_obj(np_aaatoken_t, msg_token);
	np_decode_aaatoken(msg_in->body, msg_token);

	np_dhkey_t to_key;
	_str_to_dhkey(jrb_find_str(msg_in->header, NP_MSG_HEADER_TO)->val.value.s, &to_key);

	if ( NULL != reply_to_key && _dhkey_equal(&to_key, &state->my_node_key->dhkey) )
	{
		// check if we are (one of the) receiving node(s) of this kind of message
		np_bool aaa_val = TRUE;
		aaa_val &= state->authenticate_func(state, msg_token);
		aaa_val &= state->authorize_func(state, msg_token);
		if (FALSE == aaa_val)
		{
			np_free_obj(np_aaatoken_t, msg_token);
			np_free_obj(np_key_t, reply_to_key);
			return;
		}
	}

	// always?: just store the available messages in memory and update if new data arrives
	if (TRUE == token_is_valid(msg_token))
	{
		log_msg(LOG_DEBUG, "now handling message availability");
		_np_add_sender_token(state, msg_token->subject, msg_token);
	}

	if (NULL != reply_to_key)
	{
		np_message_t *msg_out = NULL;
		np_sll_t(np_aaatoken_t, receiver_list) = _np_get_receiver_token_all(state, msg_token->subject);
		np_aaatoken_t* tmp_token = NULL;

		while (NULL != (tmp_token = sll_head(np_aaatoken_t, receiver_list)))
		{
			np_jtree_t* interest_data = make_jtree();

			np_encode_aaatoken(interest_data, tmp_token);

			np_new_obj(np_message_t, msg_out);
			np_message_create(msg_out, reply_to_key, NULL, NP_MSG_INTEREST, interest_data);
			np_msgproperty_t* prop_route = np_msgproperty_get(TRANSFORM, ROUTE_LOOKUP);

			log_msg(LOG_DEBUG, "sending back msg interest to %s", _key_as_str(reply_to_key));
			np_job_submit_msg_event(0.0, prop_route, reply_to_key, msg_out);

			np_free_obj(np_message_t, msg_out);
			np_unref_obj(np_aaatoken_t, tmp_token);
		}
		sll_free(np_aaatoken_t, receiver_list);
	}

	// check if some messages are left in the cache
	np_msgproperty_t* real_prop = np_msgproperty_get(INBOUND, msg_token->subject);
	// check if we are (one of the) receiving node(s) of this kind of message
	if ( NULL != real_prop )
	{
		log_msg(LOG_DEBUG,
				"this node is the receiver of messages, checking msgcache (%p / %u) ...",
				real_prop->msg_cache, sll_size(real_prop->msg_cache));

		// get message from cache (maybe only for one way mep ?!)
		uint16_t msg_available = 0;
		LOCK_CACHE(real_prop)
		{
			msg_available = sll_size(real_prop->msg_cache);
		}

		while (0 < msg_available)
		{
			msg_in = NULL;
			LOCK_CACHE(real_prop)
			{
				// if messages are available in cache, try to decode them !
				if (real_prop->cache_policy & FIFO)
					msg_in = sll_tail(np_message_t, real_prop->msg_cache);
				if (real_prop->cache_policy & FILO)
					msg_in = sll_head(np_message_t, real_prop->msg_cache);

				msg_available = sll_size(real_prop->msg_cache);
				real_prop->msg_threshold--;
			}
			np_job_submit_msg_event(0.0, real_prop, state->my_node_key, msg_in);
			np_unref_obj(np_message_t, msg_in);
		}
	}

	if ( NULL != reply_to_key) np_free_obj(np_key_t, reply_to_key);
	np_free_obj(np_aaatoken_t, msg_token);
}

void hnd_msg_in_authenticate(np_state_t* state, np_jobargs_t* args)
{

}

void hnd_msg_in_authorize(np_state_t* state, np_jobargs_t* args)
{

}

void hnd_msg_in_authorize_reply(np_state_t* state, np_jobargs_t* args)
{

}

void hnd_msg_in_account(np_state_t* state, np_jobargs_t* args)
{

}

void hnd_msg_in_account_reply(np_state_t* state, np_jobargs_t* args)
{

}

void hnd_msg_in_handshake(np_state_t* state, np_jobargs_t* args)
{
	log_msg(LOG_TRACE, ".end  .hnd_msg_in_handshake");

	np_message_deserialize_chunked(args->msg);

	// initial handshake message contains public encryption parameter
	np_jtree_elem_t* jrb_alias = jrb_find_str(args->msg->footer, NP_MSG_FOOTER_ALIAS_KEY);
	np_jtree_elem_t* signature = jrb_find_str(args->msg->body, NP_HS_SIGNATURE);
	np_jtree_elem_t* payload   = jrb_find_str(args->msg->body, NP_HS_PAYLOAD);

	assert (jrb_alias != NULL);

	if (signature == NULL || payload == NULL)
	{
		log_msg(LOG_WARN, "no signature or payload found in handshake message, discarding handshake attempt");
		// change of IP adresses can lead to messages not containing signatures :-(
		return;
	}

	np_key_t* alias_key = NULL;
	np_dhkey_t search_alias_key = dhkey_create_from_hash(jrb_alias->val.value.s);

	cmp_ctx_t cmp;
	np_jtree_t* hs_payload = make_jtree();

	cmp_init(&cmp, payload->val.value.bin, buffer_reader, buffer_writer);
	deserialize_jrb_node_t(hs_payload, &cmp);

	char* node_proto          = jrb_find_str(hs_payload, "_np.protocol")->val.value.s;
	char* node_hn             = jrb_find_str(hs_payload, "_np.dns_name")->val.value.s;
	char* node_port           = jrb_find_str(hs_payload, "_np.port")->val.value.s;
	np_jtree_elem_t* sign_key = jrb_find_str(hs_payload, "_np.signature_key");
	np_jtree_elem_t* pub_key  = jrb_find_str(hs_payload, "_np.public_key");
	double issued_at          = jrb_find_str(hs_payload, "_np.issued_at")->val.value.d;
	double expiration         = jrb_find_str(hs_payload, "_np.expiration")->val.value.d;

	if (0 != crypto_sign_verify_detached( (const unsigned char*) signature->val.value.bin,
			                              (const unsigned char*) payload->val.value.bin,
										  payload->val.size,
										  (const unsigned char*) sign_key->val.value.bin) )
	{
		log_msg(LOG_ERROR, "incorrect signature in handshake message");

		np_free_tree(hs_payload);
		// np_free_obj(np_message_t, args->msg);
		return;
	}
	log_msg(LOG_DEBUG, "decoding of handshake message from %s:%s (i:%f/e:%f) complete",
			node_hn, node_port, issued_at, expiration);

	// store the handshake data in the node cache, use hostname/port for key generation
	// key could be changed later, but we need a way to lookup the handshake data later
	np_key_t* hs_key = NULL;
	np_dhkey_t search_key = dhkey_create_from_hostport(node_hn, node_port);

	_LOCK_MODULE(np_keycache_t)
	{
		hs_key = _np_key_find_create(search_key);
	}

	// should never happen
	if (NULL == hs_key) return;

	uint8_t proto = np_parse_protocol_string(node_proto);

	if (NULL == hs_key->node)
	{
		np_new_obj(np_node_t, hs_key->node);
		np_node_update(hs_key->node, proto, node_hn, node_port);
		if (!(proto & PASSIVE))
		{
			hs_key->network = network_init(FALSE, proto, node_hn, node_port);
			hs_key->network->watcher.data = hs_key;
		}
	}

	if (NULL == hs_key->aaa_token)
	{
		// create a aaa token and store it as authentication data
		np_new_obj(np_aaatoken_t, hs_key->aaa_token);
	}

	if (hs_key->node->handshake_status <= HANDSHAKE_INITIALIZED)
	{

		np_aaatoken_t* my_id_token;
		my_id_token = state->my_node_key->aaa_token;

		// get our own identity from the cache and convert to curve key
		unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
		// unsigned char curve25519_pk[crypto_scalarmult_curve25519_BYTES];
		crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_id_token->private_key);
		// crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, my_id_token->public_key);

		// create shared secret
		unsigned char shared_secret[crypto_scalarmult_BYTES];
		crypto_scalarmult(shared_secret, curve25519_sk, pub_key->val.value.bin);

		np_aaatoken_t* hs_token = hs_key->aaa_token;
		if (IS_VALID(hs_token->state))
		{
			log_msg(LOG_WARN, "found valid authentication token for node %s, overwriting ...", _key_as_str(hs_key));
		}

		hs_key->aaa_token->expiration = expiration;
		hs_key->aaa_token->issued_at = issued_at;
		strncpy((char*) hs_key->aaa_token->public_key, pub_key->val.value.bin, pub_key->val.size);
		strncpy((char*) hs_key->aaa_token->session_key, (char*) shared_secret, crypto_scalarmult_BYTES);

		char session_hex[crypto_scalarmult_SCALARBYTES*2+1];
		sodium_bin2hex(session_hex, crypto_scalarmult_SCALARBYTES*2+1, hs_key->aaa_token->session_key, crypto_scalarmult_SCALARBYTES);
		log_msg(LOG_DEBUG, "session key %s", session_hex);

		hs_key->aaa_token->state |= AAA_VALID;

		np_ref_obj(np_key_t, hs_key);

		LOCK_CACHE(state)
		{
			alias_key = _np_key_find_create(search_alias_key);
		}

		if (NULL != alias_key)
		{
			alias_key->aaa_token = hs_key->aaa_token;
			alias_key->node = hs_key->node;

			if (proto & PASSIVE)
			{
				hs_key->network = alias_key->network;

				_np_suspend_event_loop();
				EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
				ev_io_stop(EV_A_ &hs_key->network->watcher);
				ev_io_init(&hs_key->network->watcher, _np_network_sendrecv, hs_key->network->socket, EV_WRITE | EV_READ);
	    		ev_io_start(EV_A_ &hs_key->network->watcher);
	        	_np_resume_event_loop();
			}
			else if (proto & TCP)
			{
				// with tcp we accepted the connection already and have incoming channel defined
				// alias key and hs_key have different network_t structures
				// TODO clean up both network structures
			}
			else
			{
				alias_key->network = hs_key->network;
			}
		}
		// sodium_bin2hex(session_hex, crypto_scalarmult_SCALARBYTES*2+1, alias_key->authentication->session_key, crypto_scalarmult_SCALARBYTES);
		// log_msg(LOG_DEBUG, "session a  key   %s", session_hex);

		hs_key->node->handshake_status = HANDSHAKE_COMPLETE;
		log_msg(LOG_DEBUG, "handshake data successfully registered for node %s (alias %s)",
				_key_as_str(hs_key), _key_as_str(alias_key));

		// send out our own handshake data
		np_msgproperty_t* hs_prop = np_msgproperty_get(OUTBOUND, NP_MSG_HANDSHAKE);
		np_job_submit_msg_event(0.0, hs_prop, hs_key, NULL);
	}

	np_free_tree(hs_payload);

	np_unref_obj(np_key_t, hs_key);
	// np_free_obj(np_message_t, args->msg);

	// log_msg(LOG_DEBUG, "finished to handle handshake message");
}

