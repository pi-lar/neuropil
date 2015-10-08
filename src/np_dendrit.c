#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "sodium.h"

#include "np_dendrit.h"

#include "dtime.h"
#include "log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_jtree.h"
#include "np_message.h"
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
	np_jtree_elem_t* subject = jrb_find_str(args->msg->header, NP_MSG_HEADER_SUBJECT);
	np_msgproperty_t* handler = np_message_get_handler(state, INBOUND, subject->val.value.s );

	// check time-to-live for message
	// double msg_tstamp = jrb_find_str(args->msg->instructions, NP_MSG_INST_TSTAMP)->val.value.d;
	char* msg_uuid = jrb_find_str(args->msg->instructions, NP_MSG_INST_UUID)->val.value.s;

	double msg_ttl = jrb_find_str(args->msg->instructions, NP_MSG_INST_TTL)->val.value.d;
	double now = dtime();

	if (now > msg_ttl) {
		log_msg(LOG_INFO, "message ttl expired, dropping message %s  / %s", msg_uuid, subject->val.value.s);
		log_msg(LOG_DEBUG, "now: %f, msg_ttl: %f", now, msg_ttl);
		np_free_obj(np_message_t, args->msg);
		log_msg(LOG_TRACE, ".end  .hnd_msg_in_received");
		return;
	}

	if (!key_equal(args->target, state->my_node_key) || handler == NULL) {
		// perform a route lookup
		log_msg(LOG_INFO, "received unrecognized message type %s, perform route lookup ...", subject->val.value.s);
		np_msgproperty_t* prop = np_message_get_handler(state, TRANSFORM, ROUTE_LOOKUP);
		job_submit_msg_event(state->jobq, 0.0, prop, args->target, args->msg);

		np_free_obj(np_message_t, args->msg);
		log_msg(LOG_TRACE, ".end  .hnd_msg_in_received");
		return;
	}

	if (handler->clb == NULL ) {
		log_msg(LOG_WARN,
				"no incoming callback function was found for type %s, dropping message",
				handler->msg_subject);
		np_free_obj(np_message_t, args->msg);
		log_msg(LOG_TRACE, ".end  .hnd_msg_in_received");
		return;
	}
	// sum up message parts if the message is for this node
	// uint16_t msg_parts = jrb_find_str(args->msg->instructions, NP_MSG_INST_PARTS)->val.value.ui;
	// uint16_t msg_part = jrb_find_str(args->msg->instructions, NP_MSG_INST_PART)->val.value.ui;

	// finally submit msg job for later execution
	job_submit_msg_event(state->jobq, 0.0, handler, state->my_node_key, args->msg);

	np_free_obj(np_message_t, args->msg);
	log_msg(LOG_TRACE, ".end  .hnd_msg_in_received");
}

/**
 ** neuropil_piggy_message:
 ** This function is responsible to add the piggy backing node information that is sent along with
 ** other ctrl messages or separately to the routing table. the PIGGY message type is a separate
 ** message type.
 **/
void hnd_msg_in_piggy(np_state_t* state, np_jobargs_t* args) {
	log_msg(LOG_TRACE, ".start.hnd_msg_in_piggy");

	if (!state->my_node_key->node->joined_network) {
		np_free_obj(np_message_t, args->msg);
		log_msg(LOG_TRACE, ".end  .hnd_msg_in_piggy");
		return;
	}

	np_key_t* node_entry;

	double tmp_ft;
	np_sll_t(np_key_t, o_piggy_list);

	LOCK_CACHE(state) {
		o_piggy_list = np_decode_nodes_from_jrb(state, args->msg->body);
	}

	while (NULL != (node_entry = sll_head(np_key_t, o_piggy_list))){
		// add entries in the message to our routing table
		// routing table is responsible to handle possible double entries
		tmp_ft = node_entry->node->failuretime;
		np_key_t *added, *deleted;

		if (!key_equal(node_entry, state->my_node_key) ) {
			if ((dtime() - tmp_ft) > GRACEPERIOD) {

				LOCK_CACHE(state->routes) {
					route_update(state, node_entry, 1, &deleted, &added);
					if (added)   np_ref_obj(np_key_t, added);
					if (deleted) np_unref_obj(np_key_t, deleted);
				}

				LOCK_CACHE(state->routes) {
					leafset_update(state, node_entry, 1, &deleted, &added);
					if (added)   np_ref_obj(np_key_t, added);
					if (deleted) np_unref_obj(np_key_t, deleted);
				}
			}
		}
		np_free_obj(np_key_t, node_entry);
	}
	sll_free(np_key_t, o_piggy_list);
	np_free_obj(np_message_t, args->msg);
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

	if (!state->my_node_key->node->joined_network) {
		np_free_obj(np_message_t, args->msg);
		return;
	}

	np_message_t* msg_in = args->msg;

	const char* subject = jrb_find_str(msg_in->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
	uint8_t ack_mode = jrb_find_str(msg_in->instructions, NP_MSG_INST_ACK)->val.value.ush;

	np_msgproperty_t* real_prop = np_message_get_handler(state, INBOUND, subject);

	log_msg(LOG_DEBUG, "pushing message into cache %p", real_prop);
	LOCK_CACHE(real_prop) {
		real_prop->msg_threshold++;
		sll_append(np_message_t, real_prop->msg_cache, args->msg);
		np_ref_obj(np_message_t, args->msg);
		// signal the np_receive function that the message has arrived
		log_msg(LOG_DEBUG, "signaling via available %p", real_prop);
		pthread_cond_signal(&real_prop->msg_received);
	}

	// TODO: more detailed msg ack handling
	if (0 < (ack_mode & ACK_DESTINATION)) {
		np_send_ack(state, args->msg);
	}

	np_free_obj(np_message_t, args->msg);

	log_msg(LOG_TRACE, ".end  .np_signal");
}


/** np_callback_wrapper
 ** np_callback_wrapper is used when a callback function is used to receive messages
 ** The purpose is automated acknowledge handling in case of ACK_CLIENT message subjects
 ** the user defined callback has to return TRUE in case the ack can be send, or FALSE
 ** if e.g. validation of the message has failed.
 **/
void np_callback_wrapper(np_state_t* state, np_jobargs_t* args) {

	np_message_t* msg_in = args->msg;
	char* subject = args->properties->msg_subject;
	char* sender = jrb_find_str(msg_in->header, NP_MSG_HEADER_FROM)->val.value.s;
	np_msgproperty_t* msg_prop = np_message_get_handler(state, INBOUND, subject);

	np_aaatoken_t* sender_token = np_get_sender_token(state, (char*) subject, sender);
	uint32_t received = 0;

	msg_prop->msg_threshold++;

	if (NULL != sender_token) {

		log_msg(LOG_DEBUG, "decrypting message ...");
		np_bool decrypt_ok = np_message_decrypt_payload(state, msg_in, sender_token);

		if (FALSE == decrypt_ok) {
			np_unref_obj(np_aaatoken_t, sender_token);
			np_free_obj(np_aaatoken_t, sender_token);
			np_unref_obj(np_message_t, msg_in);
			np_free_obj(np_message_t, msg_in);
			msg_prop->msg_threshold--;
			return;
		}

		received = jrb_find_str(msg_in->properties, NP_MSG_INST_SEQ)->val.value.ul;
		uint8_t ack_mode  = jrb_find_str(msg_in->instructions, NP_MSG_INST_ACK)->val.value.ush;

		if (0 < (ack_mode & ACK_DESTINATION)) {
			np_send_ack(state, args->msg);
		}

		np_bool result = msg_prop->user_clb(msg_in->properties, msg_in->body);
		log_msg(LOG_INFO, "handled message %u with result %d ", received, result);

		if (0 < (ack_mode & ACK_CLIENT) && (TRUE == result))
		{
			np_send_ack(state, args->msg);
		}

		np_unref_obj(np_aaatoken_t, sender_token);
		np_free_obj(np_aaatoken_t, sender_token);

		msg_prop->msg_threshold--;

	} else {

		LOCK_CACHE(msg_prop) {

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
					np_free_obj(np_message_t, old_msg);
				}

				if ( 0 < (msg_prop->cache_policy & OVERFLOW_REJECT))
				{
					log_msg(LOG_DEBUG, "rejecting new message because cache is full");
					np_free_obj(np_message_t, msg_in);
					continue;
				}
			}

			// if ( (msg_prop->cache_policy & FIFO) )
			sll_prepend(np_message_t, msg_prop->msg_cache, msg_in);
			// if ( (msg_prop->cache_policy & FILO) )
			// sll_append(np_message_t, msg_prop->msg_cache, msg_in);

			log_msg(LOG_DEBUG, "added message to the msgcache (%p / %d) ...",
								msg_prop->msg_cache, sll_size(msg_prop->msg_cache));
			np_ref_obj(np_message_t, msg_in);
		}
	}

	np_unref_obj(np_message_t, msg_in);
	np_free_obj(np_message_t, msg_in);
}

/** hnd_msg_in_join_req:
 ** internal function that is called at the destination of a JOIN message. This
 ** call encodes the leaf set of the current host and sends it to the joiner.
 **/
void hnd_msg_in_join_req(np_state_t* state, np_jobargs_t* args) {
	log_msg(LOG_TRACE, ".start.hnd_msg_in_join_req");

	np_msgproperty_t *msg_prop;
	np_key_t* join_req_key;
	np_message_t* msg_out;

	LOCK_CACHE(state) {
		join_req_key = np_node_decode_from_jrb(state, args->msg->body);
	}
	/* check to see if the node has just left the network or not */
	// double timeval = dtime();

	/* if ((timeval - sourceNode->failuretime) < GRACEPERIOD) {
		log_msg(LOG_WARN,
				"JOIN request for node: %s:%hd rejected, elapsed time since failure = %f-%f sec",
				sourceNode->dns_name, sourceNode->port, timeval, sourceNode->failuretime);

		np_new(np_message_t, o_msg_out);
		np_message_create(o_msg_out, sourceNode->key, state->neuropil->me->key, NP_MSG_JOIN_NACK, NULL );
		msg_prop = np_message_get_handler(state, OUTBOUND, NP_MSG_JOIN_NACK);
		job_submit_msg_event(state->jobq, msg_prop, sourceNode->key, o_msg_out);
		np_unref(np_message_t, o_msg_out);

		sourceNode->handshake_status = HANDSHAKE_UNKNOWN;
		// np_aaatoken_t* aaa_token = np_get_authentication_token(state->aaa_cache, sourceNode->key);
		// aaa_token->valid = 0;

		np_send_ack(state, args);

		np_unbind(np_message_t, args->msg, msg_in);
		return;
	} */

	// check for allowance of node by user defined function
	if (state->authorize_func != NULL) {

		np_bool join_allowed = state->authorize_func(state, join_req_key->authentication);
		np_new_obj(np_message_t, msg_out);

		if (join_allowed) {
			log_msg(LOG_INFO, "join request verified, sending back join acknowledge");
			np_jtree_t* jrb_me = make_jtree();

			np_node_encode_to_jrb(jrb_me, state->my_node_key);
			uint32_t in_seq = jrb_find_str(args->msg->instructions, NP_MSG_INST_SEQ)->val.value.ul;
			jrb_insert_str(jrb_me, NP_MSG_INST_SEQ, new_jval_ul(in_seq));

			np_message_create(msg_out, join_req_key, state->my_node_key, NP_MSG_JOIN_ACK, jrb_me);
			msg_prop = np_message_get_handler(state, OUTBOUND, NP_MSG_JOIN_ACK);
			state->my_node_key->node->joined_network = TRUE;
			join_req_key->node->joined_network = TRUE;

		} else {
			log_msg(LOG_INFO, "JOIN request denied by user implementation, node: %s:%s rejected",
					join_req_key->node->dns_name, join_req_key->node->port);

			np_message_create(msg_out, join_req_key, state->my_node_key, NP_MSG_JOIN_NACK, NULL );
			msg_prop = np_message_get_handler(state, OUTBOUND, NP_MSG_JOIN_NACK);

			// TODO: chicken egg problem
			// without handshake we cannot send join.nack messages
			// but we have to delete the auth token after really sending the nack
			// np_aaatoken_t* aaa_token = np_get_authentication_token(state->aaa_cache, sourceNode->key);
			// aaa_token->valid = 0;
			// sourceNode->handshake_status = HANDSHAKE_UNKNOWN;
		}

		job_submit_msg_event(state->jobq, 0.0, msg_prop, join_req_key, msg_out);

		np_key_t *added, *deleted;
		LOCK_CACHE(state->routes) {
			route_update(state, join_req_key, join_allowed, &deleted, &added);
			if (NULL != added)   np_ref_obj(np_key_t, added);
			if (NULL != deleted) np_unref_obj(np_key_t, deleted);
		}

		LOCK_CACHE(state->routes) {
			leafset_update(state, join_req_key, join_allowed, &deleted, &added);
			if (NULL != added)   np_ref_obj(np_key_t, added);
			if (NULL != deleted) np_unref_obj(np_key_t, deleted);
		}

	} else {
		log_msg(LOG_ERROR, "no join request function defined, exiting");
		exit(1);
	}

	np_send_ack(state, args->msg);

	log_msg(LOG_TRACE, ".end  .hnd_msg_in_join_req");
}

/** hnd_msg_in_join_ack:
 ** called when the current node is joining the network and has just received
 ** its leaf set. This function sends an update message to all nodes in its
 ** new leaf set to announce its arrival.
 **/
void hnd_msg_in_join_ack(np_state_t* state, np_jobargs_t* args) {
	log_msg(LOG_TRACE, ".start.hnd_msg_in_join_ack");

	np_message_t* msg_out = NULL;
	np_key_t* join_key = NULL;
	np_msgproperty_t* out_props = NULL;

	LOCK_CACHE(state) {
		join_key = np_node_decode_from_jrb(state, args->msg->body);
	}

	/* acknowledgement of join message send out earlier */
	uint32_t in_seq = jrb_find_str(args->msg->body, NP_MSG_INST_SEQ)->val.value.ul;
	np_network_t* ng = state->my_node_key->node->network;
	pthread_mutex_lock(&(ng->lock));
	np_jtree_elem_t *jrb_node = jrb_find_ulong(ng->waiting, in_seq);
	if (jrb_node != NULL) {
		np_ackentry_t *entry = (np_ackentry_t *) jrb_node->val.value.v;
		entry->acked = TRUE;
		entry->acktime = dtime();
		log_msg(LOG_DEBUG, "received acknowledgment of seq=%u", in_seq);
	}
	pthread_mutex_unlock(&(ng->lock));

	log_msg(LOG_INFO, "received join ack from key: %s host: %s port %s",
					  key_get_as_string(join_key), join_key->node->dns_name, join_key->node->port);

	/* announce arrival of new node to the nodes in my routing table */
	// TODO: check for protected node neighbours ?
	np_sll_t(np_key_t, nodes);
	LOCK_CACHE(state->routes) {
		nodes = route_get_table(state->routes);
	}

	np_key_t* elem = NULL;
	while ( NULL != (elem = sll_head(np_key_t, nodes))) {

		// send update of new node to all nodes in my routing table
		if (key_equal(elem, join_key)) continue;

		np_new_obj(np_message_t, msg_out);

		// encode informations -> has to be done for each update message new
		// otherwise there is a crash when deleting the message
		np_jtree_t* jrb_join_node = make_jtree();
		np_node_encode_to_jrb(jrb_join_node, join_key);

		np_message_create(msg_out, elem, state->my_node_key,
				NP_MSG_UPDATE_REQUEST, jrb_join_node);
		out_props = np_message_get_handler(state, OUTBOUND, NP_MSG_UPDATE_REQUEST);
		job_submit_msg_event(state->jobq, 0.0, out_props, elem, msg_out);
	}
	sll_free(np_key_t, nodes);

	// remember key for routing table update
	log_msg(LOG_INFO, "join acknowledged and updates to other nodes send");

	np_key_t *added, *deleted;
	// update table
	LOCK_CACHE(state->routes) {
		route_update(state, join_key, 1, &deleted, &added);
		if (added)   np_ref_obj(np_key_t, added);
		if (deleted) np_unref_obj(np_key_t, deleted);
	}
	// update leafset
	LOCK_CACHE(state->routes) {
		leafset_update(state, join_key, 1, &deleted, &added);
		if (added)   np_ref_obj(np_key_t, added);
		if (deleted) np_unref_obj(np_key_t, deleted);
	}

	// send a piggy message to the new node in our routing table
	np_msgproperty_t* piggy_prop = np_message_get_handler(state, TRANSFORM, NP_MSG_PIGGY_REQUEST);
	job_submit_msg_event(state->jobq, 0.0, piggy_prop, join_key, NULL);

	join_key->node->joined_network = TRUE;
	state->my_node_key->node->joined_network = TRUE;

	np_free_obj(np_message_t, args->msg);
	log_msg(LOG_TRACE, ".end  .hnd_msg_in_join_ack");
}

/**
 ** hnd_msg_join_nack
 ** internal function that is called when the sender of a JOIN message receives
 ** the JOIN_NACK message type which is join denial from the current key root
 ** in the network.
 **/
void hnd_msg_in_join_nack(np_state_t* state, np_jobargs_t* args) {

	np_key_t* nack_key;
	np_key_t search_key;
	str_to_key(&search_key, (unsigned char*) jrb_find_str(args->msg->header, NP_MSG_HEADER_FROM)->val.value.s);

	LOCK_CACHE(state) {
		nack_key = SPLAY_FIND(spt_key, &state->key_cache, &search_key);
		SPLAY_REMOVE(spt_key, &state->key_cache, nack_key);
		np_unref_obj(np_key_t, nack_key);
	}

	log_msg(LOG_INFO, "JOIN request rejected from %s:%s !", nack_key->node->dns_name, nack_key->node->port);

	nack_key->authentication->valid = 0;
	nack_key->node->joined_network = FALSE;
	nack_key->node->handshake_status = HANDSHAKE_UNKNOWN;

	np_free_obj(np_key_t, nack_key);
	np_free_obj(np_message_t, args->msg);
}

void hnd_msg_in_ping(np_state_t* state, np_jobargs_t* args) {

	if (!state->my_node_key->node->joined_network) {
		np_free_obj(np_message_t, args->msg);
		return;
	}

	np_message_t *msg_out;
	np_key_t* ping_key;
	np_key_t search_key;
	str_to_key(&search_key, (unsigned char*) jrb_find_str(args->msg->header, NP_MSG_HEADER_FROM)->val.value.s);

	LOCK_CACHE(state) {
		ping_key = SPLAY_FIND(spt_key, &state->key_cache, &search_key);
	}

	log_msg(LOG_DEBUG, "received a PING message from %s:%s !", ping_key->node->dns_name, ping_key->node->port);

	// send out a ping reply if the hostname and port is known
	if (ping_key && ping_key->node->handshake_status == HANDSHAKE_COMPLETE) {
		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, ping_key, state->my_node_key, NP_MSG_PING_REPLY, NULL );
		np_msgproperty_t* msg_pingreply_prop = np_message_get_handler(state, OUTBOUND, NP_MSG_PING_REPLY);
		job_submit_msg_event(state->jobq, 0.0, msg_pingreply_prop, ping_key, msg_out);
	}

	np_free_obj(np_message_t, args->msg);
}

void hnd_msg_in_pingreply(np_state_t* state, np_jobargs_t * args) {

	if (!state->my_node_key->node->joined_network) {
		np_free_obj(np_message_t, args->msg);
		return;
	}

	np_key_t* pingreply_key;
	np_key_t search_key;
	str_to_key(&search_key, (unsigned char*) jrb_find_str(args->msg->header, NP_MSG_HEADER_FROM)->val.value.s);

	LOCK_CACHE(state) {
		pingreply_key = SPLAY_FIND(spt_key, &state->key_cache, &search_key);
	}

	if (pingreply_key && pingreply_key->node->failuretime > 0) {
		double latency = dtime() - pingreply_key->node->failuretime;
		np_node_update_latency(pingreply_key->node, latency);
	}
	// reset for next ping attempt
	pingreply_key->node->failuretime = 0;
	np_node_update_stat(pingreply_key->node, 1);

	log_msg(LOG_DEBUG, "ping reply received from: %s:%s, latency now: %f!",
			pingreply_key->node->dns_name, pingreply_key->node->port,
		    pingreply_key->node->latency);

	np_free_obj(np_message_t, args->msg);
}

// TODO: write a function that handles path discovery
// TODO: if this is not the target node, add my own address to the update message
// TODO: if this is the target node, change target to sending instance and send again


// receive information about new nodes in the network and try to contact new nodes
void hnd_msg_in_update(np_state_t* state, np_jobargs_t* args) {

	if (!state->my_node_key->node->joined_network) {
		np_free_obj(np_message_t, args->msg);
		return;
	}

	np_message_t *msg_out;
	np_key_t *update_key;

	LOCK_CACHE(state) {
		update_key = np_node_decode_from_jrb(state, args->msg->body);
	}

	if (update_key->node->handshake_status < HANDSHAKE_INITIALIZED &&
		FALSE == update_key->node->joined_network) {

		np_jtree_t* jrb_me = make_jtree();
		np_node_encode_to_jrb(jrb_me, state->my_node_key);

		np_new_obj(np_message_t, msg_out);
		np_message_create(msg_out, update_key, state->my_node_key , NP_MSG_JOIN_REQUEST, jrb_me);
		log_msg(LOG_DEBUG, "submitting welcome message to new node");
		np_msgproperty_t* prop = np_message_get_handler(state, OUTBOUND, NP_MSG_JOIN_REQUEST);
		job_submit_msg_event(state->jobq, 0.0, prop, update_key, msg_out);
	}

	np_free_obj(np_message_t, args->msg);
}

void hnd_msg_in_interest(np_state_t* state, np_jobargs_t* args) {

	if (!state->my_node_key->node->joined_network) {
		np_free_obj(np_message_t, args->msg);
		return;
	}

	np_message_t *msg_out;

	np_key_t *reply_to_key = NULL;
	np_jtree_elem_t* reply = jrb_find_str(args->msg->header, NP_MSG_HEADER_REPLY_TO);
	if ( NULL != reply ) {
		np_new_obj(np_key_t, reply_to_key);
		str_to_key(reply_to_key, (unsigned char*) reply->val.value.s);
		log_msg(LOG_DEBUG, "reply_to key: %s", key_get_as_string(reply_to_key) );
	}

	// extract e2e encryption details for sender
	np_aaatoken_t* msg_token;
	np_new_obj(np_aaatoken_t, msg_token);
	np_decode_aaatoken(args->msg->body, msg_token);

	np_key_t to_key;
	str_to_key(&to_key, (unsigned char*) jrb_find_str(args->msg->header, NP_MSG_HEADER_TO)->val.value.s);

	if ( NULL != reply_to_key && key_equal(&to_key, state->my_node_key) ) {
		// check if we are (one of the) receiving node(s) of this kind of message
		np_bool aaa_val = TRUE;
		aaa_val &= state->authenticate_func(state, msg_token);
		aaa_val &= state->authorize_func(state, msg_token);

		if (FALSE == aaa_val) {
			np_free_obj(np_message_t, args->msg);
			return;
		}
	}

	if (TRUE == token_is_valid(msg_token)) {
		log_msg(LOG_DEBUG, "now handling message interest");
		np_add_receiver_token(state, msg_token->subject, msg_token);
	}

//	if (reply_to_key &&
//		!key_equal(reply_to_key, state->my_node_key)) {
	if (NULL != reply_to_key)
	{
		// this node is the man in the middle - inform receiver of sender token
		np_sll_t(np_aaatoken_t, available_list) = np_get_sender_token_all(state, msg_token->subject);
		np_aaatoken_t* tmp_token = NULL;

		while (NULL != (tmp_token = sll_head(np_aaatoken_t, available_list))) {

			log_msg(LOG_DEBUG, "found a sender of messages, sending back message availabilities ...");
			np_jtree_t* available_data = make_jtree();

			np_encode_aaatoken(available_data, tmp_token);

			np_new_obj(np_message_t, msg_out);
			np_message_create(msg_out, reply_to_key, NULL, NP_MSG_AVAILABLE, available_data);
			np_msgproperty_t* prop_route = np_message_get_handler(state, TRANSFORM, ROUTE_LOOKUP);
			job_submit_msg_event(state->jobq, 0.0, prop_route, reply_to_key, msg_out);

			np_free_obj(np_aaatoken_t, tmp_token);
		}
	}

	np_msgproperty_t* real_prop = np_message_get_handler(state, OUTBOUND, msg_token->subject);
	// check if we are (one of the) sending node(s) of this kind of message
	if ( NULL != real_prop ) { //

		log_msg(LOG_DEBUG,
				"this node is one sender of messages, checking msgcache (%p / %u) ...",
				real_prop->msg_cache, sll_size(real_prop->msg_cache));

		// get message from cache (maybe only for one way mep ?!)
		uint16_t msg_available = 0;

		LOCK_CACHE(real_prop) {
			msg_available = sll_size(real_prop->msg_cache);
		}
		np_bool sending_ok = TRUE;

		while (0    <  msg_available &&
			   TRUE == sending_ok)
		{
			LOCK_CACHE(real_prop) {
				// if messages are available in cache, send them !
				if (real_prop->cache_policy & FIFO)
					msg_out = sll_head(np_message_t, real_prop->msg_cache);
				if (real_prop->cache_policy & FILO)
					msg_out = sll_tail(np_message_t, real_prop->msg_cache);

				np_unref_obj(np_message_t, msg_out);
				// check for more messages in cache after head/tail command
				msg_available = sll_size(real_prop->msg_cache);
			}

			sending_ok = np_send_msg(state, real_prop->msg_subject, msg_out, real_prop);
			log_msg(LOG_DEBUG, "message in cache found and re-send initialized");
		}
		// TODO send out the non availability of data to the sender node i.e. threshold doesn't match ???
		// 2) then send out the interest to the sender of messages
		// TODO: really needed ? it will get the update when sending his own interest
		// TODO: !!! behaviour is depending on mep !!!
		// send out the availability to the target of messages
	}

	np_free_obj(np_message_t, args->msg);
}

void hnd_msg_in_available(np_state_t* state, np_jobargs_t* args) {

	if (!state->my_node_key->node->joined_network) {
		np_free_obj(np_message_t, args->msg);
		return;
	}

	np_message_t *msg_in = args->msg;

	np_key_t *reply_to_key = NULL;
	np_jtree_elem_t* reply = jrb_find_str(args->msg->header, NP_MSG_HEADER_REPLY_TO);
	if (NULL != reply) {
		np_new_obj(np_key_t, reply_to_key);
		str_to_key(reply_to_key, (unsigned char*) reply->val.value.s);
		log_msg(LOG_DEBUG, "reply key: %s", key_get_as_string(reply_to_key) );
	}

	// extract e2e encryption details for sender
	np_aaatoken_t* msg_token;
	np_new_obj(np_aaatoken_t, msg_token);
	np_decode_aaatoken(args->msg->body, msg_token);

	np_key_t to_key;
	str_to_key(&to_key, (unsigned char*) jrb_find_str(args->msg->header, NP_MSG_HEADER_TO)->val.value.s);
	if ( NULL != reply_to_key && key_equal(&to_key, state->my_node_key) ) {
		// check if we are (one of the) receiving node(s) of this kind of message
		np_bool aaa_val = TRUE;
		aaa_val &= state->authenticate_func(state, msg_token);
		aaa_val &= state->authorize_func(state, msg_token);
		if (FALSE == aaa_val) {
			np_free_obj(np_message_t, args->msg);
			return;
		}
	}

	// always?: just store the available messages in memory and update if new data arrives
	if (TRUE == token_is_valid(msg_token)) {
		log_msg(LOG_DEBUG, "now handling message availability");
		np_add_sender_token(state, msg_token->subject, msg_token);
	}

	if (reply_to_key)
	{
		np_message_t *msg_out = NULL;
		np_sll_t(np_aaatoken_t, receiver_list) = np_get_receiver_token_all(state, msg_token->subject);
		np_aaatoken_t* tmp_token = NULL;

		while (NULL != (tmp_token = sll_head(np_aaatoken_t, receiver_list))) {

			np_jtree_t* interest_data = make_jtree();

			np_encode_aaatoken(interest_data, tmp_token);

			np_new_obj(np_message_t, msg_out);
			np_message_create(msg_out, reply_to_key, NULL, NP_MSG_INTEREST, interest_data);
			np_msgproperty_t* prop_route = np_message_get_handler(state, TRANSFORM, ROUTE_LOOKUP);

			log_msg(LOG_DEBUG, "sending back msg interest to %s", key_get_as_string(reply_to_key));
			job_submit_msg_event(state->jobq, 0.0, prop_route, reply_to_key, msg_out);

			np_free_obj(np_aaatoken_t, tmp_token);
		}
	}

	// check if some messages are left in the cache
	np_msgproperty_t* real_prop = np_message_get_handler(state, INBOUND, msg_token->subject);
	// check if we are (one of the) receiving node(s) of this kind of message
	if ( NULL != real_prop ) {

		log_msg(LOG_DEBUG,
				"this node is the receiver of messages, checking msgcache (%p / %u) ...",
				real_prop->msg_cache, sll_size(real_prop->msg_cache));

		// get message from cache (maybe only for one way mep ?!)
		uint16_t msg_available = 0;
		LOCK_CACHE(real_prop) {
			msg_available = sll_size(real_prop->msg_cache);
		}

		while (0 < msg_available)
		{
			msg_in = NULL;
			LOCK_CACHE(real_prop) {
				// if messages are available in cache, try to decode them !
				if (real_prop->cache_policy & FIFO)
					msg_in = sll_tail(np_message_t, real_prop->msg_cache);
				if (real_prop->cache_policy & FILO)
					msg_in = sll_head(np_message_t, real_prop->msg_cache);

				msg_available = sll_size(real_prop->msg_cache);
				real_prop->msg_threshold--;
			}

			job_submit_msg_event(state->jobq, 0.0, real_prop, state->my_node_key, msg_in);
		}
	}

	np_free_obj(np_message_t, args->msg);
}

void hnd_msg_in_authenticate(np_state_t* state, np_jobargs_t* args) {

}

void hnd_msg_in_authenticate_reply(np_state_t* state, np_jobargs_t* args) {

}

void hnd_msg_in_handshake(np_state_t* state, np_jobargs_t* args) {

	// initial handshake message contains public encryption parameter
	// log_msg(LOG_DEBUG, "decoding of handshake message ...");
	np_jtree_elem_t* jrb_alias = jrb_find_str(args->msg->footer, NP_MSG_FOOTER_ALIAS_KEY);
	np_jtree_elem_t* signature = jrb_find_str(args->msg->body, NP_HS_SIGNATURE);
	np_jtree_elem_t* payload   = jrb_find_str(args->msg->body, NP_HS_PAYLOAD);

	if (signature == NULL || payload == NULL) {
		log_msg(LOG_WARN, "no signature or payload found in handshake message, discarding handshake attempt");
		// change of IP adresses can lead to messages not containing signatures :-(
		np_free_obj(np_message_t, args->msg);
		return;
	}
	assert (jrb_alias != NULL);
	np_key_t* alias_key = NULL;
	np_key_t* search_alias_key = key_create_from_hash((unsigned char*) jrb_alias->val.value.s);

	cmp_ctx_t cmp;
	np_jtree_t* hs_payload = make_jtree();

	cmp_init(&cmp, payload->val.value.bin, buffer_reader, buffer_writer);
	deserialize_jrb_node_t(hs_payload, &cmp);

	char* node_proto = jrb_find_str(hs_payload, "_np.protocol")->val.value.s;
	char* node_hn = jrb_find_str(hs_payload, "_np.dns_name")->val.value.s;
	char* node_port = jrb_find_str(hs_payload, "_np.port")->val.value.s;
	np_jtree_elem_t* sign_key = jrb_find_str(hs_payload, "_np.signature_key");
	np_jtree_elem_t* pub_key = jrb_find_str(hs_payload, "_np.public_key");
	double issued_at = jrb_find_str(hs_payload, "_np.issued_at")->val.value.d;
	double expiration = jrb_find_str(hs_payload, "_np.expiration")->val.value.d;

	if (0 != crypto_sign_verify_detached( (const unsigned char*) signature->val.value.bin,
			                              (const unsigned char*) payload->val.value.bin,
										  payload->val.size,
										  (const unsigned char*) sign_key->val.value.bin) )
	{
		log_msg(LOG_ERROR, "incorrect signature in handshake message");

		np_free_tree(hs_payload);
		np_free_obj(np_message_t, args->msg);
		return;
	}
	log_msg(LOG_DEBUG, "decoding of handshake message from %s:%s (i:%f/e:%f) complete",
			node_hn, node_port, issued_at, expiration);

	// store the handshake data in the node cache, use hostname/port for key generation
	// key could be changed later, but we need a way to lookup the handshake data later
	np_key_t* hs_key = NULL;
	np_key_t* search_key = key_create_from_hostport(node_hn, node_port);

	LOCK_CACHE(state) {
		if (NULL == (hs_key = SPLAY_FIND(spt_key, &state->key_cache, search_key)) ) {
			SPLAY_INSERT(spt_key, &state->key_cache, search_key);
			hs_key = search_key;
			np_ref_obj(np_key_t, hs_key);
	    } else {
	    	np_free_obj(np_key_t, search_key);
	    }
	}

	if (NULL == hs_key->node) {
		np_new_obj(np_node_t, hs_key->node);
		uint8_t proto = np_parse_protocol_string(node_proto);
		np_node_update(hs_key->node, proto, node_hn, node_port);
	}

	if (NULL == hs_key->authentication) {
		// create a aaa token and store it as authentication data
		np_new_obj(np_aaatoken_t, hs_key->authentication);
	}

	if (hs_key->node->handshake_status <= HANDSHAKE_INITIALIZED) {

		np_aaatoken_t* my_id_token;
		my_id_token = state->my_node_key->authentication;

		// get our own identity from the cache and convert to curve key
		unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
		// unsigned char curve25519_pk[crypto_scalarmult_curve25519_BYTES];
		crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_id_token->private_key);
		// crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, my_id_token->public_key);

		// create shared secret
		unsigned char shared_secret[crypto_scalarmult_BYTES];
		crypto_scalarmult(shared_secret, curve25519_sk, pub_key->val.value.bin);

		np_aaatoken_t* hs_token = hs_key->authentication;
		if (hs_token->valid)
		{
			log_msg(LOG_WARN, "found valid authentication token for node %s, overwriting ...", key_get_as_string(hs_key));
		}

		hs_key->authentication->expiration = expiration;
		hs_key->authentication->issued_at = issued_at;
		strncpy((char*) hs_key->authentication->public_key, pub_key->val.value.bin, pub_key->val.size);
		strncpy((char*) hs_key->authentication->session_key, (char*) shared_secret, crypto_scalarmult_BYTES);
		hs_key->authentication->valid = 1;

		np_ref_obj(np_key_t, hs_key);

		LOCK_CACHE(state) {
			if (NULL == (alias_key = SPLAY_FIND(spt_key, &state->key_cache, search_alias_key)) ) {
				SPLAY_INSERT(spt_key, &state->key_cache, search_alias_key);
				alias_key = search_alias_key;
				np_ref_obj(np_key_t, alias_key);
		    } else {
		    	np_free_obj(np_key_t, search_alias_key);
		    }
		}
		alias_key->authentication = hs_key->authentication;
		alias_key->node = hs_key->node;
		np_ref_obj(np_key_t, alias_key);

		hs_key->node->handshake_status = HANDSHAKE_COMPLETE;

		// send out our own handshake data
		np_msgproperty_t* hs_prop = np_message_get_handler(state, OUTBOUND, NP_MSG_HANDSHAKE);
		job_submit_msg_event(state->jobq, 0.0, hs_prop, hs_key, NULL);
	}

	np_free_tree(hs_payload);

	np_free_obj(np_key_t, hs_key);
	np_free_obj(np_message_t, args->msg);

	// log_msg(LOG_DEBUG, "finished to handle handshake message");
}

