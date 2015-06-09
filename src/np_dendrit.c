#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "sodium.h"

#include "np_dendrit.h"

#include "aaatoken.h"
#include "dtime.h"
#include "log.h"
#include "job_queue.h"
#include "jrb.h"
#include "network.h"
#include "neuropil.h"
#include "node.h"
#include "np_glia.h"
#include "np_memory.h"
#include "np_util.h"
#include "np_threads.h"
#include "message.h"
#include "route.h"


#define SEND_SIZE NETWORK_PACK_SIZE

#define GRACEPERIOD  30		/* seconds */

/**
 ** message_received:
 ** is called by network_activate and will be passed received data and size from socket
 */
void hnd_msg_in_received(np_state_t* state, np_jobargs_t* args)
{
	np_message_t* msg;
	np_bind(np_message_t, args->msg, msg);

	np_jrb_t* subject = jrb_find_str(msg->header, NP_MSG_HEADER_SUBJECT);
	np_msgproperty_t* handler = np_message_get_handler(state->messages, INBOUND, subject->val.value.s );

	if (!key_equal(args->target, state->routes->me) || handler == NULL) {
		// perform a route lookup
		log_msg(LOG_INFO, "received unrecognized message type %s, perform route lookup ...", subject->val.value.s);
		np_msgproperty_t* prop = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
		job_submit_msg_event(state->jobq, prop, args->target, args->msg);

		np_unbind(np_message_t, args->msg, msg);
		np_free(np_message_t, args->msg);
		return;
	}

	if (handler->clb == NULL ) {
		log_msg(LOG_WARN,
				"no incoming callback function was found for type %s, dropping message",
				handler->msg_subject);
		np_unbind(np_message_t, args->msg, msg);
		np_free(np_message_t, args->msg);
		return;
	}

	// decrease msg interest threshold
	// np_msginterest_t* interest = np_message_interest_match(state->messages, subject);
	// interest->msg_threshold--;

	// finally submit msg job for later execution
	job_submit_msg_event(state->jobq, handler, state->neuropil->my_key, args->msg);
	np_unbind(np_message_t, args->msg, msg);
	np_free(np_message_t, args->msg);
	return;
}

/**
 ** chimera_piggy_message:
 ** message handler for message type PIGGY ;) this used to be a piggy backing function
 ** This function is responsible to add the piggy backing node information that is sent along with
 ** other ctrl messages or separately to the routing table. the PIGGY message type is a separate
 ** message type.
 **/
void hnd_msg_in_piggy(np_state_t* state, np_jobargs_t* args) {

	if (!state->joined_network) {
		np_free(np_message_t, args->msg);
		return;
	}

	np_key_t* tmp_key;
	np_node_t* piggy;
	np_message_t* msg_in;

	np_bind(np_message_t, args->msg, msg_in);

	int i = 0;
	double tmp_ft;
	np_obj_t** o_piggy_list;

	LOCK_CACHE(state->nodes) {
		o_piggy_list = np_decode_nodes_from_jrb(state->nodes, msg_in->body);
	}

	for (i = 0; o_piggy_list[i] != NULL ; i++) {

		np_bind(np_node_t, o_piggy_list[i], piggy);
		tmp_key = piggy->key;
		tmp_ft = piggy->failuretime;
		np_unbind(np_node_t, o_piggy_list[i], piggy);

		np_key_t *added, *deleted;

		if (!key_equal(tmp_key, state->neuropil->my_key) ) {
			if ((dtime() - tmp_ft) > GRACEPERIOD) {

				LOCK_CACHE(state->nodes) {
					route_update(state, tmp_key, 1, &deleted, &added);
					if (added)   np_node_lookup(state->nodes, added, 1);
					if (deleted) np_node_release(state->nodes, deleted);
				}

				LOCK_CACHE(state->nodes) {
					leafset_update(state, tmp_key, 1, &deleted, &added);
					if (added)   np_node_lookup(state->nodes, added, 1);
					if (deleted) np_node_release(state->nodes, deleted);
				}
			}
/* 			else
 				log_msg(LOG_WARN, "refused to add %s to routing table",
 						key_get_as_string(piggy[i]->key));
		    } else {
			    log_msg(LOG_WARN, "refused to add myself to the routing table");
*/
		}
	}
	np_unbind(np_message_t, args->msg, msg_in);
	np_free(np_message_t, args->msg);
}

void np_signal (np_state_t* state, np_jobargs_t* args) {

	if (!state->joined_network) {
		np_free(np_message_t, args->msg);
		return;
	}

	np_message_t* msg_in;
	np_bind(np_message_t, args->msg, msg_in);

	log_msg(LOG_DEBUG, "message received");

	const char* subject = jrb_find_str(msg_in->header, NP_MSG_HEADER_SUBJECT)->val.value.s;
	// unsigned long msg_id = jrb_find_str(msg->header, "_np.msg.seq")->val.value.ul;

	// create message in message cache - there must be a available data structure !
	np_msginterest_t* available = np_message_available_match(state->messages, subject);
	if (!available) {
		// available = np_message_create_interest(state, subject, 0, msg_id, 1);
		log_msg(LOG_WARN, "no available message sender found on this node, dropping message ...");
		np_unbind(np_message_t, args->msg, msg_in);
		np_free(np_message_t, args->msg);
		return;
	}

	// np_msginterest_t* interested = np_message_available_update(state->messages, available);
	log_msg(LOG_DEBUG, "pushing message into cache %p", available);
	np_msgcache_push(available, args->msg);
	np_ref(np_message_t, args->msg);

	// signal the np_receive function that the message has arrived
	// if (interested) {
	log_msg(LOG_DEBUG, "signaling via available %p", available);
	pthread_mutex_lock(&available->lock);
	pthread_cond_signal(&available->msg_received);
	pthread_mutex_unlock(&available->lock);

	np_unbind(np_message_t, args->msg, msg_in);

	// TODO: more detailed msg ack handling
	if (available->send_ack && (args->properties->ack_mode == 2)) {
		np_send_ack(state, args);
	}
	np_free(np_message_t, args->msg);
}

/** hnd_msg_in_join_req:
 ** internal function that is called at the destination of a JOIN message. This
 ** call encodes the leaf set of the current host and sends it to the joiner.
 **/
void hnd_msg_in_join_req(np_state_t* state, np_jobargs_t* args) {

	np_msgproperty_t *msg_prop;
	np_obj_t* o_msg_out, *o_source_node;
	np_key_t* tmp_key = NULL;
	np_node_t* source_node;
	np_message_t *msg_in, *msg_out;

	np_bind(np_message_t, args->msg, msg_in);

	LOCK_CACHE(state->nodes) {
		o_source_node = np_node_decode_from_jrb(state->nodes, msg_in->body);
		np_bind(np_node_t, o_source_node, source_node);
	}
	tmp_key = source_node->key;
	np_unbind(np_node_t, o_source_node, source_node);

	np_unbind(np_message_t, args->msg, msg_in);

	/* check to see if the node has just left the network or not */
	// double timeval = dtime();

	/* if ((timeval - sourceNode->failuretime) < GRACEPERIOD) {
		log_msg(LOG_WARN,
				"JOIN request for node: %s:%d rejected, elapsed time since failure = %f-%f sec",
				sourceNode->dns_name, sourceNode->port, timeval, sourceNode->failuretime);

		np_new(np_message_t, o_msg_out);
		np_message_create(o_msg_out, sourceNode->key, state->neuropil->me->key, NP_MSG_JOIN_NACK, NULL );
		msg_prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_JOIN_NACK);
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
	if (state->neuropil->join_func != NULL) {

		np_bind(np_node_t, o_source_node, source_node);
		np_bool join_allowed = state->neuropil->join_func(state, source_node);
		np_unbind(np_node_t, o_source_node, source_node);

		np_new(np_message_t, o_msg_out);
		np_bind(np_message_t, o_msg_out, msg_out);

		np_bind(np_node_t, o_source_node, source_node);

		if (join_allowed) {
			log_msg(LOG_INFO, "join request verified, sending back join acknowledge");
			np_node_t* me;
			np_jrb_t* jrb_me = make_jrb();

			np_bind(np_node_t, state->neuropil->me, me);
			np_node_encode_to_jrb(jrb_me, me);
			np_unbind(np_node_t, state->neuropil->me, me);

			np_message_create(msg_out, source_node->key, state->neuropil->my_key, NP_MSG_JOIN_ACK, jrb_me);
			msg_prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_JOIN_ACK);
			state->joined_network = 1;

		} else {
			log_msg(LOG_INFO, "JOIN request denied by user implementation, node: %s:%d rejected",
					source_node->dns_name, source_node->port);

			np_message_create(msg_out, source_node->key, state->neuropil->my_key, NP_MSG_JOIN_NACK, NULL );
			msg_prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_JOIN_NACK);

			// TODO: chicken egg problem
			// without handshake we cannot send join.nack messages
			// but we have to delete the auth token after really sending the nack

			// np_aaatoken_t* aaa_token = np_get_authentication_token(state->aaa_cache, sourceNode->key);
			// aaa_token->valid = 0;
			// sourceNode->handshake_status = HANDSHAKE_UNKNOWN;
		}

		job_submit_msg_event(state->jobq, msg_prop, source_node->key, o_msg_out);

		np_key_t *added, *deleted;
		LOCK_CACHE(state->nodes) {
			route_update(state, tmp_key, join_allowed, &deleted, &added);
			if (added)   np_node_lookup(state->nodes, added, 1);
			if (deleted) np_node_release(state->nodes, deleted);
		}
		LOCK_CACHE(state->nodes) {
			leafset_update(state, tmp_key, join_allowed, &deleted, &added);
			if (added)   np_node_lookup(state->nodes, added, 1);
			if (deleted) np_node_release(state->nodes, deleted);
		}

		np_unbind(np_node_t, o_source_node, source_node);
		np_unbind(np_message_t, o_msg_out, msg_out);

	} else {
		log_msg(LOG_ERROR, "no join request function defined, exiting");
		exit(1);
	}

	np_send_ack(state, args);
}

/** hnd_msg_in_join_ack:
 ** called when the current node is joining the network and has just received
 ** its leaf set. This function sends an update message to all nodes in its
 ** new leaf set to announce its arrival.
 **/
void hnd_msg_in_join_ack(np_state_t* state, np_jobargs_t* args) {

	int i;
	np_message_t* msg_in = NULL, *msg_out = NULL;
	np_obj_t* o_msg_out = NULL;
	np_obj_t* o_join_node = NULL;
	np_node_t* join_node = NULL;
	np_key_t* tmp_key = NULL;
	np_msgproperty_t* out_props = NULL;

	np_bind(np_message_t, args->msg, msg_in);
	LOCK_CACHE(state->nodes) {
		o_join_node = np_node_decode_from_jrb(state->nodes, msg_in->body);
	}
	np_unbind(np_message_t, args->msg, msg_in);

	/* the join message ack is for me. Should only happen after
	 * a) this node requested joining / entering itself
	 */
	/*state->neuropil->bootstrap != NULL && */
	// if (key_equal(state->neuropil->my_key, state->neuropil->me->key ) ) {
		// message is for me, and I am the bootstrap node
	np_bind(np_node_t, o_join_node, join_node);
	log_msg(LOG_INFO, "received join ack from key: %s host: %s port %d",
					  key_get_as_string(join_node->key), join_node->dns_name, join_node->port);
	tmp_key = join_node->key;
	np_unbind(np_node_t, o_join_node, join_node);

	/* announce arrival of new node to the nodes in my routing table */
	// TODO: check for protected node neighbours ?
	np_key_t** nodes;
	LOCK_CACHE(state->nodes) {
		nodes = route_get_table(state->routes);
	}

	// send update of new node to all nodes in my routing table
	for (i = 0; nodes[i] != NULL ; i++) {
		np_new(np_message_t, o_msg_out);
		np_bind(np_message_t, o_msg_out, msg_out);

		// encode informations -> has to be done for each update message new
		// otherwise there is a crash when deleting the message
		np_bind(np_node_t, o_join_node, join_node);
		np_jrb_t* jrb_join_node = make_jrb();
		np_node_encode_to_jrb(jrb_join_node, join_node);
		np_unbind(np_node_t, o_join_node, join_node);

		np_message_create(msg_out, nodes[i], state->neuropil->my_key,
						  NP_MSG_UPDATE_REQUEST, jrb_join_node);
		out_props = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_UPDATE_REQUEST);
		if (!key_equal(nodes[i], tmp_key))
			job_submit_msg_event(state->jobq, out_props, nodes[i], o_msg_out);

		np_unbind(np_message_t, o_msg_out, msg_out);
	}
	log_msg(LOG_INFO, "join acknowledged and updates to other nodes send");
	free(nodes);

	np_key_t *added, *deleted;
	// update leafset
	LOCK_CACHE(state->nodes) {
		leafset_update(state, tmp_key, 1, &deleted, &added);
		if (added)   np_node_lookup(state->nodes, added, 1);
		if (deleted) np_node_release(state->nodes, deleted);
	}
	// update table
	LOCK_CACHE(state->nodes) {
		route_update(state, tmp_key, 1, &deleted, &added);
		if (added)   np_node_lookup(state->nodes, added, 1);
		if (deleted) np_node_release(state->nodes, deleted);
	}

	// send a piggy message to the new node in our routing table
	np_msgproperty_t* piggy_prop = np_message_get_handler(state->messages, TRANSFORM, NP_MSG_PIGGY_REQUEST);
	job_submit_msg_event(state->jobq, piggy_prop, tmp_key, NULL);

	state->joined_network = 1;

	np_free(np_message_t, args->msg);
}

/**
 ** hnd_msg_join_nack
 ** internal function that is called when the sender of a JOIN message receives
 ** the JOIN_NACK message type which is join denial from the current key root
 ** in the network.
 **/
void hnd_msg_in_join_nack(np_state_t* state, np_jobargs_t* args) {

	np_obj_t* o_node;
	np_node_t* node;
	np_message_t* msg_in;
	np_bind(np_message_t, args->msg, msg_in);

	np_key_t tmp_key;
	str_to_key(&tmp_key, jrb_find_str(msg_in->header, NP_MSG_HEADER_REPLY_TO)->val.value.s);

	LOCK_CACHE(state->nodes) {
		o_node = np_node_lookup(state->nodes, &tmp_key, 0);
		np_bind(np_node_t, o_node, node);
	}

	log_msg(LOG_INFO, "JOIN request rejected from %s:%d !", node->dns_name, node->port);

	np_obj_t* o_aaa_token;
	np_aaatoken_t* aaa_token;

	LOCK_CACHE(state->aaa_cache) {
		o_aaa_token = np_get_authentication_token(state->aaa_cache, node->key);
		np_bind(np_aaatoken_t, o_aaa_token, aaa_token);
	}

	aaa_token->valid = 0;
	node->handshake_status = HANDSHAKE_UNKNOWN;
	np_unbind(np_aaatoken_t, o_aaa_token, aaa_token);

	np_unbind(np_node_t, o_node, node);
	np_free(np_node_t, o_node);

	np_unbind(np_message_t, args->msg, msg_in);
	np_free(np_message_t, args->msg);
}

void hnd_msg_in_ping(np_state_t* state, np_jobargs_t* args) {

	if (!state->joined_network) {
		np_free(np_message_t, args->msg);
		return;
	}

	np_message_t* msg_in, *msg_out;
	np_obj_t* o_msg_out;

	np_obj_t* o_node;
	np_node_t* node;

	// np_jrb_t* jrb_reply_to = np_node_decode_from_str(state->nodes, jrb_find_str(msg_in->header, NP_MSG_HEADER_REPLY_TO)->val.value.s);
	// np_node_t* node = np_node_decode_from_str(state->nodes, jrb_find_str(msg_in->header, NP_MSG_HEADER_REPLY_TO)->val.value.s);

	np_bind(np_message_t, args->msg, msg_in);
	np_key_t tmp_key;
	str_to_key(&tmp_key, jrb_find_str(msg_in->header, NP_MSG_HEADER_REPLY_TO)->val.value.s);
	np_unbind(np_message_t, args->msg, msg_in);

	LOCK_CACHE(state->nodes) {
		o_node = np_node_lookup(state->nodes, &tmp_key, 0);
		np_bind(np_node_t, o_node, node);
	}

	log_msg(LOG_DEBUG, "received a PING message from %s:%d !\n", node->dns_name, node->port);

	// send out a ping reply if the hostname and port is known
	if (node->handshake_status == HANDSHAKE_COMPLETE) {
		np_new(np_message_t, o_msg_out);
		np_bind(np_message_t, o_msg_out, msg_out);

		np_message_create(msg_out, node->key, state->neuropil->my_key, NP_MSG_PING_REPLY, NULL );
		np_msgproperty_t* msg_pingreply_prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_PING_REPLY);
		job_submit_msg_event(state->jobq, msg_pingreply_prop, node->key, o_msg_out);

		np_unbind(np_message_t, o_msg_out, msg_out);
	}
	np_unbind(np_node_t, o_node, node);

	np_free(np_message_t, args->msg);
}

void hnd_msg_in_pingreply(np_state_t* state, np_jobargs_t * args) {

	if (!state->joined_network) {
		np_free(np_message_t, args->msg);
		return;
	}

	np_message_t* msg_in;
	np_obj_t* o_node;
	np_node_t* node;

	np_bind(np_message_t, args->msg, msg_in);
	np_key_t tmp_key;
	str_to_key(&tmp_key, jrb_find_str(msg_in->header, NP_MSG_HEADER_REPLY_TO)->val.value.s);
	np_unbind(np_message_t, args->msg, msg_in);

	LOCK_CACHE(state->nodes) {
		o_node = np_node_lookup(state->nodes, &tmp_key, 0);
		np_bind(np_node_t, o_node, node);
	}

	if (node->failuretime > 0) {
		double latency = dtime() - node->failuretime;
		if (latency > 0) {
			if (node->latency == 0.0) {
				node->latency = latency;
			} else {
				node->latency = (0.9 * node->latency) + (0.1 * latency);
			}
		}
	}
	np_node_update_stat(node, 1);
	log_msg(LOG_DEBUG, "ping reply received from: %s:%d, last failure / latency: %f / %f!",
						node->dns_name, node->port, node->failuretime, node->latency);
	// reset for next ping attempt
	node->failuretime = 0;

	np_unbind(np_node_t, o_node, node);

	np_free(np_message_t, args->msg);
}

// TODO: write a function that handles path discovery
// TODO: if this is not the target node, add my own address to the update message
// TODO: if this is the target node, change target to sending instance and send again
void hnd_msg_in_update(np_state_t* state, np_jobargs_t* args) {

	if (!state->joined_network) {
		np_free(np_message_t, args->msg);
		return;
	}

	np_obj_t* o_msg_out;
	np_message_t* msg_in, *msg_out;

	np_obj_t* o_node ;
	np_node_t *node, *me;

	// np_key_t* node_key;

	np_bind(np_message_t, args->msg, msg_in);

	LOCK_CACHE(state->nodes) {
		o_node = np_node_decode_from_jrb(state->nodes, msg_in->body);
		np_bind(np_node_t, o_node, node);
	}

	if (node->handshake_status < HANDSHAKE_INITIALIZED) {

		np_bind(np_node_t, state->neuropil->me, me);
		np_jrb_t* jrb_me = make_jrb();
		np_node_encode_to_jrb(jrb_me, me);
		np_unbind(np_node_t, state->neuropil->me, me);

		np_new(np_message_t, o_msg_out);
		np_bind(np_message_t, o_msg_out, msg_out);
		np_message_create(msg_out, node->key, state->neuropil->my_key , NP_MSG_JOIN_REQUEST, jrb_me);
		log_msg(LOG_DEBUG, "submitting welcome message to new node");
		np_msgproperty_t* prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_JOIN_REQUEST);
		job_submit_msg_event(state->jobq, prop, node->key, o_msg_out);
		np_unbind(np_message_t, o_msg_out, msg_out);
	}
	np_unbind(np_node_t, o_node, node);

	np_unbind(np_message_t, args->msg, msg_in);
	np_free(np_message_t, args->msg);
}

void hnd_msg_in_interest(np_state_t* state, np_jobargs_t* args) {

	if (!state->joined_network) {
		np_free(np_message_t, args->msg);
		return;
	}

	np_message_t *msg_in, *msg_out;
	np_obj_t* o_msg_out;
	np_bind(np_message_t, args->msg, msg_in);

	np_jrb_t* reply_to = jrb_find_str(msg_in->header, NP_MSG_HEADER_REPLY_TO);
	np_key_t reply_key;
	if ( reply_to ) {
		str_to_key(&reply_key, reply_to->val.value.s);
	}

	log_msg(LOG_TRACE, "now handling message interest");
	// np_node_t *replyTo = np_node_decode_from_str(state->nodes, pn_message_get_reply_to(args->msg));
	np_msginterest_t* interest = np_decode_msg_interest(state->messages, msg_in->body);

	np_unbind(np_message_t, args->msg, msg_in);

	log_msg(LOG_DEBUG, "message interest subj: %s key: %s", interest->msg_subject, key_get_as_string(interest->key));

	// always: store the interest in messages in memory and update if new data arrives
	// this also returns whether messages are already available or not
	np_msginterest_t* available = np_message_interest_update(state->messages, interest);

	if (available) {
		log_msg(LOG_DEBUG, "available key: %s interest key: %s reply key: %s",
						   key_get_as_string(available->key),
						   key_get_as_string(interest->key),
						   key_get_as_string(&reply_key) );

		log_msg(LOG_DEBUG, "message available subj: %s key: %s", available->msg_subject, key_get_as_string(available->key));

		if (reply_to &&
			!key_equal(&reply_key, state->neuropil->my_key)) {

			np_jrb_t* available_data = make_jrb();
			np_message_encode_interest(available_data, available);

			np_new(np_message_t, o_msg_out);
			np_bind(np_message_t, o_msg_out, msg_out);

			np_message_create(msg_out, interest->key, NULL, NP_MSG_AVAILABLE, available_data);
			np_msgproperty_t* prop_route = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
			log_msg(LOG_DEBUG, "sending back msg availability to %s", key_get_as_string(interest->key));
			job_submit_msg_event(state->jobq, prop_route, interest->key, o_msg_out);

			np_unbind(np_message_t, o_msg_out, msg_out);
			// np_unref(np_message_t, o_msg_out);
		}

		// check if we are (one of the) sending node(s) of this kind of message
		if ( key_equal(available->key, state->neuropil->my_key) ) {
			// TODO: match expected and real seq_num and send out real message ???
			// get message from cache (maybe only for one way mep ?!)
			unsigned int current_threshold = 0;
			// decrease threshold counter
			pthread_mutex_lock(&state->messages->interest_lock);
			current_threshold = interest->msg_threshold;
			pthread_mutex_unlock(&state->messages->interest_lock);

			o_msg_out = NULL;

			while (NULL != (o_msg_out = np_msgcache_pop(available)) && current_threshold > 0)
			{	// if messages are available in cache, send it !
				np_bind(np_message_t, o_msg_out, msg_out);

				jrb_insert_str(msg_out->header, NP_MSG_HEADER_TO,  new_jval_s((char*) key_get_as_string(interest->key)));
				np_msgproperty_t* out_prop = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
				job_submit_msg_event(state->jobq, out_prop, interest->key, o_msg_out);

				// decrease threshold counter
				pthread_mutex_lock(&state->messages->interest_lock);
				interest->msg_threshold--;
				current_threshold = interest->msg_threshold;
				pthread_mutex_unlock(&state->messages->interest_lock);

				np_unbind(np_message_t, o_msg_out, msg_out);
				// np_unref(np_message_t, o_msg_out);

				log_msg(LOG_DEBUG, "message in cache found / directly send to target node %s", key_get_as_string(interest->key));
			}
		}
		// TODO send out the non availability of data to the sender node i.e. threshold doesn't match ???
		// 2) then send out the interest to the sender of messages
		// TODO: really needed ? it will get the update when sending his own interest
		// TODO: !!! behaviour is depending on mep !!!
		// send out the availability to the target of messages
	}
	np_free(np_message_t, args->msg);
}

void hnd_msg_in_available(np_state_t* state, np_jobargs_t* args) {

	if (!state->joined_network) {
		np_free(np_message_t, args->msg);
		return;
	}

	np_message_t* msg_in, *msg_out;
	np_obj_t* o_msg_out;
	np_bind(np_message_t, args->msg, msg_in);

	np_jrb_t* reply_to = jrb_find_str(msg_in->header, NP_MSG_HEADER_REPLY_TO);
	np_key_t reply_key;
	if ( reply_to ) {
		str_to_key(&reply_key, reply_to->val.value.s);
	}
	log_msg(LOG_TRACE, "now handling message availability");
	// np_node_t *replyTo = np_node_decode_from_str(state->nodes, pn_message_get_reply_to(args->msg));
	np_msginterest_t* available = np_decode_msg_interest(state->messages, msg_in->body);

	np_unbind(np_message_t, args->msg, msg_in);

	// always: just store the available messages in memory and update if new data arrives
	np_msginterest_t* interest = np_message_available_update(state->messages, available);

	if (interest) {
		if (reply_to &&
			!key_equal(&reply_key, state->neuropil->my_key)) {

			np_jrb_t* interest_data = make_jrb();
			np_message_encode_interest(interest_data, interest);

			np_new(np_message_t, o_msg_out);
			np_bind(np_message_t, o_msg_out, msg_out);

			np_message_create(msg_out, available->key, NULL, NP_MSG_INTEREST, interest_data);
			np_msgproperty_t* prop_route = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
			log_msg(LOG_DEBUG, "sending back msg interest to %s", key_get_as_string(available->key));
			job_submit_msg_event(state->jobq, prop_route, available->key, o_msg_out);

			np_unbind(np_message_t, o_msg_out, msg_out);
			// np_unref(np_message_t, o_msg_out);
		}

		if ( key_equal(interest->key, state->neuropil->my_key) ) {
			// check if we are (one of the) receiving node(s) of this kind of message
			// match expected and real seq_num, update interest, eventually pull messages
			// TODO: do this per mep (for simple oneway nothing special required)
		}
		// send out the availability to the target of messages
		// TODO: really needed ?
	}
	np_free(np_message_t, args->msg);
}

void hnd_msg_in_handshake(np_state_t* state, np_jobargs_t* args) {

	// log_msg(LOG_DEBUG, "in_hs: message %p footer %p", args->msg, args->msg->footer);
	np_message_t* msg_in;
	np_bind(np_message_t, args->msg, msg_in);

	// initial handshake message contains public encryption parameter
	// log_msg(LOG_DEBUG, "decoding of handshake message ...");
	np_jrb_t* jrb_alias = jrb_find_str(msg_in->footer, NP_MSG_FOOTER_ALIAS_KEY);
	np_jrb_t* signature = jrb_find_str(msg_in->body, "_np.signature");
	np_jrb_t* payload   = jrb_find_str(msg_in->body, "_np.payload");

	if (signature == NULL || payload == NULL) {
		// change of IP adresses can lead to messages not containing signatures :-(
		np_unbind(np_message_t, args->msg, msg_in);
		np_free(np_message_t, args->msg);
		return;
	}
	assert (jrb_alias != NULL);

	np_key_t* alias_key = (np_key_t*) malloc (sizeof(np_key_t));
	str_to_key(alias_key, jrb_alias->val.value.s);

	cmp_ctx_t cmp;
	np_jrb_t* hs_payload = make_jrb();

	cmp_init(&cmp, payload->val.value.bin, buffer_reader, buffer_writer);
	deserialize_jrb_node_t(hs_payload, &cmp);

	char* node_hn = jrb_find_str(hs_payload, "_np.dns_name")->val.value.s;
	unsigned int node_port = jrb_find_str(hs_payload, "_np.port")->val.value.ui;
	np_jrb_t* sign_key = jrb_find_str(hs_payload, "_np.signature_key");
	np_jrb_t* pub_key = jrb_find_str(hs_payload, "_np.public_key");
	double issued_at = jrb_find_str(hs_payload, "_np.issued_at")->val.value.d;
	double expiration = jrb_find_str(hs_payload, "_np.expiration")->val.value.d;

	if (0 != crypto_sign_verify_detached( (const unsigned char*) signature->val.value.bin,
			                              (const unsigned char*) payload->val.value.bin,
										  payload->val.size,
										  (const unsigned char*) sign_key->val.value.bin) )
	{
		log_msg(LOG_ERROR, "incorrect signature in handshake message");
		job_submit_event(state->jobq, np_network_read);

		jrb_free_tree(hs_payload);
		np_unbind(np_message_t, args->msg, msg_in);
		np_free(np_message_t, args->msg);
		return;
	}
	log_msg(LOG_DEBUG, "decoding of handshake message from %s:%d (i:%f/e:%f) complete",
			node_hn, node_port, issued_at, expiration);

	np_obj_t* o_my_id_token;
	np_aaatoken_t* my_id_token;

	LOCK_CACHE(state->aaa_cache) {
		o_my_id_token = np_get_authentication_token(state->aaa_cache, state->neuropil->my_key);
		np_bind(np_aaatoken_t, o_my_id_token, my_id_token);
	}

	// get our own identity from the cache
	// convert to curve key
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	// unsigned char curve25519_pk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_id_token->private_key);
	// crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, my_id_token->public_key);

	unsigned char shared_secret[crypto_scalarmult_BYTES];
	crypto_scalarmult(shared_secret, curve25519_sk, pub_key->val.value.bin);

	np_unbind(np_aaatoken_t, o_my_id_token, my_id_token);

	// store the handshake data in the node cache, use hostname/port for key generation
	// key could be changed later, but we need a way to lookup the handshake data later
	np_obj_t* o_hs_node;
	np_node_t* hs_node;
	np_key_t* hs_key = key_create_from_hostport(node_hn, node_port);

	LOCK_CACHE(state->nodes) {
		o_hs_node = np_node_lookup(state->nodes, hs_key, 0);
		np_bind(np_node_t, o_hs_node, hs_node);
	}

	np_node_update(hs_node, node_hn, node_port);

	np_aaatoken_t* hs_token;
	np_obj_t* o_hs_token;

	LOCK_CACHE(state->aaa_cache) {
		o_hs_token = np_get_authentication_token(state->aaa_cache, hs_key);
		np_bind(np_aaatoken_t, o_hs_token, hs_token);
	}
	if (hs_token->valid)
	{
		log_msg(LOG_WARN, "found valid authentication token for node %s, overwriting ...", key_get_as_string(hs_key));
	}
	np_unbind(np_aaatoken_t, o_hs_token, hs_token);

	// create a aaa token and store it as authentication data
	np_obj_t* o_node_auth;
	np_aaatoken_t* node_auth;
	np_new(np_aaatoken_t, o_node_auth);
	np_bind(np_aaatoken_t, o_node_auth, node_auth);
	// np_aaatoken_t* node_auth = np_aaatoken_create(state->aaa_cache);
	node_auth->token_id = hs_key;
	node_auth->expiration = expiration;
	node_auth->issued_at = issued_at;
	strncpy((char*) node_auth->public_key, pub_key->val.value.bin, pub_key->val.size);
	strncpy((char*) node_auth->session_key, (char*) shared_secret, crypto_scalarmult_BYTES);

	node_auth->valid = 1;
	np_unbind(np_aaatoken_t, o_node_auth, node_auth);

	LOCK_CACHE(state->aaa_cache) {
		np_register_authentication_token(state->aaa_cache, o_node_auth, hs_key);
		np_register_authentication_token(state->aaa_cache, o_node_auth, alias_key);
	}
	// send out our own handshake data
	np_msgproperty_t* msg_prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_HANDSHAKE);

	if (hs_node->handshake_status < HANDSHAKE_COMPLETE) {
		job_submit_msg_event(state->jobq, msg_prop, hs_node->key, NULL);
			hs_node->handshake_status = HANDSHAKE_COMPLETE;
	}

	jrb_free_tree(hs_payload);

	np_unbind(np_node_t, o_hs_node, hs_node);
	np_unbind(np_message_t, args->msg, msg_in);

	np_free(np_message_t, args->msg);

	log_msg(LOG_DEBUG, "finished to decode handshake message");
}

