#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "sodium.h"

#include "np_dendrit.h"

#include "np_util.h"
#include "aaatoken.h"
#include "log.h"
#include "jrb.h"
#include "message.h"
#include "route.h"
#include "node.h"
#include "network.h"
#include "job_queue.h"
#include "np_glia.h"
#include "dtime.h"
#include "neuropil.h"


#define SEND_SIZE NETWORK_PACK_SIZE

#define GRACEPERIOD  30		/* seconds */

/**
 ** message_received:
 ** is called by network_activate and will be passed received data and size from socket
 */
void hnd_msg_in_received(np_state_t* state, np_jobargs_t* args) {

	np_message_t* msg = args->msg;

	np_jrb_t* subject = jrb_find_str(msg->header, "subject");
	np_msgproperty_t* handler = np_message_get_handler(state->messages, INBOUND, subject->val.value.s );

	if (!key_equal(args->target, state->neuropil->me->key) || handler == NULL) {
		// perform a route lookup
		log_msg(LOG_INFO, "received unrecognized message type %s, forwarding ...", subject->val.value.s);
		np_msgproperty_t* prop = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
		job_submit_msg_event(state->jobq, prop, args->target, args->msg);
		return;
	}

	// np_msgproperty_t* msg_prop = jrb_node->val.v;
	if (handler->clb == NULL ) {
		log_msg(LOG_WARN,
				"no incoming callback function was found for type %s, dropping message",
				handler->msg_subject);
		np_message_free(msg);
		return;
	}
	// finally submit msg job for later execution
	job_submit_msg_event(state->jobq, handler, state->neuropil->me->key, args->msg);
}

/**
 ** chimera_piggy_message:
 ** message handler for message type PIGGY ;) this used to be a piggy backing function
 ** This function is respopnsible to add the piggy backing node information that is sent along with
 ** other ctrl messages or separately to the routing table. the PIGGY message type is a separate
 ** message type.
 **/
void hnd_msg_in_piggy(np_state_t* state, np_jobargs_t* args) {

	if (!state->joined_network) {
		np_message_free(args->msg);
		free (args);
		return;
	}

	int i = 0;
	np_node_t** piggy = np_decode_nodes_from_amqp(state->nodes, args->msg->body);

	for (i = 0; piggy[i] != NULL ; i++) {
		if ((dtime() - piggy[i]->failuretime) > GRACEPERIOD)
			route_update(state->routes, piggy[i], 1);
		else
			log_msg(LOG_WARN, "refused to add %s to routing table",
					key_get_as_string(piggy[i]->key));
	}

	np_message_free(args->msg);
	free (args);
}

void np_signal (np_state_t* state, np_jobargs_t* args) {

	if (!state->joined_network) {
		np_message_free(args->msg);
		free (args);
		return;
	}

	log_msg(LOG_DEBUG, "message received");

	const char* subject = jrb_find_str(args->msg->header, "subject")->val.value.s;
	// MARKER -
	unsigned long msg_id = jrb_find_str(args->msg->header, "seqnum")->val.value.ul;

	char s[255];
	sprintf (s, "%s:%lu", subject, msg_id);

	// create message in message cache
	np_msginterest_t* available = np_message_create_interest(state, s, 0, msg_id, 1);
	available->payload = args->msg->body;
	np_message_available_update(state->messages, available);

	// signal the np_receive function that the message has arrived
	np_msginterest_t* interested = np_message_interest_match(state->messages, subject);

	pthread_mutex_lock(&interested->lock);
	pthread_cond_signal(&interested->msg_received);
	pthread_mutex_unlock(&interested->lock);

	// TODO:
	if (interested->send_ack && (args->properties->ack_mode == 2)) {
		np_send_ack(state, args);
	}
	free (s);
}

/** hnd_msg_in_join_req:
 ** internal function that is called at the destination of a JOIN message. This
 ** call encodes the leaf set of the current host and sends it to the joiner.
 **/
void hnd_msg_in_join_req(np_state_t* state, np_jobargs_t* args) {

	np_message_t *msg;
	np_msgproperty_t *msg_prop;
	// np_node_t* replyTo = np_node_decode_from_str(state->nodes, pn_message_get_reply_to(args->msg));
	np_node_t* sourceNode = np_node_decode_from_amqp(state->nodes, args->msg->body);

	/* check to see if the node has just left the network or not */
	double timeval = dtime();

	if ((timeval - sourceNode->failuretime) < GRACEPERIOD) {
		log_msg(LOG_WARN,
				"JOIN request for node: %s:%d rejected, elapsed time since failure = %f-%f sec",
				sourceNode->dns_name, sourceNode->port, timeval, sourceNode->failuretime);
		msg = np_message_create(state->messages, sourceNode->key, state->neuropil->me->key, NP_MSG_JOIN_NACK, NULL );
		msg_prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_JOIN_NACK);
		job_submit_msg_event(state->jobq, msg_prop, sourceNode->key, msg);

		np_send_ack(state, args);

		return;
	}

	// check for allowance of node by user defined function
	if (state->neuropil->join_func != NULL) {

		np_bool join_allowed = state->neuropil->join_func(state, sourceNode);

		if (join_allowed) {
			log_msg(LOG_INFO, "join request verified, sending back join acknowledge");
			route_update(state->routes, sourceNode, 1);

			// pn_data_t* me = pn_data(4);
			np_jrb_t* me = make_jrb();
			np_node_encode_to_amqp(me, state->neuropil->me);
			msg = np_message_create(state->messages, sourceNode->key, state->neuropil->me->key, NP_MSG_JOIN_ACK, me);
			msg_prop = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
			job_submit_msg_event(state->jobq, msg_prop, sourceNode->key, msg);
			state->joined_network = 1;

		} else {
			log_msg(LOG_INFO, "JOIN request denied by user implementation, node: %s:%d rejected",
					sourceNode->dns_name, sourceNode->port);
			route_update(state->routes, sourceNode, 0);

			msg = np_message_create(state->messages, sourceNode->key, state->neuropil->me->key, NP_MSG_JOIN_NACK, NULL );
			msg_prop = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
			job_submit_msg_event(state->jobq, msg_prop, sourceNode->key, msg);

		}
		np_send_ack(state, args);

	} else {
		log_msg(LOG_ERROR, "no join request function defined, exiting");
		exit(1);
	}

	np_message_free(args->msg);
	free (args);
}

/**
 ** hnd_msg_in_join_ack:
 ** called when the current node is joining the network and has just received
 ** its leaf set. This function sends an update message to all nodes in its
 ** new leaf set to announce its arrival.
 **/
void hnd_msg_in_join_ack(np_state_t* state, np_jobargs_t* args) {

	int i;
	// np_msgproperty_t* in_props = args->properties;
	np_msgproperty_t* out_props = NULL;
	np_message_t* msg = args->msg;

	np_node_t* bn = np_node_decode_from_amqp(state->nodes, args->msg->body);
	/* the join message ack is for me. Should only happen after
	 * a) this node requested entering itself
	 * b) this node requested a join of another node
	 */
	if (state->neuropil->bootstrap != NULL &&
		key_equal(state->neuropil->bootstrap->key, state->neuropil->me->key ) ) {
		// message is for me, and I am the bootstrap node
		log_msg(LOG_INFO, "received join ack from key: %s host: %s port %d",
				key_get_as_string(bn->key), bn->dns_name, bn->port);

		/* announce arrival of new node to the nodes in my routing table */
		// TODO: check for protected node neighbours ?
		np_node_t** nodes = route_get_table(state->routes);
		// encode informations

		np_jrb_t* joining_node = make_jrb();
		np_node_encode_to_amqp(joining_node, bn);
		// pn_data_t* existing_nodes = pn_data(4);
		// np_encode_nodes_to_amqp(existing_nodes, nodes);

		// send update of new node to all nodes in my routing table
		for (i = 0; nodes[i] != NULL ; i++) {
			msg = np_message_create(state->messages, nodes[i]->key,
					state->neuropil->me->key, NP_MSG_UPDATE_REQUEST, joining_node);
			out_props = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_UPDATE_REQUEST);
			job_submit_msg_event(state->jobq, out_props, nodes[i]->key, msg);
		}
		route_update(state->routes, bn, 1);
		log_msg(LOG_INFO, "join acknowledged and updates to other nodes send");
		free(nodes);

		// send a piggy message to the new node in our routing table
		np_msgproperty_t* piggy_prop = np_message_get_handler(state->messages, TRANSFORM, NP_MSG_PIGGY_REQUEST);
		job_submit_msg_event(state->jobq, piggy_prop, bn->key, NULL);

	} else if (state->joined_network) {
		// node already joined a network, ignore additional join request
		log_msg(LOG_WARN, "received join ack:");
		log_msg(LOG_WARN, "key: %s host: %s port %d", key_get_as_string(bn->key), bn->dns_name, bn->port);

	} else {
		// final confirmation that I can join the network
		state->joined_network = 1;
		state->neuropil->bootstrap = bn;
		route_update(state->routes, bn, 1);
	}

	np_message_free(args->msg);
	free (args);
}

/**
 ** hnd_msg_join_nack
 ** internal function that is called when the sender of a JOIN message receives
 ** the JOIN_NACK message type which is join denial from the current key root
 ** in the network.
 **/
void hnd_msg_in_join_nack(np_state_t* state, np_jobargs_t* args) {

	np_node_t *host;
	// np_global_t *chglob = (np_global_t *) state->neuropil;
	// size_t buffsize = 1024;
	// char buffer[buffsize];

	// pn_data_format(pn_message_body(args->msg), buffer, &buffsize);
	host = np_node_decode_from_str(state->nodes, jrb_find_str(args->msg->header, "reply_to")->val.value.s);
	log_msg(LOG_INFO, "JOIN request rejected from %s:%d !", host->dns_name, host->port);
	// dsleep(GRACEPERIOD);

	np_message_free(args->msg);
	free (args);

	// log_msg(LOG_DEBUG, "Re-sending JOIN message to %s:%d !", chglob->bootstrap->dns_name, chglob->bootstrap->port);
	// chimera_join (state, chglob->bootstrap);
}

void hnd_msg_in_ping(np_state_t* state, np_jobargs_t* args) {

	if (!state->joined_network) {
		np_message_free(args->msg);
		free (args);
		return;
	}

	np_node_t *node = np_node_decode_from_str(state->nodes, jrb_find_str(args->msg->header, "reply_to")->val.value.s);
	log_msg(LOG_DEBUG, "received a PING message from %s:%d !\n", node->dns_name, node->port);

	// send out a ping reply
	np_msgproperty_t* msg_pingreply_prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_PING_REPLY);
	np_message_t* msg = np_message_create(state->messages, node->key, state->neuropil->me->key, NP_MSG_PING_REPLY, NULL );
	job_submit_msg_event(state->jobq, msg_pingreply_prop, node->key, msg);

	np_message_free(args->msg);
	free (args);
}

void hnd_msg_in_pingreply(np_state_t* state, np_jobargs_t * args) {

	if (!state->joined_network) {
		np_message_free(args->msg);
		free (args);
		return;
	}

	np_node_t *node = np_node_decode_from_str(state->nodes, jrb_find_str(args->msg->header, "reply_to")->val.value.s);
	log_msg(LOG_DEBUG, "ping reply received from host: %s:%d, last failure time: %f!", node->dns_name, node->port, node->failuretime);
	node->failuretime = 0;

	np_message_free(args->msg);
	free (args);
}

// TODO: write a function that handles path discovery
// TODO: if this is not the target node, add my own address to the update message
// TODO: if this is the target node, change target to sending instance and send again

void hnd_msg_in_update(np_state_t* state, np_jobargs_t* args) {

	if (!state->joined_network) {
		np_message_free(args->msg);
		free (args);
		return;
	}

	np_node_t* node = np_node_decode_from_amqp(state->nodes, args->msg->body);

	route_update(state->routes, node, 1);
	np_message_free(args->msg);
	free (args);

	// send piggy message to the updated node
	np_msgproperty_t* piggy_prop = np_message_get_handler(state->messages, TRANSFORM, NP_MSG_PIGGY_REQUEST);
	job_submit_msg_event(state->jobq, piggy_prop, node->key, NULL);
}

void hnd_msg_in_interest(np_state_t* state, np_jobargs_t* args) {

	if (!state->joined_network) {
		np_message_free(args->msg);
		free (args);
		return;
	}

	log_msg(LOG_TRACE, "now handling message interest");

	// np_node_t *replyTo = np_node_decode_from_str(state->nodes, pn_message_get_reply_to(args->msg));
	np_msginterest_t* interest = np_decode_msg_interest(state->messages, args->msg->body);

	// always: store the interest in messages in memory and update if new data arrives
	// this also returns whether messages are already available or not
	np_msginterest_t* available = np_message_interest_update(state->messages, interest);

	// check if we are (one of the) sending node(s) of this kind of message
	if (np_message_check_handler(state->messages, OUTBOUND, interest->msg_subject) == 1) {
		// match expected and real seq_num and send out real message
		// get message from cache
		char s[255];
		snprintf (s, 255, "%s:%lu", interest->msg_subject, available->msg_seqnum);
		available = np_message_available_match(state->messages, s);

		if (available) {
			// if message is found in cache, send it !
			np_message_t* msg = np_message_create(state->messages, interest->key, state->neuropil->me->key, interest->msg_subject, available->payload);
			jrb_insert_str(msg->header, "seqnum", new_jval_ul(available->msg_seqnum));

			np_msgproperty_t* prop = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
			job_submit_msg_event(state->jobq, prop, interest->key, msg);
			log_msg(LOG_DEBUG, "send message to interested target node");

		} else {
			log_msg(LOG_WARN, "message with seq %lu not found, algorithm error !", interest->msg_seqnum);
		}
		// free (s);

	} else {
		// else match the data in memory
		// if there is an existing availability of messages,
		if (available) {
			// 1) send out the availability of data to the sender node to look up seqnum (if seq_num doesn't match)
			np_jrb_t* available_data = make_jrb();
			np_message_encode_interest(available_data, available);

			np_message_t* msg = np_message_create(state->messages, interest->key, state->neuropil->me->key, NP_MSG_AVAILABLE, available_data);
			np_msgproperty_t* msg_prop = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
			job_submit_msg_event(state->jobq, msg_prop, interest->key, msg);
		}

		// TODO send out the non availability of data to the sender node i.e. threshold doesn't match ???
		// 2) then send out the interest to the sender of messages
		// TODO: really needed ? it will get the update when sending his own interest
		// TODO: !!! behaviour is depending on mep !!!
		// send out the availability to the target of messages
	}
}

void hnd_msg_in_available(np_state_t* state, np_jobargs_t* args) {

	if (!state->joined_network) {
		np_message_free(args->msg);
		free (args);
		return;
	}

	log_msg(LOG_TRACE, "now handling message availability");
	// np_messageglobal_t* mg = state->messages;

	// np_node_t *replyTo = np_node_decode_from_str(state->nodes, pn_message_get_reply_to(args->msg));
	np_msginterest_t* available = np_decode_msg_interest(state->messages, args->msg->body);

	// always: just store the available messages in memory and update if new data arrives
	np_msginterest_t* interest = np_message_available_update(state->messages, available);

	if (np_message_check_handler(state->messages, INBOUND, available->msg_subject)) {
		// check if we are (one of the) receiving node(s) of this kind of message
		// match expected and real seq_num, update interest, eventually pull messages
		// TODO: do this per mep (for simple oneway nothing special required)

	} else {
		// else match the data in memory
		if (interest) {
			// 1) send out the existing interest of data to the source node(s) of messages (if seq_num matches)
			np_jrb_t* interest_data = make_jrb();
			np_message_encode_interest(interest_data, interest);

			np_message_t* msg = np_message_create(state->messages, available->key, state->neuropil->me->key, NP_MSG_INTEREST, interest_data);
			np_msgproperty_t* msg_prop = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
			job_submit_msg_event(state->jobq, msg_prop, interest->key, msg);
		}
		// send out the availability to the target of messages
		// TODO: really needed ?
	}
}

void hnd_msg_in_handshake(np_state_t* state, np_jobargs_t* args) {

	// initial handshake message contains public encryption parameter
	log_msg(LOG_DEBUG, "decoding of handshake message ...");

	np_key_t* alias_key = (np_key_t*) malloc (sizeof(np_key_t));
	str_to_key(alias_key, jrb_find_str(args->msg->footer, "alias_key")->val.value.s);

	np_jrb_t* signature = jrb_find_str(args->msg->body, "signature");
	np_jrb_t* payload = jrb_find_str(args->msg->body, "payload");

	cmp_ctx_t cmp;
	int cmp_err;
	unsigned int map_size;
	np_jrb_t* hs_payload = make_jrb();

	cmp_init(&cmp, payload->val.value.bin, buffer_reader, buffer_writer);
	cmp_err = cmp_read_map(&cmp, &map_size);
	deserialize_jrb_node_t(hs_payload, &cmp, map_size/2);

	char* node_hn = jrb_find_str(hs_payload, "dns_name")->val.value.s;
	unsigned int node_port = jrb_find_str(hs_payload, "port")->val.value.ui;
	np_jrb_t* sign_key = jrb_find_str(hs_payload, "signature_key");
	np_jrb_t* pub_key = jrb_find_str(hs_payload, "public_key");
	double issued_at = jrb_find_str(hs_payload, "issued_at")->val.value.d;
	double expiration = jrb_find_str(hs_payload, "expiration")->val.value.d;

	if (0 != crypto_sign_verify_detached( (const unsigned char*) signature->val.value.bin,
			                              (const unsigned char*) payload->val.value.bin,
										  payload->val.size,
										  (const unsigned char*) sign_key->val.value.bin) )
	{
		log_msg(LOG_ERROR, "incorrect signature in handshake message");
		job_submit_event(state->jobq, np_network_read);

		jrb_free_tree(hs_payload);
		np_message_free(args->msg);
		// free(pk);
		// free(payload);
		// free(signature);
		// free(hn);
		return;
	}
	log_msg(LOG_DEBUG, "decoding of handshake message from %s:%d (i:%f/e:%f) complete",
			node_hn, node_port, issued_at, expiration);

	// get our own identity from the cache
	np_aaatoken_t* my_id_token = np_get_authentication_token(state->aaa_cache, state->neuropil->me->key);
	// convert to curve key
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	// unsigned char curve25519_pk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, my_id_token->private_key);
	// crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, my_id_token->public_key);

	unsigned char shared_secret[crypto_scalarmult_BYTES];
	crypto_scalarmult(shared_secret, curve25519_sk, pub_key->val.value.bin);

	// store the handshake data in the node cache, use hostname/port for key generation
	// key could be changed later, but we need a way to lookup the handshake data later
	np_key_t* hs_key = key_create_from_hostport(node_hn, node_port);
	np_node_t* hs_node = np_node_lookup(state->nodes, hs_key, 0);
	np_node_update(hs_node, node_hn, node_port);

	np_aaatoken_t* hs_token = np_get_authentication_token(state->aaa_cache, hs_key);
	if (hs_token && hs_token->valid)
	{
		log_msg(LOG_WARN, "found valid authentication token for node %s, overwriting ...", key_get_as_string(hs_key));
		// jrb_free_tree(hs_payload);
		// np_message_free(args->msg);
		// return;
	}
	// create a aaa token and store it as authentication data
	np_aaatoken_t* node_auth = np_aaatoken_create(state->aaa_cache);
	node_auth->token_id = hs_key;
	node_auth->expiration = expiration;
	node_auth->issued_at = issued_at;
	strncpy((char*) node_auth->public_key, pub_key->val.value.bin, pub_key->val.size);
	strncpy((char*) node_auth->session_key, (char*) shared_secret, crypto_scalarmult_BYTES);

	// create the shared key
	// crypto_scalarmult(
	// 		(unsigned char*) node_auth->session_key,
	// 		curve25519_sk,
	// 		(unsigned char*) pub_key->val.value.bin);
	// register for later use
	node_auth->valid = 1;
	np_register_authentication_token(state->aaa_cache, node_auth, hs_key);
	np_register_authentication_token(state->aaa_cache, node_auth, alias_key);

	free (hs_token);

	// send out our own handshake data
	np_msgproperty_t* msg_prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_HANDSHAKE);
	job_submit_msg_event(state->jobq, msg_prop, hs_node->key, NULL);
	// submit network read event
	job_submit_event(state->jobq, np_network_read);

	jrb_free_tree(hs_payload);
	np_message_free(args->msg);
	log_msg(LOG_DEBUG, "finished to decode handshake message");
}

