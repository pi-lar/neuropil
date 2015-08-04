/**
 **
 ** neuropil.c
 **
 ** Stephan Schwichtenberg
 ** description:
 **/

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sodium.h"

#include "neuropil.h"

#include "dtime.h"
#include "log.h"
#include "include.h"
#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_container.h"
#include "np_dendrit.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_jtree.h"
#include "np_key.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_route.h"


SPLAY_GENERATE(spt_key, np_key_s, link, key_comp);
RB_GENERATE(rbt_msgproperty, np_msgproperty_s, link, property_comp);


//np_bool np_default_joinfunc (np_state_t* state, np_node_t* node ) {
//	log_msg(LOG_WARN, "using default handler for joining node %s", key_get_as_string(node->key) );
//	log_msg(LOG_WARN, "do you really want the default join handler (allow all) ???");
//	return TRUE;
//}
np_bool np_default_authorizefunc (np_state_t* state, np_aaatoken_t* token ) {
	log_msg(LOG_WARN, "using default handler to authorize %s", token->subject );
	log_msg(LOG_WARN, "do you really want the default authorize handler (allow all) ???");
	return TRUE;
}
np_bool np_default_authenticatefunc (np_state_t* state, np_aaatoken_t* token ) {
	log_msg(LOG_WARN, "using default handler to authenticate %s", token->subject);
	log_msg(LOG_WARN, "do you really want the default authenticate handler (trust all) ???");
	return TRUE;
}
np_bool np_default_accountingfunc (np_state_t* state, np_aaatoken_t* token ) {
	log_msg(LOG_WARN, "using default handler to account for %s", token->subject );
	log_msg(LOG_WARN, "do you really want the default accounting handler (account nothing) ???");
	return TRUE;
}

//void np_setjoinfunc(const np_state_t* state, np_join_func_t joinFunc) {
//	log_msg(LOG_INFO, "setting user defined join handler, that's good ...");
//	state->join_func = joinFunc;
//}

void np_setauthorizing_cb(np_state_t* state, np_aaa_func_t aaaFunc) {
	log_msg(LOG_INFO, "setting user defined authorization handler, that's good ...");
	state->authorize_func = aaaFunc;
}

void np_setauthenticate_cb(np_state_t* state, np_aaa_func_t aaaFunc) {
	log_msg(LOG_INFO, "setting user defined authentication handler, that's good ...");
	state->authenticate_func = aaaFunc;
}

void np_setaccounting_cb(np_state_t* state, np_aaa_func_t aaaFunc) {
	log_msg(LOG_INFO, "setting user defined accounting handler, that's good ...");
	state->accounting_func = aaaFunc;
}

void np_waitforjoin(const np_state_t* state) {
	while (!state->my_key->node->joined_network) {
		dsleep(0.1);
	}
}

void np_set_listener (np_state_t* state, np_callback_t msg_handler, char* subject)
{
	// check whether an handler already exists
	np_msgproperty_t* msg_prop = np_message_get_handler(state, INBOUND, subject);

	if (NULL == msg_prop) {
		// create a default set of properties for listening to oneway messages
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->clb = msg_handler;

		np_message_register_handler(state, msg_prop);
	}
	// update informations somewhere in the network
	np_send_msg_interest(state, subject);
}

void np_set_mx_property(np_state_t* state, char* subject, const char* key, np_jval_t value)
{
	np_key_t* subject_key;
	np_key_t* search_key = key_create_from_hostport(subject, 0);
	LOCK_CACHE(state) {
		if (NULL == (subject_key = SPLAY_FIND(spt_key, &state->key_cache, search_key)) ) {
			SPLAY_INSERT(spt_key, &state->key_cache, search_key);
			subject_key = search_key;
			np_ref_obj(np_key_t, subject_key);
	    } else {
	    	np_free_obj(np_key_t, search_key);
	    }
	}
}

void np_rem_mx_property(np_state_t* state, char* subject, const char* key)
{
	np_key_t* subject_key;
	np_key_t* search_key = key_create_from_hostport(subject, 0);
	LOCK_CACHE(state) {
		if (NULL == (subject_key = SPLAY_FIND(spt_key, &state->key_cache, search_key)) ) {
			SPLAY_INSERT(spt_key, &state->key_cache, search_key);
			subject_key = search_key;
			np_ref_obj(np_key_t, subject_key);
	    } else {
	    	np_free_obj(np_key_t, search_key);
	    }
	}

}

void np_send (np_state_t* state, char* subject, char *data, uint32_t seqnum)
{
	np_msgproperty_t* msg_prop = np_message_get_handler(state, OUTBOUND, subject);
	if (NULL == msg_prop) {
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->mep_type = ONE_WAY;
		msg_prop->msg_mode = OUTBOUND;
		msg_prop->clb = hnd_msg_out_send;

		np_message_register_handler(state, msg_prop);
	}

	np_message_t* msg;
	np_new_obj(np_message_t, msg);

	jrb_insert_str(msg->header, NP_MSG_HEADER_SUBJECT, new_jval_s((char*) subject));
	jrb_insert_str(msg->header, NP_MSG_HEADER_FROM, new_jval_s((char*) key_get_as_string(state->my_key)));
	jrb_insert_str(msg->properties, NP_MSG_INST_SEQ, new_jval_ul(seqnum));
	jrb_insert_str(msg->body,   NP_MSG_BODY_TEXT, new_jval_s(data));

	np_sll_t(np_aaatoken_t, interested_list) = np_get_receiver_token(state, subject);
	np_aaatoken_t* tmp_token = NULL;

	msg_prop->msg_threshold++;
	np_send_msg_availability(state, subject);

	if (NULL != (tmp_token = sll_head(np_aaatoken_t, interested_list)))
	{
		//
		// TODO: encrypt message
		//
		np_key_t* receiver_key;
		np_new_obj(np_key_t, receiver_key);
		str_to_key(receiver_key, (const unsigned char*) tmp_token->issuer);

		jrb_insert_str(msg->header, NP_MSG_HEADER_TO, new_jval_s((char*) tmp_token->issuer));
		np_msgproperty_t* out_prop = np_message_get_handler(state, TRANSFORM, ROUTE_LOOKUP);
		job_submit_msg_event(state->jobq, out_prop, receiver_key, msg);

		// try to free it, ref count my deny it
		np_unref_obj(np_message_t, msg);
		np_free_obj(np_aaatoken_t, tmp_token);

		// decrease threshold counters
		jrb_find_str(tmp_token->extensions, "msg_threshold")->val.value.ui--;
		msg_prop->msg_threshold--;

	} else {

		LOCK_CACHE(msg_prop) {

			// cache already full ?
			if (msg_prop->max_threshold <= msg_prop->msg_threshold) {
				log_msg(LOG_DEBUG, "msg cache full, checking overflow policy ...");

				if ( (msg_prop->cache_policy & OVERFLOW_PURGE) > 0)
				{
					log_msg(LOG_DEBUG, "OVERFLOW_PURGE: discarding first message");
					np_message_t* old_msg;

					if ((msg_prop->cache_policy & FIFO) > 0)
						old_msg = sll_head(np_message_t, msg_prop->msg_cache);
					if ((msg_prop->cache_policy & FILO) > 0)
						old_msg = sll_tail(np_message_t, msg_prop->msg_cache);

					msg_prop->msg_threshold--;
					np_unref_obj(np_message_t, old_msg);
					np_free_obj(np_message_t, old_msg);
				}

				if ( (msg_prop->cache_policy & OVERFLOW_REJECT) > 0)
				{
					log_msg(LOG_DEBUG, "rejecting new message because cache is full");
					np_free_obj(np_message_t, msg);
					continue;
				}
			}

			if ( (msg_prop->cache_policy & FIFO) )
				sll_prepend(np_message_t, msg_prop->msg_cache, msg);
			if ( (msg_prop->cache_policy & FILO) )
				sll_append(np_message_t, msg_prop->msg_cache, msg);

//			log_msg(LOG_DEBUG, "added message to the msgcache (%p / %d) ...",
//					msg_prop->msg_cache, sll_size(msg_prop->msg_cache));
			np_ref_obj(np_message_t, msg);
		}
	}
}

uint32_t np_receive (np_state_t* state, char* subject, char **data)
{
	np_msgproperty_t* msg_prop = np_message_get_handler(state, INBOUND, subject);
	if (NULL == msg_prop) {
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup(subject, 255);
		msg_prop->mep_type = ONE_WAY;
		msg_prop->msg_mode = INBOUND;
		msg_prop->clb = np_signal;
		// register the handler so that message can be received
		np_message_register_handler(state, msg_prop);
	}
	msg_prop->msg_threshold++;

	np_send_msg_interest(state, subject);

	np_sll_t(np_aaatoken_t, sender_token_list) = np_get_sender_token(state, subject);
	np_aaatoken_t* tmp_token = NULL;

	if (NULL == (tmp_token = sll_head(np_aaatoken_t, sender_token_list))) {

		LOCK_CACHE(msg_prop) {
			pthread_cond_wait(&msg_prop->msg_received, &msg_prop->lock);
		}

		sender_token_list = np_get_sender_token(state, subject);
		// tmp_token = sll_head(np_aaatoken_t, sender_token_list);
	}

	uint32_t received = 0;
	uint16_t counter = sll_size(msg_prop->msg_cache);
	np_message_t* msg = NULL;

	while ( NULL != (msg = sll_head(np_message_t, msg_prop->msg_cache)) &&
			counter > 0)
	{
		log_msg(LOG_DEBUG, "getting message from cache %p", msg_prop);

		// np_key_t* from_key = key_create_from_hash(
		// 		(unsigned char*) jrb_find_str(msg->header, NP_MSG_HEADER_FROM)->val.value.s);
		// np_key_t* token_key = key_create_from_hash((unsigned char*) tmp_token->issuer);

		// if (key_comp(from_key, token_key)) {

		//
		// TODO: decrypt message payload
		//
		received = jrb_find_str(msg->properties, NP_MSG_INST_SEQ)->val.value.ul;
		np_jtree_elem_t* reply_data = jrb_find_str(msg->body, NP_MSG_BODY_TEXT);
		*data = strndup(reply_data->val.value.s, strlen(reply_data->val.value.s));

		np_unref_obj(np_message_t, msg);
		np_free_obj(np_message_t, msg);
		log_msg(LOG_INFO, "someone sending us messages %s !!!", *data);
		msg_prop->msg_threshold--;

		// } else {

		// 	sll_append(np_message_t, msg_prop->msg_cache, msg)
		// }
		counter--;
	}

	// create our interest for a message and check for available messages (local and in the net)
	// np_send_msg_interest(state, subject);

	return received;
}


void np_send_ack(np_state_t* state, np_jobargs_t* args) {

	uint8_t ack = ACK_NONE;
	uint32_t seq = 0;

	np_message_t* in_msg = args->msg;

	if (NULL != jrb_find_str(in_msg->header, NP_MSG_INST_ACK_TO)) {
		// extract data from incoming message
		seq = jrb_find_str(in_msg->instructions, NP_MSG_INST_SEQ)->val.value.ul;
		ack = jrb_find_str(in_msg->instructions, NP_MSG_INST_ACK)->val.value.ush;

		// create new ack message & handlers
		// np_node_t* ack_node = np_node_decode_from_str(state->nodes, jrb_find_str(in_msg->header, NP_MSG_HEADER_REPLY_TO)->val.value.s);
		np_key_t* ack_key = key_create_from_hash(
				(unsigned char*) jrb_find_str(in_msg->header, NP_MSG_INST_ACK_TO)->val.value.s);

		np_message_t* ack_msg;
		np_msgproperty_t* prop = np_message_get_handler(state, TRANSFORM, ROUTE_LOOKUP);

		np_new_obj(np_message_t, ack_msg);
		np_message_create(ack_msg, ack_key, state->my_key, NP_MSG_ACK, NULL);
		jrb_insert_str(ack_msg->instructions, NP_MSG_INST_ACK, new_jval_ush(prop->ack_mode));
		jrb_insert_str(ack_msg->instructions, NP_MSG_INST_SEQ, new_jval_ul(seq));
		// send the ack out
		job_submit_msg_event(state->jobq, prop, ack_key, ack_msg);
		np_free_obj(np_key_t, ack_key);
	}

	np_free_obj(np_message_t, args->msg);
}


/**
 ** np_ping:
 ** sends a PING message to another node. The message is acknowledged in network layer.
 **/
void np_ping (np_state_t* state, np_key_t* key)
{
    np_message_t* out_msg;

    np_new_obj(np_message_t, out_msg);
    np_message_create (out_msg, key, state->my_key, NP_MSG_PING_REQUEST, NULL);
    log_msg(LOG_DEBUG, "ping request to: %s", key_get_as_string(key));

    np_msgproperty_t* prop = np_message_get_handler(state, OUTBOUND, NP_MSG_PING_REQUEST);
	job_submit_msg_event(state->jobq, prop, key, out_msg);
}

/**
 ** np_init:
 ** initializes neuropil on specified port and returns the const np_state_t* which
 ** contains global state of different neuropil modules.
 **/
np_state_t* np_init(uint16_t port)
{
    char name[256];
    struct hostent *he;

	np_mem_init();
    // np_printpool;

	// encryption
    sodium_init();

	// initialize key min max ranges
    key_init();

    np_state_t *state = (np_state_t *) malloc (sizeof (np_state_t));
    if (state == NULL)
	{
    	log_msg(LOG_ERROR, "neuropil_init: state module not created: %s", strerror (errno));
	    exit(1);
	}
    SPLAY_INIT(&state->key_cache);

    //
    // TODO: read my own identity from file, if a password is given
    //
    // set default aaa functions
    state->authorize_func = np_default_authorizefunc;
    state->authenticate_func = np_default_authenticatefunc;
    state->accounting_func = np_default_accountingfunc;

    pthread_mutex_init (&state->lock, NULL);

    if (gethostname (name, 256) != 0)
	{
    	log_msg(LOG_ERROR, "neuropil_init: gethostname: %s", strerror (errno));
	    exit(1);
	}
	log_msg(LOG_ERROR, "found hostname %s", &name);

	if ((he = gethostbyname (name)) == NULL)
	{
    	log_msg(LOG_WARN, "neuropil_init: gethostbyname: %s", strerror (errno));
    	// TODO: structure really needed (contains list of all interfaces !)
    	// exit(1);
	}

    // log_msg(LOG_DEBUG, "%s:%hd", name, port);
    state->my_key = key_create_from_hostport(name, port);
    np_ref_obj(np_key_t, state->my_key);

	log_msg(LOG_WARN, "node_key %p", state->my_key);
	SPLAY_INSERT(spt_key, &state->key_cache, state->my_key);

    np_node_t* me;
    np_new_obj(np_node_t, me);

    state->my_key->node = me;
	np_node_update(me, name, port);
	state->my_key->node->network = network_init(port);

    // create a new token for encryption each time neuropil starts
    np_aaatoken_t* auth_token;
    np_new_obj(np_aaatoken_t, auth_token);
    // crypto_box_keypair(auth_token->public_key, auth_token->private_key); // curve25519xsalsa20poly1305
    crypto_sign_keypair(auth_token->public_key, auth_token->private_key);   // ed25519
    // crypto_scalarmult_base(); // curve25519

	strncpy(auth_token->issuer, (char*) key_get_as_string(state->my_key), 255);
	// TODO: aaa subject should be user set-able, could also be another name
	snprintf(auth_token->subject, 255, "%s:%hd", name, port);
    auth_token->valid = 1;

    state->my_key->authentication = auth_token;

    // initialize routing table
    state->routes = route_init (state->my_key);
    if (state->routes == NULL)
	{
    	log_msg(LOG_ERROR, "neuropil_init: route_init failed: %s", strerror (errno));
	    exit(1);
	}

    // initialize job queue
    state->jobq = job_queue_create ();
    if (state->jobq == NULL)
	{
    	log_msg(LOG_ERROR, "neuropil_init: job_queue_create failed: %s", strerror (errno));
	    exit(1);
	}

    // initialize message handling system
    message_init (state);
    if (state->msg_tokens == NULL)
	{
    	log_msg(LOG_ERROR, "neuropil_init: message_init failed: %s", strerror (errno));
	    exit(1);
	}

    // initialize real network layer last
    // initialize network reading
    job_submit_event(state->jobq, np_network_read);
    // initialize retransmission of packets
    job_submit_event(state->jobq, np_retransmit_messages);
    // start leafset checking jobs
    job_submit_event(state->jobq, np_check_leafset);
    job_submit_event(state->jobq, np_write_log);
    job_submit_event(state->jobq, np_retransmit_tokens);

	log_msg(LOG_INFO, "neuropil successfully initialized: %s", key_get_as_string(state->my_key));
	log_fflush();

	return state;
}

void np_start_job_queue(np_state_t* state, uint8_t pool_size) {

	if (pthread_attr_init (&state->attr) != 0)
	{
	    log_msg (LOG_ERROR, "pthread_attr_init: %s", strerror (errno));
	    return;
	}
    if (pthread_attr_setscope (&state->attr, PTHREAD_SCOPE_SYSTEM) != 0)
	{
	    log_msg (LOG_ERROR, "pthread_attr_setscope: %s", strerror (errno));
	    return;
	}
    if (pthread_attr_setdetachstate (&state->attr, PTHREAD_CREATE_DETACHED) != 0)
	{
    	log_msg (LOG_ERROR, "pthread_attr_setdetachstate: %s", strerror (errno));
	    return;
	}

    state->thread_ids = (pthread_t *) malloc (sizeof (pthread_t) * pool_size);

    /* create the thread pool */
    for (uint8_t i = 0; i < pool_size; i++)
    {
        pthread_create (&state->thread_ids[i], &state->attr, job_exec, (void *) state);
    	log_msg(LOG_DEBUG, "neuropil thread started: %p", state->thread_ids[i]);
   	}
}

