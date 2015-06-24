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

#include "aaatoken.h"
#include "dtime.h"
#include "log.h"
#include "include.h"
#include "job_queue.h"
#include "jrb.h"
#include "message.h"
#include "network.h"
#include "node.h"
#include "np_axon.h"
#include "np_container.h"
#include "np_dendrit.h"
#include "np_glia.h"
#include "np_memory.h"
#include "np_threads.h"
#include "route.h"


int np_default_joinfunc (np_state_t* state, np_node_t* node ) {
	log_msg(LOG_WARN, "using default handler for joining node %s", key_get_as_string(node->key) );
	log_msg(LOG_WARN, "do you really want the default join handler (allow all) ???");
	return TRUE;
}
int np_default_authorizefunc (np_state_t* state, np_aaatoken_t* token ) {
	log_msg(LOG_WARN, "using default handler to authorize %s", key_get_as_string(token->token_id) );
	log_msg(LOG_WARN, "do you really want the default authorize handler (allow all) ???");
	return TRUE;
}
int np_default_authenticatefunc (np_state_t* state, np_aaatoken_t* token ) {
	log_msg(LOG_WARN, "using default handler to authenticate %s", key_get_as_string(token->token_id) );
	log_msg(LOG_WARN, "do you really want the default authenticate handler (trust all) ???");
	return TRUE;
}
int np_default_accountingfunc (np_state_t* state, np_aaatoken_t* token ) {
	log_msg(LOG_WARN, "using default handler to account for %s", key_get_as_string(token->token_id) );
	log_msg(LOG_WARN, "do you really want the default accounting handler (account nothing) ???");
	return TRUE;
}

void np_setjoinfunc(const np_state_t* state, np_join_func_t joinFunc) {
	log_msg(LOG_INFO, "setting user defined join handler, that's good ...");
	state->neuropil->join_func = joinFunc;
}
void np_setauthorizing_cb(const np_state_t* state, np_aaa_func_t aaaFunc) {
	log_msg(LOG_INFO, "setting user defined authorization handler, that's good ...");
	state->neuropil->authorize_func = aaaFunc;
}
void np_setauthenticate_cb(const np_state_t* state, np_aaa_func_t aaaFunc) {
	log_msg(LOG_INFO, "setting user defined authentication handler, that's good ...");
	state->neuropil->authenticate_func = aaaFunc;
}
void np_setaccounting_cb(const np_state_t* state, np_aaa_func_t aaaFunc) {
	log_msg(LOG_INFO, "setting user defined accounting handler, that's good ...");
	state->neuropil->accounting_func = aaaFunc;
}

void np_waitforjoin(const np_state_t* state) {
	while (!state->joined_network) {
		dsleep(1.0);
	}
}


void np_add_listener (const np_state_t* state, np_callback_t msg_handler, char* subject, int ack, int retry, int threshold)
{
	// check whether an handler already exists
	np_bool handler_exists = np_message_check_handler(state->messages, INBOUND, subject);
	if (handler_exists == FALSE) {
		np_message_create_property(state->messages, subject, INBOUND, ONE_WAY, ack, 1, retry, msg_handler);
	}

	// create message interest
	np_msginterest_t* interested = np_message_create_interest(state, subject, ONE_WAY, 0, threshold);
	if (!ack) interested->send_ack = ack;
	// update network structure
	np_send_msg_interest(state, interested);
	// update own internal structure
	np_message_interest_update(state->messages, interested);
}

void np_send (np_state_t* state, char* subject, char *data, unsigned long seqnum)
{
	np_bool handler_exists = np_message_check_handler(state->messages, OUTBOUND, subject);
	if (handler_exists == FALSE) {
		np_message_create_property(state->messages, subject, OUTBOUND, ONE_WAY, 1, 5, 5, hnd_msg_out_send);
	}

	// update general availability structures (local and in the net)
	np_msginterest_t* available = np_message_create_interest(state, subject, ONE_WAY, seqnum, 1);
	np_send_msg_availability(state, available);

	np_msginterest_t* interested = np_message_available_update(state->messages, available);

	// lookup old messages and delete them from the cache / based on threshold size
	// char s[255];
	// snprintf (s, 255, "%s:%lu", subject, seqnum-1);
	// available = np_message_available_match(state->messages, s);
	// if (available) {
	// 	log_msg(LOG_DEBUG, "deleting old messages from cache !");
	// pn_data_free (available->payload);
	// 	jrb_free_tree(available->payload);
	// 	free (available->msg_subject);
	// 	free (available);
	// }
	// put new message to the cache
	// snprintf (s, 255, "%s:%lu", subject, seqnum);
	// available = np_message_create_interest(state, s, ONE_WAY, seqnum, 1);
	// available->payload = payload;
	// np_message_available_update(state->messages, available);
	np_message_t* msg;
	np_obj_t* o_msg;

	np_new(np_message_t, o_msg);
	np_bind(np_message_t, o_msg, msg);

	jrb_insert_str(msg->header, NP_MSG_HEADER_SUBJECT, new_jval_s((char*) subject));
	jrb_insert_str(msg->header, "_np.msg.seq", new_jval_ul(seqnum));
	jrb_insert_str(msg->body, "text", new_jval_s(data));

	if (interested && interested->msg_threshold > 0) {

		jrb_insert_str(msg->header, NP_MSG_HEADER_TO,  new_jval_s((char*) key_get_as_string(interested->key)));
		// if a different node is already interested, send message directly
		np_msgproperty_t* prop = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);
		job_submit_msg_event(state->jobq, prop, interested->key, o_msg);
		log_msg(LOG_DEBUG, "interest in message found, sending it directly");

		// decrease threshold counter
		pthread_mutex_lock(&state->messages->interest_lock);
		interested->msg_threshold--;
		pthread_mutex_unlock(&state->messages->interest_lock);

	} else {
		LOCK_CACHE(available) {
			sll_append(np_obj_t, available->msg_cache, o_msg);
			np_ref(np_message_t, o_msg);
		}
	}
	np_unbind(np_message_t, o_msg, msg);
}

int np_receive (np_state_t* state, char* subject, char **data, unsigned long seqnum, int ack)
{
	int received = 0;
	// check whether an inbound message handler is already registered
	np_bool handler_exists = np_message_check_handler(state->messages, INBOUND, subject);
	if (handler_exists == FALSE) {
		np_message_create_property(state->messages, subject, INBOUND, ONE_WAY, 1, 1, 5, np_signal);
	}

	// create our interest for a message and check for available messages (local and in the net)
	np_msginterest_t* interested = np_message_create_interest(state, subject, ONE_WAY, seqnum, 1);
	if (!ack) interested->send_ack = 0;
	np_send_msg_interest(state, interested);

	// check if something is already available
	np_msginterest_t* available = np_message_interest_update(state->messages, interested);
	log_msg(LOG_DEBUG, "msg source is now %p", available);

	// if message source is available, try to receive my requested one from the message cache
	if (available) {
		// unsigned int cache_size = sll_size(interested->msg_cache);
		// log_msg(LOG_DEBUG, "cache size of interest %p: %d", interested, cache_size);
		np_obj_t* o_msg = NULL;

		LOCK_CACHE(available) {
			unsigned int cache_size = sll_size(available->msg_cache);
			log_msg(LOG_DEBUG, "cache size of interest %p: %d", available, cache_size);
			if (cache_size == 0) {
				log_msg(LOG_DEBUG, "waiting for signal via interest %p", available);
				// nothing there yet, wait for notification
				// TODO: use pthread_cond_timedwait ?
				pthread_cond_wait(&available->msg_received, &available->lock);
				// TODO: distinguish between return states of condition wait (timeout or wakeup)
			}
			log_msg(LOG_DEBUG, "getting message from interest %p", available);
			o_msg = sll_head(np_obj_t, available->msg_cache);
		}
		// extract message payload
		if (o_msg) {
			np_message_t* payload;
			np_bind(np_message_t, o_msg, payload);
			received = jrb_find_str(payload->header, "_np.msg.seq")->val.value.ul;

			np_jrb_t* reply_data = jrb_find_str(payload->body, "text");
			*data = strndup(reply_data->val.value.s, strlen(reply_data->val.value.s));

			np_unbind(np_message_t, o_msg, payload);
			np_unref(np_message_t, o_msg);
			np_free(np_message_t, o_msg);
			// TODO: send message ack

			// increase threshold counter
			pthread_mutex_lock(&state->messages->interest_lock);
			interested->msg_threshold++;
			pthread_mutex_unlock(&state->messages->interest_lock);

			log_msg(LOG_INFO, "someone sending us messages %s !!!", *data);
		} else {
			log_msg(LOG_WARN, "something is terribly wrong, message cache returned empty element !!!");
		}
	} else {
		log_msg(LOG_INFO, "no sender of messages known: SUB:%s SEQ:%lu known !", subject, seqnum);
	}
	return received;
}


void np_send_ack(np_state_t* state, np_jobargs_t* args) {

	// log_msg(LOG_INFO, "np_send_ack START");
	int ack;
	unsigned long seq;

	np_message_t* in_msg;

	np_obj_t* o_ack_node;
	np_node_t* ack_node;

	np_bind(np_message_t, args->msg, in_msg);

	if (NULL != jrb_find_str(in_msg->header, "_np.ack_to")) {
		// extract data from incoming message
		seq = jrb_find_str(in_msg->instructions, "_np.seq")->val.value.ul;
		ack = jrb_find_str(in_msg->instructions, "_np.ack")->val.value.i;

		// create new ack message & handlers
		// np_node_t* ack_node = np_node_decode_from_str(state->nodes, jrb_find_str(in_msg->header, NP_MSG_HEADER_REPLY_TO)->val.value.s);
		np_key_t* tmp_key;
		np_new_obj(np_key_t, tmp_key);
		str_to_key(tmp_key, jrb_find_str(in_msg->header, "_np.ack_to")->val.value.s);
		np_unbind(np_message_t, args->msg, in_msg);

		LOCK_CACHE(state->nodes) {
			o_ack_node = np_node_lookup(state->nodes, tmp_key, 0);
			np_bind(np_node_t, o_ack_node, ack_node);
		}

		np_message_t* ack_msg;
		np_obj_t* o_ack_msg;

		np_msgproperty_t* prop = np_message_get_handler(state->messages, TRANSFORM, ROUTE_LOOKUP);

		np_new(np_message_t, o_ack_msg);
		np_bind(np_message_t, o_ack_msg, ack_msg);

		np_message_create(ack_msg, ack_node->key, state->neuropil->my_key, NP_MSG_ACK, NULL);
		jrb_insert_str(ack_msg->instructions, "_np.ack", new_jval_i(prop->ack_mode));
		jrb_insert_str(ack_msg->instructions, "_np.seq", new_jval_ul(seq));
		// send the ack out
		job_submit_msg_event(state->jobq, prop, ack_node->key, o_ack_msg);
		np_unbind(np_node_t, o_ack_node, ack_node);
		np_unbind(np_message_t, o_ack_msg, ack_msg);
		np_free_obj(np_key_t, tmp_key);
	}

	np_free(np_message_t, args->msg);
}


/**
 ** np_ping:
 ** sends a PING message to another node. The message is acknowledged in network layer.
 **/
void np_ping (np_state_t* state, np_key_t* key)
{
    np_obj_t* o_msg;
    np_message_t* out_msg;

    // np_obj_t* target = np_node_lookup(state->nodes, key, 0);
    np_msgproperty_t* prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_PING_REQUEST);

    np_new(np_message_t, o_msg);
    np_bind(np_message_t, o_msg, out_msg);

    np_message_create (out_msg, key, state->neuropil->my_key, NP_MSG_PING_REQUEST, NULL);
    log_msg(LOG_DEBUG, "ping request to: %s", key_get_as_string(key));
	job_submit_msg_event(state->jobq, prop, key, o_msg);

	np_unbind(np_message_t, o_msg, out_msg);
}

/**
 ** np_init:
 ** initializes neuropil on specified port and returns the const np_state_t* which
 ** contains global state of different neuropil modules.
 **/
np_state_t* np_init(int port)
{
    char name[256];
    struct hostent *he;

    np_mem_init();
    // np_printpool;

    sodium_init();
    // initialize key min max ranges
    key_init();

    np_state_t *state = (np_state_t *) malloc (sizeof (np_state_t));
    if (state == NULL)
	{
    	log_msg(LOG_ERROR, "neuropil_init: state module not created: %s", strerror (errno));
	    exit(1);
	}
    state->joined_network = 0;

    state->neuropil = (np_global_t *) malloc (sizeof (np_global_t));
    if (state->neuropil == NULL)
	{
    	log_msg(LOG_ERROR, "neuropil_init: global structure not created: %s", strerror (errno));
	    exit(1);
	}

    //
    // TODO: read my own identity from file, if password is given
    //
    state->aaa_cache = np_init_aaa_cache();
    if (state->aaa_cache == NULL)
    {
    	log_msg(LOG_ERROR, "neuropil_init: global structure not created: %s", strerror (errno));
    	exit(1);
    }

    // create a new token for encryption each time neuropil starts
    np_obj_t* o_auth_token;
    np_aaatoken_t* auth_token;
    np_new(np_aaatoken_t, o_auth_token);
    np_bind(np_aaatoken_t, o_auth_token, auth_token);
    // crypto_box_keypair(auth_token->public_key, auth_token->private_key); // curve25519xsalsa20poly1305
    crypto_sign_keypair(auth_token->public_key, auth_token->private_key); // ed25519
    // crypto_scalarmult_base(); // curve25519
    np_unbind(np_aaatoken_t, o_auth_token, auth_token);

    // set a default join function
    state->neuropil->join_func = np_default_joinfunc;

    // set default aaa functions
    state->neuropil->authorize_func = np_default_authorizefunc;
    state->neuropil->authenticate_func = np_default_authenticatefunc;
    state->neuropil->accounting_func = np_default_accountingfunc;

    /* more message types can be defined here */
    pthread_mutex_init (&state->neuropil->lock, NULL);

    // initialize node management structure
    state->nodes = np_node_cache_create (64);
    if (state->nodes == NULL)
	{
    	log_msg(LOG_ERROR, "neuropil_init: node cache not created: %s", strerror (errno));
	    exit(1);
	}

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
    // strcpy (name, he->h_name);

    // log_msg(LOG_DEBUG, "%s:%d", name, port);
    np_key_t* my_key = key_create_from_hostport(name, port);
    np_ref_obj(np_key_t, my_key);

    np_node_t* me;
    state->neuropil->me = np_node_lookup(state->nodes, my_key, 1);
	np_bind(np_node_t, state->neuropil->me, me);
	np_node_update(me, name, port);

    np_bind(np_aaatoken_t, o_auth_token, auth_token);
	strncpy(auth_token->issuer, (char*) key_get_as_string(my_key), 255);
	// TODO: aaa subject should be user set-able, could also be another name
	snprintf(auth_token->subject, 255, "%s:%d", name, port);
    auth_token->valid = 1;
	np_ref(np_aaatoken_t, o_auth_token);
    np_unbind(np_aaatoken_t, o_auth_token, auth_token);

    LOCK_CACHE(state->aaa_cache) {
		np_register_authentication_token(state->aaa_cache, o_auth_token, my_key);
	}

    // initialize routing table
    state->routes = route_init (my_key);
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
    state->messages = message_init (port);
    if (state->messages == NULL)
	{
    	log_msg(LOG_ERROR, "neuropil_init: message_init failed: %s", strerror (errno));
	    exit(1);
	}

    // initialize real network layer last
    state->network = network_init (port);
    if (state->network != NULL) {
    	// initialize network reading
    	job_submit_event(state->jobq, np_network_read);
        // initialize retransmission of packets
    	job_submit_event(state->jobq, np_retransmit_messages);
		// start leafset checking jobs
		job_submit_event(state->jobq, np_check_leafset);
		job_submit_event(state->jobq, np_write_log);

	} else {
		return NULL;
	}

    // glob->join = sema_create (0);
    state->neuropil->my_key = me->key;
	log_msg(LOG_INFO, "neuropil successfully initialized: %s", key_get_as_string(my_key));

	np_unbind(np_node_t, state->neuropil->me, me);

	return state;
}

void np_start_job_queue(np_state_t* state, int pool_size) {

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
    int i = 0;
    for (i = 0; i < pool_size; i++)
    {
        pthread_create (&state->thread_ids[i], &state->attr, job_exec, (void *) state);
    	log_msg(LOG_DEBUG, "neuropil thread started: %p", state->thread_ids[i]);
   	}
}

