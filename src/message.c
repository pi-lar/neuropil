/*
 ** $Id: message.c,v 1.37 2007/04/04 00:04:49 krishnap Exp $
 **
 ** Matthew Allen
 ** description:
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "proton/message.h"

#include "message.h"

#include "neuropil.h"
#include "log.h"
#include "node.h"
#include "network.h"
#include "jval.h"
#include "threads.h"
#include "route.h"
#include "job_queue.h"
#include "np_dendrit.h"
#include "np_axon.h"
#include "np_glia.h"
#include "jrb.h"


// default message type enumeration
enum {
	NEUROPIL_PING_REQUEST = 1,
	NEUROPIL_PING_REPLY,

	NEUROPIL_JOIN = 10,
	NEUROPIL_JOIN_ACK,
	NEUROPIL_JOIN_NACK,

	NEUROPIL_AVOID = 20,
	NEUROPIL_DIVORCE,

	NEUROPIL_UPDATE = 30,
	NEUROPIL_PIGGY,

	NEUROPIL_MSG_INTEREST = 50,
	NEUROPIL_MSG_AVAILABLE,

	NEUROPIL_REST_OPERATIONS = 100,
	NEUROPIL_POST,   /*create*/
	NEUROPIL_GET,    /*read*/
	NEUROPIL_PUT,    /*update*/
	NEUROPIL_DELETE, /*delete*/
	NEUROPIL_QUERY,

	NEUROPIL_INTERN_MAX = 1024,
	NEUROPIL_DATA = 1025,

} message_enumeration;

// callback declaration taking two arguments - first argument always pointer to np_state_t structure
// typedef void (*messagehandler_in_t) (void*, void *);


// #define HEADER_SIZE (sizeof(unsigned long) + sizeof(unsigned long) + KEY_SIZE/BASE_B + 1)

// create amqp message from va_list parameter
// [] = List
// {} = map
// T  = array

#define NR_OF_ELEMS(x)  (sizeof(x) / sizeof(x[0]))

np_msgproperty_t np_internal_messages[] =
	{
		{ ROUTE_LOOKUP, TRANSFORM, DEFAULT_TYPE, 5, 1, 0, "", np_route_lookup }, // default input handling func should be "route_get" ?
		{ NP_MSG_PIGGY_REQUEST, TRANSFORM, DEFAULT_TYPE, 5, 1, 0, "", np_send_rowinfo }, // default input handling func should be "route_get" ?

		{ "", INBOUND, DEFAULT_TYPE, 5, 1, 0, "", hnd_msg_in_received },
		// TODO: add garbage collection output
		{ "", OUTBOUND, DEFAULT_TYPE, 5, 1, 0, "", hnd_msg_out_send },

		{ NP_MSG_HANDSHAKE, INBOUND, ONEWAY, 5, 0, 0, "", hnd_msg_in_handshake },
		{ NP_MSG_HANDSHAKE, OUTBOUND, ONEWAY, 5, 0, 0, "", hnd_msg_out_handshake },

		{ NP_MSG_ACK, INBOUND, ONEWAY, 5, 0, 0, "", NULL }, // incoming ack handled in network layer, not required
		{ NP_MSG_ACK, OUTBOUND, ONEWAY, 5, 0, 0, "", hnd_msg_out_ack },

		{ NP_MSG_PING_REQUEST, INBOUND, ONEWAY, 5, 1, 5, "", hnd_msg_in_ping },
		{ NP_MSG_PING_REPLY, INBOUND, ONEWAY, 5, 1, 5, "", hnd_msg_in_pingreply },
		{ NP_MSG_PING_REQUEST, OUTBOUND, ONEWAY, 5, 1, 5, "", hnd_msg_out_send },
		{ NP_MSG_PING_REPLY, OUTBOUND, ONEWAY, 5, 1, 5, "", hnd_msg_out_send },

		// join request: node unknown yet, therefore send without ack, explicit ack handling via extra messages
		{ NP_MSG_JOIN_REQUEST, INBOUND, ONEWAY, 5, 2, 5, "C", hnd_msg_in_join_req }, // just for controller ?
		{ NP_MSG_JOIN_REQUEST, OUTBOUND, ONEWAY, 5, 2, 5, "C", hnd_msg_out_send },
		{ NP_MSG_JOIN_ACK, INBOUND, ONEWAY, 5, 1, 5, "C", hnd_msg_in_join_ack },
		{ NP_MSG_JOIN_ACK, OUTBOUND, ONEWAY, 5, 1, 5, "C", hnd_msg_out_send },
		{ NP_MSG_JOIN_NACK, INBOUND, ONEWAY, 5, 1, 5, "", hnd_msg_in_join_nack },
		{ NP_MSG_JOIN_NACK, OUTBOUND, ONEWAY, 5, 1, 5, "", hnd_msg_out_send },

		{ NP_MSG_PIGGY_REQUEST, INBOUND, ONEWAY, 5, 1, 5, "C", hnd_msg_in_piggy },
		{ NP_MSG_PIGGY_REQUEST, OUTBOUND, ONEWAY, 5, 1, 5, "C", hnd_msg_out_send },
		{ NP_MSG_UPDATE_REQUEST, INBOUND, ONEWAY, 5, 1, 5, "C", hnd_msg_in_update },
		{ NP_MSG_UPDATE_REQUEST, OUTBOUND, ONEWAY, 5, 1, 5, "C", hnd_msg_out_send },

		{ NP_MSG_INTEREST, INBOUND, ONEWAY, 5, 1, 5, "C", hnd_msg_in_interest },
		{ NP_MSG_AVAILABLE, INBOUND, ONEWAY, 5, 1, 5, "C", hnd_msg_in_available },
		{ NP_MSG_INTEREST, OUTBOUND, ONEWAY, 5, 1, 5, "C", hnd_msg_out_send },
		{ NP_MSG_AVAILABLE, OUTBOUND, ONEWAY, 5, 1, 5, "C", hnd_msg_out_send }
};

/** 
 ** message_create: 
 ** creates the message to the destination #dest# the message format would be like:
 **  [ type ] [ size ] [ key ] [ data ]. It return the created message structure.
 */
pn_message_t* np_message_create(np_messageglobal_t *mg, Key* to, Key* from, const char* subject, pn_data_t* the_data) {

	pn_message_t* new_msg = pn_message();
	pn_message_set_address(new_msg, (char*) key_get_as_string(to));
	pn_message_set_reply_to(new_msg, (char*) key_get_as_string(from));
	pn_message_set_subject(new_msg, subject);

	if (the_data != NULL) {
		pn_data_t* body = pn_message_body(new_msg);
		pn_data_append(body, the_data);
	}
	return (new_msg);
}
/** 
 ** message_free:
 ** free the message and the payload
 */
void np_message_free(pn_message_t * msg) {
	pn_message_free(msg);
}

/**
 ** message_init: chstate, port
 ** Initialize messaging subsystem on port and returns the MessageGlobal * which 
 ** contains global state of message subsystem.
 ** message_init also initiate the network subsystem
 **/
np_messageglobal_t* message_init(int port) {

	int i = 0;
	np_messageglobal_t* mg = (np_messageglobal_t *) malloc(sizeof(np_messageglobal_t));

	mg->in_handlers = make_jrb();
	mg->out_handlers = make_jrb();
	mg->trans_handlers = make_jrb();

	if (pthread_mutex_init(&mg->input_lock, NULL ) != 0) {
		log_msg(LOG_ERROR, "pthread_mutex_init: %s", strerror (errno));
		return (NULL );
	}
	if (pthread_mutex_init(&mg->output_lock, NULL ) != 0) {
		log_msg(LOG_ERROR, "pthread_mutex_init: %s", strerror (errno));
		return (NULL );
	}
	if (pthread_mutex_init(&mg->trans_lock, NULL ) != 0) {
		log_msg(LOG_ERROR, "pthread_mutex_init: %s", strerror (errno));
		return (NULL);
	}
	if (pthread_mutex_init(&mg->interest_lock, NULL ) != 0) {
		log_msg(LOG_ERROR, "pthread_mutex_init: %s", strerror (errno));
		return (NULL);
	}

	/* NEUROPIL_INTERN_MSG_INTEREST HANDLING */
    mg->interest_sources = make_jrb();
    mg->interest_targets = make_jrb();

	/* NEUROPIL_INTERN_MESSAGES */
	for (i = 0; i < NR_OF_ELEMS(np_internal_messages); ++i) {
		if (strlen(np_internal_messages[i].msg_subject) > 0) {
			log_msg(LOG_DEBUG, "register handler (%d): %s", i, np_internal_messages[i].msg_subject);
			np_message_register_handler(mg, &np_internal_messages[i]);
		}
	}

	return mg;
}

np_callback_t np_message_get_callback (np_msgproperty_t *handler)
{
	assert (handler != NULL);
	assert (handler->clb != NULL);

	return handler->clb;
}

/**
 ** registers the handler function #func# with the message type #type#,
 ** it also defines the acknowledgment requirement for this type 
 **/
np_msgproperty_t* np_message_get_handler(np_messageglobal_t *mg, int msg_mode, const char* subject) {

	np_msgproperty_t* retVal = NULL;

	switch (msg_mode) {

	case INBOUND: // incoming message handler are required
		/* add message handler function into the set of all handlers */
		pthread_mutex_lock(&mg->input_lock);
		np_jrb_t* jrb_in_node = jrb_find_str(mg->in_handlers, subject);
		/* don't allow duplicates */
		if (jrb_in_node == NULL ) {
			log_msg(LOG_DEBUG, "no inbound message handler found for %s, now looking up default handler", subject);
			jrb_in_node = jrb_find_str(mg->in_handlers, "");
		}
		retVal = jrb_in_node->val.v;
		pthread_mutex_unlock(&mg->input_lock);
		break;

	case OUTBOUND: // outgoing message handlers are required
		/* add message handler function into the set of all handlers */
		pthread_mutex_lock(&mg->output_lock);
		np_jrb_t* jrb_out_node = jrb_find_str(mg->out_handlers, subject);
		/* don't allow duplicates */
		if (jrb_out_node == NULL ) {
			log_msg(LOG_DEBUG, "no outbound message handler found for %s, now looking up default handler", subject);
			jrb_out_node = jrb_find_str(mg->out_handlers, "");
		}
		retVal = jrb_out_node->val.v;
		pthread_mutex_unlock(&mg->output_lock);
		break;

	case TRANSFORM:
		// outgoing message handlers are required
		/* add message handler function into the set of all handlers */
		pthread_mutex_lock(&mg->trans_lock);
		np_jrb_t* jrb_trans_node = jrb_find_str(mg->trans_handlers, subject);
		/* don't allow duplicates */
		if (jrb_trans_node == NULL ) {
			log_msg(LOG_DEBUG, "no transform message handler found for %s, now looking up default handler", subject);
			jrb_trans_node = jrb_find_str(mg->trans_handlers, "");
		}
		retVal = jrb_trans_node->val.v;
		pthread_mutex_unlock(&mg->trans_lock);
		break;

	default:
		log_msg(LOG_DEBUG, "message mode not specified for %s, using default",
				subject);
	}
	return retVal;
}


bool np_message_check_handler(np_messageglobal_t *mg, int msg_mode, const char* subject) {

	bool retVal = 0;

	switch (msg_mode) {

	case INBOUND: // incoming message handler are required
		/* add message handler function into the set of all handlers */
		pthread_mutex_lock(&mg->input_lock);
		np_jrb_t* jrb_in_node = jrb_find_str(mg->in_handlers, subject);
		/* don't allow duplicates */
		if (jrb_in_node != NULL ) {
			retVal = 1;
		}
		pthread_mutex_unlock(&mg->input_lock);
		break;

	case OUTBOUND: // outgoing message handlers are required
		/* add message handler function into the set of all handlers */
		pthread_mutex_lock(&mg->output_lock);
		np_jrb_t* jrb_out_node = jrb_find_str(mg->out_handlers, subject);
		/* don't allow duplicates */
		if (jrb_out_node != NULL ) {
			retVal = 1;
		}
		pthread_mutex_unlock(&mg->output_lock);
		break;

	case TRANSFORM:
		// outgoing message handlers are required
		/* add message handler function into the set of all handlers */
		pthread_mutex_lock(&mg->trans_lock);
		np_jrb_t* jrb_trans_node = jrb_find_str(mg->trans_handlers, subject);
		/* don't allow duplicates */
		if (jrb_trans_node != NULL ) {
			retVal = 1;
		}
		pthread_mutex_unlock(&mg->trans_lock);
		break;

	default:
		log_msg(LOG_DEBUG, "message mode not specified for %s, default handling would be used", subject);
		break;
	}
	return retVal;
}


void np_message_register_handler(np_messageglobal_t *mg, np_msgproperty_t* msgprops) {

	switch (msgprops->msg_mode) {

	case INBOUND:
		/* add message handler function into the set of all handlers */
		pthread_mutex_lock(&mg->input_lock);

		np_jrb_t* jrb_in_node = jrb_find_str(mg->in_handlers, msgprops->msg_subject);
		/* don't allow duplicates */
		if (jrb_in_node == NULL ) {
			jrb_insert_str(mg->in_handlers, msgprops->msg_subject,
					new_jval_v(msgprops));
			log_msg(LOG_DEBUG, "inbound message handler registered for %s",
					msgprops->msg_subject);
			// jrb_node = jrb_find_str (mg->handlers, "");
		}
		pthread_mutex_unlock(&mg->input_lock);
		break;

	case OUTBOUND:
		/* add message handler function into the set of all handlers */
		pthread_mutex_lock(&mg->output_lock);
		np_jrb_t* jrb_out_node = jrb_find_str(mg->out_handlers, msgprops->msg_subject);
		/* don't allow duplicates */
		if (jrb_out_node == NULL ) {
			jrb_insert_str(mg->out_handlers, msgprops->msg_subject,
					new_jval_v(msgprops));
			log_msg(LOG_DEBUG, "outbound message handler registered for %s",
					msgprops->msg_subject);
			// jrb_node = jrb_find_str (mg->handlers, "");
		}
		pthread_mutex_unlock(&mg->output_lock);
		break;

	case TRANSFORM:
		/* add message handler function into the set of all handlers */
		pthread_mutex_lock(&mg->trans_lock);
		np_jrb_t* jrb_trans_node = jrb_find_str(mg->trans_handlers, msgprops->msg_subject);
		/* don't allow duplicates */
		if (jrb_trans_node == NULL ) {
			jrb_insert_str(mg->trans_handlers, msgprops->msg_subject,
					new_jval_v(msgprops));
			log_msg(LOG_DEBUG, "transform message handler registered for %s",
					msgprops->msg_subject);
		}
		pthread_mutex_unlock(&mg->trans_lock);
		break;

	default:
		log_msg(LOG_ERROR, "message mode not specified for %s, using default",
				msgprops->msg_subject);
	}
}

// np_msgproperty_t*
void np_message_create_property(np_messageglobal_t *mg, const char* subject, int msg_mode, int msg_type, int ack_mode, int priority, int retry, np_callback_t callback) {

	// log_msg(LOG_INFO, "message create property");
	np_msgproperty_t* prop = (np_msgproperty_t*) malloc(sizeof(np_msgproperty_t));

	prop->msg_subject = strndup(subject, 255);
	prop->msg_mode = msg_mode;
	prop->msg_type = msg_type;
	prop->priority = priority;
	prop->ack_mode = ack_mode;
	prop->retry = retry;
	prop->clb = callback;

	np_message_register_handler(mg, prop);
	return;
}

np_msginterest_t* np_message_create_interest(const np_state_t* state, const char* subject, int msg_type, unsigned long seqnum, int threshold) {

	np_msginterest_t* tmp = (np_msginterest_t*) malloc(sizeof(np_msginterest_t));
	tmp->msg_subject = strndup(subject, 255);
	tmp->key = state->neuropil->me->key;
	tmp->msg_type = msg_type;
	tmp->msg_seqnum = seqnum;
	tmp->msg_threshold = threshold;

	tmp->send_ack = 1;

	pthread_mutex_init (&tmp->lock, NULL);
    pthread_cond_init (&tmp->msg_received, &tmp->cond_attr);
    pthread_condattr_setpshared(&tmp->cond_attr, PTHREAD_PROCESS_PRIVATE);

    return tmp;
}

// update internal structure and return a interest if a matching pair has been found
np_msginterest_t* np_message_interest_update(np_messageglobal_t *mg, np_msginterest_t *interest) {

	np_msginterest_t* available = NULL;

	pthread_mutex_lock(&mg->interest_lock);

	// look up sources to see whether a sender already exists
	np_jrb_t* tmp_source = jrb_find_str(mg->interest_sources, interest->msg_subject);
	if (tmp_source != NULL) {
		np_msginterest_t* tmp = tmp_source->val.v;
		if (interest->msg_seqnum == 0) available = tmp;
		if ((tmp->msg_seqnum - tmp->msg_threshold) <= interest->msg_seqnum) available = tmp;
	} else {
		log_msg(LOG_DEBUG, "lookup of message source failed");
	}

	// look up target or create it
	np_jrb_t* tmp_target = jrb_find_str(mg->interest_targets, interest->msg_subject);
	if (tmp_target != NULL) {
		// update
		log_msg(LOG_DEBUG, "lookup of message target successful");
		np_msginterest_t* tmp = tmp_target->val.v;
		tmp->msg_type = interest->msg_type;
		tmp->msg_seqnum = interest->msg_seqnum;
		tmp->msg_threshold = interest->msg_threshold;

	} else {
		// create
		log_msg(LOG_DEBUG, "adding a new message target");
		jrb_insert_str(mg->interest_targets, interest->msg_subject, new_jval_v(interest));
	}
	pthread_mutex_unlock(&mg->interest_lock);

	return available;
}

np_msginterest_t* np_message_available_update(np_messageglobal_t *mg, np_msginterest_t *available) {

	np_msginterest_t* interest = NULL;

	pthread_mutex_lock(&mg->interest_lock);

	// look up targets to see whether a receiver already exists
	np_jrb_t* tmp_source = jrb_find_str(mg->interest_targets, available->msg_subject);
	if (tmp_source != NULL) {
		log_msg(LOG_DEBUG, "lookup of message target successful");
		np_msginterest_t* tmp = tmp_source->val.v;
		if (tmp->msg_seqnum == 0) interest = tmp;
		if ((tmp->msg_seqnum - tmp->msg_threshold) <= available->msg_seqnum) interest = tmp;
	}
	// else {
	// 	log_msg(LOG_DEBUG, "lookup of message target failed");
	// }

	// look up sources or create it
	np_jrb_t* tmp_target = jrb_find_str(mg->interest_sources, available->msg_subject);
	if (tmp_target != NULL) {
		log_msg(LOG_DEBUG, "lookup of message source successful");
		// update
		np_msginterest_t* tmp = tmp_target->val.v;
		tmp->msg_type = available->msg_type;
		tmp->msg_seqnum = available->msg_seqnum;
		tmp->msg_threshold = available->msg_threshold;
	} else {
		log_msg(LOG_DEBUG, "adding a new message source");
		// create
		jrb_insert_str(mg->interest_sources, available->msg_subject, new_jval_v(available));
	}
	pthread_mutex_unlock(&mg->interest_lock);

	return interest;
}

// check whether an interest is existing
np_msginterest_t* np_message_interest_match(np_messageglobal_t *mg, const char *subject) {

	// look up sources to see whether a sender already exists
	pthread_mutex_lock(&mg->interest_lock);
	np_jrb_t* tmp_source = jrb_find_str(mg->interest_targets, subject);
	pthread_mutex_unlock(&mg->interest_lock);

	if (tmp_source)
		return (np_msginterest_t*) tmp_source->val.v;
	else
		return NULL;
}

// check whether an interest is existing
np_msginterest_t* np_message_available_match(np_messageglobal_t *mg, const char *subject) {
	// look up sources to see whether a sender already exists
	pthread_mutex_lock(&mg->interest_lock);
	np_jrb_t* tmp_target = jrb_find_str(mg->interest_sources, subject);
	pthread_mutex_unlock(&mg->interest_lock);

	if (tmp_target)
		return (np_msginterest_t*) tmp_target->val.v;
	else
		return NULL;
}

np_msginterest_t* np_decode_msg_interest(np_messageglobal_t *mg, pn_data_t *amqp_data ) {

	np_msginterest_t* interest = (np_msginterest_t*) malloc(sizeof(np_msginterest_t));
	interest->key = (Key*) malloc(sizeof(Key));

	assert(pn_data_type(amqp_data) == PN_LIST);
	int count = pn_data_get_list(amqp_data);
	assert(count == 5);
	pn_data_enter(amqp_data);

	pn_data_next(amqp_data);
    assert(pn_data_type(amqp_data) == PN_STRING);
	pn_bytes_t bKey = pn_data_get_string(amqp_data);
	char sHostkey[bKey.size];
	strncpy(sHostkey, bKey.start, bKey.size);
	// sHostkey[bKey.size - 1]= '\0';
	str_to_key(interest->key, sHostkey);

	pn_data_next(amqp_data);
    assert(pn_data_type(amqp_data) == PN_STRING);
	pn_bytes_t bSubject = pn_data_get_string(amqp_data);
	interest->msg_subject = (char*) malloc(bSubject.size);
	strncpy(interest->msg_subject, bSubject.start, bSubject.size);
	// interest->msg_subject[bSubject.size-1] = '\0';

	pn_data_next(amqp_data);
    assert(pn_data_type(amqp_data) == PN_INT);
    interest->msg_type = pn_data_get_int(amqp_data);

    pn_data_next(amqp_data);
    assert(pn_data_type(amqp_data) == PN_ULONG);
    interest->msg_seqnum = pn_data_get_ulong(amqp_data);

    pn_data_next(amqp_data);
    assert(pn_data_type(amqp_data) == PN_INT);
    interest->msg_threshold = pn_data_get_int(amqp_data);

	pn_data_exit(amqp_data);

	if (pn_data_errno(amqp_data) < 0) {
		log_msg(LOG_ERROR, "error decoding msg_interest from amqp data structure");
	}

	return interest;
}

void np_message_encode_interest(pn_data_t *amqp_data, np_msginterest_t *interest) {

	char* keystring = (char*) key_get_as_string (interest->key);

	pn_data_put_list(amqp_data);
	pn_data_enter(amqp_data);
	pn_data_put_string(amqp_data, pn_bytes(strlen(keystring), keystring));
	pn_data_put_string(amqp_data, pn_bytes(strlen(interest->msg_subject), interest->msg_subject));
	pn_data_put_int(amqp_data, interest->msg_type);
	pn_data_put_ulong(amqp_data, interest->msg_seqnum);
	pn_data_put_int(amqp_data, interest->msg_threshold);
	pn_data_exit(amqp_data);

	if (pn_data_errno(amqp_data) < 0) {
		log_msg(LOG_ERROR, "error encoding msg_interest as amqp data structure");
	}
}
