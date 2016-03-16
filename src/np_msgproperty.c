/**
 *  np_message.c
 *  description:
 **/
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

#include "sodium.h"
#include "msgpack/cmp.h"

#include "np_msgproperty.h"

#include "jval.h"
#include "dtime.h"
#include "log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_dendrit.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_jtree.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_node.h"
#include "np_util.h"
#include "np_threads.h"

// default message type enumeration
enum {
	NEUROPIL_PING_REQUEST = 1,
	NEUROPIL_PING_REPLY,

	NEUROPIL_JOIN = 10,
	NEUROPIL_JOIN_ACK,
	NEUROPIL_JOIN_NACK,

	NEUROPIL_AVOID = 20,
	NEUROPIL_DIVORCE, // TODO: implement me

	NEUROPIL_UPDATE = 30,
	NEUROPIL_PIGGY,
	NEUROPIL_DISCOVER = 30, // TODO: implement me

	NEUROPIL_MSG_INTEREST = 50,
	NEUROPIL_MSG_AVAILABLE,

	NEUROPIL_REST_OPERATIONS = 100, // TODO: implement me
	NEUROPIL_POST,   /*create*/
	NEUROPIL_GET,    /*read*/
	NEUROPIL_PUT,    /*update*/
	NEUROPIL_DELETE, /*delete*/
	NEUROPIL_QUERY,

	NEUROPIL_INTERN_MAX = 1024,
	NEUROPIL_DATA = 1025,

} message_enumeration;


#define NR_OF_ELEMS(x)  (sizeof(x) / sizeof(x[0]))

np_msgproperty_t np_internal_messages[] =
{
	{ .msg_subject=ROUTE_LOOKUP, .mode_type=TRANSFORM, .mep_type=DEFAULT_TYPE, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=np_route_lookup }, // default input handling func should be "route_get" ?

	{ .msg_subject=DEFAULT, .mode_type=INBOUND, .mep_type=DEFAULT_TYPE, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=hnd_msg_in_received, .ttl=20.0 },
	// TODO: add garbage collection output
	{ .msg_subject=DEFAULT, .mode_type=OUTBOUND, .mep_type=DEFAULT_TYPE, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=hnd_msg_out_send, .ttl=20.0 },

	{ .msg_subject=NP_MSG_HANDSHAKE, .mode_type=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=hnd_msg_in_handshake, .ttl=20.0 },
	{ .msg_subject=NP_MSG_HANDSHAKE, .mode_type=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=hnd_msg_out_handshake , .ttl=20.0 },

	// we don't need to ack the ack the ack the ack ...
	{ .msg_subject=NP_MSG_ACK, .mode_type=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=NULL, .ttl=20.0 }, // incoming ack handled in network layer, not required
	{ .msg_subject=NP_MSG_ACK, .mode_type=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=hnd_msg_out_ack, .ttl=20.0 },

	// ping is send directly to the destination host, no ack required
	{ .msg_subject=NP_MSG_PING_REQUEST, .mode_type=INBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_NONE, .retry=5, .clb=hnd_msg_in_ping, .ttl=2.0 },
	{ .msg_subject=NP_MSG_PING_REPLY, .mode_type=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_NONE, .retry=5, .clb=hnd_msg_in_pingreply, .ttl=2.0 },
	{ .msg_subject=NP_MSG_PING_REQUEST, .mode_type=OUTBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_NONE, .retry=5, .clb=hnd_msg_out_send, .ttl=2.0 },
	{ .msg_subject=NP_MSG_PING_REPLY, .mode_type=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_NONE, .retry=5, .clb=hnd_msg_out_send, .ttl=2.0 },

	// join request: node unknown yet, therefore send without ack, explicit ack handling via extra messages
	{ .msg_subject=NP_MSG_JOIN_REQUEST, .mode_type=INBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_DESTINATION, .retry=6, .clb=hnd_msg_in_join_req, .ttl=6.0 }, // just for controller ?
	{ .msg_subject=NP_MSG_JOIN_REQUEST, .mode_type=OUTBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_DESTINATION, .retry=6, .clb=hnd_msg_out_send, .ttl=6.0 },
	{ .msg_subject=NP_MSG_JOIN_ACK, .mode_type=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_join_ack, .ttl=20.0 },
	{ .msg_subject=NP_MSG_JOIN_ACK, .mode_type=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send, .ttl=20.0 },
	{ .msg_subject=NP_MSG_JOIN_NACK, .mode_type=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_join_nack, .ttl=20.0 },
	{ .msg_subject=NP_MSG_JOIN_NACK, .mode_type=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send, .ttl=20.0 },

	{ .msg_subject=NP_MSG_PIGGY_REQUEST, .mode_type=TRANSFORM, .mep_type=DEFAULT_TYPE, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=_np_send_rowinfo, .ttl=20.0 }, // default input handling func should be "route_get" ?
	{ .msg_subject=NP_MSG_PIGGY_REQUEST, .mode_type=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_piggy, .ttl=10.0 },
	{ .msg_subject=NP_MSG_PIGGY_REQUEST, .mode_type=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send, .ttl=10.0 },

	{ .msg_subject=NP_MSG_UPDATE_REQUEST, .mode_type=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_update, .ttl=20.0 },
	{ .msg_subject=NP_MSG_UPDATE_REQUEST, .mode_type=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send, .ttl=20.0 },

	{ .msg_subject=NP_MSG_INTEREST, .mode_type=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=2, .clb=hnd_msg_in_interest, .ttl=5.0 },
	{ .msg_subject=NP_MSG_AVAILABLE, .mode_type=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=2, .clb=hnd_msg_in_available, .ttl=5.0 },
	{ .msg_subject=NP_MSG_INTEREST, .mode_type=OUTBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_EACHHOP, .retry=2, .clb=hnd_msg_out_send, .ttl=5.0 },
	{ .msg_subject=NP_MSG_AVAILABLE, .mode_type=OUTBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_EACHHOP, .retry=2, .clb=hnd_msg_out_send, .ttl=5.0 },

	{ .msg_subject=NP_MSG_AUTHENTICATION_REQUEST, .mode_type=INBOUND,  .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_authenticate, .ttl=20.0 },
	{ .msg_subject=NP_MSG_AUTHENTICATION_REQUEST, .mode_type=OUTBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send, .ttl=20.0 },
	{ .msg_subject=NP_MSG_AUTHORIZATION_REQUEST, .mode_type=INBOUND,  .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_authorize, .ttl=20.0 },
	{ .msg_subject=NP_MSG_AUTHORIZATION_REQUEST, .mode_type=OUTBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send, .ttl=20.0 },
	{ .msg_subject=NP_MSG_ACCOUNTING_REQUEST, .mode_type=INBOUND,  .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_account, .ttl=20.0 },
	{ .msg_subject=NP_MSG_ACCOUNTING_REQUEST, .mode_type=OUTBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send, .ttl=20.0 }
};

// required to properly link inline in debug mode
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, mode_type, np_msg_mode_type);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, mep_type, np_msg_mep_type);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, ack_mode, np_msg_ack_type);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, ttl, double);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, retry, uint8_t);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, max_threshold, uint16_t);

_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, partner_key, np_key_t*);


/**
 ** message_init: chstate, port
 ** Initialize messaging subsystem on port and returns the MessageGlobal * which 
 ** contains global state of message subsystem.
 ** message_init also initiate the network subsystem
 **/
void _np_msgproperty_init (np_state_t* state)
{
    RB_INIT(&state->msg_properties);
    state->msg_tokens = make_jtree();

	/* NEUROPIL_INTERN_MESSAGES */
	for (uint8_t i = 0; i < NR_OF_ELEMS(np_internal_messages); i++)
	{
		if (strlen(np_internal_messages[i].msg_subject) > 0)
		{
			log_msg(LOG_DEBUG, "register handler (%hhd): %s", i, np_internal_messages[i].msg_subject);
			RB_INSERT(rbt_msgproperty, &state->msg_properties, &np_internal_messages[i]);
		}
	}
}

np_callback_t np_msgproperty_callback (np_msgproperty_t *handler)
{
	assert (handler != NULL);
	assert (handler->clb != NULL);

	return handler->clb;
}

/**
 ** registers the handler function #func# with the message type #type#,
 ** it also defines the acknowledgment requirement for this type 
 **/
np_msgproperty_t* np_msgproperty_get(np_state_t *state, np_msg_mode_type mode_type, const char* subject)
{
	assert(subject != NULL);

	np_msgproperty_t prop = { .msg_subject=(char*) subject, .mode_type=mode_type };
	return RB_FIND(rbt_msgproperty, &state->msg_properties, &prop);
}


int16_t _np_msgproperty_comp(const np_msgproperty_t* const prop1, const np_msgproperty_t* const prop2)
{
	// TODO: check how to use bitmasks with red-black-tree efficiently
	int16_t i = strncmp(prop1->msg_subject, prop2->msg_subject, 64);

	if (0 == i)
		if (prop1->mode_type == prop2->mode_type) return  0;
		if (prop1->mode_type > prop2->mode_type)  return  1;
		if (prop1->mode_type < prop2->mode_type)  return -1;
	else
		return i;
}

void np_msgproperty_register(np_state_t *state, np_msgproperty_t* msgprops)
{
	RB_INSERT(rbt_msgproperty, &state->msg_properties, msgprops);
}

void _np_msgproperty_t_new(void* property)
{
	np_msgproperty_t* prop = (np_msgproperty_t*) property;

	prop->partner_key = NULL;

	// prop->msg_subject = strndup(subject, 255);
	prop->mode_type = INBOUND | OUTBOUND;
	prop->mep_type = ANY_TO_ANY;
	prop->ack_mode = ACK_EACHHOP;
	prop->priority = 5;
	prop->retry    = 5;
	prop->ttl      = 20.0;
	// prop->clb = callback;

	prop->max_threshold = 10;
	prop->msg_threshold =  0;

	prop->last_update = ev_time();

	// cache which will hold up to max_threshold messages
	prop->cache_policy = FIFO | OVERFLOW_PURGE;
	sll_init(np_message_t, prop->msg_cache);

	pthread_mutex_init (&prop->lock, NULL);
    pthread_cond_init (&prop->msg_received, &prop->cond_attr);
    pthread_condattr_setpshared(&prop->cond_attr, PTHREAD_PROCESS_PRIVATE);
}

void _np_msgproperty_t_del(void* property)
{
	np_msgproperty_t* prop = (np_msgproperty_t*) property;

	if (prop->msg_subject) free(prop->msg_subject);

	sll_free(np_message_t, prop->msg_cache);

	pthread_condattr_destroy(&prop->cond_attr);
    pthread_cond_destroy (&prop->msg_received);
	pthread_mutex_destroy (&prop->lock);
}

