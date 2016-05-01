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

#include "dtime.h"
#include "np_log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_dendrit.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_val.h"

// default message type enumeration
enum {
	NEUROPIL_PING_REQUEST = 1,
	NEUROPIL_PING_REPLY,

	NEUROPIL_JOIN,
	NEUROPIL_JOIN_ACK,
	NEUROPIL_JOIN_NACK,

	NEUROPIL_LEAVE,

	NEUROPIL_UPDATE,
	NEUROPIL_PIGGY,

	NEUROPIL_MSG_DISCOVER_RECEIVER,
	NEUROPIL_MSG_DISCOVER_SENDER,
	NEUROPIL_MSG_AVAILABLE_RECEIVER,
	NEUROPIL_MSG_AVAILABLE_SENDER,

	NEUROPIL_MSG_AUTHENTICATE_REQUEST,
	NEUROPIL_MSG_AUTHENTICATE_REPLY,

	NEUROPIL_MSG_AUTHORIZE_REQUEST,
	NEUROPIL_MSG_AUTHORIZE_REPLY,

	NEUROPIL_MSG_ACCOUNTING_REQUEST,

	NEUROPIL_REST_OPERATIONS, // TODO: implement me
	NEUROPIL_POST,   /*create*/
	NEUROPIL_GET,    /*read*/
	NEUROPIL_PUT,    /*update*/
	NEUROPIL_DELETE, /*delete*/
	NEUROPIL_QUERY,

} message_enumeration;

#define NR_OF_ELEMS(x)  (sizeof(x) / sizeof(x[0]))

#include "np_msgproperty_init.c"

// required to properly link inline in debug mode
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, mode_type, np_msg_mode_type);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, mep_type, np_msg_mep_type);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, ack_mode, np_msg_ack_type);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, ttl, double);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, retry, uint8_t);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, max_threshold, uint16_t);

_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, partner_key, np_dhkey_t);

RB_HEAD(rbt_msgproperty, np_msgproperty_s);
// RB_PROTOTYPE(rbt_msgproperty, np_msgproperty_s, link, property_comp);
RB_GENERATE(rbt_msgproperty, np_msgproperty_s, link, _np_msgproperty_comp);

typedef struct rbt_msgproperty rbt_msgproperty_t;
static pthread_mutex_t __lock_mutex = PTHREAD_MUTEX_INITIALIZER;
static rbt_msgproperty_t* __msgproperty_table;

_NP_MODULE_LOCK_IMPL(np_msgproperty_t);

/**
 ** message_init: chstate, port
 ** Initialize messaging subsystem on port and returns the MessageGlobal * which 
 ** contains global state of message subsystem.
 ** message_init also initiate the network subsystem
 **/
np_bool _np_msgproperty_init ()
{
	__msgproperty_table = (rbt_msgproperty_t*) malloc(sizeof(rbt_msgproperty_t));
	if (NULL == __msgproperty_table) return FALSE;

	RB_INIT(__msgproperty_table);

	/* NEUROPIL_INTERN_MESSAGES */
	for (uint8_t i = 0; i < NR_OF_ELEMS(__np_internal_messages); i++)
	{
		if (strlen(__np_internal_messages[i]->msg_subject) > 0)
		{
			log_msg(LOG_DEBUG, "register handler (%hhd): %s", i, __np_internal_messages[i]->msg_subject);
			RB_INSERT(rbt_msgproperty, __msgproperty_table, __np_internal_messages[i]);
		}
	}
	return TRUE;
}

/**
 ** registers the handler function #func# with the message type #type#,
 ** it also defines the acknowledgment requirement for this type 
 **/
np_msgproperty_t* np_msgproperty_get(np_msg_mode_type mode_type, const char* subject)
{
	assert(subject != NULL);

	np_msgproperty_t prop = { .msg_subject=(char*) subject, .mode_type=mode_type };
	return RB_FIND(rbt_msgproperty, __msgproperty_table, &prop);
}


int16_t _np_msgproperty_comp(const np_msgproperty_t* const prop1, const np_msgproperty_t* const prop2)
{
//	log_msg(LOG_DEBUG, "%s %d (&) %s %d",
//			prop1->msg_subject, prop1->mode_type,
//			prop2->msg_subject, prop2->mode_type );

	// TODO: check how to use bitmasks with red-black-tree efficiently
	int16_t i = strncmp(prop1->msg_subject, prop2->msg_subject, 64);

	if (0 == i)
	{
//		log_msg(LOG_DEBUG, "%d %d (&) %d",
//				prop1->mode_type,
//				prop2->mode_type,
//				(prop1->mode_type & prop2->mode_type) );

		if ((prop1->mode_type & prop2->mode_type)) return 0;

		if (prop1->mode_type == prop2->mode_type) return  0;
		if (prop1->mode_type > prop2->mode_type)  return  1;
		if (prop1->mode_type < prop2->mode_type)  return -1;
		return -1;
	}
	else
	{
		return i;
	}
}

void np_msgproperty_register(np_msgproperty_t* msgprops)
{
	RB_INSERT(rbt_msgproperty, __msgproperty_table, msgprops);
}

void _np_msgproperty_t_new(void* property)
{
	np_msgproperty_t* prop = (np_msgproperty_t*) property;

	prop->msg_audience = NULL;

	// prop->msg_subject = strndup(subject, 255);
	prop->mode_type = INBOUND | OUTBOUND | TRANSFORM | ROUTE;
	prop->mep_type = ANY_TO_ANY;
	prop->ack_mode = ACK_EACHHOP;
	prop->priority = 5;
	prop->retry    = 5;
	prop->ttl      = 20.0;

	prop->max_threshold = 10;
	prop->msg_threshold =  0;

	prop->last_update = ev_time();

	prop->clb_inbound = _np_never_called;
	prop->clb_outbound = _np_never_called;
	prop->clb_route = _np_route_lookup;
	prop->clb_transform = _np_never_called;

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

void _np_check_sender_msgcache(np_msgproperty_t* send_prop)
{
	// check if we are (one of the) sending node(s) of this kind of message
	// should not return NULL
	log_msg(LOG_DEBUG,
			"this node is one sender of messages, checking msgcache (%p / %u) ...",
			send_prop->msg_cache, sll_size(send_prop->msg_cache));

	// get message from cache (maybe only for one way mep ?!)
	uint16_t msg_available = 0;

	LOCK_CACHE(send_prop)
	{
		msg_available = sll_size(send_prop->msg_cache);
	}
	np_bool sending_ok = TRUE;

	while (0 < msg_available && TRUE == sending_ok)
	{
		np_message_t* msg_out = NULL;
		LOCK_CACHE(send_prop)
		{
			// if messages are available in cache, send them !
			if (send_prop->cache_policy & FIFO)
				msg_out = sll_head(np_message_t, send_prop->msg_cache);
			if (send_prop->cache_policy & FILO)
				msg_out = sll_tail(np_message_t, send_prop->msg_cache);
			// check for more messages in cache after head/tail command
			msg_available = sll_size(send_prop->msg_cache);
		}

		sending_ok = _np_send_msg(send_prop->msg_subject, msg_out, send_prop);
		np_unref_obj(np_message_t, msg_out);
		send_prop->msg_threshold--;
		log_msg(LOG_DEBUG,
				"message in cache found and re-send initialized");
	}
}

void _np_check_receiver_msgcache(np_msgproperty_t* recv_prop)
{
	log_msg(LOG_DEBUG,
			"this node is the receiver of messages, checking msgcache (%p / %u) ...",
			recv_prop->msg_cache, sll_size(recv_prop->msg_cache));

	// get message from cache (maybe only for one way mep ?!)
	uint16_t msg_available = 0;
	LOCK_CACHE(recv_prop)
	{
		msg_available = sll_size(recv_prop->msg_cache);
	}

	np_state_t* state = _np_state();
	while (0 < msg_available)
	{
		np_message_t* msg_in = NULL;

		LOCK_CACHE(recv_prop)
		{
			// if messages are available in cache, try to decode them !
			if (recv_prop->cache_policy & FIFO)
				msg_in = sll_tail(np_message_t, recv_prop->msg_cache);
			if (recv_prop->cache_policy & FILO)
				msg_in = sll_head(np_message_t, recv_prop->msg_cache);

			msg_available = sll_size(recv_prop->msg_cache);
			recv_prop->msg_threshold--;
		}
		_np_job_submit_msgin_event(0.0, recv_prop, state->my_node_key, msg_in);
		np_unref_obj(np_message_t, msg_in);
	}
}

