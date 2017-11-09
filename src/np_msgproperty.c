//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
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

#include "neuropil.h"

#include "dtime.h"
#include "np_log.h"
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
#include "np_treeval.h"
#include "np_settings.h"
#include "np_constants.h"
#include "np_list.h"


#define NR_OF_ELEMS(x)  (sizeof(x) / sizeof(x[0]))

#include "np_msgproperty_init.c"
 
NP_SLL_GENERATE_IMPLEMENTATION(np_msgproperty_ptr);

// required to properly link inline in debug mode
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, mode_type, np_msg_mode_type);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, mep_type, np_msg_mep_type);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, ack_mode, np_msg_ack_type);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, msg_ttl, double);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, retry, uint8_t);
_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, max_threshold, uint16_t);

_NP_GENERATE_PROPERTY_SETVALUE_IMPL(np_msgproperty_t, partner_key, np_dhkey_t);

RB_HEAD(rbt_msgproperty, np_msgproperty_s);
// RB_PROTOTYPE(rbt_msgproperty, np_msgproperty_s, link, property_comp);
RB_GENERATE(rbt_msgproperty, np_msgproperty_s, link, _np_msgproperty_comp);

typedef struct rbt_msgproperty rbt_msgproperty_t;
static rbt_msgproperty_t* __msgproperty_table;

np_bool __np_msgproperty_internal_msgs_ack(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body)
{
	if (msg->msg_property->is_internal == TRUE && 0 != strncmp(msg->msg_property->msg_subject, _DEFAULT,strlen(_DEFAULT))) {
		CHECK_STR_FIELD(msg->instructions, _NP_MSG_INST_ACK, msg_ack_mode);

		if (ACK_DESTINATION == (msg_ack_mode.value.ush & ACK_DESTINATION))
		{
			_np_send_ack(msg);
		}

		goto __np_return__;
	__np_cleanup__:
		log_msg(LOG_WARN, "cannot ack msg %s (%s)", msg->uuid, msg->msg_property->msg_subject);		
	}
__np_return__:
	return TRUE;
}

/**
 ** _np_msgproperty_init
 ** Initialize message property subsystem.
 **/
np_bool _np_msgproperty_init ()
{
	__msgproperty_table = (rbt_msgproperty_t*) malloc(sizeof(rbt_msgproperty_t));
	CHECK_MALLOC(__msgproperty_table);

	if (NULL == __msgproperty_table) return FALSE;

	RB_INIT(__msgproperty_table);

	// NEUROPIL_INTERN_MESSAGES
	
	np_sll_t(np_msgproperty_ptr, msgproperties);
	msgproperties  = default_msgproperties();
	sll_iterator(np_msgproperty_ptr) __np_internal_messages =  sll_first(msgproperties);

	while(__np_internal_messages != NULL)
	{
		np_msgproperty_t* property = __np_internal_messages->val;
		property->is_internal = TRUE;		

		if (strlen(property->msg_subject) > 0)
		{
			if ((property->mode_type & INBOUND) == INBOUND && (property->ack_mode & ACK_DESTINATION) == ACK_DESTINATION) {
				_np_msgproperty_add_receive_listener(__np_msgproperty_internal_msgs_ack, property);
			}

			log_debug_msg(LOG_DEBUG, "register handler: %s", property->msg_subject);
			RB_INSERT(rbt_msgproperty, __msgproperty_table, property);

		}

		sll_next(__np_internal_messages);
	}	

	sll_free(np_msgproperty_ptr, msgproperties);
	
	return TRUE;
}

void _np_msgproperty_add_receive_listener(np_usercallback_t msg_handler, np_msgproperty_t* msg_prop)
{
	// check whether an handler already exists

	if (FALSE == sll_contains(np_callback_t, msg_prop->clb_inbound, _np_in_callback_wrapper, _np_util_cmp_ref)) {
		sll_append(np_callback_t, msg_prop->clb_inbound, _np_in_callback_wrapper);
	}
	sll_append(np_usercallback_t, msg_prop->user_receive_clb, msg_handler);

}
/**
 ** registers the handler function #func# with the message type #type#,
 ** it also defines the acknowledgment requirement for this type
 **/
np_msgproperty_t* np_msgproperty_get(np_msg_mode_type mode_type, const char* subject)
{
	log_msg(LOG_TRACE, "start: np_msgproperty_t* np_msgproperty_get(np_msg_mode_type mode_type, const char* subject){");
	assert(subject != NULL);

	np_msgproperty_t prop = { .msg_subject=(char*) subject, .mode_type=mode_type };
	return RB_FIND(rbt_msgproperty, __msgproperty_table, &prop);
}

int16_t _np_msgproperty_comp(const np_msgproperty_t* const prop1, const np_msgproperty_t* const prop2)
{
	log_msg(LOG_TRACE, "start: int16_t _np_msgproperty_comp(const np_msgproperty_t* const prop1, const np_msgproperty_t* const prop2){");

	int16_t ret = -1;
	// TODO: check how to use bitmasks with red-black-tree efficiently
	int16_t i = 1;

	if(prop1 == NULL || prop1->msg_subject == NULL || prop2 == NULL || prop2->msg_subject == NULL){
		log_msg(LOG_ERROR,"Comparing properties where one is NULL");
	}else{
		i = strncmp(prop1->msg_subject, prop2->msg_subject, 255);
	}

	if (0 != i) ret = i;
	else if (prop1->mode_type == prop2->mode_type) ret =  (0);		// Is it the same bitmask ?
	else if (0 < (prop1->mode_type & prop2->mode_type)) ret = (0);	// for searching: Are some test bits set ?
	else if (prop1->mode_type > prop2->mode_type)  ret = ( 1);		// for sorting / inserting different entries
	else if (prop1->mode_type < prop2->mode_type)  ret = (-1);		

	return ret;
}

void np_msgproperty_register(np_msgproperty_t* msgprops)
{
	log_msg(LOG_TRACE, "start: void np_msgproperty_register(np_msgproperty_t* msgprops){");
	log_debug_msg(LOG_DEBUG, "registering user property: %s", msgprops->msg_subject);

	np_ref_obj(np_msgproperty_t, msgprops, ref_system_msgproperty);
	RB_INSERT(rbt_msgproperty, __msgproperty_table, msgprops);

	if ((msgprops->mode_type & OUTBOUND) == OUTBOUND) {
		_np_send_subject_discovery_messages(OUTBOUND, msgprops->msg_subject);
	}else if ((msgprops->mode_type & INBOUND) == INBOUND) {
		_np_send_subject_discovery_messages(INBOUND, msgprops->msg_subject);
	}	
}

void _np_msgproperty_t_new(void* property)
{
	log_msg(LOG_TRACE, "start: void _np_msgproperty_t_new(void* property){");
	np_msgproperty_t* prop = (np_msgproperty_t*) property;

	prop->token_min_ttl = MSGPROPERTY_DEFAULT_MIN_TTL_SEC;
	prop->token_max_ttl = MSGPROPERTY_DEFAULT_MAX_TTL_SEC;

	prop->msg_audience	= NULL;
	prop->msg_subject	= NULL;
	prop->rep_subject	= NULL;

	prop->mode_type = OUTBOUND | INBOUND | ROUTE | TRANSFORM;
	prop->mep_type	= DEFAULT_TYPE;
	prop->ack_mode	= ACK_NONE;
	prop->priority	= PRIORITY_MOD_USER_DEFAULT;
	prop->retry		= 5;
	prop->msg_ttl	= 20.0;

	prop->max_threshold = 10;
	prop->msg_threshold =  0;

	prop->is_internal = FALSE;
	prop->last_update = np_time_now();

	sll_init(np_callback_t, prop->clb_inbound);
	sll_init(np_callback_t, prop->clb_transform);
	sll_init(np_callback_t, prop->clb_outbound);
	sll_init(np_callback_t, prop->clb_route);

	sll_append(np_callback_t, prop->clb_outbound, _np_out);
	sll_append(np_callback_t, prop->clb_route, _np_glia_route_lookup);	

	sll_init(np_usercallback_t, prop->user_receive_clb);
	sll_init(np_usercallback_t, prop->user_send_clb);

	// cache which will hold up to max_threshold messages
	prop->cache_policy = FIFO | OVERFLOW_PURGE;
	sll_init(np_message_ptr, prop->msg_cache_in);
	sll_init(np_message_ptr, prop->msg_cache_out);

	_np_threads_mutex_init (&prop->lock,"property lock");
	_np_threads_condition_init_shared(&prop->msg_received);
}

void _np_msgproperty_t_del(void* property)
{
	log_msg(LOG_TRACE, "start: void _np_msgproperty_t_del(void* property){");
	np_msgproperty_t* prop = (np_msgproperty_t*) property;

	log_debug_msg(LOG_DEBUG, "Deleting msgproperty %s",prop->msg_subject);

	assert(prop != NULL);

	_LOCK_ACCESS(&prop->lock){

		if (prop->msg_subject != NULL) {
			free(prop->msg_subject);
			prop->msg_subject = NULL;
		}

		if (prop->rep_subject != NULL) {
			free(prop->rep_subject);
			prop->rep_subject = NULL;
		}

		if(prop->msg_cache_in != NULL ){
			sll_free(np_message_ptr, prop->msg_cache_in);
		}

		if(prop->msg_cache_out != NULL ){
			sll_free(np_message_ptr, prop->msg_cache_out);
		}

		sll_free(np_usercallback_t, prop->user_receive_clb);
		sll_free(np_usercallback_t, prop->user_send_clb);

		sll_free(np_callback_t, prop->clb_transform);
		sll_free(np_callback_t, prop->clb_route);
		sll_free(np_callback_t, prop->clb_outbound);
		sll_free(np_callback_t, prop->clb_inbound);		

	}
	_np_threads_mutex_destroy(&prop->lock);
	_np_threads_condition_destroy(&prop->msg_received);
	prop = NULL;
}

void _np_msgproperty_check_sender_msgcache(np_msgproperty_t* send_prop)
{
	log_msg(LOG_TRACE, "start: void _np_msgproperty_check_sender_msgcache(np_msgproperty_t* send_prop){");
	// check if we are (one of the) sending node(s) of this kind of message
	// should not return NULL
	log_debug_msg(LOG_DEBUG,
			"this node is one sender of messages, checking msgcache (%p / %u) ...",
			send_prop->msg_cache_out, sll_size(send_prop->msg_cache_out));

	// get message from cache (maybe only for one way mep ?!)
	uint16_t msg_available = 0;
	_LOCK_ACCESS(&send_prop->lock)
	{
		msg_available = sll_size(send_prop->msg_cache_out);
	}

	np_bool sending_ok = TRUE;

	while (0 < msg_available && TRUE == sending_ok)
	{
		np_message_t* msg_out = NULL;
		_LOCK_ACCESS(&send_prop->lock)
		{
			// if messages are available in cache, send them !
			if (send_prop->cache_policy & FIFO)
				msg_out = sll_head(np_message_ptr, send_prop->msg_cache_out);
			if (send_prop->cache_policy & FILO)
				msg_out = sll_tail(np_message_ptr, send_prop->msg_cache_out);

			// check for more messages in cache after head/tail command
			msg_available = sll_size(send_prop->msg_cache_out);
		}

		if(NULL != msg_out){
			send_prop->msg_threshold--;
			sending_ok = _np_send_msg(send_prop->msg_subject, msg_out, send_prop, NULL);
			np_unref_obj(np_message_t, msg_out, ref_msgproperty_msgcache);

			log_debug_msg(LOG_DEBUG,
					"message in cache found and re-send initialized");
		}
	}
}

void _np_msgproperty_check_receiver_msgcache(np_msgproperty_t* recv_prop)
{
	log_msg(LOG_TRACE, "start: void _np_msgproperty_check_receiver_msgcache(np_msgproperty_t* recv_prop){");
	log_debug_msg(LOG_DEBUG,
			"this node is the receiver of messages, checking msgcache (%p / %u) ...",
			recv_prop->msg_cache_in, sll_size(recv_prop->msg_cache_in));

	// get message from cache (maybe only for one way mep ?!)
	uint16_t msg_available = 0;
	_LOCK_ACCESS(&recv_prop->lock)
	{
		msg_available = sll_size(recv_prop->msg_cache_in);
	}

	np_state_t* state = _np_state();

	while (0 < msg_available)
	{
		np_message_t* msg_in = NULL;

		_LOCK_ACCESS(&recv_prop->lock)
		{
			// if messages are available in cache, try to decode them !
			if (recv_prop->cache_policy & FIFO)
				msg_in = sll_head(np_message_ptr, recv_prop->msg_cache_in);
			if (recv_prop->cache_policy & FILO)
				msg_in = sll_tail(np_message_ptr, recv_prop->msg_cache_in);

			msg_available = sll_size(recv_prop->msg_cache_in);
		}

		if(NULL != msg_in) {
			recv_prop->msg_threshold--;
			_np_job_submit_msgin_event(0.0, recv_prop, state->my_node_key, msg_in, NULL);
			np_unref_obj(np_message_t, msg_in, ref_msgproperty_msgcache);
		}
	}
}

void _np_msgproperty_add_msg_to_send_cache(np_msgproperty_t* msg_prop, np_message_t* msg_in)
{
	log_msg(LOG_TRACE, "start: void _np_msgproperty_add_msg_to_send_cache(np_msgproperty_t* msg_prop, np_message_t* msg_in){");
	_LOCK_ACCESS(&msg_prop->lock)
	{
		// cache already full ?
		if (msg_prop->max_threshold <= sll_size(msg_prop->msg_cache_out))
		{
			log_debug_msg(LOG_DEBUG, "send msg cache full, checking overflow policy ...");

			if (0 < (msg_prop->cache_policy & OVERFLOW_PURGE))
			{
				log_debug_msg(LOG_DEBUG, "OVERFLOW_PURGE: discarding message in send msgcache for %s", msg_prop->msg_subject);
				np_message_t* old_msg = NULL;

				if ((msg_prop->cache_policy & FIFO) > 0)
					old_msg = sll_head(np_message_ptr, msg_prop->msg_cache_out);

				if ((msg_prop->cache_policy & FILO) > 0)
					old_msg = sll_tail(np_message_ptr, msg_prop->msg_cache_out);

				if (old_msg != NULL)
				{
					// TODO: add callback hook to allow user space handling of discarded message
					msg_prop->msg_threshold--;
					np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
				}
			}

			if (0 < (msg_prop->cache_policy & OVERFLOW_REJECT))
			{
				log_msg(LOG_WARN,
						"rejecting new message because cache is full");
				break;
			}
		}

		sll_prepend(np_message_ptr, msg_prop->msg_cache_out, msg_in);

		log_debug_msg(LOG_DEBUG, "added message to the sender msgcache (%p / %d) ...",
				msg_prop->msg_cache_out, sll_size(msg_prop->msg_cache_out));
		np_ref_obj(np_message_t, msg_in, ref_msgproperty_msgcache);
	}
}
void _np_msgproperty_cleanup_receiver_cache(np_msgproperty_t* msg_prop) {

	_LOCK_ACCESS(&msg_prop->lock)
	{
		sll_iterator(np_message_ptr) iter_prop_msg_cache_in = sll_first(msg_prop->msg_cache_in);
		while (iter_prop_msg_cache_in != NULL)
		{
			sll_iterator(np_message_ptr) old_iter = iter_prop_msg_cache_in;
			sll_next(iter_prop_msg_cache_in); // we need to iterate before we delete the old iter
			np_message_t* old_msg = old_iter->val;
			if (_np_message_is_expired(old_msg)) {				
				sll_delete(np_message_ptr, msg_prop->msg_cache_in, old_iter);
				np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
				msg_prop->msg_threshold--;				
			}			
		}
	}
}
void _np_msgproperty_add_msg_to_recv_cache(np_msgproperty_t* msg_prop, np_message_t* msg_in)
{
	log_msg(LOG_TRACE, "start: void _np_msgproperty_add_msg_to_recv_cache(np_msgproperty_t* msg_prop, np_message_t* msg_in){");
	_LOCK_ACCESS(&msg_prop->lock)
	{
		if (msg_prop->max_threshold <= sll_size(msg_prop->msg_cache_in))
		{
			// cleanup of msgs in property receiver msg cache
			_np_msgproperty_cleanup_receiver_cache(msg_prop);
		}
		// cache already full ?
		if (msg_prop->max_threshold <= sll_size(msg_prop->msg_cache_in))
		{
			log_debug_msg(LOG_DEBUG, "recv msg cache full, checking overflow policy ...");

			if (0 < (msg_prop->cache_policy & OVERFLOW_PURGE))
			{
				log_debug_msg(LOG_DEBUG, "OVERFLOW_PURGE: discarding message in recv msgcache for %s", msg_prop->msg_subject);
				np_message_t* old_msg = NULL;

				if ((msg_prop->cache_policy & FIFO) > 0)
					old_msg = sll_head(np_message_ptr, msg_prop->msg_cache_in);
				if ((msg_prop->cache_policy & FILO) > 0)
					old_msg = sll_tail(np_message_ptr, msg_prop->msg_cache_in);

				if (old_msg != NULL)
				{
					// TODO: add callback hook to allow user space handling of discarded message
					msg_prop->msg_threshold--;
					np_unref_obj(np_message_t, old_msg, ref_msgproperty_msgcache);
				}
			}

			if (0 < (msg_prop->cache_policy & OVERFLOW_REJECT))
			{
				log_debug_msg(LOG_DEBUG,
						"rejecting new message because cache is full");
				continue;
			}
		}

		sll_prepend(np_message_ptr, msg_prop->msg_cache_in, msg_in);

		log_debug_msg(LOG_DEBUG, "added message to the recv msgcache (%p / %d) ...",
				msg_prop->msg_cache_in, sll_size(msg_prop->msg_cache_in));
		np_ref_obj(np_message_t, msg_in, ref_msgproperty_msgcache);
	}
}
