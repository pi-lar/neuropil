#include "neuropil.h"
#include "np_types.h"
#include "np_responsecontainer.h"

#include "np_constants.h"
#include "np_settings.h"
#include "np_log.h"
#include "np_list.h"
#include "np_memory.h"
#include "np_key.h"
#include "np_message.h"
#include "np_node.h"
#include "np_tree.h"
#include "np_network.h"

NP_SLL_GENERATE_IMPLEMENTATION(np_responsecontainer_on_t);

void _np_responsecontainer_received(np_responsecontainer_t* entry){
	if (entry->received_at == 0) {
		entry->received_at = np_time_now();
	}
	// entry->received_ack++;

	double latency = (entry->received_at - entry->send_at) / 2;
	_np_node_update_latency(entry->dest_key->node, latency);
	_np_node_update_stat(entry->dest_key->node, TRUE);
}
void _np_responsecontainer_received_ack(np_responsecontainer_t* entry)
{
	np_ref_obj(np_responsecontainer_t, entry);
	_np_responsecontainer_received(entry);	

	if (entry->msg != NULL) {

		TSP_SET(np_bool, entry->msg->is_acked, TRUE);
		
		{
			if (sll_size(entry->msg->on_ack) > 0) {
				sll_iterator(np_responsecontainer_on_t) iter_on = sll_first(entry->msg->on_ack);
				while (iter_on != NULL)
				{
					//TODO: call async
					iter_on->val(entry);
					sll_next(iter_on);
				}
			}
		}
	}
	np_unref_obj(np_responsecontainer_t, entry, __func__);
}

void _np_responsecontainer_set_timeout(np_responsecontainer_t* entry)
{
	// timeout
	log_debug_msg(LOG_ROUTING | LOG_DEBUG, "not acknowledged (TIMEOUT at %f)", entry->expires_at);
	_np_node_update_stat(entry->dest_key->node, FALSE);

	if (entry->msg != NULL) {
		TSP_SET(np_bool, entry->msg->is_in_timeout, TRUE);
		if (sll_size(entry->msg->on_timeout) > 0) {
			sll_iterator(np_responsecontainer_on_t) iter_on = sll_first(entry->msg->on_timeout);
			while (iter_on != NULL)
			{
				//TODO: call async
				iter_on->val(entry);
				sll_next(iter_on);
			}
		}
	}	
}

void _np_responsecontainer_received_response(np_responsecontainer_t* entry, np_message_t* response)
{
	np_ref_obj(np_responsecontainer_t, entry);
	_np_responsecontainer_received(entry);

	if (entry->msg != NULL) {

		TSP_SET(np_bool, entry->msg->has_reply, TRUE);

		if (sll_size(entry->msg->on_reply) > 0) {
			sll_iterator(np_message_on_reply_t) iter_on = sll_first(entry->msg->on_reply);
			while (iter_on != NULL)
			{
				//TODO: call async
				iter_on->val(entry, response);
				sll_next(iter_on);
			}
		}		
	}

	np_unref_obj(np_responsecontainer_t, entry, __func__);
}

np_bool _np_responsecontainer_is_fully_acked(np_responsecontainer_t* entry)
{
	TSP_GET(np_bool, entry->msg->is_acked, is_acked);
	return is_acked;
	// return (entry->expected_ack == entry->received_ack);
}

void _np_responsecontainer_t_new(void* obj)
{
	log_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_t_new(void* nw){");
	np_responsecontainer_t* entry = (np_responsecontainer_t *)obj;

	entry->received_at = 0.0;
	entry->send_at = 0.0;

	// entry->expected_ack = 0;
	// entry->received_ack = 0;
	entry->dest_key = NULL;
	entry->msg = NULL;
}

void _np_responsecontainer_t_del(void* obj)
{
	np_responsecontainer_t* entry = (np_responsecontainer_t *)obj;

	np_unref_obj(np_key_t, entry->dest_key, ref_ack_key);
	np_unref_obj(np_message_t, entry->msg, ref_ack_msg);

}

np_responsecontainer_t* _np_responsecontainers_get_by_uuid(char* uuid) {
	
	np_responsecontainer_t* ret = NULL;
	np_waitref_obj(np_network_t, _np_state()->my_node_key->network, my_network);

	np_responsecontainer_t *entry = NULL;
	/* just an acknowledgement of own messages send out earlier */
	_LOCK_ACCESS(&my_network->waiting_lock)
	{
		np_tree_elem_t *jrb_node = np_tree_find_str(my_network->waiting, uuid);
		if (jrb_node != NULL)
		{
			ret = (np_responsecontainer_t *)jrb_node->val.value.v;
			np_ref_obj(np_responsecontainer_t, ret, __func__);
			
		}
	}
	return ret;
}