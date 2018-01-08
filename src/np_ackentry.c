#include "neuropil.h"
#include "np_types.h"
#include "np_ackentry.h"

#include "np_constants.h"
#include "np_settings.h"
#include "np_log.h"
#include "np_list.h"
#include "np_memory.h"
#include "np_key.h"
#include "np_message.h"
#include "np_node.h"

NP_SLL_GENERATE_IMPLEMENTATION(np_ackentry_on_t);

void _np_ackentry_set_acked(np_ackentry_t* entry)
{
	np_ref_obj(np_ackentry_t, entry);
	entry->received_at = np_time_now();
	entry->has_received_ack = TRUE;
	// entry->received_ack++;

	double latency = (entry->received_at - entry->send_at)/2;
	_np_node_update_latency(entry->dest_key->node, latency);
	_np_node_update_stat(entry->dest_key->node, TRUE);

	if (entry->msg != NULL && sll_size(entry->msg->on_ack) > 0) {
		sll_iterator(np_ackentry_on_t) iter_on = sll_first(entry->msg->on_ack);
		while (iter_on != NULL)
		{
			//TODO: call async
			iter_on->val(entry);
			sll_next(iter_on);
		}
	}

	np_unref_obj(np_ackentry_t, entry, __func__);
}

np_bool _np_ackentry_is_fully_acked(np_ackentry_t* entry)
{
	return entry->has_received_ack;
	// return (entry->expected_ack == entry->received_ack);
}

void _np_ackentry_t_new(void* obj)
{
	log_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_t_new(void* nw){");
	np_ackentry_t* entry = (np_ackentry_t *)obj;

	entry->has_received_ack = FALSE;
	entry->received_at = 0.0;
	entry->send_at = 0.0;

	// entry->expected_ack = 0;
	// entry->received_ack = 0;
	entry->dest_key = NULL;
	entry->msg = NULL;
}

void _np_ackentry_t_del(void* obj)
{
	np_ackentry_t* entry = (np_ackentry_t *)obj;

	np_unref_obj(np_key_t, entry->dest_key, ref_ack_key);
	np_unref_obj(np_message_t, entry->msg, ref_ack_msg);

}
