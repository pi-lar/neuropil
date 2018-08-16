//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "neuropil.h"
#include "np_dhkey.h"
#include "np_types.h"
#include "np_msgproperty.h"
#include "np_message.h"
#include "np_memory.h"
#include "np_memory_v2.h"
#include "np_node.h"
#include "np_key.h"
#include "np_log.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "np_jobqueue.h"

/**
** _np_ping_send:
** sends a PING message to another node. The message is acknowledged in network layer.
**/
void _np_ping_send(np_key_t* key)
{
	np_state_t* state = np_state();

	np_message_t* out_msg = NULL;
	np_new_obj(np_message_t, out_msg);

	_np_message_create(out_msg, key->dhkey, state->my_node_key->dhkey, _NP_MSG_PING_REQUEST, NULL);

	np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, _NP_MSG_PING_REQUEST);
	_np_job_submit_msgout_event(0.0, prop, key, out_msg);

	log_debug_msg(LOG_INFO, "sending ping message (%s) to  %s:%s / %s", out_msg->uuid, key->node->dns_name, key->node->port, _np_key_as_str(key) );

	np_unref_obj(np_message_t, out_msg, ref_obj_creation);
}

void _np_in_ping(NP_UNUSED np_jobargs_t* args)
{
	log_debug_msg(LOG_DEBUG, "_np_in_ping for message uuid %s", args->msg->uuid);
	// nothing to do. work is done only on the sending end (ack handling)
}
