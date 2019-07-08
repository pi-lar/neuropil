//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include "np_legacy.h"
#include "np_types.h"
#include "np_responsecontainer.h"

#include "np_constants.h"
#include "np_key.h"
#include "np_log.h"
#include "np_list.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_node.h"
#include "np_settings.h"
#include "np_tree.h"



void _np_responsecontainer_t_new(NP_UNUSED np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* obj)
{
	np_responsecontainer_t* entry = (np_responsecontainer_t *)obj;

	// memset(&entry->uuid[0], 0, NP_UUID_BYTES);
	// entry->dest_dhkey = np_dhkey_min(context);
	// entry->msg_dhkey  = np_dhkey_min(context);

	entry->expires_at  = 0.0;
	entry->received_at = 0.0;
	entry->send_at     = 0.0;
}

void _np_responsecontainer_t_del(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* obj)
{
	// empty
}

/* void _np_responsehandler_set(np_key_t* key, np_responsecontainer_t* entry)
{ 
	char* uuid = &entry->uuid[0];
	np_tree_insert_str(_np_key_get_network(key)->waiting, uuid, np_treeval_new_v(entry) );

    log_debug_msg(LOG_ROUTING | LOG_MESSAGE | LOG_DEBUG, "response handling (%p) requested for msg uuid: %s", rc_tree, uuid);
};
*/

/*
np_responsecontainer_t* _np_responsecontainers_get_by_uuid(np_key_t* key, char* uuid) 
{	
	np_responsecontainer_t* ret = NULL;
	
	// just an acknowledgement of own messages send out earlier
	np_tree_elem_t *jrb_node = np_tree_find_str(_np_key_get_network(key)->waiting, uuid);
	if (jrb_node != NULL)
	{
		ret = (np_responsecontainer_t *)jrb_node->val.value.v;
	}
	return ret;
}
*/