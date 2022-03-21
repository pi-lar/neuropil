//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "np_legacy.h"
#include "np_types.h"
#include "np_responsecontainer.h"

#include "np_constants.h"
#include "np_key.h"
#include "neuropil_log.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_node.h"

void _np_responsecontainer_t_new(NP_UNUSED np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* obj)
{
	np_responsecontainer_t* entry = (np_responsecontainer_t *)obj;

	// memset(&entry->uuid[0], 0, NP_UUID_BYTES);
	_np_dhkey_assign(&entry->dest_dhkey, &dhkey_zero);
	_np_dhkey_assign(&entry->msg_dhkey, &dhkey_zero);

	entry->expires_at  = 0.0;
	entry->received_at = 0.0;
	entry->send_at     = 0.0;
}

void _np_responsecontainer_t_del(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* obj)
{
	// empty
}
