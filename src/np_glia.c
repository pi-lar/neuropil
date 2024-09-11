//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "np_glia.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "event/ev.h"
#include "sodium.h"
#include "tree/tree.h"

#include "neuropil_log.h"

#include "core/np_comp_msgproperty.h"
#include "util/np_event.h"
#include "util/np_list.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_constants.h"
#include "np_dendrit.h"
#include "np_dhkey.h"
#include "np_evloop.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_node.h"
#include "np_responsecontainer.h"
#include "np_route.h"
#include "np_settings.h"
#include "np_threads.h"
#include "np_types.h"
#include "np_util.h"

// TODO: make these configurable (via struct np_config)

void _np_glia_log_flush(np_state_t *context, NP_UNUSED np_util_event_t event) {
  _np_log_fflush(context, false);
}

/**
 ** _np_cleanup
 ** general resend mechanism. all message which have an acknowledge indicator
 *set are stored in
 ** memory. If the acknowledge has not been send in time, we try to redeliver
 *the message, otherwise
 ** the message gets deleted or dropped (if max redelivery has been reached)
 ** redelivery has two aspects -> simple resend or reroute because of bad link
 *nodes in the routing table
 **/
/*
void _np_cleanup_ack_jobexec(np_state_t* context, NP_UNUSED  np_jobargs_t args)
{
    np_waitref_obj(np_key_t, context->my_node_key, my_key);
    np_waitref_obj(np_network_t, my_key->network, my_network);

    np_tree_elem_t *jrb_ack_node = NULL;

    // wake up and check for acknowledged messages

    np_tree_elem_t* iter = NULL;
    int c = 0;

    sll_init_full(char_ptr, to_remove);

    _LOCK_ACCESS(&my_network->waiting_lock)
    {
        iter = RB_MIN(np_tree_s, my_network->waiting);
        double now =  np_time_now();
        while (iter != NULL) {
            jrb_ack_node = iter;
            iter = RB_NEXT(np_tree_s, my_network->waiting, iter);

            np_responsecontainer_t *responsecontainer = (np_responsecontainer_t
*)jrb_ack_node->val.value.v; if (responsecontainer != NULL) { bool
is_fully_acked = _np_responsecontainer_is_fully_acked(responsecontainer);

                if (is_fully_acked || now > responsecontainer->expires_at) {
                    if (!is_fully_acked) {
                        _np_responsecontainer_set_timeout(responsecontainer);
                        log_msg(LOG_WARNING, NULL, "ACK_HANDLING timeout (table
size: %3d) message (%s / %s) not acknowledged (IN TIME %f/%f)",
                            my_network->waiting->size,
                            jrb_ack_node->key.value.s,
responsecontainer->msg->msg_property->msg_subject, now,
responsecontainer->expires_at
                        );
                    }
                    sll_append(char_ptr, to_remove, jrb_ack_node->key.value.s);
                }
            }
            else
            {
                log_debug(LOG_ROUTING, NULL, "ACK_HANDLING (table size: %3d)
message (%s) not found", my_network->waiting->size, jrb_ack_node->key.value.s);
            }
            c++;
        };
    }

    if (sll_size(to_remove) > 0)
    {
        sll_iterator(char_ptr) iter_to_rm = sll_first(to_remove);
        log_debug(LOG_WARNING, NULL, "ACK_HANDLING removing %"PRIu32" (of %d)
from ack table", sll_size(to_remove), c); while (iter_to_rm != NULL)
        {
            np_responsecontainer_t *responsecontainer =
_np_responsecontainers_get_by_uuid(context, iter_to_rm->val);
            _LOCK_ACCESS(&my_network->waiting_lock)
            {
                np_tree_del_str(my_network->waiting, iter_to_rm->val);
            }
            np_unref_obj(np_responsecontainer_t, responsecontainer,
"_np_responsecontainers_get_by_uuid"); np_unref_obj(np_responsecontainer_t,
responsecontainer, ref_ack_obj);

            sll_next(iter_to_rm);
        }
    }
    sll_free(char_ptr, to_remove);

    np_unref_obj(np_key_t, my_key, FUNC);
    np_unref_obj(np_network_t, my_network, FUNC);
}
*/
