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

bool _np_glia_node_can_be_reached(const np_state_t *context,
                                  const char       *remote_ip,
                                  const socket_type protocol,
                                  np_key_t        **outgoing_interface) {
  // functions checks whether th remote_ip can be reached from already existing
  // interfaces. It does not check for potential interfaces, as we assume the
  // user knows what he is doing and will setup needed interfaces with seperate
  // np_listen() calls himself.

  assert(remote_ip != NULL && context != NULL);

  bool ret = false;

  // grab outgoing interface for this remote ip
  bool is_main_interface = false;
  bool local_is_private  = true;

  bool remote_is_private   = _np_network_is_private_address(NULL, remote_ip);
  bool remote_is_localhost = _np_network_is_loopback_address(NULL, remote_ip);

  // get outgoing local ip address to compare against
  char local_ip[40] = {0};
  _np_network_get_outgoing_ip(NULL, remote_ip, protocol, local_ip);
  np_key_t *interface_key =
      _np_keycache_find_interface(context, local_ip, NULL);

  // extract local node info, use own main interface if outgoing interface is
  // not existing
  struct np_node_s *node_info = NULL;
  if (interface_key == NULL) {
    interface_key =
        _np_keycache_find_interface(context, context->main_ip, NULL);
    // the main_ip interface has to be there
    assert(interface_key != NULL);

    is_main_interface = true;
    node_info         = interface_key->entity_array[e_nodeinfo];
  } else {
    node_info = interface_key->entity_array[e_nodeinfo];
  }

  // check whether our local interface is a "localhost" or private interface
  local_is_private = _np_network_is_private_address(NULL, node_info->ip_string);
  bool local_is_localhost =
      _np_network_is_loopback_address(NULL, node_info->ip_string);

  if (local_is_localhost && remote_is_localhost &&
      FLAG_CMP(protocol, (node_info->protocol & MASK_IP))) {
    ret = true;
    goto _np_return;
  }

  if (remote_is_private && local_is_private) {
    // if remote is a private ip address, then local and remote ip addresses
    // must match (at least some leading tuples)
    uint16_t common_tuples =
        _np_network_count_common_tuples(NULL, remote_ip, node_info->ip_string);
    ret = (common_tuples > 0);
    if (ret) goto _np_return;
  }

  if ((remote_is_private && local_is_localhost) ||
      (local_is_private && !remote_is_private)) {
    // we need a passive connection for these combinations to connect
    ret = FLAG_CMP(node_info->protocol, PASSIVE | (MASK_IP & protocol));
    if (!ret && local_is_private && !is_main_interface) {
      // our own interface may not be in passive mode, check whether the main
      // interface is passive
      np_unref_obj(np_key_t, interface_key, "_np_keycache_find_interface");
      interface_key =
          _np_keycache_find_interface(context, context->main_ip, NULL);
      node_info = interface_key->entity_array[e_nodeinfo];
      ret       = FLAG_CMP(node_info->protocol, PASSIVE | (MASK_IP & protocol));
    }
    goto _np_return;
  }

_np_return:

  if (ret && outgoing_interface != NULL) {
    *outgoing_interface = interface_key;
  } else {
    np_unref_obj(np_key_t, interface_key, "_np_keycache_find_interface");
  }
  return ret;
}
