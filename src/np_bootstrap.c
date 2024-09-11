//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "np_bootstrap.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "neuropil_log.h"

#include "core/np_comp_msgproperty.h"
#include "util/np_event.h"
#include "util/np_tree.h"

#include "np_constants.h"
#include "np_eventqueue.h"
#include "np_evloop.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_message.h"
#include "np_responsecontainer.h"
#include "np_settings.h"
#include "np_util.h"

np_module_struct(bootstrap) {
  np_state_t *context;
  TSP(np_tree_t *, bootstrap_points)
};

void __np_bootstrap_on_timeout(const np_responsecontainer_t *const entry) {
  // np_ctx_memory(entry);
  // log_msg(LOG_WARNING | LOG_ROUTING, NULL, "Bootstrap Node (%s) not reachable
  // anymore. Try to reconnect", _np_key_as_str(entry->dest_dhkey)); char*
  // reconnect = np_get_connection_string_from(entry->dest_key, true);
  // np_send_join(context, reconnect);
  // free(reconnect);
}

bool __np_bootstrap_reconnect(np_state_t               *context,
                              NP_UNUSED np_util_event_t args) {
  if (!np_module_initiated(bootstrap)) {
    return true;
  }

  np_spinlock_lock(&np_module(bootstrap)->bootstrap_points_lock);
  {
    np_tree_elem_t *iter =
        RB_MIN(np_tree_s, np_module(bootstrap)->bootstrap_points);
    while (iter != NULL) {
      if (iter->val.value.v != NULL) {
        np_key_t *bootstrap_key = (np_key_t *)iter->val.value.v;
        log_debug(LOG_DEBUG | LOG_ROUTING,
                  NULL,
                  "Sending Ping to check bootstrap node is reachable (%s)",
                  _np_key_as_str(bootstrap_key));

        // issue ping messages
        struct np_e2e_message_s *msg_out = NULL;
        np_new_obj(np_message_t, msg_out);

        np_dhkey_t ping_dhkey = {0};
        np_generate_subject(&ping_dhkey, _NP_MSG_PING_REQUEST, 16);
        _np_message_create(msg_out,
                           bootstrap_key->dhkey,
                           context->my_node_key->dhkey,
                           ping_dhkey,
                           NULL);

        np_dhkey_t ping_out_dhkey =
            _np_msgproperty_tweaked_dhkey(OUTBOUND, ping_dhkey);
        np_util_event_t ping_event = {.type = (evt_internal | evt_message),
                                      .target_dhkey = bootstrap_key->dhkey,
                                      .user_data    = msg_out};
        _np_event_runtime_add_event(context,
                                    args.current_run,
                                    ping_out_dhkey,
                                    ping_event);
        log_debug(LOG_ROUTING,
                  msg_out->uuid,
                  "submitted ping to bootstrap target key %s / %p",
                  _np_key_as_str(bootstrap_key),
                  bootstrap_key);
        np_unref_obj(np_message_t, msg_out, ref_obj_creation);
      }
      iter = RB_NEXT(np_tree_s, np_module(bootstrap)->bootstrap_points, iter);
    }
  }
  np_spinlock_unlock(&np_module(bootstrap)->bootstrap_points_lock);
  return true;
}

bool _np_bootstrap_init(np_state_t *context) {
  bool ret = false;

  if (!np_module_initiated(bootstrap)) {
    np_module_malloc(bootstrap);
    ret = true;

    TSP_INIT(_module->bootstrap_points);
    np_spinlock_lock(&np_module(bootstrap)->bootstrap_points_lock);
    { _module->bootstrap_points = np_tree_create(); }
    np_spinlock_unlock(&np_module(bootstrap)->bootstrap_points_lock);

    np_jobqueue_submit_event_periodic(context,
                                      NP_PRIORITY_LOWEST,
                                      NP_BOOTSTRAP_REACHABLE_CHECK_INTERVAL,
                                      NP_BOOTSTRAP_REACHABLE_CHECK_INTERVAL,
                                      __np_bootstrap_reconnect,
                                      "__np_bootstrap_reconnect");
  }
  return ret;
}

void _np_bootstrap_destroy(np_state_t *context) {
  if (np_module_initiated(bootstrap)) {
    np_module_var(bootstrap);

    np_tree_free(_module->bootstrap_points);
    TSP_DESTROY(_module->bootstrap_points);
    np_module_free(bootstrap);
  }
}

void np_bootstrap_add(np_state_t *context, const char *connectionstr) {

  np_spinlock_lock(&np_module(bootstrap)->bootstrap_points_lock);
  {
    np_tree_insert_str(np_module(bootstrap)->bootstrap_points,
                       connectionstr,
                       np_treeval_new_v(NULL));
  }
  np_spinlock_unlock(&np_module(bootstrap)->bootstrap_points_lock);
}

void __np_bootstrap_confirm(np_state_t *context,
                            np_key_t   *confirmed,
                            char       *connectionstr,
                            np_key_t   *replaced) {
  if (confirmed != replaced) {
    np_ref_obj(np_key_t, confirmed, ref_bootstrap_list);
    np_tree_replace_str(np_module(bootstrap)->bootstrap_points,
                        connectionstr,
                        np_treeval_new_v(confirmed));
    np_unref_obj(np_key_t, replaced, ref_bootstrap_list);
  }
}

void _np_bootstrap_confirm(np_state_t *context, np_key_t *confirmed) {

  char *connectionstr = NULL;
  np_spinlock_lock(&np_module(bootstrap)->bootstrap_points_lock);
  {
    connectionstr = np_get_connection_string_from(confirmed, true);
    np_tree_elem_t *ele =
        np_tree_find_str(np_module(bootstrap)->bootstrap_points, connectionstr);
    if (ele != NULL) {
      __np_bootstrap_confirm(context,
                             confirmed,
                             connectionstr,
                             ele->val.value.v);
    } else {
      free(connectionstr);
      char *wildcard_connectionstr =
          np_get_connection_string_from(confirmed, false);
      asprintf(&connectionstr, "*:%s", wildcard_connectionstr);
      free(wildcard_connectionstr);
      np_tree_elem_t *ele =
          np_tree_find_str(np_module(bootstrap)->bootstrap_points,
                           connectionstr);
      if (ele != NULL) {
        __np_bootstrap_confirm(context,
                               confirmed,
                               connectionstr,
                               ele->val.value.v);
      }
    }
  }
  np_spinlock_unlock(&np_module(bootstrap)->bootstrap_points_lock);
  free(connectionstr);
}

void np_bootstrap_remove(np_state_t *context, const char *connectionstr) {

  np_spinlock_lock(&np_module(bootstrap)->bootstrap_points_lock);
  {
    np_tree_elem_t *ele =
        np_tree_find_str(np_module(bootstrap)->bootstrap_points, connectionstr);
    if (ele != NULL) {
      np_unref_obj(np_key_t, ele->val.value.v, ref_bootstrap_list);
      np_tree_del_str(np_module(bootstrap)->bootstrap_points, connectionstr);
    }
  }
  np_spinlock_unlock(&np_module(bootstrap)->bootstrap_points_lock);
}
