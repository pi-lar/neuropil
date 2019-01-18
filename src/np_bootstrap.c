//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "np_constants.h"
#include "np_legacy.h"
#include "np_settings.h"
#include "np_util.h"
#include "np_log.h"
#include "np_tree.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_responsecontainer.h"

#include "np_legacy.h"
#include "np_bootstrap.h"


np_module_struct(bootstrap)
{
    np_state_t* context;	
    TSP(np_tree_t*, bootstrap_points);
};

void __np_bootstrap_on_timeout(const np_responsecontainer_t* const entry) {
    np_ctx_memory(entry);
    log_msg(LOG_WARN | LOG_ROUTING, "Bootstrap Node (%s) not reachable anymore. Try to reconnect", _np_key_as_str(entry->dest_key));
    char* reconnect = np_get_connection_string_from(entry->dest_key, true);
    np_send_join(context, reconnect);
    free(reconnect);
}

void __np_bootstrap_reconnect(np_state_t* context, NP_UNUSED  np_jobargs_t args) {
    TSP_SCOPE(np_module(bootstrap)->bootstrap_points) {
        np_tree_elem_t* iter = RB_MIN(np_tree_s, np_module(bootstrap)->bootstrap_points);
        while (iter != NULL) {
            if (iter->val.value.v != NULL) {				
                log_debug_msg(LOG_DEBUG | LOG_ROUTING, "Sending Ping to check bootstrap node is reachable (%s)", _np_key_as_str((np_key_t*)iter->val.value.v));
                
                np_message_t* out_msg = NULL;
                np_new_obj(np_message_t, out_msg);

                _np_message_create(out_msg, ((np_key_t*)iter->val.value.v)->dhkey, context->my_node_key->dhkey, _NP_MSG_PING_REQUEST, NULL);

                np_message_add_on_timeout(out_msg, __np_bootstrap_on_timeout);

                np_msgproperty_t* prop = np_msgproperty_get(context, OUTBOUND, _NP_MSG_PING_REQUEST);
                _np_job_submit_route_event(context, 0.0, prop, ((np_key_t*)iter->val.value.v), out_msg);
                np_unref_obj(np_message_t, out_msg, ref_obj_creation);
            }
            iter = RB_NEXT(np_tree_s, np_module(bootstrap)->bootstrap_points, iter);
        }
    }
}

bool _np_bootstrap_init(np_state_t* context)
{
    bool ret = false;
    if (!np_module_initiated(bootstrap)) {
        np_module_malloc(bootstrap);
        ret = true;
        TSP_INIT(_module->bootstrap_points);
        TSP_SCOPE(_module->bootstrap_points) {
            _module->bootstrap_points = np_tree_create();
        }
        np_job_submit_event_periodic(context,
            PRIORITY_MOD_LOWEST, 
            NP_BOOTSTRAP_REACHABLE_CHECK_INTERVAL, NP_BOOTSTRAP_REACHABLE_CHECK_INTERVAL,
            __np_bootstrap_reconnect,
            "__np_bootstrap_reconnect" 
        );		
    }
    return ret;
}
void _np_bootstrap_destroy(np_state_t* context)
{
    if (np_module_initiated(bootstrap)) {
        np_module_var(bootstrap);

        np_tree_free(_module->bootstrap_points);
        TSP_DESTROY(_module->bootstrap_points);
        np_module_free(bootstrap);
    }
}
void np_bootstrap_add(np_state_t* context, const char* connectionstr) {

    TSP_SCOPE(np_module(bootstrap)->bootstrap_points) {

        np_tree_insert_str(np_module(bootstrap)->bootstrap_points, connectionstr, np_treeval_new_v(NULL));
    }
}
void __np_bootstrap_confirm(np_state_t* context, np_key_t* confirmed, char* connectionstr, np_key_t* replaced) {
    if (confirmed != replaced) {
        np_ref_obj(np_key_t, confirmed, ref_bootstrap_list);
        np_tree_replace_str(np_module(bootstrap)->bootstrap_points, connectionstr, np_treeval_new_v(confirmed));
        np_unref_obj(np_key_t, replaced, ref_bootstrap_list);
    }
}

void _np_bootstrap_confirm(np_state_t* context, np_key_t* confirmed) {

    char * connectionstr = NULL;
    TSP_SCOPE(np_module(bootstrap)->bootstrap_points) {
        connectionstr  = np_get_connection_string_from(confirmed, true);		
        np_tree_elem_t* ele = np_tree_find_str(np_module(bootstrap)->bootstrap_points, connectionstr);
        if (ele != NULL) {
            __np_bootstrap_confirm(context, confirmed, connectionstr, ele->val.value.v);
        }
        else {
            free(connectionstr);
            char * wildcard_connectionstr = np_get_connection_string_from(confirmed, false);
            asprintf(&connectionstr, "*:%s", wildcard_connectionstr);
            free(wildcard_connectionstr);
            np_tree_elem_t* ele = np_tree_find_str(np_module(bootstrap)->bootstrap_points, connectionstr);
            if (ele != NULL) {
                __np_bootstrap_confirm(context, confirmed, connectionstr, ele->val.value.v);
            }
        }
    }
    free(connectionstr);
}

void np_bootstrap_remove(np_state_t* context, const char* connectionstr) {

    TSP_SCOPE(np_module(bootstrap)->bootstrap_points) {
        np_tree_elem_t* ele = np_tree_find_str(np_module(bootstrap)->bootstrap_points, connectionstr);
        if (ele != NULL) {
            np_unref_obj(np_key_t, ele->val.value.v, ref_bootstrap_list);
            np_tree_del_str(np_module(bootstrap)->bootstrap_points, connectionstr);
        }
    }
}
