//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <inttypes.h>

#include "np_legacy.h"
#include "np_shutdown.h"

#include "np_log.h"

#include "np_key.h"
#include "np_keycache.h"
#include "np_threads.h"
#include "np_types.h"
#include "np_list.h"
#include "np_route.h"
#include "np_tree.h"
#include "np_msgproperty.h"
#include "np_jobqueue.h"
#include "np_util.h"
#include "np_message.h"
#include "np_settings.h"
#include "np_constants.h"

NP_SLL_GENERATE_IMPLEMENTATION(np_destroycallback_t);

#define __NP_SHUTDOWN_SIGNAL SIGINT
np_module_struct(shutdown) {
    np_state_t* context;
    TSP(sll_return(np_destroycallback_t), on_destroy);
    bool invoke;
    struct sigaction sigact;
}; 

static void __np_shutdown_signal_handler(int sig) {
    np_thread_t* self = _np_threads_get_self(NULL);
    np_ctx_memory(self);
    log_debug(LOG_MISC, "Received signal %d", sig);
    if (FLAG_CMP(sig, __NP_SHUTDOWN_SIGNAL)) {
        np_module(shutdown)->invoke = true;
    }
}

void np_shutdown_add_callback(np_context*ac, np_destroycallback_t clb) {
    np_ctx_cast(ac);

    TSP_SCOPE(np_module(shutdown)->on_destroy) {
        sll_append(np_destroycallback_t, np_module(shutdown)->on_destroy, clb);
    }
}

void np_shutdown_check(np_state_t* context, NP_UNUSED np_jobargs_t args) {    
    if (np_module(shutdown)->invoke) {     
        log_warn(LOG_MISC, "Received terminating process signal. Shutdown in progress.");
        np_destroy(context, false);   
    }
}

void _np_shutdown_init(np_state_t* context) {

    if (!np_module_initiated(shutdown)) {
        np_module_malloc(shutdown);
        TSP_INITD(_module->on_destroy, sll_init_part(np_destroycallback_t));
        _module->invoke = false;

        memset(&_module->sigact, 0, sizeof(_module->sigact));
        _module->sigact.sa_handler = __np_shutdown_signal_handler;
        sigemptyset(&_module->sigact.sa_mask);
        _module->sigact.sa_flags = 0;            
        int res = sigaction(__NP_SHUTDOWN_SIGNAL, &_module->sigact, NULL);
        log_debug(LOG_MISC, "Init signal %d", res);

        np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_5, 0.01, 0.01, np_shutdown_check, "np_shutdown_check");
    }
}
void _np_shutdown_destroy(np_state_t* context) {

    if (np_module_initiated(shutdown)) {
        np_module_var(shutdown);
  
        TSP_DESTROY(_module->on_destroy);
        sll_free(np_destroycallback_t, _module->on_destroy);
    
        np_module_free(shutdown);
    }    
}

void _np_shutdown_run_callbacks(np_context*ac) {
    np_ctx_cast(ac);

    np_destroycallback_t clb;
    TSP_SCOPE(np_module(shutdown)->on_destroy) {
        while ((clb = sll_head(np_destroycallback_t, np_module(shutdown)->on_destroy)) != NULL)
        {
            clb(context);
        }
    }
}

void np_shutdown_notify_others(np_state_t* context) {
    np_sll_t(np_key_ptr, routing_table)  = _np_route_get_table(context);
    np_sll_t(np_key_ptr, neighbours_table) = _np_route_neighbors(context);
    np_sll_t(np_key_ptr, merge_table) = sll_merge(np_key_ptr, routing_table, neighbours_table, _np_key_cmp);

    sll_init_full(np_message_ptr, msgs);

    sll_iterator(np_key_ptr) iter_keys = sll_first(merge_table);
    while (iter_keys != NULL)
    {
        sll_append(np_message_ptr, msgs, _np_send_simple_invoke_request_msg(iter_keys->val, _NP_MSG_LEAVE_REQUEST));

        sll_next(iter_keys);
    }

    // wait for msgs to be acked
    sll_iterator(np_message_ptr) iter_msgs = sll_first(msgs);
    while (iter_msgs != NULL)
    {		
        bool msgs_is_out = false;
        while (!msgs_is_out) {
            TSP_GET(bool, iter_msgs->val->is_acked, is_acked);
            TSP_GET(bool, iter_msgs->val->is_in_timeout, is_in_timeout);
            if (is_acked || is_in_timeout) {				
                np_unref_obj(np_message_t, iter_msgs->val, "_np_send_simple_invoke_request_msg"); 
                msgs_is_out = true;
            }
            else {
                np_run(context, NP_PI/300);
            }
        }

        sll_next(iter_msgs);
    }

    sll_free(np_message_ptr, msgs);
    sll_free(np_key_ptr, merge_table);
    np_key_unref_list(routing_table, "_np_route_get_table");
    sll_free(np_key_ptr, routing_table);
    np_key_unref_list(neighbours_table, "_np_route_neighbors");
    sll_free(np_key_ptr, neighbours_table);
}
