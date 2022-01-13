//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <inttypes.h>
#include <pthread.h>

#include "np_legacy.h"
#include "np_shutdown.h"

#include "neuropil_log.h"
#include "np_log.h"

#include "np_key.h"
#include "np_keycache.h"
#include "np_threads.h"
#include "np_types.h"
#include "util/np_list.h"
#include "np_route.h"
#include "util/np_tree.h"
#include "core/np_comp_msgproperty.h"
#include "np_jobqueue.h"
#include "np_util.h"
#include "np_message.h"
#include "np_settings.h"
#include "np_constants.h"

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_destroycallback_t);
NP_SLL_GENERATE_IMPLEMENTATION(np_destroycallback_t);

#define __NP_SHUTDOWN_SIGNAL SIGINT

NP_SLL_GENERATE_IMPLEMENTATION(np_state_ptr);
np_sll_t(np_state_ptr, context_list) = NULL;

np_module_struct(shutdown) {
    np_state_t* context;
    TSP(sll_return(np_destroycallback_t), on_destroy);
    bool invoke;
    struct sigaction sigact;
};

static void __np_shutdown_signal_handler(int sig)
{
    sll_iterator(np_state_ptr) iter = NULL;

    if(context_list!=NULL){
        if (FLAG_CMP(sig, __NP_SHUTDOWN_SIGNAL)) {
            for (iter = sll_first(context_list);iter != NULL;sll_next(iter))
            {
                np_thread_t* self = _np_threads_get_self((np_state_t*)iter->val);
                np_ctx_memory(self);
                log_debug(LOG_MISC, "Received shutdown signal");
                np_module(shutdown)->invoke = true;
            }
        }
    }
}

void np_shutdown_add_callback(np_context*ac, np_destroycallback_t clb) {
    np_ctx_cast(ac);

    if (np_module_not_initiated(shutdown)) return;

    np_spinlock_lock(&np_module(shutdown)->on_destroy_lock);
    {
        sll_append(np_destroycallback_t, np_module(shutdown)->on_destroy, clb);
    }
    np_spinlock_unlock(&np_module(shutdown)->on_destroy_lock);
}

bool np_shutdown_check(np_state_t* context, NP_UNUSED np_util_event_t event)
{
    if (np_module(shutdown)->invoke) {
        log_warn(LOG_MISC, "Received terminating process signal. Shutdown in progress.");
        np_destroy(context, false);
    }
    return true;
}

void _np_shutdown_init(np_state_t* context) {

    if (np_module_not_initiated(shutdown)) {
        if(context_list == NULL){
            sll_init(np_state_ptr, context_list);
        }
        sll_append(np_state_ptr, context_list, (np_state_ptr)context);
        np_module_malloc(shutdown);
        TSP_INITD(_module->on_destroy, sll_init_part(np_destroycallback_t));
        _module->invoke = false;

        memset(&_module->sigact, 0, sizeof(_module->sigact));
        _module->sigact.sa_handler = __np_shutdown_signal_handler;
        sigemptyset(&_module->sigact.sa_mask);
        _module->sigact.sa_flags = 0;
        int res = sigaction(__NP_SHUTDOWN_SIGNAL, &_module->sigact, NULL);
        log_debug(LOG_MISC, "Init signal %d", res);

        np_jobqueue_submit_event_periodic(context, PRIORITY_MOD_LEVEL_5, 0.05, 0.05, np_shutdown_check, "np_shutdown_check");
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

void _np_shutdown_run_callbacks(np_context*ac) 
{
    np_ctx_cast(ac);

    if (np_module_not_initiated(shutdown)) return;

    np_spinlock_lock(&np_module(shutdown)->on_destroy_lock);
    {
        np_destroycallback_t clb;
        while ((clb = sll_head(np_destroycallback_t, np_module(shutdown)->on_destroy)) != NULL)
        {
            clb(context);
        }
    }
    np_spinlock_unlock(&np_module(shutdown)->on_destroy_lock);
}

void _np_shutdown_notify_others(np_context* ctx) 
{
    NP_CAST(ctx, np_state_t, context);

    np_sll_t(np_key_ptr, routing_table)  = _np_route_get_table(context);
    np_sll_t(np_key_ptr, neighbours_table) = _np_route_neighbors(context);
    np_sll_t(np_key_ptr, merge_table) = sll_merge(np_key_ptr, routing_table, neighbours_table, _np_key_cmp);

    sll_iterator(np_key_ptr) iter_keys = sll_first(merge_table);
    while (iter_keys != NULL)
    {
        np_dhkey_t leave_dhkey = iter_keys->val->dhkey;
        np_util_event_t shutdown_evt = { .type=(evt_internal|evt_shutdown), .context=context, .user_data=NULL, .target_dhkey=leave_dhkey };
        _np_keycache_handle_event(context, leave_dhkey, shutdown_evt, true);
        sll_next(iter_keys);
    }
    // TODO: wait for node components to switch state to IN_DESTROY

    sll_free(np_key_ptr, merge_table);
    np_key_unref_list(routing_table, "_np_route_get_table");
    sll_free(np_key_ptr, routing_table);
    np_key_unref_list(neighbours_table, "_np_route_neighbors");
    sll_free(np_key_ptr, neighbours_table);
}
