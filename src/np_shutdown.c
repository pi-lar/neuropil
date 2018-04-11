#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <inttypes.h>

#include "neuropil.h"
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
#include "np_util.h"
#include "np_message.h"
#include "np_settings.h"
#include "np_constants.h"

struct sigaction sigact;
np_sll_t(void_ptr, __running_instances) = NULL;

static void __np_shutdown_signal_handler(int sig) {
	if (sig == SIGINT) {

		sll_iterator(void_ptr) iter_context = sll_first(__running_instances);
		while (iter_context != NULL)
		{
			sll_iterator(void_ptr) iter_context_old = iter_context;
			np_ctx_decl(iter_context->val);
			sll_next(iter_context);
			sll_delete(void_ptr, __running_instances, iter_context_old);

			TSP_SCOPE(context->__is_in_shutdown) {
				context->__is_in_shutdown = TRUE;
			}
			log_msg(LOG_WARN, "Received terminating process signal (%"PRIi32"). Shutdown in progress.", sig);
			np_destroy(context);			
		}
		exit(EXIT_SUCCESS);
	}
}

void _np_shutdown_init_auto_notify_others(np_state_t* context) {
	
	if (__running_instances == NULL) {
		sll_init(void_ptr, __running_instances);

		sigact.sa_handler = __np_shutdown_signal_handler;
		sigemptyset(&sigact.sa_mask);
		sigact.sa_flags = 0;
		//sigaction(SIGABRT, &sigact, (struct sigaction *)NULL);
		sigaction(SIGINT, &sigact, (struct sigaction *)NULL);
		//sigaction(SIGTERM, &sigact, (struct sigaction *)NULL);
	}
	sll_append(void_ptr, __running_instances, context);
}

void _np_shutdown_deinit() {
	sigemptyset(&sigact.sa_mask);
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
		np_bool msgs_is_out = FALSE;
		while (!msgs_is_out) {
			TSP_GET(np_bool, iter_msgs->val->is_acked, is_acked);
			TSP_GET(np_bool, iter_msgs->val->is_in_timeout, is_in_timeout);
			if (is_acked || is_in_timeout) {				
				np_unref_obj(np_message_t, iter_msgs->val, "_np_send_simple_invoke_request_msg"); 
				msgs_is_out = TRUE;
			}
			else {
				np_time_sleep(0.01);
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
