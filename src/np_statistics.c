//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include <stdint.h>
#include <inttypes.h>
#include <math.h>

#include "np_legacy.h"
#include "np_types.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_scache.h"
#include "np_list.h"
#include "np_threads.h"
#include "np_route.h"
#include "np_util.h"
#include "np_key.h"
#include "np_jobqueue.h"

#include "np_statistics.h"

struct np_statistics_element_s {
    bool watch_receive;
    bool watch_send;

    uint32_t total_received;
    uint32_t total_send;
    uint32_t last_total_received;
    uint32_t last_total_send;

    uint32_t last_min_received;
    uint32_t last_min_send;
    uint32_t last_total_min_received;
    uint32_t last_total_min_send;
    double last_mindiff_received;
    double last_mindiff_send;
    double last_min_check;

    uint32_t last_sec_received;
    uint32_t last_sec_send;
    uint32_t last_total_sec_received;
    uint32_t last_total_sec_send;
    double last_secdiff_received;
    double last_secdiff_send;
    double last_sec_check;

    double first_check;
};
typedef struct np_statistics_element_s np_statistics_element_t;

bool _np_statistics_receive_msg_on_watched(np_context* ac, const np_message_t* const msg, NP_UNUSED np_tree_t* body, NP_UNUSED void* localdata)
{
    np_ctx_cast(ac);
    assert(msg != NULL);

    np_cache_item_t* item = np_simple_cache_get(context, np_module(statistics)->__cache, _np_message_get_subject(msg));
    if (item != NULL) {
        ((np_statistics_element_t*)item->value)->total_received += 1;
    }
    return true;
}

bool _np_statistics_send_msg_on_watched(np_context* ac, const np_message_t* const msg, NP_UNUSED np_tree_t* body, NP_UNUSED void* localdata)
{
    np_ctx_cast(ac);
    assert(msg != NULL);	

    np_cache_item_t* item = np_simple_cache_get(context, np_module(statistics)->__cache, _np_message_get_subject(msg));
    if (item != NULL) {
        ((np_statistics_element_t*)item->value)->total_send += 1;
    }

    return true; 
}

bool _np_statistics_init(np_state_t* context) {

    if (!np_module_initiated(statistics)) {
        np_module_malloc(statistics);

        np_module(statistics)->__cache = np_cache_init(context);
        sll_init(char_ptr, np_module(statistics)->__watched_subjects);

        TSP_INITD(np_module(statistics)->__forwarding_counter, 0);
        TSP_INITD(np_module(statistics)->__network_send_bytes, 0);
        TSP_INITD(np_module(statistics)->__network_received_bytes, 0);

        np_module(statistics)->__network_received_bytes_per_sec_last = 
            np_module(statistics)->__network_send_bytes_per_sec_last = np_time_now();

#ifdef DEBUG_CALLBACKS
        sll_init(void_ptr, np_module(statistics)->__np_debug_statistics);
#endif
    }
    return true;
}

bool np_statistics_destroy(np_state_t* context) {
    if (np_module_initiated(statistics)) {
        sll_iterator(char_ptr) iter = sll_first(np_module(statistics)->__watched_subjects);
        while (iter != NULL)
        {
            free(np_simple_cache_get(context, np_module(statistics)->__cache, iter->val)->value);
            free(iter->val);
            sll_next(iter);
        }

        sll_free(char_ptr, np_module(statistics)->__watched_subjects);
        free(np_module(statistics)->__cache);
    }
    return true;
}

void np_statistics_add_watch(np_state_t* context, char* subject) {	

    bool addtolist = true;
    sll_iterator(char_ptr) iter_subjects = sll_first(np_module(statistics)->__watched_subjects);
    while (iter_subjects != NULL)
    {
        if (strncmp(iter_subjects->val, subject, strlen(subject)) == 0) {
            addtolist = false;
            break;
        }
        sll_next(iter_subjects);
    }

    char* key = subject;
    if (addtolist == true) {
        key = strdup(subject);
        sll_append(char_ptr, np_module(statistics)->__watched_subjects, key);
        np_simple_cache_insert(context, np_module(statistics)->__cache, key, calloc(1, sizeof(np_statistics_element_t)));
    }

    np_statistics_element_t* container = np_simple_cache_get(context, np_module(statistics)->__cache, key)->value;

    if (addtolist == true) {
        CHECK_MALLOC(container);
        container->last_sec_check =
            container->last_min_check =
            container->first_check =
            np_time_now();
    }

    if (false == container->watch_receive && np_msgproperty_get(context, INBOUND, key) != NULL) {
        container->watch_receive = true;
        np_add_receive_listener(context, _np_statistics_receive_msg_on_watched, NULL, key);
    }

    if (false == container->watch_send && np_msgproperty_get(context, OUTBOUND, key) != NULL) {
        container->watch_send = true;
        np_add_send_listener(context, _np_statistics_send_msg_on_watched, NULL, key);
    }
}

void np_statistics_add_watch_internals(np_state_t* context) {
    
    //np_statistics_add_watch(context, _DEFAULT);
        
    np_statistics_add_watch(context, _NP_MSG_ACK);
    np_statistics_add_watch(context, _NP_MSG_HANDSHAKE);
    
    np_statistics_add_watch(context, _NP_MSG_PING_REQUEST);
    np_statistics_add_watch(context, _NP_MSG_LEAVE_REQUEST);
    np_statistics_add_watch(context, _NP_MSG_JOIN);
    np_statistics_add_watch(context, _NP_MSG_JOIN_REQUEST);
    np_statistics_add_watch(context, _NP_MSG_JOIN_ACK);
    np_statistics_add_watch(context, _NP_MSG_JOIN_NACK);
    
    np_statistics_add_watch(context, _NP_MSG_PIGGY_REQUEST);
    np_statistics_add_watch(context, _NP_MSG_UPDATE_REQUEST);	
    
    np_statistics_add_watch(context, _NP_MSG_DISCOVER_RECEIVER);
    np_statistics_add_watch(context, _NP_MSG_DISCOVER_SENDER);
    np_statistics_add_watch(context, _NP_MSG_AVAILABLE_RECEIVER);
    np_statistics_add_watch(context, _NP_MSG_AVAILABLE_SENDER);
    
    if(context->enable_realm_server || context->enable_realm_client){
        np_statistics_add_watch(context, _NP_MSG_AUTHENTICATION_REQUEST);
        np_statistics_add_watch(context, _NP_MSG_AUTHENTICATION_REPLY);
        np_statistics_add_watch(context, _NP_MSG_AUTHORIZATION_REQUEST);
        np_statistics_add_watch(context, _NP_MSG_AUTHORIZATION_REPLY);
    }
    np_statistics_add_watch(context, _NP_MSG_ACCOUNTING_REQUEST);
    
}

char * np_statistics_print(np_state_t* context, bool asOneLine) {
    if (!np_module_initiated(statistics)) {
        return strdup("statistics not initiated\n");
    }

    char * ret = NULL;

    char* new_line = "\n";
    if (asOneLine == true) {
        new_line = "    ";
    }
    ret = np_str_concatAndFree(ret, "-%s", new_line);

    sll_iterator(char_ptr) iter_subjects = sll_first(np_module(statistics)->__watched_subjects);

    double sec_since_start;

    double current_min_send;
    double current_min_received;
    double min_since_last_print;

    double current_sec_send;
    double current_sec_received;
    double sec_since_last_print;

    double now = np_time_now();


    uint32_t
        all_total_send = 0,
        all_total_received = 0;


    while (iter_subjects != NULL)
    {
        np_statistics_element_t* container = np_simple_cache_get(context, np_module(statistics)->__cache, iter_subjects->val)->value;

        sec_since_start = (now - container->first_check);

        // per Min calc
        min_since_last_print = (now - container->last_min_check) / 60;

        if (min_since_last_print > 1) {
            current_min_received = (container->total_received - container->last_total_min_received) / min_since_last_print;
            current_min_send = (container->total_send - container->last_total_min_send) / min_since_last_print;

            container->last_mindiff_received = current_min_received - container->last_min_received;
            container->last_mindiff_send = current_min_send - container->last_min_send;

            container->last_min_received = current_min_received;
            container->last_min_send = current_min_send;
            container->last_min_check = now;
            container->last_total_min_received = container->total_received;
            container->last_total_min_send = container->total_send;
        }
        else if ((sec_since_start / 60) < 1) {
            current_min_received = container->total_received;
            current_min_send = container->total_send;

            container->last_mindiff_received = current_min_received;
            container->last_mindiff_send = current_min_send;
        }
        else {
            current_min_received = container->last_min_received;
            current_min_send = container->last_min_send;
        }
        // per Min calc end

        // per Sec calc
        sec_since_last_print = (now - container->last_sec_check);

        if (sec_since_last_print > 1) {
            current_sec_received = (container->total_received - container->last_total_sec_received) / sec_since_last_print;
            current_sec_send = (container->total_send - container->last_total_sec_send) / sec_since_last_print;

            container->last_secdiff_received = current_sec_received - container->last_sec_received;
            container->last_secdiff_send = current_sec_send - container->last_sec_send;

            container->last_sec_received = current_sec_received;
            container->last_sec_send = current_sec_send;
            container->last_sec_check = now;
            container->last_total_sec_received = container->total_received;
            container->last_total_sec_send = container->total_send;
        }
        else {
            current_sec_received = container->last_sec_received;
            current_sec_send = container->last_sec_send;
        }
        // per Sec calc end

        if (container->watch_receive) {
            all_total_received += container->total_received;
            ret = np_str_concatAndFree(ret,
                "received total: %7"PRIu32" (%5.1f[%+5.1f] per sec) (%7.1f[%+7.1f] per min) %s%s",
                container->total_received,
                current_sec_received, container->last_secdiff_received,
                current_min_received, container->last_mindiff_received,
                iter_subjects->val, new_line);
        }

        if (container->watch_send) {
            all_total_send += container->total_send;
            ret = np_str_concatAndFree(ret,
                "send     total: %7"PRIu32" (%5.1f[%+5.1f] per sec) (%7.1f[%+7.1f] per min) %s%s",
                container->total_send,
                current_sec_send, container->last_secdiff_send,
                current_min_send, container->last_mindiff_send,
                iter_subjects->val, new_line
            );
        }
        container->last_total_received = container->total_received;
        container->last_total_send = container->total_send;

        sll_next(iter_subjects);
    }

    char* details = ret;
    ret = NULL;	


    uint32_t routes = _np_route_my_key_count_routes(context);

    uint32_t tenth = 1;
    char tmp_format[512] = { 0 };
    uint32_t minimize[] = { routes, all_total_received + all_total_send, };
    char s[32];

    for (uint32_t i = 0; i < (sizeof(minimize) / sizeof(uint32_t)); i++) {
        snprintf(s, 32, "%d", minimize[i]);
        tenth = fmax(tenth, strlen(s));
    }

    snprintf(tmp_format, 512, "%-17s %%%"PRId32""PRIu32" Node:     %%s%%s", "received total:", tenth);
    ret = np_str_concatAndFree(ret, tmp_format, all_total_received, _np_key_as_str(context->my_node_key), new_line);
    snprintf(tmp_format, 512, "%-17s %%%"PRId32""PRIu32" Identity: %%s%%s", "send     total:", tenth);
    ret = np_str_concatAndFree(ret, tmp_format, all_total_send, ((context->my_identity == NULL) ? "-" : _np_key_as_str(context->my_identity)), new_line);

    snprintf(tmp_format, 512, "%-17s %%%"PRId32""PRIu32" Jobs:     %%"PRIu32" Forwarded Msgs: %%8.0f%%s", "total:", tenth);
    TSP_GET(double, np_module(statistics)->__forwarding_counter, __fw_counter_r);
    ret = np_str_concatAndFree(ret,
        tmp_format,
        all_total_send + all_total_received,
        np_jobqueue_count(context),
        __fw_counter_r,
        new_line);


    snprintf(tmp_format, 512, "%-17s %%"PRIu32"%%s", "Reachable nodes:");
    ret = np_str_concatAndFree(ret, tmp_format, routes, /*new_line*/"  ");
    snprintf(tmp_format, 512, "%-17s %%"PRIu32" (:= %%"PRIu32"|%%"PRIu32") ", "Neighbours nodes:");
    uint32_t l, r;
    uint32_t c = _np_route_my_key_count_neighbours(context, &l, &r);
    ret = np_str_concatAndFree(ret, tmp_format, c, l, r);


    snprintf(tmp_format, 512, "In: %8%s(%5%s) Out: %8%s(%5%s)%%s");
    uint32_t __network_send_bytes_r, __network_received_bytes_r;
    double timediff;
    static const double timediff_threshhold = 1;
    TSP_SCOPE(np_module(statistics)->__network_send_bytes)
    {
        __network_send_bytes_r = np_module(statistics)->__network_send_bytes;

        timediff = now - np_module(statistics)->__network_send_bytes_per_sec_last;
        if (timediff >= timediff_threshhold) {
            np_module(statistics)->__network_send_bytes_per_sec_r = (np_module(statistics)->__network_send_bytes - np_module(statistics)->__network_send_bytes_per_sec_remember) / timediff;
            np_module(statistics)->__network_send_bytes_per_sec_last = now;
            np_module(statistics)->__network_send_bytes_per_sec_remember = np_module(statistics)->__network_send_bytes;
        }
    }
    TSP_SCOPE(np_module(statistics)->__network_received_bytes)
    {
        __network_received_bytes_r = np_module(statistics)->__network_received_bytes;
        timediff = now - np_module(statistics)->__network_received_bytes_per_sec_last;
        if (timediff >= timediff_threshhold) {
            np_module(statistics)->__network_received_bytes_per_sec_r = (np_module(statistics)->__network_received_bytes - np_module(statistics)->__network_received_bytes_per_sec_remember) / timediff;
            np_module(statistics)->__network_received_bytes_per_sec_last = now;
            np_module(statistics)->__network_received_bytes_per_sec_remember = np_module(statistics)->__network_received_bytes;
        }
    }
    char b1[255], b2[255], b3[255], b4[255];
    ret = np_str_concatAndFree(ret,
        tmp_format,
        np_util_stringify_pretty(np_util_stringify_bytes, &__network_received_bytes_r, b1),
        np_util_stringify_pretty(np_util_stringify_bytes_per_sec, &(np_module(statistics)->__network_received_bytes_per_sec_r), b3),
        np_util_stringify_pretty(np_util_stringify_bytes, &__network_send_bytes_r, b2),
        np_util_stringify_pretty(np_util_stringify_bytes_per_sec, &(np_module(statistics)->__network_send_bytes_per_sec_r), b4),
        new_line);
    
    ret = np_str_concatAndFree(ret, "%s-%s",details, new_line);
    free(details);

    return ret;
}

#ifdef NP_STATISTICS_COUNTER
void __np_increment_forwarding_counter(np_state_t* context) {
    if (np_module_initiated(statistics)) {

        TSP_SCOPE(np_module(statistics)->__forwarding_counter) {
            np_module(statistics)->__forwarding_counter++;
        }
    }
}

void __np_statistics_add_send_bytes(np_state_t* context, uint32_t add) {
    if (np_module_initiated(statistics)) {
        TSP_SCOPE(np_module(statistics)->__network_send_bytes)
        {
            np_module(statistics)->__network_send_bytes += add;
        }
    }
}

void __np_statistics_add_received_bytes(np_state_t* context, uint32_t add) {
    if (np_module_initiated(statistics)) {
        TSP_SCOPE(np_module(statistics)->__network_received_bytes)
        {
            np_module(statistics)->__network_received_bytes += add;
        }
    }
}
#endif
