//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netdb.h>
#include <inttypes.h>

#include "event/ev.h"
#include "tree/tree.h"

#include "np_constants.h"
#include "np_settings.h"
#include "neuropil_log.h"
#include "np_log.h"

#include "np_aaatoken.h"
#include "np_key.h"
#include "np_keycache.h"
#include "util/np_event.h"
#include "np_evloop.h"
#include "np_eventqueue.h"
#include "np_threads.h"
#include "np_legacy.h"
#include "np_types.h"
#include "util/np_list.h"
#include "np_route.h"
#include "util/np_tree.h"
#include "core/np_comp_msgproperty.h"
#include "np_util.h"
#include "np_message.h"
#include "np_messagepart.h"
#include "np_memory.h"
#include "np_statistics.h"

const char _np_ref_event_runtime[] = "_np_event_runtime";

#define np_event_runtime_max_size 1000
struct np_event_runtime_s {
    np_util_event_t __chained_events[np_event_runtime_max_size];
    volatile uint8_t __chained_events_size;
};
/**
 * @brief Adds an event to a given event chain to be executed after the current key lock is released.
 * 
 * @param[in] context The application Context to work in
 * @param[in] runtime The event chain object
 * @param[in] dhkey The target key for the event
 * @param[in] event The event configuration itself
 */
void __np_event_runtime_add_event(np_state_t* context, np_event_runtime_t * runtime, np_dhkey_t dhkey, np_util_event_t event, char * fn_source)
{
#ifdef DEBUG
    event.__fn_source = fn_source;
#endif
    if(runtime == NULL){
        __np_event_runtime_start_with_event(context, dhkey, event, fn_source);
        return;
    }
    
    if(runtime->__chained_events_size >= np_event_runtime_max_size)
    {
        // IS ERROR 
        for(uint8_t _idx =0;_idx<runtime->__chained_events_size;_idx++){
            np_util_event_t next_event = runtime->__chained_events[_idx];
            np_key_t * __source_key = _np_keycache_find_or_create(context, next_event.__source_dhkey);

            log_error("event@%"PRIu8" event_type: %"PRIu32" key: %s key_type: %"PRIu32" userdata_type: %"PRIu32" id: %s",
                _idx, next_event.type, _np_key_as_str(__source_key), __source_key->type,
                np_memory_get_type(next_event.user_data),
                next_event.user_data != NULL &&  _np_memory_rtti_check(next_event.user_data,np_memory_types_np_message_t) ? 
                ((np_message_t*)next_event.user_data)->uuid : 
                (next_event.user_data != NULL &&  _np_memory_rtti_check(next_event.user_data,np_memory_types_np_messagepart_t) ? ((np_messagepart_t*)next_event.user_data)->uuid
                : "no id")
            );
        }
    }
    ASSERT((runtime->__chained_events_size) < np_event_runtime_max_size,
        "Maximum event chaining reached %"PRIu8"/%"PRIu8,
        runtime->__chained_events_size,np_event_runtime_max_size
    );
    np_key_t * __source_key = _np_keycache_find(context, dhkey);

    if(__source_key != NULL){
        log_debug(LOG_EVENT, "ADDING event@%"PRIu8" event_type: %"PRIu32" key: %s key_type: %"PRIu8" userdata_type: %"PRIu32" id: %s",
            runtime->__chained_events_size, 
            event.type,
            _np_key_as_str(__source_key),
            __source_key->type,
            np_memory_get_type(event.user_data),            
            (event.user_data != NULL &&  _np_memory_rtti_check(event.user_data,np_memory_types_np_message_t) ? 
            ((np_message_t*)event.user_data)->uuid : 
            (event.user_data != NULL &&  _np_memory_rtti_check(event.user_data,np_memory_types_np_messagepart_t) ? 
            ((np_messagepart_t*)event.user_data)->uuid :
            (event.user_data != NULL &&  _np_memory_rtti_check(event.user_data,np_memory_types_np_aaatoken_t) ? 
            ((np_aaatoken_t*)event.user_data)->uuid :
            "no id")))
        ); 
        np_unref_obj(np_key_t,__source_key,"_np_keycache_find");
    }
    //ASSERT(!(runtime->__chained_events_size > 100 && event.type == 17 && _np_memory_rtti_check(event.user_data,np_memory_types_np_messagepart_t)),"TEST");

    event.__source_dhkey = dhkey;
    event.current_run = runtime;
    if(event.user_data != NULL){
        // increase the generic object reference counter (should not be nessecary but just in case)
        np_ref_obj(np_unknown_t, event.user_data, _np_ref_event_runtime);
    }
    runtime->__chained_events[runtime->__chained_events_size] = event;
    runtime->__chained_events_size++;
}
/**
 * @brief Starts a synchronus executed event chain.
 * 
 * @param[in] context The application Context to work in.
 * @param[in] dhkey   The target key for the event
 * @param[in] event   The event configuration itself
 */
void __np_event_runtime_start_with_event(np_state_t* context, np_dhkey_t dhkey, np_util_event_t event, char * source)
{
    np_event_runtime_t _run= {0};

    char run_id[NP_UUID_BYTES];
    char * run_id2 = run_id;
    np_uuid_create("ASDASDDSAAD", 5455, &run_id2);

    // add event to own chain
    __np_event_runtime_add_event(context, &_run, dhkey, event, source);
    log_info(LOG_EVENT,"start event chain %s for event_type: %"PRIu32" user_data:%p",
        run_id,
        event.type,
        event.user_data
    );

    // iterate over event chain (which may increase with each executed event )
    uint8_t chained_events_idx = 0;
    while(chained_events_idx < _run.__chained_events_size) {
        np_util_event_t next_event = _run.__chained_events[chained_events_idx];
        next_event.cleanup = NULL;
        //next_event.__user_data = next_event.user_data;
        log_info(LOG_EVENT,"run event chain %s / %"PRIu8" %s",
            run_id,
            chained_events_idx,
            #ifdef DEBUG 
                next_event.__fn_source
            #else  
                ""
            #endif
        );
        _np_keycache_execute_event(context, next_event.__source_dhkey, next_event);
        log_debug(LOG_EVENT,"completed event chain %s / %"PRIu8" %s",
            run_id,
            chained_events_idx,
            next_event.__fn_source
        );
        chained_events_idx++;
    }
    log_info(LOG_EVENT,"begin with event cleanup %s", &run_id);
    // release all associated data and run cleanup functions
    chained_events_idx = 0;
    while(chained_events_idx < _run.__chained_events_size) {
        np_util_event_t next_event = _run.__chained_events[chained_events_idx];
        log_info(LOG_EVENT,"cleanup event chain %s %"PRIu8, run_id, chained_events_idx);

        if(next_event.cleanup != NULL){
            next_event.cleanup(context, next_event);
        }
        if(next_event.user_data != NULL){
            np_unref_obj(np_unknown_t, next_event.user_data, _np_ref_event_runtime);
        }
        chained_events_idx++;
    }

    log_debug(LOG_EVENT|LOG_VERBOSE,
        "Event chain depth at %"PRIu8" (%5.1f%%)",
        chained_events_idx,
        (chained_events_idx/(np_event_runtime_max_size+.0))*100
    );
}