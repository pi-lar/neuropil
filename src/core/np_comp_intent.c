//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that an identity can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include "core/np_comp_intent.h"

#include "neuropil.h"

#include "np_aaatoken.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "np_legacy.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"

bool __is_intent_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);

    bool ret = false;
    
    NP_CAST(statemachine->_user_data, np_key_t, intent_key);
    NP_CAST(event.user_data, np_aaatoken_t, intent_token);

    if (!ret) ret  = (intent_key->type == np_key_type_intent);
    if ( ret) ret &= _np_memory_rtti_check(intent_token, np_memory_types_np_aaatoken_t);
    if ( ret) ret &= _np_aaatoken_is_valid(intent_token, np_aaatoken_type_message_intent);

    return ret;
} 
void __np_set_intent(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    // _np_aaatopen_create_ledger(...);
    // np_statemachine_handle_event(...);
}

bool __is_recveiver_intent_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    bool ret = __is_intent_token(statemachine, event);
    // ...
} 
bool __is_sender_intent_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    bool ret = __is_intent_token(statemachine, event);
    // ...
} 

// add intent token
void __np_intent_receiver_update(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    // _np_aaatoken_add_receiver();    
} 
void __np_intent_sender_update(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    // _np_aaatoken_add_sender();
}

bool __is_intent_auth_nz(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
bool __is_intent_authz(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_intent_update(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // add authorization for intent token

bool __is_intent_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_intent_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // no updates received for xxx minutes?

void __np_intent_check(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // send out intents if dht distance is not mmatching anymore
