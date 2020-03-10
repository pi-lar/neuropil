//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that an identity can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#ifndef _NP_COMP_INTENT_H_
#define _NP_COMP_INTENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "core/np_comp_intent.h"

#include "neuropil.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"

NP_API_INTERN
bool __is_intent_authz(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_intent_check(np_util_statemachine_t* statemachine, const np_util_event_t event); // send out intents if dht distance is not mmatching anymore

NP_API_INTERN
np_aaatoken_t* _np_intent_add_sender(np_key_t* subject_key, np_aaatoken_t *token);
NP_API_INTERN
np_aaatoken_t* _np_intent_add_receiver(np_key_t* subject_key, np_aaatoken_t *token);

NP_API_INTERN
np_aaatoken_t* _np_intent_get_sender_token(np_key_t* subject_key, const np_dhkey_t sender_dhkey);
NP_API_INTERN
np_aaatoken_t* _np_intent_get_receiver(np_key_t* subject_key, const np_dhkey_t target);

NP_API_INTERN
sll_return(np_aaatoken_ptr) _np_intent_get_all_sender(np_key_t* subject_key, const char* const audience);

NP_API_INTERN
sll_return(np_aaatoken_ptr) _np_intent_get_all_receiver(np_key_t* subject_key, const char* const audience);


#ifdef __cplusplus
}
#endif

#endif /* _NP_COMP_MSGPROPERTY_H_ */
