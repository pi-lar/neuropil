//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include "util/np_event.h"
#include "util/np_statemachine.h"

#ifndef _NP_COMP_IDENTITY_H_
#define _NP_COMP_IDENTITY_H_



#ifdef __cplusplus
extern "C" {
#endif

NP_API_INTERN
bool __is_identity_aaatoken(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
bool __is_identity_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
bool __is_identity_authn(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_set_identity(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_identity_update(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_identity_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_create_identity_network(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
bool __is_unencrypted_np_message(np_util_statemachine_t* statemachine, const np_util_event_t event);

NP_API_INTERN
void __np_identity_extract_handshake(np_util_statemachine_t* statemachine, const np_util_event_t event);

#ifdef __cplusplus
}
#endif

#endif /* _NP_COMP_IDENTITY_H_ */
