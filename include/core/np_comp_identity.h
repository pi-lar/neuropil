//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "np_dhkey.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"

#ifndef _NP_COMP_IDENTITY_H_
#define _NP_COMP_IDENTITY_H_



#ifdef __cplusplus
extern "C" {
#endif

/**
 * a identity component is the representation of an internal or external identity running on a node.
 * it resides in memory at the fingerprint dhkey of its token.
 * Usually internal identities are used for authentication, authorization and accounting purposes.
 * The main substructure is therefore a token. If a private key is attached to teh token, then the
 * identity may also act as a node and open an internet port.
 * If no private key is present, the identity is used to maintain trust relations with peers, i.e.
 * one may import a pre-shared pki identity and use it to verify additional signatures.
 */
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
    void __np_identity_shutdown(np_util_statemachine_t* statemachine, const np_util_event_t event);

    NP_API_INTERN
    void __np_identity_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event);

    NP_API_INTERN
    void __np_create_identity_network(np_util_statemachine_t* statemachine, const np_util_event_t event);

    NP_API_INTERN
    bool __is_unencrypted_np_message(np_util_statemachine_t* statemachine, const np_util_event_t event);

    NP_API_INTERN
    void __np_extract_handshake(np_util_statemachine_t* statemachine, const np_util_event_t event);

    NP_API_INTERN
    bool __is_authn_request(np_util_statemachine_t* statemachine, const np_util_event_t event);

    NP_API_INTERN
    bool __is_authz_request(np_util_statemachine_t* statemachine, const np_util_event_t event);

    NP_API_INTERN
    void __np_identity_handle_authn(np_util_statemachine_t* statemachine, const np_util_event_t event);

    NP_API_INTERN
    void __np_identity_handle_authz(np_util_statemachine_t* statemachine, const np_util_event_t event);

    NP_API_INTERN
    bool __is_account_request(np_util_statemachine_t* statemachine, const np_util_event_t event);

    NP_API_INTERN
    void __np_identity_handle_account(np_util_statemachine_t* statemachine, const np_util_event_t event);


#ifdef __cplusplus
}
#endif

#endif /* _NP_COMP_IDENTITY_H_ */
