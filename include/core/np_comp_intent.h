//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that
// an identity can have. It is included form np_key.c, therefore there are no
// extra #include directives.

#ifndef _NP_COMP_INTENT_H_
#define _NP_COMP_INTENT_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * mostly deprecated, most parts should be in the msgproperty component.
 */

#include "neuropil.h"

#include "core/np_comp_intent.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"

#include "np_key.h"
#include "np_keycache.h"
#include "np_memory.h"

enum crud_op {
  crud_unknown = 0,
  crud_create,
  crud_read,
  crud_update,
  crud_delete
};

NP_API_INTERN
bool __is_intent_authz(np_util_statemachine_t *statemachine,
                       const np_util_event_t   event);

NP_API_INTERN
void __np_intent_check(
    np_util_statemachine_t *statemachine,
    const np_util_event_t
        event); // send out intents if dht distance is not mmatching anymore

NP_API_INTERN
np_aaatoken_t *_np_intent_add_sender(np_key_t      *subject_key,
                                     np_aaatoken_t *token);
NP_API_INTERN
np_aaatoken_t *_np_intent_add_receiver(np_key_t      *subject_key,
                                       np_aaatoken_t *token);

NP_API_INTERN
np_aaatoken_t *_np_intent_get_sender_token(np_key_t        *subject_key,
                                           const np_dhkey_t sender_dhkey);
NP_API_INTERN
np_aaatoken_t *_np_intent_get_receiver(np_key_t        *subject_key,
                                       const np_dhkey_t target);

NP_API_INTERN
void _np_intent_get_all_receiver(np_key_t  *subject_key,
                                 np_dhkey_t audience,
                                 np_sll_t(np_aaatoken_ptr, *tmp_token_list));

NP_API_INTERN
bool _np_intent_get_ack_session(np_key_t   *subject_key,
                                np_dhkey_t  session_dhkey,
                                np_dhkey_t *ack_to_dhkey);

NP_API_INTERN
bool _np_intent_get_crypto_session(np_key_t            *subject_key,
                                   np_dhkey_t           target_dhkey,
                                   np_crypto_session_t *crypto_session);

NP_API_INTERN
bool _np_intent_has_crypto_session(np_key_t  *subject_key,
                                   np_dhkey_t session_dhkey);

NP_API_INTERN
void _np_intent_import_session(np_key_t    *subject_key,
                               np_tree_t   *crypto_tree,
                               enum crud_op crud);
NP_API_INTERN
void _np_intent_update_receiver_session(np_key_t      *subject_key,
                                        np_aaatoken_t *token,
                                        enum crud_op   crud);
NP_API_INTERN
void _np_intent_update_sender_session(np_key_t      *subject_key,
                                      np_aaatoken_t *token,
                                      enum crud_op   crud);
NP_API_INTERN
void _np_intent_update_session(np_key_t      *subject_key,
                               np_aaatoken_t *token,
                               bool           for_receiver,
                               enum crud_op   crud);

#ifdef __cplusplus
}
#endif

#endif /* _NP_COMP_MSGPROPERTY_H_ */
