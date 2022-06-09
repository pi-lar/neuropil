//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_DENDRIT_H_
#define _NP_DENDRIT_H_

#include "util/np_event.h"

#include "np_dhkey.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// input message handlers
NP_API_INTERN
bool _np_in_handshake(np_state_t *context, np_util_event_t msg_event);

NP_API_INTERN
bool _check_and_send_destination_ack(np_state_t     *context,
                                     np_util_event_t msg_event);

NP_API_INTERN
bool _np_in_piggy(np_state_t *context, np_util_event_t msg_event);
NP_API_INTERN
bool _np_in_update(np_state_t *context, np_util_event_t msg_event);
NP_API_INTERN
bool _np_in_ping(np_state_t *context, np_util_event_t msg_event);
NP_API_INTERN
bool _np_in_ack(np_state_t *context, np_util_event_t msg_event);

NP_API_INTERN
bool _np_in_join(np_state_t *context, np_util_event_t msg_event);
NP_API_INTERN
bool _np_in_leave(np_state_t *context, np_util_event_t msg_event);

NP_API_INTERN
bool _np_in_discover_receiver(np_state_t *context, np_util_event_t msg_event);
NP_API_INTERN
bool _np_in_discover_sender(np_state_t *context, np_util_event_t msg_event);
NP_API_INTERN
bool _np_in_available_sender(np_state_t *context, np_util_event_t msg_event);
NP_API_INTERN
bool _np_in_available_receiver(np_state_t *context, np_util_event_t msg_event);

NP_API_INTERN
bool _np_in_pheromone(np_state_t *context, np_util_event_t msg_event);

NP_API_INTERN
bool _np_in_authenticate(np_state_t *context, np_util_event_t msg_event);
NP_API_INTERN
bool _np_in_authenticate_reply(np_state_t *context, np_util_event_t msg_event);

NP_API_INTERN
bool _np_in_authorize(np_state_t *context, np_util_event_t msg_event);
NP_API_INTERN
bool _np_in_authorize_reply(np_state_t *context, np_util_event_t msg_event);

NP_API_INTERN
bool _np_in_account(np_state_t *context, np_util_event_t msg_event);

NP_API_INTERN
bool _np_in_callback_wrapper(np_state_t *context, np_util_event_t msg_event);

#ifdef __cplusplus
}
#endif

#endif // _NP_HANDLER_H_
