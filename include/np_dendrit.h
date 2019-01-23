//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_DENDRIT_H_
#define _NP_DENDRIT_H_

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// input message handlers
NP_API_INTERN
void _np_in_handshake(np_state_t* context, np_jobargs_t args);

NP_API_INTERN
void _np_in_received(np_state_t* context, np_key_t* alias_key, void* data_blob);

NP_API_INTERN
void _np_in_piggy (np_state_t* context, np_jobargs_t args);
NP_API_INTERN
void _np_in_update (np_state_t* context, np_jobargs_t args);
NP_API_INTERN
void _np_in_ack(np_state_t* context, np_jobargs_t args);
NP_API_INTERN
void __np_in_ack_handle(np_message_t * msg);

NP_API_INTERN
void _np_in_join_req(np_state_t* context, np_jobargs_t args);
NP_API_INTERN
void _np_in_join_ack (np_state_t* context, np_jobargs_t args);
NP_API_INTERN
void _np_in_join_nack (np_state_t* context, np_jobargs_t args);

NP_API_INTERN
void _np_in_leave_req(np_state_t* context, np_jobargs_t args);

NP_API_INTERN
void _np_in_discover_receiver(np_state_t* context, np_jobargs_t args);
NP_API_INTERN
void _np_in_discover_sender(np_state_t* context, np_jobargs_t args);
NP_API_INTERN
void _np_in_available_sender(np_state_t* context, np_jobargs_t args);
NP_API_INTERN
void _np_in_available_receiver(np_state_t* context, np_jobargs_t args);

NP_API_INTERN
void _np_in_authenticate(np_state_t* context, np_jobargs_t args);
NP_API_INTERN
void _np_in_authenticate_reply(np_state_t* context, np_jobargs_t args);

NP_API_INTERN
void _np_in_authorize(np_state_t* context, np_jobargs_t args);
NP_API_INTERN
void _np_in_authorize_reply(np_state_t* context, np_jobargs_t args);

NP_API_INTERN
void _np_in_account(np_state_t* context, np_jobargs_t args);

NP_API_INTERN
void _np_in_signal_np_receive (np_state_t* context, np_jobargs_t args);
NP_API_INTERN
void _np_in_callback_wrapper(np_state_t* context, np_jobargs_t args);
NP_API_INTERN
void _np_in_new_msg_received(np_message_t* msg_to_submit, np_msgproperty_t* handler, bool allow_destination_ack);


NP_API_INTERN
    void _np_dendrit_propagate_senders(np_dhkey_t target_to_receive_tokens, np_message_intent_public_token_t* msg_token, bool inform_counterparts);
NP_API_INTERN
    void _np_dendrit_propagate_receivers(np_dhkey_t target_to_receive_tokens, np_message_intent_public_token_t* msg_token, bool inform_counterparts);
NP_API_INTERN
    void _np_dendrit_propagate_list(np_msgproperty_t* subject_property, np_dhkey_t target, np_sll_t(np_aaatoken_ptr, list_to_send));
#ifdef __cplusplus
}
#endif

#endif // _NP_HANDLER_H_
