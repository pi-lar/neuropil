//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that an identity can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include "stdio.h"
#include "inttypes.h"

#include "core/np_comp_alias.h"
#include "core/np_comp_node.h"

#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_key.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "np_message.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"


bool __is_alias_handshake_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: bool __is_alias_handshake_token(...) {");
    
    bool ret = false;
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_token) && FLAG_CMP(event.type, evt_internal);
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_np_aaatoken_t);
    if ( ret) {
        NP_CAST(event.user_data, np_aaatoken_t, hs_token);
        ret &= (hs_token->type == np_aaatoken_type_handshake);
        ret &= _np_aaatoken_is_valid(hs_token, hs_token->type);
    }
    return ret;
}

void __np_alias_set(np_util_statemachine_t* statemachine, const np_util_event_t event)
{   // handle internal received handsjake token
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void __np_alias_set(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);
    NP_CAST(event.user_data, np_aaatoken_t, handshake_token);

    np_node_t* alias_node = NULL;
    np_dhkey_t search_key = {0};

    _np_str_dhkey(handshake_token->issuer, &search_key);
    np_key_t* node_key = _np_keycache_find(context, search_key);
    if (node_key == NULL) 
    {
        alias_node = _np_node_from_token(handshake_token, handshake_token->type);
        alias_node->_handshake_status++;
    }
    else 
    {
        alias_node = _np_key_get_node(node_key);
        log_debug_msg(LOG_DEBUG, "start: void __np_alias_set(...) %p / %p {", node_key, alias_node);
    }

    sll_append(void_ptr, alias_key->entities, handshake_token);
    sll_append(void_ptr, alias_key->entities, alias_node);
    np_ref_obj(no_node_t, alias_node, "__np_alias_set");

    alias_key->type |= np_key_type_alias;
    handshake_token->state = AAA_VALID;
}

void __np_create_session(np_util_statemachine_t* statemachine, const np_util_event_t event)
{   // create crypto session and "steal" node sructure
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_DEBUG, "start: void __np_create_session(...) {");

    NP_CAST(statemachine->_user_data, np_key_t, alias_key);
    NP_CAST(sll_first(alias_key->entities)->val, np_aaatoken_t, handshake_token);
    np_node_t* alias_node = _np_key_get_node(alias_key);

    np_aaatoken_t* my_token = _np_key_get_token(context->my_node_key);
    np_node_t* my_node = _np_key_get_node(context->my_node_key);

    // MUST be there
    np_tree_elem_t* remote_hs_prio = np_tree_find_str(handshake_token->extensions, NP_HS_PRIO);
    // COULD be there
    np_tree_elem_t* response_uuid = np_tree_find_str(handshake_token->extensions, _NP_MSG_INST_RESPONSE_UUID);
    
    if (response_uuid == NULL ||
        remote_hs_prio->val.value.ul > my_node->handshake_priority)
    {
        log_debug_msg(LOG_HANDSHAKE,
            "handshake session created in server mode. remote-prio: %"PRIu32" local-prio: %"PRIu32" ",
                remote_hs_prio->val.value.ul, my_node->handshake_priority
            );
        np_crypto_session(context,
                &my_token->crypto,
                &alias_node->session,
                &handshake_token->crypto,
                true
            );
    }
    else 
    {
        log_debug_msg(LOG_HANDSHAKE,
            "handshake session created in client mode. remote-prio: %"PRIu32" local-prio: %"PRIu32" ",
                remote_hs_prio->val.value.ul, my_node->handshake_priority
            );
        np_crypto_session(context,
                &my_token->crypto,
                &alias_node->session,
                &handshake_token->crypto,
                true
            );
    }
    alias_node->_handshake_status++;
    alias_node->session_key_is_set = true;

    log_debug_msg(LOG_DEBUG, "start: __np_create_session(...) { node now complete: %p / %p %d", alias_key, alias_node, alias_node->_handshake_status);
} 

bool __is_msg_join_ack(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_node_transfer_session(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // join acknowledge

bool __is_msg_join_nack(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_node_handle_leave(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // join hasn't been acknowledged, drop everything

bool __is_crypted_message(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_alias_decrypt(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // decrypt transport encryption

bool __is_dht_message(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_handle_np_message(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // handle ght messages (ping, piggy, ...)

bool __is_usr_message(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_handle_usr_msg(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // pass on to the specific message intent

bool __is_leave_message(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_handle_leave_msg(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // node has left, invalidate node


