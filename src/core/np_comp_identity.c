//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that an identity can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include "core/np_comp_identity.h"

#include "stdint.h"
#include "inttypes.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_node.h"
#include "np_route.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"


// IN_SETUP -> IN_USE transition condition / action #1
bool __is_identity_aaatoken(np_util_statemachine_t* statemachine, const np_util_event_t event) {

    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __is_identity_aaatoken(...){");

    bool ret = false;

    if (!ret) ret  = FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_token);
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
    if ( ret) 
    {
        NP_CAST(event.user_data, np_aaatoken_t, identity);
        ret &= (  identity->type == np_aaatoken_type_identity                             ) ||
               ( (identity->type == np_aaatoken_type_node) && identity->private_key_is_set);

        ret &= _np_aaatoken_is_valid(identity, identity->type);
    }
    return ret;
}

// IN_USE -> IN_DESTROY transition condition / action #1
bool __is_identity_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __is_identity_invalid(...){");

    bool ret = false;
    
    NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);
    
    if (!ret) ret = (sll_size(my_identity_key->entities) == 1);
    if ( ret) {
        NP_CAST(sll_first(my_identity_key->entities)->val, np_aaatoken_t, identity);
        ret &= (  identity->type == np_aaatoken_type_identity                             ) ||
               ( (identity->type == np_aaatoken_type_node) && identity->private_key_is_set);
        ret &= !_np_aaatoken_is_valid(identity, identity->type);
        // ret &= (identity->expires_at < np_time_now());
        log_debug_msg(LOG_DEBUG, "context->my_node_key =  %p %p %d", my_identity_key, identity, identity->type);
    }

    return ret;
}

bool __is_identity_authn(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    return false;    
}

void __np_identity_update(np_util_statemachine_t* statemachine, const np_util_event_t event) { }

void __np_identity_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{    
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_identity_destroy(...){");

    NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);

    if (FLAG_CMP(my_identity_key->type, np_key_type_node))
    {
        NP_CAST(sll_tail(void_ptr, my_identity_key->entities), np_network_t, my_network);
        _np_network_disable(my_network);
        np_unref_obj(np_network_t, my_network, "__np_create_identity_network");

        NP_CAST(sll_tail(void_ptr, my_identity_key->entities), np_node_t, my_node);
        np_unref_obj(np_node_t, my_node, "__np_create_identity_network");        
    }

    NP_CAST(sll_tail(void_ptr, my_identity_key->entities), np_aaatoken_t, my_token);
    np_unref_obj(np_aaatoken_t, my_token, "__np_set_identity");

    sll_free(void_ptr, my_identity_key->entities);

    ref_replace_reason(np_key_t, my_identity_key, "__np_set_identity", "_np_keycache_finalize");
    my_identity_key->type = np_key_type_unknown;
}

void __np_set_identity(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{    
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void _np_set_identity(...){");

    NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);
    NP_CAST(event.user_data, np_aaatoken_t, identity);

    np_ref_obj(np_key_t, my_identity_key, "__np_set_identity");

    if (FLAG_CMP(identity->type, np_aaatoken_type_node) )
    {
        my_identity_key->type |= np_key_type_node;

        sll_append(void_ptr, my_identity_key->entities, identity);
        np_ref_obj(np_aaatoken_t, identity, "__np_set_identity");
    
        context->my_node_key = my_identity_key;

        if (NULL == context->my_identity) 
        {
            my_identity_key->type |= np_key_type_ident;
            context->my_identity = my_identity_key;
        }
        log_debug_msg(LOG_DEBUG, "context->my_node_key =  %p %p %d", context->my_node_key, identity, identity->type);
    }
    else if(FLAG_CMP(identity->type, np_aaatoken_type_identity) )
    {
        sll_append(void_ptr, my_identity_key->entities, identity);
        np_ref_obj(np_aaatoken_t, identity, "__np_set_identity");
    
        if (NULL == context->my_identity || context->my_identity == context->my_node_key)
        {
            context->my_identity = my_identity_key;
        }
        log_debug_msg(LOG_DEBUG, "context->my_identity =  %p %p %d", context->my_identity, identity, identity->type);
    }

    // to be moved
    if (context->my_node_key != NULL &&
        _np_key_cmp(my_identity_key, context->my_node_key) != 0) 
    {
        np_dhkey_t node_dhkey = np_aaatoken_get_fingerprint(_np_key_get_token(context->my_node_key), false);
        np_aaatoken_set_partner_fp(_np_key_get_token(context->my_identity), node_dhkey);
        _np_aaatoken_update_extensions_signature(_np_key_get_token(context->my_node_key));
        
        np_dhkey_t ident_dhkey = np_aaatoken_get_fingerprint(_np_key_get_token(context->my_identity), false);
        np_aaatoken_set_partner_fp(_np_key_get_token(context->my_node_key), ident_dhkey);
    }
    
    _np_aaatoken_update_extensions_signature(identity);
    identity->state = AAA_VALID | AAA_AUTHENTICATED | AAA_AUTHORIZED;
    
    // _np_statistics_update_prometheus_labels(context, NULL);

#ifdef DEBUG
    char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES*2+1]; ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES*2] = '\0';
    char curve25519_pk[crypto_scalarmult_curve25519_BYTES*2+1]; curve25519_pk[crypto_scalarmult_curve25519_BYTES*2] = '\0';
    
    sodium_bin2hex(ed25519_pk, crypto_sign_ed25519_PUBLICKEYBYTES*2+1, identity->crypto.ed25519_public_key, crypto_sign_ed25519_PUBLICKEYBYTES);
    sodium_bin2hex(curve25519_pk, crypto_scalarmult_curve25519_BYTES*2+1, identity->crypto.derived_kx_public_key, crypto_scalarmult_curve25519_BYTES);
    
    log_debug_msg(LOG_DEBUG, "identity token: my cu pk: %s ### my ed pk: %s", curve25519_pk, ed25519_pk);
#endif
}

void __np_create_identity_network(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_create_identity_network(...){");

    NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);
    NP_CAST(event.user_data, np_aaatoken_t, identity);

    if (FLAG_CMP(identity->type, np_aaatoken_type_node))
    {
        // create node structure (do we still need it ???)
        np_node_t* my_node = _np_node_from_token(identity, np_aaatoken_type_node);
        sll_append(void_ptr, my_identity_key->entities, my_node);
        ref_replace_reason(np_node_t, my_node, "_np_node_from_token", "__np_create_identity_network")

        // create incoming network
        np_network_t* my_network = NULL;
        np_new_obj(np_network_t, my_network);
        if (_np_network_init(my_network, true, my_node->protocol, my_node->dns_name, my_node->port, -1, my_node->protocol) ) 
        {
            _np_network_set_key(my_network, my_identity_key);

            sll_append(void_ptr, my_identity_key->entities, my_network);
            ref_replace_reason(np_network_t, my_network, ref_obj_creation, "__np_create_identity_network")

            log_debug_msg(LOG_DEBUG, "Network %s is the main receiving network %d", np_memory_get_id(my_network), identity->type);

            _np_network_enable(my_network);
        }
    }
}

bool __is_unencrypted_np_message(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_unencrypted_np_message(...) {");
    
    bool ret = false;

    if (!ret) ret  = (FLAG_CMP(event.type, evt_external) && FLAG_CMP(event.type, evt_message));
    if ( ret) ret &= _np_memory_rtti_check(event.user_data, np_memory_types_BLOB_1024);
    if ( ret) 
    {
        // TODO: // ret &= _np_message_validate_format(message);
    }
    return ret;
}

void __np_extract_handshake(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_extract_handshake(...){");

    NP_CAST(event.user_data, void_ptr, raw_message);

    bool clean_message = true;
    np_message_t* msg_in = NULL;
    np_new_obj(np_message_t, msg_in, ref_obj_creation);

    bool is_deserialization_successful = _np_message_deserialize_header_and_instructions(msg_in, raw_message);
    CHECK_STR_FIELD_BOOL(msg_in->header, _NP_MSG_HEADER_SUBJECT, str_msg_subject, "NO SUBJECT IN MESSAGE")
    {   // check if the message is really a handshake message
        is_deserialization_successful &= ( 0 == strncmp(str_msg_subject->val.value.s, _NP_MSG_HANDSHAKE, strlen(_NP_MSG_HANDSHAKE)) );
    }

    if (is_deserialization_successful) 
    {
        log_debug_msg(LOG_SERIALIZATION | LOG_MESSAGE | LOG_DEBUG,
                    "deserialized message %s (source: \"%s\")", msg_in->uuid, event.user_data);

        CHECK_STR_FIELD_BOOL(msg_in->header, _NP_MSG_HEADER_SUBJECT, msg_subject, "NO SUBJECT IN MESSAGE")
        {
            // const char* str_msg_subject = msg_subject->val.value.s;
            log_debug_msg(LOG_ROUTING | LOG_DEBUG, "(msg: %s) received msg", msg_in->uuid);

            np_msgproperty_t* handshake_prop = _np_msgproperty_get(context, INBOUND, _NP_MSG_HANDSHAKE);
            if (_np_msgproperty_check_msg_uniquety(handshake_prop, msg_in)) 
            {
                _np_message_deserialize_chunked(msg_in);

                np_dhkey_t handshake_dhkey    = _np_msgproperty_dhkey(INBOUND, _NP_MSG_HANDSHAKE);
                np_util_event_t handshake_evt = { .type=(evt_external|evt_message), .context=context, 
                                                .user_data=msg_in, .target_dhkey=event.target_dhkey};
                _np_keycache_handle_event(context, handshake_dhkey, handshake_evt, false);
                clean_message = false;
            }
            else
            {
                log_msg(LOG_INFO, "duplicate handshake message (%s) detected, dropping it ...", msg_in->uuid);
            }
        }
    }
    else 
    {
        log_msg(LOG_WARN, "error deserializing initial message from new partner node");
        np_memory_free(context, raw_message);
        clean_message = false;
    }

    if (clean_message)
        np_unref_obj(np_message_t, msg_in, ref_obj_creation);

} 

void __np_identity_shutdown(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void _np_set_identity(...){");

    NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);

    if (FLAG_CMP(my_identity_key->type, np_key_type_node) &&
        my_identity_key == context->my_node_key)
    {
        NP_CAST(sll_last(my_identity_key->entities)->val, np_network_t, my_network);
        _np_network_disable(my_network);
    }
    
    if(FLAG_CMP(my_identity_key->type, np_key_type_ident) &&
       my_identity_key == context->my_identity )
    { 
        // TODO: disable followup authn / authz requests
    }
}

bool __is_authn_request(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __is_authn_request(...){");

    bool ret = false;
    NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);
    
    if (!ret) ret  =  FLAG_CMP(event.type, evt_authn);
    if ( ret) ret &= (FLAG_CMP(event.type, evt_external) && FLAG_CMP(event.type, evt_token) );
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
    if ( ret) {
        NP_CAST(event.user_data, np_aaatoken_t, token);
        ret &= (token->type == np_aaatoken_type_identity || token->type == np_aaatoken_type_node);
        ret &= _np_aaatoken_is_valid(token, token->type);
        log_debug_msg(LOG_DEBUG, "context->my_node_key =  %p %p %d", my_identity_key, token, token->type);
    }
    return ret;
}

bool __is_authz_request(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __is_authz_request(...){");

    bool ret = false;
    NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_authz);
    if ( ret) ret &= (FLAG_CMP(event.type, evt_external) && FLAG_CMP(event.type, evt_token) );
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
    if ( ret) {
        NP_CAST(event.user_data, np_aaatoken_t, token);
        ret &= (token->type == np_aaatoken_type_identity       || 
                token->type == np_aaatoken_type_node           || 
                token->type == np_aaatoken_type_message_intent);
        ret &= _np_aaatoken_is_valid(token, token->type);
        log_debug_msg(LOG_DEBUG, "context->my_node_key =  %p %p %d", my_identity_key, token, token->type);
    }
    return ret;
}

void __np_identity_handle_authn(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_identity_handle_authn(...){");

    NP_CAST(event.user_data, np_aaatoken_t, authn_token);

    // transport layer encryption
    if (authn_token->type == np_aaatoken_type_identity || authn_token->type == np_aaatoken_type_node)
    {
        if ( !FLAG_CMP(authn_token->state, AAA_AUTHENTICATED) ) 
        {
            log_debug_msg(LOG_DEBUG, "now checking (join/ident) authentication of token");
            struct np_token tmp_user_token = { 0 };
            bool join_allowed = context->authenticate_func(context, np_aaatoken4user(&tmp_user_token, authn_token));
            log_debug_msg(LOG_DEBUG, "authentication of token: %"PRIu8, join_allowed);

            if (true == join_allowed && context->enable_realm_client == false)
            {
                authn_token->state |= AAA_AUTHENTICATED;
                np_util_event_t authn_event = { .type=(evt_internal|evt_token|evt_authn), .context=context, .user_data=authn_token, .target_dhkey=event.target_dhkey};
                _np_keycache_handle_event(context, event.target_dhkey, authn_event, false);
            }
            else if (false == join_allowed && context->enable_realm_client == false) 
            {
                np_dhkey_t leave_dhkey = np_aaatoken_get_fingerprint(authn_token, false);
                np_util_event_t shutdown_evt = { .type=(evt_internal|evt_shutdown), .context=context, .user_data=NULL, .target_dhkey=leave_dhkey };
                _np_keycache_handle_event(context, leave_dhkey, shutdown_evt, true);
            }
        }
    }
    else if (authn_token->type == np_aaatoken_type_message_intent) 
    {
        // TODO: lookup hash of sending/receiving entitiy locally or in the dht
    }
}

void __np_identity_handle_authz(np_util_statemachine_t* statemachine, const np_util_event_t event)
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __np_identity_handle_authz(...){");

    NP_CAST(event.user_data, np_aaatoken_t, authz_token);

    if (authz_token->type == np_aaatoken_type_message_intent)
    {
        if ( !FLAG_CMP(authz_token->state, AAA_AUTHORIZED) )
        {
            log_debug_msg(LOG_DEBUG, "now checking (join/ident) authorization of token");
            struct np_token tmp_user_token = { 0 };
            bool access_allowed = context->authorize_func(context, np_aaatoken4user(&tmp_user_token, authz_token));
            log_debug_msg(LOG_DEBUG, "authorization of token: %"PRIu8, access_allowed);

            if (true == access_allowed && context->enable_realm_client == false)
            {
                authz_token->state |= AAA_AUTHORIZED;
                np_util_event_t authz_event = { .type=(evt_internal|evt_token|evt_authz), .context=context, .user_data=authz_token, .target_dhkey=event.target_dhkey };
                _np_keycache_handle_event(context, event.target_dhkey, authz_event, true);
            }
        }
    }
}

bool __is_account_request(np_util_statemachine_t* statemachine, const np_util_event_t event)
{} // check for local identity validity 

void __np_identity_handle_account(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{}
