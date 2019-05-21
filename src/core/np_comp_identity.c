//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that an identity can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include "neuropil.h"

#include "np_aaatoken.h"
#include "np_key.h"
#include "np_legacy.h"
#include "np_memory.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"


// IN_SETUP -> IN_USE transition condition / action #1
bool __is_identity_aaatoken(np_util_statemachine_t* statemachine, const np_util_event_t event) {

    np_ctx_decl(event.context);
    bool ret = false;

    if (!ret) ret  = FLAG_CMP(event.type, evt_internal) && FLAG_CMP(event.type, evt_token);
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
    if ( ret) {
        NP_CAST(event.user_data, np_aaatoken_t, identity);
        ret &= (context->my_identity == NULL);
        ret &= (identity->type == np_aaatoken_type_identity);
        ret &= identity->private_key_is_set;
        ret &= _np_aaatoken_is_valid(identity, identity->type);
    }
    return ret;
}
// IN_USE -> IN_DESTROY transition condition / action #1
bool __is_identity_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);

    bool ret = false;
    
    NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);
    
    if (!ret) ret = (sll_size(my_identity_key->entities) == 1);
    if ( ret) {
        NP_CAST(sll_first(my_identity_key->entities)->val, np_aaatoken_t, identity);
        ret &= (identity->type == np_aaatoken_type_identity);
        ret &= !_np_aaatoken_is_valid(identity, identity->type);
    }
    return ret;
}
void __np_identity_update(np_util_statemachine_t* statemachine, const np_util_event_t event) { }

void __np_identity_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{    
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);

    NP_CAST( sll_first(my_identity_key->entities)->val, np_aaatoken_t, identity );
    np_unref_obj(np_aaatoken_t, identity, ref_key_aaa_token);

    _np_keycache_remove(context, my_identity_key->dhkey);
    my_identity_key->is_in_keycache = false;

    sll_clear(void_ptr, my_identity_key->entities);

    my_identity_key->type = np_key_type_unknown;
}

void __np_set_identity(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{    
    np_ctx_memory(statemachine->_user_data);

    log_debug_msg(LOG_DEBUG, "start: void _np_set_identity(np_aaatoken_t* identity){");

    NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);
    NP_CAST(event.user_data, np_aaatoken_t, identity);

    np_ref_switch(np_aaatoken_t, identity, ref_key_aaa_token, identity);
    sll_append(void_ptr, my_identity_key->entities, identity);

    my_identity_key->is_in_keycache = true;
    my_identity_key->type |= np_key_type_ident;
    
    // context->my_identity = my_identity_key;
    // np_ref_switch(np_key_t, context->my_identity, ref_state_identitykey, my_identity_key);
    
    // to be moved
    if (context->my_node_key != NULL &&
        _np_key_cmp(my_identity_key, context->my_node_key) != 0) 
    {
        np_dhkey_t node_dhkey = np_aaatoken_get_fingerprint(context->my_node_key->aaa_token, false);
        np_aaatoken_set_partner_fp(context->my_identity->aaa_token, node_dhkey);
        _np_aaatoken_update_extensions_signature(context->my_node_key->aaa_token);
        
        np_dhkey_t ident_dhkey = np_aaatoken_get_fingerprint(context->my_identity->aaa_token, false);
        np_aaatoken_set_partner_fp(context->my_node_key->aaa_token, ident_dhkey);
    }
    
    _np_aaatoken_update_extensions_signature(identity);
    identity->state = AAA_VALID | AAA_AUTHENTICATED | AAA_AUTHORIZED;
    
    _np_statistics_update_prometheus_labels(context, NULL);

#ifdef DEBUG
    char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES*2+1]; ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES*2] = '\0';
    char curve25519_pk[crypto_scalarmult_curve25519_BYTES*2+1]; curve25519_pk[crypto_scalarmult_curve25519_BYTES*2] = '\0';
    
    sodium_bin2hex(ed25519_pk, crypto_sign_ed25519_PUBLICKEYBYTES*2+1, identity->crypto.ed25519_public_key, crypto_sign_ed25519_PUBLICKEYBYTES);
    sodium_bin2hex(curve25519_pk, crypto_scalarmult_curve25519_BYTES*2+1, identity->crypto.derived_kx_public_key, crypto_scalarmult_curve25519_BYTES);
    
    log_debug_msg(LOG_DEBUG, "identity token: my cu pk: %s ### my ed pk: %s\n", curve25519_pk, ed25519_pk);
#endif

}
